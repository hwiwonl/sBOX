#include <uapi/linux/ptrace.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>

// open, openat, openat2 flags
#include <uapi/linux/fcntl.h>
#include <linux/fs.h>

#define TCP_EVENT_TYPE_CONNECT 1
#define TCP_EVENT_TYPE_ACCEPT  2
#define TCP_EVENT_TYPE_CLOSE   3

// type
#define SBX_TAINT       2
#define SBX_UNTAINT     1
// status
#define SBX_VIOLATE     3
#define SBX_KILL        2
#define SBX_FORK        1
#define SBX_NONE        0
// functions
#define SBX_FUNC_EXEC               0x10
#define SBX_FUNC_TCP_V4_CONNECT     0x11
#define SBX_FUNC_TCP_V6_CONNECT     0x12
#define SBX_FUNC_TCP_SET_STATE      0x13
#define SBX_FUNC_TCP_CLOSE          0x14
#define SBX_FUNC_TCP_ACCEPT         0x15
#define SBX_FUNC_FORK               0x16
#define SBX_FUNC_KILL               0x17

// For trcing do_filp_open()
struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};
// Creates NUM_CPU int-indexed arrays which are optimized for fastest lookup and update
BPF_PERCPU_ARRAY(do_filp_open_intermediate, struct open_flags, 1);

// Taint analysis
struct sbx_state_t {
    u8 tainted;
};
// Taint status hash map 
BPF_HASH(states, u32, struct sbx_state_t);

static struct sbx_state_t *create_or_lookup_sbx_state(u32 pid)
{
    struct sbx_state_t temp = {
        .tainted = 0,
    };
    return states.lookup_or_try_init(&pid, &temp);
}

struct sbx_event_t {
    u8      type;                   // 1:Taint / 0:Untaint
    u8      status;                 // 2:Violated / 1:Fork / 0:None
    u32     func;                   // Function id
    u32     ppid;                   // For forked processes
    u32     pid;                    // Process id
    char    comm[TASK_COMM_LEN];    // Process name
};
BPF_PERF_OUTPUT(sbx_event);

/*
 * Trace `kill` syscall 
 */
struct val_t {
    u64 pid;
    int sig;
    int tpid;
    char comm[TASK_COMM_LEN];
};
BPF_HASH(infotmp, u32, struct val_t);

// tcp_set_state doesn't run in the context of the process that initiated the
// connection so we need to store a map TUPLE -> PID to send the right PID on
// the event
struct ipv4_tuple_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 netns;
};

struct ipv6_tuple_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u32 netns;
};

struct pid_comm_t {
    u64 pid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(tuplepid_ipv4, struct ipv4_tuple_t, struct pid_comm_t);
BPF_HASH(tuplepid_ipv6, struct ipv6_tuple_t, struct pid_comm_t);

BPF_HASH(connectsock, u64, struct sock *);

static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct sock *skp)
{
    u32 net_ns_inum = 0;
    u32 saddr = skp->__sk_common.skc_rcv_saddr;
    u32 daddr = skp->__sk_common.skc_daddr;
    struct inet_sock *sockp = (struct inet_sock *)skp;
    u16 sport = sockp->inet_sport;
    u16 dport = skp->__sk_common.skc_dport;
#ifdef CONFIG_NET_NS
    net_ns_inum = skp->__sk_common.skc_net.net->ns.inum;
#endif

    tuple->saddr = saddr;
    tuple->daddr = daddr;
    tuple->sport = sport;
    tuple->dport = dport;
    tuple->netns = net_ns_inum;

    // if addresses or ports are 0, ignore
    if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
        return 0;
    }

    return 1;
}

static int read_ipv6_tuple(struct ipv6_tuple_t *tuple, struct sock *skp)
{
    u32 net_ns_inum = 0;
    unsigned __int128 saddr = 0, daddr = 0;
    struct inet_sock *sockp = (struct inet_sock *)skp;
    u16 sport = sockp->inet_sport;
    u16 dport = skp->__sk_common.skc_dport;
#ifdef CONFIG_NET_NS
    net_ns_inum = skp->__sk_common.skc_net.net->ns.inum;
#endif
    bpf_probe_read_kernel(&saddr, sizeof(saddr),
                    skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&daddr, sizeof(daddr),
                    skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

    tuple->saddr = saddr;
    tuple->daddr = daddr;
    tuple->sport = sport;
    tuple->dport = dport;
    tuple->netns = net_ns_inum;

    // if addresses or ports are 0, ignore
    if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
        return 0;
    }

    return 1;
}

static bool check_family(struct sock *sk, u16 expected_family) {
    u64 zero = 0;
    u16 family = sk->__sk_common.skc_family;
    return family == expected_family;
}

int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid = bpf_get_current_pid_tgid();

    u16 family = sk->__sk_common.skc_family;

    // stash the sock ptr for lookup on return
    connectsock.update(&pid, &sk);

    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid = bpf_get_current_pid_tgid();
    // bpf_trace_printk("@trace_connect_v4_return(pid:%d)\n", pid);
    u32 pid_ = pid >> 32;
    // @@TAINT
    struct sbx_event_t sbxevt = { };
    struct sbx_state_t *state = states.lookup(&pid_);
    if (!state) {
        // bpf_trace_printk("INIT SBX STATE (pid:%d)\n", pid_);
        state = create_or_lookup_sbx_state(pid_);
    } 
    if (!state) {
        bpf_trace_printk("[!] Failed to create_or_lookup_sbx_state()\n");
    } else {
        if (!state->tainted) {
            sbxevt.type = SBX_TAINT;
            sbxevt.status = SBX_NONE;
            sbxevt.func = SBX_FUNC_TCP_V4_CONNECT;
            sbxevt.pid = pid_;
            sbxevt.ppid = 0;
            bpf_get_current_comm(&sbxevt.comm, sizeof(sbxevt.comm));
            sbx_event.perf_submit(ctx, &sbxevt, sizeof(sbxevt));
            bpf_trace_printk("[+] TAINT (pid=%d,func=@tcp_v4_connect)\n", pid_);
            state->tainted = 1;
        }
    }

    struct sock **skpp;
    skpp = connectsock.lookup(&pid);
    if (skpp == 0) {
        return 0;       // missed entry
    }

    connectsock.delete(&pid);

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    struct ipv4_tuple_t t = { };
    if (!read_ipv4_tuple(&t, skp)) {
        return 0;
    }

    struct pid_comm_t p = { };
    p.pid = pid;
    bpf_get_current_comm(&p.comm, sizeof(p.comm));

    tuplepid_ipv4.update(&t, &p);

    return 0;
}

int trace_connect_v6_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid = bpf_get_current_pid_tgid();

    u16 family = sk->__sk_common.skc_family;
 
    // stash the sock ptr for lookup on return
    connectsock.update(&pid, &sk);

    return 0;
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid = bpf_get_current_pid_tgid();
    u32 pid_ = pid >> 32;
    // @@TAINT
    struct sbx_event_t sbxevt = { };
    struct sbx_state_t *state = states.lookup(&pid_);
    if (!state) {
        // bpf_trace_printk("INIT SBX STATE (pid:%d)\n", pid_);
        state = create_or_lookup_sbx_state(pid_);
    } 
    if (!state) {
        bpf_trace_printk("[!] Failed to create_or_lookup_sbx_state()\n");
    } else {
        if (!state->tainted) {
            sbxevt.type = SBX_TAINT;
            sbxevt.status = SBX_NONE;
            sbxevt.func = SBX_FUNC_TCP_V6_CONNECT;            
            sbxevt.pid = pid_;
            sbxevt.ppid = 0;
            bpf_get_current_comm(&sbxevt.comm, sizeof(sbxevt.comm));
            sbx_event.perf_submit(ctx, &sbxevt, sizeof(sbxevt));
            bpf_trace_printk("[+] TAINT (pid=%d,func=@tcp_v6_connect)\n", pid_);
            state->tainted = 1;
        }
    }

    struct sock **skpp;
    skpp = connectsock.lookup(&pid);
    if (skpp == 0) {
        return 0;       // missed entry
    }

    connectsock.delete(&pid);

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    struct ipv6_tuple_t t = { };
    if (!read_ipv6_tuple(&t, skp)) {
        return 0;
    }

    struct pid_comm_t p = { };
    p.pid = pid;
    bpf_get_current_comm(&p.comm, sizeof(p.comm));

    tuplepid_ipv6.update(&t, &p);

    return 0;
}

int trace_tcp_set_state_entry(struct pt_regs *ctx, struct sock *skp, int state)
{
    if (state != TCP_ESTABLISHED && state != TCP_CLOSE) {
        return 0;
    }

    u16 family = skp->__sk_common.skc_family;

    u8 ipver = 0;
    if (check_family(skp, AF_INET)) {
        ipver = 4;
        struct ipv4_tuple_t t = { };
        if (!read_ipv4_tuple(&t, skp)) {
            return 0;
        }

        if (state == TCP_CLOSE) {
            tuplepid_ipv4.delete(&t);
            return 0;
        }

        struct pid_comm_t *p;
        p = tuplepid_ipv4.lookup(&t);
        if (p == 0) {
            return 0;       // missed entry
        }

        u32 pid_ = p->pid >> 32;
        // @@TAINT
        struct sbx_event_t sbxevt = { };
        struct sbx_state_t *state = states.lookup(&pid_);
        if (!state) {
            // bpf_trace_printk("INIT SBX STATE (pid:%d)\n", pid_);
            state = create_or_lookup_sbx_state(pid_);
        } 
        if (!state) {
            bpf_trace_printk("[!] Failed to create_or_lookup_sbx_state()\n");
        } else {
            if (!state->tainted) {
                sbxevt.type = SBX_TAINT;
                sbxevt.status = SBX_NONE;
                sbxevt.func = SBX_FUNC_TCP_SET_STATE;      
                sbxevt.pid = pid_;
                sbxevt.ppid = 0;
                int i;
                for (i = 0; i < TASK_COMM_LEN; i++) {
                    sbxevt.comm[i] = p->comm[i];
                }
                sbx_event.perf_submit(ctx, &sbxevt, sizeof(sbxevt));
                bpf_trace_printk("[+] TAINT (pid=%d, func=@tcp_set_state)\n", pid_);
                state->tainted = 1;
            }
        }

        tuplepid_ipv4.delete(&t);

    } else if (check_family(skp, AF_INET6)) {
        ipver = 6;
        struct ipv6_tuple_t t = { };
        if (!read_ipv6_tuple(&t, skp)) {
            return 0;
        }

        if (state == TCP_CLOSE) {
            tuplepid_ipv6.delete(&t);
            return 0;
        }

        struct pid_comm_t *p;
        p = tuplepid_ipv6.lookup(&t);
        if (p == 0) {
            return 0;       // missed entry
        }

        u32 pid_ = p->pid >> 32;
        // @@TAINT
        struct sbx_event_t sbxevt = { };
        struct sbx_state_t *state = states.lookup(&pid_);
        if (!state) {
            // bpf_trace_printk("INIT SBX STATE (pid:%d)\n", pid_);
            state = create_or_lookup_sbx_state(pid_);
        } 
        if (!state) {
            bpf_trace_printk("[!] Failed to create_or_lookup_sbx_state()\n");
        } else {
            if (!state->tainted) {
                sbxevt.type = SBX_TAINT;
                sbxevt.status = SBX_NONE;
                sbxevt.func = SBX_FUNC_TCP_SET_STATE;      
                sbxevt.pid = pid_;
                sbxevt.ppid = 0;
                int i;
                for (i = 0; i < TASK_COMM_LEN; i++) {
                    sbxevt.comm[i] = p->comm[i];
                }
                sbx_event.perf_submit(ctx, &sbxevt, sizeof(sbxevt));
                bpf_trace_printk("[+] TAINT (pid=%d, func=@tcp_set_state)\n", pid_);
                state->tainted = 1;
            }
        }

        tuplepid_ipv6.delete(&t);
    }
    // else drop

    return 0; 
}

int trace_close_entry(struct pt_regs *ctx, struct sock *skp)
{
    u64 pid = bpf_get_current_pid_tgid();
    u32 pid_ = pid >> 32;

    struct sbx_event_t sbxevt = { };
    struct sbx_state_t *state = states.lookup(&pid_);
    if (!state) {
        // bpf_trace_printk("INIT SBX STATE (pid:%d)\n", pid_);
        state = create_or_lookup_sbx_state(pid_);
    } 
    if (!state) {
        bpf_trace_printk("[!] Failed to create_or_lookup_sbx_state()\n");
    } else {
        if (state->tainted) {
            sbxevt.type = SBX_UNTAINT;
            sbxevt.status = SBX_NONE;
            sbxevt.func = SBX_FUNC_TCP_CLOSE;            
            sbxevt.pid = pid_;
            sbxevt.ppid = 0;
            bpf_get_current_comm(&sbxevt.comm, sizeof(sbxevt.comm));
            sbx_event.perf_submit(ctx, &sbxevt, sizeof(sbxevt));            
            bpf_trace_printk("[x] UNTAINT (pid:%d) closed socket\n", pid_);
            state->tainted = 0;
        }
    }

    return 0;
};

int trace_accept_return(struct pt_regs *ctx)
{
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    u16 lport = 0;
    lport = newsk->__sk_common.skc_num;

    if (PORT_EXCEPT_RULES)
        return 0;

    u64 pid = bpf_get_current_pid_tgid();
    u32 pid_ = pid >> 32;

    // @@TAINT
    struct sbx_event_t sbxevt = { };
    struct sbx_state_t *state = states.lookup(&pid_);
    if (!state) {
        // bpf_trace_printk("INIT SBX STATE (pid:%d)\n", pid_);
        state = create_or_lookup_sbx_state(pid_);
    } 
    if (!state) {
        bpf_trace_printk("[!] Failed to create_or_lookup_sbx_state()\n");
    } else {
        if (!state->tainted) {
            sbxevt.type = SBX_TAINT;
            sbxevt.status = SBX_NONE;
            sbxevt.func = SBX_FUNC_TCP_ACCEPT;
            sbxevt.pid = pid_;
            sbxevt.ppid = 0;
            bpf_get_current_comm(&sbxevt.comm, sizeof(sbxevt.comm));
            sbx_event.perf_submit(ctx, &sbxevt, sizeof(sbxevt));
            bpf_trace_printk("[+] TAINT (pid=%d,func=@inet_csk_accept)\n", pid_);
            state->tainted = 1;
        } 
    }

    return 0;
}

/* Probe every fork/vfork/clone and duplicate the current
 * bpfbox state, including taintedness. */
RAW_TRACEPOINT_PROBE(sched_process_fork)
{
    struct sbx_state_t *state;

    struct task_struct *p = (struct task_struct *)ctx->args[0];
    struct task_struct *c = (struct task_struct *)ctx->args[1];

    u32 ppid = p->pid;
    u32 cpid = c->pid;

    // bpf_trace_printk("[-] fork (ppid:%d->cpid:%d)\n", ppid, cpid);
    state = states.lookup(&ppid);
    if (!state) {
        // bpf_trace_printk("pid:%d is not tainted", ppid);
        return 0;
    }

    struct sbx_event_t sbxevt = { };
    sbxevt.type = SBX_TAINT;
    sbxevt.status = SBX_FORK;
    sbxevt.func = SBX_FUNC_FORK;
    sbxevt.pid = cpid;
    sbxevt.ppid = ppid;
    bpf_get_current_comm(&sbxevt.comm, sizeof(sbxevt.comm));
    sbx_event.perf_submit(ctx, &sbxevt, sizeof(sbxevt));
    
    bpf_trace_printk("[-] fork (ppid:%d->cpid:%d)\n", ppid, cpid);
    bpf_trace_printk("[+] TAINT (forked pid:%d)\n", cpid);
    
    states.update(&cpid, state);

    return 0;
}

/*
 * EXEC FILTER (by tracing `do_filp_open`)
 */
/* A kprobe that checks the arguments to do_filp_open
 * (underlying implementation of open, openat, and openat2). */
// int kprobe__do_filp_open(struct pt_regs *ctx, int dfd,
//         struct filename *pathname, const struct open_flags *op)
int kprobe__do_filp_open(struct pt_regs *ctx, int dfd,
        struct filename *pathname, const struct open_flags *op)
{
    int zero = 0;
    struct open_flags tmp;
    bpf_probe_read(&tmp, sizeof(tmp), op);

    do_filp_open_intermediate.update(&zero, &tmp);

    return 0;
}


/* A kretprobe that checks the file struct pointer returned
 * by do_filp_open (underlying implementation of open, openat,
 * and openat2). */
// int kretprobe__do_filp_open(struct pt_regs *ctx)
int kretprobe__do_filp_open(struct pt_regs *ctx)
{
    // Get file pointer from return value
    u32 pid = bpf_get_current_pid_tgid();
    struct sbx_state_t *state = states.lookup(&pid);
    if (!state) {
        // bpf_trace_printk("NOT TARGET\n");
        return 0;
    }

    struct file *fp = (struct file*)PT_REGS_RC(ctx);
    if (!fp)
    {
        bpf_trace_printk("failed to fp\n");
        return 0;
    }

    // Access the open_flags struct from the entrypoint arguments
    int zero = 0;
    struct open_flags *op = do_filp_open_intermediate.lookup(&zero);
    if (!op)
    {
        bpf_trace_printk("failed to open flags\n");
        return 0;
    }

    // If we are not tainted we don't care
    if (!state->tainted)
    {
        // bpf_trace_printk("NOT OUR TARGET\n");
        return 0;
    }

    struct dentry *dentry = fp->f_path.dentry;
    struct dentry *parent = fp->f_path.dentry->d_parent;
    u32 inode = dentry->d_inode->i_ino;
    u32 parent_inode = parent ? parent->d_inode->i_ino : 0;
    int acc_mode = op->acc_mode;

    if (acc_mode & MAY_EXEC)
    {
        // bpf_trace_printk("ACCESS TYPE : EXEC [%s]\n", dentry->d_name.name);
        struct sbx_event_t sbxevt = { };
        if (FS_EXEC_RULES)
            return 0;
        else {
            sbxevt.type = SBX_NONE;
            sbxevt.status = SBX_VIOLATE;
            sbxevt.func = SBX_FUNC_EXEC;
            sbxevt.pid = pid;
            sbxevt.ppid = 0;
            bpf_get_current_comm(&sbxevt.comm, sizeof(sbxevt.comm));
            sbx_event.perf_submit(ctx, &sbxevt, sizeof(sbxevt));
            bpf_trace_printk("[!] VIOLATION : EXEC policy [%s:%d]\n", dentry->d_name.name, inode);
            bpf_send_signal(SIGKILL);
            // return 0;
        }
    }

    // bpf_trace_printk("Enforcing on [%s]\n", dentry->d_name.name);
    // bpf_send_signal(SIGKILL);

    return 0;
}

int syscall__kill(struct pt_regs *ctx, int tpid, int sig)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    struct val_t val = {.pid = pid};
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.tpid = tpid;
        val.sig = sig;
        infotmp.update(&tid, &val);
    }
    return 0;
};

int do_ret_sys_kill(struct pt_regs *ctx)
{
    struct val_t *valp;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    valp = infotmp.lookup(&tid);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    
    struct sbx_event_t sbxevt = { };
    struct sbx_state_t *state = states.lookup(&pid);
    if (state)
    {
        if (state->tainted) {
            sbxevt.type = SBX_UNTAINT;
            sbxevt.status = SBX_KILL;
            sbxevt.func = SBX_FUNC_KILL;
            sbxevt.pid = pid;
            sbxevt.ppid = 0;
            int i;
            for (i=0;i< TASK_COMM_LEN; i++)
                sbxevt.comm[i] = valp->comm[i];
            sbx_event.perf_submit(ctx, &sbxevt, sizeof(sbxevt));
            bpf_trace_printk("[x] UNTAINT (pid=%d,proc=%s) killed process\n", pid, valp->comm);
            state->tainted = 0;
        }
    }

    return 0;
}
