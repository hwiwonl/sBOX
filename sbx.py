# sudo python3 sbx.py --conf sbx.c --rule rule.yml
# sudo python3 sbx.py -c sbx.c -r rule.yml -p 42847
from __future__ import print_function
from http.client import PRECONDITION_REQUIRED
from bcc import BPF

import os, sys
import signal
import stat
import time
import argparse
import logging
import yaml

logger = logging.getLogger()

logger.setLevel(logging.INFO)

fileHandler = logging.FileHandler('/var/log/sbx.log')
fileHandler.terminator = ""
logger.addHandler(fileHandler)

class SBXRules:
    def __init__(self, args):
        self.fs_exec_rules = []
        self.port_rules = []
        self.args = args

        stream = open(self.args.rule, 'r')
        rules = yaml.load(stream)
        ''' execution exception rules
        - ld-*.so file should be excluded
            - debian : /lib/x86_64-linux-gnu/ld-2.xx.so
            - rhel   : /lib64/ld-2.xx.so
        '''
        exec = rules['exec']
        for e in exec:
            self.generate_fs_rule('x', e)
        
        if type(self.args.port) is int:
            self.generate_port_rule(self.args.port)
        else:
            for p in self.args.port:
                self.generate_port_rule(p)

    def generate_fs_rule(self, mode, path):
        """
        Generate fs rule for mode + path
        """
        from glob import glob

        paths = glob(path)

        # Compute rule based on path
        for path in paths:
            # Path is a directory
            if os.path.isdir(path):
                rule = f'parent_inode == {os.lstat(path)[stat.ST_INO]}'
                # print(path,rule)
            # Path is a file
            elif os.path.isfile(path):
                rule = f'inode == {os.lstat(path)[stat.ST_INO]}'
                # print(path,rule)

            '''
            @@TODO : READ/WRITE/ACCESS mode support
            '''
            # if 'r' in mode:
            #     self.fs_read_rules.append(rule)

            # if 'w' in mode:
            #     self.fs_write_rules.append(rule)

            # if 'a' in mode:
            #     self.fs_append_rules.append(rule)

            if 'x' in mode:
                self.fs_exec_rules.append(rule)

    def generate_port_rule(self, port):
        rule = 'lport == {0}'.format(port)
        self.port_rules.append(rule)

    def apply_rules(self):
        """
        Generate and apply rules for the BPF program
        """
        try:
            with open(self.args.conf, "r") as f:
                bpf_text = f.read()
        except:
            print("[!] No such a conf file")
            return ""

        bpf_text = bpf_text.replace(
            'PORT_EXCEPT_RULES',
            ' || '.join(self.port_rules) if self.port_rules else '0',
        )

        bpf_text = bpf_text.replace(
            'FS_EXEC_RULES',
            ' || '.join(self.fs_exec_rules) if self.fs_exec_rules else '0',
        )

        return bpf_text

def get_ppid(pid):
    try:
        ppid = 0
        ppidName = "*"
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    ppid = int(line.split()[1])
                if line.startswith("Name:"):
                    ppidName = line.split()[1]
    except IOError:
        pass
    return (ppid, ppidName)

def get_pidName(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("Name:"):
                    return line.split()[1]
    except IOError:
        pass
    return "*"

def print_sbx_event(cpu, data, size):
    event = b["sbx_event"].event(data)
    
    if event.type == 2:
        type_str = "T"
    elif event.type == 1:
        type_str = "U"
    else:
        type_str = "-"
    print("%-2s " % (type_str), end="")
    logging.info("%-2s " % (type_str))

    if event.status == 3:
        type_status = "V"
    elif event.status == 2:
        type_status = "K"
    elif event.status == 1:
        type_status = "F"
    else:
        type_status = "-"
    print("%-2s " % (type_status), end="")
    logging.info("%-2s " % (type_status))

    if event.ppid == 0:
        ppid, ppidName = get_ppid(event.pid)
        if event.status == 3:
            pidName = event.comm.decode('utf-8', 'replace')
        else:
            pidName = get_pidName(event.pid)
        pstree = "{0}({1})->{2}({3})".format(ppidName,ppid,pidName,event.pid)
        print("%-6d %-6d %-16s " % (ppid, event.pid, event.comm.decode('utf-8', 'replace')), end="")
        logging.info("%-6d %-6d %-16s " % (ppid, event.pid, event.comm.decode('utf-8', 'replace')))
    else:
        ppidName = get_pidName(event.ppid)
        if event.status == 3:
            pidName = event.comm.decode('utf-8', 'replace')
        else:
            pidName = get_pidName(event.pid)
        pstree = "{0}({1})->{2}({3})".format(ppidName,event.ppid,pidName,event.pid)
        print("%-6d %-6d %-16s " % (event.ppid, event.pid, event.comm.decode('utf-8', 'replace')), end="")
        logging.info("%-6d %-6d %-16s " % (event.ppid, event.pid, event.comm.decode('utf-8', 'replace')))

    if event.func == 0x10:
        func_name = "EXEC"
    elif event.func == 0x11:
        func_name = "tcp_v4_connect()"
    elif event.func == 0x12:
        func_name = "tcp_v6_connect()"
    elif event.func == 0x13:
        func_name = "tcp_set_state()"
    elif event.func == 0x14:
        func_name = "tcp_close()"
    elif event.func == 0x15:
        func_name = "tcp_accept()"
    elif event.func == 0x16:
        func_name = "fork()"
    elif event.func == 0x17:
        func_name = "kill()"
    else:
        func_name = "unknown()"

    print("%-16s " % (func_name), end="")
    logging.info("%-16s " % (func_name))
    print("%-24s" % (pstree), end="")
    logging.info("%-24s" % (pstree))
    # print(get_ppid(event.pid))
    print()
    logging.info("\n")

if __name__ == '__main__':
    signal.signal(signal.SIGINT, lambda x, y: sys.exit())
    signal.signal(signal.SIGTERM, lambda x, y: sys.exit())

    parser = argparse.ArgumentParser(
        description="Sandboxing malicious processes",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-c", "--conf", required=True,
        help='sbx config file (in C)')
    parser.add_argument("-r", "--rule", required=True,
        help='sbx rule file (in YAML)')
    parser.add_argument("-p", "--port", nargs='*', default=22, type=int,
        help='port exception (multi args is supported')

    args = parser.parse_args()

    if os.geteuid() != 0:
        parser.error("Need superuser privileges")

    sbx = SBXRules(args)

    try:
        # initialized BPF
        b = BPF(text=sbx.apply_rules())
        b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_entry")
        b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
        b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_entry")
        b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")
        b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state_entry")
        # b.attach_kprobe(event="tcp_setsockopt", fn_name="trace_tcp_setsockopt_entry")
        b.attach_kprobe(event="tcp_close", fn_name="trace_close_entry")
        b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return")

        # kill_fnname = b.get_syscall_fnname("kill")
        # b.attach_kprobe(event=kill_fnname, fn_name="syscall__kill")
        # b.attach_kretprobe(event=kill_fnname, fn_name="do_ret_sys_kill")
        
    except:
        sys.exit(-1)

    print()
    print("%-2s %-2s %-6s %-6s %-16s %-16s %-24s" %
          ("T", "S", "PPID", "PID", "COMM", "FUNC", "PSTREE"))
    print("%-2s %-2s %-6s %-6s %-16s %-16s %-24s" %
          ("=", "=", "====", "===", "====", "====", "======"))
    logging.info("\n\n")
    logging.info("%-2s %-2s %-6s %-6s %-16s %-16s %-24s\n" %
          ("T", "S", "PPID", "PID", "COMM", "FUNC", "PSTREE"))
    logging.info("%-2s %-2s %-6s %-6s %-16s %-16s %-24s\n" %
          ("=", "=", "====", "===", "====", "====", "======"))

    b["sbx_event"].open_perf_buffer(print_sbx_event)
    while 1:
        try:
            b.perf_buffer_poll()
            # b.trace_print()
            # time.sleep(0.1)
        except KeyboardInterrupt:
            exit()
