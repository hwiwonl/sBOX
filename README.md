# sBOX: System Call Confinement using eBPF

## Supported OS
* Ubuntu 20.04 (*default kernel supports [bcc](https://github.com/iovisor/bcc)*)
* Ubuntu 18.04 (*automatic kernel upgrade is supported*)
* AlmaLinux 8 (*default kernel supports [bcc](https://github.com/iovisor/bcc)*)
* CentOS 8 (*default kernel supports [bcc](https://github.com/iovisor/bcc)*)
* CentOs 7 (*automatic kernel upgrade is supported*)

## Setup
`root` 권한으로 실행합니다.
```sh
./setup_sbx.sh
```

## Run (local)
`root` 권한으로 실행합니다.
```
python3 sbx.py -h
usage: sbx.py [-h] -c CONF -r RULE [-p [PORT [PORT ...]]]

Sandboxing malicious processes

optional arguments:
  -h, --help            show this help message and exit
  -c CONF, --conf CONF  sbx config file (in C)
  -r RULE, --rule RULE  sbx rule file (in YAML)
  -p [PORT [PORT ...]], --port [PORT [PORT ...]]
                        port exception
```

### 기본모드
```bash
python3 sbx.py -c sbx.c -r rule.yml
```

### 포트제외
특정 포트 번호들은 `-p` 옵션을 사용해서 예외처리할 수 있습니다. 여러개의 포트를 지정할 수 있습니다. 특히, Ansible/Fabric SSH 접근으로 사용하는 포트(42847)는 반드시 예외처리해야 합니다. 서비스별로 다른 포트를 지정할 경우 반드시 [service](./template.service) 파일의 명령어를 알맞게 수정하여 서비스 등록하셔야 합니다.
```bash
python3 sbx.py -c sbx.c -r rule.yml -p 42847 8888
```

## Run (remote)
Ansible/Fabric 코드를 통해 원격 서버에 SBX 설정을 완료한 경우 **ls22sbx** 이름의 서비스로 동작하게 됩니다. 이는 다음을 통해 확인할 수 있습니다.
```
systemctl status ls22sbx
● ls22sbx.service - Sandbox Daemon
   Loaded: loaded (/etc/systemd/system/ls22sbx.service; enabled; vendor preset: enabled)
   Active: active (running) since Fri 2022-04-01 05:22:59 UTC; 4s ago
 Main PID: 25551 (python3)
    Tasks: 1 (limit: 4675)
   CGroup: /system.slice/ls22sbx.service
           └─25551 /usr/bin/python3 /root/sbx.py -c /root/sbx.c -r /root/rule.yml -p 42847

Apr 01 05:22:59 ls22 systemd[1]: Started Sandbox Daemon.
```

만약, rule을 변경하거나 service 파일을 수정하여 업데이트한 경우 다음의 명령어를 통해 반드시 재실행해야 합니다.
```sh
# .service 파일을 수정한 경우 반드시 daemon-reload 명령어를 수행합니다.
systemctl daemon-reload
# 단순히 rule 파일만 변경한 경우 restart 명령어만 수행해도 됩니다.
systemctl restart ls22sbx
```

로그는 `/var/log/sbx.log` 파일에 저장됩니다.
```
tail -f /var/log/sbx.log

T  S  PPID   PID    COMM             FUNC             PSTREE
=  =  ====   ===    ====             ====             ======
T  -  27129  27681  python3          tcp_accept()     python3(27129)->python3(27681)
T  F  27681  27786  python3          fork()           python3(27681)->python3(27786)
T  F  27786  27787  python3          fork()           python3(27786)->python3(27787)
T  F  27787  27788  sh               fork()           sh(27787)->id(27788)
U  -  27129  27681  python3          tcp_close()      python3(27129)->python3(27681)
T  -  27129  27681  python3          tcp_accept()     python3(27129)->python3(27681)
T  F  27681  27789  python3          fork()           python3(27681)->python3(27789)
T  F  27789  27790  python3          fork()           python3(27789)->python3(27790)
T  F  27790  27791  sh               fork()           sh(27790)->sh(27791)
-  V  27790  27791  sh               EXEC             sh(27790)->sh(27791)
U  -  27129  27681  python3          tcp_close()      python3(27129)->python3(27681)
```
* `T` 컬럼은 taint 정보를 담고 있으며, **T**는 **taint 활성화**, **U**는 **taint 해제**를 의미합니다. 
* `S` 컬럼은 상태(status) 정보를 담고 있으며, **F**는 **프로세스 fork**, **K**는 **프로세스 kill**, **V**는 **정책 위반 탐지 및 차단**을 의미합니다.
* `PPID`는 부모프로세스 id, `PID`는 해당 프로세스 id를 의미합니다.
* `COMM` 컬럼은 해당 프로세스의 이름을 의미합니다.
* `FUNC` 컬럼은 해당 프로세스를 호출한 syscall을 나타냅니다.
* `PSTREE` 컬럼은 부모-현재 프로세스 정보를 표현합니다.

## Rule
화이트리스트 방식의 접근제어 모델이기에, 예외적으로 실행 가능한 명령어를 지정해주기 위해서는 `rule-XX.yml` 파일에 해당 명령어의 **절대경로**를 입력하면 됩니다. 현재 예시 파일로 제공한 `rule-debian.yml`의 경우 다음과 같습니다.
```yml
exec:
  - /lib/x86_64-linux-gnu/ld-*
  - /usr/sbin/sshd
  - /bin/sh
  - /bin/bash
  - /bin/dash
  - /usr/bin/id
  - /usr/bin/git
  - /usr/lib/git-core
```
실행 가능한 바이너리의 경우 기본적으로 `ld-*` 라이브러리(e.g., ld-2.27.so)를 참조하기에 이는 무조건 예외처리에 추가해야 합니다. 그리고 이후에 예외적으로 실행하고 싶은 명령어들의 절대 경로를 입력합니다. 위처럼 `/bin/sh`와 같이 쉘 인터페이스 바이너리를 예외처리한 경우, 빌트인 명령어들(e.g., /bin/sh -c pwd)은 실행될 수 있습니다. 이를 차단하고 싶은 경우 `sh` 쉘 인터페이스 바이너리들을 모두 rule 파일에서 제거하시면 됩니다. 


## Case Study
### [C1] backdoor [thetick](https://github.com/nccgroup/thetick)
NCC group에서 개발한 백도어를 사용합니다. 호스트에서 다음과 같이 bot 연결을 확인할 수 있습니다. bot 0에 대해서 명령어를 수행하면 모두 제대로 실행되지 않는 것을 알 수 있습니다.
```
python tick.py

▄▄▄█████▓ ██░ ██ ▓█████    ▄▄▄█████▓ ██▓ ▄████▄   ██ ▄█▀
▓  ██▒ ▓▒▓██░ ██▒▓█   ▀    ▓  ██▒ ▓▒▓██▒▒██▀ ▀█   ██▄█▒
▒ ▓██░ ▒░▒██▀▀██░▒███      ▒ ▓██░ ▒░▒██▒▒▓█    ▄ ▓███▄░
░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄    ░ ▓██▓ ░ ░██░▒▓▓▄ ▄██▒▓██ █▄
  ▒██▒ ░ ░▓█▒░██▓░▒████▒     ▒██▒ ░ ░██░▒ ▓███▀ ░▒██▒ █▄
  ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░     ▒ ░░   ░▓  ░ ░▒ ▒  ░▒ ▒▒ ▓▒
    ░     ▒ ░▒░ ░ ░ ░  ░       ░     ▒ ░  ░  ▒   ░ ░▒ ▒░
  ░       ░  ░░ ░   ░        ░       ▒ ░░        ░ ░░ ░
          ░  ░  ░   ░  ░             ░  ░ ░      ░  ░
                                        ░
                Embedded Linux Backdoor
               by Mario Vilas (NCC Group)

Listening on: 0.0.0.0:5555
Bot 0 [7bc09be9-3995-4bc2-9423-5a0d5653d01c] connected from 192.168.1.65
[No bot selected] use 0
[Bot 0: 192.168.1.65] ?

Available commands (type help * or help <command>)
==================================================
bots   clear    dig       exec  fork  kill   proxy  push  shell
chmod  current  download  exit  help  pivot  pull   rm    use

[Bot 0: 192.168.1.65] exec ls

[Bot 0: 192.168.1.65] exec id

[Bot 0: 192.168.1.65] shell
/-------------------------------------------------\
| Entering remote shell. Use Control+C to return. |
\-------------------------------------------------/


[Bot 0: 192.168.1.65]
```

SBX 로그를 확인해보면 다음과 같이 정책 위반(`V`)이 발생한 것을 확인할 수 있습니다.
```
tail -f /var/log/sbx.log

T  S  PPID   PID    COMM             FUNC             PSTREE
=  =  ====   ===    ====             ====             ======
T  -  25340  26974  ticksvc          tcp_v4_connect() ticksvc(25340)->ticksvc(26974)
U  -  25340  26974  ticksvc          tcp_close()      ticksvc(25340)->ticksvc(26974)
T  -  25340  26974  ticksvc          tcp_v4_connect() ticksvc(25340)->ticksvc(26974)
U  -  25340  26974  ticksvc          tcp_close()      ticksvc(25340)->ticksvc(26974)
T  -  25340  27004  ticksvc          tcp_v4_connect() ticksvc(25340)->ticksvc(27004)
T  F  27004  27005  ticksvc          fork()           ticksvc(27004)->*(27005)
-  V  0      27005  ticksvc          EXEC             *(0)->ticksvc(27005)
T  F  27004  27006  ticksvc          fork()           ticksvc(27004)->ticksvc(27006)
-  V  0      27006  ticksvc          EXEC             *(0)->ticksvc(27006)
T  F  27004  27007  ticksvc          fork()           ticksvc(27004)->ticksvc(27007)
-  V  27004  27007  ticksvc          EXEC             ticksvc(27004)->ticksvc(27007)
U  -  27004  27007  ticksvc          tcp_close()      ticksvc(27004)->ticksvc(27007)
```
