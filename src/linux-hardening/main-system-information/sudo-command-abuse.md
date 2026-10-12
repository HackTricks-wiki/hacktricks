# Sudoコマンドの悪用

{{#include ../../banners/hacktricks-training.md}}

## Sudoで許可されたインタプリタ

`sudo -l` でユーザーがインタプリタをrootとして実行できる場合、直接的なコード実行として扱ってください。インタプリタは任意のコードを実行するように設計されているため、`python3`、`perl`、`ruby`、`lua`、`node`などのバイナリを許可するルールは、引数が厳密に制限・検証されていない限り、通常はroot権限でのコマンド実行と同等です。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

一般的な確認手順は、まずユーザーの権限を一覧表示し、次にインタプリタの`-c`オプションを使ってPythonの文を実行することです。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```

その他のインタープリターの例を以下に示します。列挙したインタープリターには、インラインコードの実行や子プロセスAPIに関するドキュメントがあります。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```

正確なパスが重要です。sudo ルールで `/usr/bin/python3` が許可されている場合は、検証時にもその正確なパスを使用してください。<sup>[[2]](#references)</sup>

`/usr/bin/python*` のような sudo 実行ファイルの glob は、Python 3 向けに書かれたスクリプトに対して Python 2 も許可する場合があります。呼び出し元が制御できるテキストをスクリプトが `input()` に渡す場合、[Python 2 はそのテキストを式として評価します](https://docs.python.org/2/library/functions.html#input)。インタープリターを明示して呼び出すと、スクリプトの shebang は上書きされます。実行経路として扱う前に、インストールされている該当バイナリ、実効 RunAs と引数ポリシー、拒否設定、到達可能な入力を確認してください。

root 権限で実行可能な sudo ルールにスクリプトの固定パスが指定されていても、そのスクリプトが実行する内容までは制限されません。読み取り可能な Bash ラッパーでは、sudo で呼び出し元が引数を選べる場合に、最初の実行コマンドが `$1` などの引用符で囲まれていない位置パラメーターを**コマンド語**として使用しているか確認してください。実効 RunAs ID、パスワードと引数のポリシー、後続の拒否設定、実際に実行されるスクリプトの分岐を確認してください。`NOEXEC`、安全な引数リストの固定、またはコマンドを検証するラッパーによって結果が変わることがあります。列挙中に短いスクリプトを静的に調査し、テストコマンドを使って実行するのは避けてください。

制限のない、root 権限で実行可能な `dotnet` の sudo ルールも、インタープリターの観点から確認する価値があります。.NET SDK がインストールされている場合、[`dotnet fsi` は F# コードを対話的に、またはスクリプトから実行します](https://learn.microsoft.com/en-us/dotnet/fsharp/tools/fsharp-interactive/)。また、[`dotnet run` はソースからプロジェクトを実行します](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-run)。まず実効 RunAs ID と正確な引数ポリシーを確認してください。特定の安全なサブコマンドや信頼されたアプリケーションに限定されたルールは、これとは異なる権限付与です。また、ランタイムのみのインストールでは SDK コマンドが使えない場合があります。実行ファイル名は確認の手掛かりであり、コード実行の証明ではありません。

```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```

## Sudoで許可された `tee`: 任意の特権ファイル書き込み

GNU `tee` は、標準入力をファイルオペランドとして指定されたすべてのパスにコピーします。したがって、呼び出し元が引数を制御できる状態で `/usr/bin/tee` の root 実行を許可する sudo ルールは、任意のファイルを root 権限で作成または上書きできる手段になります。`-a` を追加すると、追記する動作に変わります。`PASSWD:` タグは sudo の認証に関するものであり、それ自体では書き込み先も標準入力から読み取るバイト列も制限しません。<sup>[[2]](#references)[[27]](#references)[[28]](#references)</sup>

まず、正確なルールを確認してください。許可されたテストシステムでは、安全に作成できる使い捨ての書き込み先を使ってのみ、この手段の動作を検証してください。最後の `>/dev/null` は、`tee` が標準出力にコピーする内容を抑制するだけです。<sup>[[28]](#references)</sup>

```bash
sudo -l
printf '%s\n' 'controlled-write' | sudo /usr/bin/tee /root/tee-proof >/dev/null
printf '%s\n' 'appended-line' | sudo /usr/bin/tee -a /root/tee-proof >/dev/null
```

`sudo`をproducerの前に付けても、後続のshellリダイレクトによる権限は昇格しません。出力先を開くのは呼び出し元のshellだからです。上記のpipelineのように、特権プロセスが書き込みを行う必要があります。<sup>[[1]](#references)[[15]](#references)</sup>

書き込みを確認したら、[Arbitrary File Write to Root](../interesting-files-permissions/write-to-root.md)から適切なroot code executionのsinkを選びます。確認されたchainの一例では、root権限の`tee`で`/etc/cron.d/`内に短命のfileを作成し、user-controlled scriptを通じてbackdoorを起動した後、実行後にcron fileを削除していました。cron fileを削除することで長期的なpersistence entryになるのを防げましたが、system logには活動の証拠が残っていました。<sup>[[27]](#references)</sup>

## Sudo-allowed editors

`sudo -l`でユーザーがrootとして対話型editorを実行できる場合、無害なfile編集権限ではなく、command executionの攻撃面として扱ってください。editorは多くの場合、shell commandの実行、任意のfileの読み取りや書き込み、editor内からの外部helperの呼び出しが可能です。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

一般的な確認手順: ユーザーの権限を一覧表示し、sudoを使って許可されている各editorやpagerを起動します。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```

### Nanoによるコマンド実行

`nano` の実行が sudo 経由で許可されている場合、エディタのインターフェースからコマンドを実行できる可能性があります。<sup>[[12]](#references)</sup>

```text
Ctrl+R
Ctrl+X
```

その後、nano のコマンドプロンプトで `id` や `/bin/sh` などのコマンドを入力します。<sup>[[12]](#references)</sup>

```bash
id
/bin/sh
```

対話型シェルで使用可能な端末ストリームがない場合、このリダイレクト形式は標準出力と標準エラーをファイルディスクリプター 0 に割り当てます。<sup>[[15]](#references)</sup>

```bash
reset; /bin/sh 1>&0 2>&0
```

正確なキー操作は nano のバージョンやビルドオプションによって異なる場合がありますが、セキュリティ上の問題は同じです。エディタが root 権限で実行され、外部コマンドを呼び出せる状態になっています。<sup>[[1]](#references)[[12]](#references)</sup>

### その他の一般的なエディタからの脱出方法

Vim 系のエディタでは、一般に `:!` を使ってコマンドを実行できます。<sup>[[13]](#references)</sup>

```text
:!/bin/sh
```

`less`などのpagerでもshell実行が可能になることがあります。<sup>[[14]](#references)</sup>

`apport-cli`をrootとして実行できるsudoルールがある場合も、同様にpagerを確認してください。影響を受けるApportのバージョンでは、攻撃者が端末サイズを調整できる状態で、クラッシュレポートが`less`で開かれることがありました。特定のsudoおよびpagerの条件が満たされると、pagerからroot shellを取得できる可能性がありました。バージョンだけで脆弱と判断する前に、有効なsudoルール、pagerの設定、ディストリビューションのパッケージ修正を確認してください。受動的なenumerationでは、クラッシュを発生させたり、特権付きレポートを開いたりせずに、パッケージとポリシーのメタデータを読み取ってください。[UbuntuのCVEレコード](https://ubuntu.com/security/CVE-2023-1326)には、バックポートされた修正を含む、リリースごとの修正済みパッケージバージョンが記載されています。

```text
!/bin/sh
```

## その他の sudo および doas ルールの危険性

まず `sudo -l`、`sudo -V`、該当する `doas` ポリシーを確認します。許可されたコマンド、実行ユーザー、引数、環境、デフォルト設定をまとめて確認してください。root 以外のサービスアカウントとして実行する権限でも、そのアカウントのファイルや root への経路にアクセスできる場合があります。

sudo で実行を許可された固定の Python スクリプトでも、対話形式で入力された、呼び出し元が制御できる値を [`os.system()`](https://docs.python.org/3/library/os.html#os.system) に連結すれば、RunAs の権限で shell command を実行できる場合があります。shell の句読記号を denylist で排除しても安全性の証明にはなりません。[shell は `$(...)` による command substitution も認識します](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html)。許可された引数が入力処理の分岐に届くこと、入力が安全な検証なしに shell command に渡されること、実効 sudo ポリシーが意図した RunAs user を許可していることを確認してください。スクリプトのパスや `os.system()` の呼び出しだけでは確認の手掛かりにすぎません。特権スクリプトを実行せずにソースを調べてください。

`chattr` を実効的に root で実行できる sudo 権限があれば、ファイルの immutable (`i`) 属性を解除できる場合がありますが、それだけで書き込み権限や新たな identity が得られるわけではありません。[`chattr` のマニュアル](https://man7.org/linux/man-pages/man1/chattr.1.html)によると、この属性は変更を阻止し、変更できるのは root または `CAP_LINUX_IMMUTABLE` を持つプロセスだけです。sudo の正確な引数ポリシーとファイルシステムの対応状況を確認し、属性の解除後に呼び出し元がそのファイルへ書き込めること、および上位の identity で動くプロセスがそのファイルを利用することを個別に確認してください。たとえば login shell の差し替えには、対象アカウントが受け入れる認証情報と、その shell を使った実際のログインも必要です。列挙中に設定を変更せず、ポリシー、ファイル属性、権限を確認してください。

sudo が password と one-time code の両方を要求する場合、それらの前提条件とコマンド許可は分けて考えてください。読み取り可能な `.google_authenticator` ファイルは機密性の高い seed 情報です。一方、古いアプリケーションやデータベースの password hash は、現在のアカウント password の候補にすぎません。いずれも、実効 PAM 設定で別の要素が受け入れられる証明にはなりません。許可を得たうえで、正確な RunAs と引数を確認してください。RubyGems の `gem` を root で無制限に実行できる権限は、editor command を利用できる場合があります（[GTFOBins](https://gtfobins.github.io/gtfobins/gem/)）。ただし、制限付きの許可や認証失敗では該当しません。受動的な列挙では、seed の表示、password の復元、code の生成、特権コマンドの実行をせず、パスとポリシーを報告してください。

Chef の `knife` を root 権限で無制限に実行できる sudo 権限は、interpreter の観点から個別に確認する価値があります。[Chef の説明によると、`knife exec -E` はローカルで Ruby 文字列を評価します](https://docs.chef.io/workstation/26/tools/knife/knife_exec/)。実効 sudo ルールで `exec` subcommand と呼び出し元が指定する `-E` 引数が許可されること、意図した RunAs identity、該当するコマンド拒否や固定引数を確認してください。インストール済みの binary や、他の subcommand だけを許可するルールは確認の手掛かりにすぎません。受動的な列挙では `knife` を実行せず、ルールを報告してください。

対話型 `msfconsole` を root 権限で正確に実行できる sudo 権限も同様に慎重な確認が必要です。[GTFOBins は `irb` console を紹介しています](https://gtfobins.org/gtfobins/msfconsole/)。これは sudo identity を引き継ぐ可能性があります。実効 RunAs user、許可される引数一覧、コマンド拒否、`NOEXEC` などの制限、インストール済み console の挙動、呼び出し元が対話入力を渡せるかを確認してください。パスが強調表示されているだけでは確認の手掛かりにすぎません。受動的な列挙では console を起動しないでください。

FreeBSD では、root としての `pkg update` および `pkg install *` に限定された sudo ルールでも、repository の信頼性を確認する必要があります。呼び出し元が `/etc/hosts` に書き込めるか、実効的に有効な repository 設定が `signature_type: none` の HTTP hostname を使うかを確認してください。[FreeBSD の `pkg.conf` マニュアル](https://man.freebsd.org/cgi/man.cgi?query=pkg.conf&sektion=5)によると、`none` は署名検証を無効化します。`pkg+http` だけでは、その設定が使われているとは限りません。package に install script が含まれる場合があります（[FreeBSD Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/pkg-files/)）。したがって、repository endpoint を実際に制御でき、package を選択できる呼び出し元は root の境界を越えられる可能性があります。結論を出す前に、repository の上書き設定、SRV/mirror の解決、実効 sudo 引数、package の選択、script の実行を確認してください。列挙中に名前解決先を変更したり `pkg` を実行したりせず、ポリシーと小さなローカル設定ファイルを確認してください。

root 権限で `apt-get update` および `apt-get upgrade` を実行でき、sudo が呼び出し元の制御する `http_proxy` を保持する場合も、repository の信頼性を確認する必要があります。実効 APT proxy 設定がその変数を使うか、どの有効な repository request に影響するかを確認してください。proxy だけでは、信頼された署名鍵で認証された archive 内の package を置き換えられません。[APT の HTTP transport マニュアル](https://manpages.debian.org/experimental/apt/apt-transport-http.1.en.html)には proxy の優先順位が、[apt-secure](https://manpages.debian.org/experimental/apt/apt-secure.8.en.html)には署名検証、未認証 repository の上書き設定、未認証 package の確認要件が記載されています。正確な sudo RunAs と引数、repository の認証ポリシー、必要な対話的承認、選択された upgrade が root として package script を実行するかを確認してください。受動的にポリシーとローカル設定を調べ、列挙中に package の通信先を変更したり upgrade を実行したりしないでください。

root 権限で `snap install` を実行できる sudo ルールは、引数によって呼び出し元がローカル snap と制限の緩い install mode を選べる場合、package から code への境界になり得ます。[Snap の説明](https://snapcraft.io/docs/explanation/snap-development/install-modes/)によると、`--dangerous` はローカル snap の assertion 検証を省略し、`--devmode` は confinement を緩和します。[install hook は初回インストール時に実行されることがあります](https://snapcraft.io/docs/reference/development/supported-snap-hooks/)。protected host file へのアクセスを主張する前に、正確な sudo の引数／RunAs ポリシー、snap file の管理者、インストール済み snapd がこれらの mode を受け入れるか、hook の実効 identity と confinement を確認してください。`snap` binary や wildcard のように見えるルールだけでは、この経路の証明になりません。受動的な列挙では package をインストールせず、hook も実行しないでください。

**root 以外**のアカウントの、credential を読む独自 binary を正確に実行できる sudo 権限では、まず実行せずに許可された binary とファイル権限を確認してください。埋め込まれた password gate は、wide character として格納されている場合があります。[GNU `strings` には 16-bit little-endian の抽出方法が記載されています](https://sourceware.org/binutils/docs/binutils/strings.html)。文字列が見つかっても、それが受け入れられる password であることや、成功分岐が現在の credential を公開することの証明にはなりません。binary の挙動、保護データへの対象アカウントのアクセス、credential の有効性、その後に別のアカウントや group へ移行する経路を個別に確認してください。そのアカウントが `docker` group に属する場合は、host root へのアクセスを推論する前に socket へのアクセスと daemon の rootful/rootless identity を確認してください。[Docker の説明では、この group が持つ root レベルの影響が記載されています](https://docs.docker.com/engine/install/linux-postinstall/)。通常の列挙では、binary を実行したり strings を出力したりせず、sudo ルールと group 所属を報告してください。

アプリケーションのメンテナンス script に対する wildcard sudo ルールは、script path 以外も確認する必要があります。許可された script が制限のない引数を受け取るか、権限の低いアプリケーションアカウントから書き換え可能な設定を読むかを確認し、その値を shell command や subprocess の環境まで追跡してください。たとえば ZoneMinder の [`zmupdate.pl` は `mysqldump` command を組み立て、`qx` で実行します](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmupdate.pl.in)。また、[`zmdc.pl` は daemon 起動前に `ZM_LD_PRELOAD` 設定を `LD_PRELOAD` にコピーします](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmdc.pl.in)。対応する入力を制御でき、その入力がインストール済み version の該当コードに届くなら、どちらかの script を root として実行する sudo ルールは信頼境界を越える可能性があります。実効 sudo ルール、アプリケーション設定への書き込み権限、script のソースを確認してください。wildcard や設定値だけでは、実行の証明にならず、確認の手掛かりにすぎません。

- `SETENV`、`env_keep`、`secure_path`、`LD_PRELOAD` は、範囲が狭いコマンドでも import、library、PATH hijack を可能にする場合があります。[環境変数ガイド](../linux-basics/linux-environment-variables.md)と[SUID/linker abuse](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md)を参照してください。

root 権限で実行できる正確な `SETENV` 付き shell wrapper も、wrapper が固定 Python script を文字列で import する場合は、1 段階先まで確認する必要があります。`secure_path` が制限するのは shell command の検索であり、Python の[`PYTHONPATH` module 検索](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH)ではありません。[`-E` と `-I`](https://docs.python.org/3/using/cmdline.html#cmdoption-E) を指定すると、Python はその環境変数を無視します。code execution とみなす前に、実効 sudo tag と拒否設定、wrapper の分岐、interpreter option、import 解決、呼び出し元が書き込める検索 directory を確認してください。短い script は静的に調べ、特権 wrapper は実行しないでください。

`XDG_CONFIG_HOME` を保持する関連 sudo default がある場合、root 権限での正確な `neofetch ""` sudo 許可でも shell configuration を読み込む可能性があります。[Neofetch の configuration loader](https://github.com/dylanaraps/neofetch/blob/master/neofetch) は、その directory 配下の `neofetch/config.conf` または `neofetch/config` を source します。引数が空でも、この検索は阻止されません。インストール済み loader、実効 RunAs と引数ポリシー、コマンド拒否の有無、sudo がこのコマンドで実際に選択した変数を保持するか、呼び出し元が読み取り可能な configuration path を制御するかを確認してください。変数が保持されることや Neofetch がインストールされていることだけでは、確認の手掛かりにすぎません。特権コマンドを実行したり configuration の内容を出力したりせずに、ポリシーとファイル metadata を確認してください。[sudoers の環境変数処理](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)も参照してください。

root 権限で `facter` を無制限に実行できる sudo ルールでは、custom fact も別途確認が必要です。[Puppet の説明](https://help.puppet.com/core/current/Content/PuppetCore/loading_custom_facts.htm)によると、`--custom-dir` は選択した directory から Ruby fact file を読み込みます。正確な sudo ルールでその option が許可されるか、インストール済み Facter が受け入れるか、呼び出し元がその directory を制御できるかを確認してください。固定引数のみの許可、明示的なコマンド拒否、custom fact の無効化によって結果は変わる場合があります。受動的な列挙では Facter を実行したり fact の内容を読んだりせず、候補となるポリシーを報告してください。

root 権限で正確に実行できる `SETENV` 付き sudo script では、`find` のような bare command name と、sudo ポリシーおよび script 初期化後の実効 `PATH` を確認してください。source された Bash file が `enable -n [` を実行する場合もあります。[Bash はその後 `PATH` から外部の `[` を検索します](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)。適用される[sudoers の環境および `secure_path` ルール](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)、`NOSETENV`／`NOEXEC` や拒否ルール、script と source file の処理、呼び出し元が制御できる実行可能な検索 directory を確認してください。script に bare command が記載されているだけでは、特権実行の証明にならず、確認の手掛かりにすぎません。sudo ルールを実行せずに調べてください。
- 固定 URL を `curl` で取得する特権 script でも、適用される sudo ルールが呼び出し元の制御する `http_proxy` を保持し、request がその proxy を経由する場合、呼び出し元が response を選べる可能性があります。その後、script が外部 entity を解決する XML parser に response を渡すと、悪意ある response により特権プロセスが読み取り可能な file が漏洩する可能性があります。正確な sudo 環境ポリシー、`no_proxy` の除外設定、要求 URL、parser の設定、出力先を確認してください。proxy 変数や XML parser があるだけでは脆弱性ではありません。[curl の proxy 環境変数に関するドキュメント](https://everything.curl.dev/usingcurl/proxies/env.html)には変数の挙動が記載されています。受動的な列挙では network request を送信したり、悪意ある XML を parse したりしないでください。
- 呼び出し元の影響を受けるデータから PostScript file を作成し、その後 `ps2pdf -dNOSAFER` を実行する root 権限の sudo script は、入力からのデータフローを個別に確認する必要があります。Ghostscript の説明によると、この flag は `.setsafe` が呼び出されるまで SAFER を無効化し、プロセスの OS 権限内での PostScript file 操作を許可します。呼び出し元の引数から組み立てられた SQL query が、攻撃者の制御する行を PostScript template に渡す場合があります。しかし、query string や `ps2pdf` の呼び出しだけでは、そのデータが実行可能な PostScript 構文に届く証明になりません。実効 sudo ルール、入力から template までの正確な経路、escape 処理、インストール済み Ghostscript の挙動、document の解釈前に SAFER が再有効化されるかを確認してください。受動的な列挙では特権変換を実行しないでください。[Ghostscript の `-dNOSAFER` ドキュメント](https://ghostscript.readthedocs.io/en/master/Use.html)を参照してください。
- shell script を実行する sudo ルールでは、保持される変数と script 自体を照らし合わせてください。`if $CHECK_CONTENT; then` のような構文は、展開された値を command として実行します。したがって、script path と引数が固定されていても、`CHECK_CONTENT` を保持すると command execution が可能になる場合があります。その分岐に到達できるか、環境変数が実際に保持されるかは、個々のルールで確認が必要です。<sup>[[2]](#references)[[22]](#references)</sup>
- sudo で実行を許可された Python script は、書き込み可能な directory や cache 済み `.pyc` file から code を import する場合があります。[privilege escalation guide](../linux-basics/linux-privilege-escalation/README.md)では cache のケースを説明しています。
- root として実行を許可された固定 Python script でも、対話型 debugger が公開されている可能性があります。`pdb.set_trace()` や `pdb.post_mortem()` などの呼び出しは、呼び出し元が breakpoint や exception handler に到達でき、かつ **debugger の入力 stream を制御できる**場合に、debug 対象プロセスの context で Python statement を実行できます。正確な sudo RunAs ルール、認証と分岐条件、exception に到達可能か、terminal/input の所有者、debugger が同じ特権プロセスで動くかを確認してください。別の terminal に接続された debugger へのアクセスは、socket request によって exception を発生させるだけでは得られません。[Python のドキュメントには debugger による statement の評価と post-mortem mode が記載されています](https://docs.python.org/3/library/pdb.html)。列挙中に特権 handler を起動せず、script を静的に調べてください。
- sudo で実行を許可された固定 Python script が、database や Unix socket から profile field を読み取り、後で `str.format()` の **format string** になる文字列に追加する場合もあります。[replacement field は attribute や mapping key をたどれます](https://docs.python.org/3/library/string.html#format-string-syntax)。攻撃者が制御できる field は、`format()` に渡された object を調べ、結果が出力されるか、呼び出し元が読み取れる場所に保存される場合、そこからアクセス可能なデータを露出させる可能性があります。実効 sudo RunAs identity、該当 record への書き込み権限、format string への data flow、渡される object、出力の可視性を確認してください。これは自動的な code execution ではありません。また、信頼できる固定の format string に攻撃者が制御する *値* を渡すケースとは異なります。漏洩した secret が OS account への移行に使えるのは、その account が受け入れる場合だけです。特権操作を実行せず、script と socket の権限を確認してください。
- root 権限の Python wrapper が、呼び出し元の選択した URL を GitPython の `Repo.clone_from` に渡す場合があります。さらに wrapper が Git の `protocol.ext.allow=always` を有効化すると、`ext::` remote が外部 helper を呼び出す可能性があります。正確な sudo 引数、URL の取得元、GitPython package の version と vendor patch の有無、wrapper が unsafe protocol を明示的に許可しているかを確認してください。GitPython 3.1.30 では[unsafe protocol をデフォルトで防ぐ機能](https://github.com/gitpython-developers/GitPython/commit/2625ed9)が追加されました。`git` executable の version は別途確認が必要です。受動的な確認では、clone を実行せず、ルールと限定された範囲のソースだけを読みます。
- repository を clone する CLI を別ユーザーで実行する sudo 権限は、shell string injection の別経路を生む可能性があります。呼び出し元が選んだ repository 引数が、Node.js の [`child_process.exec`](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback) や他の shell command builder に、安全な引数分離なしで届くかを追跡してください。Node の `exec` は command string を shell に渡します。正確な RunAs user、許可される subcommand と引数、インストール済み wrapper の code、入力検証を確認してください。repository tool の名前や無制限の sudo ルールだけでは command injection の証明になりません。列挙中に特権 clone を実行せず、wrapper を調べてください。
- root 所有の独自 wrapper は、その binary と script が書き換え不可でも、特権操作を実行する判断が、一般ユーザーが変更できる flag、ローカル API の値、service の状態に依存する場合があります。各 gate の入力と認可検査を追跡してください。列挙中は稼働状態を変更せずに設定と権限を調べます。wrapper 内の `systemd-run` 呼び出しが関係するのは、その gate に影響を与えられる場合だけです。
- sudo で root として実行を許可された backup client は、呼び出し元が設定 file を選択できる場合があります（例: `npbackup-cli -c`）。正確な RunAs user と許可引数を確認し、呼び出し元が設定 path、backup source path、repository、read/restore option を制御するかを調べてください。読み取り可能な設定内の暗号化された repository secret は client で利用できる場合がありますが、ルールだけでは repository へのアクセスや root file の漏洩は証明できません。backup を実行したり、内容を出力したりせずに認可を確認してください。
- [Restic](https://github.com/restic/restic/blob/master/doc/030_preparing_a_new_repo.rst) は、repository password を取得する program を呼び出す `--password-command` に対応しています。sudo ルールが、権限の低いユーザーに、呼び出し元が指定した password command と password が必要な subcommand を root として実行させる場合、その helper が root として実行される可能性があります。正確な sudo 引数と除外設定を確認してください。この条件を列挙するためだけに helper や backup command を実行しないでください。
- root 権限での `restic backup` 許可は、sudo 引数の pattern によって、呼び出し元が source と、後から読み取り・復号できる repository の両方を選択できる場合、file read の境界を越える可能性もあります。[sudoers の引数 wildcard は空白や slash にも一致します](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)。したがって、固定 repository prefix が source を制限すると決めつけず、末尾の wildcard を確認してください。[Restic は local と remote の repository に backup できます](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html)が、local repository には新たに書き込まれた root 専用 object が含まれる可能性があります。漏洩と判断する前に、実効 sudo ポリシー、backend access、repository password、生成される object の権限を確認してください。backup に含まれた SSH key が login に使えるのは、接続先 account がそれを受け入れる場合だけです。受動的な確認中に backup を実行して検証しないでください。
- 無制限の独自メンテナンス／backup command は、出力 path を受け付けたり、独自の job scheduler を備えたりする場合があります。file write 経路では、正確な sudo ルールと RunAs user を確認し、呼び出し元が data と宛先の両方を制御するかを調べてください。scheduled command 経路では、scheduler の実行 identity、command input、追加の password や認可 gate を確認してください。command 名や `NOPASSWD` だけでは、どちらの経路も証明できません。[root-owned file への書き込み](../interesting-files-permissions/write-to-root.md)および[cron と systemd timer](../processes-crontab-systemd-dbus/cron-and-systemd-timers.md)を参照してください。
- 固定 sudo command でも、共有書き込み可能 directory から予測可能な configuration file を読み込む場合があります。呼び出し元がその file を置き換えられるか、その source／destination field が特権的な fetch や copy を制御するかを追跡してください。ローカル file URL からは sudo RunAs account のみが読める data が漏洩する可能性があります。呼び出し元が制御する source と保護された destination の組み合わせは、write 経路になる場合があります。インストール済み program の URL 処理、destination path の検査、実効 sudo ルール、出力へのアクセス性を確認してください。書き込み可能な `/tmp` configuration path だけでは確認の手掛かりにすぎません。特権転送を実行せずに binary と file metadata を調べてください。
- `git apply` の sudo ルールは、呼び出し元が制御する patch で RunAs account に file を書かせる可能性があります。[CVE-2023-23946](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh) では、command が `--unsafe-paths` を受け付けない場合でも、細工された patch が symlink を作成し、working tree の外に書き込むことができました。実効 sudo 引数ルール、patch の取得元、RunAs account が working directory にアクセスできるか、インストール済み Git の修正または vendor backport を確認してください。`--unsafe-paths` を許可する無制限のルールは、別個に明示的な option のリスクがあります。Git の version や `git apply` の許可だけでは、保護された file を変更できる証明になりません。受動的な列挙では信頼できない patch を適用しないでください。
- root 権限での `clamscan --debug` ルールは、権限の低いユーザーが DMG image を指定でき、インストール済み parser が、debug output 経由で file 内容を漏洩し得る[CVE-2023-20052](https://blog.clamav.net/2023/02/clamav-01038-01052-and-101-patch.html)の影響を受ける場合、read 境界を越える可能性があります。正確な許可引数と scan path、入力を制御できるか、実効 RunAs account、engine の修正／backport、呼び出し元が出力を確認できるかを調べてください。より広いルールで `--file-list`／`-f` が許可される場合は、その file-list の挙動を個別に確認してください。`--debug <scan-path>` に固定されたポリシーでは、その option は許可されません。列挙中に細工された file を scan したり、保護された出力を表示したりせず、ポリシーと package metadata を確認してください。
- root 権限で、呼び出し元が選択した暗号化 disk image を開く sudo ルールと、生成された mapper を mount する別のルールは、呼び出し元が制御する file を host の mount namespace に取り込む可能性があります。両方の実効ルールと引数、image と mapper 名を制御できるか、実際の mount target、取り込まれる file の所有者と mode を確認してください。set-user-ID への移行には、アクセス可能な executable、set-user-ID を有効にする mount option（`nosuid` は無効化します）、適用される process／MAC policy も必要です。image を開いたり mount したりするだけでは確認の手掛かりにすぎません。既存 backup を介する別経路には、実際に使える key と、内部に含まれる有用で読み取り可能な secret が必要です。受動的な列挙では image を開いたり mount したりせず、ポリシーと path を調べてください。[cryptsetup のマニュアル](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)および[mount option](https://man7.org/linux/man-pages/man8/mount.8.html)を参照してください。
- root 権限で実行できる shell／Python script が、固定 directory へ移動せずに `./helper` を呼び出す場合、working directory も確認してください。`subprocess.run` に渡す `['./helper']` という Python list も、呼び出し元が選ぶ working directory の影響を同様に受ける場合があります。呼び出し元が書き込み可能な directory を選び、そこにその相対名の executable を置ける可能性があります。script 内の別の場所で absolute path を使っていても、この呼び出しは保護されません。code execution とみなす前に、実効ルール、`runchdir` などの directory 変更ポリシー、script の処理と分岐到達性、書き込み可能かつ実行可能な directory、mount／`NOEXEC` の制限を確認してください。script が読めない場合は、認可された経路でソースを確認するまで挙動は不明です。helper を実行するのではなく、script を静的に確認してください。[sudoers のマニュアル](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)には working directory のポリシーが記載されています。
- root 権限で実行できる固定 Python validator でも、呼び出し元が選択した data file を評価する可能性があります。[Python の `eval()` ドキュメントは信頼できない入力を避けるよう警告しています](https://docs.python.org/3/library/functions.html#eval)。入力末尾の確認、算術演算子の prefix、検証分岐は、残りの式が `eval` に届くなら sandbox にはなりません。実行経路と判断する前に、実効 sudo ルール、呼び出し元が正確な file を選択・制御できるか、parser の分岐条件と式の構築、特権プロセスの identity を確認してください。読み取り可能な script に `eval` があるだけでは確認の手掛かりにすぎません。列挙中に validator を実行したり、test expression を入力したりせず、ソースと file 権限を調べてください。
- root 権限で実行される Ruby wrapper が、`YAML.load(File.read("dependencies.yml"))` のように相対 YAML file 名を読む場合、wrapper または sudo ポリシーが directory を固定しない限り、呼び出し元の working directory から入力を取る可能性があります。正確な許可引数、directory と file の権限、インストール済み Psych の挙動を確認してください。以前の `YAML.load` 実装では任意の Ruby object を deserialize できましたが、新しい release ではデフォルトで class が制限されます。static な呼び出し箇所は確認の手掛かりにすぎません。呼び出し元が書き込み可能な directory から実際に file を読み込むこと、およびインストール済み loader が危険な class を受け入れることを確認してください。信頼できない入力には、明示的で最小限の class allowlist を指定した `safe_load` を優先してください。[Ruby 3.0 Psych ドキュメント](https://docs.ruby-lang.org/en/3.0/Psych.html)および[Ruby 3.1 Psych ドキュメント](https://ruby-doc.org/core-3.1.2/Psych.html)を参照してください。

- `sudo go run /absolute/file.go` を root 権限で正確に実行できる場合、Go source が相対 WASM file を読み込み、その結果を調べてから相対 shell script を実行する可能性があるなら、working directory を確認してください。実効 RunAs、command 引数と拒否設定、呼び出し元が書き込み可能な current directory、WASM から分岐までの data flow、その分岐から helper が呼び出されるかを確認してください。固定 sudo `runchdir`、`os.Chdir`、[`exec.Cmd.Dir`](https://pkg.go.dev/os/exec) によって検索場所が変わる場合があります。同じ file 内にコードが併記されているだけでは候補にすぎません。Go、WASM、helper を実行せずにソースを調べてください。
- `sudoedit` と引数 wildcard では、正確な version とルールの確認が必要です。[checklist](linux-privilege-escalation-checklist.md)では sudoedit の file 編集に関する問題を扱っています。別ユーザーに対する wildcard path の `sudoedit` 許可では、実効 `sudoedit_follow`／`FOLLOW` 設定、`sudoedit_checkdir`、解決後の target、各親 entry を置き換えられるユーザーを調べてください。前者は symlink の追跡を許可する場合があり、後者を無効にすると書き込み可能 directory の検査がなくなります。しかし、いずれの設定も単独では他ユーザーの file への書き込みを証明しません。結論を出す前に、インストール済み sudo ポリシーと実際に一致する引数を確認してください。[sudoers option の定義](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)も参照してください。
- sudoers command ルールでは、引数 wildcard は path 文字だけでなく空白にも一致します。read 権限を持つ command に `/restricted/*` のような引数を指定するルールは、一致する prefix の後ろに追加の file 引数を許可する場合があります。正確な RunAs user、command path、引数 pattern、その後の拒否設定を確認してください。file を読めることが実証されても、command execution を意味するわけではありません。[sudoers のマニュアル](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)では、引数 glob と command path glob を区別しています。
- path に見える引数 glob は `../` にも一致する場合があります。たとえば、root 権限の `node /opt/scripts/*.js` ルールでは、指定 path が `/opt/scripts/` で始まり、親 directory をたどって解決されるなら、呼び出し元が `/opt/scripts` 外の JavaScript file を指定できる可能性があります。これは **引数** glob です。Node executable に対する command path glob では slash の一致規則が異なります。code execution と結論づける前に、実効ルール、その後の拒否設定、path 解決、target file を制御できるか、sudoers の正規表現／digest 制限を確認してください。[sudoers の wildcard 規則](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)および[Node の command-line ドキュメント](https://nodejs.org/api/cli.html)を参照してください。
- archiver などの utility program には execution hook がある場合があります。shell や interpreter だけが command を実行できると決めつけず、正確に許可される引数を[GTFOBins](https://gtfobins.github.io/)で確認してください。
- root 権限での無制限な `qpdf` ルールは、PDF attachment を介して特権 file を露出させる可能性があります。qpdf 10.2 以降は、出力 PDF と組み合わせた `--empty`、`--add-attachment file ... --` に対応しています。特権プロセスが選択された source を読み取れ、呼び出し元がアクセス可能な path に PDF を書ける場合、出力に source bytes が含まれる可能性があります。file disclosure が可能と結論づける前に、実効 sudo 引数と除外設定、qpdf version、source へのアクセス、出力 path を確認してください。root SSH key を読めても、その key が有効で root SSH authentication が許可されている場合に限り login に役立ちます。[qpdf の attachment option](https://qpdf.readthedocs.io/en/stable/cli.html#embedded-files-attachments)を参照してください。
- sudo timestamp の再利用は、cache ポリシー、所有 user、terminal/session、権限に左右されます。[privilege escalation guide](../linux-basics/linux-privilege-escalation/README.md#reusing-sudo-tokens)で確認事項を説明しています。
- `doas` には独自のルールと設定があります。[doas の項目](../linux-basics/linux-privilege-escalation/README.md#doas)を参照し、許可される command と書き込み可能な設定 path を確認してください。

### sudo で実行する build／package tool

Foundry の `forge` を無制限に実行できる sudo 権限は、RunAs identity が root 以外のユーザーでも問題になり得ます。`--use` などの compiler option でローカル executable を選択でき、`forge flatten -o` で出力 file を指定できます。権限を悪用可能とみなす前に、インストール済み Forge version、正確な sudo 引数、アクセス可能な project と compiler path、出力権限、実効環境を確認してください。`PATH` を介して見つかる相対 helper executable は、version と環境に依存する経路であり、すべての Forge build にあるとは限りません。<sup>[[23]](#references)[[24]](#references)</sup>

root 権限での無制限な `pacman` 許可では、package query 以外も実行できます。`-U` はローカル package を受け入れ、package に install script が含まれる場合があり、`--hookdir` で別の hook directory を指定できます。テストする前に、実効 sudo ルール、引数制限、除外設定を確認してください。受動的な列挙で package をインストールしたり hook を実行したりする必要はありません。<sup>[[25]](#references)[[26]](#references)</sup>

固定された sudo shell wrapper が、指定された npm dependency をインストールしてから Node application を起動する場合もあります。正確な RunAs ルール、package がすでにインストール済みか、実効 `HOME` と npm `userconfig`、project 設定や command-line の上書き、権限の低いユーザーがその名前に対して取得される registry／package を制御できるかを確認してください。[npm にはユーザー単位と project 単位の `.npmrc` 読み込みが記載されています](https://docs.npmjs.com/cli/v6/configuring-npm/npmrc/)。sudo の `HOME` の挙動はインストール済みポリシーと distribution によって異なるため、権限の低いユーザーの `.npmrc` が特権 npm process に読み込まれるとは限りません。新たにインストールされた package が特権 application に import される場合、その module code は application の identity で実行される可能性があります。install-time script は別の経路であり、version と設定に依存します。[npm にはその lifecycle と user の扱いが記載されています](https://docs.npmjs.com/cli/v6/using-npm/scripts/)。`.npmrc` の path や `npm install` の行だけでは、確認の手掛かりにすぎません。受動的な列挙では install や application の起動をせず、ルール、短い wrapper、設定 path、package の出所を調べてください。

root 権限での `pip` または `pip3 download` 許可も、引数で呼び出し元が信頼できない source distribution を選択できる場合、package build の確認が必要です。URL pattern がローカル service と `.tar.gz` suffix に制限されていても同様です。`pip download` は archive URL を受け付け、package metadata を解決します。sdist の準備時には、archive を保存するだけの段階に至る前に、build backend や旧来の `setup.py` code が実行される場合があります。正確な sudo RunAs と引数ルール、呼び出し元が選択した archive を公開／差し替えできるか、その pip version が実際に metadata を準備するかを確認してください。固定された信頼済み archive や wheel では、この経路の証明になりません。受動的な列挙では信頼できない package を取得・build しないでください。pip の[download command](https://pip.pypa.io/en/stable/cli/pip_download/)、[build-system interface](https://pip.pypa.io/en/stable/reference/build-system/)、[secure-install のガイダンス](https://pip.pypa.io/en/stable/topics/secure-installs/)を参照してください。

呼び出し元が選択したローカル project path で `pip install` を許可する sudo ルールは、より直接的な build 境界です。[pip はローカル project directory を受け付け](https://pip.pypa.io/en/stable/topics/local-project-installs/)、その build system を呼び出します。[build backend は project が制御する build hook を実行します](https://pip.pypa.io/en/stable/reference/build-system/)。このルールを特権 code execution とみなす前に、実効 RunAs identity、正確な引数制限と拒否設定、選択された project を制御できるか、インストール済み pip／backend の挙動を確認してください。固定された信頼済み project や、呼び出し元が path を選べないルールでは、この経路は成立しません。受動的な列挙では package をインストールせず、ルールと project metadata を確認してください。

root 権限での無制限な `easy_install` 許可も、関連する旧式 package build の確認事項です。[Setuptools の説明](https://setuptools.pypa.io/en/stable/deprecated/easy_install.html)によると、Easy Install はローカル project directory を受け入れ、source distribution を build します。呼び出し元が制御する project は、その build 中に sudo identity で `setup.py` を実行する場合があります。実効 RunAs account、正確な command と引数制限（後続の拒否設定を含む）、選択された project を制御できるか、インストール済み tool の挙動を確認してください。固定された信頼済み project や、呼び出し元が source を選べないポリシーでは、この経路は成立しません。列挙中に package をインストールせず、ルールと project metadata を調べてください。

呼び出し元が選んだ URL を使って `setuptools.package_index.PackageIndex.download` を呼び出す sudo 許可 Python wrapper は、`pip download` とは別の確認対象です。[setuptools GHSA-5rjg-fvgr-3xxf](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf)では、78.1.1 より前の影響を受ける release において、URL から生成された filename が意図した download directory の外に解決され、プロセス権限で書き込まれる問題が説明されています。実効 sudo RunAs と引数ルール、wrapper が呼び出し元の URL をこの API に正確に渡すか、インストール済み build または vendor backport、生成された path の解決先を確認してください。version string や書き込み可能な download directory だけでは、任意の場所への書き込みの証明になりません。列挙中に URL を取得したり file を書き込んだりせず、短い wrapper と package metadata を調べてください。

呼び出し元が選択した `.spec` file を PyInstaller に渡す sudo 許可 build wrapper では、同様の信頼境界の確認が必要です。PyInstaller spec は **build 時**に評価される executable Python であり、`datas` entry によって build identity から読み取り可能な file を artifact に同梱できます。正確な RunAs user、sudo の引数と拒否ルール、wrapper の path と分岐処理、指定された spec file を制御できるか、生成された artifact にアクセスできるかを確認してください。`.py` input が許可されているだけ、あるいは PyInstaller がインストールされているだけでは、spec file の制御や特権実行の証明になりません。受動的な確認では wrapper の限定的な範囲と metadata のみを読み、build を実行しないでください。[PyInstaller spec-file ドキュメント](https://pyinstaller.org/en/stable/spec-files.html)を参照してください。

### sudo で実行する preset／plugin loader

呼び出し元が選択した preset／plugin directory を受け付ける Python tool は、sudo で与えられた権限を使って code を import する場合があります。たとえば BBOT は `-p` で preset を受け付け、[custom module ドキュメント](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/#load-modules-from-custom-locations)には追加の Python module directory を選択する `module_dirs` entry の説明があります。実効 sudo ルールが呼び出し元の選択した preset を許可し、呼び出し元が指定 directory 内の module を制御できる場合、tool が無効な module を拒否する前に、その import で特権ユーザーとして code が実行される可能性があります。列挙中に module を読み込まず、インストール済み version、正確な sudo の RunAs と引数ポリシー、preset／module path の所有者を確認してください。

### sudo で実行する Backdrop command-line tool

[Bee](https://github.com/backdrop-contrib/bee) は Backdrop CMS 用の PHP command-line tool です。`eval` (`php-eval`) と `php-script` command は、呼び出し元が指定した PHP を実行できます。Bee が Backdrop installation を bootstrap できる場合、root 権限で Bee executable を無制限の引数付きで許可する sudo ルールは、root code execution につながる可能性があります。site directory から実行するか、global `--root=<directory>` option で site を選択します。Bee や Backdrop の `settings.php` file が見つかっただけでは、sudo 許可、利用可能な site、bootstrap の成功は証明されません。テスト前に、実効 sudo ルール、command 除外設定、executable の identity、site へのアクセスを確認してください。受動的な列挙では Bee を実行せず、ルールと file path を調べてください。PHP command の追加については[Bee command changelog](https://github.com/backdrop-contrib/bee/blob/1.x-1.x/CHANGELOG.md)を参照してください。

### sudo で実行する terminal server

`mosh-server` は呼び出し元の user として対話型 terminal server を起動します。高い UDP port と session key を選び、両方を呼び出し元に通知します。また、client が接続すると通常はその user の login shell を起動します。したがって、root 権限で `mosh-server` を無制限に実行できる sudo 許可は、server command 自体が detach する場合でも、shell の確認候補です。server を起動せずに、実効 RunAs identity、許可引数と除外設定、インストール済み binary、shell、client の利用可否、UDP access を確認してください。受動的な列挙では sudo ルールを調べるだけにとどめ、server を起動したり実際の session key を表示したりしないでください。[Mosh server のマニュアル](https://manpages.debian.org/unstable/mosh/mosh-server.1.en.html)および[upstream の設計説明](https://github.com/mobile-shell/mosh#how-it-works)を参照してください。

### 呼び出し元の task file を書き換える特権 backup wrapper

root として実行される shell wrapper が、呼び出し元の選択した task file を受け取り、source path から `../` を除去し、結果が許可 directory で始まることを確認してから task file を書き換え、その *path* を backup program に渡す場合があります。変換後の path を完全に canonical 化して確認してください。文字列を一度だけ置換する処理では、字句的な prefix 検査を通過する新しい traversal sequence が作られる可能性があります。backup program が書き換え済みのメモリ内データを読むのか、file を再度開くのかも確認してください。再度開く場合、書き換えに失敗すると元の入力 file が残る可能性があります。

Linux では、`fs.protected_regular` によって、world-writable かつ sticky な directory 内にある他ユーザー所有の regular file に対する `O_CREAT` 書き込みが拒否される場合があります。この拒否は保護になりますが、書き込み error を無視する shell wrapper は、元の task file を使って処理を続ける可能性があります。設定、file の所有者と directory、失敗時に wrapper が停止するかを確認してください。file disclosure の候補となるのは、実効 sudo ルールが特権ユーザーとして wrapper を許可し、呼び出し元が task input と読み取り可能な backup destination を制御でき、backup utility が実際に保護対象を含める場合だけです。列挙中に backup を実行せず、これらの条件を調べてください。

### 特権 packet tool の引数 wildcard

`tcpdump` の sudo ルールで **引数 pattern** に `*` がある場合、空白や slash にも一致するため、path に見える制限が追加の option text を許してしまう可能性があります。これは command の executable path にある wildcard とは異なります。RunAs ルール全体と後続の拒否設定を確認してください。option の注入が可能なら、許可される呼び出し方とインストール済み [`tcpdump` option の挙動](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)によって、`-F`、`-V`、`-r`、`-w`、`-Z` が有用な read/write primitive になるかが決まります。`-V` は任意の一般 file を dump するのではなく、capture filename の一覧を読み込みます。sudo が command を許可していても、AppArmor などの MAC policy が file access を阻止する場合があります。disk 上に profile file があるだけでは、ロード済みまたは enforce 中の証明にはなりません。結論を出す前に、認可とポリシーを受動的に確認してください。[sudoers のマニュアル](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)には wildcard の違いが記載されています。

`tcpdump` executable だけを列挙し、引数制限のない root 権限 sudo ルールも確認対象です。[tcpdump のマニュアル](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)によると、`-C` または `-G` によって保存 capture が rotate されると、`-z` が post-rotation command として実行されます。`-Z` や compile 時のデフォルトによって、その command の実行前に権限を落とす場合があります。このルールを escalation 経路とみなす前に、実効 sudo ルール、インストール済み build、権限低下の挙動、rotation が発生可能かを確認してください。強調表示されたルールは候補であり、root command execution の証明ではありません。

### sudo で実行する Nmap wrapper

sudo で許可された `nmap` path が shell wrapper である場合、許可された正確な path と転送されるすべての option を確認してください。よく知られた `--script` 表記を禁止しても、NSE code の読み込みを必ずしも防げるわけではありません。Nmap の[`--datadir`](https://nmap.org/book/man-misc-options.html) は data file を選択し、scripting が有効な場合、NSE は選択された data directory から [`nse_main.lua` を読み込みます](https://nmap.org/book/nse-implementation.html)。インストール済み build によっては別の long-option 表記も受け入れるため、制限とその binary の実際の parser を照合してください。[`--excludefile`](https://nmap.org/book/man-target-specification.html) は別の file read 面です。parser error が text を漏洩する場合もあります。列挙中に scan を実行せず、実効 sudo ルール、wrapper の処理、Nmap version、directory を制御できるか、MAC policy を確認してください。

### sudo で実行する Mercurial pull hook

固定 source を指定した `sudo hg pull /fixed/source` でも、command が `-R` で固定しない限り、pull 先の**受信側** repository は current working directory によって選択されます。呼び出し元が制御する受信側 repository は `.hg/hgrc` に hook を定義でき、hook は sudo RunAs user として実行される場合があります。[Mercurial は信頼されていない user または group が所有する repository 設定を無視します](https://mercurial-scm.org/help/topics/config)。code execution とみなす前に、RunAs account の信頼済み user／group と正確な working directory を確認してください。受動的な確認ではポリシーと設定を読むだけで十分です。列挙のために pull や hook の呼び出しを行わないでください。

### sudo で実行する Git pull hook

root 権限で `sudo git pull` を正確に実行できる場合、working directory で選択される**受信側** repository も確認してください。呼び出し元が所有する repository には、Git process の identity で pull が実際に merge を正常実行した際に動く executable `post-merge` hook を置ける場合があります。[Git の hook ドキュメント](https://git-scm.com/docs/githooks)および[pull の merge／rebase に関する挙動](https://git-scm.com/docs/git-pull)を参照してください。実効 sudo ルールと CWD、active hook path とその権限、新しい commit を伴う merge に到達できるかを確認してください。失敗、何も起きない場合、または rebase のみの場合は、この hook 経路の証明になりません。特権 pull を実行せず、ポリシーと repository metadata を調べてください。

### sudo で実行する rsync archive copy

`sudo rsync -a ... /writable/source/* /fixed/destination/` の場合、**sudoers の引数 pattern** にある `*` は空白にも一致するため、source と destination の間に追加 option を許可する可能性があります。これは filename に対する shell expansion とは別です。呼び出し元が source を設定でき、destination に特権 rsync process が書き込める場合、[`--chown`](https://download.samba.org/pub/rsync/rsync.1) によって特権的な所有者を指定しつつ、archive mode が permission bit を保持し、所有権付き SetUID file を作成できる可能性があります。正確な[sudoers wildcard の意味](https://man7.org/linux/man-pages/man5/sudoers.5.html)、rsync version、後続の拒否設定、filesystem の `nosuid`、MAC policy を確認してください。一致するルールは確認候補であり、特権 escalation の成功を証明するものではありません。

### sudo で実行する packet-filter rule export

`iptables` と `iptables-save`（または対応する `ip6tables` の組み合わせ）の両方を root 権限で無制限に実行できる場合、file write の確認が必要です。`comment` match は呼び出し元が選択した rule text を受け入れ、`iptables-save -f` は選択した path に rule set を書き出します。<sup>[[20]](#references)[[21]](#references)</sup>有用な payload になるかは、インストール済み backend が comment をどのように serialize するか、destination file が export 内の他の行を受け入れるかによります。`iptables-save` だけでは、任意の内容を指定して書き込めません。正確な sudo RunAs identity、引数と除外設定、利用可能な match extension、backend、destination の権限を確認してください。列挙中は firewall rule を変更したり file に書き込んだりせず、許可設定を調べてください。

### 特権下の Below logging directory

[CVE-2025-27591](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w)は、world-writable な `/var/log/below` directory を作成する 0.9.0 より前の Below release に影響しました。service または sudo で許可された command が影響を受ける build を root として実行し、ユーザーが sticky bit のない log directory への書き込みと検索をできる場合、特権プロセスが log entry を開く前に、symlink に置き換えられる可能性があります。インストール済み package の修正状況、正確な特権実行経路、実効 directory access、sticky bit と ACL、`/var/log/below/error_root.log` の metadata を確認してください。world-writable path や sudo ルールだけでは、経路全体の証明になりません。sticky directory や vendor backport によって評価は変わります。受動的な列挙では metadata のみを確認し、link を作成したり特権 program を実行したりする必要はありません。

### 書き込み可能な入力からの特権 support-bundle 収集

sudo で許可された support-profile script が root として固定 log path を読み込み、その内容を profile archive にコピーする場合があります。まず実際の script で file read を確認し、次に呼び出し元が source path や親 directory entry を symlink に置き換えられるかを調べてください。特権 read がその link をたどり、生成された archive を呼び出し元が読めるなら、保護された file が漏洩する可能性があります。sudo 許可、書き換え可能な source path、特権 read、読み取り可能な出力がすべて必要です。書き込み可能な log や profile filename だけでは不十分です。列挙中に file を置き換えたり profile を生成したりせず、実効権限と link metadata を調べてください。[Nagios XI の support guidance](https://support.nagios.com/forum/viewtopic.php?t=62758)には、root で実行される profile script と出力 archive が記載されており、この種の bundle で入力と出力へのアクセスを制限する必要性が分かります。

### root で実行する Python archive restore script

Python の restore script を限定的に実行する sudo ルールでも、archive input を確認する必要があります。呼び出し元が archive を選択または差し替えでき、script が root として `tarfile.extractall(filter="data")` で展開する場合、filter を信頼する前に interpreter の security update を確認してください。CPython は CVE-2025-4517 を含む複数の symlink／hard-link filter bypass を、3.9.23、3.10.18、3.11.13、3.12.11、3.13.4 で修正しました。distribution による backport でより古い version も修正される場合があるため、表示された interpreter version だけでは影響の有無を証明できません。<sup>[[16]](#references)[[17]](#references)</sup>

受動的な確認では、正確な sudo command と script を読み、どの引数で archive を選ぶかを追跡し、現在のユーザーが archive またはその親 directory に書き込めるかを調べてください。インストール済み vendor patch と展開先は個別に確認してください。`filter="data"` を使っても、信頼できない archive がすべて安全になるわけではありません。<sup>[[16]](#references)[[17]](#references)</sup>

### sudo で実行する machine-learning model loader

呼び出し元が選択した `.pt`、`.pth`、`.ckpt` file を許可する sudo ルールでは、特権 script がその file を [`torch.load`](https://docs.pytorch.org/docs/stable/generated/torch.load.html)、`pickle.load`、その他の pickle ベース loader に渡す場合、確認が必要です。実効 RunAs ルール、呼び出し元が選択した model を作成／差し替えできるか、shell wrapper から Python helper までの実際の引数の流れを確認してください。`.pth` 拡張子は、無関係な Python site configuration file にも使われます。したがって、拡張子だけでは model loading の証拠になりません。archive scan や static pickle scan では、後の load が安全である証明にはなりません。loader の[version によって異なる `weights_only` の挙動](https://docs.pytorch.org/docs/stable/notes/serialization.html)と allowlisting を調べてください。[ML pickle と Fickling の説明](../../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)も参照してください。受動的な列挙では model を読み込んだり展開したりしないでください。

### 保存された入力を sudo で実行する expression parser

sudo を介して root として動く固定 Python script でも、権限の低いユーザーが application database に保存できる text を評価する場合があります。TensorFlow では `preprocess_input_exprs_arg_string(value, safe=False)` が `eval` 経路を選びます。[TensorFlow の advisory](https://github.com/tensorflow/tensorflow/security/advisories/GHSA-75c9-jrh4-79mc)には、unsafe parser と、command-line caller の修正が記載されています。application に明示的な `safe=False` 呼び出しがある場合、その command-line caller に patch が適用されていても、別途確認が必要です。実効 sudo ルール、該当する入力行を変更できるユーザー、filtering／scoring によりその行が呼び出し箇所に届くか、インストール済み関数の挙動を確認してください。TensorFlow version、sudo 許可、固定 model file だけでは、経路全体の証明になりません。受動的に script と data flow を調べ、列挙中に特権 helper を実行したり test expression を送信したりしないでください。

### sudo で許可された needrestart の設定

`needrestart -c` は、呼び出し元が選択した Perl configuration file を読み込み、その内容を評価します。`sudo -l` で root としての `needrestart` が `-c` を許す引数付きで認められ、呼び出し元が書き込み可能な場所にある読み取り可能な configuration file を選べるなら、その権限は root code execution につながる可能性があります。正確な sudo の RunAs と引数ルールを確認してください。固定引数一覧のみを許可するルールでは、この経路を阻止できる場合があります。これは needrestart の interpreter-scanning 脆弱性とは別の問題です。package の更新や `interpscan` の無効化によって、無制限な root `-c` 許可が安全になるわけではありません。<sup>[[2]](#references)[[18]](#references)[[19]](#references)</sup>

### 別アカウントで sudo 実行する Python import

固定の Python entry point でも、呼び出し元が編集または置換できる module を import する可能性があります。sudo が **root 以外**の service user として script を実行する場合も同様です。`from utils import status` のような文字列がある場合、package directory の権限だけでなく、ローカルの `utils/__init__.py` と `utils/status.py` も確認してください。書き込み可能な file を実行経路とみなす前に、script の import path、正確な sudo 許可引数、該当 action からその import に到達するかを確認してください。列挙中に import や script の実行をせず、file と権限を調べてください。<sup>[[2]](#references)[[3]](#references)</sup>

`python3 /absolute/script.py` を正確に指定する sudo ルールでは、script は読み取り可能であれば十分です。実行可能 bit や shebang は必要ありません。ローカルの **不足している** module も確認してください。script directory が呼び出し元の書き込み可能領域にある場合、そこに作成した module filename を Python が RunAs identity で読み込む可能性があります。実効 sudo ルール、interpreter の実際の[module 検索 path](https://docs.python.org/3/library/sys_path_init.html)、module が built-in または frozen か、import に到達するかを確認してください。script に対する直接の sudo ルールでは、実行 bit と shebang の要件が異なります。`sudo -u account` の後ろに呼び出し元の token を追加する wrapper も、引数の流れを確認してください。その token 内の別の `-u` が関係するのは、呼び出される sudo ポリシーがその identity を許可する場合だけです。静的な文字列だけでは、どちらの経路も証明できません。

### 呼び出し元が制御する設定を使って sudo で実行する Apache

特権 `apachectl`、`apache2ctl`、`httpd` の呼び出しに、呼び出し元が制御する `-f` configuration file を指定できる sudo ルールでは、その file と親 directory の権限を確認してください。Apache の [`LoadModule`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadmodule) directive は、module 名に続けて **module filename** を指定します。[`LoadFile`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadfile) も file を読み込みます。[`Include` と `IncludeOptional`](https://httpd.apache.org/docs/2.4/mod/core.html#include) は configuration を拡張したり、error 経由で file の内容を露出させたりする場合があります。独自 wrapper がこれらの path を検証したり、権限を落としたり、引数を制限したりする可能性があるため、書き込み可能な設定だけでは code execution の証明ではなく確認候補です。結論を出す前に path の canonicalization、symlink、directive の解釈を確認してください。

### 呼び出し元が制御する設定を使って sudo で実行する nginx

root 権限で nginx を無制限に実行できるルールでは、[`-c` で別の configuration を選択](https://nginx.org/en/docs/switches.html)できる場合があります。正確な sudo 引数と除外設定、呼び出し元が設定を指定できるか、起動後の master／worker が保護された path にアクセスできるかを調べてください。選択された `root` と `autoindex` の組み合わせにより、新しい listener 経由で file を公開できる場合があります。[`dav_methods PUT`](https://nginx.org/en/docs/http/ngx_http_dav_module.html) が特権 file write 経路になる可能性もありますが、DAV module はデフォルトでは build されません。その module の有無、listener に到達可能か、file 権限、一時 file の挙動を確認する必要があります。[`error_log` directive](https://nginx.org/en/docs/ngx_core_module.html#error_log) で任意の file を指定することもできます。`/etc/ld.so.preload` などの機密 configuration file に log を書くことが escalation 経路になるのは、特権 writer が実際に有効で、log record を制御できる場合だけです。`sudo -l` で executable が強調表示されているだけでは、これらの経路が機能する証明になりません。受動的な列挙では nginx を起動したり再設定したりしないでください。

### 特権 Bash prompt の pattern 比較

sudo で許可された Bash script が呼び出し元から値を読み取り、`[[ "$expected" == $entered ]]` で確認する場合、右辺が引用符で囲まれていないため、Bash は pattern として解釈します。そのため wildcard で、期待値を知らなくても比較を満たせる場合があります。右辺を引用符で囲む（`[[ "$expected" == "$entered" ]]`）と、literal string の比較になります。正確な sudo ルール、prompt に到達できるか、比較後に script が何をするかを確認してください。構文だけでは悪用可能な経路の証明にはなりません。列挙中に期待値を出力しないでください。[Bash conditional constructs のリファレンス](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)を参照してください。

### file をダウンロードして実行する sudo helper

URL を呼び出し元が選択でき、response を disk に書き込み、その file を後で interpreter や shell で実行する特権 helper は、無制限の root sudo 許可の場合、data flow の確認が必要です。[sudoers では command entry に引数がなければ任意の引数を許可します](https://man7.org/linux/man-pages/man5/sudoers.5.html)。executable path が固定されていても、引数で何を選べるかは制限されません。インストール済み helper の URL 検証、出力 path、成功時の分岐、その後の実行を確認してください。libcurl の import や表示可能な文字列があるだけでは、この経路の証明になりません。

出力 basename が固定されていても、helper が**呼び出し元の制御する working directory 内の相対 path**を使う場合、書き込みと実行の間に置換できる可能性があります。root 所有 file を rename／置換できるかは file mode だけでなく、directory への書き込みと検索権限、および sticky bit の制限によって決まります。[`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html)を参照してください。helper が file descriptor を開いたまま使うのか、後で path を再度開くのか、書き込み前に信頼済み directory に移動するのかを確認してください。列挙中は特権 download や race を実行せず、sudo ポリシー、helper、directory metadata を受動的に調べてください。

root sudo download helper が、`curl <caller input> -o <fixed output>` のような Bash command string を構築する場合、**引数** injection も起こり得ます。空白を拒否する filter でも、[Bash の brace expansion](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html) は残ります。引用符で囲まれていない comma 区切りの要素は、複数の curl 引数に展開される場合があります。固定の `-o` より前に入力が curl に渡るなら、呼び出し元が指定した出力 option により、helper の identity で最初の URL の出力先を選択できる場合があります。[curl は URL の順番に従って output option を対応付けます](https://curl.se/docs/manpage.html#-o)。正確な shell、引用符、入力検証、実効 sudo ルール、curl の引数順と対応 URL scheme、呼び出し元が取得 bytes を制御できるか、結果を読めるかを確認してください。PyInstaller で package 化された executable に Python application logic が含まれる場合はありますが、package 化の印や `curl` という文字列だけでは、この data flow の証明になりません。認可されている場合は、offline copy の限定された範囲を調べてください。通常の列挙では helper を実行したり、攻撃者が選択した data を取得したりしないでください。

root sudo shell script が[`mktemp -u`／`--dry-run`](https://www.gnu.org/software/coreutils/manual/html_node/mktemp-invocation.html)を呼び出すだけでは、未使用の名前を選択するだけで、file は**作成されません**。その後、別ユーザーが影響を与えられる directory 内に file を作成し、再度開いて内容を root の `authorized_keys` のような保護された destination に追加するなら、一時 file race の可能性を確認してください。正確な sudo ルール、directory と file の所有権、作成から再オープンまでの順序、kernel の保護、特権書き込みで攻撃者が制御する bytes を実際に使用するかを確認してください。`mktemp -u` という文字列や書き込み可能な `/tmp` だけでは race の証明になりません。列挙中に script を実行したり一時 file を race させたりせず、script と path metadata を調べてください。

## 防御上の注意

- sudo 経由で interpreter や対話型 editor を許可しないでください。<sup>[[1]](#references)</sup>
- `tee` のような汎用 file writer に、制限のない operand を許可しないでください。固定 destination を選び、呼び出し元が制御する path を拒否する root 所有 wrapper を使ってください。<sup>[[2]](#references)</sup>
- 範囲の狭い管理操作を 1 つだけ実行する、固定された root 所有 wrapper を優先してください。<sup>[[1]](#references)[[2]](#references)</sup>
- interpreter が避けられない場合は、正確な script path に制限し、ユーザーが制御する引数、書き込み可能な import、`PYTHONPATH`、安全でない環境変数の保持を防いでください。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- file 編集が必要なら、正確な file path に制限し、patch 適用済み sudo version と厳格な環境処理を前提に `sudoedit` を検討してください。<sup>[[1]](#references)[[2]](#references)</sup>
- `SETENV`、`env_keep`、書き込み可能な working directory、書き込み可能な module／import path、`NOEXEC`、`use_pty`、logging を確認してください。ただし、これらを完全な sandbox と見なさないでください。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — Python ドキュメント](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Miscellaneous operating system interfaces — Python ドキュメント](https://docs.python.org/3/library/os.html)
- [5] [perlrun — Perl interpreter の実行方法](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl ドキュメント](https://perldoc.perl.org/functions/exec)
- [7] [Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby ドキュメント](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — Node.js ドキュメント](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js ドキュメント](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua man page](https://www.lua.org/manual/5.4/lua.html)
- [12] [GNU nano text editor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [16] [Python 3.9.23–3.13.4 security release](https://discuss.python.org/t/python-3-13-4-3-12-11-3-11-13-3-10-18-and-3-9-23-are-now-available/94367)
- [17] [tarfile extraction filter — Python ドキュメント](https://docs.python.org/3/library/tarfile.html#extraction-filters)
- [18] [needrestart configuration option と evaluation — upstream source](https://github.com/liske/needrestart/blob/master/needrestart)
- [19] [needrestart command の挙動 — GTFOBins](https://gtfobins.org/gtfobins/needrestart/)
- [20] [iptables-save(8) — netfilter マニュアルページ](https://www.man7.org/linux/man-pages/man8/iptables-save.8.html)
- [21] [iptables-extensions(8): comment match — netfilter マニュアルページ](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [22] [Simple Command Expansion — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Simple-Command-Expansion.html)
- [23] [Forge compiler option — Foundry ドキュメント](https://getfoundry.sh/forge/reference/forge-inspect/)
- [24] [Forge flatten — Foundry ドキュメント](https://getfoundry.sh/forge/reference/forge-flatten/)
- [25] [pacman(8) — Arch マニュアルページ](https://man.archlinux.org/man/pacman.8.en)
- [26] [PKGBUILD(5) install script — Arch マニュアルページ](https://man.archlinux.org/man/core/pacman/PKGBUILD.5.en)
- [27] [Volexity — VerdantBamboo: Just Another BRICKSTORM in the Firewall](https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/)
- [28] [GNU Coreutils — `tee`: 複数の file または process への出力リダイレクト](https://www.gnu.org/software/coreutils/manual/html_node/tee-invocation.html)
{{#include ../../banners/hacktricks-training.md}}
