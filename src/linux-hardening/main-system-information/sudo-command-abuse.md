# Sudoコマンドの悪用

{{#include ../../banners/hacktricks-training.md}}

## sudoで実行を許可されたインタープリター

`sudo -l` でユーザーがインタープリターを root として実行できる場合、直接的なコード実行が可能だと考えてください。インタープリターは任意のコードを実行するように設計されているため、`python3`、`perl`、`ruby`、`lua`、`node` などのバイナリを許可するルールは、引数が厳密に制限・検証されていない限り、通常は root コマンドの実行と同等です。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

一般的な確認手順: まずユーザーの権限を一覧表示し、次にインタープリターの `-c` オプションで Python の文を実行します。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```

その他のインタープリターの例を以下に示します。ここに挙げたインタープリターのドキュメントでは、インラインコードの実行または子プロセスAPIについて説明されています。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```

正確なパスが重要です。sudo rule が `/usr/bin/python3` を許可している場合は、検証時にもその正確なパスを使用してください。<sup>[[2]](#references)</sup>

`/usr/bin/python*` のような sudo executable glob は、Python 3 向けに書かれたスクリプトに対して Python 2 も許可する可能性があります。呼び出し元が制御できるテキストをスクリプトが `input()` に渡す場合、[Python 2 はそのテキストを式として評価します](https://docs.python.org/2/library/functions.html#input)。インタープリターを明示して実行すると、スクリプトの shebang は無視されます。これを実行経路と見なす前に、インストール済みで条件に一致するバイナリー、実効 RunAs と引数ポリシー、拒否設定、到達可能な入力を確認してください。

root 権限で実行可能な sudo rule にスクリプトの固定パスが指定されていても、そのスクリプトが実行する内容までは制限されません。読み取り可能な Bash wrapper では、sudo が呼び出し元による引数の選択を許可している場合、最初に実行されるコマンドが、引用符で囲まれていない位置パラメーター（`$1` など）を**コマンドワード**として使っていないか確認してください。実効 RunAs identity、パスワードと引数のポリシー、その後の拒否設定、実際に実行されるスクリプトの分岐を確認してください。`NOEXEC`、安全な引数リストへの固定、またはコマンドを検証する wrapper によって結果が変わることがあります。列挙中は、テスト用コマンドで実行せず、短いスクリプトを静的に調べてください。

制限のない root 権限で実行可能な `dotnet` の sudo rule についても、インタープリターの観点から確認する価値があります。.NET SDK がインストールされている場合、[`dotnet fsi` は F# コードを対話的に、またはスクリプトから実行します](https://learn.microsoft.com/en-us/dotnet/fsharp/tools/fsharp-interactive/)。また、[`dotnet run` はソースからプロジェクトを実行します](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-run)。まず実効 RunAs identity と正確な引数ポリシーを確認してください。特定の安全なサブコマンドや信頼できるアプリケーションに固定された rule は、別種の権限付与です。また、runtime のみのインストールでは SDK コマンドが使えない場合があります。実行ファイル名は確認の手掛かりであり、コード実行の証明ではありません。

```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```

## sudoで許可されたエディタ

`sudo -l` でユーザーが root として対話型エディタを実行できる場合、無害なファイル編集権限ではなく、コマンド実行の手段として扱ってください。エディタ内からシェルコマンドの実行、任意のファイルの読み取りや書き込み、外部ヘルパーの呼び出しができることがよくあります。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

一般的な確認手順: ユーザーの権限を列挙してから、sudo 経由で許可されている各エディタまたはページャーを起動します。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```

### nano コマンド実行

`nano` が sudo 経由で許可されている場合、エディターのインターフェースからコマンドを実行できる可能性があります。<sup>[[12]](#references)</sup>

```text
Ctrl+R
Ctrl+X
```

次に、nano コマンドのプロンプトで `id` や `/bin/sh` などのコマンドを入力します。<sup>[[12]](#references)</sup>

```bash
id
/bin/sh
```

対話型シェルで使用可能な端末ストリームがない場合、このリダイレクト形式は標準出力と標準エラーをファイルディスクリプター 0 に割り当てます。<sup>[[15]](#references)</sup>

```bash
reset; /bin/sh 1>&0 2>&0
```

nano のバージョンやビルドオプションによってキーの正確な順序は異なる場合がありますが、セキュリティ上の問題は同じです。エディターが root 権限で実行され、外部コマンドを呼び出せます。<sup>[[1]](#references)[[12]](#references)</sup>

### その他の一般的なエディターからのエスケープ

Vim 系エディターでは、通常 `:!` を使ってコマンドを実行できます。<sup>[[13]](#references)</sup>

```text
:!/bin/sh
```

`less` などの pager からも shell execution が可能です。<sup>[[14]](#references)</sup>

root として `apport-cli` の実行を許可する sudo rule についても、同様に pager を確認してください。影響を受ける Apport のバージョンでは、攻撃者が調整できる端末サイズで crash report を `less` で開くことがあり、特定の sudo と pager の条件が満たされると、pager から root shell を取得できる可能性がありました。バージョンだけで脆弱と判断する前に、有効な sudo rule、pager の設定、ディストリビューションのパッケージ修正を確認してください。passive enumeration 中は、crash を発生させたり、特権付きの report を開いたりせずに、パッケージと policy のメタデータを読み取ってください。[Ubuntu's CVE record](https://ubuntu.com/security/CVE-2023-1326) には、backport された修正を含む、リリースごとの修正済みパッケージバージョンが記載されています。

```text
!/bin/sh
```

## その他の sudo と doas ルールの危険性

まず `sudo -l`、`sudo -V`、該当する場合は `doas` のポリシーを確認します。許可されたコマンド、実行ユーザー、引数、環境、デフォルト設定をまとめて読み取ります。root 以外のサービスアカウントとして実行する権限でも、そのアカウントのファイルや root への経路が露出する場合があります。

sudo で許可された固定の Python スクリプトでも、対話的に入力された呼び出し元制御のデータが [`os.system()`](https://docs.python.org/3/library/os.html#os.system) に連結されると、RunAs の実行ユーザー権限で shell コマンドを実行できる場合があります。shell の句読記号を denylist で拒否するだけでは安全性を証明できません。[shell は `$(...)` によるコマンド置換も認識します](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html)。許可された引数が入力を受け取る分岐に到達すること、その入力が安全な検証なしに shell コマンドへ渡ること、実効 sudo ポリシーが意図した RunAs ユーザーを許可することを確認します。スクリプトのパスや `os.system()` の呼び出しだけでは、あくまでレビューの手掛かりです。特権スクリプトを実行せず、ソースを確認してください。

`chattr` を root として実行できる実効 sudo 許可があれば、immutable (`i`) ファイル属性を解除できますが、それだけで書き込み権限や新たな ID が得られるわけではありません。[`chattr` のマニュアル](https://man7.org/linux/man-pages/man1/chattr.1.html)によると、この属性は変更をブロックし、変更できるのは root または `CAP_LINUX_IMMUTABLE` を持つプロセスだけです。sudo の引数ポリシーとファイルシステムの対応状況を確認したうえで、属性を解除した後に呼び出し元がファイルへ書き込めるか、そのファイルをより高い権限のプロセスが利用するかを個別に検証します。たとえばログインシェルの置き換えには、対象アカウントが受け付ける認証情報と、そのシェルを使った実際のログインも必要です。調査中にポリシー、ファイル属性、権限を変更せずに確認してください。

sudo がパスワードとワンタイムコードの両方を要求する場合、それぞれの前提条件をコマンド許可とは別に扱います。読み取り可能な `.google_authenticator` ファイルには機密性の高いシード情報が含まれます。一方、古いアプリケーションやデータベースに保存されたパスワードハッシュは、現在のアカウントパスワードの候補にすぎません。どちらも、実効 PAM 設定で他方の要素が受け付けられることを証明しません。許可を得た後、正確な RunAs と引数を確認します。RubyGems `gem` を root として無制限に実行できる場合、エディターコマンドが悪用可能なことがあります（[GTFOBins](https://gtfobins.github.io/gtfobins/gem/)）。ただし、制限付きの許可や認証失敗では該当しません。受動的な調査では、シードの表示、パスワードの復元、コードの生成、特権コマンドの実行を行わず、パスとポリシーを報告してください。

Chef の `knife` を root として実行できる無制限の sudo 許可は、インタープリターの観点から確認する必要があります。[Chef のドキュメントによると、`knife exec -E` はローカルで Ruby 文字列を評価します](https://docs.chef.io/workstation/26/tools/knife/knife_exec/)。実効 sudo ルールが `exec` サブコマンドと呼び出し元指定の `-E` 引数を許可すること、意図した RunAs ID、該当するコマンド拒否や固定引数を確認します。インストール済みバイナリや、他のサブコマンドに限定されたルールは、確認の手掛かりにすぎません。受動的な調査ではルールを報告し、`knife` は実行しないでください。

対話型の `msfconsole` を root として実行できる正確な sudo 許可も同様に機密性が高いものです。[GTFOBins は、sudo の ID を引き継ぐ可能性のある `irb` コンソールについて説明しています](https://gtfobins.org/gtfobins/msfconsole/)。実効 RunAs ユーザー、許可された引数一覧、コマンド拒否、`NOEXEC` その他の制限、インストール済みコンソールの挙動、呼び出し元が対話入力を渡せるかを確認します。パスが強調表示されているだけでは、あくまでレビューの手掛かりです。受動的な調査ではコンソールを起動しないでください。

FreeBSD では、root としての `pkg update` および `pkg install *` のみに制限された sudo ルールでも、リポジトリの信頼性を確認する必要があります。呼び出し元が `/etc/hosts` に書き込めるか、また、*実効的に有効な*リポジトリ設定が `signature_type: none` の HTTP ホスト名を使うかを確認します。[FreeBSD の `pkg.conf` マニュアル](https://man.freebsd.org/cgi/man.cgi?query=pkg.conf&sektion=5)によると、`none` は署名チェックを無効にします。`pkg+http` だけでは、そのことは確認できません。パッケージにはインストールスクリプトを含められるため（[FreeBSD Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/pkg-files/)）、呼び出し元が実際にリポジトリのエンドポイントを制御し、パッケージを選択できるなら、root の境界を越える可能性があります。結論を出す前に、リポジトリの上書き設定、SRV／ミラー解決、実効 sudo 引数、パッケージ選択、スクリプトの実行を確認してください。調査中は、名前解決先を変更したり `pkg` を実行したりせず、ポリシーと小さなローカル設定ファイルを確認してください。

`apt-get update` と `apt-get upgrade` を root として実行できる sudo 許可も、sudo が呼び出し元制御の `http_proxy` を保持する場合は、リポジトリの信頼性を確認する必要があります。実効 APT プロキシ設定が実際にその変数を使うか、どの有効なリポジトリへのリクエストに影響するかを確認します。信頼された署名鍵で認証されたアーカイブから、プロキシだけでパッケージを置き換えることはできません。[APT の HTTP transport マニュアル](https://manpages.debian.org/experimental/apt/apt-transport-http.1.en.html)ではプロキシの優先順位が、[apt-secure](https://manpages.debian.org/experimental/apt/apt-secure.8.en.html)では署名チェック、安全でないリポジトリの上書き、認証されていないパッケージを受け入れる際の確認が説明されています。正確な sudo RunAs と引数、リポジトリの認証ポリシー、必要な対話的な承認、選択されたアップグレードが root としてパッケージスクリプトを実行するかを確認してください。調査中はポリシーとローカル設定を受動的に確認し、パッケージ通信の転送やアップグレードの実行は行わないでください。

`snap install` を root として実行できる sudo ルールは、呼び出し元がローカル snap と制限の緩いインストールモードを選べる場合、パッケージとコードの境界になり得ます。[Snap のドキュメント](https://snapcraft.io/docs/explanation/snap-development/install-modes/)によると、`--dangerous` はローカル snap の assertion チェックを省略し、`--devmode` は confinement を緩和します。[インストールフックは初回インストール時に実行される可能性があります](https://snapcraft.io/docs/reference/development/supported-snap-hooks/)。特権ホスト上のファイルへアクセスできると結論づける前に、正確な sudo 引数／RunAs ポリシー、snap ファイルの制御者、インストール済み snapd がこれらのモードを受け付けるか、フックの実効 ID と confinement を確認します。`snap` バイナリやワイルドカードのように見えるルールだけでは、この一連の条件は証明されません。受動的な調査では、パッケージをインストールしたりフックを実行したりしないでください。

**root 以外**のアカウントのカスタム認証情報読み取りバイナリを sudo で実行できる正確な許可がある場合、まず実行せずに、許可されたバイナリとファイル権限を調べます。埋め込まれたパスワードゲートは、wide character としてしか見えない場合があります。[GNU `strings` のドキュメントでは、16 ビット little-endian の抽出方法が説明されています](https://sourceware.org/binutils/docs/binutils/strings.html)。文字列が見えても、それが受け付けられるパスワードであることや、成功時の分岐で現在の認証情報が公開されることの証明にはなりません。バイナリの挙動、保護されたデータへの対象アカウントのアクセス、認証情報の有効性、その後のアカウントまたはグループの変更を個別に確認します。そのアカウントが `docker` グループに属している場合、ホスト root へのアクセスを推測する前に、ソケットへのアクセス権とデーモンが rootful か rootless かを確認します。[Docker は、そのグループが持つ root レベルの影響について説明しています](https://docs.docker.com/engine/install/linux-postinstall/)。通常の調査では、バイナリを実行したり文字列をダンプしたりせず、sudo ルールとグループ所属を報告してください。

アプリケーションのメンテナンススクリプトに対するワイルドカード sudo ルールは、スクリプトのパスだけでなく、さらに詳しく確認する必要があります。許可されたスクリプトが制限のない引数を受け取るか、権限の低いアプリケーションアカウントから書き込み可能な設定を読むか、その値が shell コマンドや subprocess の環境へ流れるかを確認します。たとえば、ZoneMinder の [`zmupdate.pl` は `mysqldump` コマンドを組み立てて `qx` 経由で実行します](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmupdate.pl.in)。また、[`zmdc.pl` はデーモン起動前に `ZM_LD_PRELOAD` 設定を `LD_PRELOAD` にコピーします](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmdc.pl.in)。root としてどちらかのスクリプトを許可する sudo ルールは、対応する入力を制御でき、それがインストール済みバージョンの該当コードに到達する場合、信頼境界を越える可能性があります。実効 sudo ルール、アプリケーション設定へのアクセス権、スクリプトのソースを確認してください。ワイルドカードや設定値だけでは、あくまでレビューの手掛かりであり、実行の証拠ではありません。

- `SETENV`、`env_keep`、`secure_path`、`LD_PRELOAD` によって、通常なら限定的なコマンドが import、ライブラリ、PATH の hijack に変わることがあります。[環境変数ガイド](../linux-basics/linux-environment-variables.md)と[SUID／linker の悪用](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md)を参照してください。

shell wrapper が固定の Python スクリプトを文字列どおりの import 付きで起動する場合、root として実行できる `SETENV` 付きの正確な sudo 許可は、短い一段階のレビューも必要です。`secure_path` が制限するのは shell のコマンド検索であり、Python の[`PYTHONPATH` モジュール検索](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH)ではありません。Python の[`-E` と `-I`](https://docs.python.org/3/using/cmdline.html#cmdoption-E)は、その環境変数を無視させます。コード実行と判断する前に、実効 sudo タグと拒否ルール、wrapper の分岐、インタープリターのオプション、import の解決、呼び出し元が書き込める検索ディレクトリを確認します。短いスクリプトは静的に確認し、特権 wrapper は実行しないでください。

root としての正確な `neofetch ""` sudo 許可でも、該当する sudo のデフォルト設定が呼び出し元制御の `XDG_CONFIG_HOME` を保持する場合、shell 設定を読み込む可能性があります。[Neofetch の設定ローダー](https://github.com/dylanaraps/neofetch/blob/master/neofetch)は、そのディレクトリ以下にある `neofetch/config.conf` または `neofetch/config` を source します。空の引数リストでも、この参照は防げません。インストール済みローダー、実効 RunAs と引数ポリシー、コマンド拒否の有無、sudo がこのコマンドに対して実際に指定変数を保持するか、呼び出し元が読み取り可能な設定パスを制御できるかを確認します。変数が保持されることや Neofetch がインストールされていることだけでは、あくまでレビューの手掛かりです。特権コマンドを実行したり設定内容を表示したりせず、ポリシーとファイルのメタデータを確認してください。[sudoers の環境処理](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)を参照してください。

root として `facter` を無制限に実行できる sudo ルールは、カスタム fact の観点から別途確認が必要です。[Puppet のドキュメント](https://help.puppet.com/core/current/Content/PuppetCore/loading_custom_facts.htm)によると、`--custom-dir` は指定されたディレクトリから Ruby fact ファイルを読み込みます。正確な sudo ルールでこのオプションが許可されるか、インストール済み Facter が受け付けるか、呼び出し元がそのディレクトリを制御できるかを確認します。固定引数の許可、明示的なコマンド拒否、またはカスタム fact の無効化によって結果は変わる可能性があります。受動的な調査では、Facter を実行したり fact の内容を読んだりせず、候補となるポリシーを報告してください。

`SETENV` 付きで root として実行できる正確な sudo スクリプト許可がある場合、`find` などの裸のコマンド名と、sudo ポリシーおよびスクリプト初期化後の実効 `PATH` を確認します。source された Bash ファイルで `enable -n [` を実行すると、[Bash は後にスクリプトがそのコマンドを使用したとき、`PATH` 内の外部 `[` を検索します](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)。これを確認するには、該当する[sudoers の環境ルールと `secure_path` ルール](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)、`NOSETENV`／`NOEXEC` や拒否エントリーの有無、スクリプトと source されたファイルの処理、呼び出し元が制御できる実行可能な検索ディレクトリを確認します。スクリプトが読み取れることや裸のコマンドを含むことは、特権実行の証拠ではなく、レビューの手掛かりです。sudo ルールを実行せずに確認してください。
- 固定 URL を `curl` で取得する特権スクリプトでも、該当する sudo ルールが `http_proxy` を保持し、リクエストがそのプロキシを経由する場合、呼び出し元がレスポンスを選べる可能性があります。その後、レスポンスを外部エンティティを解決する XML parser に渡すなら、悪意あるレスポンスによって特権プロセスが読めるファイルが漏洩する可能性があります。正確な sudo の環境ポリシー、`no_proxy` の除外、要求 URL、parser の設定、出力先を確認してください。プロキシ変数や XML parser があるだけでは脆弱性ではありません。[curl のプロキシ環境変数に関するドキュメント](https://everything.curl.dev/usingcurl/proxies/env.html)では変数の挙動が説明されています。受動的な調査ではネットワークリクエストを送信したり、悪意ある XML を parse したりしないでください。
- 呼び出し元の影響を受けるデータから PostScript ファイルを作り、`ps2pdf -dNOSAFER` を実行する root 対応 sudo スクリプトは、別途入力フローを確認する必要があります。Ghostscript のドキュメントによると、このフラグは `.setsafe` まで SAFER を無効にし、プロセスの OS 権限の範囲内で PostScript のファイル操作を可能にします。呼び出し元引数から組み立てられた SQL クエリが、攻撃者制御の行データを PostScript テンプレートへ渡すことはあり得ますが、クエリ文字列や `ps2pdf` の呼び出しだけでは、そのデータが実行可能な PostScript 構文に到達する証拠にはなりません。実効 sudo ルール、入力からテンプレートへの正確な経路、エスケープ処理、インストール済み Ghostscript の挙動、文書の解釈前に SAFER が再有効化されるかを確認します。受動的な調査では特権変換を実行しないでください。[Ghostscript の `-dNOSAFER` に関するドキュメント](https://ghostscript.readthedocs.io/en/master/Use.html)を参照してください。
- shell スクリプトを実行する sudo ルールでは、保持される変数とスクリプト自体を比較します。`if $CHECK_CONTENT; then` のような構文は、展開された値をコマンドとして実行するため、スクリプトのパスと引数が固定されていても `CHECK_CONTENT` が保持されればコマンド実行につながる可能性があります。その分岐に到達できるか、環境が実際に保持されるかは、個々のルールについて確認する必要があります。<sup>[[2]](#references)[[22]](#references)</sup>
- sudo で許可された Python スクリプトは、書き込み可能なディレクトリやキャッシュされた `.pyc` ファイルからコードを import する場合があります。[権限昇格ガイド](../linux-basics/linux-privilege-escalation/README.md)ではキャッシュのケースを詳しく説明しています。
- root として実行が許可された固定の Python スクリプトでも、対話型 debugger が露出する場合があります。`pdb.set_trace()` や `pdb.post_mortem()` のような呼び出しは、呼び出し元が breakpoint または例外ハンドラーに到達でき、**debugger の入力ストリームを制御できる**場合、debugger 対象プロセスのコンテキストで Python 文を実行できます。正確な sudo RunAs ルール、認証と分岐の条件、例外に到達できるか、端末／入力の所有者、debugger が同じ特権プロセス内で動作するかを確認します。別の端末に接続された debugger に対して、socket リクエストで例外を発生させるだけではアクセスできません。[Python のドキュメントでは、debugger による文の評価と post-mortem モードが説明されています](https://docs.python.org/3/library/pdb.html)。調査中に特権ハンドラーを発動させず、スクリプトを静的に確認してください。
- sudo で許可された固定の Python スクリプトが、データベースまたは Unix socket からプロフィールのフィールドを読み、それを後に `str.format()` の**書式文字列**となる文字列に追加する場合もあります。[置換フィールドでは属性や mapping key をたどれます](https://docs.python.org/3/library/string.html#format-string-syntax)。そのため、攻撃者制御のフィールドは `format()` に渡されたオブジェクトを調べ、その結果が表示されるか呼び出し元が読める場所に保存される場合、そこからアクセス可能なデータを露出させる可能性があります。実効 sudo RunAs ID、対象レコードへの書き込み権限、書式文字列へのデータフロー、渡されるオブジェクト、出力の可視性を確認します。これは自動的なコード実行ではありません。信頼できるリテラル書式文字列に攻撃者制御の*値*を渡すケースとは異なります。漏洩した秘密が OS アカウントへの移行に使えるのは、そのアカウントがその秘密を受け付ける場合だけです。特権操作を実行せずにスクリプトと socket の権限を確認してください。
- root 対応の Python wrapper が、呼び出し元指定の URL を GitPython の `Repo.clone_from` に渡す場合があります。wrapper が Git の `protocol.ext.allow=always` も有効にしていると、`ext::` remote によって外部 helper を起動できる可能性があります。正確な sudo 引数、URL の取得元、GitPython パッケージのバージョンとベンダーの patch 状況、unsafe protocol を明示的に許可しているかを確認します。GitPython は 3.1.30 で[デフォルトの unsafe-protocol ガード](https://github.com/gitpython-developers/GitPython/commit/2625ed9)を追加しました。`git` 実行ファイルのバージョンは別の情報です。受動的なレビューでは、clone を実行せず、ルールと範囲を限定したソースのみを確認してください。
- 別ユーザーとして実行する sudo 許可がある repository-cloning CLI には、shell 文字列への injection 経路が別に存在する場合があります。呼び出し元指定の repository 引数が、Node.js の[`child_process.exec`](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback)や、引数を安全に分離しない別の shell コマンド構築処理に渡るかを追跡します。Node の `exec` はコマンド文字列を shell に渡します。正確な RunAs ユーザー、許可されたサブコマンドと引数、インストール済み wrapper のコード、入力検証を確認します。repository ツールの名前や無制限の sudo ルールだけでは、コマンド injection の証拠になりません。調査中に特権 clone を実行せず、wrapper を確認してください。
- カスタムの root 所有 wrapper は、バイナリやスクリプトに書き込めなくても、特権操作を実行するかどうかの判断が、権限のないユーザーが変更できるフラグ、ローカル API の値、サービスの状態に依存している場合があります。各ゲートを入力と認可チェックまでたどります。調査中は運用状態を変更せずに設定と権限を確認してください。wrapper 内の `systemd-run` 呼び出しが重要なのは、そのゲートに影響を与えられる場合だけです。
- sudo で root として実行できるバックアップクライアントが、呼び出し元指定の設定ファイル（例: `npbackup-cli -c`）を受け付ける場合があります。正確な RunAs ユーザーと許可された引数を確認し、呼び出し元が設定パス、バックアップ元のパス、repository、read／restore オプションを制御できるか確認します。読み取り可能な設定ファイルに暗号化された repository の秘密情報があれば、クライアントが利用できる場合がありますが、ルールだけでは repository へのアクセスや root ファイルの漏洩は証明されません。バックアップを実行したり内容をダンプしたりせずに、認可の状況を検証してください。
- [Restic](https://github.com/restic/restic/blob/master/doc/030_preparing_a_new_repo.rst) は repository のパスワードを取得するプログラムを呼び出す `--password-command` をサポートしています。権限の低いユーザーが root として restic を実行でき、呼び出し元がパスワードコマンドとパスワードを必要とするサブコマンドを指定できる sudo ルールがある場合、その helper が root として実行される可能性があります。正確な sudo 引数と除外ルールを確認してください。条件を調べるだけのために helper やバックアップコマンドを実行しないでください。
- root 対応の `restic backup` 許可も、sudo の引数パターンが呼び出し元に、source と後で読み取り・復号できる repository の両方を選ばせる場合、ファイル読み取りの境界を越える可能性があります。[sudoers の引数ワイルドカードは空白とスラッシュに一致します](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)。そのため、固定 repository prefix で source が制限されると思い込まず、末尾のワイルドカードを確認します。[Restic はローカルとリモートの repository にバックアップできます](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html)。ただし、ローカル repository には新たに書き込まれた root 専用オブジェクトが含まれる場合があります。漏洩と判断する前に、実効 sudo ポリシー、backend へのアクセス、repository のパスワード、結果として作成されるオブジェクトの権限を確認します。バックアップされた SSH key でログインできるのは、接続先アカウントがその key を受け付ける場合だけです。受動的なレビューではテストのためにバックアップを実行しないでください。
- 無制限のカスタムメンテナンス／バックアップコマンドが、出力先パスを受け付けたり、独自のジョブスケジューラーを備えていたりする場合があります。ファイル書き込み経路では、正確な sudo ルールと実行ユーザーを確認したうえで、呼び出し元がデータと出力先の両方を制御できるか確認します。スケジュール実行経路では、スケジューラーの実行 ID、コマンド入力、追加のパスワードや認可ゲートを確認します。コマンド名や `NOPASSWD` だけでは、どちらの経路も証明されません。[root 所有ファイルへの書き込み](../interesting-files-permissions/write-to-root.md)と[cron および systemd timer](../processes-crontab-systemd-dbus/cron-and-systemd-timers.md)を参照してください。
- 固定の sudo コマンドでも、共有の書き込み可能ディレクトリから予測可能な設定ファイルを読み込む場合があります。呼び出し元がそのファイルを置き換えられるか、source と destination のフィールドが特権による取得またはコピーを制御するかを追跡します。ローカルファイル URL からは、sudo の RunAs アカウントにしか読めないデータが露出する可能性があります。呼び出し元制御の source と保護された destination の組み合わせは、書き込み経路を生み出す可能性があります。特権転送を実行せず、インストール済みプログラムの URL 処理、destination のパスチェック、実効 sudo ルール、出力へのアクセス性を確認します。書き込み可能な `/tmp` の設定パスだけでは、あくまでレビューの手掛かりです。特権転送を実行せずに、バイナリとファイルのメタデータを確認してください。
- `git apply` の sudo ルールによって、RunAs アカウントが呼び出し元制御の patch で選択されたファイルへ書き込める場合があります。[CVE-2023-23946](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh) では、コマンドが `--unsafe-paths` を受け付けない場合でも、細工された patch によって symlink を作成し、working tree の外へ書き込むことができました。実効 sudo の引数ルール、patch の取得元、RunAs アカウントが working directory にアクセスできるか、インストール済み Git に修正が適用されているか、またはベンダーの backport があるかを確認します。`--unsafe-paths` を許可する無制限のルールは、明示的なオプションに関する別のリスクです。Git のバージョンや `git apply` の許可だけでは、保護されたファイルを変更できる証拠になりません。受動的な調査では信頼できない patch を適用しないでください。
- root 対応の `clamscan --debug` ルールは、権限の低いユーザーが DMG イメージを指定でき、インストール済み parser が、debug 出力を通じてファイル内容を漏洩する可能性があった[CVE-2023-20052](https://blog.clamav.net/2023/02/clamav-01038-01052-and-101-patch.html)の影響を受ける場合、読み取りの境界を越える可能性があります。正確に許可された引数とスキャンパス、入力の制御、実効 RunAs アカウント、engine の修正／backport、出力が呼び出し元から見えるかを確認します。より広いルールで `--file-list`／`-f` が許可される場合、その file-list の挙動は別に確認してください。`--debug <scan-path>` に固定されたポリシーでは、このオプションは許可されません。調査中に細工したファイルをスキャンしたり保護された出力を表示したりせず、ポリシーとパッケージのメタデータを確認してください。
- 呼び出し元指定の暗号化ディスクイメージを開く root 対応 sudo ルールと、生成された mapper を mount する別のルールがあると、呼び出し元制御のファイルをホストの mount namespace に取り込める可能性があります。両方の実効ルールと引数、イメージと mapper 名の制御、実際の mount 先、作成されたファイルの owner と mode を確認します。set-user-ID による移行には、アクセス可能な実行ファイル、これを有効にする mount オプション（`nosuid` は無効化します）、適用されるプロセスまたは MAC ポリシーも必要です。イメージを開くことや mount することだけでは、レビューの手掛かりにすぎません。既存バックアップを使う別の経路には、実際に有効な key と、内部にある有用で読み取り可能な秘密情報が必要です。受動的な調査ではイメージを開いたり mount したりせず、ポリシーとパスを確認してください。[cryptsetup のマニュアル](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)と[mount オプション](https://man7.org/linux/man-pages/man8/mount.8.html)を参照してください。
- shell または Python スクリプトに対する root 対応 sudo ルールは、スクリプトが固定ディレクトリへ移動せずに `./helper` を呼び出す場合、working directory の確認が必要です。`subprocess.run` に渡される `['./helper']` のような Python list でも、呼び出し元が選ぶ working directory の影響を受けます。呼び出し元が書き込み可能なディレクトリを選び、そこにその相対名の実行ファイルを置ける可能性があります。スクリプト内の別の箇所で絶対パスを使っていても、この呼び出しは保護されません。コード実行と判断する前に、実効ルール、`runchdir` その他のディレクトリ変更ポリシー、スクリプトの処理と分岐に到達できるか、書き込み可能かつ実行可能なディレクトリ、mount／`NOEXEC` の制限を確認します。スクリプトが読めない場合、認可された方法でソースを確認するまでは挙動は不明です。helper を実行せず、スクリプトを静的に確認してください。[sudoers のマニュアル](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)では working directory のポリシーが説明されています。
- root 対応の固定 Python validator でも、呼び出し元指定のデータファイルを評価する場合があります。[Python の `eval()` ドキュメントは、信頼できない入力に対する使用を警告しています](https://docs.python.org/3/library/functions.html#eval)。入力の末尾チェック、算術式の prefix、検証分岐があっても、残りの式が `eval` まで到達するなら sandbox にはなりません。実行経路と判断する前に、実効 sudo ルール、呼び出し元が正確なファイルを選択・制御できるか、parser の分岐条件と式の構築、特権プロセスの ID を確認します。読み取り可能なスクリプトに `eval` があるだけでは、レビューの手掛かりにすぎません。調査中は validator を実行したりテスト式を送信したりせず、ソースとファイル権限を確認してください。
- root 対応の sudo Ruby wrapper が `YAML.load(File.read("dependencies.yml"))` のような相対 YAML ファイル名を読み取ると、wrapper または sudo ポリシーがそのディレクトリを固定しない限り、呼び出し元の working directory から入力を取る可能性があります。正確に許可された引数、ディレクトリとファイルの権限、インストール済み Psych の挙動を確認します。古い `YAML.load` の実装では任意の Ruby オブジェクトを deserialize できましたが、新しいリリースではデフォルトでクラスが制限されます。静的な呼び出し箇所はレビューの手掛かりにすぎません。実際に呼び出し元が書き込めるディレクトリからファイルを読み、インストール済み loader が危険なクラスを受け付けることを確認してください。信頼できない入力には、明示的で最小限のクラス allowlist を指定した `safe_load` を優先してください。[Ruby 3.0 の Psych ドキュメント](https://docs.ruby-lang.org/en/3.0/Psych.html)と[Ruby 3.1 の Psych ドキュメント](https://ruby-doc.org/core-3.1.2/Psych.html)を参照してください。

- root としての正確な `sudo go run /absolute/file.go` 許可は、Go ソースが相対 WASM ファイルを読み込み、その結果を確認後に相対 shell スクリプトを実行する可能性がある場合、working directory の確認が必要です。実効 RunAs、コマンド引数と拒否ルール、呼び出し元が書き込める current directory、WASM から分岐へのデータフロー、その分岐が helper を呼び出すかを確認します。固定の sudo `runchdir`、`os.Chdir`、または[`exec.Cmd.Dir`](https://pkg.go.dev/os/exec)によって検索場所が変わる可能性があります。静的に同時に存在するだけでは候補にすぎません。Go、WASM、helper を実行せずにソースを確認してください。
- `sudoedit` と引数のワイルドカードでは、バージョンとルールを正確に確認する必要があります。[チェックリスト](linux-privilege-escalation-checklist.md)には sudoedit のファイル編集に関する問題が含まれています。別ユーザーのファイルに対するワイルドカードパスの `sudoedit` 許可では、実効 `sudoedit_follow` または `FOLLOW` 設定、`sudoedit_checkdir`、解決後の対象、各親エントリーを置き換えられるユーザーを確認します。前者は symlink の追跡を許可する可能性があり、後者を無効にすると書き込み可能ディレクトリのチェックがなくなりますが、いずれも単独では他ユーザーのファイルへ書き込めることを証明しません。結論を出す前に、インストール済み sudo のポリシーと、実際に一致する引数を確認します。[sudoers のオプション定義](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)を参照してください。
- sudoers のコマンドルールでは、引数のワイルドカードは空白だけでなくパス文字にも一致します。`/restricted/*` のような引数を持つ読み取り可能コマンドのルールでは、一致した prefix の後に余分なファイル引数を許可する場合があります。正確な実行ユーザー、コマンドパス、引数パターン、その後の拒否ルールを確認します。ファイルを読み取れたことが、コマンド実行を意味するわけではありません。[sudoers のマニュアル](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)では、引数の glob とコマンドパスの glob が区別されています。
- パスのように見える引数 glob が `../` に一致する場合もあります。たとえば、root 対応の `node /opt/scripts/*.js` ルールでは、指定されたパスが `/opt/scripts/` で始まり、親ディレクトリのセグメントを通じて解決されるなら、呼び出し元が `/opt/scripts` の外部にある JavaScript ファイルを指定できる場合があります。これは**引数**の glob です。Node 実行ファイルのコマンドパスに対する glob は、スラッシュの扱いが異なります。コード実行と判断する前に、実効ルール、その後の拒否ルール、パス名の解決、対象ファイルの制御、sudoers の正規表現や digest の制限を確認します。[sudoers のワイルドカードルール](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)と[Node のコマンドラインに関するドキュメント](https://nodejs.org/api/cli.html)を参照してください。
- Archiver などのユーティリティには、実行フックがある場合があります。shell やインタープリターだけがコマンドを実行すると決めつけず、正確に許可された引数を[GTFOBins](https://gtfobins.github.io/)で確認してください。
- root として `qpdf` を無制限に実行できるルールがあれば、PDF の添付ファイルを通じて特権ファイルを露出させる可能性があります。qpdf 10.2 以降は、出力 PDF に対して `--empty` と `--add-attachment file ... --` をサポートしています。特権プロセスが選択された source を読み取れ、呼び出し元がアクセス可能なパスへ PDF を書き込める場合、その出力に source のバイト列を含められます。ファイル漏洩が可能か判断する前に、実効 sudo 引数と除外ルール、qpdf のバージョン、source へのアクセス、出力先を確認してください。root の SSH key を読めても、その key が有効で root の SSH 認証が許可されている場合にのみログインに役立ちます。[qpdf の添付ファイルオプション](https://qpdf.readthedocs.io/en/stable/cli.html#embedded-files-attachments)を参照してください。
- sudo の timestamp 再利用は、cache ポリシー、所有ユーザー、端末／セッション、権限によります。[権限昇格ガイド](../linux-basics/linux-privilege-escalation/README.md#reusing-sudo-tokens)では確認項目を解説しています。
- `doas` には独自のルールと設定があります。[doas のセクション](../linux-basics/linux-privilege-escalation/README.md#doas)に従って、許可されたコマンドと書き込み可能な設定パスを確認してください。

### sudo で実行する build／package ツール

Foundry の `forge` を無制限に実行できる sudo 許可は、RunAs ID が root 以外のユーザーでも問題になる場合があります。`--use` などの compiler オプションではローカル実行ファイルを選択でき、`forge flatten -o` では出力ファイルを選択できます。悪用可能と判断する前に、インストール済み Forge のバージョン、正確な sudo 引数、アクセス可能な project と compiler のパス、出力の権限、実効環境を確認してください。`PATH` 経由で見つかる相対 helper 実行ファイルは、バージョンと環境に依存する経路であり、すべての Forge build に当てはまるものではありません。<sup>[[23]](#references)[[24]](#references)</sup>

root として `pacman` を無制限に実行できる許可では、パッケージの照会に限らず、`-U` でローカルパッケージを指定でき、パッケージにはインストールスクリプトを含められ、`--hookdir` では別の hook ディレクトリを指定できます。テストの前に、実効 sudo ルール、引数の制限と除外ルールを確認してください。受動的な調査でパッケージをインストールしたり hook を実行したりする必要はありません。<sup>[[25]](#references)[[26]](#references)</sup>

固定の sudo shell wrapper が、名前を指定した npm dependency をインストールしてから Node アプリケーションを起動する場合もあります。正確な RunAs ルール、パッケージがすでにインストールされているか、実効 `HOME` と npm `userconfig`、project の設定またはコマンドラインによる上書き、その名前に対して返される registry または package を権限の低いユーザーが制御できるかを確認します。[npm のドキュメントでは、ユーザー単位および project 単位の `.npmrc` 検索について説明されています](https://docs.npmjs.com/cli/v6/configuring-npm/npmrc/)。sudo の `HOME` の挙動はインストール済みポリシーとディストリビューションによって異なるため、特権 npm プロセスが書き込み可能なユーザーの `.npmrc` を読むとは限りません。新たにインストールされたパッケージが特権アプリケーションから import されると、そのアプリケーションの ID でモジュールコードが実行される可能性があります。インストール時スクリプトは、バージョンと設定に依存する別の経路です。[npm のドキュメントでは、そのライフサイクルとユーザーの扱いについて説明されています](https://docs.npmjs.com/cli/v6/using-npm/scripts/)。`.npmrc` のパスや `npm install` の行だけでは、あくまでレビューの手掛かりです。受動的な調査では、インストールやアプリケーションの起動を行わず、ルール、短い wrapper、設定パス、パッケージの来歴を確認してください。

root 対応の `pip` または `pip3 download` 許可も、引数によって呼び出し元が信頼できない source distribution を選べる場合、package build に関する確認の手掛かりになります。URL パターンがローカルサービスと `.tar.gz` suffix に制限されていても同様です。`pip download` は archive URL を受け付け、パッケージのメタデータを解決します。sdist の準備時には、archive が保存されるだけの段階で build backend や legacy `setup.py` のコードが実行される場合があります。正確な sudo RunAs と引数ルール、呼び出し元が選択した archive を公開または置き換えられるか、その pip バージョンが実際にメタデータを準備するかを確認します。固定された信頼できる archive や wheel だけでは、この経路は証明されません。受動的な調査では信頼できないパッケージを取得したり build したりしないでください。pip の[download コマンド](https://pip.pypa.io/en/stable/cli/pip_download/)、[build-system interface](https://pip.pypa.io/en/stable/reference/build-system/)、[secure-install のガイダンス](https://pip.pypa.io/en/stable/topics/secure-installs/)を参照してください。

呼び出し元指定のローカル project パスを使った `pip install` を許可する sudo ルールには、より直接的な build 境界があります。[pip はローカル project ディレクトリを受け付け](https://pip.pypa.io/en/stable/topics/local-project-installs/)、その build system を実行します。[build backend は project が制御する build hook を実行します](https://pip.pypa.io/en/stable/reference/build-system/)。このルールを特権コード実行と判断する前に、実効 RunAs ID、正確な引数の制限と拒否ルール、選択された project の制御、インストール済み pip／backend の挙動を確認してください。固定された信頼できる project や、呼び出し元指定のパスを許可しないルールでは、この経路は成立しません。受動的な調査ではパッケージをインストールせずに、ルールと project のメタデータを確認してください。

root として `easy_install` を無制限に実行できる許可も、関連するレガシーな package build の確認事項です。[Setuptools のドキュメント](https://setuptools.pypa.io/en/stable/deprecated/easy_install.html)によると、Easy Install はローカル project ディレクトリを受け付け、source distribution を build します。呼び出し元が制御する project の build 中に、sudo の ID で `setup.py` が実行される場合があります。実効 RunAs アカウント、コマンドと引数の正確な制限（後続の拒否ルールを含む）、選択された project を制御できるか、インストール済みツールの挙動を確認します。固定された信頼できる project や、呼び出し元指定の source を許可しないポリシーでは、この経路は成立しません。調査中にパッケージをインストールせず、ルールと project のメタデータを確認してください。

sudo で許可された Python wrapper が、呼び出し元指定の URL を使って `setuptools.package_index.PackageIndex.download` を呼び出す場合は、`pip download` とは別のレビュー対象です。[setuptools GHSA-5rjg-fvgr-3xxf](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf)では、78.1.1 より前の影響を受けるリリースにおいて、URL 由来のファイル名が意図された download ディレクトリから逸脱し、プロセスの権限で書き込む可能性が説明されています。実効 sudo RunAs と引数ルール、wrapper がこの API に呼び出し元の URL を渡すこと、インストール済み build またはベンダーの backport、その結果のパスがどこに解決されるかを確認します。バージョン文字列や書き込み可能な download ディレクトリだけでは、任意の書き込みは証明されません。調査中に URL を取得したりファイルを書き込んだりせず、短い wrapper とパッケージのメタデータを確認してください。

PyInstaller に呼び出し元指定の `.spec` ファイルを渡す sudo 許可付き build wrapper も、同じ信頼境界の確認が必要です。PyInstaller spec は**build 時に**評価される実行可能な Python であり、その `datas` エントリーによって、build ID が読み取れるファイルを artifact に含められます。正確な RunAs ユーザー、sudo の引数と拒否ルール、wrapper のパスと分岐処理、選択された spec ファイルを制御できるか、生成された artifact にアクセスできるかを確認します。`.py` 入力を許可しているだけ、または PyInstaller がインストールされているだけでは、spec ファイルの制御や特権実行は証明されません。受動的なレビューでは、範囲を限定した wrapper ファイルとメタデータのみを読み、build は実行しないでください。[PyInstaller spec ファイルのドキュメント](https://pyinstaller.org/en/stable/spec-files.html)を参照してください。

### sudo で実行する preset／plugin loader

呼び出し元指定の preset または plugin ディレクトリを受け付ける Python ツールは、sudo で与えられた権限でコードを import する場合があります。たとえば BBOT は `-p` で preset を受け付けます。[カスタムモジュールのドキュメント](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/#load-modules-from-custom-locations)では、追加の Python module ディレクトリを選択する `module_dirs` エントリーについて説明しています。実効 sudo ルールが呼び出し元指定の preset を許可し、呼び出し元が選択されたディレクトリ内の module を制御できる場合、ツールが無効な module を拒否する前でも、特権ユーザーとして import 時にコードが実行される可能性があります。調査中に module を読み込まず、インストール済みバージョン、sudo の正確な RunAs と引数ポリシー、preset と module のパスの所有者を確認してください。

### sudo で実行する Backdrop コマンドラインツール

[Bee](https://github.com/backdrop-contrib/bee) は Backdrop CMS 用の PHP コマンドラインツールです。`eval` (`php-eval`) と `php-script` コマンドは、呼び出し元指定の PHP を実行できます。したがって、Bee 実行ファイルを無制限の引数で root として実行できる sudo ルールがあり、Bee が Backdrop のインストールを bootstrap できる場合、root コード実行につながる可能性があります。サイトディレクトリから実行するか、グローバルな `--root=<directory>` オプションでサイトを指定します。Bee や Backdrop の `settings.php` ファイルが見つかっただけでは、sudo の許可、利用可能なサイト、bootstrap の成功は証明されません。テストの前に、実効 sudo ルール、コマンド除外の有無、実行ファイルの ID、サイトへのアクセスを確認してください。受動的な調査では Bee を実行せず、ルールとファイルパスを確認します。PHP コマンドの追加については[Bee のコマンド変更履歴](https://github.com/backdrop-contrib/bee/blob/1.x-1.x/CHANGELOG.md)を参照してください。

### sudo で実行する terminal server

`mosh-server` は、呼び出し元のユーザーとして対話型 terminal server を起動します。高位の UDP port と session key を選択し、その両方を呼び出し元に報告します。通常、クライアントが接続すると、そのユーザーのログイン shell を起動します。そのため、サーバーコマンド自体は detach しても、root 対応の無制限な `mosh-server` sudo 許可は shell に関するレビュー対象です。特権昇格経路と判断する前に、実効 RunAs ID、許可された引数と除外ルール、インストール済みバイナリ、shell、クライアントの利用可否、UDP アクセスを確認してください。受動的な調査では sudo ルールを確認し、server を起動したり有効な session key を表示したりしないでください。[Mosh server のマニュアル](https://manpages.debian.org/unstable/mosh/mosh-server.1.en.html)と[上流の設計メモ](https://github.com/mobile-shell/mosh#how-it-works)を参照してください。

### 呼び出し元の task file を書き換える特権バックアップ wrapper

root として実行する shell wrapper が、呼び出し元指定の task file を受け付け、source パスから `../` を取り除き、結果が許可されたディレクトリから始まるか確認し、task file を書き換えた後、*パス名*をバックアッププログラムへ渡す場合があります。完全に canonicalize した後の変換済みパスを確認します。文字列を一度置換しただけで、新たな traversal シーケンスができ、字句的な prefix チェックを通過する場合があります。また、バックアッププログラムが変換後のメモリ上のデータを読むのか、ファイルを再度開くのかも確認します。再度開くなら、書き換えに失敗したとき、元の入力がそのまま残る可能性があります。

Linux では、`fs.protected_regular` によって、world-writable かつ sticky なディレクトリ内にある他ユーザー所有の通常ファイルに対する `O_CREAT` の書き込みが拒否される場合があります。この拒否自体は保護になりますが、shell wrapper が書き込みエラーを無視すると、元の task file を使って処理が続く可能性があります。設定、ファイルの owner とディレクトリ、wrapper が失敗時に停止するかを確認します。実効 sudo ルールで特権ユーザーとして wrapper を実行でき、呼び出し元が task 入力と読み取り可能なバックアップ先を制御でき、バックアップユーティリティが保護された source を実際に含める場合に限り、このパスはファイル漏洩の候補となります。調査中にバックアップを実行せず、これらの条件を確認してください。

### 特権 packet ツールの引数ワイルドカード

`tcpdump` の sudo ルールでは、**引数パターン**の `*` は空白とスラッシュにも一致するため、パス名のような制限でも追加のオプションテキストを許す場合があります。これはコマンドの実行ファイルパスにあるワイルドカードとは異なります。完全な RunAs ルールと後続の拒否ルールを確認してください。オプションを injection できる場合、有用な読み取り／書き込み機能を `-F`、`-V`、`-r`、`-w`、`-Z` が提供するかどうかは、許可された起動方法とインストール済み[`tcpdump` のオプション仕様](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)によります。`-V` が読むのは capture filename のリストであり、任意の汎用ファイルを dump するものではありません。sudo がコマンドを許可していても、AppArmor やその他の MAC ポリシーがファイルアクセスをブロックする場合があります。ディスク上に profile ファイルがあっても、ロードされていることや強制モードであることの証明にはなりません。結論を出す前に、認可とポリシーを受動的に確認してください。[sudoers のマニュアル](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)では、ワイルドカードの違いが説明されています。

root 対応の sudo ルールに `tcpdump` 実行ファイルだけが記載され、引数の制限がない場合も確認が必要です。[tcpdump のマニュアル](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)では、保存した capture が `-C` または `-G` でローテーションするとき、`-z` がローテーション後のコマンドとして実行されると説明されています。`-Z` またはコンパイル時のデフォルトによって、そのコマンドが実行される前に権限が落とされる場合があります。特権昇格経路と判断する前に、実効 sudo ルール、インストール済み build、権限を落とす挙動、ローテーションが発生し得るかを確認します。強調表示されたルールは候補であり、root としてコマンドを実行できる証拠ではありません。

### sudo で実行する Nmap wrapper

sudo で許可された `nmap` のパスが shell wrapper である場合、許可されたパスと転送されるすべてのオプションを確認します。よく知られた `--script` 表記をブロックしても、NSE のコード読み込みが必ず防がれるとは限りません。Nmap の[`--datadir`](https://nmap.org/book/man-misc-options.html)はデータファイルを選択し、script が有効な場合、NSE は選択されたデータディレクトリから[`nse_main.lua` を読み込みます](https://nmap.org/book/nse-implementation.html)。インストール済み build によっては、別の長形式オプション表記も受け付けるため、そのバイナリの実際の parser と制限を比較してください。[`--excludefile`](https://nmap.org/book/man-target-specification.html)は別のファイル読み取り面であり、parser エラーからテキストが漏れる場合があります。調査中に scan を実行せず、実効 sudo ルール、wrapper の処理、Nmap のバージョン、ディレクトリの制御、MAC ポリシーを確認してください。

### sudo で実行する Mercurial pull hook

固定された source を指定する `sudo hg pull /fixed/source` でも、コマンドが `-R` で repository を固定しない限り、**受信側**の repository は current working directory によって選択されます。呼び出し元制御の受信側 repository では `.hg/hgrc` に hook を定義でき、その hook が sudo の RunAs ユーザーとして実行される可能性があります。[Mercurial は、信頼されていないユーザーまたはグループが所有する repository 設定を無視します](https://mercurial-scm.org/help/topics/config)。コード実行と判断する前に、RunAs アカウントの信頼されたユーザー／グループと正確な working directory を確認してください。受動的なレビューではポリシーと設定を読むだけで十分です。調査のために pull や hook の実行を行わないでください。

### sudo で実行する Git pull hook

root としての正確な `sudo git pull` 許可については、working directory で選択される**受信側**repository も確認してください。呼び出し元所有の repository に実行可能な `post-merge` hook があり、pull で merge が正常に行われると、Git プロセスの ID で実行されます。[Git のドキュメントではこの hook が説明されています](https://git-scm.com/docs/githooks)。また、[pull における merge と rebase の挙動](https://git-scm.com/docs/git-pull)も参照してください。実効 sudo ルールと CWD、active な hook のパスと権限、新しい commit を含む merge に到達できるかを確認します。失敗した pull、何も変更しない pull、rebase のみの pull では、この hook 経路は成立しません。特権 pull を実行せず、ポリシーと repository のメタデータを確認してください。

### sudo で実行する rsync archive copy

`sudo rsync -a ... /writable/source/* /fixed/destination/` では、**sudoers の引数パターン**にある `*` が空白に一致し、source と destination の間に追加オプションを許す場合があります。これはファイル名に対する shell 展開とは異なります。呼び出し元が source を用意でき、特権 rsync プロセスが destination に書き込める場合、[`--chown`](https://download.samba.org/pub/rsync/rsync.1)で特権所有者を指定できます。archive mode は permission bit を保持するため、所有者が設定された SetUID ファイルを作成できる可能性があります。正確な[sudoers のワイルドカードの意味](https://man7.org/linux/man-pages/man5/sudoers.5.html)、rsync のバージョン、後続の拒否ルール、ファイルシステムの `nosuid`、MAC ポリシーを確認します。一致するルールはレビュー候補であり、特権昇格成功の証拠ではありません。

### sudo で実行する packet-filter ルールの export

`iptables` と `iptables-save` の両方（または対応する `ip6tables` の組み合わせ）を root として無制限に実行できる許可は、ファイル書き込みの観点から確認が必要です。`comment` match は呼び出し元が選んだルールテキストを受け付け、`iptables-save -f` はシリアライズされた ruleset を指定パスへ書き込みます。<sup>[[20]](#references)[[21]](#references)</sup>有用な payload になるかは、インストール済み backend が comment をどうシリアライズするか、出力先ファイルが export 内の他の行を受け入れるかによります。`iptables-save` だけでは、任意に選択した内容を書き込めません。sudo RunAs ID、引数と除外ルール、利用可能な match extension、backend、出力先の権限を確認します。調査中は firewall ルールを変更したりファイルを書き込んだりせず、許可内容を確認してください。

### 特権で使われる Below のログディレクトリ

[CVE-2025-27591](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w)の影響を受けたのは、world-writable な `/var/log/below` ディレクトリを作成する 0.9.0 より前の Below リリースです。サービスや許可された sudo コマンドが影響を受ける build を root として実行する場合、sticky bit のないログディレクトリ内で書き込みと検索ができるユーザーは、特権プロセスがログを開く前にログエントリーを symlink に置き換えられる可能性があります。インストール済みパッケージに修正が適用されているか、正確な特権実行経路、実効的なディレクトリアクセス、sticky bit と ACL、`/var/log/below/error_root.log` のメタデータを確認してください。world-writable なパスや sudo ルールがあるだけでは、一連の条件は証明されません。sticky directory やベンダーの backport によって評価は変わります。受動的な調査ではメタデータを確認するだけでよく、link の作成や特権プログラムの実行は必要ありません。

### 書き込み可能な入力を使う特権 support bundle の収集

sudo で許可された support-profile スクリプトは、root として固定されたログパスを読み、その内容を profile archive にコピーする場合があります。実際のスクリプトがファイルを読むか確認したうえで、呼び出し元が source パスや親ディレクトリエントリーを symlink に置き換えられるか確認します。特権読み取りがその link を追跡し、生成された archive を呼び出し元が読める場合、保護されたファイルが漏洩する可能性があります。sudo 許可、書き込み可能な source パス、特権読み取り、読み取り可能な出力のすべてが必要です。書き込み可能なログや profile filename だけでは不十分です。調査中にファイルを置き換えたり profile を生成したりせず、実効権限と link のメタデータを確認してください。[Nagios XI の support ガイダンス](https://support.nagios.com/forum/viewtopic.php?t=62758)では、root として実行する profile スクリプトと出力 archive が説明されており、このような bundle の入力と出力を制限する必要性が示されています。

### root として実行する Python archive restore スクリプト

Python の restore スクリプトに対する範囲の狭い sudo ルールでも、archive 入力を確認する必要があります。呼び出し元が archive を選択または置き換えられ、スクリプトが root として `tarfile.extractall(filter="data")` で展開する場合、その filter を信用する前に interpreter のセキュリティ更新を確認してください。CPython は、CVE-2025-4517 を含む複数の symlink／hard-link filter 回避を、3.9.23、3.10.18、3.11.13、3.12.11、3.13.4 で修正しました。ディストリビューションの backport により、より古いバージョンにも修正が適用されている場合があります。そのため、表示された interpreter のバージョンだけでは影響の有無を判断できません。<sup>[[16]](#references)[[17]](#references)</sup>

受動的なレビューでは、正確な sudo コマンドとスクリプトを読み、どの引数で archive を選択するかを追跡し、現在のユーザーが archive またはその親ディレクトリに書き込めるかを確認します。インストール済みバージョンにベンダーの修正が適用されているかと、展開先は別々に確認してください。`filter="data"` があっても、すべての信頼できない archive が安全になるわけではありません。<sup>[[16]](#references)[[17]](#references)</sup>

### sudo で実行する machine-learning model loader

呼び出し元指定の `.pt`、`.pth`、`.ckpt` ファイルを許可する sudo ルールは、特権スクリプトがそのファイルを[`torch.load`](https://docs.pytorch.org/docs/stable/generated/torch.load.html)、`pickle.load`、その他の pickle ベース loader に渡す場合、確認が必要です。実効 RunAs ルール、呼び出し元が選択された model を作成または置き換えられるか、shell wrapper を経由して Python helper に渡る実際の引数フローを確認します。`.pth` 拡張子は無関係な Python site configuration ファイルにも使われるため、拡張子だけでは model が読み込まれる証拠になりません。archive scan や静的な pickle scan だけでは、その後の load が安全だとは証明できません。loader の[バージョンによって異なる `weights_only` の挙動](https://docs.pytorch.org/docs/stable/notes/serialization.html)と allowlist を確認してください。[ML の pickle と Fickling に関する注意事項](../../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)も参照してください。受動的な調査で model を読み込んだり展開したりしないでください。

### 保存された入力を sudo で実行する式 parser

root として sudo 経由で実行する固定 Python スクリプトでも、権限の低いユーザーがアプリケーションデータベースに保存できるテキストを評価する場合があります。TensorFlow では、`preprocess_input_exprs_arg_string(value, safe=False)` を呼び出すと `eval` 経路が選択されます。[TensorFlow の advisory](https://github.com/tensorflow/tensorflow/security/advisories/GHSA-75c9-jrh4-79mc)では、安全でない parser と、コマンドライン呼び出し元に対する修正が説明されています。コマンドライン呼び出し元に修正が適用されていても、アプリケーションが明示的に `safe=False` を呼び出す場合は別途確認が必要です。実効 sudo ルール、対象の入力行を変更できるユーザー、フィルタリングや scoring によってその行が呼び出し箇所まで到達するか、インストール済み関数の挙動を確認します。TensorFlow のバージョン、sudo 許可、ハードコードされた model ファイルだけでは、一連の条件は証明されません。調査中は特権 helper を実行したりテスト式を送信したりせず、スクリプトとデータフローを受動的に確認してください。

### sudo で許可された needrestart の設定

`needrestart -c` は呼び出し元指定の Perl 設定ファイルを読み込み、その内容を評価します。`sudo -l` で root としての `needrestart` が許可され、引数で `-c` を指定でき、呼び出し元が書き込み可能な場所にある読み取り可能な設定ファイルを選択できる場合、その許可は root コード実行につながる可能性があります。sudo の正確な RunAs と引数ルールを確認します。固定された引数リストだけを許可するルールなら、この経路を防げる場合があります。これは needrestart の interpreter scanning に関する脆弱性とは別の問題です。パッケージを更新したり `interpscan` を無効化したりしても、root としての無制限な `-c` 許可は安全になりません。<sup>[[2]](#references)[[18]](#references)[[19]](#references)</sup>

### 別アカウントとして sudo で実行する Python import

固定の Python entry point でも、sudo がスクリプトを**root 以外**のサービスユーザーとして実行する場合を含め、呼び出し元が編集または置換できる module を import する場合があります。リテラルな `from utils import status` では、package ディレクトリの権限だけでなく、ローカルの `utils/__init__.py` と `utils/status.py` も確認します。書き込み可能なファイルを実行経路と判断する前に、スクリプトの import パス、sudo で許可された正確な引数、該当する処理が import に到達するかを確認してください。調査中に import やスクリプト実行をせず、ファイルと権限を確認してください。<sup>[[2]](#references)[[3]](#references)</sup>

`python3 /absolute/script.py` に対する正確な sudo ルールでは、スクリプトは読み取り可能であればよく、実行可能である必要も shebang も必要ありません。ローカルに**存在しない** module も確認します。スクリプトが import する module の filename を、呼び出し元が書き込み可能なスクリプトディレクトリに作成できるなら、Python がそのファイルを RunAs ID で読み込む可能性があります。実効 sudo ルール、インタープリターの実際の[モジュール検索パス](https://docs.python.org/3/library/sys_path_init.html)、module が built-in または frozen か、import に到達するかを確認してください。スクリプトへの直接 sudo ルールには、実行ビットと shebang に関して異なる要件があります。`sudo -u account` の後ろに呼び出し元指定の token を追加する別の wrapper も、引数フローを確認する必要があります。追加された `-u` が関係するのは、呼び出された sudo ポリシーが結果の ID を許可する場合だけです。静的な文字列だけでは、どちらの経路も証明されません。

### 呼び出し元制御の設定を使う sudo Apache

特権で実行される `apachectl`、`apache2ctl`、`httpd` が呼び出し元制御の `-f` 設定ファイルを受け付ける sudo ルールでは、そのファイルと親ディレクトリの権限を確認します。Apache の[`LoadModule`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadmodule) directive は、module 名に続いて**module filename**を受け付けます。[`LoadFile`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadfile) もファイルを読み込みます。[`Include` と `IncludeOptional`](https://httpd.apache.org/docs/2.4/mod/core.html#include) によって設定を追加したり、エラーを通じてファイル内容を露出させたりできます。カスタム wrapper がこれらのパスを検証したり、権限を落としたり、引数を制限したりする可能性もあるため、書き込み可能な設定ファイルはコード実行の証拠ではなく、レビュー候補です。結論を出す前に、パスの canonicalization、symlink、directive の parsing を確認してください。

### 呼び出し元制御の設定を使う sudo nginx

root 対応の `nginx` を無制限に実行できるルールでは、[`-c` で別の設定を選択できます](https://nginx.org/en/docs/switches.html)。sudo の正確な引数と除外ルール、呼び出し元が設定を指定できるか、生成される master や worker が保護されたパスにアクセスできるかを確認します。選択した `root` と `autoindex` により、新しい listener を通じてファイルを露出させる可能性があります。[`dav_methods PUT`](https://nginx.org/en/docs/http/ngx_http_dav_module.html)によって、特権ファイルへの書き込み経路が生まれる可能性がありますが、DAV module はデフォルトでは build に含まれません。module の有無、listener への到達性、ファイル権限、一時ファイルの挙動を確認する必要があります。[`error_log` directive](https://nginx.org/en/docs/ngx_core_module.html#error_log)でも任意のファイルを指定できます。`/etc/ld.so.preload` のような機密性の高い設定ファイルへのログ書き込みが権限昇格経路となるには、実効的な特権書き込みと、制御可能なログレコードが必要です。`sudo -l` で実行ファイルが強調表示されていても、これらの経路が機能する証拠ではなく、レビューの手掛かりです。受動的な調査では nginx を起動したり再設定したりしないでください。

### 特権 Bash prompt におけるパターン比較

sudo で許可された Bash スクリプトが呼び出し元から値を読み取り、`[[ "$expected" == $entered ]]` でチェックする場合、Bash は引用符で囲まれていない右辺をパターンとして解釈します。そのため、expected の値を知らなくてもワイルドカードで比較を通過できる可能性があります。右辺を引用符で囲む（`[[ "$expected" == "$entered" ]]`）と、リテラル文字列として比較されます。正確な sudo ルール、prompt に到達できるか、比較の後にスクリプトが何をするかを確認します。この構文だけでは悪用可能な経路は証明されません。調査中に expected の値を表示しないでください。[Bash の conditional constructs に関するリファレンス](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)を参照してください。

### ファイルをダウンロードして実行する sudo helper

呼び出し元指定の URL を受け付け、その応答をディスクに書き込み、その後 interpreter や shell でそのファイルを実行するカスタム helper に対する、root 対応の無制限 sudo 許可は、データフローの確認が必要です。[sudoers では、コマンドエントリーに引数が記載されていなければ任意の引数が許可されます](https://man7.org/linux/man-pages/man5/sudoers.5.html)。実行ファイルのパスが固定されていても、引数から選択できるものは制限されません。インストール済み helper における実際の URL 検証、出力パス、成功時の分岐、その後の実行を確認します。libcurl の import や表示可能な文字列があるだけでは、一連の処理は証明されません。

固定された出力 basename でも、**呼び出し元が制御する working directory にある相対パス**を helper が使う場合、書き込みと実行の間に置き換えられる可能性があります。root 所有ファイルの rename や置き換えは、ファイルの mode だけでなく、ディレクトリへの書き込み／検索権限と sticky bit の制限で決まります。[`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html)を参照してください。helper が後からパスを再度開くのか、すでに開いている file descriptor を使うのか、書き込み前に信頼できるディレクトリへ移動するかを確認します。sudo ポリシー、helper、ディレクトリのメタデータを受動的に確認し、調査中に特権ダウンロードを実行したり race を仕掛けたりしないでください。

root として実行する download helper が、`curl <caller input> -o <fixed output>` のような Bash コマンド文字列を構築する場合、**引数**の injection も起こり得ます。空白を拒否する filter でも、[Bash の brace expansion](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html)は残ります。引用符で囲まれていない comma 区切りの要素が、別々の curl 引数に展開される場合があります。入力が固定 `-o` より前に curl へ渡る場合、呼び出し元指定の出力オプションで、helper の ID における最初の URL の出力先を選択できる可能性があります。[curl は出力オプションを順番に URL に関連付けます](https://curl.se/docs/manpage.html#-o)。正確な shell、引用符付け、入力検証、実効 sudo ルール、curl の引数順と対応 URL scheme、取得するバイト列を呼び出し元が制御できるか、結果を読めるかを確認します。PyInstaller でパッケージ化された実行ファイルに Python のアプリケーションロジックが含まれている場合はありますが、パッケージ化を示す記号や `curl` という文字列だけでは、このデータフローは証明されません。認可されている場合は、範囲を限定したオフラインコピーを確認してください。通常の調査では helper を実行したり、攻撃者指定のデータを取得したりしないでください。

root で sudo 実行する shell スクリプトが[`mktemp -u`／`--dry-run`](https://www.gnu.org/software/coreutils/manual/html_node/mktemp-invocation.html)を呼び出すだけなら、未使用の名前を選択するにすぎず、ファイルは作成**されません**。その後、別ユーザーが影響を与えられるディレクトリでその名前を使ってファイルを作成し、再度開いて、内容を root の `authorized_keys` のような保護された destination に追記する場合、一時ファイルの race がないか確認してください。正確な sudo ルール、ディレクトリとファイルの owner、作成および再オープンの順序、kernel の保護、特権書き込みに攻撃者制御のバイト列が実際に使われるかを確認します。`mktemp -u` という文字列や書き込み可能な `/tmp` だけでは、race は証明されません。調査中にスクリプトを実行したり一時ファイルを race させたりせず、スクリプトとパスのメタデータを確認してください。

## 防御上の注意点

- sudo 経由でインタープリターや対話型エディターを許可しないようにします。<sup>[[1]](#references)</sup>
- 単一の限定された管理操作を実行する、root 所有の固定 wrapper を優先します。<sup>[[1]](#references)[[2]](#references)</sup>
- インタープリターが避けられない場合は、正確なスクリプトパスに制限し、ユーザー制御の引数、書き込み可能な import、`PYTHONPATH`、安全でない環境の保持を防ぎます。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- ファイル編集が必要な場合は、正確なファイルパスに制限し、修正済みの sudo バージョンと厳格な環境処理を前提に `sudoedit` を検討します。<sup>[[1]](#references)[[2]](#references)</sup>
- `SETENV`、`env_keep`、書き込み可能な working directory、書き込み可能な module／import パス、`NOEXEC`、`use_pty`、logging を確認します。ただし、これらを完全な sandbox と見なしてはいけません。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [コマンドラインと環境 — Python ドキュメント](https://docs.python.org/3/using/cmdline.html)
- [4] [os — その他のオペレーティングシステムインターフェース — Python ドキュメント](https://docs.python.org/3/library/os.html)
- [5] [perlrun — Perl インタープリターの実行方法](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl ドキュメント](https://perldoc.perl.org/functions/exec)
- [7] [Ruby のコマンドラインオプション](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby ドキュメント](https://ruby-doc.org/3.4/Kernel.html)
- [9] [コマンドライン API — Node.js ドキュメント](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js ドキュメント](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua マニュアルページ](https://www.lua.org/manual/5.4/lua.html)
- [12] [GNU nano テキストエディター](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [リダイレクト — Bash リファレンスマニュアル](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [16] [Python 3.9.23～3.13.4 のセキュリティリリース](https://discuss.python.org/t/python-3-13-4-3-12-11-3-11-13-3-10-18-and-3-9-23-are-now-available/94367)
- [17] [tarfile の展開 filter — Python ドキュメント](https://docs.python.org/3/library/tarfile.html#extraction-filters)
- [18] [needrestart の設定オプションと評価 — upstream source](https://github.com/liske/needrestart/blob/master/needrestart)
- [19] [needrestart のコマンド挙動 — GTFOBins](https://gtfobins.org/gtfobins/needrestart/)
- [20] [iptables-save(8) — netfilter マニュアルページ](https://www.man7.org/linux/man-pages/man8/iptables-save.8.html)
- [21] [iptables-extensions(8): comment match — netfilter マニュアルページ](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [22] [単純コマンドの展開 — Bash リファレンスマニュアル](https://www.gnu.org/s/bash/manual/html_node/Simple-Command-Expansion.html)
- [23] [Forge の compiler オプション — Foundry ドキュメント](https://getfoundry.sh/forge/reference/forge-inspect/)
- [24] [Forge flatten — Foundry ドキュメント](https://getfoundry.sh/forge/reference/forge-flatten/)
- [25] [pacman(8) — Arch マニュアルページ](https://man.archlinux.org/man/pacman.8.en)
- [26] [PKGBUILD(5) のインストールスクリプト — Arch マニュアルページ](https://man.archlinux.org/man/core/pacman/PKGBUILD.5.en)
{{#include ../../banners/hacktricks-training.md}}
