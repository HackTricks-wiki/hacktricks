# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Bash が非対話的に起動されてスクリプトまたは `-c` コマンドを実行すると、`BASH_ENV` の値を展開し、指定されたコマンドを実行する前に、結果として得られたファイルを source します。Bash はこのファイルの検索に `PATH` を使用しません。そのため、攻撃者が制御する環境変数を使用して非対話的な Bash を起動するプロセスでは、読み取り可能な shell payload を最初に実行させることができます。<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
フックは対象が実際に Bash を起動した場合にのみ実行されます。別のプラットフォーム上の `/bin/sh` や、shell なしでコマンドを実行するプログラムは、必ずしもこれを受け入れるとは限りません。Bash は privileged mode では `BASH_ENV` を無視します。effective user/group ID と real user/group ID が異なる場合、Bash は startup files もスキップし、`-p` が指定されない限り effective ID をリセットします。`-p` を指定すると privileged mode は有効なままとなり、`BASH_ENV` も引き続き無視されます。<sup>[[1]](#references)[[2]](#references)</sup>

macOS では、`launchd` jobs で継承される、または job ごとの environment variables を定義できるため、privileged scripts に渡される plists と launch contexts を調査してください。interpreter variables の sanitize を SIP だけに依存しないでください。最小限の environment（`env -i`）を使用し、`BASH_ENV` を明示的に unset し、意図した interpreter を absolute path で呼び出し、書き込み可能な startup files を避けてください。

## zsh `ZDOTDIR`

zsh は、non-interactive shells を含むすべての通常の shell で `$ZDOTDIR/.zshenv` を読み込みます。`ZDOTDIR` が unset の場合は `HOME` を使用します。そのため、`ZDOTDIR` を書き込み可能な directory に redirect すると、`zsh -c` command または script の前にその `.zshenv` が実行されます。<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` は `RCS` オプションを解除し、このユーザーの startup file をスキップします。グローバルな `/etc/zshenv` は引き続き読み込まれるため、信頼できる最小限の内容にしておく必要があります。

## fish `XDG_CONFIG_HOME`

fish は、interactive shell や login shell に限らず、すべての shell の起動時に `$XDG_CONFIG_HOME/fish/conf.d/*.fish` と `$XDG_CONFIG_HOME/fish/config.fish` を読み込みます。また、`XDG_DATA_DIRS` のエントリ配下にある `fish/vendor_conf.d/*.fish` も実行します。そのため、攻撃者がこれらの変数のいずれかと読み取り可能なディレクトリを制御できる場合、fish script または `-c` command より前に code を実行できます。<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
信頼できる呼び出しには `fish --no-config` を使用し、信頼できない XDG path variables をクリアします。

## References

- [1] [Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash Invoking Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh Startup/Shutdown Files](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish Configuration files](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
