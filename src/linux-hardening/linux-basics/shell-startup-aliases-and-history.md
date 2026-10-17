# Shellの起動、エイリアス、履歴

{{#include ../../banners/hacktricks-training.md}}

エイリアス、関数、起動ファイル、または環境変数によって実行方法が変わると、shellコマンドは同じ名前の実行ファイルとは異なる動作をすることがあります。コマンドの出力を信用したり、スクリプトが対話型セッションと同じPATHを使うと思い込んだりする前に、これらを確認してください。

## 現在のshellを調べる

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` と `command -V` を使うと、名前が alias、function、builtin、file のどれに解決されるかが分かります。`command -v` と `which` は、alias や function について同じ結果を示すとは限りません。Shell history からコマンドや認証情報が見つかることがありますが、不完全な場合や無効化されている場合、またはセッション終了までメモリ上に保持される場合があります。

## 起動ファイルと履歴ファイルを確認する

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

ユーザーが書き込み可能な startup file は、次回の shell 起動時にコマンドを実行できます。システム全体の startup file や、権限の高いユーザーの startup file は、権限の低いアカウントが変更できる場合、より重大なリスクとなります。非対話型の Bash も、`BASH_ENV` で指定されたファイルを読み込むことがあります。[environment variables](linux-environment-variables.md#bash_env--env) のページでは、この挙動やその他の interpreter hook について説明しています。永続化の経路だと判断する前に、実際の shell が login、interactive、non-interactive の各セッションでどのファイルを読み込むか確認してください。

global startup file が読み込むファイルも確認してください。たとえば、`/etc/bash.bashrc` に文字列として `source /opt/app/venv/bin/activate` が記述されている場合、shell が実際にその startup file を読み込むと、activation file が shell code として実行されます。activation file、symlink と親ディレクトリの permissions、ACL を確認してください。権限の低いユーザーが書き込み可能なファイルを変更できても、特権 shell または特権タスクが後でそのファイルを読み込む場合に限り、影響を与えられます。書き込みアクセスが `sudoedit` に依存する場合は、該当する sudoers rule と、インストール済みの vendor-patched sudo package をまず確認してください。upstream の version string だけでは、[sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) があるとは判断できません。

[users and sessions](../user-information/user-and-session-triage.md) の説明に従って、history、dotfiles、backups に secrets がないか確認してください。特権スクリプトが名前でコマンドを解決する場合は、この確認に [PATH hijacking guidance](linux-environment-variables.md#path) も加えてください。

## Zsh startup のリダイレクトとコンパイル済みファイル

デフォルトの `RCS` 設定では、zsh は通常の起動時に `$ZDOTDIR/.zshenv` を読み込みます。これには `zsh -c` や scripts も含まれます。`ZDOTDIR` が設定されていない場合は、`$HOME` が使われます。command runner が environment map を受け取る場合、いずれかの変数を特権 zsh process に渡すかどうかを確認してください。その場合、書き込み可能な `.zshenv` は、runner がチェックまたは allowlist する command body より前に実行される可能性があります。これには、特権 process がリダイレクトされた directory を引き継ぐ必要があります。`zsh -f` はユーザーの startup file をスキップしますが、global `zshenv` はスキップしません（通常は `/etc/zshenv` ですが、distribution によってパスは異なります）。[macOS zsh injection page](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) に、最小限の `ZDOTDIR` の例があります。<sup>[[1]](#references)[[2]](#references)</sup>

新しく、有効な `.zshenv.zwc` または `.zshrc.zwc` が存在する場合、plaintext の startup file の代わりに実行されます。startup directory に書き込み可能であれば、変更した file をコンパイルした後、無害に見える plaintext に戻すことで、実行可能な code をコンパイル済みファイルに残せます。これは難読化であり、暗号化ではありません。以下の使い捨てテストは、テキストファイルだけを調べても不十分な理由を示しています。実際の home directory には触れません。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

実際のターゲットでは、有効な `ZDOTDIR`/`HOME` を特定し、テキストファイルと `.zwc` ファイルの両方を調べて、タイムスタンプ、所有者、書き込み可能な親ディレクトリを確認してください。`.zwc` ファイルが優先されるには、元のファイルと一致し、かつ新しいものでなければなりません。<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh の起動ファイルと終了ファイル](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Shell の起動環境へのコード注入に関する勧告](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh の組み込みコマンド: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [確認し忘れた .zshrc.zwc](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
