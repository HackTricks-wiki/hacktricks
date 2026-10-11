# シェルの起動、エイリアス、履歴

{{#include ../../banners/hacktricks-training.md}}

エイリアス、関数、起動ファイル、または環境変数によって実行方法が変わると、シェルコマンドの動作は同じ名前の実行ファイルとは異なる場合があります。コマンドの出力を信用したり、スクリプトが対話型セッションと同じ PATH を使うと仮定したりする前に、これらを確認してください。

## 現在のシェルを確認する

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` と `command -V` を使うと、名前が alias、function、builtin、file のいずれに解決されるかを確認できます。`command -v` と `which` では、alias や function について同じ結果が得られるとは限りません。Shell history からコマンドや認証情報が漏れることがありますが、内容が不完全だったり、無効化されていたり、セッション終了までメモリ上に保持されていたりする場合があります。

## 起動ファイルと履歴ファイルを確認する

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

ユーザーが書き込み可能な startup file は、次回の shell 起動時にコマンドを実行できます。下位権限のアカウントが変更できる場合、システム全体の startup file や特権ユーザーの startup file は、より機微な対象です。非対話型の Bash も `BASH_ENV` で指定されたファイルを読み込むことがあります。この動作やその他の interpreter hook については、[environment variables](linux-environment-variables.md#bash_env--env) のページで説明しています。永続化経路だと断定する前に、実際の shell が login、interactive、non-interactive の各セッションでどのファイルを読み込むか確認してください。

グローバルな startup file が読み込むファイルも確認してください。たとえば、`/etc/bash.bashrc` に `source /opt/app/venv/bin/activate` という記述があれば、shell が実際にその startup file を読み込む際に、activation file が shell code として実行されます。activation file、symlink と親ディレクトリの permissions、ACLs を確認してください。下位権限のユーザーが特権 shell に影響を及ぼせるのは、その shell または特権タスクが後からそのファイルを読み込む場合に限られます。書き込み権限が `sudoedit` に依存する場合は、正確な sudoers rule と、インストールされているベンダーによるパッチ適用済みの sudo package をまず確認してください。upstream のバージョン文字列だけでは、[sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) の有無は判断できません。

[users and sessions](../user-information/user-and-session-triage.md) の説明に従い、history、dotfiles、backups に secrets がないか確認してください。特権スクリプトが名前でコマンドを解決する場合は、この確認に [PATH hijacking のガイダンス](linux-environment-variables.md#path) も組み合わせてください。
{{#include ../../banners/hacktricks-training.md}}
