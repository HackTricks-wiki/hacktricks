# Shellの起動、alias、履歴

{{#include ../../banners/hacktricks-training.md}}

alias、function、起動ファイル、または環境変数によって実行方法が変わると、shellコマンドは同じ名前の実行ファイルとは異なる動作をすることがあります。コマンドの出力を信用したり、スクリプトが対話型セッションと同じPATHを使うと想定したりする前に、これらを確認してください。

## 現在のshellを調べる

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` と `command -V` を使うと、名前が alias、function、builtin、またはファイルのいずれに解決されるかを確認できます。`command -v` と `which` では、alias や function について同じ結果が得られるとは限りません。Shell history からコマンドや認証情報が漏れることがありますが、履歴が不完全だったり、無効になっていたり、セッション終了までメモリ内に保持されていたりする場合があります。

## 起動ファイルと履歴ファイルを確認する

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

ユーザーが書き込み可能な startup file は、次回の shell 起動時にコマンドを実行できます。低い権限のアカウントがシステム全体の startup file や特権ユーザーの startup file を変更できる場合、より重大な問題になります。非対話型 Bash は `BASH_ENV` で指定されたファイルも読み込むことがあります。[environment variables](linux-environment-variables.md#bash_env--env) のページでは、この動作やその他のインタープリターフックについて説明しています。persistence path と断定する前に、ログイン、対話型、非対話型セッションで実際の shell がどのファイルを読み込むか確認してください。

グローバル startup file が読み込むファイルも調べてください。たとえば、`/etc/bash.bashrc` に `source /opt/app/venv/bin/activate` が文字どおり記述されている場合、shell がその startup file を実際に読み込むと、activation file が shell code として実行されます。activation file、symlink と親ディレクトリの権限、ACL を確認してください。低い権限のユーザーが特権 shell に影響を与えられるのは、その shell または後続の特権タスクがそのファイルを読み込む場合に限られます。書き込み権限が `sudoedit` に依存する場合は、まず正確な sudoers ルールと、インストール済みのベンダーパッチ適用済み sudo パッケージを確認してください。upstream のバージョン文字列だけでは、[sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) があるとは判断できません。

[users and sessions](../user-information/user-and-session-triage.md) の説明に従って、history、dotfiles、バックアップに秘密情報がないか確認してください。特権スクリプトが名前でコマンドを解決する場合は、この調査と [PATH hijacking guidance](linux-environment-variables.md#path) を組み合わせてください。
{{#include ../../banners/hacktricks-training.md}}
