# Shellの起動、alias、履歴

{{#include ../../banners/hacktricks-training.md}}

alias、関数、起動ファイル、または環境変数によって実行方法が変わると、shellコマンドは同じ名前の実行ファイルとは異なる動作をすることがあります。コマンドの出力を信用したり、スクリプトが対話型セッションと同じPATHを使うと思い込んだりする前に、これらを確認してください。

## 現在のshellを調べる

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` と `command -V` を使うと、名前が alias、function、builtin、file のいずれに解決されるかを確認できます。`command -v` と `which` では、alias や function の扱いが異なる場合があります。Shell history からコマンドや認証情報が見つかることがありますが、履歴が不完全だったり、無効になっていたり、セッション終了までメモリ上に保持されていたりする場合があります。

## 起動設定ファイルと履歴ファイルを確認する

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

ユーザーが書き込み可能な起動ファイルは、次回の shell 起動時にコマンドを実行できます。システム全体の起動ファイルや特権ユーザーの起動ファイルは、低い権限のアカウントが変更できる場合、より重大なリスクになります。非対話型の Bash も、`BASH_ENV` で指定されたファイルを読み込むことがあります。[環境変数](linux-environment-variables.md#bash_env--env)のページでは、この動作やその他のインタープリターのフックについて説明しています。永続化の経路だと断定する前に、ログイン、対話型、非対話型の各セッションで、実際の shell がどのファイルを読み込むか確認してください。

グローバルな起動ファイルから読み込まれるファイルも調べてください。たとえば、`/etc/bash.bashrc` に `source /opt/app/venv/bin/activate` とそのまま記述されている場合、shell がその起動ファイルを実際に読み込むと、activation ファイルが shell コードとして実行されます。activation ファイル、シンボリックリンクと親ディレクトリの権限、ACL を確認してください。低い権限のユーザーが特権 shell に影響を与えられるのは、その shell または特権タスクが後でそのファイルを読み込む場合に限られます。書き込みアクセスが `sudoedit` に依存する場合は、まず sudoers ルールの正確な内容と、インストール済みのベンダーパッチ適用済み sudo パッケージを確認してください。上流版のバージョン文字列だけでは、[sudoedit の引数インジェクション脆弱性](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands)があるとは判断できません。

[ユーザーとセッション](../user-information/user-and-session-triage.md)で説明されているように、history、dotfiles、バックアップに秘密情報がないか確認してください。特権スクリプトがコマンドを名前で解決する場合は、この調査と [PATH hijacking のガイダンス](linux-environment-variables.md#path)を組み合わせてください。
{{#include ../../banners/hacktricks-training.md}}
