# シェルの起動設定、エイリアス、履歴

{{#include ../../banners/hacktricks-training.md}}

エイリアス、関数、起動ファイル、環境変数によって実行方法が変わると、シェルコマンドは同じ名前の実行ファイルとは異なる動作をすることがあります。コマンドの出力を信用したり、スクリプトが対話型セッションと同じ PATH を使うと想定したりする前に、これらを確認してください。

## 現在のシェルを確認する

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` と `command -V` を使うと、名前が alias、function、builtin、file のいずれに解決されるかがわかります。`command -v` と `which` では、alias や function について同じ結果が得られるとは限りません。Shell history からコマンドや認証情報が漏れることがありますが、履歴が不完全だったり、無効になっていたり、セッション終了までメモリ上に保持されていたりする場合もあります。

## 起動ファイルと履歴ファイルを確認する

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

ユーザーが書き込み可能な startup file は、次回の shell 起動時にコマンドを実行できます。下位権限のアカウントが変更できる場合、システム全体の startup file や特権ユーザーの startup file は、より慎重に扱う必要があります。非対話型 Bash も `BASH_ENV` で指定されたファイルを読み込むことがあります。この動作やその他のインタープリターのフックについては、[環境変数](linux-environment-variables.md#bash_env--env)のページを参照してください。persistence path と断定する前に、ログイン、対話型、非対話型セッションで実際の shell が読み込むファイルを確認してください。

グローバル startup file が読み込むファイルも調べてください。たとえば、`/etc/bash.bashrc` 内の `source /opt/app/venv/bin/activate` という記述は、shell が実際にその startup file を読み込むときに、activation file を shell code として実行します。activation file、symlink と親ディレクトリの権限、ACL を確認してください。下位権限のユーザーが書き込めるファイルであっても、特権 shell または特権タスクが後でそのファイルを読み込む場合に限り、その shell に影響を与えられます。書き込み権限が `sudoedit` に依存する場合は、まず正確な sudoers ルールと、インストール済みのベンダーパッチ適用済み sudo package を確認してください。upstream のバージョン文字列だけでは、[sudoedit の argument-injection 脆弱性](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands)があるとは判断できません。

[ユーザーとセッション](../user-information/user-and-session-triage.md)で説明されているように、history、dotfile、backup に秘密情報がないか確認してください。特権スクリプトが名前でコマンドを解決する場合は、この確認と [PATH hijacking のガイダンス](linux-environment-variables.md#path)を組み合わせてください。
{{#include ../../banners/hacktricks-training.md}}
