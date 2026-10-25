# Shellの起動、Aliases、History

{{#include ../../banners/hacktricks-training.md}}

Alias、関数、起動ファイル、または環境変数によって実行方法が変わると、Shellコマンドは同じ名前の実行ファイルとは異なる動作をすることがあります。コマンドの出力を信頼したり、スクリプトが対話型セッションと同じPATHを使うと仮定したりする前に、これらを確認してください。

## 現在のShellを調べる

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` と `command -V` を使うと、名前が alias、function、builtin、file のいずれに解決されるかを確認できます。`command -v` と `which` では、alias や function について同じ結果が得られるとは限りません。Shell history からコマンドや認証情報が漏れることがありますが、履歴が不完全だったり、無効になっていたり、セッション終了までメモリ内に保持されていたりする場合があります。

変更された `.bashrc` で、パスワード入力プロンプトを装い、入力内容を記録してから本来のコマンドに渡す `sudo` alias を定義できます。これにより、`sudo` executable や `PATH` を変更せずに、認証情報の傍受を隠すことができます。<sup>[[5]](#references)</sup> Shell が変更された startup file を読み込み、alias を展開する必要があります。<sup>[[7]](#references)</sup> デフォルトでは、`expand_aliases` が有効になっていない限り、non-interactive Bash は alias を展開しません。<sup>[[6]](#references)</sup>

## Startup file と history file の確認

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

ユーザーが書き込み可能な startup file は、次回の shell 起動時にコマンドを実行できます。システム全体の startup file や特権ユーザーの startup file は、低い権限のアカウントから変更できる場合、より機微な対象です。非対話型 Bash も `BASH_ENV` で指定されたファイルを読み込むことがあります。この動作やその他の interpreter hook については、[environment variables](linux-environment-variables.md#bash_env--env) のページを参照してください。永続化の手段だと断定する前に、実際の shell が login、interactive、non-interactive の各 session でどのファイルを読み込むか確認してください。

global startup file が読み込むファイルも調べてください。たとえば、`/etc/bash.bashrc` に `source /opt/app/venv/bin/activate` と直接記述されている場合、shell がその startup file を実際に読み込むと、activation file が shell code として実行されます。activation file、symlink と親ディレクトリの permissions、ACL を確認してください。低い権限のユーザーが特権 shell に影響を与えられるのは、その shell または後続の特権 task がそのファイルを読み込む場合に限られます。書き込み権限が `sudoedit` に依存する場合は、正確な sudoers rule と、ベンダーの patch が適用されたインストール済み sudo package をまず確認してください。upstream の version string だけでは、[sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) の有無は判断できません。

[users and sessions](../user-information/user-and-session-triage.md) の説明に従い、history、dotfiles、backup に secret がないか確認してください。特権 script が名前で command を解決する場合は、この調査と [PATH hijacking guidance](linux-environment-variables.md#path) を併せて確認してください。

## Zsh startup redirection とコンパイル済みファイル

デフォルトの `RCS` 設定では、zsh は通常の起動前に `$ZDOTDIR/.zshenv` を読み込みます。これには `zsh -c` や script の実行も含まれます。`ZDOTDIR` が未設定の場合は `$HOME` が使われます。command runner が environment map を受け取る場合、特権 zsh process にどちらかの変数が渡されるか確認してください。書き込み可能な `.zshenv` があれば、runner が検査または allowlist した command body より先にコードを実行できます。これには、特権 process がリダイレクト先の directory を引き継ぐ必要があります。`zsh -f` はユーザーの startup file を読み込みませんが、global `zshenv`（多くの場合 `/etc/zshenv` ですが、distribution によって path は異なります）は読み込みます。[macOS zsh injection page](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) に、最小限の `ZDOTDIR` の例があります。<sup>[[1]](#references)[[2]](#references)</sup>

新しく有効な `.zshenv.zwc` または `.zshrc.zwc` がある場合、plaintext の startup file の代わりにそれが実行されます。startup directory に書き込めるなら、変更したファイルをコンパイルしてから無害に見える plaintext を元に戻すことで、実行可能なコードをコンパイル済みコピーに残せます。これは暗号化ではなく、難読化です。以下の使い捨てテストは、text file だけを調べても不十分な理由を示します。実際の home directory には触れません。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

実際のターゲットでは、実効的な `ZDOTDIR`/`HOME` を特定し、テキストファイルと `.zwc` ファイルの両方を調べて、タイムスタンプ、所有者、親ディレクトリの書き込み権限を確認してください。`.zwc` ファイルが優先されるには、ソースファイルと一致し、かつ新しい必要があります。<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zshの起動ファイルと終了ファイル](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Shell起動環境への注入に関する注意喚起](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zshのシェル組み込みコマンド: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [確認し忘れた .zshrc.zwc](https://dfir.ch/posts/compiled_zsh/)
- [5] [AIを活用した諜報キャンペーン、政府のLinuxインフラを標的に](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Bashマニュアル: Aliases](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Bashマニュアル: Bashの起動ファイル](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
