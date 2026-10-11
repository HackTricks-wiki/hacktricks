# Shell 启动、别名和历史记录

{{#include ../../banners/hacktricks-training.md}}

如果别名、函数、启动文件或环境变量改变了命令的运行方式，那么 shell 命令的行为可能与同名可执行文件不同。在信任命令的输出，或假设脚本使用的 PATH 与交互式会话相同之前，请先检查这些因素。

## 检查当前 shell

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` 和 `command -V` 可以揭示某个名称会解析为别名、函数、内建命令还是文件。对于别名和函数，`command -v` 和 `which` 给出的结果可能并不一致。Shell 历史记录可能会暴露命令或凭据，但它可能不完整、已被禁用，或者一直保存在内存中，直到会话退出。

## 检查启动和历史记录文件

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

用户可写入的启动文件可以在未来启动 shell 时执行命令。如果低权限账户能够修改系统范围的启动文件或特权用户的启动文件，风险会更高。非交互式 Bash 也可能读取 `BASH_ENV` 指定的文件；[环境变量](linux-environment-variables.md#bash_env--env)页面介绍了这种行为以及其他解释器钩子。在断言某条 persistence 路径可行之前，请先确认实际 shell 在登录、交互式和非交互式会话中会读取哪些文件。

还要检查全局启动文件所 source 的文件。例如，若 `/etc/bash.bashrc` 中有字面命令 `source /opt/app/venv/bin/activate`，那么 shell 实际读取该启动文件时，就会将激活文件作为 shell 代码执行。检查激活文件、符号链接和父目录的权限，以及 ACL；只有当特权 shell 或特权任务之后会 source 该文件时，低权限用户才能通过写入该文件影响特权 shell。如果写入权限取决于 `sudoedit`，请先确认确切的 sudoers 规则和已安装的厂商补丁版 sudo 软件包；仅凭上游版本字符串无法确认是否存在 [sudoedit 参数注入风险](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands)。

按照[用户和会话](../user-information/user-and-session-triage.md)中的说明，检查 history、dotfiles 和备份中是否包含机密信息。如果特权脚本通过名称解析命令，请将此项检查与 [PATH 劫持指南](linux-environment-variables.md#path)结合起来。
{{#include ../../banners/hacktricks-training.md}}
