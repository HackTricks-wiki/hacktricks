# Shell 启动、Aliases 和历史记录

{{#include ../../banners/hacktricks-training.md}}

如果 alias、函数、启动文件或环境变量改变了 shell 命令的运行方式，该命令的行为可能会与同名可执行文件不同。在信任命令输出，或假设脚本使用的 PATH 与交互式会话相同时，请先检查这些因素。

## 检查当前 shell

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` 和 `command -V` 可以显示名称解析为 alias、function、builtin 还是文件。对于 alias 和 function，`command -v` 与 `which` 给出的结果可能不同。Shell history 可能暴露命令或凭据，但内容可能不完整、已禁用，或在会话退出前一直保存在内存中。

修改后的 `.bashrc` 可以定义一个模仿密码提示的 `sudo` alias，记录输入内容，并将其传递给真正的命令。这样无需修改 `sudo` 可执行文件或 `PATH`，就能暗中截取凭据。<sup>[[5]](#references)</sup> Shell 必须读取修改后的启动文件并展开该 alias。<sup>[[7]](#references)</sup> 默认情况下，非交互式 Bash 不会展开 alias，除非启用 `expand_aliases`。<sup>[[6]](#references)</sup>

## 检查启动文件和 history

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

用户可写的启动文件可以在 shell 下次启动时执行命令。如果低权限账户能够修改系统级启动文件或特权用户的启动文件，风险会更高。非交互式 Bash 也可以读取 `BASH_ENV` 指定的文件；[environment variables](linux-environment-variables.md#bash_env--env) 页面介绍了这一行为和其他解释器钩子。在声称存在持久化路径之前，请先确认实际 shell 在登录、交互式和非交互式会话中会读取哪些文件。

还要检查全局启动文件所加载的文件。例如，如果 `/etc/bash.bashrc` 中有字面内容 `source /opt/app/venv/bin/activate`，那么 shell 实际读取该启动文件时，就会将激活文件作为 shell 代码执行。检查激活文件、符号链接和父目录的权限以及 ACL；低权限用户只有在特权 shell 或特权任务之后加载该文件时，才能影响特权 shell。如果写入权限取决于 `sudoedit`，请先核实确切的 sudoers 规则和已安装的供应商补丁版 sudo 软件包；仅凭上游版本字符串，无法确认存在 [sudoedit 参数注入风险](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands)。

按照[用户和会话](../user-information/user-and-session-triage.md)中的说明，检查历史记录、点文件和备份中是否包含机密信息。如果特权脚本按名称解析命令，请结合 [PATH 劫持指南](linux-environment-variables.md#path)进行审查。

## Zsh 启动重定向与编译文件

在默认的 `RCS` 设置下，zsh 会在常规调用（包括 `zsh -c` 和脚本）之前读取 `$ZDOTDIR/.zshenv`；如果未设置 `ZDOTDIR`，则使用 `$HOME`。如果命令运行器接受环境映射，请测试它是否会将任一变量传递给特权 zsh 进程。这样一来，可写的 `.zshenv` 就能在运行器检查或允许列表中的命令主体运行**之前**执行代码。前提是特权进程继承了重定向后的目录；`zsh -f` 会跳过用户启动文件，但不会跳过全局 `zshenv`（通常是 `/etc/zshenv`，但不同发行版的路径可能有所不同）。[macOS zsh 注入页面](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir)提供了一个最简 `ZDOTDIR` 示例。<sup>[[1]](#references)[[2]](#references)</sup>

较新且有效的 `.zshenv.zwc` 或 `.zshrc.zwc` 会取代其纯文本启动文件执行。如果你能写入启动目录，那么编译修改后的文件后，再将纯文本文件恢复为看似无害的内容，就可以把可执行代码留在编译副本中。这只是隐藏手段，并非加密。下面的临时测试说明了为什么仅检查文本文件并不足够；它不会触及真实的 home 目录。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

对于真实目标，确定其生效的 `ZDOTDIR`/`HOME`，检查文本文件和 `.zwc` 文件，并核查时间戳、所有权以及父目录是否可写。`.zwc` 文件必须与源文件匹配，且时间戳更新，才能优先使用。<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh 启动与关闭文件](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Shell 启动环境注入安全公告](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh shell 内建命令：zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [你忘记检查的 .zshrc.zwc](https://dfir.ch/posts/compiled_zsh/)
- [5] [AI 驱动的间谍活动针对政府 Linux 基础设施](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Bash 手册：Aliases](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Bash 手册：Bash 启动文件](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
