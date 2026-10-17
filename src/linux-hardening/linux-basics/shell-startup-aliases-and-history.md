# Shell 启动、别名与历史记录

{{#include ../../banners/hacktricks-training.md}}

如果别名、函数、启动文件或环境变量改变了命令的运行方式，shell 命令的行为可能会与同名可执行文件不同。在信任命令的输出，或假设脚本使用与交互式会话相同的 PATH 之前，请先检查这些内容。

## 检查当前 shell

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` 和 `command -V` 可以显示名称解析为 alias、函数、内建命令还是文件。对于 alias 和函数，`command -v` 和 `which` 给出的结果可能不同。Shell 历史记录可能泄露命令或凭据，但也可能不完整、已禁用，或一直保存在内存中，直到会话退出。

## 检查启动和历史记录文件

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

用户可写的 startup 文件可以在未来启动 shell 时执行命令。如果低权限账户能够修改系统级 startup 文件或特权用户的 startup 文件，风险会更高。非交互式 Bash 也可能读取 `BASH_ENV` 指定的文件；[环境变量](linux-environment-variables.md#bash_env--env) 页面说明了这一行为以及其他解释器钩子。在声称存在持久化路径之前，请先确认实际 shell 在登录、交互式和非交互式会话中会读取哪些文件。

还要检查全局 startup 文件所 source 的文件。例如，`/etc/bash.bashrc` 中的字面内容 `source /opt/app/venv/bin/activate` 会在 shell 实际读取该 startup 文件时，将激活文件作为 shell 代码运行。检查激活文件、符号链接和父目录的权限，以及 ACL；只有当低权限用户可写的文件之后被该 shell 或特权任务 source 时，低权限用户才可能影响特权 shell。如果写入权限取决于 `sudoedit`，请先确认确切的 sudoers 规则以及已安装的供应商修补版 sudo 软件包；仅凭上游版本字符串无法确认是否存在 [sudoedit 参数注入风险](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands)。

按[用户和会话](../user-information/user-and-session-triage.md)中的说明，检查 history、dotfiles 和备份中是否有密钥。如果特权脚本按名称解析命令，请将此检查与 [PATH 劫持指南](linux-environment-variables.md#path)结合起来。

## Zsh startup 重定向和编译文件

使用默认的 `RCS` 设置时，zsh 会在常规调用之前读取 `$ZDOTDIR/.zshenv`，包括 `zsh -c` 和脚本调用；如果未设置 `ZDOTDIR`，则使用 `$HOME`。当命令运行器接受环境变量映射时，请测试它是否会将这两个变量中的任意一个传递给特权 zsh 进程。这样一来，可写的 `.zshenv` 就能在运行器检查或 allowlist 命令主体之前执行代码。前提是特权进程继承了重定向后的目录；`zsh -f` 会跳过用户 startup 文件，但不会跳过全局 `zshenv`（通常是 `/etc/zshenv`，但不同发行版的路径可能不同）。[macOS zsh 注入页面](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir)提供了一个最简 `ZDOTDIR` 示例。<sup>[[1]](#references)[[2]](#references)</sup>

如果 `.zshenv.zwc` 或 `.zshrc.zwc` 更新且有效，zsh 会执行它，而不是对应的明文 startup 文件。如果你能写入 startup 目录，就可以编译修改后的文件，然后将看似无害的明文文件还原，从而在编译副本中留下可执行代码。这只是混淆，不是加密。下面的临时测试说明了为什么仅检查文本文件并不足够；它不会触及真实的 home 目录。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

对于真实目标，确定其有效的 `ZDOTDIR`/`HOME`，检查文本文件和 `.zwc` 文件，并核查时间戳、所有权以及父目录是否可写。`.zwc` 文件必须与源文件匹配，且时间戳更新，才能优先使用。<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh 启动和关闭文件](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Shell 启动环境注入安全公告](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh shell 内置命令：zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [你忘了检查的 .zshrc.zwc](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
