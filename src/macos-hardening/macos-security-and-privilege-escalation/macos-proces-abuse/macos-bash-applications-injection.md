# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

当 Bash 以非交互方式运行脚本或 `-c` 命令时，它会展开 `BASH_ENV` 的值，并在执行请求的命令之前加载所得文件。Bash 不会使用 `PATH` 查找此文件。因此，如果某个进程使用攻击者可控的环境变量启动非交互式 Bash，就可以使其先执行一个可读取的 shell payload。<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
该 hook 仅在目标实际启动 Bash 时运行；其他平台上的 `/bin/sh`，或不通过 shell 执行命令的程序，不一定会遵循它。Bash 在 privileged mode 下会忽略 `BASH_ENV`。当 effective 和 real user/group IDs 不同时，Bash 也会跳过 startup files，并在未提供 `-p` 时重置 effective IDs；使用 `-p` 时，privileged mode 会保持启用，且 `BASH_ENV` 仍会被忽略。<sup>[[1]](#references)[[2]](#references)</sup>

在 macOS 上，`launchd` jobs 可以定义继承的或按 job 设置的 environment variables，因此应检查向 privileged scripts 提供环境的 plists 和 launch contexts。不要仅依赖 SIP 来清理 interpreter variables：使用最小化环境（`env -i`），显式 unset `BASH_ENV`，通过绝对路径调用预期的 interpreter，并避免使用可写的 startup files。

## zsh `ZDOTDIR`

zsh 会为每个普通 shell 读取 `$ZDOTDIR/.zshenv`，包括 non-interactive shells；如果未设置 `ZDOTDIR`，则使用 `HOME`。因此，将 `ZDOTDIR` 重定向到可写目录后，在执行 `zsh -c` 命令或 script 之前，就会执行其中的 `.zshenv`。<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` 会取消设置 `RCS` 选项，并跳过此用户 startup file。全局 `/etc/zshenv` 仍会被读取，因此必须保持可信且精简。

## fish `XDG_CONFIG_HOME`

fish 在每个 shell 启动时都会读取 `$XDG_CONFIG_HOME/fish/conf.d/*.fish` 和 `$XDG_CONFIG_HOME/fish/config.fish`，而不仅仅是在 interactive 或 login shell 中读取。它还会在 `XDG_DATA_DIRS` 中各条目下执行 `fish/vendor_conf.d/*.fish`。因此，能够控制这些变量之一以及一个可读目录的攻击者，可以在 fish script 或 `-c` command 之前运行代码。<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
对可信调用使用 `fish --no-config`，并清除不可信的 XDG 路径变量。

## References

- [1] [Bash 启动文件](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash 调用 Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh 启动/关闭文件](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish 配置文件](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
