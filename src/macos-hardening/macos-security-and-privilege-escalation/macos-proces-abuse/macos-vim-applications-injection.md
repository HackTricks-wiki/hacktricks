# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 概述

Vim 自带的脚本语言（Vimscript）可以在启动时通过环境变量运行**任意 Ex 命令和 shell 命令**。如果权限更高的进程（维护/root 工作流、`sudo vim …`、由其他工具启动的编辑器、`crontab -e`、`visudo`、调用编辑器的 `git`/`less` 等）在攻击者可控制的环境中启动 Vim/Neovim，攻击者就能在该上下文中实现代码执行。

## `VIMINIT`

初始化期间，Vim 会读取并执行 **`VIMINIT`** 中的 Ex 命令。Ex 命令包括 `:!cmd`（运行 shell 命令）和 `:call system(...)`，因此单个变量即可在编辑任何文件之前实现任意执行。<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
第一 个示例中通过 stdin 传入的 `:qa!` 只有在 payload 运行后才会关闭编辑器；在真实场景中，受害者可以正常打开 Vim。

`VIMINIT` 会被解析为**一行 Ex command**。使用 `|`（或字面换行符）分隔命令链。它的优先级高于用户的 vimrc 和 `EXINIT`，因此 payload 不需要恶意配置文件，并且会在正常用户配置之前运行。<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

如果未设置 `VIMINIT`，Vim（以及 `vi`/`ex` 兼容二进制文件）会回退到 **`EXINIT`**，其执行方式相同。这是 vi 时代的经典变体，使用的是同一种 primitive。<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## 启动抑制与可利用性

此 primitive 依赖于**正常启动**。`vim -u NONE` / `nvim -u NONE` 会跳过环境/用户初始化（以及 plugins），而 `-u <file>` 则会使用指定文件。Vim 的 `-es`/`-Es` 以及 Neovim 的 `-es`、`-Es` 或 `-l` 也会跳过这些初始化步骤。不要将 `--headless` 误认为安全模式：正常的 Neovim headless 启动仍会处理 `VIMINIT`。<sup>[[1]](#references)[[2]](#references)</sup>

因此，应验证完整的启动链：该变量必须通过 wrapper、`sudo` policy、job runner 和 editor selection 保留下来，并且最终命令不得强制使用 `-u NONE`/`NORC` 或 batch mode。可靠的 payload 可以使用 `|qall!` 自行终止，这也使测试不提供 TTY 的 wrapper 变得更容易。<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim 当前目录 Lua module hijacking

另一种独立的 Neovim injection primitive 会影响 Lua `package.path`/`package.cpath` 仍包含 `./?.lua` 或 `./?.so` 等当前目录模板的 build。仅启动 Neovim 并不足够：某个 config 或 plugin 必须调用 `require("name")`，且此前不能有 loader 解析出该名称。常见 trigger 是**可选 dependency check**，例如 `pcall(require, "optional_dep")`；此时将 `optional_dep.lua` 放入 attacker-controlled working directory，便会执行该文件，同时无需启用独立的 `'exrc'` local-configuration feature。核心 `vim.*` modules 以及已在 `'runtimepath'` 中找到的 modules 通常无法被 shadow，因此应枚举实际缺失/可选的 `require()` 调用，而不是猜测名称。<sup>[[3]](#references)</sup>

以下内容使用一个无害 marker 复现该 loader primitive：<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```
检查正在运行的构建版本，而不是仅依赖版本字符串：<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
上游正在跟踪移除正常编辑器启动期间的当前目录回退，同时保留 Lua-script（`nvim -l`）行为。在已安装的构建版本不再暴露该行为之前，请将以下内容放在 `init.lua` 的**开头**（它会有意移除相对的当前目录 Lua/C 模块模板，因此不要将其应用于需要这些模板的工作流）：<sup>[[3]](#references)</sup>
```lua
local function drop_cwd(path)
local keep = {}
for entry in path:gmatch("[^;]+") do
if not entry:match("^%./") then keep[#keep + 1] = entry end
end
return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```
## 注意事项与限制

- **Neovim** 同时支持 `VIMINIT` 和 `EXINIT` fallback，但其正常的用户配置文件是 `init.vim` 或 `init.lua`。<sup>[[2]](#references)</sup>
- 环境变量路径不需要可写文件。Local rc 和当前目录 module hijacking 是独立的、基于文件的 primitives。<sup>[[1]](#references)[[3]](#references)</sup>
- Project-local configuration 与 modelines 是不同的攻击面。启用 Vim 的 `'exrc'` 后，由其他用户拥有的 local vimrc/exrc 会受到 `'secure'` 限制；但是，解压 archive 通常会使植入的文件归受害者所有，从而绕过这种基于所有权的保护。启用 `'exrc'` 后，Neovim 还会搜索 `.nvim.lua`、`.nvimrc` 或 `.exrc`——不要将这一 opt-in 机制与上文的 `require()` 当前目录 fallback 混淆。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Editor-selection variables 只决定启动哪个程序；它们不能保证 `VIMINIT` 会到达最终进程。在 Vim/Neovim 的 exec boundary 检查确切的环境和参数。<sup>[[1]](#references)[[2]](#references)</sup>

## 加固

- 在 privileged 或 automated editor launches 之前显式删除这些变量：`env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`。当调用方必须忽略所有用户 startup source 时，`-u NONE` 很重要。<sup>[[1]](#references)[[2]](#references)</sup>
- 将 `EDITOR`/`VISUAL` 设置为受信任的 absolute paths，避免在继承的用户环境中以 root 运行 interactive editors，并确保 wrappers 在 sanitization 后无法恢复 `VIMINIT`/`EXINIT`。<sup>[[1]](#references)[[2]](#references)</sup>
- 对于 Neovim，更新到一个在 editor mode 中移除 current-directory Lua/C search templates 的 build，或在加载 plugins 前删除这些 templates。在打开不受信任的 repositories 时，审计 plugin code 中可选的 `pcall(require, ...)` calls。<sup>[[3]](#references)</sup>
- 将对目标 editor environment、working directory 或 startup configuration 的控制视为 editor security context 中潜在的 code-execution primitive。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim 文档 — `starting.txt`（initialization、`VIMINIT`、`EXINIT`）](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim 文档 — startup 和 initialization](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — `require()` 中的 current-directory fallback](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
