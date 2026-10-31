# macOS Vim/Neovim 应用注入

{{#include ../../../banners/hacktricks-training.md}}

## 概述

Vim 自带的脚本语言（Vimscript）可以在启动时通过环境变量运行**任意 Ex 命令和 shell 命令**。如果权限更高的进程（维护/root 工作流、`sudo vim …`、由其他工具启动的编辑器、`crontab -e`、`visudo`、调用编辑器的 `git`/`less` 等）在攻击者可控的环境变量影响下启动 Vim/Neovim，攻击者便可在该上下文中执行代码。

## `VIMINIT`

初始化期间，Vim 会读取并执行 **`VIMINIT`** 中的 Ex 命令。Ex 命令包括 `:!cmd`（运行 shell 命令）和 `:call system(...)`，因此只需一个变量，就能在编辑任何文件之前实现任意代码执行。<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

第一个示例中通过 stdin 输入的 `:qa!` 只会在 payload 运行后关闭编辑器；在真实场景中，受害者可以正常打开 Vim。

`VIMINIT` 会被解析为**一行 Ex 命令**。使用 `|`（或字面换行符）分隔命令链。它的优先级高于用户的 vimrc 和 `EXINIT`，因此 payload 无需恶意配置文件，并且会在正常用户配置之前运行。<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

如果未设置 `VIMINIT`，Vim（以及 `vi`/`ex` 兼容二进制文件）会回退到 **`EXINIT`**，并以相同方式执行。它是同一原语在 vi 时代的经典变体。<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## 使用 Vim `exrc` 的项目本地 rc

这是 `VIMINIT` 的一种基于文件的替代方案。如果受害者已在用户配置中启用 `set exrc`，Vim 也会从其**工作目录**（而不只是正在编辑的文件所在目录）加载 `.vimrc`（然后是 `_vimrc` 或 `.exrc`）。在项目中放置一个本地 `.vimrc`，并让受害者从该项目启动 Vim。在 Unix 上，Vim 会对由其他人拥有的本地 rc 文件应用 `secure` 限制，但受害者解压的归档文件通常会让植入的文件归受害者所有，从而绕过此检查。<sup>[[1]](#references)</sup>

这个独立标记展示了启动触发条件，且不会修改真实的用户配置：<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim 的情况不同：当前版本要求先信任项目本地的 `.nvim.lua`、`.nvimrc` 或 `.exrc`，才会执行它们。信任状态与文件内容哈希绑定，因此修改已信任的文件后，需要再次确认信任。攻击者如果只能在仓库中放置文件，不能假设 `exrc` 会静默执行；应将这种需要用户选择并经过信任门控的方式，与下文的当前目录 Lua `require()` 方式区分开来。<sup>[[4]](#references)[[5]](#references)</sup>

如需了解可写的**用户** vimrc，而非项目本地 vimrc，请参阅 [macOS Vim startup configuration](../../macos-auto-start-locations.md#vim-startup-configuration)。

## 启动抑制与可利用性

此原语依赖**正常启动**。`vim -u NONE` / `nvim -u NONE` 会跳过环境/用户初始化（以及插件），而 `-u <file>` 则使用指定文件。Vim 的 `-es`/`-Es` 和 Neovim 的 `-es`、`-Es` 或 `-l` 也会跳过这些初始化步骤。不要误以为 `--headless` 是安全模式：正常的 Neovim headless 启动仍会处理 `VIMINIT`。<sup>[[1]](#references)[[2]](#references)</sup>

因此，应验证完整的启动链：该变量必须能够经过 wrapper、`sudo` 策略、job runner 和编辑器选择环节，且最终命令不能强制使用 `-u NONE`/`NORC` 或 batch mode。可靠的 payload 可以用 `|qall!` 结束自身；这也便于测试不提供 TTY 的 wrapper。<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim 当前目录 Lua 模块劫持

另一种 Neovim 注入原语会影响 Lua `package.path`/`package.cpath` 中仍包含 `./?.lua` 或 `./?.so` 等当前目录模板的版本。仅启动 Neovim 还不够：配置或插件必须调用 `require("name")`，且此前不能有其他 loader 解析该名称。常见触发点是**可选依赖检查**，例如 `pcall(require, "optional_dep")`；此时只要在攻击者控制的工作目录中放置 `optional_dep.lua`，就能执行其中的代码，无需启用独立的 `'exrc'` 本地配置功能。核心 `vim.*` 模块以及已在 `'runtimepath'` 中找到的模块通常无法被遮蔽，因此应枚举实际缺失/可选的 `require()` 调用，而不是猜测模块名。<sup>[[3]](#references)</sup>

以下示例使用无害标记复现该 loader 原语：<sup>[[3]](#references)</sup>

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

检查正在运行的构建版本，而不是只依赖版本字符串：<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

上游正在跟进移除常规编辑器启动时的当前目录回退机制，同时保留 Lua 脚本（`nvim -l`）行为。在已安装的构建版本不再提供此机制之前，请将以下内容放在 `init.lua` 的**开头**（它会有意移除相对路径的当前目录 Lua/C 模块模板，因此不要用于需要这些模板的工作流）：<sup>[[3]](#references)</sup>

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

## Notes and caveats

- **Neovim** 支持 `VIMINIT` 和备用的 `EXINIT`，但其常规用户配置文件是 `init.vim` 或 `init.lua`。<sup>[[2]](#references)</sup>
- 环境变量路径不需要可写文件。本地 rc 和当前目录模块劫持是独立的、基于文件的原语。<sup>[[1]](#references)[[3]](#references)</sup>
- 项目本地 rc 文件不同于 modelines，也不同于上述 `require()` 当前目录回退。Vim 和 Neovim 对它们的检查方式不同；请参阅上文的项目本地 `exrc` 工作流。<sup>[[1]](#references)[[4]](#references)</sup>
- 编辑器选择变量只决定启动哪个程序，并不保证 `VIMINIT` 会传递到最终进程。请检查 Vim/Neovim exec 边界处的确切环境和参数。<sup>[[1]](#references)[[2]](#references)</sup>

## Hardening

- 在以特权运行编辑器或自动启动编辑器之前，明确移除这些变量：`env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`。当调用方必须忽略所有用户启动来源时，`-u NONE` 很重要。<sup>[[1]](#references)[[2]](#references)</sup>
- 将 `EDITOR`/`VISUAL` 设置为可信的绝对路径，避免在继承用户环境的情况下以 root 身份运行交互式编辑器，并确保包装器无法在清理后重新设置 `VIMINIT`/`EXINIT`。<sup>[[1]](#references)[[2]](#references)</sup>
- 对于 Neovim，升级到会在编辑器模式下移除当前目录 Lua/C 搜索模板的版本，或在加载插件前将其清除。在打开不可信仓库时，审查插件代码中可选的 `pcall(require, ...)` 调用。<sup>[[3]](#references)</sup>
- 将对目标的编辑器环境、工作目录或启动配置的控制视为可能在编辑器安全上下文中执行代码的原语。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim 文档 — `starting.txt`（初始化、`VIMINIT`、`EXINIT`）](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim 文档 — 启动与初始化](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — `require()` 中的当前目录回退](https://github.com/neovim/neovim/issues/38966)
- [4] [Neovim 选项 — 项目本地 `exrc` 与信任要求](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Neovim 编辑 — 可信文件与 `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
