# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Vim's own scripting language (Vimscript) can run **arbitrary Ex commands and shell commands at startup** from environment variables. If a more privileged process (a maintenance/root workflow, a `sudo vim …`, an editor spawned by another tool, `crontab -e`, `visudo`, `git`/`less` invoking an editor, …) launches Vim/Neovim with an attacker-influenced environment, the attacker gets code execution in that context.

## `VIMINIT`

During initialization Vim reads and executes the Ex commands in **`VIMINIT`**. Ex commands include `:!cmd` (run a shell command) and `:call system(...)`, so a single variable yields arbitrary execution before any file is edited.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

The `:qa!` fed on stdin in the first example only closes the editor after the payload has run; in a real scenario the victim can open Vim normally.

`VIMINIT` is parsed as **one Ex command line**. Separate a chain with `|` (or a literal newline). It has precedence over the user's vimrc and `EXINIT`, so a payload does not need a malicious configuration file and runs before the normal user configuration.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

If `VIMINIT` is not set, Vim (and the `vi`/`ex` compatibility binaries) falls back to **`EXINIT`**, which is executed the same way. It is the classic vi-era variant of the same primitive.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Startup suppression and exploitability

This primitive depends on a **normal startup**. `vim -u NONE` / `nvim -u NONE` skip the environment/user initialization (and plugins), while `-u <file>` uses that file instead. Vim `-es`/`-Es` and Neovim `-es`, `-Es`, or `-l` also skip these initialization steps. Do not mistake `--headless` for a safe mode: a normal Neovim headless startup still processes `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Consequently, validate the complete launch chain: the variable must survive the wrapper, `sudo` policy, job runner, and editor selection, and the final command must not force `-u NONE`/`NORC` or batch mode. A reliable payload can terminate itself with `|qall!`, which also makes testing wrappers that do not provide a TTY easier.<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim current-directory Lua module hijacking

A separate Neovim injection primitive affects builds whose Lua `package.path`/`package.cpath` still contain current-directory templates such as `./?.lua` or `./?.so`. Starting Neovim alone is insufficient: a config or plugin must call `require("name")`, and no earlier loader may resolve that name. A common trigger is an **optional dependency check** such as `pcall(require, "optional_dep")`; placing `optional_dep.lua` in an attacker-controlled working directory then executes it without enabling the separate `'exrc'` local-configuration feature. Core `vim.*` modules and modules already found on `'runtimepath'` are not generally shadowable, so enumerate actual missing/optional `require()` calls rather than guessing names.<sup>[[3]](#references)</sup>

The following reproduces the loader primitive with a harmless marker:<sup>[[3]](#references)</sup>

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

Check the running build instead of relying only on a version string:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream tracks removal of the current-directory fallback during normal editor startup while retaining Lua-script (`nvim -l`) behavior. Until the installed build no longer exposes it, place this at the **start** of `init.lua` (it intentionally removes relative current-directory Lua/C module templates, so do not apply it to workflows that require them):<sup>[[3]](#references)</sup>

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

- **Neovim** honours both `VIMINIT` and the `EXINIT` fallback, but its normal user configuration is `init.vim` or `init.lua`.<sup>[[2]](#references)</sup>
- The environment-variable path needs no writable file. Local rc and current-directory module hijacking are separate, file-backed primitives.<sup>[[1]](#references)[[3]](#references)</sup>
- Project-local configuration is a different surface from modelines. With Vim's `'exrc'` enabled, a local vimrc/exrc owned by another user runs with `'secure'` restrictions; however, extracting an archive normally makes the planted file owned by the victim and defeats that ownership-based protection. Neovim also searches for `.nvim.lua`, `.nvimrc`, or `.exrc` when `'exrc'` is enabled—do not conflate that opt-in mechanism with the `require()` current-directory fallback above.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Editor-selection variables only choose what program is launched; they do not guarantee that `VIMINIT` reaches the final process. Inspect the exact environment and arguments at the Vim/Neovim exec boundary.<sup>[[1]](#references)[[2]](#references)</sup>

## Hardening

- Explicitly drop the variables before privileged or automated editor launches: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` is important when the caller must ignore every user startup source.<sup>[[1]](#references)[[2]](#references)</sup>
- Set `EDITOR`/`VISUAL` to trusted absolute paths, avoid running interactive editors as root with an inherited user environment, and ensure wrappers cannot restore `VIMINIT`/`EXINIT` after sanitization.<sup>[[1]](#references)[[2]](#references)</sup>
- For Neovim, update to a build that removes current-directory Lua/C search templates during editor mode, or strip them before loading plugins. Audit plugin code for optional `pcall(require, ...)` calls when opening untrusted repositories.<sup>[[3]](#references)</sup>
- Treat control over a target's editor environment, working directory, or startup configuration as a potential code-execution primitive in the editor's security context.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim documentation — `starting.txt` (initialization, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim documentation — startup and initialization](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — current-directory fallback in `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
