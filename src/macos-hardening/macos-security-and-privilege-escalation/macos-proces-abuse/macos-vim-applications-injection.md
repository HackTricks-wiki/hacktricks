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

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```

The `:qa!` fed on stdin just closes the editor after the payload has already run; in a real scenario the victim simply opens Vim normally.

## `EXINIT`

If `VIMINIT` is not set, Vim (and the `vi`/`ex` compatibility binaries) falls back to **`EXINIT`**, which is executed the same way. It is the classic vi-era variant of the same primitive.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Notes and caveats

- **Neovim** honours `VIMINIT` too (it is checked before the user `init.vim`/`init.lua`).
- Batch/Ex mode (`vim -es` / `vim -Es`) does **not** source `VIMINIT`/`EXINIT`; the variables run in a normal (interactive) startup, which is the common victim scenario.
- Related file-based vectors are the per-directory `exrc`/`.nvimrc` "modeline"/local-rc features and `-u <vimrc>`; the environment-variable path above needs no writable file at all.

## Hardening

- Sanitize the environment (drop `VIMINIT`/`EXINIT`) before launching editors from privileged or automated contexts, and prefer `sudo -i`/`env -i` wrappers that reset the environment.
- Set `EDITOR`/`VISUAL` to trusted absolute paths and avoid running editors as root with an inherited user environment.
- Treat control over a target's environment as equivalent to code execution for any Vim/Neovim it spawns.

## References

- [1] [Vim documentation — `starting.txt` (initialization, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)

{{#include ../../../banners/hacktricks-training.md}}
