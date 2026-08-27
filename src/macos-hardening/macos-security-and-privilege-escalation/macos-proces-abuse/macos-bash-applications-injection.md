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

## References

- [1] [Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash Invoking Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh Startup/Shutdown Files](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish Configuration files](https://fishshell.com/docs/current/language.html#configuration-files)

{{#include ../../../banners/hacktricks-training.md}}
