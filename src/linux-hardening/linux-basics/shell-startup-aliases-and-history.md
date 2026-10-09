# Shell Startup, Aliases, and History

{{#include ../../banners/hacktricks-training.md}}

A shell command may behave differently from the executable with the same name if an alias, function, startup file, or environment variable changes how it runs. Check these before trusting a command's output or assuming a script uses the same PATH as an interactive session.

## Inspect the current shell

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` and `command -V` reveal whether a name resolves to an alias, function, builtin, or file. `command -v` and `which` may not tell the same story for aliases and functions. Shell history can expose commands or credentials, but it may be incomplete, disabled, or held in memory until the session exits.

## Review startup and history files

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

A user-writable startup file can execute commands on a future shell launch. A system-wide startup file or a privileged user's startup file is more sensitive if a lower-privileged account can modify it. Non-interactive Bash can also read the file named by `BASH_ENV`; the [environment variables](linux-environment-variables.md#bash_env--env) page explains that behavior and other interpreter hooks. Verify which files the actual shell reads for login, interactive, and non-interactive sessions before claiming a persistence path.

Also inspect files sourced by a global startup file. For example, a literal `source /opt/app/venv/bin/activate` in `/etc/bash.bashrc` runs the activation file as shell code when a shell actually reads that startup file. Review the activation file, symlink and parent-directory permissions, and ACLs; a lower-privileged writer can affect a privileged shell only if that shell or a privileged task later sources it. If write access depends on `sudoedit`, first verify the exact sudoers rule and the installed vendor-patched sudo package; an upstream version string alone does not establish [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Check history, dotfiles, and backups for secrets as described in [users and sessions](../user-information/user-and-session-triage.md). If a privileged script resolves commands by name, combine this review with the [PATH hijacking guidance](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
