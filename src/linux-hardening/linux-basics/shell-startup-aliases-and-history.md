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

A modified `.bashrc` can define a `sudo` alias that imitates a password prompt, records the response, and passes it to the real command. This can conceal credential interception without changing the `sudo` executable or `PATH`.<sup>[[5]](#references)</sup> The shell must read the modified startup file and expand the alias.<sup>[[7]](#references)</sup> By default, non-interactive Bash does not expand aliases unless `expand_aliases` is enabled.<sup>[[6]](#references)</sup>

## Review startup and history files

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

A user-writable startup file can execute commands on a future shell launch. A system-wide startup file or a privileged user's startup file is more sensitive if a lower-privileged account can modify it. Non-interactive Bash can also read the file named by `BASH_ENV`; the [environment variables](linux-environment-variables.md#bash_env--env) page explains that behavior and other interpreter hooks. Verify which files the actual shell reads for login, interactive, and non-interactive sessions before claiming a persistence path.

Also inspect files sourced by a global startup file. For example, a literal `source /opt/app/venv/bin/activate` in `/etc/bash.bashrc` runs the activation file as shell code when a shell actually reads that startup file. Review the activation file, symlink and parent-directory permissions, and ACLs; a lower-privileged writer can affect a privileged shell only if that shell or a privileged task later sources it. If write access depends on `sudoedit`, first verify the exact sudoers rule and the installed vendor-patched sudo package; an upstream version string alone does not establish [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Check history, dotfiles, and backups for secrets as described in [users and sessions](../user-information/user-and-session-triage.md). If a privileged script resolves commands by name, combine this review with the [PATH hijacking guidance](linux-environment-variables.md#path).

## Zsh startup redirection and compiled files

With its default `RCS` settings, zsh reads `$ZDOTDIR/.zshenv` before normal invocations, including `zsh -c` and scripts; if `ZDOTDIR` is unset, it uses `$HOME`. When a command runner accepts an environment map, test whether it forwards either variable into a privileged zsh process. A writable `.zshenv` can then run **before** the command body that the runner checks or allowlists. This requires the privileged process to inherit the redirected directory; `zsh -f` skips user startup files, but not the global `zshenv` (often `/etc/zshenv`, but distribution paths vary). The [macOS zsh injection page](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) has a minimal `ZDOTDIR` example.<sup>[[1]](#references)[[2]](#references)</sup>

A newer, valid `.zshenv.zwc` or `.zshrc.zwc` is executed instead of its plaintext startup file. If you can write the startup directory, compiling a modified file and then restoring harmless-looking plaintext can leave executable code in the compiled copy. This is obscurity, not encryption. The disposable test below shows why inspecting only the text file is insufficient; it does not touch a real home directory.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

For a real target, resolve its effective `ZDOTDIR`/`HOME`, inspect both the text and `.zwc` files, and check timestamps, ownership, and writable parent directories. A `.zwc` file must match the source file and be newer to take precedence.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh startup and shutdown files](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Shell startup environment injection advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh shell builtins: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [The .zshrc.zwc You Forgot to Check](https://dfir.ch/posts/compiled_zsh/)
- [5] [AI-Powered Espionage Campaign Targets Government Linux Infrastructure](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Bash manual: Aliases](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Bash manual: Bash startup files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
