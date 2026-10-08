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

## Other sudo and doas rule hazards

Start with `sudo -l`, `sudo -V`, and any applicable `doas` policy. Read the allowed command, run-as user, arguments, environment, and defaults together. Permission to run as a non-root service account can still expose that account's files or a route to root.

- `SETENV`, `env_keep`, `secure_path`, and `LD_PRELOAD` can turn an otherwise narrow command into an import, library, or PATH hijack. See the [environment-variable guide](../linux-basics/linux-environment-variables.md) and [SUID/linker abuse](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md).
- A sudo-allowed Python script may import code from a writable directory or cached `.pyc` file. The [privilege escalation guide](../linux-basics/linux-privilege-escalation/README.md) details the cache case.
- A custom root-owned wrapper may appear safe because its binaries and scripts are not writable, yet its decision to run a privileged action may depend on a flag, local API value, or service state that an unprivileged user can change. Trace each gate back to its input and authorization checks. During enumeration, inspect configuration and permissions without changing operational state; a `systemd-run` call inside the wrapper is only relevant if the gate can be influenced.
- A backup client allowed through sudo as root may accept a caller-selected configuration file (for example, `npbackup-cli -c`). Check the exact run-as user and permitted arguments, then whether the caller controls the configuration path, backup source paths, and repository or read/restore options. An encrypted repository secret in a readable config may still be usable by the client, but the rule alone does not prove repository access or root-file disclosure. Validate authorization without running a backup or dumping its contents.
- [Restic](https://github.com/restic/restic/blob/master/doc/030_preparing_a_new_repo.rst) supports `--password-command`, which calls a program to obtain a repository password. If a sudo rule lets a lower-privileged user run restic as root with a caller-chosen password command and a subcommand that needs the password, that helper may run as root. Review the exact sudo arguments and exclusions; do not invoke the helper or a backup command merely to enumerate the condition.
- An unrestricted custom maintenance or backup command may accept an output path or offer its own job scheduler. For a file-write path, verify the exact sudo rule and run-as user, then whether the caller controls both the data and the destination. For a scheduled-command path, verify the scheduler's execution identity, command input, and any additional password or authorization gate. The command name or `NOPASSWD` alone proves neither route. See [writing to root-owned files](../interesting-files-permissions/write-to-root.md) and [cron and systemd timers](../processes-crontab-systemd-dbus/cron-and-systemd-timers.md).
- `sudoedit` and argument wildcards require exact version and rule checks; the [checklist](linux-privilege-escalation-checklist.md) includes the sudoedit file-edit issue.
- In a sudoers command rule, an argument wildcard can match whitespace as well as path characters. A rule for a read-capable command with an argument such as `/restricted/*` may therefore admit an extra file argument after a matching prefix. Review the exact run-as user, command path, argument pattern, and later denials; demonstrated file read does not imply command execution. The [sudoers manual](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf) distinguishes argument globs from command-path globs.
- Archivers and other utility programs may have execution hooks. Test the exact allowed arguments against [GTFOBins](https://gtfobins.github.io/) rather than assuming that only shells or interpreters execute commands.
- Sudo timestamp reuse depends on the cache policy, owning user, terminal/session, and permissions. The [privilege escalation guide](../linux-basics/linux-privilege-escalation/README.md#reusing-sudo-tokens) covers the checks.
- `doas` has its own rules and configuration. Check permitted commands and writable configuration paths as described in the [doas section](../linux-basics/linux-privilege-escalation/README.md#doas).

### Privileged Below logging directory

[CVE-2025-27591](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w) affected Below releases before 0.9.0 that created a world-writable `/var/log/below` directory. If a service or a permitted sudo command runs an affected build as root, a user who can write and traverse a non-sticky log directory may be able to replace a log entry with a symlink before the privileged process opens it. Review the installed package's patch status, the exact privileged execution path, effective directory access, sticky bit and ACLs, and metadata for `/var/log/below/error_root.log`. A world-writable path or a sudo rule alone does not establish the full chain. A sticky directory or vendor backport changes the assessment. Passive enumeration should inspect metadata only; it need not create a link or run the privileged program.

### Root-run Python archive restore scripts

A tightly scoped sudo rule for a Python restore script still needs a review of its archive input. If the caller can select or replace the archive and the script extracts it as root with `tarfile.extractall(filter="data")`, check the interpreter's security updates before trusting the filter. CPython fixed several symlink and hard-link filter bypasses, including CVE-2025-4517, in 3.9.23, 3.10.18, 3.11.13, 3.12.11, and 3.13.4. Distribution backports can fix an earlier version, so the displayed interpreter version alone is not proof of exposure.<sup>[[16]](#references)[[17]](#references)</sup>

For a passive review, read the exact sudo command and script, trace which argument chooses the archive, and check whether the current user can write the archive or its containing directory. Confirm the installed vendor patch and extraction destination separately; `filter="data"` does not make every untrusted archive safe.<sup>[[16]](#references)[[17]](#references)</sup>

### Sudo-allowed needrestart configuration

`needrestart -c` loads a caller-selected Perl configuration file and evaluates its contents. If `sudo -l` allows `needrestart` as root with arguments permitting `-c`, and the caller can choose a readable configuration file in a writable location, that permission can lead to root code execution. Check the exact sudo run-as and argument rule; a rule permitting only a fixed argument list may block this path. This is separate from the needrestart interpreter-scanning vulnerabilities: updating the package or disabling `interpscan` does not make an unrestricted root `-c` grant safe.<sup>[[2]](#references)[[18]](#references)[[19]](#references)</sup>

### Sudo-run Python imports under another account

A fixed Python entry point can still import a module that the caller can edit or replace, including when sudo runs the script as a **non-root** service user. For a literal `from utils import status`, review local `utils/__init__.py` and `utils/status.py` as well as the package directory permissions. Confirm the script's import path, the exact allowed sudo arguments, and whether the relevant action reaches that import before treating the writable file as an execution path. Inspect files and permissions without importing or running the script during enumeration.<sup>[[2]](#references)[[3]](#references)</sup>

### Sudo-run Apache with a caller-controlled configuration

If a sudo rule permits a privileged `apachectl`, `apache2ctl`, or `httpd` invocation with a caller-controlled `-f` configuration file, review that file and its parent directory permissions. Apache's [`LoadModule`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadmodule) directive takes a module name followed by the **module filename**; [`LoadFile`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadfile) also loads a file. [`Include` and `IncludeOptional`](https://httpd.apache.org/docs/2.4/mod/core.html#include) can extend the configuration or expose file contents through errors. A custom wrapper may validate these paths, drop privileges, or restrict arguments, so a writable config alone is a review candidate rather than proof of code execution. Check path canonicalization, symlinks, and directive parsing before drawing a conclusion.

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
- [16] [Python 3.9.23–3.13.4 security releases](https://discuss.python.org/t/python-3-13-4-3-12-11-3-11-13-3-10-18-and-3-9-23-are-now-available/94367)
- [17] [tarfile extraction filters — Python documentation](https://docs.python.org/3/library/tarfile.html#extraction-filters)
- [18] [needrestart configuration option and evaluation — upstream source](https://github.com/liske/needrestart/blob/master/needrestart)
- [19] [needrestart command behavior — GTFOBins](https://gtfobins.org/gtfobins/needrestart/)

{{#include ../../banners/hacktricks-training.md}}
