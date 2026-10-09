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

A sudo rule permitting `apport-cli` as root deserves the same pager review. Affected Apport versions could open a crash report in `less` with an attacker-adjustable terminal size; the pager could then provide a root shell if the special sudo and pager conditions were met. Check the effective sudo rule, pager configuration, and distribution package fix before treating the version alone as vulnerable. Read the package and policy metadata without generating a crash or opening the privileged report during passive enumeration. [Ubuntu's CVE record](https://ubuntu.com/security/CVE-2023-1326) lists release-specific fixed package versions, including backported fixes.

```text
!/bin/sh
```

## Other sudo and doas rule hazards

Start with `sudo -l`, `sudo -V`, and any applicable `doas` policy. Read the allowed command, run-as user, arguments, environment, and defaults together. Permission to run as a non-root service account can still expose that account's files or a route to root.

- `SETENV`, `env_keep`, `secure_path`, and `LD_PRELOAD` can turn an otherwise narrow command into an import, library, or PATH hijack. See the [environment-variable guide](../linux-basics/linux-environment-variables.md) and [SUID/linker abuse](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md).
- For a sudo rule that runs a shell script, compare preserved variables with the script itself. A construct such as `if $CHECK_CONTENT; then` runs the expanded value as a command, so preserving `CHECK_CONTENT` can permit command execution even when the script path and arguments are fixed. Whether the branch is reachable and the environment is actually retained must be checked for the specific rule.<sup>[[2]](#references)[[22]](#references)</sup>
- A sudo-allowed Python script may import code from a writable directory or cached `.pyc` file. The [privilege escalation guide](../linux-basics/linux-privilege-escalation/README.md) details the cache case.
- A root-capable Python wrapper may pass a caller-selected URL to GitPython's `Repo.clone_from`. If the wrapper also enables Git's `protocol.ext.allow=always`, an `ext::` remote can invoke an external helper. Check the exact sudo arguments, where the URL comes from, the GitPython package version and vendor patch status, and whether the wrapper explicitly opts into unsafe protocols. GitPython added a [default unsafe-protocol guard](https://github.com/gitpython-developers/GitPython/commit/2625ed9) in 3.1.30; the version of the `git` executable is a separate fact. Passive review should read the rule and bounded source only, without invoking the clone.
- A custom root-owned wrapper may appear safe because its binaries and scripts are not writable, yet its decision to run a privileged action may depend on a flag, local API value, or service state that an unprivileged user can change. Trace each gate back to its input and authorization checks. During enumeration, inspect configuration and permissions without changing operational state; a `systemd-run` call inside the wrapper is only relevant if the gate can be influenced.
- A backup client allowed through sudo as root may accept a caller-selected configuration file (for example, `npbackup-cli -c`). Check the exact run-as user and permitted arguments, then whether the caller controls the configuration path, backup source paths, and repository or read/restore options. An encrypted repository secret in a readable config may still be usable by the client, but the rule alone does not prove repository access or root-file disclosure. Validate authorization without running a backup or dumping its contents.
- [Restic](https://github.com/restic/restic/blob/master/doc/030_preparing_a_new_repo.rst) supports `--password-command`, which calls a program to obtain a repository password. If a sudo rule lets a lower-privileged user run restic as root with a caller-chosen password command and a subcommand that needs the password, that helper may run as root. Review the exact sudo arguments and exclusions; do not invoke the helper or a backup command merely to enumerate the condition.
- An unrestricted custom maintenance or backup command may accept an output path or offer its own job scheduler. For a file-write path, verify the exact sudo rule and run-as user, then whether the caller controls both the data and the destination. For a scheduled-command path, verify the scheduler's execution identity, command input, and any additional password or authorization gate. The command name or `NOPASSWD` alone proves neither route. See [writing to root-owned files](../interesting-files-permissions/write-to-root.md) and [cron and systemd timers](../processes-crontab-systemd-dbus/cron-and-systemd-timers.md).
- A root-capable sudo rule for a shell script deserves a working-directory review if the script directly invokes `./helper` without first moving to a fixed directory. The caller may be able to choose a writable directory and place an executable with that relative name there; an absolute path elsewhere in the script does not protect this call. Confirm the effective rule, `runchdir` or other directory-changing policy, script flow, writable and executable directory, and mount/`NOEXEC` restrictions before treating it as code execution. Review the script statically instead of running the helper. The [sudoers manual](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf) documents working-directory policy.
- `sudoedit` and argument wildcards require exact version and rule checks; the [checklist](linux-privilege-escalation-checklist.md) includes the sudoedit file-edit issue.
- In a sudoers command rule, an argument wildcard can match whitespace as well as path characters. A rule for a read-capable command with an argument such as `/restricted/*` may therefore admit an extra file argument after a matching prefix. Review the exact run-as user, command path, argument pattern, and later denials; demonstrated file read does not imply command execution. The [sudoers manual](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf) distinguishes argument globs from command-path globs.
- Archivers and other utility programs may have execution hooks. Test the exact allowed arguments against [GTFOBins](https://gtfobins.github.io/) rather than assuming that only shells or interpreters execute commands.
- An unrestricted root-capable `qpdf` rule can expose a privileged file through PDF attachments: qpdf 10.2 and later support `--empty` and `--add-attachment file ... --` with an output PDF. If the privileged process can read the selected source and write the PDF to a caller-accessible path, that output can carry the source bytes. Review the effective sudo arguments and exclusions, qpdf version, source access, and output path before concluding that file disclosure is possible. Reading a root SSH key is useful for login only when that key is valid and root SSH authentication is permitted. See the [qpdf attachment options](https://qpdf.readthedocs.io/en/stable/cli.html#embedded-files-attachments).
- Sudo timestamp reuse depends on the cache policy, owning user, terminal/session, and permissions. The [privilege escalation guide](../linux-basics/linux-privilege-escalation/README.md#reusing-sudo-tokens) covers the checks.
- `doas` has its own rules and configuration. Check permitted commands and writable configuration paths as described in the [doas section](../linux-basics/linux-privilege-escalation/README.md#doas).

### Sudo-run build and package tools

An unrestricted sudo grant for Foundry's `forge` can matter even when the RunAs identity is another non-root user. Compiler options such as `--use` can select a local executable, and `forge flatten -o` selects an output file. Check the installed Forge version, exact sudo arguments, accessible project and compiler paths, output permissions, and effective environment before treating the grant as exploitable. A relative helper executable found through `PATH` is a version- and environment-dependent route, not a property to assume for every Forge build.<sup>[[23]](#references)[[24]](#references)</sup>

An unrestricted root-capable `pacman` grant permits more than package queries: `-U` accepts a local package, packages can contain install scripts, and `--hookdir` selects another hook directory. Review the effective sudo rule, argument restrictions and exclusions before testing; passive enumeration does not need to install a package or run a hook.<sup>[[25]](#references)[[26]](#references)</sup>

### Sudo-run preset and plugin loaders

Python tools that accept a caller-selected preset or plugin directory may import code with the privileges granted by sudo. For example, BBOT accepts a preset with `-p`, and its [custom-module documentation](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/#load-modules-from-custom-locations) describes `module_dirs` entries that select additional Python module directories. If the effective sudo rule permits a caller-selected preset and the caller controls a module in the selected directory, the import can execute code as the privileged user, potentially before the tool rejects an invalid module. Check the installed version, exact sudo run-as and argument policy, and ownership of the preset and module paths without loading the module during enumeration.

### Sudo-run Backdrop command line tool

[Bee](https://github.com/backdrop-contrib/bee) is a PHP command line tool for Backdrop CMS. Its `eval` (`php-eval`) and `php-script` commands can run caller-supplied PHP. A sudo rule that permits the Bee executable as root with unrestricted arguments can therefore expose root code execution when Bee can bootstrap a Backdrop installation. Run it from the site directory or select a site using the global `--root=<directory>` option; simply finding Bee or a Backdrop `settings.php` file does not prove the sudo permission, a usable site, or successful bootstrap. Review the effective sudo rule, any command exclusions, the executable's identity, and access to the site before testing. During passive enumeration, inspect the rule and file paths without invoking Bee. See the [Bee command changelog](https://github.com/backdrop-contrib/bee/blob/1.x-1.x/CHANGELOG.md) for the PHP command additions.

### Sudo-run terminal servers

`mosh-server` starts an interactive terminal server as the invoking user. It chooses a high UDP port and session key, reports both to the caller, and normally launches that user's login shell when a client connects. An unrestricted root-capable sudo grant for `mosh-server` is therefore a shell review candidate, even though the server command itself detaches. Check the effective RunAs identity, permitted arguments and exclusions, installed binary, shell, client availability, and UDP access. Passive enumeration should inspect the sudo rule without starting a server or printing any live session key. See the [Mosh server manual](https://manpages.debian.org/unstable/mosh/mosh-server.1.en.html) and [upstream design notes](https://github.com/mobile-shell/mosh#how-it-works).

### Privileged backup wrappers that rewrite a caller's task file

A root-run shell wrapper may accept a task file selected by the caller, strip `../` from source paths, check that each result starts with an allowed directory, rewrite the task file, and then pass its *pathname* to a backup program. Review the transformed path after full canonical resolution: a single string-replacement pass can expose a new traversal sequence that a lexical prefix check accepts. Also check whether the backup program reads the transformed in-memory data or opens the file again. If it opens the file again, a failed rewrite can leave the original input in place.

On Linux, `fs.protected_regular` can deny an `O_CREAT` write to another user's regular file in a world-writable sticky directory. That denial is protective, but a shell wrapper that ignores the write error may still continue with the original task file. Confirm the setting, the file's owner and directory, and whether the wrapper stops on failure. The path is only a file-disclosure candidate when the effective sudo rule permits the wrapper as a privileged user, the caller controls the task input and readable backup destination, and the backup utility actually includes protected sources. Inspect these conditions without running the backup during enumeration.

### Argument wildcards on privileged packet tools

In a sudo rule for `tcpdump`, a `*` in the **argument pattern** can match whitespace and slashes, so a pathname-looking restriction may still allow additional option text. This differs from a wildcard in the command's executable path; inspect the complete RunAs rule and any later denials. If options can be injected, the permitted invocation and installed [`tcpdump` option semantics](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in) determine whether `-F`, `-V`, `-r`, `-w`, or `-Z` gives a useful read/write primitive. `-V` reads a list of capture filenames, not an arbitrary general-purpose file dump. AppArmor or another MAC policy can block file access even when sudo permits the command; a profile file on disk does not prove that it is loaded or enforcing. Review authorization and policy passively before drawing a conclusion. The [sudoers manual](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf) describes the wildcard distinction.

### Sudo-run Nmap wrappers

When a sudo-allowed `nmap` path is a shell wrapper, inspect the exact permitted path and every option it forwards. Blocking the familiar `--script` spelling does not necessarily block NSE code loading: Nmap's [`--datadir`](https://nmap.org/book/man-misc-options.html) selects data files, and NSE [loads `nse_main.lua`](https://nmap.org/book/nse-implementation.html) from the selected data directory when scripting is enabled. Some installed builds also accept alternate long-option spellings, so compare restrictions with that binary's actual parser. [`--excludefile`](https://nmap.org/book/man-target-specification.html) is a separate file-read surface; parser errors may disclose text. Check the effective sudo rule, wrapper logic, Nmap version, directory control, and MAC policy without running scans during enumeration.

### Sudo-run Mercurial pull hooks

A fixed source in `sudo hg pull /fixed/source` still leaves the **receiving** repository selected by the current working directory unless the command fixes it with `-R`. A caller-controlled receiving repo can define hooks in `.hg/hgrc`, and a hook may run as the sudo RunAs user. [Mercurial ignores repository configuration owned by an untrusted user or group](https://mercurial-scm.org/help/topics/config), so inspect the RunAs account's trusted users/groups and the exact working directory before treating this as code execution. Reading the policy and config is sufficient for a passive review; do not pull or invoke a hook to enumerate it.

### Sudo-run rsync archive copies

For `sudo rsync -a ... /writable/source/* /fixed/destination/`, a `*` in the **sudoers argument pattern** can match spaces and admit an extra option between source and destination. This is distinct from shell expansion of filenames. If the caller can populate the source and the destination is writable by the privileged rsync process, [`--chown`](https://download.samba.org/pub/rsync/rsync.1) can request privileged ownership while archive mode preserves permission bits, potentially creating an owned SetUID file. Check the exact [sudoers wildcard semantics](https://man7.org/linux/man-pages/man5/sudoers.5.html), rsync version, later denials, filesystem `nosuid`, and MAC policy. A matching rule is a review candidate, not proof of successful privilege escalation.

### Sudo-run packet-filter rule export

An unrestricted root-capable grant for both `iptables` and `iptables-save` (or the matching `ip6tables` pair) deserves a file-write review. The `comment` match accepts caller-chosen rule text, while `iptables-save -f` writes the serialized ruleset to a selected pathname.<sup>[[20]](#references)[[21]](#references)</sup> A useful payload depends on how the installed backend serializes comments and whether the destination file accepts other lines in the export; `iptables-save` alone does not provide arbitrary chosen content. Check the exact sudo RunAs identity, arguments and exclusions, available match extension, backend, and destination permissions. During enumeration, inspect the grant without changing firewall rules or writing a file.

### Privileged Below logging directory

[CVE-2025-27591](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w) affected Below releases before 0.9.0 that created a world-writable `/var/log/below` directory. If a service or a permitted sudo command runs an affected build as root, a user who can write and traverse a non-sticky log directory may be able to replace a log entry with a symlink before the privileged process opens it. Review the installed package's patch status, the exact privileged execution path, effective directory access, sticky bit and ACLs, and metadata for `/var/log/below/error_root.log`. A world-writable path or a sudo rule alone does not establish the full chain. A sticky directory or vendor backport changes the assessment. Passive enumeration should inspect metadata only; it need not create a link or run the privileged program.

### Privileged support-bundle collection from writable inputs

A support-profile script permitted by `sudo` may read fixed log paths as root and copy their contents into a profile archive. Review the actual script for file reads, then check whether the caller can replace a source path or any parent directory entry with a symlink. If the privileged read follows that link and the resulting archive is readable by the caller, a protected file can be disclosed. The sudo grant, writable source path, privileged read, and readable output must all be present; a writable log or profile filename alone is insufficient. Inspect the effective permissions and link metadata without replacing files or generating a profile during enumeration. [Nagios XI support guidance](https://support.nagios.com/forum/viewtopic.php?t=62758) documents its root-run profile script and output archive, illustrating why such bundles need restricted inputs and output access.

### Root-run Python archive restore scripts

A tightly scoped sudo rule for a Python restore script still needs a review of its archive input. If the caller can select or replace the archive and the script extracts it as root with `tarfile.extractall(filter="data")`, check the interpreter's security updates before trusting the filter. CPython fixed several symlink and hard-link filter bypasses, including CVE-2025-4517, in 3.9.23, 3.10.18, 3.11.13, 3.12.11, and 3.13.4. Distribution backports can fix an earlier version, so the displayed interpreter version alone is not proof of exposure.<sup>[[16]](#references)[[17]](#references)</sup>

For a passive review, read the exact sudo command and script, trace which argument chooses the archive, and check whether the current user can write the archive or its containing directory. Confirm the installed vendor patch and extraction destination separately; `filter="data"` does not make every untrusted archive safe.<sup>[[16]](#references)[[17]](#references)</sup>

### Sudo-run machine-learning model loaders

A sudo rule that permits a caller-selected `.pt`, `.pth`, or `.ckpt` file deserves review when a privileged script passes that file to [`torch.load`](https://docs.pytorch.org/docs/stable/generated/torch.load.html), `pickle.load`, or another pickle-based loader. Check the effective RunAs rule, whether the caller can create or replace the selected model, and the actual argument flow through any shell wrapper into the Python helper. The `.pth` extension also names unrelated Python site configuration files, so the extension alone is not evidence of model loading. An archive scan or static pickle scan does not establish that the later load is safe; inspect the loader's [version-dependent `weights_only` behavior](https://docs.pytorch.org/docs/stable/notes/serialization.html) and any allowlisting. See the [ML pickle and Fickling notes](../../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md). Passive enumeration should never load or unpack the model.

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
- [20] [iptables-save(8) — netfilter manual page](https://www.man7.org/linux/man-pages/man8/iptables-save.8.html)
- [21] [iptables-extensions(8): comment match — netfilter manual page](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [22] [Simple Command Expansion — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Simple-Command-Expansion.html)
- [23] [Forge compiler options — Foundry documentation](https://getfoundry.sh/forge/reference/forge-inspect/)
- [24] [Forge flatten — Foundry documentation](https://getfoundry.sh/forge/reference/forge-flatten/)
- [25] [pacman(8) — Arch manual pages](https://man.archlinux.org/man/pacman.8.en)
- [26] [PKGBUILD(5) install scripts — Arch manual pages](https://man.archlinux.org/man/core/pacman/PKGBUILD.5.en)

{{#include ../../banners/hacktricks-training.md}}
