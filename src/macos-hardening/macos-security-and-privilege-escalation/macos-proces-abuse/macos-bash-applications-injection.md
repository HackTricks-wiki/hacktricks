# macOS Bash Applications Injection

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

## References

- [1] [Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash Invoking Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)

{{#include ../../../banners/hacktricks-training.md}}
