# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks kao što su KernelSU, APatch i SKRoot patch-uju ili hook-uju Android/Linux kernel i izlažu privilegovanu funkcionalnost neprivilegovanoj userspace manager app. Magisk je zasebno obrađen u nastavku, jer je CVE-2024-48336 obuhvatao učitavanje koda na strani manager-a, a ne ovaj KernelSU syscall path.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Ova stranica apstrahuje tehnike i probleme otkrivene u javnim istraživanjima (naročito Zimperium-ovu analizu KernelSU v0.5.7), kako bi i red i blue teams razumeli attack surface, exploitation primitive i pouzdane mitigacije.<sup>[[1]](#references)</sup>

---
## Arhitektonski obrazac: syscall-hooked manager kanal

- U KernelSU v0.5.7, kernel hook na `prctl` prima magic value, command ID i argumente specifične za command iz userspace-a.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Caller najpre zahteva status manager-a pomoću `CMD_BECOME_MANAGER`. Authorization je specifičan za command: `CMD_GRANT_ROOT` proverava stanje manager/allowlist-a, `CMD_ALLOW_SU` je dostupan samo manager-u, a `CMD_SET_SEPOLICY` je u ovoj verziji dostupan samo root-u.<sup>[[2]](#references)[[11]](#references)</sup>
- Ostali command-i ispituju verziju/konfiguraciju ili prijavljuju framework events.<sup>[[2]](#references)</sup>
- Pošto svaka app može da pozove ovaj syscall interface, ispravnost manager authentication-a je kritična.<sup>[[1]](#references)[[2]](#references)</sup>

Primer (KernelSU dizajn):
- Hooked syscall: prctl
- Magic value za preusmeravanje ka KernelSU handler-u: 0xDEADBEEF
- Command-i uključuju: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, itd.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (kako je implementiran)

Kada userspace pozove prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU proverava:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Provera prefix-a path-a
- Prosleđeni path mora da počinje očekivanim prefix-om za UID caller-a, npr. /data/data/<pkg> ili /data/user/<id>/<pkg>.
- Reference: logika path prefix-a u core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Provera vlasništva
- Vlasnik path-a mora biti UID caller-a.
- Reference: logika vlasništva u core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) APK signature check putem FD table scan-a
- Iteriraju se otvoreni file descriptor-i calling process-a po rastućem redosledu descriptor-a.
- Za svaki regular file čiji path počinje sa `/data/app/` i završava se sa `/base.apk`, zahteva se da path sadrži package substring izveden iz prosleđenog data-directory path-a.
- Proverava se signature prvog kandidata koji prođe te path provere.
- Parsira se APK v2 signature i proverava u odnosu na official manager certificate.
- References: manager.c (iteriranje FD-ova), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Ako sve provere prođu, kernel privremeno kešira UID manager-a; command-i dostupni samo manager-u zatim prihvataju taj UID, dok ostali command-i zadržavaju sopstveni UID ili allowlist provere.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Klasa vulnerability-ja: oslanjanje na APK selection izveden iz path-a

KernelSU v0.5.7 ne vezuje rezultat signature provere za identity instaliranog package-a iz PackageManager-a. U `manager.c`, package test je samo provera substring-a u path-u (`strstr(cwd, pkg)`); prvi kandidat koji prođe tu proveru zatim se proverava potpisom. Napadač zato može da postavi genuine manager APK pod `/data/app/` path koji takođe sadrži ime package-a napadača i da obezbedi da on bude prvi izabran.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Ovo trust-by-indirection omogućava neprivilegovanoj app da se predstavlja kao manager bez posedovanja manager signing key-a.<sup>[[1]](#references)</sup>

Ključna svojstva koja se iskorišćavaju:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scan je uređen prema descriptor index-u, a package check je provera substring-a u path-u, a ne verifikovano povezivanje package-to-APK identity-ja.
- open() vraća najniži raspoloživi FD. Zatvaranjem FD-ova sa manjim brojevima najpre, napadač može da kontroliše redosled.
- Bundled manager APK može da se postavi pod `/data/app/` na path koji sadrži package string napadača, uz zadržavanje official manager signature.

---
## Preduslovi napada

Konkretan slučaj za KernelSU v0.5.7 zahteva:<sup>[[1]](#references)[[3]](#references)</sup>

- Uređaj je već root-ovan pomoću ranjivog rooting framework-a (npr. KernelSU v0.5.7).
- Napadač može lokalno da izvršava proizvoljan neprivilegovan code (Android app process).
- Za implementaciju v0.5.7, `current->real_parent` mora imati UID 0 (source comment ovo opisuje kao zahtev da je process direct child od zygote-a); `manager.c` odbacuje druge parent-e.<sup>[[3]](#references)</sup>
- Pravi manager se još nije autentifikovao (npr. neposredno nakon reboot-a). Neki framework-ovi keširaju UID manager-a nakon uspeha; morate pobediti u race-u.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

Koraci visokog nivoa (demo video prikazuje javni proof of concept u radu):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Napravite validan path do sopstvenog app data directory-ja kako biste zadovoljili provere prefix-a i vlasništva.
2) Postavite genuine KernelSU Manager base.apk pod `/data/app/` na path koji sadrži vaš package string, a zatim ga otvorite na FD-u sa manjim brojem od FD-a vašeg base.apk-a.
3) Pozovite prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) da biste prošli provere.
4) Upotrebite `CMD_GRANT_ROOT`, zatim `CMD_ALLOW_SU` za persistent su; root-only `CMD_SET_SEPOLICY` pozovite tek nakon dobijanja root-a i samo tamo gde je podržan.

Praktične napomene za korak 2 (FD ordering):<sup>[[1]](#references)</sup>
- Identifikujte FD vašeg process-a za sopstveni /data/app/*/base.apk prolaskom kroz /proc/self/fd symlink-ove.
- Zatvorite FD sa malim brojem (npr. stdin, fd 0) i najpre otvorite legitimate manager APK tako da zauzme fd 0 (ili bilo koji index manji od FD-a vašeg base.apk-a).
- Bundle-ujte legitimate manager APK sa svojom app tako da njegov path počinje sa `/data/app/`, završava se sa `/base.apk` i sadrži vaš package string. Na primer, path unutar `lib` directory-ja vaše app može da zadovolji ove provere.<sup>[[1]](#references)[[3]](#references)</sup>

Primeri code snippets-a (Android/Linux, samo ilustrativno):

Enumerišite otvorene FD-ove da biste pronašli base.apk entries:
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
Naterajte FD sa nižim brojem da pokazuje na legitimni manager APK:
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
Autentifikacija Manager-a putem KernelSU v0.5.7 `prctl` hook-a:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
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
Nakon uspeha, privilegovane komande (primeri):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: promoviše trenutni proces u root
- CMD_ALLOW_SU: dodaje vaš package/UID u allowlist za trajni su
- CMD_SET_SEPOLICY: prilagođava SELinux policy nakon dobijanja root privilegija; KernelSU v0.5.7 proverava UID 0 za ovu komandu.<sup>[[2]](#references)</sup>

Savet za race/persistence:
- Registrujte BOOT_COMPLETED receiver u AndroidManifest (`RECEIVE_BOOT_COMPLETED`) da se pokrene nakon reboot-a i pokuša authentication pre pravog manager-a; permission autorizuje prijem `ACTION_BOOT_COMPLETED`, ali sama po sebi ne garantuje prioritet pri scheduling-u.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Smernice za detekciju i mitigation

Za framework developere:
- Vežite authentication za package/UID pozivaoca, a ne za proizvoljne FD-ove:
- Odredite package pozivaoca na osnovu njegovog UID-a i proverite ga u odnosu na signature instaliranog package-a (putem PackageManager-a), umesto skeniranja FD-ova.
- Ako je kernel-only, koristite stabilan identitet pozivaoca (task creds) i proveravajte ga na stabilnom source of truth-u kojim upravlja init/userspace helper, a ne preko process FD-ova.
- Izbegavajte provere path-prefix-a kao identiteta; pozivalac ih trivijalno može zadovoljiti.
- Koristite challenge–response zasnovan na nonce-u preko kanala i obrišite svaki keširani manager identitet pri boot-u ili tokom ključnih događaja.
- Razmotrite authenticated IPC zasnovan na binder-u umesto preopterećivanja generičkih syscall-ova kada je to izvodljivo.

Za defendere/blue team:
- Detektujte prisustvo rooting framework-ova i manager procesa; nadgledajte prctl pozive sa sumnjivim magic constants (npr. 0xDEADBEEF) ako imate kernel telemetry.<sup>[[1]](#references)[[11]](#references)</sup>
- Na upravljanim flotama blokirajte ili prijavite boot receiver-e iz nepouzdanih package-ova koji neposredno nakon boot-a ubrzano pokušavaju privilegovane manager komande.
- Obezbedite da su uređaji ažurirani na zakrpane verzije framework-a; invalidirajte keširane manager ID-jeve nakon update-a.

Ograničenja napada:<sup>[[1]](#references)[[2]](#references)</sup>
- Utiče samo na uređaje koji su već rootovani pomoću ranjivog framework-a.
- Obično zahteva reboot/race window pre nego što se legitimni manager autentifikuje (neki framework-ovi keširaju manager UID do resetovanja).

---
## Povezane napomene kroz framework-ove

- Authentication zasnovan na password-u (npr. istorijske APatch/SKRoot verzije) može biti slab ako su password-i pogodni za pogađanje/bruteforce ili ako su validacije neispravne.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Authentication zasnovan na package/signature-u (npr. KernelSU) u principu je jači, ali mora biti vezan za stvarnog pozivaoca, a ne za artefakte izvedene iz path-a i odabrane putem skeniranja FD-ova.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 je uticao na pre-Canary 27007 verzije koje su učitavale code iz neproverenog GMS package-a, omogućavajući lokalnoj aplikaciji da izvrši code u Magisk aplikaciji i eskalira na root bez interakcije korisnika.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Rooting svega zlog: bezbednosne rupe koje bi mogle da ugroze vaš mobilni uređaj](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – authentication provere u core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – iteracija FD-ova u manager.c, provera package-a i poziv signature-a](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – APK v2 verifikacija u apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [KernelSU projekat](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk issue #8279 – provera da li je GMS system app](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – identifikatori komandi u ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
