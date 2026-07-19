# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks kao što su KernelSU, APatch, SKRoot i Magisk često patch-uju Linux/Android kernel i izlažu privilegovanu funkcionalnost neprivilegovanom userspace „manager“ app-u putem hook-ovanog syscall-a. Ako je korak manager-authentication neispravan, bilo koja lokalna app može pristupiti ovom kanalu i eskalirati privilegije na već root-ovanim uređajima.

Ova stranica apstrahuje tehnike i zamke otkrivene u javnim istraživanjima (naročito Zimperium-ovoj analizi KernelSU v0.5.7), kako bi red i blue teams mogli da razumeju attack surface, exploitation primitive i robusne mitigacije.

---
## Arhitektonski obrazac: syscall-hooked manager kanal

- Kernel module/patch hook-uje syscall (najčešće prctl) da bi primao "commands" iz userspace-a.
- Protocol je obično: magic_value, command_id, arg_ptr/len ...
- Userspace manager app se prvo authenticates (npr. CMD_BECOME_MANAGER). Kada kernel označi caller-a kao trusted manager, prihvataju se privilegovane commands:
- Dodeli root caller-u (npr. CMD_GRANT_ROOT)
- Upravljaj allowlists/deny-lists za su
- Prilagodi SELinux policy (npr. CMD_SET_SEPOLICY)
- Proveri version/configuration
- Pošto bilo koja app može da pozove syscalls, ispravnost manager authentication-a je kritična.

Primer (KernelSU dizajn):
- Hooked syscall: prctl
- Magic value za preusmeravanje ka KernelSU handler-u: 0xDEADBEEF
- Commands uključuju: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, itd.

---
## KernelSU v0.5.7 authentication flow (kako je implementiran)

Kada userspace pozove prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU proverava:

1) Provera path prefix-a
- Prosleđeni path mora da počinje očekivanim prefix-om za caller UID, npr. /data/data/<pkg> ili /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.

2) Provera vlasništva
- Path mora biti u vlasništvu caller UID-a.
- Reference: core_hook.c (v0.5.7) ownership logic.

3) APK signature check putem FD table scan-a
- Iterira kroz open file descriptors (FDs) calling process-a.
- Bira prvi file čiji path odgovara /data/app/*/base.apk.
- Parsira APK v2 signature i proverava je u odnosu na official manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).

Ako sve provere prođu, kernel privremeno kešira manager UID i prihvata privilegovane commands od tog UID-a dok se ne resetuje.

---
## Klasa vulnerability-ja: verovanje u „prvi matching APK“ iz FD iteration-a

Ako je signature check vezan za „prvi matching /data/app/*/base.apk“ pronađen u process FD table-i, on zapravo ne proverava package caller-a. Attacker može unapred postaviti legitimno signed APK (stvarni manager-ov) tako da se pojavi ranije u FD listi od njegovog sopstvenog base.apk.

Ovo trust-by-indirection omogućava neprivileged app-u da impersonate-uje manager-a bez posedovanja manager signing key-a.

Ključne exploited properties:
- FD scan nije vezan za package identity caller-a; on samo pattern-match-uje path strings.
- open() vraća najniži dostupan FD. Zatvaranjem lower-numbered FDs prvo, attacker može da kontroliše ordering.
- Filter samo proverava da li path odgovara /data/app/*/base.apk – ne i da li odgovara installed package-u caller-a.

---
## Attack preconditions

- Uređaj je već root-ovan pomoću vulnerable rooting framework-a (npr. KernelSU v0.5.7).
- Attacker može lokalno da pokrene proizvoljan unprivileged code (Android app process).
- Pravi manager se još nije authenticat-ovao (npr. odmah nakon reboot-a). Neki framework-ovi keširaju manager UID nakon uspeha; potrebno je pobediti u race-u.

---
## Exploitation outline (KernelSU v0.5.7)

High-level koraci:
1) Izgradi validan path do sopstvenog app data directory-ja da bi zadovoljio prefix i ownership checks.
2) Obezbedi da genuine KernelSU Manager base.apk bude otvoren na lower-numbered FD-u od sopstvenog base.apk.
3) Pozovi prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) da bi prošao provere.
4) Izdaj privilegovane commands kao što su CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY da bi elevation ostao trajno aktivan.

Practical notes za step 2 (FD ordering):
- Identifikuj FD svog process-a za sopstveni /data/app/*/base.apk prolaskom kroz /proc/self/fd symlinks.
- Zatvori low FD (npr. stdin, fd 0) i prvo otvori legitimate manager APK tako da zauzme fd 0 (ili bilo koji index niži od FD-a sopstvenog base.apk).
- Bundle-uj legitimate manager APK sa svojom app tako da njegov path zadovolji kernel-ov naive filter. Na primer, postavi ga pod subpath koji odgovara /data/app/*/base.apk.

Primer code snippets-a (Android/Linux, samo ilustrativno):

Enumeriši open FDs da bi pronašao base.apk entries:
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
Autentikacija Managera putem prctl hook-a:
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
After uspeha, privilegovane komande (primeri):
- CMD_GRANT_ROOT: promovisati trenutni proces u root
- CMD_ALLOW_SU: dodati vaš package/UID na allowlist za persistent su
- CMD_SET_SEPOLICY: prilagoditi SELinux policy kako framework podržava

Savet za race/persistence:
- Registrujte BOOT_COMPLETED receiver u AndroidManifest (RECEIVE_BOOT_COMPLETED) da se pokrene rano nakon reboot-a i pokuša authentication pre pravog manager-a.

---
## Smernice za detekciju i ublažavanje

Za developere framework-a:
- Vežite authentication za package/UID pozivaoca, a ne za proizvoljne FD-ove:
- Razrešite package pozivaoca na osnovu njegovog UID-a i proverite ga u odnosu na signature instaliranog package-a (putem PackageManager-a), umesto skeniranja FD-ova.
- Ako je rešenje kernel-only, koristite stabilni identitet pozivaoca (task creds) i validirajte ga na stabilnom source of truth-u kojim upravlja init/userspace helper, a ne na process FD-ovima.
- Izbegavajte provere path-prefix-a kao identiteta; pozivalac ih trivijalno može zadovoljiti.
- Koristite nonce-based challenge–response preko kanala i obrišite svaki keširani identitet manager-a pri boot-u ili tokom ključnih događaja.
- Razmotrite authenticated IPC zasnovan na binder-u umesto preopterećivanja generičkih syscall-ova kada je to izvodljivo.

Za defendere/blue team:
- Detektujte prisustvo rooting framework-a i manager procesa; nadgledajte prctl pozive sa sumnjivim magic constants (npr. 0xDEADBEEF) ako imate kernel telemetry.
- Na managed fleet-ovima blokirajte ili alarmirajte na boot receiver-e iz nepouzdanih package-ova koji neposredno nakon boot-a ubrzano pokušavaju privilegovane manager komande.
- Obezbedite da su uređaji ažurirani na patched verzije framework-a; invalidirajte keširane manager ID-jeve nakon update-a.

Ograničenja attack-a:
- Utiče samo na uređaje koji su već rootovani pomoću ranjivog framework-a.
- Obično zahteva reboot/race window pre nego što se legitimni manager authenticira (neki framework-ovi keširaju UID manager-a do reset-a).

---
## Povezane beleške kroz framework-ove

- Password-based auth (npr. istorijski APatch/SKRoot build-ovi) može biti slab ako su password-i lako pogodivi ili podložni bruteforce-u, odnosno ako su validacije neispravne.
- Package/signature-based auth (npr. KernelSU) je u principu jači, ali mora biti vezan za stvarnog pozivaoca, a ne za indirektne artefakte poput FD scan-ova.
- Magisk: CVE-2024-48336 (MagiskEoP) je pokazao da čak i zreli ekosistemi mogu biti podložni identity spoofing-u koji dovodi do izvršavanja koda sa root privilegijama unutar manager context-a.

---
## Reference

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
