# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica dokumentuje praktičan secure-boot proboj na više MediaTek platformi iskorišćavanjem rupe u verifikaciji kada je konfiguracija bootloader-a uređaja (seccfg) postavljena na "unlocked". Greška omogućava pokretanje patch-ovanog bl2_ext na ARM EL3 koji onemogućava verifikaciju potpisa nižih nivoa, rušeći lanac poverenja i omogućavajući učitavanje proizvoljnog nepotpisanog TEE/GZ/LK/Kernel.

> Pažnja: Rano patchovanje tokom boot-a može trajno brick-ovati uređaje ako su offsets pogrešni. Uvek čuvajte full dumps i pouzdan recovery path.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Ključna granica poverenja:
- bl2_ext izvršava na EL3 i odgovoran je za verifikaciju TEE, GenieZone, LK/AEE i kernela. Ako bl2_ext sam po sebi nije autentifikovan, ostatak lanca se trivijalno zaobilazi.

## Root cause

Na pogođenim uređajima, Preloader ne primenjuje autentifikaciju particije bl2_ext kada seccfg ukazuje na "unlocked" stanje. To omogućava flešovanje bl2_ext pod kontrolom napadača koji se izvršava na EL3.

Unutar bl2_ext, funkcija politike verifikacije može biti patch-ovana tako da bezuslovno prijavi da verifikacija nije potrebna. Minimalni konceptualni patch je:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Sa ovom izmenom, sve naredne slike (TEE, GZ, LK/AEE, Kernel) se prihvataju bez kriptografskih provera kada ih učita ispravljeni bl2_ext koji radi na EL3.

## Kako proceniti cilj (expdb logovi)

Izvezite i pregledajte boot logove (npr. expdb) oko učitavanja bl2_ext. Ako je img_auth_required = 0 i vreme verifikacije sertifikata je ~0 ms, sprovođenje verifikacije je verovatno isključeno i uređaj je eksploatabilan.

Primer isječka loga:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Napomena: Navodno neki uređaji preskaču verifikaciju bl2_ext čak i sa zaključanim bootloader-om, što pojačava posledice.

Uređaji koji dolaze sa lk2 secondary bootloader-om su zabeleženi sa istom logičkom rupom, zato prikupite expdb logs za obe bl2_ext i lk2 particije da potvrdite da li bilo koji put primenjuje potpise pre nego što pokušate porting.

Ako post-OTA Preloader sada loguje img_auth_required = 1 za bl2_ext čak i dok je seccfg otključan, vendor je verovatno zatvorio rupu — pogledajte napomene o OTA persistence ispod.

## Praktičan tok eksploatacije (Fenrir PoC)

Fenrir je referentni exploit/patching toolkit za ovu klasu problema. Podržava Nothing Phone (2a) (Pacman) i poznato radi (delimično podržano) na CMF Phone 1 (Tetris). Portovanje na druge modele zahteva reverse engineering specifičnog za uređaj bl2_ext.

High-level process:
- Obtain the device bootloader image for your target codename and place it as `bin/<device>.bin`
- Build a patched image that disables the bl2_ext verification policy
- Flash the resulting payload to the device (fastboot assumed by the helper script)

Komande:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Ako fastboot nije dostupan, morate koristiti odgovarajući alternativni metod flešovanja za vašu platformu.

### OTA-patched firmware: keeping the bypass alive (NothingOS 4, late 2025)

Nothing je zakrpio Preloader u novembru 2025. u NothingOS 4 stable OTA (build BP2A.250605.031.A3) kako bi primenio verifikaciju bl2_ext čak i kada je seccfg otključan. Fenrir `pacman-v2.0` ponovo funkcioniše mešanjem ranjivog Preloadera iz NOS 4 beta sa stabilnim LK payloadom:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Važno:
- Flash-ujte isporučeni Preloader **samo** na odgovarajući uređaj/slot; pogrešan Preloader je trenutni hard brick.
- Proverite expdb nakon flash-ovanja; img_auth_required bi trebalo da se vrati na 0 za bl2_ext, što potvrđuje da se ranjivi Preloader izvršava pre vašeg zakrpljenog LK.
- Ako buduće OTAs zakrpe i Preloader i LK, sačuvajte lokalnu kopiju ranjivog Preloader-a da biste ponovo otvorili taj propust.

### Automatizacija build-a & payload debugging

- `build.sh` sada automatski preuzima i eksportuje Arm GNU Toolchain 14.2 (aarch64-none-elf) prvi put kada ga pokrenete, tako da ne morate ručno da žonglirate cross-kompajlerima.
- Export `DEBUG=1` pre poziva `build.sh` da bi payloads bili kompajlirani sa detaljnim serijskim ispisima, što značajno pomaže kada slepo patchujete EL3 code paths.
- Uspešni build-ovi generišu i `lk.patched` i `<device>-fenrir.bin`; potonji već sadrži ubačen payload i to je ono što treba da flash-ujete/boot-testirate.

## Runtime payload capabilities (EL3)

Patched bl2_ext payload može:
- Registrovati prilagođene fastboot komande
- Kontrolisati/override-ovati boot režim
- Dinamički pozivati ugrađene bootloader funkcije tokom izvršavanja
- Lažirati “lock state” kao locked dok je zapravo unlocked kako bi se prošli strožiji integritetni checkovi (u nekim okruženjima i dalje mogu biti potrebna podešavanja vbmeta/AVB)

Ograničenje: Trenutni PoCs primećuju da modifikacija memorije u runtime-u može izazvati grešku zbog MMU ograničenja; payloads generalno izbegavaju upise u živu memoriju dok se to ne reši.

## Payload staging patterns (EL3)

Fenrir deli svoju instrumentaciju na tri compile-time faze: stage1 se izvršava pre `platform_init()`, stage2 pre nego što LK signalizira ulazak u fastboot, a stage3 se izvršava neposredno pre nego što LK učita Linux. Svaki device header pod `payload/devices/` sadrži adrese za ove hook-ove plus fastboot pomoćne simbole, pa držite te offsete sinhronizovane sa vašim target build-om.

Stage2 je zgodno mesto da se registruju proizvoljni `fastboot oem` verbs:
```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
video_printf("r0rt1z2 was here...\n");
fastboot_info("pwned by r0rt1z2");
fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
notify_enter_fastboot();
}
```
Stage3 pokazuje kako privremeno promeniti atribute tabele stranica da bi se izmenili nepromenljivi stringovi, kao što je Android’s “Orange State” upozorenje, bez potrebe za pristupom kernelu nizvodno:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Pošto stage1 pokreće pre nego što platforma bude podignuta, to je pravo mesto da pozovete OEM power/reset primitives ili da ubacite dodatno integrity logging pre nego što se verified boot lanac razorava.

## Saveti za portovanje

- Reverse engineer uređaju-specifičan bl2_ext da biste locirali logiku verifikacione politike (npr. sec_get_vfy_policy).
- Identifikujte mesto vraćanja politike ili granu odluke i ispravite je da „no verification required“ (return 0 / unconditional allow).
- Držite ofsete potpuno specifičnim za uređaj i firmware; nemojte ponovo koristiti adrese između varijanti.
- Validirajte prvo na žrtvenoj jedinici. Pripremite plan oporavka (npr. EDL/BootROM loader/SoC-specific download mode) pre nego što flashujete.
- Uređaji koji koriste lk2 sekundarni bootloader ili prijavljuju “img_auth_required = 0” za bl2_ext čak i dok su zaključani treba da se tretiraju kao ranjive kopije ove klase buga; prema izveštajima, Vivo X80 Pro je već preskakao verifikaciju uprkos prijavljenom zaključanom stanju.
- Kada OTA počne da primenjuje bl2_ext potpise (img_auth_required = 1) u otključanom stanju, proverite da li se stariji Preloader (često dostupan u beta OTA-ima) može flash-ovati da ponovo otvori rupu, a zatim ponovo pokrenite fenrir sa ažuriranim ofsetima za noviji LK.

## Bezbednosni uticaj

- Izvršavanje EL3 koda nakon Preloader-a i potpuni kolaps lanca poverenja za ostatak boot puta.
- Mogućnost bootovanja unsigned TEE/GZ/LK/Kernel, zaobilaženjem očekivanja secure/verified boot-a i omogućavanjem trajnog kompromitovanja.

## Napomene o uređajima

- Potvrđeno podržano: Nothing Phone (2a) (Pacman)
- Poznato da radi (nepotpuna podrška): CMF Phone 1 (Tetris)
- Posmatrano: prema izveštajima, Vivo X80 Pro nije verifikovao bl2_ext čak i kada je zaključan
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) ponovo je omogućio bl2_ext verifikaciju; fenrir `pacman-v2.0` vraća bypass flashovanjem beta Preloader-a plus zakrpljenog LK kao što je prikazano gore
- Izveštaji iz industrije ističu dodatne lk2-bazirane vendore koji isporučuju istu logičku grešku, pa očekujte dalje preklapanje kroz MTK izdanja 2024–2025.

## Reference

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
