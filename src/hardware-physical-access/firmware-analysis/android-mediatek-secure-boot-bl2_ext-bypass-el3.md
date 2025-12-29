# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica dokumentuje praktičan prekid secure-boot-a na više MediaTek platformi zloupotrebom praznine u verifikaciji kada je konfiguracija bootloader-a (seccfg) postavljena na "unlocked". Propust omogućava pokretanje izmenjenog bl2_ext u ARM EL3 kako bi se onemogućila dalja verifikacija potpisa, urušivši lanac poverenja i omogućivši učitavanje proizvoljnih unsigned TEE/GZ/LK/Kernel komponenti.

> Upozorenje: Early-boot patching može trajno brick-ovati uređaje ako su offsets pogrešni. Uvek čuvajte full dumps i pouzdan recovery path.

## Pogođeni tok pokretanja (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Ključna granica poverenja:
- bl2_ext izvodi kod na EL3 i odgovoran je za verifikaciju TEE, GenieZone, LK/AEE i kernela. Ako bl2_ext sam nije autentifikovan, ostatak lanca se trivijalno zaobilazi.

## Osnovni uzrok

Na pogođenim uređajima, Preloader ne forsira autentifikaciju bl2_ext particije kada seccfg ukazuje na stanje "unlocked". Ovo omogućava flashovanje bl2_ext pod kontrolom napadača koji se izvršava na EL3.

Unutar bl2_ext, funkcija politike verifikacije može se zakrpiti da bezuslovno prijavljuje da verifikacija nije potrebna. Minimalna konceptualna zakrpa je:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Sa ovom izmenom, sve naredne images (TEE, GZ, LK/AEE, Kernel) se prihvataju bez kriptografskih provera kada ih učitava izmenjeni bl2_ext koji radi na EL3.

## Kako proceniti cilj (expdb logovi)

Izdumpujte/pregledajte boot logove (npr. expdb) oko učitavanja bl2_ext. Ako je img_auth_required = 0 i vreme verifikacije sertifikata je ~0 ms, verovatno nije omogućena provera (enforcement) i uređaj je eksploatabilan.

Primer isečka loga:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Napomena: Na nekim uređajima se navodno preskače bl2_ext verifikacija čak i sa zaključanim bootloader-om, što pogoršava uticaj.

Uređaji koji isporučuju lk2 secondary bootloader primećeni su sa istim logičkim propustom, zato preuzmite expdb logove za obe particije bl2_ext i lk2 da potvrdite da li bilo koji od puteva primenjuje potpise pre nego što pokušate portovanje.

## Praktičan tok eksploatacije (Fenrir PoC)

Fenrir je referentni exploit/patching toolkit za ovu klasu problema. Podržava Nothing Phone (2a) (Pacman) i poznato funkcioniše (delimično podržano) na CMF Phone 1 (Tetris). Portovanje na druge modele zahteva reverse engineering device-specific bl2_ext.

Visok nivo procesa:
- Nabavite bootloader image uređaja za ciljnu kodnu oznaku i smestite ga kao `bin/<device>.bin`
- Izgradite patchovan image koji onemogućava politiku verifikacije bl2_ext
- Flashujte dobijeni payload na uređaj (skripta podrazumevano koristi fastboot)

Komande:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Ako fastboot nije dostupan, morate koristiti odgovarajuću alternativnu flashing metodu za vašu platformu.

### Automatizacija build-a i debugovanje payload-a

- `build.sh` sada automatski preuzima i exportuje Arm GNU Toolchain 14.2 (aarch64-none-elf) prvi put kad ga pokrenete, tako da ne morate ručno baratati cross-compilers.
- Exportujte `DEBUG=1` pre pokretanja `build.sh` da kompajlirate payloads sa verbose serial prints, što uveliko pomaže kada radite blind-patching EL3 code paths.
- Uspešni build-i generišu i `lk.patched` i `<device>-fenrir.bin`; ovaj drugi već ima payload injektovan i upravo njega treba flash/boot-test-ovati.

## Runtime payload capabilities (EL3)

Patchovani bl2_ext payload može:
- Registruje prilagođene fastboot komande
- Kontrolisati/override-ovati boot mode
- Dinamički pozivati ugrađene bootloader funkcije u runtime-u
- Spoof-ovati “lock state” kao locked dok je zapravo unlocked kako biste prošli strože integrity check-ove (u nekim okruženjima i dalje će biti potrebna podešavanja vbmeta/AVB)

Ograničenje: Trenutni PoCs navode da runtime modifikacija memorije može izazvati fault zbog MMU ograničenja; payloads generalno izbegavaju live memory writes dok se ovo ne reši.

## Obrasci payload staging-a (EL3)

Fenrir deli svoju instrumentaciju na tri compile-time faze: stage1 se izvršava pre `platform_init()`, stage2 pre nego što LK signalizira ulazak u fastboot, a stage3 se izvršava neposredno pre nego što LK učita Linux. Svaki device header u `payload/devices/` sadrži adrese za ove hook-ove plus fastboot helper simbole, pa sinhronizujte te offset-e sa vašim ciljanim build-om.

Stage2 je zgodno mesto za registraciju proizvoljnih `fastboot oem` naredbi:
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
Stage3 prikazuje kako privremeno promeniti atribute page-table-a kako bi se zakrpile nepromenljive stringove, kao što je Android-ovo upozorenje „Orange State“, bez potrebe za pristupom downstream kernelu:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Pošto stage1 pokreće pre platform bring-up, to je pravo mesto za pozivanje OEM power/reset primitives ili za umetanje dodatnog integrity logging-a pre nego što se verified boot chain razbije.

## Saveti za portovanje

- Reverse engineer device-specific bl2_ext da biste locirali verification policy logic (npr. sec_get_vfy_policy).
- Identifikujte policy return site ili decision branch i patčujte ga na “no verification required” (return 0 / unconditional allow).
- Držite offsets potpuno device- i firmware-specific; ne reuse-ujte adrese između varijanti.
- Validirajte prvo na sacrificial unit. Pripremite recovery plan (npr. EDL/BootROM loader/SoC-specific download mode) pre nego što flash-ujete.
- Uređaji koji koriste lk2 secondary bootloader ili prijavljuju “img_auth_required = 0” za bl2_ext čak i dok su locked treba da se tretiraju kao vulnerable copies ove klase buga; Vivo X80 Pro je već primećen kako preskače verification uprkos prijavljenom lock state-u.
- Uporedite expdb logs iz locked i unlocked stanja — ako certificate timing skoči sa 0 ms na nenultu vrednost nakon što ponovo relock-ujete, verovatno ste patčovali pravi decision point, ali i dalje morate ojačati lock-state spoofing da sakrijete modifikaciju.

## Bezbednosni uticaj

- EL3 code execution posle Preloader-a i potpuni chain-of-trust collapse za ostatak boot puta.
- Mogućnost boot-ovanja unsigned TEE/GZ/LK/Kernel, zaobilaženje secure/verified boot očekivanja i omogućavanje persistent compromise.

## Napomene o uređajima

- Potvrđeno podržan: Nothing Phone (2a) (Pacman)
- Poznato radi (nepotpuna podrška): CMF Phone 1 (Tetris)
- Primećeno: izveštaji govore da Vivo X80 Pro nije verifikovao bl2_ext čak i kada je bio locked
- Izveštaji iz industrije ističu dodatne lk2-based vendore koji isporučuju istu logičku manu, pa očekujte dalje preklapanje kroz MTK izdanja 2024–2025.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
