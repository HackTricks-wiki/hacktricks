# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica dokumentuje praktičan secure-boot break na više MediaTek platformi iskorišćavanjem praznine u verifikaciji kada je konfiguracija bootloadera uređaja (seccfg) postavljena na "unlocked". Propust dozvoljava pokretanje izmenjenog bl2_ext na ARM EL3 koji onemogućava verifikaciju potpisa nižih komponenti, rušeći lanac poverenja i omogućavajući učitavanje proizvoljnih unsigned TEE/GZ/LK/Kernel.

> Upozorenje: Patchovanje u ranoj fazi boot-a može trajno brick-ovati uređaje ako su offseti pogrešni. Uvek sačuvajte potpune dump-ove i pouzdan put oporavka.

## Pogođeni boot tok (MediaTek)

- Normalan tok: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ranljiv tok: Kada je seccfg postavljen na unlocked, Preloader može preskočiti verifikaciju bl2_ext. Preloader i dalje skače u bl2_ext na EL3, tako da izmišljeni bl2_ext može nakon toga učitati neverifikovane komponente.

Ključna granica poverenja:
- bl2_ext se izvršava na EL3 i odgovoran je za verifikaciju TEE, GenieZone, LK/AEE i kernela. Ako bl2_ext sam nije autentifikovan, ostatak lanca se trivijalno zaobilazi.

## Osnovni uzrok

Na pogođenim uređajima, Preloader ne primenjuje autentifikaciju particije bl2_ext kada seccfg pokazuje "unlocked" stanje. To omogućava flashovanje bl2_ext koji kontroliše napadač i koji se izvršava na EL3.

Unutar bl2_ext, funkcija politike verifikacije može se zakrpiti tako da bezuslovno prijavi da verifikacija nije potrebna. Minimalna konceptualna zakrpa je:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Sa ovom izmenom, sve naredne slike (TEE, GZ, LK/AEE, Kernel) se prihvataju bez kriptografskih provera kada ih učita izmenjeni bl2_ext koji radi na EL3.

## Kako izvršiti triage cilja (expdb logs)

Izvezite/ispitajte boot logove (npr. expdb) oko učitavanja bl2_ext. Ako je img_auth_required = 0 i certificate verification time is ~0 ms, sprovođenje je verovatno isključeno i uređaj je exploitable.

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Napomena: Navodno neki uređaji preskaču verifikaciju bl2_ext čak i sa locked bootloader-om, što pojačava uticaj.

## Praktičan tok iskorišćavanja (Fenrir PoC)

Fenrir je referentni exploit/patching toolkit za ovu klasu problema. Podržava Nothing Phone (2a) (Pacman) i poznato radi (delimično podržano) na CMF Phone 1 (Tetris). Portovanje na druge modele zahteva reverse engineering uređaja-specifičnog bl2_ext.

Pregled procesa:
- Preuzmite bootloader image uređaja za ciljani codename i smestite ga kao bin/<device>.bin
- Sastavite patched image koji onemogućava bl2_ext verification policy
- Flash-ujte dobijeni payload na uređaj (helper script pretpostavlja fastboot)

Komande:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
Ako fastboot nije dostupan, morate koristiti odgovarajući alternativni flashing metod za vašu platformu.

## Mogućnosti runtime payload-a (EL3)

Ispravljeni bl2_ext payload može:
- Registruje prilagođene fastboot komande
- Kontroliše/override-uje boot mode
- Dinamički poziva ugrađene bootloader funkcije u runtime-u
- Spoof-uje “lock state” kao locked dok je zapravo unlocked, kako bi prošao jače provere integriteta (u nekim okruženjima i dalje mogu biti potrebne prilagodbe vbmeta/AVB)

Ograničenje: Trenutni PoC-ovi navode da modifikacija runtime memorije može izazvati fault zbog MMU ograničenja; payload-i uglavnom izbegavaju live zapise u memoriju dok se ovo ne reši.

## Saveti za portovanje

- Reverse engineer device-specific bl2_ext da pronađete logiku verifikacione politike (npr. sec_get_vfy_policy).
- Identifikujte mesto povratka politike ili granu odluke i ispravite je na “no verification required” (return 0 / unconditional allow).
- Održavajte offset-e potpuno specifičnim za uređaj i firmware; ne ponovo koristite adrese između varijanti.
- Validirajte prvo na žrtvenom uređaju. Pripremite plan oporavka (npr. EDL/BootROM loader/SoC-specific download mode) pre nego što flash-ujete.

## Uticaj na bezbednost

- Izvršavanje EL3 koda nakon Preloader-a i potpuni kolaps chain-of-trust za ostatak boot puta.
- Mogućnost boot-ovanja unsigned TEE/GZ/LK/Kernel, zaobilaženje secure/verified boot očekivanja i omogućavanje persistentnog kompromitovanja.

## Ideje za detekciju i hardening

- Osigurajte da Preloader verifikuje bl2_ext bez obzira na seccfg stanje.
- Sprovodite rezultate autentifikacije i prikupljajte audit dokaze (timings > 0 ms, striktne greške pri neusklađenosti).
- Lock-state spoofing treba učiniti neefikasnim za attestation (vežite lock state za AVB/vbmeta verifikacione odluke i fuse-backed stanje).

## Napomene o uređajima

- Potvrđeno podržano: Nothing Phone (2a) (Pacman)
- Poznato da radi (nepotpuna podrška): CMF Phone 1 (Tetris)
- Primećeno: Navodno Vivo X80 Pro nije verifikovao bl2_ext čak i kada je bio locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
