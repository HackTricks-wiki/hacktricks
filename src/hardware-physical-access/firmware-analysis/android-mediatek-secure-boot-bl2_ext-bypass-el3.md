# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica dokumentuje praktičan prekid secure-boot-a na više MediaTek platformi zloupotrebom praznine u verifikaciji kada je konfiguracija bootloader-a uređaja (seccfg) podešena na "unlocked". Propust omogućava pokretanje ispravljenog bl2_ext na ARM EL3 koji onemogućava verifikaciju potpisa nizvodno, urušavajući lanac poverenja i omogućavajući učitavanje proizvoljnog nepotpisanog TEE/GZ/LK/Kernel-a.

> Upozorenje: Patch-ovanje u ranoj fazi boot‑a može trajno oštetiti uređaje ako su offseti pogrešni. Uvek čuvajte potpune dump-ove i pouzdanu putanju za recovery.

## Pogođeni boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Ključna granica poverenja:
- bl2_ext izvršava kod na EL3 i odgovoran je za verifikaciju TEE, GenieZone, LK/AEE i kernela. Ako bl2_ext sam nije autentifikovan, ostatak lanca se lako zaobilazi.

## Uzrok

Na pogođenim uređajima, Preloader ne primenjuje autentikaciju particije bl2_ext kada seccfg ukazuje na stanje "unlocked". To omogućava flashovanje bl2_ext koji kontroliše napadač i koji radi na EL3.

Unutar bl2_ext, funkcija politike verifikacije može se patch-ovati da bezuslovno prijavi da verifikacija nije potrebna. Minimalni konceptualni patch je:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Sa ovom izmenom, sve naredne slike (TEE, GZ, LK/AEE, Kernel) se prihvataju bez kriptografskih provera kada ih učitava izmenjeni bl2_ext koji radi na EL3.

## Kako triage cilj (expdb logs)

Dump/inspect boot logs (e.g., expdb) oko učitavanja bl2_ext. Ako je img_auth_required = 0 i vreme verifikacije sertifikata ~0 ms, enforcement je verovatno isključen i uređaj je exploitable.

Primer isečka loga:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Napomena: Neki uređaji navodno preskaču bl2_ext verification čak i sa locked bootloader-om, što pogoršava uticaj.

## Praktični tok eksploatacije (Fenrir PoC)

Fenrir je referentni exploit/patching toolkit za ovu klasu problema. Podržava Nothing Phone (2a) (Pacman) i poznato radi (nepotpuno podržano) na CMF Phone 1 (Tetris). Portiranje na druge modele zahteva reverse engineering uređajno-specifičnog bl2_ext.

High-level process:
- Preuzmite bootloader image uređaja za ciljnu kodnu oznaku i postavite ga kao bin/<device>.bin
- Izgradite patched image koja onemogućava politiku verifikacije bl2_ext
- Flash-ujte rezultirajući payload na uređaj (fastboot se pretpostavlja u helper skripti)

Komande:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## Runtime payload capabilities (EL3)

A patched bl2_ext payload can:
- Registruje prilagođene fastboot komande
- Kontroliše/prepisuje boot mode
- Dinamički poziva ugrađene bootloader funkcije tokom izvršavanja
- Lažira “lock state” kao locked dok je zapravo unlocked da bi prošao strože provere integriteta (u nekim okruženjima i dalje mogu biti potrebne vbmeta/AVB prilagodbe)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Porting tips

- Reverse engineer the device-specific bl2_ext to locate verification policy logic (e.g., sec_get_vfy_policy).
- Identify the policy return site or decision branch and patch it to “no verification required” (return 0 / unconditional allow).
- Keep offsets fully device- and firmware-specific; do not reuse addresses between variants.
- Validate on a sacrificial unit first. Prepare a recovery plan (e.g., EDL/BootROM loader/SoC-specific download mode) before you flash.

## Security impact

- EL3 code execution after Preloader and full chain-of-trust collapse for the rest of the boot path.
- Ability to boot unsigned TEE/GZ/LK/Kernel, bypassing secure/verified boot expectations and enabling persistent compromise.

## Detection and hardening ideas

- Ensure Preloader verifies bl2_ext regardless of seccfg state.
- Enforce authentication results and gather audit evidence (timings > 0 ms, strict errors on mismatch).
- Lock-state spoofing should be made ineffective for attestation (tie lock state to AVB/vbmeta verification decisions and fuse-backed state).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
