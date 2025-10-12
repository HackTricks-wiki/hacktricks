# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy dokumenteer 'n praktiese secure-boot break op verskeie MediaTek-platforms deur 'n verifikasiegaping te misbruik wanneer die toestel se bootloader-konfigurasie (seccfg) op "unlocked" gestel is. Die fout laat 'n gepatchede bl2_ext op ARM EL3 toe om downstream-handtekeningsverifikasie uit te skakel, wat die vertrouensketting laat inklap en willekeurige ongetekende TEE/GZ/LK/Kernel-lading moontlik maak.

> Waarskuwing: Early-boot patching kan toestelle permanent brick maak as offsets verkeerd is. Always keep full dumps and a reliable recovery path.

## Geaffekteerde opstartvloei (MediaTek)

- Normale pad: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Kwetsbare pad: Wanneer seccfg op "unlocked" gestel is, mag Preloader die verifikasie van bl2_ext oorslaan. Preloader spring steeds na binne in bl2_ext by EL3, dus kan 'n crafted bl2_ext daarna unverified komponente laai.

Belangrike vertrouensgrens:
- bl2_ext voer uit by EL3 en is verantwoordelik vir die verifikasie van TEE, GenieZone, LK/AEE en die kernel. As bl2_ext self nie geauthentiseer is nie, word die res van die ketting triviaal omseil.

## Hoofoorsaak

Op geaffekteerde toestelle dwing die Preloader nie die authentication van die bl2_ext partition af wanneer seccfg 'n "unlocked" toestand aandui nie. Dit laat toe om 'n attacker-controlled bl2_ext te flash wat by EL3 loop.

Binne bl2_ext kan die verification policy-funksie gepatch word om onvoorwaardelik te rapporteer dat verifikasie nie nodig is nie. 'n Minimale konseptuele patch is:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Met hierdie verandering word alle daaropvolgende beelde (TEE, GZ, LK/AEE, Kernel) aanvaar sonder kriptografiese kontroles wanneer hulle deur die gepatchte bl2_ext wat by EL3 loop gelaai word.

## How to triage a target (expdb logs)

Dump/inspect opstartlogs (bv. expdb) rondom die bl2_ext-laai. As img_auth_required = 0 en certificate verification time is ~0 ms, is afdwinging waarskynlik af en die toestel is uitbuitbaar.

Voorbeeld log-uittreksel:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Let wel: Sommige toestelle slaan na bewering die bl2_ext verifikasie oor, selfs met 'n gegrendelde bootloader, wat die impak vererger.

## Praktiese uitbuiting-werkstroom (Fenrir PoC)

Fenrir is 'n verwysings exploit/patching toolkit vir hierdie klas van probleem. Dit ondersteun Nothing Phone (2a) (Pacman) en is bekend dat dit werk (onvolledig ondersteun) op CMF Phone 1 (Tetris). Porting na ander modelle vereis reverse engineering van die toestel-spesifieke bl2_ext.

Hoëvlak proses:
- Kry die toestel se bootloader-beeld vir jou teiken-kodenaam en plaas dit as bin/<device>.bin
- Bou 'n gepatchte beeld wat die bl2_ext verifikasiebeleid deaktiveer
- Flits die resulterende payload na die toestel (fastboot word deur die helper-skrip veronderstel)

Opdragte:
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
- Register custom fastboot commands
- Control/override boot mode
- Dynamically call built‑in bootloader functions at runtime
- Spoof “lock state” as locked while actually unlocked to pass stronger integrity checks (some environments may still require vbmeta/AVB adjustments)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Porting tips

- Reverse-engineer die device-spesifieke bl2_ext om die verifikasiebeleid-logika te lokaliseer (bv., sec_get_vfy_policy).
- Identifiseer die beleid se return-ligging of besluittak en patch dit na “no verification required” (return 0 / unconditional allow).
- Hou offsets volledig device- en firmware-spesifiek; hergebruik nie adresse tussen variante nie.
- Valideer eers op 'n offer-eenheid. Berei 'n herstelplan voor (bv., EDL/BootROM loader/SoC-specific download mode) voordat jy flash.

## Security impact

- EL3 code execution after Preloader and full chain-of-trust collapse for the rest of the boot path.
- Vermoë om unsigned TEE/GZ/LK/Kernel te boot, wat secure/verified boot-verwagtinge omseil en permanente kompromittering moontlik maak.

## Detection and hardening ideas

- Verseker dat Preloader bl2_ext verifieer ongeag seccfg-toestand.
- Handhaaf authentication resultate en versamel ouditbewyse (timings > 0 ms, strict errors on mismatch).
- Lock-state spoofing moet ondoeltreffend gemaak word vir attestation (tie lock state to AVB/vbmeta verification decisions and fuse-backed state).

## Device notes

- Bevestigde ondersteuning: Nothing Phone (2a) (Pacman)
- Bekend werkend (onvolledige ondersteuning): CMF Phone 1 (Tetris)
- Waargenome: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
