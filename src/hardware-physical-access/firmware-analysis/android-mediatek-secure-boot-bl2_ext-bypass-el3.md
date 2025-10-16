# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy dokumenteer 'n praktiese secure-boot break op verskeie MediaTek-platforms deur 'n verifikasie-gaping te misbruik wanneer die toestel se bootloader-konfigurasie (seccfg) op "unlocked" is. Die fout laat toe dat 'n gepatchte bl2_ext by ARM EL3 uitgevoer word om downstream handtekeningverifikasie uit te skakel, die ketting van vertroue te breek en arbitrêre ongehandte TEE/GZ/LK/Kernel-ladings toe te laat.

> Waarskuwing: Vroeë-opstart patching kan toestelle permanent onbruikbaar maak as offsets verkeerd is. Hou altyd volledige dumps en 'n betroubare herstelpad.

## Affected boot flow (MediaTek)

- Normale pad: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Kwetsbare pad: Wanneer seccfg op unlocked gestel is, kan Preloader die verifikasie van bl2_ext oorslaan. Preloader spring steeds na bl2_ext by EL3, sodat 'n gemaakte bl2_ext daarna ongeverifieerde komponente kan laai.

Belangrike vertrouensgrens:
- bl2_ext voer by EL3 uit en is verantwoordelik vir die verifikasie van TEE, GenieZone, LK/AEE en die kernel. As bl2_ext self nie geauthentiseer is nie, kan die res van die ketting maklik oorgeslaan word.

## Root cause

Op aangetaste toestelle dwing die Preloader nie die authenticatie van die bl2_ext-partisie af wanneer seccfg 'n "unlocked" toestand aandui nie. Dit maak dit moontlik om 'n deur 'n aanvaller beheerde bl2_ext te flash wat by EL3 uitgevoer word.

Binne bl2_ext kan die verification policy-funksie gepatch word om onvoorwaardelik te rapporteer dat verifikasie nie vereis word nie. 'n Minimale konseptuele patch is:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Met hierdie verandering word alle daaropvolgende images (TEE, GZ, LK/AEE, Kernel) aanvaar sonder kriptografiese kontroles wanneer hulle deur die patched bl2_ext wat by EL3 loop, gelaai word.

## Hoe om 'n teiken te triageer (expdb logs)

Dump/inspect boot logs (bv. expdb) rondom die bl2_ext-laai. As img_auth_required = 0 en sertifikaatverifikasietyd ~0 ms is, is afdwinging waarskynlik afgeskakel en is die toestel uitbuitbaar.

Voorbeeld log-uittreksel:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Nota: Sommige toestelle blyk bl2_ext verification oor te slaan selfs met 'n locked bootloader, wat die impak vererger.

## Praktiese eksploitasie-werkstroom (Fenrir PoC)

Fenrir is 'n verwysings exploit/patching toolkit vir hierdie tipe probleem. Dit ondersteun Nothing Phone (2a) (Pacman) en is bekend om te werk (onvolledig ondersteun) op CMF Phone 1 (Tetris). Porting na ander modelle vereis reverse engineering van die device-specific bl2_ext.

Hoëvlak proses:
- Verkry die toestel bootloader image vir jou teiken codename en plaas dit as bin/<device>.bin
- Bou 'n gepatchede image wat die bl2_ext verification policy deaktiveer
- Flash die resulterende payload na die toestel (fastboot assumed by the helper script)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
As fastboot nie beskikbaar is nie, moet jy 'n geskikte alternatiewe flashing-metode vir jou platform gebruik.

## Runtime payload-vaardighede (EL3)

'n Gepatchede bl2_ext payload kan:
- Registreer pasgemaakte fastboot-opdragte
- Beheer/override boot-modus
- Dinamies ingeboude bootloader-funksies tydens runtime aanroep
- Spoof “lock state” as locked terwyl dit eintlik unlocked is om sterker integriteitskontroles te slaag (sommige omgewings mag steeds vbmeta/AVB-aanpassings vereis)

Beperking: Huidige PoCs merk op dat runtime-geheue-wysigings as gevolg van MMU-beperkings 'n fout kan veroorsaak; payloads vermy oor die algemeen live memory writes totdat dit opgelos is.

## Porting-wenke

- Reverse engineer die toestel-spesifieke bl2_ext om verifikasiebeleid-logika te lokaliseer (bv., sec_get_vfy_policy).
- Identifiseer die beleid-terugkeerplek of beslissingsvertakking en patch dit na “no verification required” (return 0 / unconditional allow).
- Hou offsets volledig toestel- en firmware-spesifiek; moenie adresse tussen variante hergebruik nie.
- Valideer eers op 'n offer-eenheid. Berei 'n herstelplan voor (bv., EDL/BootROM loader/SoC-spesifieke download mode) voordat jy flash.

## Sekuriteitsimpak

- EL3-kode-uitvoering ná die Preloader en volledige ketting-van-vertroue-instorting vir die res van die boot-pad.
- Vermoë om unsigned TEE/GZ/LK/Kernel te boot, deur secure/verified boot-verwachtinge te omseil en bestendige kompromittering moontlik te maak.

## Opsporing en verhardingsidees

- Verseker dat die Preloader bl2_ext verifieer ongeag die seccfg-toestand.
- Dwing authentication results af en versamel ouditbewyse (timings > 0 ms, streng foute by mismatch).
- Lock-state spoofing moet ondoeltreffend gemaak word vir attestasie (koppel lock state aan AVB/vbmeta-verifikasiebesluite en fuse-backed state).

## Toestelnotas

- Bevestig ondersteun: Nothing Phone (2a) (Pacman)
- Bekend werkend (onvolledige ondersteuning): CMF Phone 1 (Tetris)
- Waargeneem: Vivo X80 Pro het na berigte nie bl2_ext verifieer nie, selfs toe dit locked was

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
