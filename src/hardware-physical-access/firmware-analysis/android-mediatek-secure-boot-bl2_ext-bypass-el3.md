# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy dokumenteer 'n praktiese secure-boot-breek op verskeie MediaTek-platforms deur 'n verifikasie-gaping te misbruik wanneer die toestel se bootloader-konfigurasie (seccfg) op "unlocked" gestel is. Die fout maak dit moontlik om 'n gepatchte bl2_ext by ARM EL3 uit te voer om aflopende handtekeningverifikasie uit te skakel, wat die vertroueketting laat ineenstort en willekeurige ongetekende TEE/GZ/LK/Kernel-lading moontlik maak.

> Waarskuwing: Vroeë-boot-patching kan toestelle permanent brick as offsets verkeerd is. Hou altyd volledige dumps en 'n betroubare herstelpad.

## Geaffekteerde opstartvloei (MediaTek)

- Normale pad: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Kwetsbare pad: Wanneer seccfg op unlocked gestel is, kan Preloader verifiëring van bl2_ext oorslaan. Preloader spring steeds in bl2_ext by EL3, dus kan 'n vakkundig opgestelde bl2_ext daarna ongeverifieerde komponente laai.

Sleutel-vertrouesgrens:
- bl2_ext word by EL3 uitgevoer en is verantwoordelik vir die verifikasie van TEE, GenieZone, LK/AEE en die kernel. As bl2_ext self nie geauthentiseer is nie, word die res van die ketting eenvoudig omseil.

## Hoof oorsaak

Op geaffekteerde toestelle dwing die Preloader nie die autentisering van die bl2_ext-partisie af wanneer seccfg 'n "unlocked" toestand aandui nie. Dit laat toe om 'n deur 'n aanvaller beheerde bl2_ext te flash wat by EL3 uitgevoer word.

Binne bl2_ext kan die verifikasiebeleid-funksie gepatch word om onvoorwaardelik te rapporteer dat verifikasie nie benodig word nie. 'n Minimale konseptuele patch is:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Met hierdie verandering word alle daaropvolgende images (TEE, GZ, LK/AEE, Kernel) aanvaar sonder kriptografiese kontroles wanneer hulle deur die gepatchte bl2_ext wat op EL3 loop gelaai word.

## Hoe om 'n teiken te triageer (expdb logs)

Dump/inspect boot logs (e.g., expdb) rondom die bl2_ext load. As img_auth_required = 0 en certificate verification time is ~0 ms, is afdwinging waarskynlik af en kan die toestel uitgebuit word.

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Note: Sommige toestelle omseil na bewering bl2_ext verification selfs met 'n locked bootloader, wat die impak vererger.

Toestelle wat met die lk2 secondary bootloader gestuur word, is met dieselfde logiese gaping waargeneem, so haal expdb logs vir beide bl2_ext en lk2 partitions om te bevestig of enigeen van die paaie signatures afdwing voordat jy met porting begin.

## Praktiese uitbuiting-werkstroom (Fenrir PoC)

Fenrir is 'n reference exploit/patching toolkit vir hierdie tipe probleem. Dit ondersteun Nothing Phone (2a) (Pacman) en is bekend dat dit werk (onvolledig ondersteun) op CMF Phone 1 (Tetris). Porting na ander modelle vereis reverse engineering van die device-spesifieke bl2_ext.

Hoëvlak proses:
- Haal die device bootloader image vir jou teiken codename en plaas dit as `bin/<device>.bin`
- Bou 'n patched image wat die bl2_ext verification policy uitskakel
- Flash die resulterende payload na die device (fastboot word aanvaar deur die helper script)

Opdragte:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
As fastboot nie beskikbaar is nie, moet jy 'n geskikte alternatiewe flashing-methode vir jou platform gebruik.

### Build automation & payload debugging

- `build.sh` laai nou outomaties af en exporteer die Arm GNU Toolchain 14.2 (aarch64-none-elf) die eerste keer wat jy dit hardloop, sodat jy nie handmatig met cross-compilers hoef te jongleer nie.
- Exporteer `DEBUG=1` voordat jy `build.sh` aanroep om payloads met uitgebreide seriële prints saam te stel, wat baie help wanneer jy blind-patch EL3-kodepade.
- Suksesvolle builds lewer beide `lk.patched` en `<device>-fenrir.bin`; laasgenoemde het reeds die payload ingespuit en is wat jy moet flash/boot-test.

## Runtime payload capabilities (EL3)

'n Gepatchede bl2_ext payload kan:
- Register custom fastboot commands
- Beheer/of oorskryf die boot-modus
- Roep dinamies ingeboude bootloader-funksies tydens runtime aan
- Spoof “lock state” as locked terwyl dit eintlik unlocked is om sterker integriteitskontroles te slaag (sommige omgewings mag steeds vbmeta/AVB-aanpassings vereis)

Beperking: Huidige PoCs noem dat runtime-geheuewysiging moontlik fault weens MMU-beperkings; payloads vermy oor die algemeen regstreekse geheue-skrifte totdat dit opgelos is.

## Payload staging patterns (EL3)

Fenrir verdeel sy instrumentasie in drie compile-time stages: stage1 hardloop voor `platform_init()`, stage2 hardloop voordat LK fastboot-ingang sein, en stage3 voer onmiddellik uit voordat LK Linux laai. Elke device header onder `payload/devices/` verskaf die adresse vir hierdie hooks plus fastboot helper symbols, so hou daardie offsets gesinkroniseer met jou target build.

Stage2 is 'n gerieflike plek om arbitrêre `fastboot oem` verbs te registreer:
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
Stage3 demonstreer hoe om bladsy-tabel-attribuutte tydelik om te skakel om onveranderlike stringe soos Android se “Orange State” waarskuwing te patch sonder om downstream kernel access nodig te hê:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Omdat stage1 afgevuur word voordat die platform opgestel word, is dit die regte plek om na OEM power/reset primitives te roep of om addisionele integriteitslogering in te voeg voordat die verified boot chain afgebreek word.

## Porting wenke

- Reverse engineer die device-specific bl2_ext om die verification policy logic te lokaliseren (e.g., sec_get_vfy_policy).
- Identifiseer die policy return site of decision branch en patch dit na “no verification required” (return 0 / unconditional allow).
- Hou offsets volledig device- en firmware-spesifiek; moenie adresse tussen variante hergebruik nie.
- Valideer eers op ’n opofferings-eenheid. Berei ’n recovery plan voor (e.g., EDL/BootROM loader/SoC-specific download mode) voordat jy flash.
- Toestelle wat die lk2 secondary bootloader gebruik of “img_auth_required = 0” vir bl2_ext rapporteer selfs terwyl hulle gesluit is, moet beskou word as kwesbare kopieë van hierdie foutklas; Vivo X80 Pro is reeds waargeneem wat verifikasie oorslaan ondanks ’n gerapporteerde slotstaat.
- Vergelyk expdb logs van beide geslote en ontslote state—as certificate timing van 0 ms na ’n nie‑nul‑waarde spring sodra jy weer sluit, het jy waarskynlik die regte decision point gepatch maar moet steeds die lock-state spoofing verhard om die wysiging te verberg.

## Sekuriteitsimpak

- EL3 code execution ná Preloader en volledige chain-of-trust ineenstorting vir die res van die boot path.
- Vermoë om unsigned TEE/GZ/LK/Kernel te boot, wat secure/verified boot‑verwagtinge omseil en persistent compromise moontlik maak.

## Toestelnotas

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- Industry coverage highlights additional lk2-based vendors shipping the same logic flaw, so expect further overlap across 2024–2025 MTK releases.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
