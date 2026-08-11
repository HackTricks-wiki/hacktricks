# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

Wanneer ’n gemagtigde assessering swak of ontbrekende firmware-signatuurverifikasie aantoon, kan ’n gewysigde firmwarebeeld die integriteitsimpak demonstreer. Die volgende lab-werkvloei voeg ’n bind shell by terwyl die oorspronklike onttrekkings-, emulasie- en herverpakkingsstappe behou word.<sup>[[2]](#references)[[3]](#references)</sup>

1. Die firmware kan met firmware-mod-kit (FMK) onttrek word.
2. Die teikenfirmware se argitektuur en endianness moet geïdentifiseer word.
3. ’n Cross compiler kan met Buildroot of ander geskikte metodes vir die omgewing gebou word.
4. Die backdoor kan met die cross compiler gebou word.
5. Die backdoor kan na die onttrekte firmware se /usr/bin-gids gekopieer word.
6. Die toepaslike QEMU-binêre lêer kan na die onttrekte firmware se rootfs gekopieer word.
7. Die backdoor kan met chroot en QEMU geëmuleer word.
8. Die backdoor kan via netcat verkry word.
9. Die QEMU-binêre lêer moet uit die onttrekte firmware se rootfs verwyder word.
10. Die gewysigde firmware kan met FMK herverpak word.
11. Die firmware met die backdoor kan getoets word deur dit met firmware analysis toolkit (FAT) te emuleer en met netcat aan die teiken se backdoor-IP en -poort te koppel.

As ’n root shell reeds deur dinamiese ontleding, bootloader-manipulasie of hardware security testing verkry is, kan voorafgecompileerde toetsbinêre lêers soos implants of reverse shells uitgevoer word. Metasploit se `msfvenom` kan ’n argitektuurspesifieke payload vir hierdie valideringswerkvloei genereer:<sup>[[4]](#references)</sup>

1. Die teikenfirmware se argitektuur en endianness moet geïdentifiseer word.
2. Msfvenom kan gebruik word om die teiken-payload, aanvaller-gasheer-IP, luisterpoortnommer, lêertipe, argitektuur, platform en uitvoerlêer te spesifiseer.
3. Die payload kan na die gekompromitteerde toestel oorgedra word en daar kan verseker word dat dit uitvoertoestemmings het.
4. Metasploit kan voorberei word om inkomende versoeke te hanteer deur msfconsole te begin en die instellings volgens die payload te konfigureer.
5. Die meterpreter reverse shell kan op die gekompromitteerde toestel uitgevoer word.

## Unauthenticated transport bridges to privileged update protocols

’n Algemene ontwerpfout in ingebedde stelsels is om die **same internal command protocol over several transports** bloot te stel, maar authentication slegs op een daarvan af te dwing. USB kan byvoorbeeld challenge-response vereis, terwyl BLE bloot ongeauthentiseerde **GATT writes** na dieselfde bevoorregte firmware-opdateringshanteerder deurstuur.<sup>[[1]](#references)</sup>

Tipiese offensive workflow:

1. Enumereer die BLE GATT-databasis en identifiseer skryfbare characteristics wat deur die amptelike mobiele toepassing gebruik word.
2. Snuffel toepassingverkeer af en soek na **magic bytes / opcodes** wat met die bedrade protokol ooreenstem.
3. Herhaal bevoorregte opdragte oor BLE **without pairing** en verifieer of sensitiewe bewerkings steeds werk.
4. Indien firmware-upgrade-, config write-, debug- of factory-test-opcodes bereikbaar is, behandel BLE as ’n **radio-reachable admin port**.

Vinnige kontroles:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Dinge om tydens reversing te verifieer:

- Vereis BLE **pairing/bonding** of slegs ’n gewone verbinding?
- Word alle transports na dieselfde interne dispatcher table gerouteer?
- Word bevoorregte opcodes verskillend op USB / BLE / UART / Wi-Fi gefiltreer?
- Kan die mobiele app firmware update-, recovery- of diagnostic handlers op afstand aktiveer?

## Firmware containers wat slegs ’n checksum gebruik, is steeds firmware wat deur ’n aanvaller beheer word

’n Firmware container wat slegs deur ’n **unkeyed checksum** (CRC32, SHA-256, MD5, ens.) beskerm word, bied korrupsieopsporing, **nie egtheid nie**. As die aanvaller die update routine kan bereik, kan hulle die image patch, die checksum herbereken en arbitrêre code flash.<sup>[[1]](#references)</sup>

Waarskuwingstekens tydens RE:

- Update code valideer slegs ’n trailing checksum blob soos `CHK2`, `CRC` of `SHA256`.
- Geen signature verification of secure-boot root of trust is teenwoordig nie.
- Geen device-bound MAC / HMAC / authenticated encryption word gebruik nie.
- Recovery mode aanvaar dieselfde unauthenticated image format.

Praktiese validation flow:

1. Extract die firmware container en identifiseer bootloader, main firmware en integrity metadata.
2. Modify ’n onskadelike string of banner in die image.
3. Recompute die checksum presies soos die updater dit verwag.
4. Reflash die image deur die normale update path.
5. Bevestig die verandering tydens boot om arbitrêre firmware replacement te bewys.

As dit oor ’n remote bereikbaar transport soos BLE/Wi-Fi werk, is die bug effektief **unauthenticated OTA firmware replacement**.

## Om ’n trusted USB peripheral via firmware reflashing in BadUSB te verander

Wanneer die target device reeds deur die host oor USB vertrou word, hoef malicious firmware moontlik nie ’n volledige nuwe USB stack te implementeer nie. ’n Baie makliker pivot is dikwels om **bestaande HID support te hergebruik**.<sup>[[1]](#references)</sup>

Nuttige patroon:

1. Kontroleer of die device reeds as ’n **HID Consumer Control** / media / vendor HID interface enumereer.
2. Locate die bestaande **HID report descriptor** in firmware.
3. Append of replace descriptor entries sodat die device ook **keyboard** capability adverteer.
4. Hergebruik bestaande firmware routines wat reeds HID reports stuur in plaas daarvan om ’n nuwe transport implementation te skryf.
5. Inject key press + key release reports om commands op die host te tik.

Dit verander firmware compromise in **host compromise**, omdat die PC die reflashed peripheral as ’n legitimate keyboard sal vertrou.

### Minimale assessment checklist

- Toon `dmesg`, Device Manager of USB descriptors ’n bestaande HID interface?
- Is daar ekstra ruimte naby die report descriptor of ’n relocatable descriptor table?
- Kan bestaande media-control send routines vir keyboard reports hergebruik word?
- Aanvaar die host die nuwe keyboard interface outomaties ná reflashing?

## Betroubare payload execution binne RTOS firmware

In plaas daarvan om fragile trampolines in willekeurige code paths in te voeg, soek na **bestaande RTOS tasks** wat ongebruik of min impak het tydens normale werking.<sup>[[1]](#references)</sup>

Waarom dit nuttig is:

- Die scheduler begin jou payload natuurlik tydens boot.
- Jy vermy die korrupsie van kritieke control flow.
- Delayed payloads is minder geneig om watchdog resets te veroorsaak as wanneer dit binne ’n latency-sensitive USB/network handler uitgevoer word.

Goeie targets is diagnostic-, factory-test-, telemetry- of coprocessor service tasks wat tydens normale gebruik dormant voorkom.

## Vinnige exploit-iterasie: hergebruik onskadelike protocol handlers

Sodra firmware patching moontlik is, is ’n kompakte manier om RE te versnel om ’n harmless command handler (byvoorbeeld ’n **echo/debug opcode**) met custom **memory read / write / execute** primitives te oorskryf. Dit vermy volledige reflashing vir elke eksperiment en is veral nuttig wanneer die device die modified handler oor ’n vinnige wired transport ondersteun.<sup>[[1]](#references)</sup>

Gebruik dit om:

- Scatter-loaded memory maps te verifieer
- Heap/task state live te inspekteer
- Klein payloads te toets voordat dit in flash gebrand word
- Function pointers, strings en descriptor tables veilig te herstel

## References

- [1] [Pwnd Blaster: Hacking jou PC met jou speaker sonder om ooit daaraan te raak](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Hoe om `msfvenom` te gebruik](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
