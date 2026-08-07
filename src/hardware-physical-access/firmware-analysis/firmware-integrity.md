# Firmware-integriteit

{{#include ../../banners/hacktricks-training.md}}

Die **custom firmware en/of compiled binaries kan opgelaai word om integriteits- of signature-verification-foute uit te buit**. Die volgende stappe kan vir backdoor bind shell-kompilering gevolg word:

1. Die firmware kan met firmware-mod-kit (FMK) onttrek word.
2. Die teikenfirmware se argitektuur en endianness moet geïdentifiseer word.
3. ’n Cross compiler kan met Buildroot of ander geskikte metodes vir die omgewing gebou word.
4. Die backdoor kan met die cross compiler gebou word.
5. Die backdoor kan na die onttrekte firmware se /usr/bin-gids gekopieer word.
6. Die toepaslike QEMU-binary kan na die onttrekte firmware se rootfs gekopieer word.
7. Die backdoor kan met chroot en QEMU geëmuleer word.
8. Die backdoor kan via netcat bereik word.
9. Die QEMU-binary moet uit die onttrekte firmware se rootfs verwyder word.
10. Die gewysigde firmware kan met FMK herverpak word.
11. Die backdoored firmware kan getoets word deur dit met firmware analysis toolkit (FAT) te emuleer en met netcat aan die teiken-backdoor se IP en poort te koppel.

Indien ’n root shell reeds deur dynamic analysis, bootloader manipulation of hardware security testing verkry is, kan voorafgecompileerde malicious binaries soos implants of reverse shells uitgevoer word. Geoutomatiseerde payload/implant-tools soos die Metasploit-framework en 'msfvenom' kan met die volgende stappe benut word:

1. Die teikenfirmware se argitektuur en endianness moet geïdentifiseer word.
2. Msfvenom kan gebruik word om die teiken-payload, attacker host-IP, listening port number, filetype, architecture, platform en die output file te spesifiseer.
3. Die payload kan na die gekompromitteerde toestel oorgedra word, en daar moet verseker word dat dit execution permissions het.
4. Metasploit kan voorberei word om incoming requests te hanteer deur msfconsole te begin en die settings volgens die payload te konfigureer.
5. Die meterpreter reverse shell kan op die gekompromitteerde toestel uitgevoer word.

## Ongemagtigde transport bridges na privileged update-protocols

’n Algemene embedded-ontwerpfout is om die **same internal command protocol oor verskeie transports bloot te stel**, maar authentication slegs op een daarvan af te dwing. USB kan byvoorbeeld challenge-response vereis, terwyl BLE bloot unauthenticated **GATT writes** na dieselfde privileged firmware-update-handler deurstuur.<sup>[[1]](#references)</sup>

Tipiese offensive workflow:

1. Enumerate die BLE GATT-databasis en identifiseer writable characteristics wat deur die amptelike mobile app gebruik word.
2. Sniff app-traffic en soek na **magic bytes / opcodes** wat met die wired protocol ooreenstem.
3. Replay privileged commands oor BLE **without pairing** en verifieer of sensitiewe operasies steeds werk.
4. Indien firmware-upgrade-, config-write-, debug- of factory-test-opcodes bereikbaar is, behandel BLE as ’n **radio-reachable admin port**.

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

- Vereis BLE **pairing/bonding**, of slegs ’n gewone verbinding?
- Word alle transports na dieselfde interne dispatcher-tabel herlei?
- Word bevoorregte opcodes verskillend op USB / BLE / UART / Wi-Fi gefiltreer?
- Kan die mobiele app firmware update-, recovery- of diagnostic handlers op afstand aktiveer?

## Firmware-containers wat slegs ’n checksum gebruik, is steeds firmware wat deur die aanvaller beheer word

’n Firmware-container wat slegs deur ’n **unkeyed checksum** (CRC32, SHA-256, MD5, ens.) beskerm word, bied korrupsie-opsporing, **nie egtheid nie**. As die aanvaller die update-roetine kan bereik, kan hulle die image patch, die checksum herbereken en arbitrêre code flash.<sup>[[1]](#references)</sup>

Rooi vlae tydens RE:

- Update-code valideer slegs ’n checksum blob aan die einde, soos `CHK2`, `CRC` of `SHA256`.
- Geen signature verification of secure-boot root of trust is teenwoordig nie.
- Geen device-bound MAC / HMAC / authenticated encryption word gebruik nie.
- Recovery mode aanvaar dieselfde unauthenticated image-formaat.

Praktiese valideringsvloei:

1. Ekstraheer die firmware-container en identifiseer bootloader, hoof-firmware en integrity metadata.
2. Wysig ’n onskadelike string of banner in die image.
3. Herbereken die checksum presies soos die updater dit verwag.
4. Flash die image weer deur die normale update-pad.
5. Bevestig die verandering tydens boot om arbitrêre firmware-vervanging te bewys.

As dit oor ’n op afstand bereikbare transport soos BLE/Wi-Fi werk, is die fout effektief **unauthenticated OTA firmware replacement**.

## Om ’n vertroude USB-peripheral in BadUSB te verander deur firmware te reflash

Wanneer die teikentoestel reeds deur die host oor USB vertrou word, hoef malicious firmware moontlik nie ’n volledige nuwe USB-stack te implementeer nie. ’n Baie makliker pivot is dikwels om bestaande HID-support te **hergebruik**.<sup>[[1]](#references)</sup>

Nuttige patroon:

1. Kontroleer of die toestel reeds as ’n **HID Consumer Control** / media- / vendor HID-interface enumereer.
2. Vind die bestaande **HID report descriptor** in firmware.
3. Voeg descriptor-inskrywings by of vervang dit sodat die toestel ook keyboard-vermoë adverteer.
4. Hergebruik bestaande firmware-roetines wat reeds HID reports stuur, eerder as om ’n nuwe transport-implementering te skryf.
5. Injecteer key press + key release reports om commands op die host te tik.

Dit verander firmware compromise in **host compromise**, omdat die PC die gereflashte peripheral as ’n legitieme keyboard sal vertrou.

### Minimum-assesseringskontrolelys

- Toon `dmesg`, Device Manager of USB descriptors ’n bestaande HID-interface?
- Is daar spasie naby die report descriptor of ’n relocatable descriptor-tabel?
- Kan bestaande media-control send-roetines vir keyboard reports hergebruik word?
- Aanvaar die host die nuwe keyboard-interface outomaties ná reflashing?

## Betroubare payload-uitvoering binne RTOS-firmware

In plaas daarvan om kwesbare trampolines in willekeurige code paths in te voeg, soek **bestaande RTOS-tasks** wat ongebruik of min impak het tydens normale werking.<sup>[[1]](#references)</sup>

Waarom dit nuttig is:

- Die scheduler begin jou payload natuurlik tydens boot.
- Jy vermy die korrupsie van kritieke control flow.
- Vertraagde payloads sal minder waarskynlik watchdog resets aktiveer as wanneer dit binne ’n latency-sensitive USB/network handler uitgevoer word.

Goeie teikens is diagnostic-, factory-test-, telemetry- of coprocessor service-tasks wat tydens normale gebruik dormant voorkom.

## Vinnige exploit-iterasie: herbenut onskadelike protocol handlers

Sodra firmware-patching moontlik is, is ’n kompakte manier om RE te versnel om ’n onskadelike command handler (byvoorbeeld ’n **echo/debug opcode**) met custom **memory read / write / execute** primitives te oorskryf. Dit vermy volledige reflashing vir elke eksperiment en is besonder nuttig wanneer die toestel die gewysigde handler oor ’n vinnige wired transport ondersteun.<sup>[[1]](#references)</sup>

Gebruik dit om:

- Scatter-loaded memory maps te verifieer
- Heap/task-state live te inspekteer
- Klein payloads te toets voordat dit in flash gebrand word
- Function pointers, strings en descriptor-tabelle veilig te herstel

## Verwysings

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
