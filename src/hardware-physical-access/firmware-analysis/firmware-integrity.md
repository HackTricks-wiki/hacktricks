# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

Die **custom firmware en/of compiled binaries can be uploaded to exploit integrity or signature verification flaws**. Die volgende stappe kan gevolg word vir backdoor bind shell compilation:

1. Die firmware can be extracted using firmware-mod-kit (FMK).
2. Die target firmware architecture and endianness should be identified.
3. A cross compiler can be built using Buildroot or other suitable methods for the environment.
4. Die backdoor can be built using the cross compiler.
5. Die backdoor can be copied to the extracted firmware /usr/bin directory.
6. Die appropriate QEMU binary can be copied to the extracted firmware rootfs.
7. Die backdoor can be emulated using chroot and QEMU.
8. Die backdoor can be accessed via netcat.
9. Die QEMU binary should be removed from the extracted firmware rootfs.
10. Die modified firmware can be repackaged using FMK.
11. Die backdoored firmware can be tested by emulating it with firmware analysis toolkit (FAT) and connecting to the target backdoor IP and port using netcat.

As a root shell alreeds obtained through dynamic analysis, bootloader manipulation, or hardware security testing, precompiled malicious binaries such as implants or reverse shells can be executed. Automated payload/implant tools like the Metasploit framework and 'msfvenom' can be leveraged using the following steps:

1. Die target firmware architecture and endianness should be identified.
2. Msfvenom can be used to specify the target payload, attacker host IP, listening port number, filetype, architecture, platform, and the output file.
3. Die payload can be transferred to the compromised device and ensured that it has execution permissions.
4. Metasploit can be prepared to handle incoming requests by starting msfconsole and configuring the settings according to the payload.
5. Die meterpreter reverse shell can be executed on the compromised device.

## Unauthenticated transport bridges to privileged update protocols

A common embedded design mistake is exposing the **same internal command protocol over several transports** but enforcing authentication on only one of them. For example, USB may require challenge-response while BLE simply forwards unauthenticated **GATT writes** into the same privileged firmware-update handler.

Typical offensive workflow:

1. Enumereer die BLE GATT database and identify writable characteristics used by the official mobile app.
2. Sniff app traffic and look for **magic bytes / opcodes** that match the wired protocol.
3. Replay privileged commands over BLE **without pairing** and verify whether sensitive operations still work.
4. If firmware upgrade, config write, debug, or factory-test opcodes are reachable, treat BLE as a **radio-reachable admin port**.

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Dinge om te verifieer tydens reversing:

- Vereis BLE **pairing/bonding** of net ’n gewone connection?
- Word alle transports na dieselfde interne dispatcher table gerouteer?
- Word bevoorregte opcodes anders gefilter op USB / BLE / UART / Wi-Fi?
- Kan die mobile app firmware update, recovery, of diagnostic handlers op afstand aktiveer?

## Checksum-only firmware containers is steeds attacker-controlled firmware

’n Firmware container wat net deur ’n **unkeyed checksum** (CRC32, SHA-256, MD5, ens.) beskerm word, bied korrupsie-detectie, **nie authenticity** nie. As die attacker die update routine kan bereik, kan hulle die image patch, die checksum herbereken, en arbitrêre code flash.

Red flags tydens RE:

- Update code valideer net ’n trailing checksum blob soos `CHK2`, `CRC`, of `SHA256`.
- Geen signature verification of secure-boot root of trust is teenwoordig nie.
- Geen device-bound MAC / HMAC / authenticated encryption word gebruik nie.
- Recovery mode aanvaar dieselfde unauthenticated image format.

Praktiese validation flow:

1. Extract die firmware container en identifiseer bootloader, main firmware, en integrity metadata.
2. Modifiseer ’n harmless string of banner in die image.
3. Herbereken die checksum presies soos die updater verwag.
4. Reflash die image deur die normale update path.
5. Bevestig die verandering by boot om arbitrêre firmware replacement te bewys.

As dit oor ’n remotely reachable transport soos BLE/Wi-Fi werk, is die bug effektief **unauthenticated OTA firmware replacement**.

## Om ’n trusted USB peripheral in BadUSB te verander via firmware reflashing

Wanneer die teiken device reeds deur die host oor USB vertrou word, hoef malicious firmware dalk nie ’n nuwe volle USB stack te implementeer nie. ’n Baie makliker pivot is dikwels om **existing HID support** te hergebruik.

Nuttige patroon:

1. Kontroleer of die device reeds as ’n **HID Consumer Control** / media / vendor HID interface enumereer.
2. Vind die bestaande **HID report descriptor** in firmware.
3. Voeg descriptor entries by of vervang dit sodat die device ook **keyboard** capability adverteer.
4. Hergebruik bestaande firmware routines wat reeds HID reports stuur in plaas daarvan om ’n nuwe transport implementation te skryf.
5. Inject key press + key release reports om commands op die host te tik.

Dit verander firmware compromise in **host compromise** omdat die PC die reflashed peripheral as ’n legitieme keyboard sal vertrou.

### Minimal assessment checklist

- Wys `dmesg`, Device Manager, of USB descriptors ’n bestaande HID interface?
- Is daar spasie naby die report descriptor of ’n relocatable descriptor table?
- Kan bestaande media-control send routines vir keyboard reports hergebruik word?
- Accepteer die host outomaties die nuwe keyboard interface ná reflashing?

## Betroubare payload execution binne RTOS firmware

In plaas daarvan om brose trampolines in random code paths in te voeg, soek vir **existing RTOS tasks** wat ongebruik of lae impak in normale werking is.

Hoekom dit nuttig is:

- Die scheduler begin jou payload natuurlik tydens boot.
- Jy vermy om kritieke control flow te korrupteer.
- Vertraagde payloads is minder geneig om watchdog resets te trigger as wanneer hulle binne ’n latency-sensitive USB/network handler loop.

Goeie teikens is diagnostic, factory-test, telemetry, of coprocessor service tasks wat dormant lyk tydens normale gebruik.

## Vinnige exploit-iterasie: hergebruik benign protocol handlers

Sodra firmware patching moontlik is, is ’n kompakte manier om RE te versnel om ’n harmless command handler (byvoorbeeld ’n **echo/debug opcode**) te oorskryf met custom **memory read / write / execute** primitives. Dit vermy full reflashing vir elke eksperiment en is veral nuttig wanneer die device die modified handler oor ’n vinnige wired transport ondersteun.

Gebruik dit om:

- Scatter-loaded memory maps te verifieer
- Heap/task state live te inspekteer
- Klein payloads te toets voordat jy hulle in flash brand
- Function pointers, strings, en descriptor tables veilig te recover

## References

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
