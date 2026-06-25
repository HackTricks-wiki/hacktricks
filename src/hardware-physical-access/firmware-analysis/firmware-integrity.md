# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

**firmware maalum na/au compiled binaries zinaweza kupakiwa ili kunufaika na udhaifu wa integrity au signature verification**. Hatua zifuatazo zinaweza kufuatwa kwa backdoor bind shell compilation:

1. Firmware inaweza kutolewa kwa kutumia firmware-mod-kit (FMK).
2. Firmware architecture lengwa na endianness vinapaswa kutambuliwa.
3. Cross compiler inaweza kujengwa kwa kutumia Buildroot au mbinu nyingine zinazofaa kwa mazingira.
4. Backdoor inaweza kujengwa kwa kutumia cross compiler.
5. Backdoor inaweza kunakiliwa kwenye saraka ya firmware iliyotolewa /usr/bin.
6. QEMU binary inayofaa inaweza kunakiliwa kwenye firmware rootfs iliyotolewa.
7. Backdoor inaweza kuigwa kwa kutumia chroot na QEMU.
8. Backdoor inaweza kufikiwa kupitia netcat.
9. QEMU binary inapaswa kuondolewa kutoka kwenye firmware rootfs iliyotolewa.
10. Firmware iliyobadilishwa inaweza kupakiwa upya kwa kutumia FMK.
11. Firmware yenye backdoor inaweza kujaribiwa kwa kuiiga na firmware analysis toolkit (FAT) na kuunganisha kwenye target backdoor IP na port kwa kutumia netcat.

Kama root shell tayari imepatikana kupitia dynamic analysis, bootloader manipulation, au hardware security testing, precompiled malicious binaries kama implants au reverse shells zinaweza kutekelezwa. Automated payload/implant tools kama Metasploit framework na 'msfvenom' zinaweza kutumiwa kwa kutumia hatua zifuatazo:

1. Firmware architecture lengwa na endianness vinapaswa kutambuliwa.
2. Msfvenom inaweza kutumiwa kubainisha target payload, attacker host IP, nambari ya listening port, filetype, architecture, platform, na output file.
3. Payload inaweza kuhamishiwa kwenye kifaa kilichoathiriwa na kuhakikisha kuwa ina execution permissions.
4. Metasploit inaweza kutayarishwa kushughulikia incoming requests kwa kuanzisha msfconsole na kusanidi settings kulingana na payload.
5. meterpreter reverse shell inaweza kutekelezwa kwenye kifaa kilichoathiriwa.

## Unauthenticated transport bridges to privileged update protocols

Kosa la kawaida la embedded design ni kufichua **same internal command protocol over several transports** lakini kuweka authentication kwenye moja tu kati yao. Kwa mfano, USB inaweza kuhitaji challenge-response wakati BLE inapitisha tu **GATT writes** zisizo na authentication kwenda kwenye same privileged firmware-update handler.

Typical offensive workflow:

1. Enumerate BLE GATT database na utambue writable characteristics zinazotumiwa na official mobile app.
2. Sniff app traffic na utafute **magic bytes / opcodes** zinazolingana na wired protocol.
3. Replay privileged commands over BLE **without pairing** na thibitisha kama sensitive operations bado zinafanya kazi.
4. Ikiwa firmware upgrade, config write, debug, au factory-test opcodes zinaweza kufikiwa, chukulia BLE kama **radio-reachable admin port**.

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Mambo ya kuthibitisha wakati wa reversing:

- Je, BLE inahitaji **pairing/bonding** au connection ya kawaida tu?
- Je, transports zote zinaelekezwa kwenye internal dispatcher table moja?
- Je, privileged opcodes huchujwa kwa njia tofauti kwenye USB / BLE / UART / Wi-Fi?
- Je, mobile app inaweza ku-trigger firmware update, recovery, au diagnostic handlers kwa mbali?

## Checksum-only firmware containers are still attacker-controlled firmware

Firmware container inayolindwa tu kwa **unkeyed checksum** (CRC32, SHA-256, MD5, n.k.) hutoa detection ya corruption, **sio authenticity**. Kama attacker anaweza kufikia update routine, anaweza ku-patch image, ku-recompute checksum, na ku-flash arbitrary code.

Red flags wakati wa RE:

- Update code inathibitisha tu trailing checksum blob kama `CHK2`, `CRC`, au `SHA256`.
- Hakuna signature verification au secure-boot root of trust iliyopo.
- Hakuna device-bound MAC / HMAC / authenticated encryption inayotumika.
- Recovery mode inakubali image format ileile isiyo na uthibitisho.

Practical validation flow:

1. Extract firmware container na identify bootloader, main firmware, na integrity metadata.
2. Modify string au banner isiyo na madhara kwenye image.
3. Recompute checksum exactly kama updater inavyotegemea.
4. Reflash image kupitia normal update path.
5. Confirm mabadiliko wakati wa boot ili kuthibitisha arbitrary firmware replacement.

Kama hii inafanya kazi kupitia remotely reachable transport kama BLE/Wi-Fi, bug kwa vitendo ni **unauthenticated OTA firmware replacement**.

## Turning a trusted USB peripheral into BadUSB via firmware reflashing

Wakati device lengwa tayari inaaminika na host kupitia USB, malicious firmware huenda isihitaji kutekeleza full new USB stack. Njia rahisi zaidi mara nyingi ni **reuse existing HID support**.

Pattern muhimu:

1. Angalia kama device tayari inajitambulisha kama **HID Consumer Control** / media / vendor HID interface.
2. Locate existing **HID report descriptor** kwenye firmware.
3. Append au replace descriptor entries ili device pia itangaze uwezo wa **keyboard**.
4. Reuse existing firmware routines ambazo tayari hutuma HID reports badala ya kuandika new transport implementation.
5. Inject key press + key release reports ili kuandika commands kwenye host.

Hii inageuza firmware compromise kuwa **host compromise** kwa sababu PC itaamini peripheral iliyoreflashed kama keyboard halali.

### Minimal assessment checklist

- Je, `dmesg`, Device Manager, au USB descriptors zinaonyesha existing HID interface?
- Je, kuna spare room karibu na report descriptor au relocatable descriptor table?
- Je, existing media-control send routines zinaweza kutumiwa tena kwa keyboard reports?
- Je, host inakubali kiotomatiki new keyboard interface baada ya reflashing?

## Reliable payload execution inside RTOS firmware

Badala ya kuingiza fragile trampolines kwenye random code paths, tafuta **existing RTOS tasks** ambazo hazitumiki au zenye impact ndogo katika matumizi ya kawaida.

Kwa nini hii inasaidia:

- Scheduler huanza payload yako kwa kawaida wakati wa boot.
- Unakwepa kuharibu critical control flow.
- Delayed payloads zina uwezekano mdogo wa ku-trigger watchdog resets kuliko zinapoendeshwa ndani ya latency-sensitive USB/network handler.

Targets nzuri ni diagnostic, factory-test, telemetry, au coprocessor service tasks ambazo zinaonekana dormant katika normal usage.

## Fast exploit iteration: repurpose benign protocol handlers

Mara firmware patching inapowezekana, njia fupi ya kuharakisha RE ni ku-overwrite harmless command handler (kwa mfano **echo/debug opcode**) kwa custom **memory read / write / execute** primitives. Hii huepuka full reflashing kwa kila jaribio na ni muhimu hasa wakati device ina-support modified handler kupitia fast wired transport.

Tumia hii kwa:

- Verify scatter-loaded memory maps
- Inspect heap/task state live
- Test small payloads kabla ya kuziingiza kwenye flash
- Recover function pointers, strings, na descriptor tables kwa usalama

## References

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
