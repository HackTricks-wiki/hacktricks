# Uadilifu wa Firmware

{{#include ../../banners/hacktricks-training.md}}

**custom firmware na/au compiled binaries zinaweza kupakiwa ili kutumia udhaifu wa integrity au signature verification**. Hatua zifuatazo zinaweza kufuatwa kwa ajili ya backdoor bind shell compilation:

1. Firmware inaweza kutolewa kwa kutumia firmware-mod-kit (FMK).
2. Firmware architecture na endianness ya target inapaswa kutambuliwa.
3. Cross compiler inaweza kutengenezwa kwa kutumia Buildroot au mbinu nyingine zinazofaa kwa mazingira hayo.
4. Backdoor inaweza kujengwa kwa kutumia cross compiler.
5. Backdoor inaweza kunakiliwa kwenye directory ya /usr/bin ya firmware iliyotolewa.
6. QEMU binary inayofaa inaweza kunakiliwa kwenye rootfs ya firmware iliyotolewa.
7. Backdoor inaweza ku-emulate kwa kutumia chroot na QEMU.
8. Backdoor inaweza kufikiwa kupitia netcat.
9. QEMU binary inapaswa kuondolewa kutoka kwenye rootfs ya firmware iliyotolewa.
10. Firmware iliyorekebishwa inaweza kupakiwa upya kwa kutumia FMK.
11. Backdoored firmware inaweza kujaribiwa kwa ku-emulate kwa kutumia firmware analysis toolkit (FAT), kisha kuunganisha kwenye backdoor IP na port ya target kwa kutumia netcat.

Ikiwa root shell tayari imepatikana kupitia dynamic analysis, bootloader manipulation, au hardware security testing, malicious binaries zilizotengenezwa awali kama implants au reverse shells zinaweza kuendeshwa. Automated payload/implant tools kama Metasploit framework na 'msfvenom' zinaweza kutumiwa kwa kufuata hatua zifuatazo:

1. Firmware architecture na endianness ya target inapaswa kutambuliwa.
2. Msfvenom inaweza kutumiwa kubainisha target payload, attacker host IP, listening port number, filetype, architecture, platform, na output file.
3. Payload inaweza kuhamishiwa kwenye compromised device na kuhakikisha kuwa ina execution permissions.
4. Metasploit inaweza kutayarishwa kushughulikia incoming requests kwa kuanzisha msfconsole na kusanidi settings kulingana na payload.
5. Meterpreter reverse shell inaweza kuendeshwa kwenye compromised device.

## Unauthenticated transport bridges to privileged update protocols

Kosa la kawaida katika embedded design ni kuwasilisha **internal command protocol ileile kupitia transports kadhaa**, lakini kuweka authentication kwenye transport moja tu. Kwa mfano, USB inaweza kuhitaji challenge-response, huku BLE ikipitisha tu **GATT writes** zisizo na authentication kwenda kwenye privileged firmware-update handler ileile.<sup>[[1]](#references)</sup>

Typical offensive workflow:

1. Enumerate BLE GATT database na utambue writable characteristics zinazotumiwa na official mobile app.
2. Sniff app traffic na utafute **magic bytes / opcodes** zinazoendana na wired protocol.
3. Replay privileged commands kupitia BLE **without pairing** na uthibitishe kama sensitive operations bado zinafanya kazi.
4. Ikiwa firmware upgrade, config write, debug, au factory-test opcodes zinaweza kufikiwa, ichukulie BLE kama **radio-reachable admin port**.

Ukaguzi wa haraka:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Mambo ya kuthibitisha wakati wa kufanya reversing:

- Je, BLE inahitaji **pairing/bonding** au connection ya kawaida tu?
- Je, transports zote zinaelekezwa kwenye jedwali lilelile la ndani la dispatcher?
- Je, privileged opcodes zinachujwa kwa njia tofauti kwenye USB / BLE / UART / Wi-Fi?
- Je, mobile app inaweza kuanzisha firmware update, recovery, au diagnostic handlers kwa mbali?

## Firmware containers zenye checksum-only bado zinadhibitiwa na attacker

Firmware container inayolindwa na **unkeyed checksum** pekee (CRC32, SHA-256, MD5, n.k.) hutoa utambuzi wa uharibifu, **si uthibitisho wa uhalali**. Ikiwa attacker anaweza kufikia update routine, anaweza kupatch image, kukokotoa upya checksum, na ku-flash code yoyote.<sup>[[1]](#references)</sup>

Dalili za hatari wakati wa RE:

- Update code inathibitisha blob ya checksum iliyo mwishoni pekee, kama `CHK2`, `CRC`, au `SHA256`.
- Hakuna signature verification au secure-boot root of trust.
- Hakuna device-bound MAC / HMAC / authenticated encryption inayotumika.
- Recovery mode inakubali image format ileile isiyo na authentication.

Mtiririko wa practical validation:

1. Extract firmware container na utambue bootloader, main firmware, na integrity metadata.
2. Badilisha string au banner isiyo na madhara kwenye image.
3. Kokotoa upya checksum kwa usahihi kulingana na inavyotarajiwa na updater.
4. Reflash image kupitia njia ya kawaida ya update.
5. Thibitisha mabadiliko wakati wa boot ili kuthibitisha arbitrary firmware replacement.

Ikiwa hii inafanya kazi kupitia transport inayoweza kufikiwa remotely kama BLE/Wi-Fi, bug hiyo kwa ufanisi ni **unauthenticated OTA firmware replacement**.

## Kubadilisha USB peripheral inayoaminika kuwa BadUSB kupitia firmware reflashing

Wakati target device tayari inaaminika na host kupitia USB, malicious firmware huenda isihitaji kuimplement USB stack mpya kamili. Pivot rahisi zaidi mara nyingi ni **kutumia upya HID support iliyopo**.<sup>[[1]](#references)</sup>

Pattern muhimu:

1. Kagua ikiwa device tayari inajitokeza kama **HID Consumer Control** / media / vendor HID interface.
2. Tafuta **HID report descriptor** iliyopo ndani ya firmware.
3. Ongeza au badilisha descriptor entries ili device pia itangaze uwezo wa **keyboard**.
4. Tumia upya firmware routines zilizopo ambazo tayari hutuma HID reports badala ya kuandika transport implementation mpya.
5. Inject key press + key release reports ili kuandika commands kwenye host.

Hii hubadilisha firmware compromise kuwa **host compromise** kwa sababu PC itaamini peripheral iliyoreflashiwa kama keyboard halali.

### Minimal assessment checklist

- Je, `dmesg`, Device Manager, au USB descriptors zinaonyesha HID interface iliyopo?
- Je, kuna nafasi ya ziada karibu na report descriptor au relocatable descriptor table?
- Je, media-control send routines zilizopo zinaweza kutumiwa upya kwa keyboard reports?
- Je, host inakubali kiotomatiki keyboard interface mpya baada ya reflashing?

## Reliable payload execution ndani ya RTOS firmware

Badala ya kuingiza trampolines dhaifu kwenye code paths zisizo maalum, tafuta **RTOS tasks zilizopo** ambazo hazitumiki au zina athari ndogo wakati wa matumizi ya kawaida.<sup>[[1]](#references)</sup>

Sababu ya hii kuwa muhimu:

- Scheduler huanzisha payload yako kwa njia ya kawaida wakati wa boot.
- Unaepuka kuharibu critical control flow.
- Payloads zilizocheleweshwa zina uwezekano mdogo wa kusababisha watchdog resets kuliko zinapoendeshwa ndani ya USB/network handler inayohitaji latency ndogo.

Targets nzuri ni diagnostic, factory-test, telemetry, au coprocessor service tasks zinazoonekana kuwa dormant katika matumizi ya kawaida.

## Fast exploit iteration: kutumia upya benign protocol handlers

Mara firmware patching inapowezekana, njia fupi ya kuharakisha RE ni ku-overwrite harmless command handler (kwa mfano **echo/debug opcode**) kwa custom **memory read / write / execute** primitives. Hii huondoa hitaji la kufanya full reflashing kwa kila experiment na ni muhimu hasa wakati device inasaidia handler iliyorekebishwa kupitia fast wired transport.<sup>[[1]](#references)</sup>

Tumia hii kwa:

- Kuthibitisha scatter-loaded memory maps
- Kukagua heap/task state live
- Kujaribu payloads ndogo kabla ya kuzichoma kwenye flash
- Kurecover function pointers, strings, na descriptor tables kwa usalama

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
