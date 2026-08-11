# Uadilifu wa Firmware

{{#include ../../banners/hacktricks-training.md}}

Tathmini iliyoidhinishwa inapogundua uthibitishaji dhaifu au usiokuwepo wa saini ya firmware, firmware image iliyorekebishwa inaweza kuonyesha athari kwa uadilifu. Workflow ifuatayo ya lab inaongeza bind shell huku ikihifadhi hatua za awali za extraction, emulation na repacking.<sup>[[2]](#references)[[3]](#references)</sup>

1. Firmware inaweza kutolewa kwa kutumia firmware-mod-kit (FMK).
2. Architecture na endianness ya target firmware zinapaswa kutambuliwa.
3. Cross compiler inaweza kutengenezwa kwa kutumia Buildroot au njia nyingine zinazofaa kwa mazingira hayo.
4. Backdoor inaweza kujengwa kwa kutumia cross compiler.
5. Backdoor inaweza kunakiliwa kwenye directory ya /usr/bin ya firmware iliyotolewa.
6. Binary inayofaa ya QEMU inaweza kunakiliwa kwenye rootfs ya firmware iliyotolewa.
7. Backdoor inaweza ku-emulate kwa kutumia chroot na QEMU.
8. Backdoor inaweza kufikiwa kupitia netcat.
9. Binary ya QEMU inapaswa kuondolewa kwenye rootfs ya firmware iliyotolewa.
10. Firmware iliyorekebishwa inaweza kupakiwa upya kwa kutumia FMK.
11. Firmware yenye backdoor inaweza kujaribiwa kwa kui-emulate kwa kutumia firmware analysis toolkit (FAT), kisha kuunganisha kwenye IP na port ya backdoor ya target kwa kutumia netcat.

Ikiwa root shell tayari imepatikana kupitia dynamic analysis, bootloader manipulation au hardware security testing, test binaries zilizotengenezwa awali kama implants au reverse shells zinaweza kutekelezwa. `msfvenom` ya Metasploit inaweza kutengeneza payload maalum kwa architecture kwa workflow hii ya validation:<sup>[[4]](#references)</sup>

1. Architecture na endianness ya target firmware zinapaswa kutambuliwa.
2. Msfvenom inaweza kutumiwa kubainisha target payload, IP ya attacker host, port number ya kusikilizia, filetype, architecture, platform na output file.
3. Payload inaweza kuhamishiwa kwenye kifaa kilichoathiriwa na kuhakikisha kuwa ina execution permissions.
4. Metasploit inaweza kutayarishwa kushughulikia requests zinazoingia kwa kuanzisha msfconsole na kusanidi settings kulingana na payload.
5. Meterpreter reverse shell inaweza kutekelezwa kwenye kifaa kilichoathiriwa.

## Transport bridges zisizo na authentication kuelekea privileged update protocols

Kosa la kawaida katika embedded design ni kufichua **same internal command protocol kupitia transports kadhaa** lakini kutekeleza authentication kwenye transport moja tu. Kwa mfano, USB inaweza kuhitaji challenge-response, huku BLE ikipitisha tu **GATT writes** zisizo na authentication kwenda kwenye handler ileile yenye privilege ya firmware-update.<sup>[[1]](#references)</sup>

Typical offensive workflow:

1. Enumerate BLE GATT database na utambue writable characteristics zinazotumiwa na official mobile app.
2. Sniff app traffic na utafute **magic bytes / opcodes** zinazolingana na wired protocol.
3. Replay privileged commands kupitia BLE **bila pairing** na uthibitishe ikiwa sensitive operations bado zinafanya kazi.
4. Ikiwa firmware upgrade, config write, debug au factory-test opcodes zinafikiwa, ichukulie BLE kama **radio-reachable admin port**.

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

- Je, BLE inahitaji **pairing/bonding** au muunganisho wa kawaida pekee?
- Je, transports zote zinaelekezwa kwenye jedwali lilelile la ndani la dispatcher?
- Je, privileged opcodes huchujwa kwa njia tofauti kwenye USB / BLE / UART / Wi-Fi?
- Je, mobile app inaweza kuanzisha firmware update, recovery, au diagnostic handlers kwa mbali?

## Checksum-only firmware containers are still attacker-controlled firmware

Firmware container inayolindwa na **unkeyed checksum** pekee (CRC32, SHA-256, MD5, n.k.) hutoa utambuzi wa uharibifu, **si uthibitisho wa uhalali**. Ikiwa attacker anaweza kufikia update routine, anaweza kurekebisha image, kukokotoa checksum upya, na ku-flash code yoyote.<sup>[[1]](#references)</sup>

Red flags wakati wa RE:

- Update code inathibitisha trailing checksum blob pekee, kama `CHK2`, `CRC`, au `SHA256`.
- Hakuna signature verification au secure-boot root of trust.
- Hakuna device-bound MAC / HMAC / authenticated encryption inayotumika.
- Recovery mode inakubali image format ileile isiyo na authentication.

Practical validation flow:

1. Extract firmware container na utambue bootloader, main firmware, na integrity metadata.
2. Rekebisha string au banner isiyo na madhara kwenye image.
3. Kokotoa checksum upya kwa usahihi kulingana na matarajio ya updater.
4. Reflash image kupitia njia ya kawaida ya update.
5. Thibitisha mabadiliko wakati wa boot ili kuthibitisha arbitrary firmware replacement.

Ikiwa hii inafanya kazi kupitia transport inayoweza kufikiwa kwa mbali, kama BLE/Wi-Fi, bug hiyo kwa ufanisi ni **unauthenticated OTA firmware replacement**.

## Turning a trusted USB peripheral into BadUSB via firmware reflashing

Wakati target device tayari inaaminika na host kupitia USB, malicious firmware huenda isihitaji kutekeleza USB stack mpya kamili. Mara nyingi pivot rahisi zaidi ni **kutumia tena existing HID support**.<sup>[[1]](#references)</sup>

Useful pattern:

1. Kagua ikiwa device tayari inajitambulisha kama **HID Consumer Control** / media / vendor HID interface.
2. Tafuta existing **HID report descriptor** kwenye firmware.
3. Ongeza au badilisha descriptor entries ili device pia itangaze uwezo wa **keyboard**.
4. Tumia tena firmware routines zilizopo ambazo tayari hutuma HID reports badala ya kuandika transport implementation mpya.
5. Ingiza key press + key release reports ili kuandika commands kwenye host.

Hii hubadilisha firmware compromise kuwa **host compromise** kwa sababu PC itaamini peripheral iliyofanyiwa reflash kama keyboard halali.

### Minimal assessment checklist

- Je, `dmesg`, Device Manager, au USB descriptors zinaonyesha HID interface iliyopo?
- Je, kuna nafasi iliyobaki karibu na report descriptor au relocatable descriptor table?
- Je, existing media-control send routines zinaweza kutumiwa tena kwa keyboard reports?
- Je, host inakubali kiotomatiki keyboard interface mpya baada ya reflashing?

## Reliable payload execution inside RTOS firmware

Badala ya kuingiza fragile trampolines kwenye random code paths, tafuta **existing RTOS tasks** ambazo hazitumiki au zina athari ndogo wakati wa normal operation.<sup>[[1]](#references)</sup>

Kwa nini hii ni muhimu:

- Scheduler inaanzisha payload yako kwa njia ya kawaida wakati wa boot.
- Unaepuka kuharibu critical control flow.
- Delayed payloads zina uwezekano mdogo wa kusababisha watchdog resets kuliko zinapoendeshwa ndani ya latency-sensitive USB/network handler.

Targets nzuri ni diagnostic, factory-test, telemetry, au coprocessor service tasks zinazoonekana kuwa dormant wakati wa matumizi ya kawaida.

## Fast exploit iteration: repurpose benign protocol handlers

Mara tu firmware patching inapowezekana, njia fupi ya kuharakisha RE ni kubadilisha harmless command handler (kwa mfano **echo/debug opcode**) na custom **memory read / write / execute** primitives. Hii huepusha reflashing kamili kwa kila jaribio na ni muhimu hasa wakati device inasaidia modified handler kupitia wired transport yenye kasi.<sup>[[1]](#references)</sup>

Tumia hii kwa:

- Kuthibitisha scatter-loaded memory maps
- Kukagua heap/task state live
- Kujaribu payloads ndogo kabla ya kuzichoma kwenye flash
- Kurejesha function pointers, strings, na descriptor tables kwa usalama

## References

- [1] [Pwnd Blaster: Kudukua PC yako kwa kutumia speaker yako bila kuigusa kamwe](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Jinsi ya kutumia `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
