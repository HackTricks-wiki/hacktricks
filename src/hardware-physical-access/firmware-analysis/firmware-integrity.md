# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

**custom firmware और/या compiled binaries को integrity या signature verification flaws exploit करने के लिए upload किया जा सकता है**। backdoor bind shell compilation के लिए निम्नलिखित steps follow किए जा सकते हैं:

1. firmware को firmware-mod-kit (FMK) का उपयोग करके extract किया जा सकता है।
2. target firmware architecture और endianness की पहचान की जानी चाहिए।
3. environment के लिए Buildroot या अन्य उपयुक्त methods का उपयोग करके cross compiler बनाया जा सकता है।
4. backdoor को cross compiler का उपयोग करके build किया जा सकता है।
5. backdoor को extracted firmware /usr/bin directory में copy किया जा सकता है।
6. appropriate QEMU binary को extracted firmware rootfs में copy किया जा सकता है।
7. backdoor को chroot और QEMU का उपयोग करके emulate किया जा सकता है।
8. backdoor को netcat के माध्यम से access किया जा सकता है।
9. QEMU binary को extracted firmware rootfs से remove किया जाना चाहिए।
10. modified firmware को FMK का उपयोग करके repackaged किया जा सकता है।
11. backdoored firmware को firmware analysis toolkit (FAT) के साथ emulate करके और netcat का उपयोग करके target backdoor IP और port से connect करके test किया जा सकता है।

यदि dynamic analysis, bootloader manipulation, या hardware security testing के माध्यम से root shell पहले ही प्राप्त हो चुका है, तो precompiled malicious binaries जैसे implants या reverse shells execute किए जा सकते हैं। Metasploit framework और 'msfvenom' जैसे automated payload/implant tools का उपयोग निम्नलिखित steps के साथ किया जा सकता है:

1. target firmware architecture और endianness की पहचान की जानी चाहिए।
2. Msfvenom का उपयोग target payload, attacker host IP, listening port number, filetype, architecture, platform, और output file specify करने के लिए किया जा सकता है।
3. payload को compromised device पर transfer किया जा सकता है और सुनिश्चित किया जा सकता है कि उसके पास execution permissions हैं।
4. Metasploit को msfconsole शुरू करके और payload के अनुसार settings configure करके incoming requests handle करने के लिए तैयार किया जा सकता है।
5. meterpreter reverse shell को compromised device पर execute किया जा सकता है।

## Unauthenticated transport bridges to privileged update protocols

एक सामान्य embedded design mistake यह है कि **same internal command protocol को several transports पर expose किया जाता है** लेकिन authentication केवल उनमें से एक पर enforce की जाती है। उदाहरण के लिए, USB challenge-response require कर सकता है जबकि BLE बिना authentication के **GATT writes** को उसी privileged firmware-update handler में simply forward कर देता है।

Typical offensive workflow:

1. BLE GATT database को enumerate करें और official mobile app द्वारा उपयोग की जाने वाली writable characteristics identify करें।
2. app traffic sniff करें और **magic bytes / opcodes** खोजें जो wired protocol से match करते हों।
3. privileged commands को BLE पर **without pairing** replay करें और verify करें कि sensitive operations अभी भी work करती हैं या नहीं।
4. यदि firmware upgrade, config write, debug, या factory-test opcodes reachable हों, तो BLE को एक **radio-reachable admin port** मानें।

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
बैक करते समय सत्यापित करने योग्य बातें:

- क्या BLE को **pairing/bonding** की ज़रूरत है या सिर्फ़ plain connection काफी है?
- क्या सभी transports एक ही internal dispatcher table पर routed हैं?
- क्या privileged opcodes USB / BLE / UART / Wi-Fi पर अलग तरह से filtered हैं?
- क्या mobile app firmware update, recovery, या diagnostic handlers को remotely trigger कर सकती है?

## Checksum-only firmware containers still attacker-controlled firmware हैं

एक firmware container जो सिर्फ़ एक **unkeyed checksum** (CRC32, SHA-256, MD5, आदि) से protected है, corruption detection देता है, **authenticity** नहीं। अगर attacker update routine तक पहुंच सकता है, तो वह image को patch कर सकता है, checksum recompute कर सकता है, और arbitrary code flash कर सकता है।

RE के दौरान red flags:

- Update code सिर्फ़ trailing checksum blob जैसे `CHK2`, `CRC`, या `SHA256` को validate करता है।
- कोई signature verification या secure-boot root of trust मौजूद नहीं है।
- कोई device-bound MAC / HMAC / authenticated encryption इस्तेमाल नहीं होता।
- Recovery mode वही unauthenticated image format accept करता है।

Practical validation flow:

1. Firmware container को extract करें और bootloader, main firmware, और integrity metadata identify करें।
2. Image में कोई harmless string या banner modify करें।
3. Checksum को बिल्कुल वैसे ही recompute करें जैसा updater expect करता है।
4. Normal update path से image को reflash करें।
5. Boot पर change confirm करें ताकि arbitrary firmware replacement साबित हो।

अगर यह remotely reachable transport जैसे BLE/Wi-Fi पर काम करता है, तो bug effectively **unauthenticated OTA firmware replacement** है।

## Trusted USB peripheral को firmware reflashing के जरिए BadUSB में बदलना

जब target device host के लिए USB पर पहले से trusted है, तो malicious firmware को full new USB stack implement करने की ज़रूरत नहीं हो सकती। अक्सर एक बहुत आसान pivot होता है **existing HID support** को reuse करना।

Useful pattern:

1. Check करें कि device पहले से **HID Consumer Control** / media / vendor HID interface के रूप में enumerate होता है या नहीं।
2. Firmware में existing **HID report descriptor** locate करें।
3. Descriptor entries append या replace करें ताकि device **keyboard** capability भी advertise करे।
4. Existing firmware routines को reuse करें जो पहले से HID reports भेजती हैं, बजाय नया transport implementation लिखने के।
5. Host पर commands type करने के लिए key press + key release reports inject करें।

इससे firmware compromise, **host compromise** में बदल जाता है क्योंकि PC reflashed peripheral को एक legitimate keyboard के रूप में trust करेगा।

### Minimal assessment checklist

- क्या `dmesg`, Device Manager, या USB descriptors में existing HID interface दिखती है?
- क्या report descriptor के पास spare room है या relocatable descriptor table है?
- क्या existing media-control send routines को keyboard reports के लिए reuse किया जा सकता है?
- क्या host reflashing के बाद नए keyboard interface को auto-accept करता है?

## RTOS firmware के अंदर reliable payload execution

Random code paths में fragile trampolines डालने के बजाय, **existing RTOS tasks** खोजें जो normal operation में unused या low-impact हों।

यह क्यों उपयोगी है:

- Scheduler boot के दौरान आपका payload naturally start करता है।
- आप critical control flow corrupt करने से बचते हैं।
- Delayed payloads के latency-sensitive USB/network handler के अंदर चलने की तुलना में watchdog resets trigger करने की संभावना कम होती है।

अच्छे targets diagnostic, factory-test, telemetry, या coprocessor service tasks हैं जो normal usage में dormant दिखते हैं।

## Fast exploit iteration: benign protocol handlers को repurpose करना

एक बार firmware patching possible हो जाए, RE को तेज़ करने का compact तरीका है किसी harmless command handler को overwrite करना (उदाहरण के लिए एक **echo/debug opcode**) custom **memory read / write / execute** primitives से। इससे हर experiment के लिए full reflashing की ज़रूरत नहीं रहती और यह खास तौर पर तब उपयोगी है जब device modified handler को fast wired transport पर support करता हो।

इसे उपयोग करें ताकि:

- scatter-loaded memory maps verify कर सकें
- heap/task state live inspect कर सकें
- छोटे payloads flash में burn करने से पहले test कर सकें
- function pointers, strings, और descriptor tables safely recover कर सकें

## References

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
