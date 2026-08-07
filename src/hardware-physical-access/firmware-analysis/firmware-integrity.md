# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

**custom firmware और/या compiled binaries को integrity या signature verification flaws का exploit करने के लिए upload किया जा सकता है**। backdoor bind shell compilation के लिए निम्नलिखित steps अपनाए जा सकते हैं:

1. firmware को firmware-mod-kit (FMK) का उपयोग करके extract किया जा सकता है।
2. target firmware architecture और endianness की पहचान की जानी चाहिए।
3. environment के लिए Buildroot या अन्य उपयुक्त methods का उपयोग करके cross compiler बनाया जा सकता है।
4. cross compiler का उपयोग करके backdoor बनाया जा सकता है।
5. backdoor को extracted firmware की /usr/bin directory में copy किया जा सकता है।
6. उपयुक्त QEMU binary को extracted firmware rootfs में copy किया जा सकता है।
7. backdoor को chroot और QEMU का उपयोग करके emulate किया जा सकता है।
8. backdoor को netcat के माध्यम से access किया जा सकता है।
9. QEMU binary को extracted firmware rootfs से remove किया जाना चाहिए।
10. modified firmware को FMK का उपयोग करके repackage किया जा सकता है।
11. backdoored firmware को firmware analysis toolkit (FAT) के साथ emulate करके और netcat का उपयोग करते हुए target backdoor IP और port से connect करके test किया जा सकता है।

यदि dynamic analysis, bootloader manipulation या hardware security testing के माध्यम से root shell पहले ही प्राप्त की जा चुकी है, तो implants या reverse shells जैसी precompiled malicious binaries को execute किया जा सकता है। Metasploit framework और 'msfvenom' जैसे automated payload/implant tools का उपयोग निम्नलिखित steps के माध्यम से किया जा सकता है:

1. target firmware architecture और endianness की पहचान की जानी चाहिए।
2. Msfvenom का उपयोग target payload, attacker host IP, listening port number, filetype, architecture, platform और output file निर्दिष्ट करने के लिए किया जा सकता है।
3. payload को compromised device पर transfer किया जा सकता है और यह सुनिश्चित किया जा सकता है कि उसके पास execution permissions हों।
4. msfconsole शुरू करके और payload के अनुसार settings configure करके incoming requests को handle करने के लिए Metasploit को तैयार किया जा सकता है।
5. compromised device पर meterpreter reverse shell को execute किया जा सकता है।

## Unauthenticated transport bridges to privileged update protocols

एक सामान्य embedded design mistake यह है कि **same internal command protocol को कई transports पर expose किया जाता है**, लेकिन authentication केवल उनमें से एक पर enforce की जाती है। उदाहरण के लिए, USB में challenge-response आवश्यक हो सकता है, जबकि BLE केवल unauthenticated **GATT writes** को उसी privileged firmware-update handler में forward करता है।<sup>[[1]](#references)</sup>

Typical offensive workflow:

1. BLE GATT database को enumerate करें और official mobile app द्वारा उपयोग की जाने वाली writable characteristics की पहचान करें।
2. app traffic को sniff करें और ऐसे **magic bytes / opcodes** खोजें जो wired protocol से match करते हों।
3. BLE पर privileged commands को **pairing के बिना** replay करें और verify करें कि sensitive operations अभी भी काम करते हैं या नहीं।
4. यदि firmware upgrade, config write, debug या factory-test opcodes reachable हों, तो BLE को **radio-reachable admin port** मानें।

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
reversing के दौरान सत्यापित करने योग्य बातें:

- क्या BLE के लिए **pairing/bonding** आवश्यक है या केवल plain connection पर्याप्त है?
- क्या सभी transports एक ही internal dispatcher table पर routed हैं?
- क्या privileged opcodes को USB / BLE / UART / Wi-Fi पर अलग-अलग filter किया जाता है?
- क्या mobile app firmware update, recovery या diagnostic handlers को remotely trigger कर सकता है?

## केवल checksum वाले firmware containers अभी भी attacker-controlled firmware हैं

केवल **unkeyed checksum** (CRC32, SHA-256, MD5 आदि) से protected firmware container corruption detection प्रदान करता है, **authenticity** नहीं। यदि attacker update routine तक पहुंच सकता है, तो वह image को patch करके checksum दोबारा compute कर सकता है और arbitrary code flash कर सकता है।<sup>[[1]](#references)</sup>

RE के दौरान red flags:

- Update code केवल `CHK2`, `CRC` या `SHA256` जैसे trailing checksum blob को validate करता है।
- कोई signature verification या secure-boot root of trust मौजूद नहीं है।
- कोई device-bound MAC / HMAC / authenticated encryption उपयोग नहीं किया गया है।
- Recovery mode वही unauthenticated image format स्वीकार करता है।

Practical validation flow:

1. Firmware container extract करें और bootloader, main firmware तथा integrity metadata की पहचान करें।
2. Image में किसी harmless string या banner को modify करें।
3. Checksum को ठीक उसी तरह recompute करें जैसा updater अपेक्षा करता है।
4. Normal update path के माध्यम से image को reflash करें।
5. Arbitrary firmware replacement सिद्ध करने के लिए boot पर बदलाव की पुष्टि करें।

यदि यह BLE/Wi-Fi जैसे remotely reachable transport पर काम करता है, तो bug प्रभावी रूप से **unauthenticated OTA firmware replacement** है।

## Firmware reflashing के माध्यम से trusted USB peripheral को BadUSB में बदलना

जब target device पहले से USB के माध्यम से host द्वारा trusted हो, तो malicious firmware को full नया USB stack implement करने की आवश्यकता नहीं हो सकती। अक्सर एक अधिक आसान pivot **existing HID support** का reuse करना होता है।<sup>[[1]](#references)</sup>

Useful pattern:

1. जांचें कि device पहले से **HID Consumer Control** / media / vendor HID interface के रूप में enumerate होता है या नहीं।
2. Firmware में मौजूदा **HID report descriptor** का पता लगाएं।
3. Descriptor entries को append या replace करें ताकि device keyboard capability भी advertise करे।
4. नई transport implementation लिखने के बजाय, उन existing firmware routines को reuse करें जो पहले से HID reports भेजती हैं।
5. Host पर commands type करने के लिए key press + key release reports inject करें।

इससे firmware compromise **host compromise** में बदल जाता है, क्योंकि PC reflashed peripheral को legitimate keyboard के रूप में trust करेगा।

### Minimal assessment checklist

- क्या `dmesg`, Device Manager या USB descriptors मौजूदा HID interface दिखाते हैं?
- क्या report descriptor के पास spare room या relocatable descriptor table मौजूद है?
- क्या existing media-control send routines को keyboard reports के लिए reuse किया जा सकता है?
- क्या reflashing के बाद host नई keyboard interface को automatically accept करता है?

## RTOS firmware के अंदर reliable payload execution

Random code paths में fragile trampolines insert करने के बजाय, ऐसे **existing RTOS tasks** खोजें जो normal operation में unused या low-impact हों।<sup>[[1]](#references)</sup>

यह क्यों उपयोगी है:

- Scheduler boot के दौरान आपके payload को naturally start करता है।
- आप critical control flow को corrupt करने से बचते हैं।
- USB/network handler के अंदर चलाने की तुलना में delayed payloads से watchdog resets trigger होने की संभावना कम होती है, क्योंकि वे latency-sensitive code path में execute नहीं होते।

अच्छे targets diagnostic, factory-test, telemetry या coprocessor service tasks होते हैं, जो normal usage में dormant दिखाई देते हैं।

## Fast exploit iteration: benign protocol handlers को repurpose करना

जब firmware patching संभव हो, तो RE को accelerate करने का एक compact तरीका है किसी harmless command handler (उदाहरण के लिए **echo/debug opcode**) को custom **memory read / write / execute** primitives से overwrite करना। इससे हर experiment के लिए full reflashing की आवश्यकता नहीं रहती और यह विशेष रूप से उपयोगी है जब device modified handler को fast wired transport के माध्यम से support करता हो।<sup>[[1]](#references)</sup>

इसका उपयोग करें:

- Scatter-loaded memory maps को verify करने के लिए
- Heap/task state को live inspect करने के लिए
- Flash में burn करने से पहले छोटे payloads test करने के लिए
- Function pointers, strings और descriptor tables को safely recover करने के लिए

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
