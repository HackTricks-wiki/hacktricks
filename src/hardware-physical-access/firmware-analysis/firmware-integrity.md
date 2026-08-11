# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

जब authorized assessment में कमजोर या अनुपस्थित firmware-signature verification मिलती है, तो integrity impact प्रदर्शित करने के लिए modified firmware image का उपयोग किया जा सकता है। निम्न lab workflow मूल extraction, emulation और repacking steps को बनाए रखते हुए एक bind shell जोड़ता है।<sup>[[2]](#references)[[3]](#references)</sup>

1. Firmware को firmware-mod-kit (FMK) का उपयोग करके extract किया जा सकता है।
2. Target firmware architecture और endianness की पहचान की जानी चाहिए।
3. Environment के लिए Buildroot या अन्य उपयुक्त methods का उपयोग करके cross compiler बनाया जा सकता है।
4. Cross compiler का उपयोग करके backdoor बनाया जा सकता है।
5. Backdoor को extracted firmware की /usr/bin directory में copy किया जा सकता है।
6. उपयुक्त QEMU binary को extracted firmware rootfs में copy किया जा सकता है।
7. Backdoor को chroot और QEMU का उपयोग करके emulate किया जा सकता है।
8. Backdoor को netcat के माध्यम से access किया जा सकता है।
9. QEMU binary को extracted firmware rootfs से हटा देना चाहिए।
10. Modified firmware को FMK का उपयोग करके repackage किया जा सकता है।
11. Backdoored firmware को firmware analysis toolkit (FAT) के साथ emulate करके और netcat का उपयोग कर target backdoor IP तथा port से connect करके test किया जा सकता है।

यदि dynamic analysis, bootloader manipulation या hardware security testing के माध्यम से root shell पहले ही प्राप्त की जा चुकी है, तो implants या reverse shells जैसे precompiled test binaries को execute किया जा सकता है। Metasploit का `msfvenom` इस validation workflow के लिए architecture-specific payload generate कर सकता है:<sup>[[4]](#references)</sup>

1. Target firmware architecture और endianness की पहचान की जानी चाहिए।
2. Msfvenom का उपयोग target payload, attacker host IP, listening port number, filetype, architecture, platform और output file निर्दिष्ट करने के लिए किया जा सकता है।
3. Payload को compromised device में transfer किया जा सकता है और यह सुनिश्चित किया जा सकता है कि उसके पास execution permissions हों।
4. Payload के अनुसार settings configure करके msfconsole start करने पर incoming requests handle करने के लिए Metasploit को तैयार किया जा सकता है।
5. Meterpreter reverse shell को compromised device पर execute किया जा सकता है।

## Unauthenticated transport bridges to privileged update protocols

एक सामान्य embedded design mistake यह है कि **same internal command protocol को कई transports पर expose किया जाता है**, लेकिन authentication उनमें से केवल एक पर लागू की जाती है। उदाहरण के लिए, USB में challenge-response आवश्यक हो सकता है, जबकि BLE केवल unauthenticated **GATT writes** को उसी privileged firmware-update handler में forward करता है।<sup>[[1]](#references)</sup>

Typical offensive workflow:

1. BLE GATT database को enumerate करें और official mobile app द्वारा उपयोग की जाने वाली writable characteristics की पहचान करें।
2. App traffic को sniff करें और ऐसे **magic bytes / opcodes** खोजें जो wired protocol से match करते हों।
3. BLE पर **without pairing** privileged commands replay करें और verify करें कि sensitive operations अभी भी काम करती हैं या नहीं।
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
Reversing के दौरान सत्यापित करने योग्य बातें:

- क्या BLE के लिए **pairing/bonding** आवश्यक है या केवल plain connection पर्याप्त है?
- क्या सभी transports एक ही internal dispatcher table पर route किए जाते हैं?
- क्या privileged opcodes को USB / BLE / UART / Wi-Fi पर अलग-अलग तरीके से filter किया जाता है?
- क्या mobile app firmware update, recovery या diagnostic handlers को remotely trigger कर सकता है?

## केवल checksum वाले firmware containers अभी भी attacker-controlled firmware हैं

केवल **unkeyed checksum** (CRC32, SHA-256, MD5 आदि) से protected firmware container corruption detection प्रदान करता है, **authenticity** नहीं। यदि attacker update routine तक पहुंच सकता है, तो वह image को patch करके checksum दोबारा calculate कर सकता है और arbitrary code flash कर सकता है।<sup>[[1]](#references)</sup>

RE के दौरान red flags:

- Update code केवल `CHK2`, `CRC` या `SHA256` जैसे trailing checksum blob को validate करता है।
- Signature verification या secure-boot root of trust मौजूद नहीं है।
- Device-bound MAC / HMAC / authenticated encryption का उपयोग नहीं किया गया है।
- Recovery mode वही unauthenticated image format स्वीकार करता है।

Practical validation flow:

1. Firmware container extract करें और bootloader, main firmware तथा integrity metadata की पहचान करें।
2. Image में कोई harmless string या banner modify करें।
3. Updater की अपेक्षा के अनुसार checksum को ठीक उसी तरह recompute करें।
4. Normal update path के माध्यम से image को फिर से flash करें।
5. Arbitrary firmware replacement सिद्ध करने के लिए boot के दौरान बदलाव की पुष्टि करें।

यदि यह BLE/Wi-Fi जैसे remotely reachable transport पर काम करता है, तो bug प्रभावी रूप से **unauthenticated OTA firmware replacement** है।

## Trusted USB peripheral को firmware reflashing के माध्यम से BadUSB में बदलना

जब target device पहले से USB के माध्यम से host द्वारा trusted हो, तो malicious firmware को पूरी तरह नया USB stack implement करने की आवश्यकता नहीं हो सकती। अक्सर एक बहुत आसान pivot **मौजूदा HID support का reuse** करना होता है।<sup>[[1]](#references)</sup>

Useful pattern:

1. जांचें कि क्या device पहले से **HID Consumer Control** / media / vendor HID interface के रूप में enumerate होता है।
2. Firmware में मौजूदा **HID report descriptor** खोजें।
3. Descriptor entries को append या replace करें, ताकि device keyboard capability भी advertise करे।
4. नया transport implementation लिखने के बजाय, मौजूदा firmware routines का reuse करें जो पहले से HID reports भेजती हैं।
5. Host पर commands type करने के लिए key press + key release reports inject करें।

यह firmware compromise को **host compromise** में बदल देता है, क्योंकि PC reflashed peripheral को legitimate keyboard के रूप में trust करेगा।

### Minimal assessment checklist

- क्या `dmesg`, Device Manager या USB descriptors किसी existing HID interface को दिखाते हैं?
- क्या report descriptor के पास spare room या relocatable descriptor table मौजूद है?
- क्या existing media-control send routines को keyboard reports के लिए reuse किया जा सकता है?
- क्या reflashing के बाद host नई keyboard interface को automatically accept करता है?

## RTOS firmware के भीतर reliable payload execution

Random code paths में fragile trampolines insert करने के बजाय, ऐसे **existing RTOS tasks** खोजें जो normal operation में unused या low-impact हों।<sup>[[1]](#references)</sup>

यह उपयोगी क्यों है:

- Scheduler boot के दौरान आपके payload को naturally start करता है।
- आप critical control flow को corrupt करने से बचते हैं।
- USB/network handler के latency-sensitive context में चलाने की तुलना में delayed payloads से watchdog resets trigger होने की संभावना कम होती है।

अच्छे targets diagnostic, factory-test, telemetry या coprocessor service tasks होते हैं, जो normal usage में dormant दिखाई देते हैं।

## Fast exploit iteration: benign protocol handlers को repurpose करना

जब firmware patching संभव हो जाए, तो RE को तेज करने का एक compact तरीका किसी harmless command handler (उदाहरण के लिए **echo/debug opcode**) को custom **memory read / write / execute** primitives से overwrite करना है। इससे हर experiment के लिए full reflashing की आवश्यकता नहीं रहती और यह विशेष रूप से तब उपयोगी होता है जब device modified handler को fast wired transport पर support करता हो।<sup>[[1]](#references)</sup>

इसका उपयोग करें:

- Scatter-loaded memory maps को verify करने के लिए
- Heap/task state को live inspect करने के लिए
- Flash में burn करने से पहले छोटे payloads test करने के लिए
- Function pointers, strings और descriptor tables को safely recover करने के लिए

## References

- [1] [Pwnd Blaster: अपने speaker का उपयोग करके, उसे कभी छुए बिना अपने PC को hack करना](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - `msfvenom` का उपयोग कैसे करें](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
