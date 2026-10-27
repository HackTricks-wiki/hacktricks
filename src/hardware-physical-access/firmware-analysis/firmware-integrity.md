# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

जब किसी अधिकृत assessment में firmware-signature verification कमज़ोर या अनुपस्थित पाई जाती है, तो integrity पर पड़ने वाले असर को दिखाने के लिए modified firmware image का उपयोग किया जा सकता है। नीचे दिया गया lab workflow, extraction, emulation और repacking के मूल चरणों को बनाए रखते हुए bind shell जोड़ता है।<sup>[[2]](#references)[[3]](#references)</sup>

1. firmware को firmware-mod-kit (FMK) का उपयोग करके extract किया जा सकता है।
2. target firmware का architecture और endianness पता होना चाहिए।
3. Buildroot या environment के लिए उपयुक्त किसी अन्य तरीके से cross compiler बनाया जा सकता है।
4. cross compiler का उपयोग करके backdoor बनाया जा सकता है।
5. backdoor को extracted firmware की /usr/bin directory में copy किया जा सकता है।
6. उपयुक्त QEMU binary को extracted firmware के rootfs में copy किया जा सकता है।
7. backdoor को chroot और QEMU का उपयोग करके emulate किया जा सकता है।
8. backdoor को netcat के ज़रिए access किया जा सकता है।
9. extracted firmware के rootfs से QEMU binary हटा देनी चाहिए।
10. modified firmware को FMK का उपयोग करके दोबारा package किया जा सकता है।
11. backdoored firmware को firmware analysis toolkit (FAT) से emulate करके और netcat का उपयोग कर target backdoor IP और port से connect करके test किया जा सकता है।

यदि dynamic analysis, bootloader manipulation या hardware security testing के ज़रिए पहले ही root shell प्राप्त की जा चुकी है, तो implants या reverse shells जैसी precompiled test binaries चलाई जा सकती हैं। इस validation workflow के लिए Metasploit का `msfvenom` architecture-specific payload बना सकता है:<sup>[[4]](#references)</sup>

1. target firmware का architecture और endianness पता होना चाहिए।
2. target payload, attacker host IP, listening port number, filetype, architecture, platform और output file निर्दिष्ट करने के लिए Msfvenom का उपयोग किया जा सकता है।
3. payload को compromised device पर transfer किया जा सकता है और यह सुनिश्चित किया जा सकता है कि उसे execute करने की permissions हों।
4. msfconsole शुरू करके और payload के अनुसार settings configure करके, incoming requests संभालने के लिए Metasploit तैयार किया जा सकता है।
5. compromised device पर meterpreter reverse shell चलाया जा सकता है।

## बिना authentication वाले transport bridges से privileged update protocols तक पहुँच

Embedded design में एक आम गलती है **एक ही internal command protocol को कई transports पर उपलब्ध कराना**, लेकिन authentication केवल उनमें से एक पर लागू करना। उदाहरण के लिए, USB पर challenge-response की आवश्यकता हो सकती है, जबकि BLE बिना authentication वाले **GATT writes** को सीधे उसी privileged firmware-update handler तक पहुँचा सकता है।<sup>[[1]](#references)</sup>

आम offensive workflow:

1. BLE GATT database को enumerate करें और official mobile app द्वारा उपयोग की जाने वाली writable characteristics पहचानें।
2. App traffic को sniff करें और wired protocol से मेल खाने वाले **magic bytes / opcodes** खोजें।
3. BLE पर **pairing के बिना** privileged commands दोबारा भेजें और जाँचें कि संवेदनशील operations अब भी काम करते हैं या नहीं।
4. यदि firmware upgrade, config write, debug या factory-test opcodes तक पहुँचा जा सकता है, तो BLE को **radio के ज़रिए पहुँच योग्य admin port** मानें।

त्वरित जाँचें:

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

रिवर्सिंग के दौरान जांचें:

- क्या BLE के लिए **pairing/bonding** आवश्यक है या केवल सामान्य कनेक्शन?
- क्या सभी transports को एक ही internal dispatcher table पर route किया जाता है?
- क्या privileged opcodes को USB / BLE / UART / Wi-Fi पर अलग-अलग तरीके से filter किया जाता है?
- क्या mobile app दूर से firmware update, recovery या diagnostic handlers को trigger कर सकता है?

## केवल checksum वाले firmware containers में भी attacker-controlled firmware होता है

केवल **unkeyed checksum** (CRC32, SHA-256, MD5 आदि) से सुरक्षित firmware container, **authenticity नहीं, बल्कि corruption detection** प्रदान करता है। यदि attacker update routine तक पहुंच सकता है, तो वह image को patch कर सकता है, checksum दोबारा निकाल सकता है और मनमाना code flash कर सकता है।<sup>[[1]](#references)</sup>

RE के दौरान खतरे के संकेत:

- Update code केवल trailing checksum blob, जैसे `CHK2`, `CRC` या `SHA256`, को validate करता है।
- कोई signature verification या secure-boot root of trust मौजूद नहीं है।
- Device-bound MAC / HMAC / authenticated encryption का उपयोग नहीं किया गया है।
- Recovery mode वही unauthenticated image format स्वीकार करता है।

व्यावहारिक validation प्रक्रिया:

1. Firmware container निकालें और bootloader, main firmware तथा integrity metadata की पहचान करें।
2. Image में कोई हानिरहित string या banner बदलें।
3. Updater की अपेक्षा के अनुसार checksum दोबारा निकालें।
4. सामान्य update path से image को फिर से flash करें।
5. Boot होने पर बदलाव की पुष्टि करें, ताकि arbitrary firmware replacement साबित हो सके।

यदि यह BLE/Wi-Fi जैसे remotely reachable transport से काम करता है, तो यह प्रभावी रूप से **unauthenticated OTA firmware replacement** है।

## Fragmented update state और writable integrity metadata

Updater installation के दौरान signed firmware header को verify कर सकता है, लेकिन फिर भी images को केवल stored integrity hash के आधार पर boot कर सकता है। Cypherock X1 पर Bootloader ने अलग-अलग Firewall tasks शुरू किए: header verify करना और version/size को RAM में रखना, firmware signature को RAM में store करना, लिखी गई image को verify करना, और अंत में image का hash करके उसे persistent Primary Bootloader Data में store करना। Signature को persist नहीं किया गया था। एक authenticated upgrade transaction लागू करने के बजाय, इन tasks को अलग-अलग call किया जा सकता था।<sup>[[5]](#references)</sup>

MCU code execution और Flash write access के साथ, रिपोर्ट किए गए attack में application image को फिर से लिखा गया, Bootloader RAM में version/size values बदली गईं जिन्हें Firewall के साथ साझा किया जाता था, और फिर malicious image का hash store करने तथा सामान्य boot state बहाल करने के लिए अंतिम metadata task call किया गया। सामान्य boot integrity check ने signature को दोबारा जांचे बिना उस hash को स्वीकार कर लिया। इसी तरह के updater की समीक्षा करते समय पता लगाएं कि **कौन-सा component हर task को invoke कर सकता है**, verified values कहां रखी जाती हैं, और क्या boot के समय लिया गया निर्णय *उसी image* को authenticate करता है जिसका hash store किया गया है। यह checksum-only image format से अधिक सीमित समस्या है: signature verification मौजूद था, लेकिन state transition उससे बंधा हुआ नहीं था।<sup>[[5]](#references)</sup>

## Untrusted firmware measurements पर secure-element signatures

Secure element, उस code द्वारा दिया गया hash sign करके चल रहे code को attest नहीं करता। उसी wallet में, secure element ने device serial number और फिर MCU के माध्यम से दिए गए cloud nonce और firmware hash के XOR को sign किया। Compromised firmware, अलग bytes चलाते हुए भी, sign किए जाने के लिए expected hash दे सकता था। Companion client ने firmware version भी cloud को भेजा, इसलिए verifier की expected-hash तुलना अब भी MCU से आई measurement पर निर्भर थी, Flash को स्वतंत्र रूप से पढ़ने पर नहीं।<sup>[[5]](#references)</sup>

Device-side परिणाम एक अलग trust boundary था: cloud ने device की जांच की, लेकिन device ने cloud के verdict को authenticate नहीं किया। Modified client, tampered device को local success रिपोर्ट कर सकता था। Measurement के provenance और response authentication की अलग-अलग जांच करें; valid secure-element signature और success screen अपने-आप यह साबित नहीं करते कि installed application authentic है।<sup>[[5]](#references)</sup>

इस updater के analysis को संभव बनाने वाले protected-code disclosure के लिए, देखें [Firewall copy-task firmware acquisition](index.html#disclosing-protected-code-through-a-firewall-copy-task)।<sup>[[5]](#references)</sup>

## Firmware reflashing के जरिए trusted USB peripheral को BadUSB में बदलना

जब host पहले से ही USB के जरिए target device पर भरोसा करता है, तो malicious firmware को शायद पूरी नई USB stack लागू करने की आवश्यकता न हो। अक्सर **मौजूदा HID support का दोबारा उपयोग करना** कहीं आसान तरीका होता है।<sup>[[1]](#references)</sup>

उपयोगी तरीका:

1. जांचें कि क्या device पहले से **HID Consumer Control** / media / vendor HID interface के रूप में enumerate होता है।
2. Firmware में मौजूदा **HID report descriptor** ढूंढें।
3. Descriptor entries जोड़ें या बदलें, ताकि device **keyboard** capability भी advertise करे।
4. नया transport implementation लिखने के बजाय, मौजूदा firmware routines का दोबारा उपयोग करें जो पहले से HID reports भेजती हैं।
5. Host पर commands टाइप करने के लिए key press + key release reports inject करें।

इससे firmware compromise, **host compromise** में बदल जाता है, क्योंकि PC reflashed peripheral को एक वैध keyboard मानेगा।

### न्यूनतम assessment checklist

- क्या `dmesg`, Device Manager या USB descriptors में कोई मौजूदा HID interface दिखता है?
- क्या report descriptor के पास खाली जगह है या relocatable descriptor table उपलब्ध है?
- क्या मौजूदा media-control send routines को keyboard reports के लिए दोबारा इस्तेमाल किया जा सकता है?
- क्या reflashing के बाद host नए keyboard interface को अपने-आप स्वीकार करता है?

## RTOS firmware के भीतर payload का विश्वसनीय execution

Random code paths में नाज़ुक trampolines डालने के बजाय, ऐसे **मौजूदा RTOS tasks** ढूंढें जो सामान्य operation में unused हों या जिनका प्रभाव कम हो।<sup>[[1]](#references)</sup>

यह क्यों उपयोगी है:

- Scheduler boot के दौरान स्वाभाविक रूप से आपका payload शुरू करता है।
- आप critical control flow को corrupt करने से बचते हैं।
- Latency-sensitive USB/network handler के भीतर चलाने की तुलना में, delayed payloads से watchdog reset होने की संभावना कम होती है।

अच्छे targets वे diagnostic, factory-test, telemetry या coprocessor service tasks हैं जो सामान्य उपयोग में निष्क्रिय दिखते हैं।

## Exploit iteration तेज़ करें: benign protocol handlers का दोबारा उपयोग

Firmware patching संभव होने पर, RE को तेज़ करने का एक सरल तरीका है किसी harmless command handler (उदाहरण के लिए **echo/debug opcode**) को custom **memory read / write / execute** primitives से overwrite करना। इससे हर experiment के लिए पूरी reflashing की आवश्यकता नहीं पड़ती और यह खास तौर पर तब उपयोगी है जब device modified handler को तेज़ wired transport पर support करता हो।<sup>[[1]](#references)</sup>

इसका उपयोग करें:

- Scatter-loaded memory maps को verify करने के लिए
- Heap/task state को live inspect करने के लिए
- Payloads को flash में लिखने से पहले छोटे payloads test करने के लिए
- Function pointers, strings और descriptor tables को सुरक्षित रूप से recover करने के लिए

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - How to use `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [How And Why We Hacked Cypherock Hardware Wallet: The Full Story](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
