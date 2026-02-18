# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## सारांश

"Carbonara" MediaTek के XFlash download path का दुरुपयोग कर के modified Download Agent stage 2 (DA2) चलाता है, भले ही DA1 की integrity checks मौजूद हों। DA1 DA2 का अपेक्षित SHA-256 RAM में स्टोर करता है और branching से पहले इसकी तुलना करता है। कई loaders में host पूरा DA2 load address/size नियंत्रित करता है, जिससे एक unchecked memory write संभव होता है जो उस इन-मेमोरी hash को overwrite कर सकता है और execution को arbitrary payloads पर redirect कर सकता है (pre-OS context जहाँ cache invalidation DA द्वारा संभाला जाता है)।

## XFlash में ट्रस्ट बाउंडरी (DA1 → DA2)

- **DA1** BootROM/Preloader द्वारा signed/loaded होता है। जब Download Agent Authorization (DAA) enabled होता है, तो केवल signed DA1 ही चलना चाहिए।
- **DA2** USB के माध्यम से भेजा जाता है। DA1 **size**, **load address**, और **SHA-256** प्राप्त करता है और प्राप्त DA2 का hash निकालकर उसे DA1 में embedded एक **expected hash** (RAM में copy किया गया) से तुलना करता है।
- **कमज़ोरी:** unpatched loaders पर DA1 DA2 के load address/size को sanitize नहीं करता और expected hash को memory में writable रखता है, जिससे host उस check में छेड़छाड़ कर सकता है।

## Carbonara फ्लो ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** DA1→DA2 staging flow में प्रवेश करें (DA1 DRAM allocate करता है, तैयार करता है, और expected-hash buffer को RAM में expose करता है)।
2. **Hash-slot overwrite:** एक छोटा payload भेजें जो DA1 मेमोरी स्कैन करके stored DA2-expected hash ढूंढे और उसे attacker-modified DA2 के SHA-256 से overwrite कर दे। यह user-controlled load का उपयोग करके payload को उस जगह लैंड कराता है जहाँ hash रहता है।
3. **Second `BOOT_TO` + digest:** patched DA2 metadata के साथ एक और `BOOT_TO` ट्रिगर करें और modified DA2 से मिलते हुए raw 32-byte digest भेजें। DA1 प्राप्त DA2 पर SHA-256 फिर से गणना करके अब patched expected hash से तुलना करता है, और jump सफल होकर attacker code में चला जाता है।

क्योंकि load address/size attacker-controlled होते हैं, यही primitive memory में कहीं भी लिख सकता है (सिर्फ hash buffer तक सीमित नहीं), जिससे early-boot implants, secure-boot bypass helpers, या malicious rootkits सक्षम होते हैं।

## Minimal PoC pattern (mtkclient-style)
```python
if self.xsend(self.Cmd.BOOT_TO):
payload = bytes.fromhex("a4de2200000000002000000000000000")
if self.xsend(payload) and self.status() == 0:
import hashlib
da_hash = hashlib.sha256(self.daconfig.da2).digest()
if self.xsend(da_hash):
self.status()
self.info("All good!")
```
- `payload` DA1 के अंदर expected-hash बफर को पैच करने वाले paid-tool blob की नकल करता है।
- `sha256(...).digest()` कच्चे बाइट भेजता है (hex नहीं) ताकि DA1 उसे patched बफर से तुलना करे।
- DA2 कोई भी attacker-built image हो सकता है; load address/size चुनने से arbitrary memory placement संभव होता है और cache invalidation DA द्वारा संभाल लिया जाता है।

## पैच परिदृश्य (hardened loaders)

- **निवारण**: Updated DAs DA2 load address को `0x40000000` पर हार्डकोड करते हैं और host द्वारा दिया गया पता ignore करते हैं, इसलिए लिखने से DA1 hash slot (~0x200000 range) तक नहीं पहुँच सकता। हैश compute होता रहता है पर अब attacker-writable नहीं होता।
- **Patched DAs का पता लगाना**: mtkclient/penumbra DA1 को address-hardening दर्शाने वाले पैटर्न के लिए स्कैन करते हैं; यदि पाया जाता है, तो Carbonara छोड़ दी जाती है। पुराने DAs writable hash slots प्रकट करते हैं (सामान्यत: V5 DA1 में `0x22dea4` जैसे ऑफ़सेट के आसपास) और शोषण योग्य बने रहते हैं।
- **V5 बनाम V6**: कुछ V6 (XML) loaders अभी भी user-supplied addresses स्वीकार करते हैं; नई V6 binaries आमतौर पर fixed address लागू करती हैं और Carbonara के प्रति immune होती हैं, जब तक कि उन्हें downgraded न किया गया हो।

## Post-Carbonara (heapb8) नोट

MediaTek ने Carbonara को पैच किया; एक नई भेद्यता, **heapb8**, patched V6 loaders पर DA2 USB file download handler को टारगेट करती है, जिससे code execution मिलता है भले ही `boot_to` hardened हो। यह chunked file transfers के दौरान heap overflow का दुरुपयोग कर DA2 control flow पर कब्जा कर लेती है। Exploit Penumbra/mtk-payloads में सार्वजनिक है और यह दर्शाती है कि Carbonara के फिक्स सभी DA attack surface को बंद नहीं करते।

## Triage और hardening के लिए नोट्स

- Devices जिनमें DA2 address/size unchecked होते हैं और DA1 expected hash को writable रखता है वे vulnerable होते हैं। अगर बाद का Preloader/DA address bounds लागू करता है या hash को immutable रखता है तो Carbonara mitigate हो जाता है।
- DAA सक्षम करना और यह सुनिश्चित करना कि DA1/Preloader BOOT_TO parameters (bounds + authenticity of DA2) को validate करें, primitive को बंद कर देता है। केवल hash patch को बंद करना बिना load को सीमित किए arbitrary write जोखिम छोड़ देता है।

## संदर्भ

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
