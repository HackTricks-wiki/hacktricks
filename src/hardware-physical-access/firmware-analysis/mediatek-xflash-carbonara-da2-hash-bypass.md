# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## सारांश

"Carbonara" MediaTek के XFlash download path का दुरुपयोग करता है ताकि DA1 की integrity checks के बावजूद modified Download Agent stage 2 (DA2) चलाया जा सके। DA1 RAM में DA2 का अपेक्षित SHA-256 स्टोर करता है और branching से पहले इसकी तुलना करता है। कई loaders पर host DA2 के load address/size को पूरी तरह नियंत्रित करता है, जिससे unchecked memory write संभव होता है जो उस in-memory hash को overwrite कर सकता है और execution को arbitrary payloads की ओर redirect कर सकता है (pre-OS context में, cache invalidation DA द्वारा संभाला जाता है)।

## XFlash में ट्रस्ट बाउंड्री (DA1 → DA2)

- **DA1** BootROM/Preloader द्वारा signed/loaded होता है। जब Download Agent Authorization (DAA) enabled होता है, तो केवल signed DA1 को ही चलना चाहिए।
- **DA2** USB के माध्यम से भेजा जाता है। DA1 को **size**, **load address**, और **SHA-256** प्राप्त होते हैं और यह प्राप्त DA2 का hash बनाकर उसे DA1 में embedded एक **expected hash** (RAM में कॉपी) से तुलना करता है।
- **Weakness:** unpatched loaders पर DA1 DA2 के load address/size को sanitize नहीं करता और expected hash को memory में writable रखता है, जिससे host इस check को बदल सकता है।

## Carbonara फ्लो ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** DA1→DA2 स्टेजिंग फ्लो में प्रवेश करें (DA1 DRAM allocate करता है, तैयार करता है, और RAM में expected-hash buffer को expose करता है)।
2. **Hash-slot overwrite:** एक छोटा payload भेजें जो DA1 memory स्कैन करके वहाँ सहेजे गए DA2-expected hash को ढूँढे और उसे attacker-modified DA2 के SHA-256 से overwrite कर दे। यह user-controlled load का उपयोग करके payload को उस स्थान पर उतारता है जहाँ hash स्थित है।
3. **Second `BOOT_TO` + digest:** patched DA2 metadata के साथ एक और `BOOT_TO` ट्रिगर करें और modified DA2 से मेल खाने वाला कच्चा 32-byte digest भेजें। DA1 प्राप्त DA2 पर फिर से SHA-256 गणना करता है, उसे अब patched expected hash से तुलना करता है, और jump attacker code में सफल हो जाता है।

चूंकि load address/size attacker-controlled होते हैं, यही primitive memory में कहीं भी लिख सकता है (केवल hash buffer तक सीमित नहीं), जिससे early-boot implants, secure-boot bypass helpers, या malicious rootkits संभव हो जाते हैं।

## न्यूनतम PoC पैटर्न (mtkclient-style)
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
- `payload` paid-tool blob की नकल करता है जो DA1 के अंदर expected-hash buffer को पैच करता है।
- `sha256(...).digest()` कच्चे बाइट्स भेजता है (hex नहीं) ताकि DA1 पैच किए गए buffer के खिलाफ तुलना करे।
- DA2 कोई भी attacker-built image हो सकता है; load address/size चुनने से arbitrary memory placement संभव होता है और cache invalidation DA द्वारा संभाला जाता है।

## ट्रायज और हार्डनिंग के लिए नोट्स

- ऐसे devices जहाँ DA2 का address/size unchecked है और DA1 expected hash को writable रखता है, वे vulnerable होते हैं। अगर बाद का Preloader/DA address bounds लागू करता है या hash को immutable रखता है, तो Carbonara mitigate हो जाता है।
- DAA को सक्षम करना और यह सुनिश्चित करना कि DA1/Preloader BOOT_TO parameters (bounds + authenticity of DA2) को validate करें, primitive को बंद कर देता है। केवल hash patch को बंद करना बिना load को bound किए arbitrary write risk को बनाए रखता है।

## संदर्भ

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
