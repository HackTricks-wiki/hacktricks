# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Summary

"Carbonara", MediaTek के XFlash download path का abuse करके DA1 integrity checks के बावजूद modified Download Agent stage 2 (DA2) चलाता है। DA1, RAM में DA2 के expected SHA-256 को store करता है और branching से पहले उसकी तुलना करता है। कई loaders में host, DA2 के load address/size को पूरी तरह control करता है, जिससे एक unchecked memory write मिलता है जो उस in-memory hash को overwrite कर सकता है और execution को arbitrary payloads की ओर redirect कर सकता है (pre-OS context, जिसमें cache invalidation DA द्वारा handle किया जाता है)।<sup>[[1]](#references)[[2]](#references)</sup>

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** को BootROM/Preloader द्वारा signed/loaded किया जाता है। जब Download Agent Authorization (DAA) enabled होता है, तो केवल signed DA1 को run करना चाहिए।
- **DA2** USB के जरिए भेजा जाता है। DA1 **size**, **load address**, और **SHA-256** receive करता है और received DA2 को hash करके उसकी तुलना **DA1 में embedded expected hash** से करता है (जिसे RAM में copy किया जाता है)।
- **Weakness:** Unpatched loaders में DA1, DA2 के load address/size को sanitize नहीं करता और expected hash को memory में writable रखता है, जिससे host check के साथ tamper कर सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** DA1→DA2 staging flow में enter करें (DA1 allocate करता है, DRAM prepare करता है और RAM में expected-hash buffer expose करता है)।
2. **Hash-slot overwrite:** एक छोटा payload भेजें जो DA1 memory को stored DA2-expected hash के लिए scan करे और उसे attacker-modified DA2 के SHA-256 से overwrite कर दे। यह user-controlled load का leverage लेकर payload को उस स्थान पर पहुंचाता है जहां hash मौजूद है।
3. **Second `BOOT_TO` + digest:** Patched DA2 metadata के साथ एक और `BOOT_TO` trigger करें और modified DA2 से match करने वाला raw 32-byte digest भेजें। DA1 received DA2 पर SHA-256 दोबारा calculate करता है, उसकी तुलना अब-patched expected hash से करता है, और jump attacker code में सफलतापूर्वक हो जाता है।

Affected loaders में unchecked address और size, attacker-selected pre-OS memory-write primitive प्रदान कर सकते हैं, जो hash slot से आगे तक प्रभावी हो सकता है। SoC memory map और बाद के verification stages के आधार पर, यह early-boot implants, secure-boot-bypass helpers या rootkit-style payloads को support कर सकता है। केवल DA code execution अपने-आप persistence या complete secure-boot bypass प्रदान नहीं करता; इसके लिए अलग persistence mechanism और compatible verification chain अभी भी आवश्यक हैं।<sup>[[1]](#references)[[2]](#references)</sup>

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
- 16-बाइट `payload` paid-tool workflow में देखे गए blob को पुन:निर्मित करता है और published implementation द्वारा expected-hash buffer को patch करने के लिए उपयोग किया जाता है। यह loader-specific है, हर SoC या DA के लिए portable hash-slot patch नहीं है।<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` raw bytes भेजता है (hex नहीं), ताकि DA1 patched buffer से तुलना कर सके।
- किसी vulnerable और matched loader पर, DA2 attacker-built image हो सकता है और चुना गया load metadata उसके memory placement को नियंत्रित करता है। Transmission से पहले DA/SoC combination को validate करें, क्योंकि गलत addresses target को hang या damage कर सकते हैं।<sup>[[3]](#references)</sup>

## Patch landscape (hardened loaders)

- **देखी गई mitigation**: Researchers द्वारा जांचे गए hardened DAs DA2 load address को `0x40000000` पर force करते हैं और host-supplied address को ignore करते हैं, जिससे `0x200000` के आसपास देखे गए DA1 hash region में writes रुक जाती हैं। दोनों addresses को implementation-specific मानें, architectural constants नहीं।
- **Patched DAs का पता लगाना**: mtkclient/penumbra DA1 को ऐसे patterns के लिए scan करते हैं जो address-hardening का संकेत देते हैं; pattern मिलने पर Carbonara को skip कर दिया जाता है। पुराने DAs writable hash slots expose करते हैं (आमतौर पर V5 DA1 में `0x22dea4` जैसे offsets के आसपास) और exploitable बने रहते हैं।
- **V5 बनाम V6**: कुछ V6 (XML) loaders अभी भी user-supplied addresses स्वीकार करते हैं; नए V6 binaries आमतौर पर fixed address लागू करते हैं और downgrade किए बिना Carbonara से immune रहते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

## Post-Carbonara (heapb8) note

MediaTek ने Carbonara को patch कर दिया; एक नई vulnerability, **heapb8**, patched V6 loaders पर DA2 USB file download handler को target करती है और `boot_to` hardened होने पर भी code execution देती है। यह chunked file transfers के दौरान heap overflow का दुरुपयोग करके DA2 के control flow पर कब्जा करती है। यह exploit Penumbra/mtk-payloads में public है और दिखाता है कि Carbonara fixes सभी DA attack surface को बंद नहीं करते।<sup>[[4]](#references)</sup>

## Triage और hardening के लिए notes

- वे devices vulnerable हैं जहां DA2 address/size unchecked हैं और DA1 expected hash को writable बनाए रखता है। यदि कोई बाद का Preloader/DA address bounds लागू करता है या hash को immutable रखता है, तो Carbonara mitigated है।
- DAA enable करना और यह सुनिश्चित करना कि DA1/Preloader BOOT_TO parameters (bounds + DA2 की authenticity) validate करें, इस primitive को बंद करता है। केवल hash patch को बंद करने से, load को bound किए बिना, arbitrary write risk बना रहता है।

## References

- [1] [Carbonara: वह MediaTek exploit जिसे किसी ने serve नहीं किया](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: patched V6 Download Agents का exploitation](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
