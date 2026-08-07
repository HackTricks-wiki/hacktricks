# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## सारांश

"Carbonara" MediaTek के XFlash download path का दुरुपयोग करके DA1 integrity checks के बावजूद modified Download Agent stage 2 (DA2) चलाता है। DA1 RAM में DA2 के expected SHA-256 को store करता है और branch करने से पहले उसकी तुलना करता है। कई loaders में host DA2 के load address/size को पूरी तरह नियंत्रित करता है, जिससे unchecked memory write प्राप्त होती है। यह in-memory hash को overwrite कर सकती है और arbitrary payloads की ओर execution redirect कर सकती है (pre-OS context, जिसमें cache invalidation DA द्वारा handle किया जाता है)।<sup>[[1]](#references)[[2]](#references)</sup>

## XFlash में Trust boundary (DA1 → DA2)

- **DA1** को BootROM/Preloader द्वारा signed/load किया जाता है। जब Download Agent Authorization (DAA) enabled हो, तो केवल signed DA1 को चलना चाहिए।
- **DA2** USB के माध्यम से भेजा जाता है। DA1 **size**, **load address**, और **SHA-256** प्राप्त करता है और received DA2 का hash बनाकर उसकी तुलना **DA1 में embedded expected hash** से करता है (जिसे RAM में copy किया जाता है)।
- **Weakness:** Unpatched loaders पर DA1 DA2 load address/size को sanitize नहीं करता और expected hash को memory में writable रखता है, जिससे host check के साथ tamper कर सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** DA1→DA2 staging flow में प्रवेश करें (DA1 allocation करता है, DRAM तैयार करता है, और RAM में expected-hash buffer को expose करता है)।
2. **Hash-slot overwrite:** एक छोटा payload भेजें जो stored DA2-expected hash के लिए DA1 memory को scan करे और उसे attacker-modified DA2 के SHA-256 से overwrite कर दे। यह user-controlled load का लाभ उठाकर payload को उस स्थान पर पहुंचाता है जहां hash मौजूद है।
3. **Second `BOOT_TO` + digest:** patched DA2 metadata के साथ एक और `BOOT_TO` trigger करें और modified DA2 से matching raw 32-byte digest भेजें। DA1 received DA2 पर SHA-256 दोबारा compute करता है, उसकी तुलना अब patched expected hash से करता है, और jump सफलतापूर्वक attacker code में पहुंच जाता है।

क्योंकि load address/size attacker-controlled होते हैं, यही primitive memory में कहीं भी write कर सकती है (केवल hash buffer में नहीं), जिससे early-boot implants, secure-boot bypass helpers या malicious rootkits enable हो जाते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

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
- `payload` DA1 के अंदर expected-hash buffer को patch करने वाले paid-tool blob की नकल करता है।
- `sha256(...).digest()` raw bytes भेजता है (hex नहीं), ताकि DA1 patched buffer के विरुद्ध तुलना करे।
- DA2 कोई भी attacker-built image हो सकता है; load address/size चुनने से arbitrary memory placement संभव होता है और cache invalidation DA द्वारा संभाला जाता है।<sup>[[3]](#references)</sup>

## Patch landscape (hardened loaders)

- **Mitigation**: Updated DAs DA2 load address को `0x40000000` पर hardcode करते हैं और host द्वारा दिए गए address को अनदेखा करते हैं, इसलिए writes DA1 hash slot (~0x200000 range) तक नहीं पहुंच सकते। Hash की गणना अब भी होती है, लेकिन attacker उसे write नहीं कर सकता।
- **Detecting patched DAs**: mtkclient/penumbra DA1 को ऐसे patterns के लिए scan करते हैं जो address-hardening का संकेत देते हैं; मिलने पर Carbonara को skip कर दिया जाता है। पुराने DAs writable hash slots (आमतौर पर V5 DA1 में `0x22dea4` जैसे offsets के आसपास) expose करते हैं और exploitable रहते हैं।
- **V5 vs V6**: कुछ V6 (XML) loaders अब भी user-supplied addresses स्वीकार करते हैं; नए V6 binaries आमतौर पर fixed address लागू करते हैं और downgrade किए बिना Carbonara से immune रहते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

## Post-Carbonara (heapb8) note

MediaTek ने Carbonara को patch कर दिया; एक नई vulnerability, **heapb8**, patched V6 loaders के DA2 USB file download handler को target करती है और `boot_to` hardened होने पर भी code execution देती है। यह chunked file transfers के दौरान heap overflow का दुरुपयोग करके DA2 के control flow पर कब्जा करती है। यह exploit Penumbra/mtk-payloads में public है और दिखाता है कि Carbonara fixes सभी DA attack surface को बंद नहीं करते।<sup>[[4]](#references)</sup>

## Notes for triage and hardening

- जिन devices में DA2 address/size unchecked हैं और DA1 expected hash को writable रखता है, वे vulnerable हैं। यदि बाद का Preloader/DA address bounds लागू करता है या hash को immutable रखता है, तो Carbonara mitigated है।
- DAA enable करना और यह सुनिश्चित करना कि DA1/Preloader BOOT_TO parameters (bounds + DA2 की authenticity) validate करें, primitive को बंद कर देता है। केवल hash patch को बंद करने से, load को bound किए बिना, arbitrary write risk बना रहता है।

## References

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
