# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

"Carbonara" hutumia njia ya upakuaji ya MediaTek XFlash kuendesha hatua ya pili ya Download Agent (DA2) iliyorekebishwa licha ya ukaguzi wa uadilifu wa DA1. DA1 huhifadhi SHA-256 inayotarajiwa ya DA2 kwenye RAM na kuilinganisha kabla ya kufanya tawi la utekelezaji. Kwenye loaders nyingi, host hudhibiti kikamilifu anwani/ukubwa wa kupakia DA2, hivyo kutoa uandishi wa kumbukumbu usiokaguliwa ambao unaweza kubatilisha hash iliyo kwenye kumbukumbu na kuelekeza utekelezaji kwenye payloads za kiholela (muktadha wa pre-OS, huku cache invalidation ikishughulikiwa na DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Mpaka wa uaminifu katika XFlash (DA1 → DA2)

- **DA1** imesainiwa/inapakiwa na BootROM/Preloader. Download Agent Authorization (DAA) ikiwa imewezeshwa, ni DA1 iliyosainiwa pekee inayopaswa kuendeshwa.
- **DA2** hutumwa kupitia USB. DA1 hupokea **size**, **load address**, na **SHA-256**, kisha huhash received DA2 na kuilinganisha na **expected hash iliyopachikwa ndani ya DA1** (iliyonakiliwa kwenye RAM).
- **Udhaifu:** Kwenye loaders ambazo hazijafanyiwa patch, DA1 haisafishi load address/size ya DA2 na huacha expected hash ikiwa inaweza kuandikwa kwenye kumbukumbu, hivyo kumwezesha host kuharibu ukaguzi huo.<sup>[[1]](#references)[[2]](#references)</sup>

## Mtiririko wa Carbonara ("two BOOT_TO" trick)

1. **BOOT_TO ya kwanza:** Ingia kwenye mtiririko wa staging wa DA1→DA2 (DA1 hutenga kumbukumbu, huandaa DRAM, na kufichua buffer ya expected-hash kwenye RAM).
2. **Kubatilisha hash-slot:** Tuma payload ndogo inayochanganua kumbukumbu ya DA1 ili kupata DA2-expected hash iliyohifadhiwa na kuibatilisha kwa SHA-256 ya DA2 iliyorekebishwa na mshambuliaji. Hii hutumia load inayodhibitiwa na mtumiaji kuweka payload mahali ambapo hash ipo.
3. **BOOT_TO ya pili + digest:** Anzisha BOOT_TO nyingine ikiwa na metadata ya DA2 iliyorekebishwa na tuma digest ghafi ya baiti 32 inayolingana na DA2 iliyorekebishwa. DA1 hukokotoa tena SHA-256 ya DA2 iliyopokelewa, huilinganisha na expected hash ambayo sasa imebadilishwa, na jump hufaulu kuingia kwenye attacker code.

Kwa sababu load address/size inadhibitiwa na mshambuliaji, primitive hiyo hiyo inaweza kuandika mahali popote kwenye kumbukumbu (si kwenye hash buffer pekee), na kuwezesha implants za early-boot, wasaidizi wa secure-boot bypass, au rootkits hasidi.<sup>[[1]](#references)[[2]](#references)</sup>

## Muundo wa chini kabisa wa PoC (mtindo wa mtkclient)
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
- `payload` inarudia blob ya paid-tool inayopatch buffer ya expected-hash ndani ya DA1.
- `sha256(...).digest()` hutuma raw bytes (si hex), hivyo DA1 hulinganisha dhidi ya buffer iliyopatchiwa.
- DA2 inaweza kuwa image yoyote iliyoundwa na attacker; kuchagua load address/size huruhusu arbitrary memory placement, huku cache invalidation ikishughulikiwa na DA.<sup>[[3]](#references)</sup>

## Muhtasari wa patch (loaders zilizoimarishwa)

- **Mitigation**: DAs zilizosasishwa huweka DA2 load address kuwa `0x40000000` moja kwa moja na hupuuza address inayotolewa na host, hivyo writes haziwezi kufikia DA1 hash slot (takriban eneo la `0x200000`). Hash bado huhesabiwa, lakini haiwezi tena kuandikwa na attacker.
- **Kutambua DAs zilizopatchiwa**: mtkclient/penumbra huchanganua DA1 kutafuta patterns zinazoonyesha address-hardening; zikizipata, Carbonara hurukwa. DAs za zamani zina hash slots zinazoweza kuandikwa (mara nyingi karibu na offsets kama `0x22dea4` katika V5 DA1) na bado zinaweza ku-exploitwa.
- **V5 dhidi ya V6**: Baadhi ya V6 (XML) loaders bado hukubali addresses zinazotolewa na user; binaries mpya za V6 kwa kawaida hulazimisha fixed address na haziathiriwi na Carbonara isipokuwa zishushwe kwa downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Maelezo ya Post-Carbonara (heapb8)

MediaTek ilipatch Carbonara; vulnerability mpya zaidi, **heapb8**, hulenga DA2 USB file download handler kwenye patched V6 loaders, na kutoa code execution hata wakati `boot_to` imeimarishwa. Hutumia heap overflow wakati wa chunked file transfers ili kutwaa DA2 control flow. Exploit hii iko hadharani katika Penumbra/mtk-payloads na inaonyesha kuwa fixes za Carbonara hazifungi attack surface yote ya DA.<sup>[[4]](#references)</sup>

## Notes za triage na hardening

- Devices ambazo DA2 address/size hazikaguliwi na DA1 inaendelea kuweka expected hash ikiwa writable zina vulnerability. Ikiwa Preloader/DA ya baadaye inatekeleza address bounds au inaweka hash kuwa immutable, Carbonara imezuiwa.
- Kuwezesha DAA na kuhakikisha kuwa DA1/Preloader zinavalidate BOOT_TO parameters (bounds + authenticity ya DA2) hufunga primitive hii. Kufunga hash patch pekee bila kuweka mipaka ya load bado kunaacha arbitrary write risk.

## References

- [1] [Carbonara: exploit ya MediaTek ambayo hakuna aliye-serve](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Nyaraka za Carbonara exploit](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Source code ya Penumbra Carbonara](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: ku-exploit patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
