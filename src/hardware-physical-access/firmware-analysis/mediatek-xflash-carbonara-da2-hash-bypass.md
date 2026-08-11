# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

"Carbonara" hutumia njia ya upakuaji ya MediaTek XFlash kuendesha hatua ya pili ya Download Agent (DA2) iliyorekebishwa licha ya ukaguzi wa uadilifu wa DA1. DA1 huhifadhi SHA-256 inayotarajiwa ya DA2 kwenye RAM na kuilinganisha kabla ya kuruka. Kwenye loaders nyingi, host hudhibiti kikamilifu anwani/ukubwa wa kupakia DA2, hivyo kutoa memory write isiyokaguliwa inayoweza kubatilisha hash hiyo iliyo kwenye memory na kuelekeza utekelezaji kwenye payloads za kiholela (katika muktadha wa pre-OS, huku cache invalidation ikishughulikiwa na DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Trust boundary katika XFlash (DA1 → DA2)

- **DA1** husainiwa/kupakiwa na BootROM/Preloader. Download Agent Authorization (DAA) ikiwa imewashwa, ni DA1 iliyosainiwa pekee inayopaswa kuendeshwa.
- **DA2** hutumwa kupitia USB. DA1 hupokea **size**, **load address**, na **SHA-256**, kisha huhash received DA2 na kuilinganisha na **expected hash iliyopachikwa kwenye DA1** (na kunakiliwa kwenye RAM).
- **Weakness:** Kwenye loaders ambazo hazijapatchiwa, DA1 haifanyi sanitize ya load address/size ya DA2 na huacha expected hash ikiwa inaweza kuandikwa kwenye memory, hivyo host anaweza kuingilia ukaguzi.<sup>[[1]](#references)[[2]](#references)</sup>

## Mtiririko wa Carbonara ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Ingia kwenye mtiririko wa staging wa DA1→DA2 (DA1 hutenga memory, huandaa DRAM, na kufichua expected-hash buffer kwenye RAM).
2. **Hash-slot overwrite:** Tuma payload ndogo inayochanganua memory ya DA1 kwa ajili ya DA2-expected hash iliyohifadhiwa na kuibatilisha kwa SHA-256 ya DA2 iliyorekebishwa na attacker. Hii hutumia load inayodhibitiwa na user ili payload ifike mahali hash ilipo.
3. **Second `BOOT_TO` + digest:** Anzisha `BOOT_TO` nyingine yenye metadata ya DA2 iliyopatchiwa na tuma digest ghafi ya byte 32 inayolingana na DA2 iliyorekebishwa. DA1 huhesabu upya SHA-256 ya DA2 iliyopokelewa, huilinganisha na expected hash iliyopatchiwa, kisha jump hufaulu na kuingia kwenye code ya attacker.

Kwenye loaders zilizoathirika, address na size zisizokaguliwa zinaweza kumpa attacker pre-OS memory-write primitive anayochagua, nje ya hash slot. Kulingana na memory map ya SoC na hatua za verification zinazofuata, hii inaweza kusaidia early-boot implants, secure-boot-bypass helpers, au payloads za mtindo wa rootkit. Utekelezaji wa code ya DA pekee hauleti persistence moja kwa moja wala secure-boot bypass kamili; persistence mechanism tofauti na verification chain inayooana bado vinahitajika.<sup>[[1]](#references)[[2]](#references)</sup>

## Muundo mdogo wa PoC (mtindo wa mtkclient)
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
- `payload` ya baiti 16 inazalisha tena blob iliyozingatiwa katika workflow ya paid-tool na kutumiwa na implementation iliyochapishwa ku-patch buffer ya expected-hash. Ni loader-specific, si patch ya hash-slot inayoweza kutumika kwenye kila SoC au DA.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` hutuma raw bytes (si hex), ili DA1 ilinganishe na buffer iliyopatchiwa.
- Kwenye loader iliyo vulnerable na inayolingana, DA2 inaweza kuwa image iliyoundwa na attacker, na load metadata iliyochaguliwa hudhibiti memory placement yake. Thibitisha mchanganyiko wa DA/SoC kabla ya transmission, kwa sababu anwani zisizo sahihi zinaweza kusimamisha au kuharibu target.<sup>[[3]](#references)</sup>

## Mandhari ya patch (loaders zilizoimarishwa)

- **Mitigation iliyozingatiwa**: DAs zilizoimarishwa zilizochunguzwa na researchers hulazimisha DA2 load address iwe `0x40000000` na hupuuza anwani inayotolewa na host, hivyo kuzuia writes kwenye DA1 hash region iliyozingatiwa karibu na `0x200000`. Chukulia anwani zote mbili kuwa implementation-specific, si architectural constants.
- **Kutambua DAs zilizopatchiwa**: mtkclient/penumbra huchanganua DA1 kwa patterns zinazoashiria address-hardening; ikipatikana, Carbonara hurukwa. DAs za zamani hufichua writable hash slots (mara nyingi karibu na offsets kama `0x22dea4` kwenye V5 DA1) na bado zinaweza ku-exploitika.
- **V5 dhidi ya V6**: Baadhi ya V6 (XML) loaders bado hukubali anwani zinazotolewa na user; binaries mpya za V6 kwa kawaida hulazimisha anwani maalum na hazina kinga dhidi ya Carbonara isipokuwa zishushwe kwenye version ya zamani.<sup>[[2]](#references)[[3]](#references)</sup>

## Dokezo la Post-Carbonara (heapb8)

MediaTek ili-patch Carbonara; vulnerability mpya zaidi, **heapb8**, inalenga DA2 USB file download handler kwenye V6 loaders zilizopatchiwa, na kutoa code execution hata wakati `boot_to` imeimarishwa. Inatumia heap overflow wakati wa chunked file transfers ili kutwaa DA2 control flow. Exploit hiyo iko hadharani kwenye Penumbra/mtk-payloads na inaonyesha kwamba fixes za Carbonara hazifungi attack surface yote ya DA.<sup>[[4]](#references)</sup>

## Maelezo ya triage na hardening

- Devices ambazo DA2 address/size hazijakaguliwa na DA1 inaendelea kuweka expected hash ikiwa writable ziko vulnerable. Ikiwa Preloader/DA ya baadaye inatekeleza address bounds au inaweka hash ikiwa immutable, Carbonara ime-mitigate.
- Kuwezesha DAA na kuhakikisha DA1/Preloader zinathibitisha BOOT_TO parameters (bounds + authenticity ya DA2) hufunga primitive hiyo. Kufunga hash patch pekee bila kuweka mipaka ya load bado kunaacha arbitrary write risk.

## References

- [1] [Carbonara: MediaTek exploit ambayo hakuna aliyeitumia](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Nyaraka za Carbonara exploit](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Source code ya Penumbra Carbonara](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: ku-exploit Download Agents za V6 zilizopatchiwa](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
