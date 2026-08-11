# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kwa maelezo zaidi kuhusu jinsi Infrared inavyofanya kazi, angalia:


{{#ref}}
../infrared.md
{{#endref}}

## Kipokeaji cha Mawimbi ya IR katika Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero hutumia kipokeaji cha IR cha demodulation kunasa mawimbi kutoka kwenye remote za kawaida za IR. Baadhi ya simu, zikiwemo modeli fulani za Xiaomi, zina transmitter ya IR, lakini nyingi haziwezi kupokea na kutafsiri mawimbi ya udhibiti wa remote.<sup>[[1]](#references)</sup>

**Kipokeaji cha infrared cha Flipper ni nyeti sana**. Unaweza hata **kunasa mawimbi** ukiwa **mahali fulani kati** ya remote na TV. Si lazima uelekeze remote moja kwa moja kwenye port ya IR ya Flipper. Hii huwa muhimu mtu anapobadilisha channel akiwa amesimama karibu na TV, huku wewe na Flipper mkiwa mbali kwa kiasi fulani.

Uchanganuzi wa protocol hufanyika kwenye software. Protocol zinazotambuliwa zinaweza kuhifadhiwa kama commands zilizotafsiriwa; protocol zisizotumika zinaweza kunaswa na kuchezwa tena kama raw timing data, kulingana na mipaka ya carrier-frequency na timing ya hardware.<sup>[[1]](#references)</sup>

## Vitendo

### Remote za Universal

Mode ya universal-remote ya Flipper Zero hupitia commands zinazojulikana kutoka kwenye infrared database yake kwa TV, vifaa vya sauti, projectors na air conditioners zinazotumika. Haihakikishiwi kudhibiti kila kifaa, na inapaswa kutumika tu kwenye vifaa unavyomiliki au ambavyo umeidhinishwa kuvifanyia majaribio.<sup>[[1]](#references)</sup>

Inatosha kubonyeza kitufe cha kuwasha/kuzima katika mode ya Universal Remote, na Flipper **itatuma kwa mfuatano commands za "Power Off"** za TV zote inazozijua: Sony, Samsung, Panasonic... na kadhalika. TV inapopokea mawimbi yake, itayajibu na kuzima.

Brute-force kama hii huchukua muda. Kadiri dictionary inavyokuwa kubwa, ndivyo itakavyochukua muda mrefu zaidi kumaliza. Haiwezekani kujua ni signal ipi hasa TV ilitambua kwa sababu hakuna feedback kutoka kwenye TV.

### Jifunze Remote Mpya

Flipper Zero inaweza **kunasa signal ya infrared**. Ikiitambua protocol na command, huhifadhi representation iliyotafsiriwa; vinginevyo, inaweza kuhifadhi raw timing data kwa ajili ya kuicheza tena baadaye.<sup>[[1]](#references)</sup>

## References

- [1] [Kudhibiti TV kwa kutumia Infrared Port ya Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
