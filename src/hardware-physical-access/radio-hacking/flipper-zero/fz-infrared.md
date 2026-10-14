# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kwa maelezo zaidi kuhusu jinsi Infrared inavyofanya kazi, angalia:


{{#ref}}
../infrared.md
{{#endref}}

## Kipokezi cha Mawimbi ya IR katika Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero hutumia kipokezi cha IR kinachodemodulate ili kunasa mawimbi kutoka kwa rimoti za kawaida za IR. Baadhi ya simu, zikiwemo modeli fulani za Xiaomi, zina transmita ya IR, lakini nyingi haziwezi kupokea na kusimbua mawimbi ya rimoti.<sup>[[1]](#references)</sup>

**Kipokezi** cha infrared cha Flipper **kina usikivu mkubwa**. Unaweza hata **kunasa mawimbi** ukiwa **mahali fulani katikati** ya rimoti na TV. Si lazima kuelekeza rimoti moja kwa moja kwenye mlango wa IR wa Flipper. Hii husaidia mtu anapobadilisha chaneli akiwa karibu na TV, huku wewe na Flipper mkiwa mbali kiasi.

Usimbuaji wa protocol hufanyika kwenye software. Protocol zinazotambuliwa zinaweza kuhifadhiwa kama amri zilizosimbuliwa; protocol zisizotumika zinaweza kunaswa na kurudiwa kama data ghafi ya muda, kulingana na mipaka ya hardware ya masafa ya carrier na muda.<sup>[[1]](#references)</sup>

## Vitendo

### Rimoti za Universal

Hali ya Universal Remote ya Flipper Zero hupitia amri zinazojulikana katika hifadhidata yake ya infrared kwa TV, vifaa vya sauti, projectors na viyoyozi vinavyotumika. Haijahakikishwa kudhibiti kila kifaa, na inapaswa kutumiwa tu kwenye vifaa unavyomiliki au ambavyo umeidhinishwa kuvijaribu.<sup>[[1]](#references)</sup>

Inatosha kubonyeza kitufe cha kuwasha/kuzima katika hali ya Universal Remote, na Flipper itatuma **mfululizo amri za "Power Off"** za TV zote inazozijua: Sony, Samsung, Panasonic... na nyinginezo. TV inapopokea mawimbi yake, itayajibu na kuzimika.

Brute-force hii huchukua muda. Kadiri dictionary inavyokuwa kubwa, ndivyo itakavyochukua muda mrefu zaidi kukamilika. Haiwezekani kujua ni mawimbi gani hasa TV ilitambua kwa kuwa TV haitoi mrejesho.

### Jifunze Rimoti Mpya

Flipper Zero inaweza **kunasa mawimbi ya infrared**. IkItambua protocol na amri, huhifadhi uwakilishi uliosimbuliwa; la sivyo, inaweza kuhifadhi data ghafi ya muda kwa ajili ya kurudia baadaye.<sup>[[1]](#references)</sup>

## References

- [1] [Kudhibiti TV kwa kutumia Mlango wa Infrared wa Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
