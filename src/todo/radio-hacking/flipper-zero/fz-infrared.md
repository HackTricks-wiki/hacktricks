# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kwa maelezo zaidi kuhusu jinsi Infrared inavyofanya kazi, angalia:


{{#ref}}
../infrared.md
{{#endref}}

## Kipokezi cha IR Signal katika Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper hutumia kipokezi cha digital IR signal cha TSOP, ambacho **huruhusu kunasa signals kutoka kwenye IR remotes**. Kuna baadhi ya **smartphones** kama Xiaomi ambazo pia zina port ya IR, lakini kumbuka kwamba **nyingi kati yake zinaweza kutuma** signals pekee na **haziwezi kuzipokea**.<sup>[[1]](#references)</sup>

**Kipokezi cha infrared cha Flipper ni nyeti sana**. Unaweza hata **kunasa signal** ukiwa **mahali fulani kati** ya remote na TV. Si lazima uelekeze remote moja kwa moja kwenye port ya IR ya Flipper. Hii huwa muhimu mtu anapobadilisha channels akiwa amesimama karibu na TV, huku wewe na Flipper mkiwa mbali kwa kiasi fulani.

Kwa kuwa **decoding ya infrared** signal hufanyika upande wa **software**, Flipper Zero inaweza kinadharia kusaidia **kupokea na kutuma IR remote codes zozote**. Kwa protocols **zisizojulikana** ambazo hazikuweza kutambuliwa - **hurekodi na kucheza tena** raw signal kama ilivyopokelewa.<sup>[[1]](#references)</sup>

## Vitendo

### Universal Remotes

Flipper Zero inaweza kutumika kama **universal remote ya kudhibiti TV, air conditioner, au media center yoyote**. Katika mode hii, Flipper **hufanya bruteforce** ya **codes zote zinazojulikana** za manufacturers wote wanaoungwa mkono **kulingana na dictionary kutoka kwenye SD card**. Huhitaji kuchagua remote maalum ili kuzima TV ya restaurant.<sup>[[1]](#references)</sup>

Inatosha kubonyeza kitufe cha kuwasha/kuzima katika mode ya Universal Remote, na Flipper **itatuma kwa mfuatano commands za "Power Off"** za TV zote inazozijua: Sony, Samsung, Panasonic... na nyinginezo. TV inapopokea signal yake, itaitikia na kuzima.

Brute-force kama hii huchukua muda. Kadiri dictionary inavyokuwa kubwa, ndivyo itakavyochukua muda mrefu zaidi kumaliza. Haiwezekani kujua ni signal ipi hasa TV ilitambua kwa kuwa hakuna feedback kutoka kwenye TV.

### Jifunze Remote Mpya

Inawezekana **kunasa infrared signal** kwa kutumia Flipper Zero. Ikiwa **itaipata signal hiyo kwenye database**, Flipper **itajua kiotomatiki kifaa hicho ni kipi** na itakuruhusu kuingiliana nacho.\
Ikiwa haitapata, Flipper inaweza **kuhifadhi** **signal** hiyo na kukuruhusu **kuicheza tena**.<sup>[[1]](#references)</sup>

## Marejeo

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
