# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

Mara kadhaa nyuma ya pazia inategemea **Host header** kufanya baadhi ya vitendo. Kwa mfano, inaweza kutumia thamani yake kama **domain ya kutuma upya nenosiri**. Hivyo unapopokea barua pepe yenye kiungo cha kurekebisha nenosiri lako, domain inayotumika ni ile uliyoweka katika Host header. Kisha, unaweza kuomba upya nenosiri wa watumiaji wengine na kubadilisha domain kuwa moja inayodhibitiwa na wewe ili kuiba nambari zao za kurekebisha nenosiri. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> Kumbuka kwamba inawezekana usihitaji hata kusubiri mtumiaji abonyeze kiungo cha kurekebisha nenosiri ili kupata token, kwani labda hata **filters za spam au vifaa/boti vingine vya kati vitabonyeza ili kuchambua**.

### Session booleans

Wakati mwingine unapokamilisha uthibitisho fulani kwa usahihi, nyuma ya pazia itachangia **boolean yenye thamani "True" kwa sifa ya usalama ya kikao chako**. Kisha, mwisho tofauti utaweza kujua kama umepita hiyo ukaguzi.\
Hata hivyo, ikiwa **umepita ukaguzi** na kikao chako kinapewa ile thamani "True" katika sifa ya usalama, unaweza kujaribu **kufikia rasilimali nyingine** ambazo **zinategemea sifa hiyo hiyo** lakini ambazo **hupaswi kuwa na ruhusa** za kufikia. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Register functionality

Jaribu kujiandikisha kama mtumiaji ambaye tayari yupo. Jaribu pia kutumia wahusika sawa (madoadoa, nafasi nyingi na Unicode).

### Takeover emails

Jiandikishe barua pepe, kabla ya kuithibitisha badilisha barua pepe, kisha, ikiwa barua pepe mpya ya uthibitisho itatumwa kwa barua pepe ya kwanza iliyosajiliwa, unaweza kuchukua barua pepe yoyote. Au ikiwa unaweza kuwezesha barua pepe ya pili kuthibitisha ile ya kwanza, unaweza pia kuchukua akaunti yoyote.

### Access Internal servicedesk of companies using atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE method

Wanda maendeleo wanaweza kusahau kuzima chaguzi mbalimbali za ufuatiliaji katika mazingira ya uzalishaji. Kwa mfano, njia ya HTTP `TRACE` imeundwa kwa madhumuni ya uchunguzi. Ikiwa imewezeshwa, seva ya wavuti itajibu maombi yanayotumia njia ya `TRACE` kwa kurudisha katika jibu ombi halisi lililopokelewa. Tabia hii mara nyingi haina madhara, lakini wakati mwingine husababisha kufichuliwa kwa taarifa, kama vile jina la vichwa vya uthibitishaji vya ndani ambavyo vinaweza kuongezwa kwa maombi na proxies za kinyume.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

{{#include ../banners/hacktricks-training.md}}
