# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kwa maelezo zaidi kuhusu jinsi Infrared inavyofanya kazi angalia:

{{#ref}}
../infrared.md
{{#endref}}

## IR Signal Receiver in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper inatumia mpokeaji wa ishara za IR wa dijitali TSOP, ambayo **inaruhusu kukamata ishara kutoka kwa IR remotes**. Kuna baadhi ya **smartphones** kama Xiaomi, ambazo pia zina bandari ya IR, lakini kumbuka kwamba **zaidi ya hizo zinaweza tu kutuma** ishara na **hazina uwezo wa kupokea** hizo.

Mpokeaji wa infrared wa Flipper **una hisia nyeti sana**. Unaweza hata **kukamata ishara** wakati unabaki **mahali fulani kati** ya remote na TV. Kuelekeza remote moja kwa moja kwenye bandari ya IR ya Flipper si lazima. Hii inakuwa muhimu wakati mtu anabadilisha vituo akiwa karibu na TV, na wewe na Flipper mpo mbali kidogo.

Kadri **ufafanuzi wa ishara za infrared** unavyofanyika upande wa **programu**, Flipper Zero ina uwezo wa **kupokea na kutuma nambari zozote za IR remote**. Katika kesi ya **protokali zisizojulikana** ambazo hazikuweza kutambuliwa - inarekodi na kurudisha **ishara ghafi kama ilivyopokelewa**.

## Actions

### Universal Remotes

Flipper Zero inaweza kutumika kama **remote ya ulimwengu mzima kudhibiti TV yoyote, kiyoyozi, au kituo cha media**. Katika hali hii, Flipper **inatumia nguvu** zote **za nambari zinazojulikana** za wazalishaji wote wanaoungwa mkono **kulingana na kamusi kutoka kwenye kadi ya SD**. Huna haja ya kuchagua remote maalum ili kuzima TV ya mgahawa.

Inatosha kubonyeza kitufe cha nguvu katika hali ya Universal Remote, na Flipper itatuma **kwa mpangilio "Power Off"** amri za TVs zote inazozijua: Sony, Samsung, Panasonic... na kadhalika. Wakati TV inapokea ishara yake, itajibu na kuzima.

Nafasi hiyo ya nguvu inachukua muda. Kamusi kubwa, itachukua muda mrefu kumaliza. Haiwezekani kujua ni ishara gani hasa TV ilitambua kwani hakuna mrejesho kutoka kwa TV.

### Learn New Remote

Inawezekana **kukamata ishara ya infrared** na Flipper Zero. Ikiwa **inatambua ishara katika hifadhidata** Flipper itajua moja kwa moja **ni kifaa gani hiki** na itakuruhusu kuingiliana nacho.\
Ikiwa haitakubali, Flipper inaweza **kuhifadhi** **ishara** na itakuruhusu **kuirudisha**.

## References

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
