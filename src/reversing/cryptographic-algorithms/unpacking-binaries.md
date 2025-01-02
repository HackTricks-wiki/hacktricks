{{#include ../../banners/hacktricks-training.md}}

# Kutambua binaries zilizofungwa

- **ukosefu wa nyuzi**: Ni kawaida kukutana na binaries zilizofungwa ambazo hazina karibu nyuzi yoyote
- Kuna **nyuzi nyingi zisizotumika**: Pia, wakati malware inatumia aina fulani ya pakka ya kibiashara ni kawaida kukutana na nyuzi nyingi zisizo na marejeo. Hata kama nyuzi hizi zipo, hiyo haimaanishi kwamba binary haijafungwa.
- Unaweza pia kutumia zana fulani kujaribu kubaini ni pakka gani ilitumika kufunga binary:
- [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
- [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
- [Language 2000](http://farrokhi.net/language/)

# Mapendekezo Msingi

- **Anza** kuchambua binary iliyofungwa **kutoka chini katika IDA na kuhamia juu**. Unpackers huondoka mara tu msimbo uliofunguliwa unapoondoka, hivyo ni vigumu kwa unpacker kuhamasisha utekelezaji kwa msimbo uliofunguliwa mwanzoni.
- Tafuta **JMP's** au **CALLs** kwa **registers** au **mikoa** ya **kumbukumbu**. Pia tafuta **kazi zinazoshinikiza hoja na mwelekeo wa anwani kisha kuita `retn`**, kwa sababu kurudi kwa kazi katika kesi hiyo kunaweza kuita anwani iliyoshinikizwa tu kwenye stack kabla ya kuitwa.
- Weka **breakpoint** kwenye `VirtualAlloc` kwani hii inatoa nafasi katika kumbukumbu ambapo programu inaweza kuandika msimbo uliofunguliwa. "Endesha hadi msimbo wa mtumiaji" au tumia F8 ili **kupata thamani ndani ya EAX** baada ya kutekeleza kazi na "**fuata anwani hiyo katika dump**". Hujui kama hiyo ndiyo mkoa ambapo msimbo uliofunguliwa utaokolewa.
- **`VirtualAlloc`** ikiwa na thamani "**40**" kama hoja inamaanisha Soma+Andika+Tekeleza (msimbo fulani unaohitaji utekelezaji utaandikwa hapa).
- **Wakati wa kufungua** msimbo ni kawaida kukutana na **kuita kadhaa** kwa **operesheni za hesabu** na kazi kama **`memcopy`** au **`Virtual`**`Alloc`. Ikiwa unajikuta katika kazi ambayo kwa wazi inafanya tu operesheni za hesabu na labda `memcopy`, mapendekezo ni kujaribu **kupata mwisho wa kazi** (labda JMP au wito kwa register fulani) **au** angalau **kuitwa kwa kazi ya mwisho** na kuendesha hadi hapo kwani msimbo si wa kuvutia.
- Wakati wa kufungua msimbo **kumbuka** kila wakati unapobadilisha **mkoa wa kumbukumbu** kwani mabadiliko ya mkoa wa kumbukumbu yanaweza kuashiria **kuanza kwa msimbo wa kufungua**. Unaweza kwa urahisi dump mkoa wa kumbukumbu ukitumia Process Hacker (process --> properties --> memory).
- Wakati wa kujaribu kufungua msimbo njia nzuri ya **kujua kama tayari unafanya kazi na msimbo uliofunguliwa** (hivyo unaweza tu kuudump) ni **kuangalia nyuzi za binary**. Ikiwa katika hatua fulani unafanya jump (labda kubadilisha mkoa wa kumbukumbu) na unagundua kwamba **nyuzi nyingi zaidi zimeongezwa**, basi unaweza kujua **unafanya kazi na msimbo uliofunguliwa**.\
Hata hivyo, ikiwa pakka tayari ina nyuzi nyingi unaweza kuona ni nyuzi ngapi zina neno "http" na kuona ikiwa nambari hii inaongezeka.
- Unapodump executable kutoka mkoa wa kumbukumbu unaweza kurekebisha baadhi ya vichwa kwa kutumia [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).

{{#include ../../banners/hacktricks-training.md}}
