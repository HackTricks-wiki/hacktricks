# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

## Threat Modeling

Karibu kwenye mwongozo wa kina wa HackTricks kuhusu Threat Modeling! Anza uchunguzi wa kipengele hiki muhimu cha usalama wa mtandao, ambapo tunatambua, kuelewa, na kupanga mikakati dhidi ya udhaifu unaoweza kutokea katika mfumo. Thread hii inatoa mwongozo wa hatua kwa hatua uliojaa mifano halisi, programu za kusaidia, na maelezo rahisi kueleweka. Inafaa kwa wapya na wataalamu wenye uzoefu wanaotafuta kuimarisha ulinzi wao wa usalama wa mtandao.

### Commonly Used Scenarios

1. **Software Development**: Kama sehemu ya Mzunguko wa Maisha ya Maendeleo ya Programu Salama (SSDLC), threat modeling husaidia katika **kutambua vyanzo vya udhaifu** katika hatua za awali za maendeleo.
2. **Penetration Testing**: Mfumo wa Kiwango cha Utekelezaji wa Upenyo (PTES) unahitaji **threat modeling ili kuelewa udhaifu wa mfumo** kabla ya kufanya mtihani.

### Threat Model in a Nutshell

Threat Model kwa kawaida inawakilishwa kama mchoro, picha, au aina nyingine ya uwasilishaji wa kuona unaoonyesha usanifu uliopangwa au ujenzi wa sasa wa programu. Inafanana na **data flow diagram**, lakini tofauti kuu iko katika muundo wake unaolenga usalama.

Threat models mara nyingi hujumuisha vipengele vilivyotajwa kwa rangi nyekundu, vinavyowakilisha udhaifu, hatari, au vizuizi vinavyoweza kutokea. Ili kurahisisha mchakato wa kutambua hatari, triad ya CIA (Usiri, Uaminifu, Upatikanaji) inatumika, ik forming msingi wa mbinu nyingi za threat modeling, huku STRIDE ikiwa moja ya maarufu zaidi. Hata hivyo, mbinu iliyochaguliwa inaweza kutofautiana kulingana na muktadha maalum na mahitaji.

### The CIA Triad

Triad ya CIA ni mfano unaotambulika sana katika uwanja wa usalama wa habari, ikisimama kwa Usiri, Uaminifu, na Upatikanaji. Nguzo hizi tatu zinaunda msingi ambao hatua nyingi za usalama na sera zimejengwa, ikiwa ni pamoja na mbinu za threat modeling.

1. **Usiri**: Kuhakikisha kwamba data au mfumo haupatikani kwa watu wasioidhinishwa. Hii ni kipengele cha kati cha usalama, kinachohitaji udhibiti sahihi wa ufikiaji, usimbaji, na hatua nyingine za kuzuia uvunjaji wa data.
2. **Uaminifu**: Usahihi, uthabiti, na kuaminika kwa data katika mzunguko wake wa maisha. Kanuni hii inahakikisha kwamba data haibadilishwi au kuingiliwa na wahusika wasioidhinishwa. Mara nyingi inahusisha checksums, hashing, na mbinu nyingine za uthibitishaji wa data.
3. **Upatikanaji**: Hii inahakikisha kwamba data na huduma zinapatikana kwa watumiaji walioidhinishwa wanapohitajika. Hii mara nyingi inahusisha redundancy, uvumilivu wa makosa, na usanifu wa upatikanaji wa juu ili kuweka mifumo ikifanya kazi hata wakati wa usumbufu.

### Threat Modeling Methodlogies

1. **STRIDE**: Iliyotengenezwa na Microsoft, STRIDE ni kifupi cha **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege**. Kila kundi linawakilisha aina ya tishio, na mbinu hii hutumiwa mara nyingi katika hatua ya kubuni ya programu au mfumo ili kutambua vitisho vinavyoweza kutokea.
2. **DREAD**: Hii ni mbinu nyingine kutoka Microsoft inayotumika kwa tathmini ya hatari ya vitisho vilivyotambuliwa. DREAD inasimama kwa **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability**. Kila moja ya mambo haya inapata alama, na matokeo yake yanatumika kuipa kipaumbele vitisho vilivyotambuliwa.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Hii ni mbinu ya hatua saba, **risk-centric**. Inajumuisha kufafanua na kutambua malengo ya usalama, kuunda upeo wa kiufundi, uharibifu wa programu, uchambuzi wa vitisho, uchambuzi wa udhaifu, na tathmini ya hatari/triage.
4. **Trike**: Hii ni mbinu inayotegemea hatari inayolenga kulinda mali. Inaanza kutoka mtazamo wa **risk management** na inatazama vitisho na udhaifu katika muktadha huo.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Mbinu hii inalenga kuwa rahisi zaidi na kuunganishwa katika mazingira ya maendeleo ya Agile. Inachanganya vipengele kutoka mbinu nyingine na inazingatia **uwakilishi wa kuona wa vitisho**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Iliyotengenezwa na Kituo cha Uratibu cha CERT, mfumo huu unalenga **tathmini ya hatari ya shirika badala ya mifumo au programu maalum**.

## Tools

Kuna zana kadhaa na suluhisho za programu zinazopatikana ambazo zinaweza **kusaidia** katika kuunda na kusimamia threat models. Hapa kuna chache unazoweza kuzingatia.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Zana ya kisasa ya GUI ya wavuti ya kuvunja/mchambuzi wa wavuti kwa wataalamu wa usalama wa mtandao. Spider Suite inaweza kutumika kwa ramani na uchambuzi wa uso wa shambulio.

**Usage**

1. Chagua URL na Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Tazama Mchoro

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Mradi wa chanzo wazi kutoka OWASP, Threat Dragon ni programu ya wavuti na desktop ambayo inajumuisha uchoraji wa mifumo pamoja na injini ya sheria za kuunda vitisho/mipango kiotomatiki.

**Usage**

1. Unda Mradi Mpya

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Wakati mwingine inaweza kuonekana kama hii:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Anzisha Mradi Mpya

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Hifadhi Mradi Mpya

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Unda mfano wako

Unaweza kutumia zana kama SpiderSuite Crawler kukupa inspiration, mfano wa msingi ungeweza kuonekana kama hii

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Tu kidogo ya maelezo kuhusu viumbe:

- Mchakato (Kiumbe chenyewe kama vile Webserver au kazi ya wavuti)
- Mchezaji (Mtu kama vile Mtembezi wa Tovuti, Mtumiaji au Msimamizi)
- Mstari wa Mtiririko wa Data (Kiashiria cha Maingiliano)
- Mpaka wa Kuaminika (Sehemu tofauti za mtandao au upeo.)
- Hifadhi (Mambo ambapo data zinahifadhiwa kama vile Maktaba)

5. Unda Tishio (Hatua 1)

Kwanza unapaswa kuchagua safu unayotaka kuongeza tishio

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Sasa unaweza kuunda tishio

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Kumbuka kwamba kuna tofauti kati ya Vitisho vya Mchezaji na Vitisho vya Mchakato. Ikiwa ungeongeza tishio kwa Mchezaji basi utaweza kuchagua tu "Spoofing" na "Repudiation". Hata hivyo katika mfano wetu tunaongeza tishio kwa kiumbe cha Mchakato hivyo tutaona hii katika kisanduku cha uundaji wa tishio:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Imekamilika

Sasa mfano wako wa kumaliza unapaswa kuonekana kama hii. Na hivi ndivyo unavyofanya mfano rahisi wa tishio na OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Hii ni zana ya bure kutoka Microsoft inayosaidia katika kutafuta vitisho katika hatua ya kubuni ya miradi ya programu. Inatumia mbinu ya STRIDE na inafaa hasa kwa wale wanaoendeleza kwenye stack ya Microsoft.


{{#include ../banners/hacktricks-training.md}}
