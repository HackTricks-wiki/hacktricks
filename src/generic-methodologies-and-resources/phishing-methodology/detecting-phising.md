# Kugundua Phishing

{{#include ../../banners/hacktricks-training.md}}

## Utangulizi

Ili kugundua jaribio la phishing ni muhimu **kuelewa mbinu za phishing zinazotumiwa leo**. Kwenye ukurasa wa mzazi wa chapisho hili, unaweza kupata taarifa hii, hivyo kama hujui ni mbinu zipi zinazotumiwa leo nakusihi uende kwenye ukurasa wa mzazi na usome angalau sehemu hiyo.

Chapisho hili linategemea wazo kwamba **washambuliaji watajaribu kwa namna fulani kuiga au kutumia jina la kikoa la mwathirika**. Ikiwa kikoa chako kinaitwa `example.com` na unapata phishing ukitumia jina la kikoa tofauti kabisa kwa sababu fulani kama `youwonthelottery.com`, mbinu hizi hazitakufichua.

## Mabadiliko ya majina ya kikoa

Ni rahisi **kufichua** jaribio hizo za **phishing** ambazo zitatumia jina la **kikoa linalofanana** ndani ya barua pepe.\
Inatosha **kuunda orodha ya majina ya phishing yanayoweza kutokea** ambayo mshambuliaji anaweza kutumia na **kuangalia** ikiwa yame **jiandikisha** au kuangalia ikiwa kuna **IP** inayotumia hilo.

### Kupata kikoa chenye shaka

Kwa kusudi hili, unaweza kutumia yoyote ya zana zifuatazo. Kumbuka kwamba zana hizi pia zitafanya maombi ya DNS kiotomatiki ili kuangalia ikiwa kikoa kina IP yoyote iliyotolewa:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Unaweza kupata maelezo mafupi ya mbinu hii kwenye ukurasa wa mzazi. Au soma utafiti wa asili katika** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Kwa mfano, mabadiliko ya bit 1 katika kikoa microsoft.com yanaweza kubadilisha kuwa _windnws.com._\
**Washambuliaji wanaweza kujiandikisha kwa majina mengi ya kikoa yanayohusiana na mwathirika ili kuwahamisha watumiaji halali kwenye miundombinu yao**.

**Majina yote ya kikoa yanayoweza kubadilishwa yanapaswa pia kufuatiliwa.**

### Ukaguzi wa Msingi

Mara tu unapokuwa na orodha ya majina ya kikoa yenye shaka unapaswa **kuangalia** (hasa bandari za HTTP na HTTPS) ili **kuona ikiwa wanatumia fomu ya kuingia inayofanana** na moja ya kikoa cha mwathirika.\
Unaweza pia kuangalia bandari 3333 kuona ikiwa iko wazi na inafanya kazi ya `gophish`.\
Ni muhimu pia kujua **umri wa kila kikoa chenye shaka kilichogunduliwa**, kadri inavyokuwa changa ndivyo inavyokuwa hatari zaidi.\
Unaweza pia kupata **picha za skrini** za ukurasa wa wavuti wa HTTP na/au HTTPS wenye shaka ili kuona ikiwa ni ya shaka na katika hali hiyo **ingia ili kuangalia kwa undani zaidi**.

### Ukaguzi wa Juu

Ikiwa unataka kwenda hatua moja mbele nakusihi **ufuatilie majina hayo ya kikoa yenye shaka na kutafuta zaidi** mara kwa mara (kila siku? inachukua sekunde/chache tu). Unapaswa pia **kuangalia** bandari **zilizofunguliwa** za IP zinazohusiana na **kutafuta mifano ya `gophish` au zana zinazofanana** (ndiyo, washambuliaji pia hufanya makosa) na **kufuatilia ukurasa wa wavuti wa HTTP na HTTPS wa majina ya kikoa yenye shaka na subdomains** ili kuona ikiwa wameiga fomu yoyote ya kuingia kutoka kwenye kurasa za wavuti za mwathirika.\
Ili **kujiandaa** kwa hili nakusihi uwe na orodha ya fomu za kuingia za majina ya kikoa ya mwathirika, spider ukurasa wa wavuti wenye shaka na kulinganisha kila fomu ya kuingia iliyopatikana ndani ya majina ya kikoa yenye shaka na kila fomu ya kuingia ya kikoa cha mwathirika kwa kutumia kitu kama `ssdeep`.\
Ikiwa umepata fomu za kuingia za majina ya kikoa yenye shaka, unaweza kujaribu **kutuma akidi za takataka** na **kuangalia ikiwa inakuhamisha kwenye kikoa cha mwathirika**.

## Majina ya kikoa yanayotumia maneno muhimu

Ukurasa wa mzazi pia unataja mbinu ya mabadiliko ya jina la kikoa ambayo inajumuisha kuweka **jina la kikoa la mwathirika ndani ya kikoa kikubwa** (kwa mfano, paypal-financial.com kwa paypal.com).

### Uwazi wa Cheti

Haiwezekani kuchukua mbinu ya awali ya "Brute-Force" lakini kwa kweli **inawezekana kufichua jaribio kama hilo la phishing** pia kwa shukrani kwa uwazi wa cheti. Kila wakati cheti kinapotolewa na CA, maelezo yanapatikana hadharani. Hii inamaanisha kwamba kwa kusoma uwazi wa cheti au hata kufuatilia, **inawezekana kupata majina ya kikoa yanayotumia neno muhimu ndani ya jina lake** Kwa mfano, ikiwa mshambuliaji anaunda cheti cha [https://paypal-financial.com](https://paypal-financial.com), kuona cheti kunawezekana kupata neno muhimu "paypal" na kujua kwamba barua pepe yenye shaka inatumika.

Chapisho [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) linapendekeza kwamba unaweza kutumia Censys kutafuta vyeti vinavyoathiri neno muhimu maalum na kuchuja kwa tarehe (vyeti "vipya" pekee) na kwa mtoaji wa CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Hata hivyo, unaweza kufanya "kile kile" kwa kutumia wavuti ya bure [**crt.sh**](https://crt.sh). Unaweza **kutafuta neno muhimu** na **kuchuja** matokeo **kwa tarehe na CA** ikiwa unataka.

![](<../../images/image (519).png>)

Kwa kutumia chaguo hili la mwisho unaweza hata kutumia uwanja wa Matching Identities kuona ikiwa kuna kitambulisho chochote kutoka kwenye kikoa halisi kinacholingana na chochote cha majina ya kikoa yenye shaka (kumbuka kwamba jina la kikoa lenye shaka linaweza kuwa la uwongo).

**Chaguo lingine** ni mradi mzuri unaoitwa [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream inatoa mtiririko wa wakati halisi wa vyeti vilivyoundwa hivi karibuni ambavyo unaweza kutumia kugundua maneno muhimu yaliyotajwa katika wakati (karibu) halisi. Kwa kweli, kuna mradi unaoitwa [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) ambao unafanya hivyo.

### **Majina mapya ya kikoa**

**Chaguo la mwisho** ni kukusanya orodha ya **majina mapya ya kikoa yaliyosajiliwa** kwa baadhi ya TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) inatoa huduma hiyo) na **kuangalia maneno muhimu katika majina haya ya kikoa**. Hata hivyo, majina marefu ya kikoa mara nyingi hutumia moja au zaidi ya subdomains, hivyo neno muhimu halitaonekana ndani ya FLD na huwezi kupata subdomain ya phishing.

{{#include ../../banners/hacktricks-training.md}}
