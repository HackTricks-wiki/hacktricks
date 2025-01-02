# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)ni mchanganuzi wa ishara za dijiti bure kwa GNU/Linux na macOS, ulioandaliwa kutoa taarifa za ishara za redio zisizojulikana. Inasaidia vifaa mbalimbali vya SDR kupitia SoapySDR, na inaruhusu demodulation inayoweza kubadilishwa ya ishara za FSK, PSK na ASK, kufungua video za analojia, kuchambua ishara zenye mchanganyiko na kusikiliza vituo vya sauti vya analojia (yote kwa wakati halisi).

### Mipangilio ya Msingi

Baada ya kufunga kuna mambo machache ambayo unaweza kufikiria kuyapanga.\
Katika mipangilio (kitufe cha pili cha tab) unaweza kuchagua **kifaa cha SDR** au **chagua faili** kusoma na ni frequency ipi ya kusawazisha na kiwango cha Sampuli (inapendekezwa hadi 2.56Msps ikiwa PC yako inasaidia)\\

![](<../../images/image (245).png>)

Katika tabia ya GUI inapendekezwa kuwezesha mambo machache ikiwa PC yako inasaidia:

![](<../../images/image (472).png>)

> [!NOTE]
> Ikiwa unagundua kuwa PC yako haitoi mambo jaribu kuzima OpenGL na kupunguza kiwango cha sampuli.

### Matumizi

- Ili **kukamata muda wa ishara na kuichambua** tu shikilia kitufe "Push to capture" kwa muda wote unahitaji.

![](<../../images/image (960).png>)

- **Tuner** ya SigDigger husaidia **kukamata ishara bora** (lakini inaweza pia kuziharibu). Kwa kawaida anza na 0 na endelea **kuifanya iwe kubwa zaidi hadi** upate **kelele** inayotambulika kuwa **kubwa** kuliko **kuboresha ishara** unayohitaji).

![](<../../images/image (1099).png>)

### Sambaza na kituo cha redio

Na [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sambaza na kituo unachotaka kusikia, pangilia chaguo la "Baseband audio preview", pangilia upana wa bendi ili kupata taarifa zote zinazotumwa na kisha weka Tuner kwenye kiwango kabla ya kelele kuanza kuongezeka:

![](<../../images/image (585).png>)

## Hila za Kuvutia

- Wakati kifaa kinatuma mchanganyiko wa taarifa, kwa kawaida **sehemu ya kwanza itakuwa preamble** hivyo **huna** haja ya **kuhofia** ikiwa **hupati taarifa** hapo **au ikiwa kuna makosa**.
- Katika fremu za taarifa kwa kawaida unapaswa **kupata fremu tofauti zikiwa zimepangwa vizuri kati yao**:

![](<../../images/image (1076).png>)

![](<../../images/image (597).png>)

- **Baada ya kurejesha bits unapaswa kuzichakata kwa namna fulani**. Kwa mfano, katika codification ya Manchester up+down itakuwa 1 au 0 na down+up itakuwa nyingine. Hivyo, jozi za 1s na 0s (ups na downs) zitakuwa 1 halisi au 0 halisi.
- Hata kama ishara inatumia codification ya Manchester (haiwezekani kupata zaidi ya 0s au 1s mbili mfululizo), unaweza **kupata 1s au 0s kadhaa pamoja katika preamble**!

### Kufichua aina ya moduli kwa IQ

Kuna njia 3 za kuhifadhi taarifa katika ishara: Kurekebisha **amplitude**, **frequency** au **phase**.\
Ikiwa unachunguza ishara kuna njia tofauti za kujaribu kubaini ni ipi inatumika kuhifadhi taarifa (pata njia zaidi hapa chini) lakini moja nzuri ni kuangalia grafu ya IQ.

![](<../../images/image (788).png>)

- **Kugundua AM**: Ikiwa katika grafu ya IQ inaonekana kwa mfano **duka 2** (labda moja katika 0 na nyingine katika amplitude tofauti), inaweza kumaanisha kuwa hii ni ishara ya AM. Hii ni kwa sababu katika grafu ya IQ umbali kati ya 0 na duka ni amplitude ya ishara, hivyo ni rahisi kuona amplitudes tofauti zinazo tumika.
- **Kugundua PM**: Kama katika picha ya awali, ikiwa unapata mduka midogo isiyohusiana kati yao inaweza kumaanisha kuwa moduli ya awamu inatumika. Hii ni kwa sababu katika grafu ya IQ, pembe kati ya nukta na 0,0 ni awamu ya ishara, hivyo inamaanisha kuwa awamu 4 tofauti zinatumika.
- Kumbuka kwamba ikiwa taarifa imefichwa katika ukweli kwamba awamu inabadilishwa na sio katika awamu yenyewe, huwezi kuona awamu tofauti zikiwa zimejulikana wazi.
- **Kugundua FM**: IQ haina uwanja wa kutambua frequencies (umbali hadi katikati ni amplitude na pembe ni awamu).\
Kwa hivyo, ili kutambua FM, unapaswa **kuona kimsingi duara tu** katika grafu hii.\
Zaidi ya hayo, frequency tofauti "inawakilishwa" na grafu ya IQ kwa **kuongezeka kwa kasi katika duara** (hivyo katika SysDigger kuchagua ishara grafu ya IQ inajazwa, ikiwa unapata ongezeko au mabadiliko ya mwelekeo katika duara iliyoundwa inaweza kumaanisha kuwa hii ni FM):

## Mfano wa AM

{% file src="../../images/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Kufichua AM

#### Kuangalia envelope

Kuangalia taarifa za AM na [**SigDigger** ](https://github.com/BatchDrake/SigDigger)na kuangalia tu **envelop** unaweza kuona viwango tofauti vya amplitude. Ishara inayotumika inatuma mapigo yenye taarifa katika AM, hii ndiyo jinsi mapigo moja yanavyoonekana:

![](<../../images/image (590).png>)

Na hii ndiyo jinsi sehemu ya alama inavyoonekana na waveform:

![](<../../images/image (734).png>)

#### Kuangalia Histogram

Unaweza **kuchagua ishara nzima** ambapo taarifa inapatikana, chagua **Amplitude** mode na **Selection** na bonyeza **Histogram.** Unaweza kuona kuwa viwango 2 wazi vinapatikana tu

![](<../../images/image (264).png>)

Kwa mfano, ikiwa unachagua Frequency badala ya Amplitude katika ishara hii ya AM unapata frequency 1 tu (hakuna njia taarifa iliyorekebishwa katika frequency inatumia frequency 1 tu).

![](<../../images/image (732).png>)

Ikiwa unapata frequencies nyingi huenda hii isiwe FM, labda frequency ya ishara ilibadilishwa tu kwa sababu ya kituo.

#### Kwa IQ

Katika mfano huu unaweza kuona jinsi kuna **duara kubwa** lakini pia **pointi nyingi katikati.**

![](<../../images/image (222).png>)

### Pata Kiwango cha Alama

#### Kwa alama moja

Chagua alama ndogo zaidi unayoweza kupata (hivyo unahakikisha ni 1 tu) na angalia "Selection freq". Katika kesi hii itakuwa 1.013kHz (hivyo 1kHz).

![](<../../images/image (78).png>)

#### Kwa kundi la alama

Unaweza pia kuashiria idadi ya alama unazopanga kuchagua na SigDigger itakadiria frequency ya alama 1 (alama zaidi zilizochaguliwa bora zaidi labda). Katika hali hii nilichagua alama 10 na "Selection freq" ni 1.004 Khz:

![](<../../images/image (1008).png>)

### Pata Bits

Baada ya kugundua hii ni ishara ya **AM modulated** na **kasi ya alama** (na kujua kwamba katika kesi hii kitu chochote juu kinamaanisha 1 na kitu chochote chini kinamaanisha 0), ni rahisi sana **kupata bits** zilizowekwa katika ishara. Hivyo, chagua ishara yenye taarifa na pangilia sampuli na uamuzi na bonyeza sampuli (hakikisha kuwa **Amplitude** imechaguliwa, kasi iliyogunduliwa ya **Symbol rate** imepangiliwa na **Gadner clock recovery** imechaguliwa):

![](<../../images/image (965).png>)

- **Sync to selection intervals** inamaanisha kwamba ikiwa hapo awali umechagua vipindi ili kupata kasi ya alama, kasi hiyo ya alama itatumika.
- **Manual** inamaanisha kwamba kasi ya alama iliyotajwa itatumika
- Katika **Fixed interval selection** unaashiria idadi ya vipindi vinavyopaswa kuchaguliwa na inakadiria kasi ya alama kutoka hapo
- **Gadner clock recovery** kwa kawaida ndiyo chaguo bora, lakini bado unahitaji kuashiria baadhi ya kasi ya alama ya karibu.

Ukibonyeza sampuli hii inaonekana:

![](<../../images/image (644).png>)

Sasa, ili kufanya SigDigger kuelewa **wapi kuna kiwango** cha kiwango kinachobeba taarifa unahitaji kubonyeza kwenye **kiwango cha chini** na kudumisha kubonyeza hadi kiwango kikubwa zaidi:

![](<../../images/image (439).png>)

Ikiwa ingekuwa kwa mfano **viwango 4 tofauti vya amplitude**, unapaswa kuwa na mipangilio ya **Bits per symbol kuwa 2** na kuchagua kutoka ndogo hadi kubwa zaidi.

Hatimaye **kuongeza** **Zoom** na **kubadilisha saizi ya Row** unaweza kuona bits (na unaweza kuchagua yote na nakala ili kupata bits zote):

![](<../../images/image (276).png>)

Ikiwa ishara ina zaidi ya 1 bit kwa alama (kwa mfano 2), SigDigger haina **njia ya kujua ni alama ipi** 00, 01, 10, 11, hivyo itatumia **mifumo tofauti ya kijivu** kuwakilisha kila moja (na ikiwa unakopa bits itatumia **nambari kutoka 0 hadi 3**, utahitaji kuzitibu).

Pia, tumia **codifications** kama **Manchester**, na **up+down** inaweza kuwa **1 au 0** na down+up inaweza kuwa 1 au 0. Katika hali hizo unahitaji **kuzitibu ups zilizopatikana (1) na downs (0)** ili kubadilisha jozi za 01 au 10 kama 0s au 1s.

## Mfano wa FM

{% file src="../../images/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Kufichua FM

#### Kuangalia frequencies na waveform

Mfano wa ishara inayotuma taarifa iliyorekebishwa katika FM:

![](<../../images/image (725).png>)

Katika picha ya awali unaweza kuona vizuri kwamba **frequencies 2 zinatumika** lakini ikiwa unachunguza **waveform** huenda usiweze kutambua kwa usahihi frequencies 2 tofauti:

![](<../../images/image (717).png>)

Hii ni kwa sababu nilikamata ishara katika frequencies zote mbili, hivyo moja ni karibu na nyingine kwa hasi:

![](<../../images/image (942).png>)

Ikiwa frequency iliyosawazishwa iko **karibu na frequency moja kuliko nyingine** unaweza kwa urahisi kuona frequencies 2 tofauti:

![](<../../images/image (422).png>)

![](<../../images/image (488).png>)

#### Kuangalia histogram

Kuangalia histogram ya frequency ya ishara yenye taarifa unaweza kwa urahisi kuona ishara 2 tofauti:

![](<../../images/image (871).png>)

Katika kesi hii ikiwa unachunguza **Amplitude histogram** utapata **amplitude moja tu**, hivyo **haiwezi kuwa AM** (ikiwa unapata amplitudes nyingi huenda ni kwa sababu ishara imekuwa ikipoteza nguvu katika kituo):

![](<../../images/image (817).png>)

Na hii ingekuwa histogram ya awamu (ambayo inaonyesha wazi kuwa ishara haijarekebishwa katika awamu):

![](<../../images/image (996).png>)

#### Kwa IQ

IQ haina uwanja wa kutambua frequencies (umbali hadi katikati ni amplitude na pembe ni awamu).\
Kwa hivyo, ili kutambua FM, unapaswa **kuona kimsingi duara tu** katika grafu hii.\
Zaidi ya hayo, frequency tofauti "inawakilishwa" na grafu ya IQ kwa **kuongezeka kwa kasi katika duara** (hivyo katika SysDigger kuchagua ishara grafu ya IQ inajazwa, ikiwa unapata ongezeko au mabadiliko ya mwelekeo katika duara iliyoundwa inaweza kumaanisha kuwa hii ni FM):

![](<../../images/image (81).png>)

### Pata Kiwango cha Alama

Unaweza kutumia **mbinu ile ile iliyotumika katika mfano wa AM** kupata kiwango cha alama mara tu unapopata frequencies zinazobeba alama.

### Pata Bits

Unaweza kutumia **mbinu ile ile iliyotumika katika mfano wa AM** kupata bits mara tu umepata **ishara imejarekebishwa katika frequency** na **kasi ya alama**.

{{#include ../../banners/hacktricks-training.md}}
