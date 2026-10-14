# Redio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) ni kichanganuzi cha mawimbi ya dijitali cha bure kwa GNU/Linux na macOS, kilichoundwa ili kutoa taarifa kutoka kwa mawimbi ya redio yasiyojulikana. Kinaunga mkono vifaa vya SDR kupitia SoapySDR na hutoa zana za demodulation na uchanganuzi wa wakati halisi kwa FSK, PSK, ASK, video ya analogi, mawimbi ya burst na chaneli za sauti za analogi.<sup>[[1]](#references)</sup>

### Mipangilio ya Msingi

Baada ya kusakinisha, kuna mambo machache unayoweza kufikiria kusanidi.\
Katika mipangilio (kitufe cha kichupo cha pili), chagua **kifaa cha SDR** au faili ya ingizo, frequency ya kusikiliza na sample rate. Rate ya hadi 2.56 Msps inaweza kufaa ikiwa kifaa mwenyeji kinaiunga mkono.

![Mipangilio ya SigDigger inayoonyesha kifaa cha SDR, faili ya ingizo, frequency na chaguo za sample rate](<../../images/image (245).png>)

Katika tabia ya GUI, inashauriwa kuwezesha mambo machache ikiwa PC yako inayaunga mkono:

![SigDigger - Mipangilio ya Msingi: Katika tabia ya GUI, inashauriwa kuwezesha mambo machache ikiwa PC yako inayaunga mkono](<../../images/image (472).png>)

> [!TIP]
> Ukigundua kuwa PC yako hairekodi data, jaribu kuzima OpenGL na kupunguza sample rate.

### Matumizi

- Ili **kunasa sehemu ya muda wa mawimbi na kuichanganua**, shikilia kitufe cha "Push to capture" kwa muda unaohitaji.

![Mipangilio ya Msingi - Matumizi: Ili kunasa sehemu ya muda wa mawimbi na kuichanganua, shikilia kitufe cha "Push to capture" kwa muda unaohitaji](<../../images/image (960).png>)

- **Tuner** ya SigDigger husaidia **kunasa mawimbi bora** (lakini pia inaweza kuyaharibu). Ni bora kuanza na 0 na kuendelea **kuongeza thamani yake hadi** kelele inayoletwa iwe **kubwa zaidi** kuliko **uboreshaji wa mawimbi** unaohitaji.

![Kidhibiti cha tuner cha SigDigger kimewekwa ili kuboresha mawimbi ya redio yaliyonaswa](<../../images/image (1099).png>)

### Kusawazisha na chaneli ya redio

Ukitumia [**SigDigger** ](https://github.com/BatchDrake/SigDigger), sawazisha na chaneli unayotaka kusikiliza, sanidi chaguo la "Baseband audio preview", sanidi bandwidth ili kupata taarifa zote zinazotumwa, kisha weka Tuner kwenye kiwango kabla kelele haijaanza kuongezeka sana:<sup>[[1]](#references)</sup>

![Chaneli ya redio iliyosawazishwa kwenye SigDigger, ikiwa na baseband audio preview na bandwidth iliyosanidiwa](<../../images/image (585).png>)

## Mbinu za kuvutia

- Kifaa kinapotuma burst za taarifa, kwa kawaida **sehemu ya kwanza huwa preamble**, kwa hiyo **usijali** ikiwa **hupati taarifa** humo **au kuna makosa**.
- Katika fremu za taarifa, kwa kawaida unapaswa **kupata fremu tofauti zilizopangiliwa vizuri zilingane**:

![Kusawazisha na chaneli ya redio - Mbinu za kuvutia: Katika fremu za taarifa, kwa kawaida unapaswa kupata fremu tofauti zilizopangiliwa vizuri zilingane](<../../images/image (1076).png>)

![Kusawazisha na chaneli ya redio - Mbinu za kuvutia: Katika fremu za taarifa, kwa kawaida unapaswa kupata fremu tofauti zilizopangiliwa vizuri zilingane](<../../images/image (597).png>)

- **Baada ya kurejesha mabadiliko ya viwango, huenda ukahitaji kuyadekodi.** Kwa Manchester encoding, mwelekeo mmoja wa mabadiliko unawakilisha `0` na mwelekeo ulio kinyume unawakilisha `1`; polarity halisi hutegemea kanuni inayotumika.
- Preamble inaweza kuwa na mfululizo wa viwango vilivyosampuliwa vilivyo sawa hata kama payload inatumia Manchester encoding, kwa hiyo tambua mpaka wa fremu kabla ya kuidikodi.

### Kutambua aina ya modulation kwa kutumia IQ

Kuna njia 3 za kuhifadhi taarifa katika mawimbi: kubadilisha **amplitude**, **frequency** au **phase**.\
Unapochunguza mawimbi, kuna njia tofauti za kujaribu kubaini kinachotumika kuhifadhi taarifa (angalia njia zaidi hapa chini), lakini njia nzuri ni kuangalia grafu ya IQ.

![Grafu ya IQ ya SigDigger inayotumika kutambua kama mawimbi yanatumia amplitude, frequency au phase modulation](<../../images/image (788).png>)

- **Kutambua AM**: Ikiwa grafu ya IQ inaonyesha, kwa mfano, **duara 2** (huenda moja liko kwenye 0 na jingine kwenye amplitude tofauti), huenda hii ni mawimbi ya AM. Hii ni kwa sababu kwenye grafu ya IQ umbali kati ya 0 na duara ni amplitude ya mawimbi, hivyo ni rahisi kuona amplitude tofauti zinazotumika.
- **Kutambua PM**: Kama ilivyo kwenye picha iliyotangulia, ukiona miduara midogo isiyohusiana, huenda inatumika phase modulation. Hii ni kwa sababu kwenye grafu ya IQ, pembe kati ya nukta na 0,0 ndiyo phase ya mawimbi, kwa hiyo ina maana kuwa phase 4 tofauti zinatumika.
  - Kumbuka kuwa ikiwa taarifa imefichwa kwenye ukweli kwamba phase inabadilishwa, badala ya kuwa kwenye phase yenyewe, hutaona phase tofauti zikitofautiana kwa uwazi.
- **Kutambua FM**: IQ haina sehemu ya kutambua frequencies (umbali kutoka katikati ni amplitude na pembe ni phase).\
  Kwa hiyo, ili kutambua FM, kwenye grafu hii unapaswa **kuona duara tu kwa kiasi kikubwa**.\
  Zaidi ya hayo, frequency offset hubadilisha kasi ya mzunguko kuzunguka duara la IQ. Kwa hiyo, kwenye SigDigger, mabadiliko ya kasi au mwelekeo wa mzunguko yanaweza kuonyesha FM.

## Mfano wa AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Kutambua AM

#### Kuchunguza envelope

Unapokagua data ya AM kwa [**SigDigger**](https://github.com/BatchDrake/SigDigger), **envelope** ya mawimbi inaweza kuonyesha viwango tofauti vya amplitude. Mawimbi ya mfano hutuma taarifa kama mipigo iliyomoduliwa kwa amplitude; mpigo mmoja unaonekana hivi:<sup>[[1]](#references)</sup>

![Envelope ya mawimbi ya AM kwenye SigDigger yenye viwango vya amplitude vya mipigo vilivyo wazi](<../../images/image (590).png>)

Na hivi ndivyo sehemu ya symbol inavyoonekana pamoja na waveform:

![Kutambua AM - Kuchunguza envelope: Hivi ndivyo sehemu ya symbol inavyoonekana pamoja na waveform](<../../images/image (734).png>)

#### Kuchunguza Histogram

Unaweza **kuchagua mawimbi yote** yenye taarifa, kuchagua hali ya **Amplitude** na **Selection**, kisha kubofya **Histogram**. Unaweza kuona kuwa kuna viwango 2 vilivyo wazi pekee.

![Histogram ya amplitude ya SigDigger inayoonyesha viwango viwili vilivyo wazi kwa mawimbi ya AM yaliyochaguliwa](<../../images/image (264).png>)

Kwa mfano, ukichagua Frequency badala ya Amplitude katika mawimbi haya ya AM, utapata frequency 1 tu (haiwezekani taarifa iliyomoduliwa kwenye frequency itumie frequency 1 tu).

![Histogram ya frequency ya SigDigger kwa mawimbi ya AM inayoonyesha frequency moja](<../../images/image (732).png>)

Ukipata frequencies nyingi, huenda haya si mawimbi ya FM; huenda frequency ya mawimbi ilibadilika tu kwa sababu ya chaneli.

#### Kwa kutumia IQ

Katika mfano huu unaweza kuona kuna **duara kubwa**, lakini pia **nukta nyingi katikati**.

![Kuchunguza Histogram - Kwa kutumia IQ: Katika mfano huu unaweza kuona kuwa kuna duara kubwa, lakini pia nukta nyingi katikati](<../../images/image (222).png>)

### Kupata Symbol Rate

#### Kwa kutumia symbol moja

Chagua kipindi kifupi zaidi chenye symbol moja kwa uwazi na uangalie **Selection freq**. Katika mfano huu ni 1.013 kHz, takribani 1 kHz.

![Kupata Symbol Rate - Kwa kutumia symbol moja: Chagua kipande kifupi zaidi chenye symbol moja unachoweza kupata (ili uhakikishe ni moja tu) na uangalie "Selection freq". Katika mfano huu ni 1.013 kHz (yaani 1 kHz).](<../../images/image (78).png>)

#### Kwa kutumia kundi la symbols

Unaweza pia kubainisha idadi ya symbols utakazochagua, na SigDigger itakokotoa frequency ya symbol 1 (huenda symbols nyingi zaidi zikatoa matokeo bora). Katika mfano huu nilichagua symbols 10 na "Selection freq" ni 1.004 kHz:

![Hesabu ya symbol rate kwenye SigDigger kwa kutumia kundi teule la symbols kumi](<../../images/image (1008).png>)

### Kupata Bits

Baada ya kutambua AM na kukadiria **symbol rate**, chagua eneo la mawimbi, sanidi amplitude sampling na viwango vya uamuzi, chagua **Gardner clock recovery**, kisha ubonyeze **Sample**:

![Paneli ya Get Bits ya SigDigger ikiwa imesanidiwa kwa AM sampling, symbol rate na Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** humaanisha kuwa ikiwa awali ulichagua vipindi ili kupata symbol rate, symbol rate hiyo itatumika.
- **Manual** humaanisha kuwa symbol rate iliyoonyeshwa ndiyo itatumika.
- Katika **Fixed interval selection**, unaonyesha idadi ya vipindi vitakavyochaguliwa na kisha symbol rate huhesabiwa kutokana navyo.
- **Gardner clock recovery** ni chaguo-msingi linalofaa, lakini bado linahitaji symbol rate ya takribani.

Ukibonyeza Sample, hiki ndicho kinachoonekana:

![Kwa kutumia kundi la symbols - Kupata Bits: Hiki ndicho kinachoonekana unapobonyeza Sample](<../../images/image (644).png>)

Sasa, ili SigDigger itambue **eneo la viwango** vinavyobeba taarifa, bofya **kiwango cha chini** na uendelee kushikilia huku ukisogeza hadi kwenye kiwango cha juu zaidi:

![Uteuzi wa eneo la viwango kwenye SigDigger kutoka kiwango cha chini cha amplitude hadi kiwango cha juu](<../../images/image (439).png>)

Kama kungekuwa na, kwa mfano, **viwango 4 tofauti vya amplitude**, ungelazimika kuweka **Bits per symbol kuwa 2** na kuchagua kutoka kiwango cha chini zaidi hadi cha juu zaidi.

Hatimaye, **ukikuza** kwa kutumia **Zoom** na **kubadilisha Row size**, unaweza kuona bits (na unaweza kuchagua zote na kunakili ili kupata bits zote):

![Kwa kutumia kundi la symbols - Kupata Bits: Hatimaye, ukikuza kwa kutumia Zoom na kubadilisha Row size, unaweza kuona bits (na unaweza kuchagua zote na kunakili ili kupata bits zote)](<../../images/image (276).png>)

Ikiwa mawimbi yana zaidi ya bit 1 kwa symbol (kwa mfano 2), SigDigger **haiwezi kujua ni symbol ipi** ni 00, 01, 10 au 11, kwa hiyo itatumia **viwango tofauti vya kijivu** kuwakilisha kila moja (na ukinakili bits, itatumia **namba kutoka 0 hadi 3**, ambazo utahitaji kuzishughulikia).

Kwa line encoding kama **Manchester**, geuza kila jozi halali ya mabadiliko (`01` au `10`) kuwa data bit kulingana na kanuni inayotumiwa na itifaki.

## Mfano wa FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Kutambua FM

#### Kuchunguza frequencies na waveform

Mfano wa mawimbi yanayotuma taarifa iliyomoduliwa kwa FM:

![Kutambua FM - Kuchunguza frequencies na waveform: Mfano wa mawimbi yanayotuma taarifa iliyomoduliwa kwa FM](<../../images/image (725).png>)

Spectrum inaonyesha wazi **frequencies mbili**, ingawa huenda ikawa vigumu kuzitofautisha kwenye waveform ya time-domain:

![Waveform ya FM ya SigDigger ambapo ni vigumu kutofautisha frequencies hizo mbili moja kwa moja](<../../images/image (717).png>)

Hii hutokea kwa sababu capture imewekwa katikati ya frequencies zote mbili, kwa hiyo frequency offsets zake zinakaribia kuwa kinyume:

![Capture ya FM ya SigDigger inayoonyesha frequencies hizo mbili zikiwa na thamani zinazokaribia kuwa kinyume](<../../images/image (942).png>)

Ikiwa frequency iliyosawazishwa **iko karibu zaidi na frequency moja kuliko nyingine**, unaweza kuona kwa urahisi frequencies 2 tofauti:

![Kutambua FM - Kuchunguza frequencies na waveform: Ikiwa frequency iliyosawazishwa iko karibu zaidi na frequency moja kuliko nyingine, unaweza kuona kwa urahisi frequencies 2 tofauti](<../../images/image (422).png>)

![Kutambua FM - Kuchunguza frequencies na waveform: Ikiwa frequency iliyosawazishwa iko karibu zaidi na frequency moja kuliko nyingine, unaweza kuona kwa urahisi frequencies 2 tofauti](<../../images/image (488).png>)

#### Kuchunguza histogram

Ukichunguza histogram ya frequency ya mawimbi yenye taarifa, unaweza kuona kwa urahisi mawimbi 2 tofauti:

![Kuchunguza frequencies na waveform - Kuchunguza histogram: Ukichunguza histogram ya frequency ya mawimbi yenye taarifa, unaweza kuona kwa urahisi mawimbi 2 tofauti](<../../images/image (871).png>)

Katika hali hii, ukichunguza **Amplitude histogram**, utapata **amplitude moja tu**, kwa hiyo **hayawezi kuwa mawimbi ya AM** (ukipata amplitudes nyingi, huenda ni kwa sababu mawimbi yalipoteza nguvu yalipopitia kwenye chaneli):

![Amplitude histogram ya SigDigger kwa mawimbi ya FM inayoonyesha kiwango kimoja cha amplitude](<../../images/image (817).png>)

Na hii ndiyo histogram ya phase (inayoonyesha wazi kuwa mawimbi hayajamoduliwa kwa phase):

![Kuchunguza frequencies na waveform - Kuchunguza histogram: Hii ndiyo histogram ya phase (inayoonyesha wazi kuwa mawimbi hayajamoduliwa kwa phase)](<../../images/image (996).png>)

#### Kwa kutumia IQ

IQ haina sehemu ya kutambua frequencies (umbali kutoka katikati ni amplitude na pembe ni phase).\
Kwa hiyo, ili kutambua FM, kwenye grafu hii unapaswa **kuona duara tu kwa kiasi kikubwa**.\
Zaidi ya hayo, frequency offset hubadilisha kasi ya mzunguko kuzunguka duara la IQ. Kwa hiyo, kwenye SigDigger, mabadiliko ya kasi au mwelekeo wa mzunguko yanaweza kuonyesha FM:

![Grafu ya IQ ya SigDigger ambapo FM huonekana kama mabadiliko ya kasi ya mzunguko kuzunguka duara](<../../images/image (81).png>)

### Kupata Symbol Rate

Unaweza kutumia **mbinu ileile iliyotumika kwenye mfano wa AM** kupata symbol rate baada ya kupata frequencies zinazobeba symbols.

### Kupata Bits

Unaweza kutumia **mbinu ileile iliyotumika kwenye mfano wa AM** kupata bits baada ya **kubaini kuwa mawimbi yamemoduliwa kwa frequency** na kupata **symbol rate**.

## References

- [1] [SigDigger - Kichanganuzi cha mawimbi ya dijitali cha bure kwa GNU/Linux na macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
