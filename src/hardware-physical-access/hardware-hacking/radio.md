# Redio

{{#include ../../banners/hacktricks-training.md}}

Kwa kazi mahususi za itifaki baada ya kutambua ishara, tazama [majaribio ya RFID/NFC, sub-GHz, infrared, BLE, na LoRaWAN](../radio-hacking/README.md).

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) ni kichanganuzi huria cha ishara za kidijitali kwa GNU/Linux na macOS, kilichoundwa kutoa taarifa kutoka kwa ishara za redio zisizojulikana. Kinaunga mkono vifaa vya SDR kupitia SoapySDR na hutoa zana za demodulation na uchanganuzi wa wakati halisi kwa FSK, PSK, ASK, video ya analogi, ishara za mipasuko, na chaneli za sauti za analogi.<sup>[[1]](#references)</sup>

### Mipangilio ya Msingi

Baada ya kusakinisha, kuna mambo kadhaa unayoweza kufikiria kusanidi.\
Katika mipangilio (kitufe cha kichupo cha pili), chagua **kifaa cha SDR** au faili ya ingizo, masafa ya kurekebisha, na kiwango cha sampuli. Kiwango cha hadi 2.56 Msps kinaweza kufaa ikiwa mfumo mwenyeji unakiunga mkono.

![Mipangilio ya SigDigger inayoonyesha kifaa cha SDR, faili ya ingizo, masafa na chaguo za kiwango cha sampuli](<../../images/image (245).png>)

Katika tabia ya GUI, inapendekezwa kuwasha baadhi ya vitu ikiwa PC yako inaviunga mkono:

![SigDigger - Mipangilio ya Msingi: Katika tabia ya GUI, inapendekezwa kuwasha baadhi ya vitu ikiwa PC yako inaviunga mkono](<../../images/image (472).png>)

> [!TIP]
> Ukigundua kuwa PC yako hainasa vitu, jaribu kuzima OpenGL na kupunguza kiwango cha sampuli.

### Matumizi

- Ili **kunasa ishara kwa muda na kuichanganua**, shikilia kitufe cha "Push to capture" kwa muda unaohitaji.

![Mipangilio ya Msingi - Matumizi: Ili kunasa ishara kwa muda na kuichanganua, shikilia kitufe cha "Push to capture" kwa muda unaohitaji](<../../images/image (960).png>)

- **Tuner** ya SigDigger husaidia **kunasa ishara bora zaidi** (lakini inaweza pia kuzidhoofisha). Ni vyema kuanza na 0 na kuendelea **kuiongeza hadi** kelele **inayoletwa** iwe **kubwa zaidi** kuliko **uboreshaji wa ishara** unaohitaji).

![Kidhibiti cha tuner cha SigDigger kimewekwa ili kuboresha ishara ya redio iliyonaswa](<../../images/image (1099).png>)

### Kusawazisha na chaneli ya redio

Kwa kutumia [**SigDigger** ](https://github.com/BatchDrake/SigDigger), sawazisha na chaneli unayotaka kusikiliza, sanidi chaguo la "Baseband audio preview", weka kipimo data ili kupata taarifa zote zinazotumwa kisha weka Tuner kwenye kiwango kilicho kabla ya kelele kuanza kuongezeka sana:<sup>[[1]](#references)</sup>

![Chaneli ya redio iliyosawazishwa kwenye SigDigger ikiwa na Baseband audio preview na kipimo data vilivyosaniwa](<../../images/image (585).png>)

## Mbinu za kuvutia

- Kifaa kinapotuma mipasuko ya taarifa, kwa kawaida **sehemu ya kwanza huwa preamble**, kwa hiyo **usijali** ikiwa **hupati taarifa** humo **au ikiwa kuna hitilafu**.
- Katika fremu za taarifa, kwa kawaida unapaswa **kupata fremu tofauti zilizopangiliwa vizuri baina yake**:

![Kusawazisha na chaneli ya redio - Mbinu za kuvutia: Katika fremu za taarifa, kwa kawaida unapaswa kupata fremu tofauti zilizopangiliwa vizuri baina yake](<../../images/image (1076).png>)

![Kusawazisha na chaneli ya redio - Mbinu za kuvutia: Katika fremu za taarifa, kwa kawaida unapaswa kupata fremu tofauti zilizopangiliwa vizuri baina yake](<../../images/image (597).png>)

- **Baada ya kurejesha mabadiliko ya viwango, huenda ukahitaji kuyadecodi.** Kwa encoding ya Manchester, mwelekeo mmoja wa mpito huwakilisha `0` na mwelekeo ulio kinyume huwakilisha `1`; polarity halisi hutegemea kanuni inayotumika.
- Preamble inaweza kuwa na mfululizo wa kiwango kilekile kilichosampuliwa hata kama payload inatumia encoding ya Manchester, kwa hiyo tambua mpaka wa fremu kabla ya ku-decode.

### Kutambua aina ya modulation kwa kutumia IQ

Kuna njia 3 za kuhifadhi taarifa katika ishara: kubadilisha **amplitude**, **frequency** au **phase**.\
Unapochunguza ishara, kuna njia tofauti za kujaribu kubaini kinachotumiwa kuhifadhi taarifa (tazama njia zaidi hapa chini), lakini njia nzuri ni kuangalia grafu ya IQ.

![Grafu ya IQ ya SigDigger inayotumiwa kutambua kama ishara inatumia amplitude, frequency au phase modulation](<../../images/image (788).png>)

- **Kutambua AM**: Ikiwa, kwa mfano, grafu ya IQ inaonyesha **duara 2** (huenda moja liko kwenye 0 na jingine kwenye amplitude tofauti), hii inaweza kumaanisha kuwa ni ishara ya AM. Hii ni kwa sababu katika grafu ya IQ, umbali kati ya 0 na duara ni amplitude ya ishara, hivyo ni rahisi kuona amplitudes tofauti zinazotumika.
- **Kutambua PM**: Kama ilivyo kwenye picha iliyotangulia, ukiona miduara midogo isiyohusiana, huenda ikamaanisha kuwa phase modulation inatumika. Hii ni kwa sababu katika grafu ya IQ, pembe kati ya nukta na 0,0 ni phase ya ishara, hivyo ina maana kuwa phases 4 tofauti zinatumika.
  - Kumbuka kwamba ikiwa taarifa imefichwa katika mabadiliko ya phase badala ya phase yenyewe, hutaona phases tofauti zikitofautiana waziwazi.
- **Kutambua FM**: IQ haina sehemu ya kutambua frequencies (umbali kutoka katikati ni amplitude na pembe ni phase).\
  Kwa hiyo, ili kutambua FM, kimsingi unapaswa **kuona duara pekee** kwenye grafu hii.\
  Zaidi ya hayo, frequency offset hubadilisha kasi ya mzunguko kuzunguka duara la IQ. Kwa hiyo, katika SigDigger, mabadiliko ya kasi au mwelekeo wa mzunguko yanaweza kuashiria FM.

## Mfano wa AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Kutambua AM

#### Kukagua envelope

Unapokagua data ya AM kwa kutumia [**SigDigger**](https://github.com/BatchDrake/SigDigger), **envelope** ya ishara inaweza kuonyesha viwango tofauti vya amplitude. Ishara ya mfano hutuma taarifa kama mipigo yenye amplitude modulation; mpigo mmoja unaonekana hivi:<sup>[[1]](#references)</sup>

![Envelope ya ishara ya AM katika SigDigger yenye viwango vya wazi vya amplitude ya mipigo](<../../images/image (590).png>)

Na hivi ndivyo sehemu ya symbol inavyoonekana pamoja na waveform:

![Kutambua AM - Kukagua envelope: Na hivi ndivyo sehemu ya symbol inavyoonekana pamoja na waveform](<../../images/image (734).png>)

#### Kukagua Histogram

Unaweza **kuchagua ishara yote** ilipo taarifa, kuchagua hali ya **Amplitude** na **Selection**, kisha kubofya **Histogram.** Unaweza kuona kuwa viwango 2 vilivyo wazi pekee ndivyo vinapatikana.

![Histogram ya amplitude ya SigDigger inayoonyesha viwango viwili vilivyo wazi kwa ishara ya AM iliyochaguliwa](<../../images/image (264).png>)

Kwa mfano, ukichagua Frequency badala ya Amplitude katika ishara hii ya AM, utapata frequency 1 tu (haiwezekani taarifa iliyomodulishwa kwenye frequency kutumia frequency 1 tu).

![Histogram ya frequency ya SigDigger kwa ishara ya AM inayoonyesha frequency moja](<../../images/image (732).png>)

Ukipata frequencies nyingi, huenda hii isiwe FM; pengine frequency ya ishara ilibadilika tu kutokana na chaneli.

#### Kwa kutumia IQ

Katika mfano huu unaweza kuona **duara kubwa**, lakini pia **nukta nyingi katikati**.

![Kukagua Histogram - Kwa kutumia IQ: Katika mfano huu unaweza kuona duara kubwa, lakini pia nukta nyingi katikati](<../../images/image (222).png>)

### Kupata Symbol Rate

#### Kwa symbol moja

Chagua kipindi kidogo zaidi ambacho kina symbol moja kwa uwazi, kisha uangalie **Selection freq**. Katika mfano huu ni 1.013 kHz, takriban 1 kHz.

![Kupata Symbol Rate - Kwa symbol moja: Chagua kipindi kidogo zaidi unachoweza kupata (ili kuhakikisha kina symbol moja tu) kisha uangalie "Selection freq". Katika mfano huu ni 1.013 kHz (yaani 1 kHz).](<../../images/image (78).png>)

#### Kwa kundi la symbols

Unaweza pia kuonyesha idadi ya symbols utakazochagua na SigDigger itakokotoa frequency ya symbol 1 (huenda kadiri unavyochagua symbols nyingi ndivyo matokeo yanavyokuwa bora). Katika hali hii nilichagua symbols 10 na "Selection freq" ni 1.004 Khz:

![Hesabu ya symbol-rate ya SigDigger kwa kutumia kundi lililochaguliwa la symbols kumi](<../../images/image (1008).png>)

### Kupata Bits

Baada ya kutambua AM na kukadiria **symbol rate**, chagua eneo la ishara, sanidi amplitude sampling na viwango vya uamuzi, chagua **Gardner clock recovery**, kisha ubonyeze **Sample**:

![Paneli ya SigDigger ya Kupata Bits ikiwa imesanidiwa kwa AM sampling, symbol rate na Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** inamaanisha kuwa ikiwa awali ulichagua vipindi ili kupata symbol rate, symbol rate hiyo itatumika.
- **Manual** inamaanisha kuwa symbol rate iliyoonyeshwa ndiyo itakayotumika.
- Katika **Fixed interval selection** unaonyesha idadi ya vipindi vitakavyochaguliwa na mfumo huhesabu symbol rate kutokana navyo.
- **Gardner clock recovery** ni chaguo-msingi linalofaa, lakini bado linahitaji makadirio ya symbol rate.

Ukibonyeza sample, hiki ndicho kinachoonekana:

![Kwa kundi la symbols - Kupata Bits: Ukibonyeza sample, hiki ndicho kinachoonekana](<../../images/image (644).png>)

Sasa, ili SigDigger itambue **eneo la kiwango** linalobeba taarifa, unahitaji kubofya **kiwango cha chini** na kuendelea kushikilia hadi **kiwango cha juu zaidi**:

![Uteuzi wa masafa ya viwango katika SigDigger kutoka kiwango cha chini cha amplitude hadi kiwango cha juu](<../../images/image (439).png>)

Kwa mfano, kama kungekuwa na **viwango 4 tofauti vya amplitude**, ungehitaji kusanidi **Bits per symbol kuwa 2** na kuchagua kutoka kiwango cha chini zaidi hadi cha juu zaidi.

Hatimaye, kwa **kuongeza** **Zoom** na **kubadilisha Row size**, unaweza kuona bits (na unaweza kuchagua zote na kunakili ili kupata bits zote):

![Kwa kundi la symbols - Kupata Bits: Hatimaye, kwa kuongeza Zoom na kubadilisha Row size, unaweza kuona bits (na unaweza kuchagua zote na kunakili ili kupata bits zote)](<../../images/image (276).png>)

Ikiwa ishara ina zaidi ya bit 1 kwa kila symbol (kwa mfano 2), SigDigger **haiwezi kujua ni symbol ipi** ni 00, 01, 10 au 11, kwa hiyo itatumia **vivuli tofauti vya kijivu** kuwakilisha kila moja (na ukinakili bits, itatumia **namba kuanzia 0 hadi 3**, ambazo utahitaji kuzichakata).

Kwa line encoding kama **Manchester**, badilisha kila jozi halali ya mipito (`01` au `10`) kuwa data bit kulingana na kanuni inayotumiwa na itifaki.

## Mfano wa FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Kutambua FM

#### Kukagua frequencies na waveform

Mfano wa ishara inayotuma taarifa zilizomodulishwa kwa FM:

![Kutambua FM - Kukagua frequencies na waveform: Mfano wa ishara inayotuma taarifa zilizomodulishwa kwa FM](<../../images/image (725).png>)

Spectrum inaonyesha wazi **frequencies mbili**, ingawa huenda ikawa vigumu kuzitofautisha katika waveform ya time-domain:

![Waveform ya FM katika SigDigger ambapo frequencies mbili ni vigumu kuzitofautisha moja kwa moja](<../../images/image (717).png>)

Hii hutokea kwa sababu capture iko katikati ya frequencies zote mbili, hivyo frequency offsets zake zinakaribiana na kuwa kinyume:

![Capture ya FM ya SigDigger inayoonyesha frequencies mbili zikiwa takriban kinyume cha kila moja](<../../images/image (942).png>)

Ikiwa frequency iliyosawazishwa iko **karibu zaidi na frequency moja kuliko nyingine**, unaweza kuona kwa urahisi frequencies 2 tofauti:

![Kutambua FM - Kukagua frequencies na waveform: Ikiwa frequency iliyosawazishwa iko karibu zaidi na frequency moja kuliko nyingine, unaweza kuona kwa urahisi frequencies 2 tofauti](<../../images/image (422).png>)

![Kutambua FM - Kukagua frequencies na waveform: Ikiwa frequency iliyosawazishwa iko karibu zaidi na frequency moja kuliko nyingine, unaweza kuona kwa urahisi frequencies 2 tofauti](<../../images/image (488).png>)

#### Kukagua histogram

Ukikagua histogram ya frequency ya ishara yenye taarifa, unaweza kuona kwa urahisi ishara 2 tofauti:

![Kukagua frequencies na waveform - Kukagua histogram: Ukikagua histogram ya frequency ya ishara yenye taarifa, unaweza kuona kwa urahisi ishara 2 tofauti](<../../images/image (871).png>)

Katika hali hii, ukiangalia **Amplitude histogram** utapata **amplitude moja tu**, kwa hiyo **haiwezi kuwa AM** (ukipata amplitudes nyingi, huenda ni kwa sababu ishara imepoteza nguvu ilipopitia chaneli):

![Histogram ya amplitude ya SigDigger kwa ishara ya FM inayoonyesha kiwango kimoja cha amplitude](<../../images/image (817).png>)

Na hii ndiyo histogram ya phase (inayoonyesha wazi kuwa ishara haijamodulishwa kwa phase):

![Kukagua frequencies na waveform - Kukagua histogram: Hii ndiyo histogram ya phase (inayoonyesha wazi kuwa ishara haijamodulishwa kwa phase)](<../../images/image (996).png>)

#### Kwa kutumia IQ

IQ haina sehemu ya kutambua frequencies (umbali kutoka katikati ni amplitude na pembe ni phase).\
Kwa hiyo, ili kutambua FM, kimsingi unapaswa **kuona duara pekee** kwenye grafu hii.\
Zaidi ya hayo, frequency offset hubadilisha kasi ya mzunguko kuzunguka duara la IQ. Kwa hiyo, katika SigDigger, mabadiliko ya kasi au mwelekeo wa mzunguko yanaweza kuashiria FM:

![Grafu ya IQ ya SigDigger ambapo FM inaonekana kama mabadiliko ya kasi ya mzunguko kuzunguka duara](<../../images/image (81).png>)

### Kupata Symbol Rate

Unaweza kutumia **mbinu ileile iliyotumiwa katika mfano wa AM** kupata symbol rate baada ya kupata frequencies zinazobeba symbols.

### Kupata Bits

Unaweza kutumia **mbinu ileile iliyotumiwa katika mfano wa AM** kupata bits baada ya **kubaini kuwa ishara imemodulishwa kwa frequency** na kupata **symbol rate**.

## References

- [1] [SigDigger - Kichanganuzi huria cha ishara za kidijitali kwa GNU/Linux na macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
