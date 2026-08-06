# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger) ni free digital signal analyzer kwa GNU/Linux na macOS, iliyoundwa kutoa taarifa kutoka kwa radio signals zisizojulikana. Inaunga mkono vifaa mbalimbali vya SDR kupitia SoapySDR, na inaruhusu demodulation inayoweza kurekebishwa ya FSK, PSK na ASK signals, kudecode video ya analog, kuchambua bursty signals na kusikiliza analog voice channels (yote kwa real time).<sup>[[1]](#references)</sup>

### Basic Config

Baada ya kusakinisha kuna mambo machache unayoweza kufikiria kuyaconfigure.\
Katika settings (kitufe cha tab ya pili) unaweza kuchagua **SDR device** au **select a file** ya kusoma, pamoja na frequency ya kusyntonise na Sample rate (inapendekezwa hadi 2.56Msps ikiwa PC yako inai-support)

![SigDigger settings zinazoonyesha SDR device, input file, frequency na sample rate options](<../../images/image (245).png>)

Katika GUI behaviour inapendekezwa kuwezesha mambo machache ikiwa PC yako inai-support:

![SigDigger - Basic Config: Katika GUI behaviour inapendekezwa kuwezesha mambo machache ikiwa PC yako inai-support](<../../images/image (472).png>)

> [!TIP]
> Ukigundua kuwa PC yako hainacapture vitu, jaribu kudisable OpenGL na kupunguza sample rate.

### Uses

- Ili **capture muda fulani wa signal na kuichambua**, endelea kushikilia kitufe cha "Push to capture" kwa muda unaohitaji.

![Basic Config - Uses: Ili capture muda fulani wa signal na kuichambua, endelea kushikilia kitufe cha "Push to capture" kwa muda unaohitaji](<../../images/image (960).png>)

- **Tuner** ya SigDigger husaidia **capture signals bora zaidi** (lakini inaweza pia kuzidhoofisha). Kwa kawaida anza na 0 na endelea **kuiongeza hadi** upate kwamba **noise** inayoongezwa ni **kubwa** kuliko **uboreshaji wa signal** unaohitaji).

![SigDigger tuner control iliyorekebishwa kuboresha radio signal iliyocapture](<../../images/image (1099).png>)

### Synchronize with radio channel

Ukitumia [**SigDigger** ](https://github.com/BatchDrake/SigDigger) synchronize na channel unayotaka kusikia, configure option ya "Baseband audio preview", configure bandwith ili kupata taarifa zote zinazotumwa, kisha set Tuner kwenye kiwango kabla noise haijaanza kuongezeka sana:<sup>[[1]](#references)</sup>

![SigDigger radio channel iliyosynchronize ikiwa na baseband audio preview na bandwidth iliyoconfigure](<../../images/image (585).png>)

## Interesting tricks

- Device inapotuma bursts za taarifa, kwa kawaida **sehemu ya kwanza itakuwa preamble**, kwa hiyo **huhitaji kuwa na wasiwasi** ikiwa **hupati taarifa** humo **au ikiwa kuna errors**.
- Katika frames za taarifa kwa kawaida unapaswa **kupata frames tofauti zikiwa zime-align vizuri kati yao**:

![Synchronize with radio channel - Interesting tricks: Katika frames za taarifa kwa kawaida unapaswa kupata frames tofauti zikiwa zime-align vizuri kati yao](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks: Katika frames za taarifa kwa kawaida unapaswa kupata frames tofauti zikiwa zime-align vizuri kati yao](<../../images/image (597).png>)

- **Baada ya kurecover bits unaweza kuhitaji kuziprocess kwa njia fulani**. Kwa mfano, katika Manchester codification, up+down itakuwa 1 au 0 na down+up itakuwa nyingine. Kwa hiyo pairs za 1 na 0 (ups na downs) zitakuwa 1 halisi au 0 halisi.
- Hata kama signal inatumia Manchester codification (haiwezekani kupata zaidi ya 0 au 1 mbili mfululizo), unaweza **kupata 1 au 0 kadhaa pamoja katika preamble**!

### Uncovering modulation type with IQ

Kuna njia 3 za kuhifadhi taarifa katika signals: Kumodulate **amplitude**, **frequency** au **phase**.\
Unapochunguza signal kuna njia tofauti za kujaribu kubaini kinachotumika kuhifadhi taarifa (tafuta njia zaidi hapa chini), lakini njia nzuri ni kuangalia IQ graph.

![SigDigger IQ graph inayotumika kutambua ikiwa signal inatumia amplitude, frequency au phase modulation](<../../images/image (788).png>)

- **Detecting AM**: Ikiwa IQ graph inaonyesha kwa mfano **circles 2** (huenda moja ikiwa kwenye 0 na nyingine ikiwa na amplitude tofauti), inaweza kumaanisha kuwa hii ni AM signal. Hii ni kwa sababu katika IQ graph, umbali kati ya 0 na circle ni amplitude ya signal, kwa hiyo ni rahisi kuona amplitudes tofauti zinazotumika.
- **Detecting PM**: Kama kwenye image iliyotangulia, ukipata circles ndogo zisizohusiana huenda ikamaanisha kuwa phase modulation inatumika. Hii ni kwa sababu katika IQ graph, angle kati ya point na 0,0 ni phase ya signal, hivyo hii inamaanisha kuwa phases 4 tofauti zinatumika.
- Kumbuka kwamba ikiwa taarifa imefichwa katika ukweli kwamba phase imebadilishwa, na si katika phase yenyewe, hutaona phases tofauti zikiwa zimetenganishwa wazi.
- **Detecting FM**: IQ haina field ya kutambua frequencies (umbali hadi centre ni amplitude na angle ni phase).\
Kwa hiyo, ili kutambua FM, unapaswa **kuona kimsingi circle moja tu** katika graph hii.\
Zaidi ya hayo, frequency tofauti "inawakilishwa" na IQ graph kupitia **kuongezeka kwa speed kuzunguka circle** (kwa hiyo katika SysDigger, unaposelect signal IQ graph hujazwa; ukipata acceleration au mabadiliko ya direction katika circle iliyoundwa, inaweza kumaanisha kuwa hii ni FM):

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering AM

#### Checking the envelope

Unapocheck AM info kwa [**SigDigger** ](https://github.com/BatchDrake/SigDigger) na kuangalia tu **envelop**, unaweza kuona levels tofauti zilizo wazi za amplitude. Signal iliyotumika inatuma pulses zenye taarifa katika AM; hivi ndivyo pulse moja inavyoonekana:<sup>[[1]](#references)</sup>

![SigDigger AM signal envelope yenye pulse amplitude levels zilizo wazi](<../../images/image (590).png>)

Na hivi ndivyo sehemu ya symbol inavyoonekana pamoja na waveform:

![Uncovering AM - Checking the envelope: Na hivi ndivyo sehemu ya symbol inavyoonekana pamoja na waveform](<../../images/image (734).png>)

#### Checking the Histogram

Unaweza **kuselect signal nzima** ambapo taarifa iko, uchague mode ya **Amplitude** na **Selection**, kisha ubofye **Histogram.** Unaweza kuona kwamba levels 2 zilizo wazi pekee ndizo zinapatikana

![SigDigger amplitude histogram inayoonyesha levels 2 zilizo wazi kwa AM signal iliyoselect](<../../images/image (264).png>)

Kwa mfano, ukichagua Frequency badala ya Amplitude katika AM signal hii, utapata frequency 1 tu (haiwezekani taarifa iliyomodulatewa katika frequency kutumia freq 1 tu).

![SigDigger frequency histogram ya AM signal inayoonyesha frequency moja](<../../images/image (732).png>)

Ukipata frequencies nyingi, huenda hii isiwe FM; labda signal frequency ilibadilishwa tu kwa sababu ya channel.

#### With IQ

Katika mfano huu unaweza kuona kuna **circle kubwa**, lakini pia **points nyingi katikati.**

![Checking the Histogram - With IQ: Katika mfano huu unaweza kuona kuna circle kubwa, lakini pia points nyingi katikati](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

Select symbol ndogo zaidi unayoweza kupata (ili uhakikishe ni 1 tu) na uangalie "Selection freq". Katika hali hii itakuwa 1.013kHz (yaani 1kHz).

![Get Symbol Rate - With one symbol: Select symbol ndogo zaidi unayoweza kupata (ili uhakikishe ni 1 tu) na uangalie "Selection freq". Katika hali hii itakuwa 1.013kHz (yaani 1kHz)](<../../images/image (78).png>)

#### With a group of symbols

Unaweza pia kuonyesha idadi ya symbols utakazoselect, na SigDigger itacalculate frequency ya symbol 1 (huenda symbols nyingi zaidi zilizoselect zikawa bora). Katika hali hii niliselect symbols 10 na "Selection freq" ni 1.004 Khz:

![SigDigger symbol-rate calculation ikitumia group iliyoselect ya symbols kumi](<../../images/image (1008).png>)

### Get Bits

Baada ya kugundua kuwa hii ni signal **iliyomodulatewa kwa AM** na **symbol rate** (na kujua kwamba katika hali hii kitu kilicho juu kinamaanisha 1 na kilicho chini kinamaanisha 0), ni rahisi sana **kupata bits** zilizocodewa katika signal. Kwa hiyo, select signal iliyo na info, configure sampling na decision, kisha ubonyeze sample (hakikisha **Amplitude** imeselected, **Symbol rate** iliyogunduliwa imeconfigure na **Gadner clock recovery** imeselected):

![SigDigger Get Bits panel iliyoconfigure kwa AM sampling, symbol rate na Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** inamaanisha kwamba ikiwa awali ulichagua intervals ili kupata symbol rate, symbol rate hiyo itatumika.
- **Manual** inamaanisha kuwa symbol rate iliyoonyeshwa ndiyo itatumika
- Katika **Fixed interval selection** unaonyesha idadi ya intervals zinazopaswa kuselectiwa, na inacalculate symbol rate kutokana nazo
- **Gadner clock recovery** kwa kawaida ndiyo option bora, lakini bado unahitaji kuonyesha symbol rate ya kukadiria.

Ukibonyeza sample, hivi ndivyo itaonekana:

![With a group of symbols - Get Bits: Ukibonyeza sample, hivi ndivyo itaonekana](<../../images/image (644).png>)

Sasa, ili SigDigger ielewe **range iko wapi** ya level inayobeba taarifa, unahitaji kubofya **lower level** na kuendelea kushikilia hadi kwenye level kubwa zaidi:

![SigDigger level-range selection kutoka lower amplitude level hadi upper level](<../../images/image (439).png>)

Iwapo kungekuwa na mfano wa **amplitude levels 4 tofauti**, ungehitaji kuconfigure **Bits per symbol kuwa 2** na kuselect kutoka ndogo zaidi hadi kubwa zaidi.

Hatimaye, kwa **kuongeza** **Zoom** na **kubadilisha Row size**, unaweza kuona bits (na unaweza kuselect zote na ku-copy ili kupata bits zote):

![With a group of symbols - Get Bits: Hatimaye, kwa kuongeza Zoom na kubadilisha Row size, unaweza kuona bits (na unaweza kuselect zote na ku-copy ili kupata bits zote)](<../../images/image (276).png>)

Ikiwa signal ina zaidi ya bit 1 kwa symbol (kwa mfano 2), SigDigger **haina njia ya kujua ni symbol gani** ni 00, 01, 10, 11, kwa hiyo itatumia **grey scales** tofauti kuwakilisha kila moja (na ukicopy bits itatumia **namba kutoka 0 hadi 3**, utahitaji kuzitreat).

Pia, tumia **codifications** kama **Manchester**, ambapo **up+down** inaweza kuwa **1 au 0**, na down+up inaweza kuwa 1 au 0. Katika hali hizo unahitaji **kuzitreat ups (1) na downs (0)** ulizopata ili kubadilisha pairs za 01 au 10 kuwa 0 au 1.

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering FM

#### Checking the frequencies and waveform

Mfano wa signal inayotuma taarifa iliyomodulatewa katika FM:

![Uncovering FM - Checking the frequencies and waveform: Mfano wa signal inayotuma taarifa iliyomodulatewa katika FM](<../../images/image (725).png>)

Katika image iliyotangulia unaweza kuona vizuri kwamba **frequencies 2 zinatumika**, lakini ukiangalia **waveform** huenda **usiweze kutambua kwa usahihi frequencies 2 tofauti**:

![SigDigger FM waveform ambapo frequencies mbili ni vigumu kutofautisha moja kwa moja](<../../images/image (717).png>)

Hii ni kwa sababu nilicapture signal katika frequencies zote mbili, kwa hiyo moja ni takriban negative ya nyingine:

![SigDigger FM capture inayoonyesha frequencies mbili kama negatives zinazokaribiana](<../../images/image (942).png>)

Ikiwa frequency iliyosynchronize iko **karibu na frequency moja kuliko nyingine**, unaweza kuona kwa urahisi frequencies 2 tofauti:

![Uncovering FM - Checking the frequencies and waveform: Ikiwa frequency iliyosynchronize iko karibu na frequency moja kuliko nyingine, unaweza kuona kwa urahisi frequencies 2 tofauti](<../../images/image (422).png>)

![Uncovering FM - Checking the frequencies and waveform: Ikiwa frequency iliyosynchronize iko karibu na frequency moja kuliko nyingine, unaweza kuona kwa urahisi frequencies 2 tofauti](<../../images/image (488).png>)

#### Checking the histogram

Ukicheck frequency histogram ya signal yenye taarifa, unaweza kuona kwa urahisi signals 2 tofauti:

![Checking the frequencies and waveform - Checking the histogram: Ukicheck frequency histogram ya signal yenye taarifa, unaweza kuona kwa urahisi signals 2 tofauti](<../../images/image (871).png>)

Katika hali hii ukicheck **Amplitude histogram** utapata **amplitude moja tu**, kwa hiyo **haiwezi kuwa AM** (ukipata amplitudes nyingi huenda ni kwa sababu signal imepoteza nguvu kwenye channel):

![SigDigger amplitude histogram ya FM signal inayoonyesha amplitude level moja](<../../images/image (817).png>)

Na hii itakuwa phase histogram (ambayo inaonyesha wazi kwamba signal haijamodulatewa katika phase):

![Checking the frequencies and waveform - Checking the histogram: Na hii itakuwa phase histogram (ambayo inaonyesha wazi kwamba signal haijamodulatewa katika phase)](<../../images/image (996).png>)

#### With IQ

IQ haina field ya kutambua frequencies (umbali hadi centre ni amplitude na angle ni phase).\
Kwa hiyo, ili kutambua FM, unapaswa **kuona kimsingi circle moja tu** katika graph hii.\
Zaidi ya hayo, frequency tofauti "inawakilishwa" na IQ graph kupitia **kuongezeka kwa speed kuzunguka circle** (kwa hiyo katika SysDigger, unaposelect signal IQ graph hujazwa; ukipata acceleration au mabadiliko ya direction katika circle iliyoundwa, inaweza kumaanisha kuwa hii ni FM):

![SigDigger IQ graph ambapo FM inaonekana kama mabadiliko ya acceleration kuzunguka circle](<../../images/image (81).png>)

### Get Symbol Rate

Unaweza kutumia **technique ile ile iliyotumika katika AM example** kupata symbol rate baada ya kupata frequencies zinazobeba symbols.

### Get Bits

Unaweza kutumia **technique ile ile iliyotumika katika AM example** kupata bits baada ya **kugundua kuwa signal imemodulatewa katika frequency** na kupata **symbol rate**.

## References

- [1] [SigDigger - Free digital signal analyzer for GNU/Linux and macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
