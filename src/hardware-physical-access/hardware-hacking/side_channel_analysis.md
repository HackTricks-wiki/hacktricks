# Mashambulizi ya Uchambuzi wa Side-Channel

{{#include ../../banners/hacktricks-training.md}}

Mashambulizi ya side-channel hufichua siri kwa kuchunguza "leakage" ya kimwili au ya usanifu mdogo inayohusiana na hali ya ndani, lakini ambayo si sehemu ya kiolesura cha kimantiki cha kifaa. Mifano inaanzia kupima mkondo wa umeme unaotumiwa papo hapo na smart-card hadi kutumia vibaya athari za usimamizi wa nishati ya CPU kupitia mtandao.

Kwa kifaa lengwa chenye hardware ya ARM debug inayofikika, [CoreSight ETM tracing over SWO](arm-coresight-instruction-tracing.md) inaweza kutoa marejeo ya njia ya utekelezaji pamoja na vipimo vya power au EM; hii ni debug trace, si njia ya leakage.<sup>[[17]](#references)</sup>

---

## Njia Kuu za Leakage

| Njia | Kifaa Lengwa cha Kawaida | Vifaa vya Kupimia |
|---------|---------------|-----------------|
| Matumizi ya umeme | Smart cards, IoT MCUs, FPGAs | Oscilloscope pamoja na shunt resistor au differential probe; CW503 ni chanzo cha umeme cha probes/LNAs, si probe yenyewe<sup>[[11]](#references)</sup> |
| Uga wa sumakuumeme (EM) | CPUs, RFID, AES accelerators | H-field/near-field probe pamoja na low-noise amplifier na oscilloscope au kipokezi cha SDR kama RTL-SDR<sup>[[13]](#references)</sup> |
| Muda wa utekelezaji / caches | Desktop na cloud CPUs | Vipima muda vya usahihi wa juu (`rdtsc`/`rdtscp`) au kipimo cha muda wa safari ya data kutoka mbali |
| Sauti / mitikisiko | Keyboards, 3-D printers, printers, relays, na voltage regulators za CPU | MEMS microphone au laser vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Mwanga na joto | Status LEDs, displays, DRAM, na vifaa vinavyoathiriwa na joto | Photodiode, kamera ya kasi ya juu, au kamera ya IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Uingizaji wa hitilafu | Usimbaji fiche wa ASIC/MCU | Clock/voltage glitch, EMFI, au uingizaji wa laser |

---

## Uchambuzi wa Nguvu

### Simple Power Analysis (SPA)
Chunguza trace *moja* na uhusishe vipengele vinavyoonekana na shughuli kama vile matawi, modular multiplication, au mfuatano tofauti wa maagizo.<sup>[[1]](#references)</sup>

Mipangilio halisi hutegemea kifaa lengwa. Mfano ufuatao unatumia ChipWhisperer capture API ya kiwango cha juu ya sasa, baada ya scope na target kuunganishwa na kusanidiwa:<sup>[[1]](#references)</sup>

```python
import chipwhisperer as cw

scope = cw.scope()
scope.default_setup()
target = cw.target(scope)
ktp = cw.ktp.Basic()
key, plaintext = ktp.next()
trace = cw.capture_trace(scope, target, plaintext, key)
if trace is not None:
    print(trace.wave)  # NumPy array of power samples
```

### Differential/Correlation Power Analysis (DPA/CPA)
Kusanya trace nyingi, kadiria byte ya ufunguo `k`, kisha ukokotoe modeli ya leakage ya Hamming-weight (HW) au Hamming-distance (HD) na ulinganishe modeli hiyo na kila sampuli. Idadi ya trace zinazohitajika hutegemea kifaa lengwa, kelele, ulinganifu, countermeasures na modeli ya leakage; si kiwango kisichobadilika.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA ni kipimo cha msingi cha kawaida. Template attacks, mutual-information analysis na mbinu za machine learning zinaweza kusaidia pale ambapo leak si ya mstari au traces hazijalinganishwa vizuri.

---

## Uchambuzi wa Kielektromagnetiki (EMA)
Uchambuzi wa EM wa karibu unaweza kuchunguza shughuli zinazotegemea data bila kuweka shunt kwenye njia ya usambazaji wa umeme. Si lazima ufichue ishara sawa na ya power trace: nafasi na mwelekeo wa probe, bandwidth, gain ya sehemu ya mbele, ubora wa trigger na umbali vyote vina umuhimu.

---

## Mashambulizi ya Muda na ya Micro-architectural
CPU za kisasa hufichua siri kupitia rasilimali zinazoshirikiwa:
* **Hertzbleed (2022)** – Dynamic voltage and frequency scaling inayotegemea data huunda njia ya remote timing. Jaribio la awali la kurejesha ufunguo kutoka mwanzo hadi mwisho lililenga SIKE; tafiti zilizofuata zinajadili primitives nyingine.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution inaweza kufichua data inayotumiwa na maagizo ya vector gather katika mipaka ya usalama.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Ushughulikiaji usio sahihi wa hali ya speculative vector-register unaweza kufichua data kutoka kwenye core ileile ya kimwili.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Shambulio la transient-execution huchanganya phantom execution na mafunzo katika transient execution ili kuunda gadgets za misprediction zinazodhibitiwa na mshambuliaji.<sup>[[5]](#references)</sup>

---

## Mashambulizi ya Akustiki na ya Macho
Leak ya akustiki imetumiwa kurejesha funguo za RSA kutoka kwenye kelele ya kompyuta mpakato katika jaribio lililodhibitiwa, ikiwemo kwa kutumia maikrofoni ya simu ya mkononi iliyo karibu.<sup>[[6]](#references)</sup> Utafiti tofauti wa kibodi wa 2023 uliainisha mibofyo ya vitufe kwa usahihi wa 95% ulipofunzwa kwa rekodi kutoka kwenye simu iliyo karibu, na 93% ulipofunzwa kwa sauti ya Zoom; takwimu hizi zinaelezea jaribio la kifaa kilichofunzwa katika makala hiyo, si kibodi au mwathiriwa yeyote.<sup>[[9]](#references)</sup> Miale ya macho kutoka kwenye LED za hali inaweza pia kuhusishwa na data iliyochakatwa. Matokeo haya hutegemea shabaha na usanidi; usihitimishe kuwa masafa au kiwango cha mafanikio ni sawa kwa vifaa visivyohusiana.<sup>[[7]](#references)</sup>

---

## Uingizaji wa Hitilafu na Uchambuzi Tofauti wa Hitilafu (DFA)
Kuchanganya hitilafu zinazodhibitiwa na uchunguzi wa side-channel kunaweza kupunguza utafutaji wa ufunguo kwa baadhi ya algorithms na implementations. Majukwaa ya kawaida ya maabara ni pamoja na vipengele vya ChipWhisperer vya voltage/clock glitching na zana maalumu za EM fault-injection kama ChipSHOUTER au PicoEMP. Maelezo ya awali ya “sub-1 ns” hayapaswi kutumiwa kama vipimo: mwongozo uliochapishwa wa ChipSHOUTER unaorodhesha upana wa kawaida wa mipigo inayoingizwa kuwa **15–80 ns** kwa ncha ya 1 mm na **24–480 ns** kwa ncha ya 4 mm (ingawa jitter ya trigger/pulse imeainishwa kwa picoseconds). Usahihi wa muda unaohitajika, nafasi ya probe na idadi ya matokeo yenye hitilafu hutegemea shabaha na fault model.<sup>[[1]](#references)[[10]](#references)</sup>

## Vidokezo vya Utafiti Visivyothibitishwa Vilivyobakizwa kutoka Rasimu ya Awali

Rasimu ya awali pia ilidai kuwa: usanidi wa EM wa **500 MHz–3 GHz** ulirejesha ufunguo wa STM32 kutoka umbali wa zaidi ya **10 cm** kwa kutumia RTL-SDR; LED ya shughuli ya DDR4 ilifichua ufunguo wa raundi ya AES kwa chini ya dakika moja katika “Black Hat 2023”; na jukwaa la open-source la RISC-V glitching la 2025 liitwalo **GlitchKit-R5**. Hakuna makala ya msingi, nyenzo za mkutano au hazina ya mradi inayolingana na madai haya iliyopatikana wakati wa ukaguzi huu. Maelezo haya mahususi yamebakizwa kama vidokezo vya utafutaji/uzalishaji upya, si kama matokeo yaliyothibitishwa au mapendekezo ya zana.

---

## Mtiririko wa Kawaida wa Shambulio
1. Tambua njia ya leak na sehemu ya kuunganisha (pini ya VCC, capacitor ya decoupling, sehemu ya near-field).
2. Weka trigger (GPIO au inayotegemea pattern).  
3. Kusanya traces za kutosha kwa jaribio la takwimu lililochaguliwa, ukirekodi plaintext/ciphertext na metadata nyingine.
4. Chakata awali (alignment, kuondoa wastani, LP/HP filter, wavelet, PCA).
5. Urejeshaji wa ufunguo kwa takwimu au ML (CPA, MIA, DL-SCA).
6. Thibitisha na urudie kwa outliers.

---

## Ulinzi na Uimarishaji
* Implementations za **constant-time** na algorithms zinazohitaji kumbukumbu nyingi.
* **Masking/shuffling** – gawanya siri katika sehemu za nasibu; upinzani wa first-order huthibitishwa kwa TVLA.
* **Hiding** – vidhibiti vya voltage vilivyo kwenye chip, clock ya nasibu, mantiki ya dual-rail, ngao za EM.
* **Utambuzi wa hitilafu** – hesabu rudufu, threshold signatures.
* **Kiutendaji** – zima DVFS/turbo katika crypto kernels, tenga SMT, kataza co-location katika clouds za multi-tenant.

---

## Zana na Frameworks
* **ChipWhisperer-Husky** (2024) – scope ya 500 MS/s pamoja na trigger ya Cortex-M; Python API kama ilivyoelezwa hapo juu.<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – zana za kibiashara za uchambuzi na majaribio otomatiki.
* **scaaml** – zana na datasets za SCA ya deep learning inayotumia TensorFlow.<sup>[[12]](#references)</sup>
* **pyecsca** – toolkit ya open-source ya reverse-engineering ya implementations za ECC zisizojulikana kupitia side channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [Nyaraka za ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Makala ya Shambulio la Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: Kutumia Gather Data ya Speculative](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Kufichua Sehemu Mpya za Mashambulizi kwa Mafunzo katika Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Utoaji wa Ufunguo wa RSA kupitia Cryptanalysis ya Akustiki ya Bandwidth Ndogo](https://eprint.iacr.org/2013/857.pdf)
- [7] [Uvujaji wa Taarifa kutoka kwa Miale ya Macho](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Nyaraka za kifaa cha pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Shambulio la Kivitendo la Akustiki la Side Channel kwenye Kibodi kwa Kutumia Deep Learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - Mwongozo wa mtumiaji wa ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Nyaraka za ChipWhisperer — usambazaji wa umeme wa probe ya CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Nyaraka za Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — Kufanya mashambulizi ya kielektromagnetiki ya side-channel ya gharama nafuu kwa kutumia RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Kusimbua Intellectual Property: Shambulio la Akustiki na Sumaku la Side-Channel kwenye Printa ya 3-D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Mashambulizi ya Akustiki ya Side-Channel kwenye Printa](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Upelelezi wa Halijoto kwa Kutumia DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [Kufuatilia Maagizo: Ufuatiliaji wa ARM wa Moja kwa Moja kwa ETM, ITM na TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
