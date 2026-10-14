# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Mashambulizi ya side-channel hurejesha siri kwa kuchunguza "leakage" ya kimaumbile au ya usanifu mdogo wa kompyuta ambayo *inahusiana* na hali ya ndani lakini *si* sehemu ya kiolesura cha kimantiki cha kifaa. Mifano ni kuanzia kupima mkondo wa umeme wa papo hapo unaotumiwa na smart card hadi kutumia vibaya athari za usimamizi wa nishati ya CPU kupitia mtandao.

---

## Njia Kuu za Leakage

| Njia | Lengo la Kawaida | Vifaa vya Kupimia |
|---------|---------------|-----------------|
| Matumizi ya nishati | Smart card, MCU za IoT, FPGA | Oscilloscope pamoja na kizuia mkondo (shunt resistor) au differential probe; CW503 ni chanzo cha umeme cha probes/LNAs, si probe yenyewe<sup>[[11]](#references)</sup> |
| Uga wa kielektroniki (EM) | CPU, RFID, vichapuzi vya AES | H-field/near-field probe pamoja na amplifier yenye kelele ndogo na oscilloscope au kipokezi cha SDR kama RTL-SDR<sup>[[13]](#references)</sup> |
| Muda wa utekelezaji / caches | CPU za kompyuta za mezani na cloud | Vipima muda vya usahihi wa juu (`rdtsc`/`rdtscp`) au kipimo cha muda wa safari ya mawimbi kwa mbali |
| Sauti / mitambo | Kibodi, printa za 3-D, printa, relay, na vidhibiti vya volteji ya CPU | MEMS microphone au laser vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Mwanga na joto | Taa za hali, skrini, DRAM, na vifaa vinavyounganishwa na joto | Photodiode, kamera ya kasi ya juu, au kamera ya IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Uingizaji wa hitilafu | Usimbaji fiche wa ASIC/MCU | Clock/voltage glitch, EMFI, au uingizaji kwa laser |

---

## Power Analysis

### Simple Power Analysis (SPA)
Chunguza trace *moja* na uhusishe vipengele vinavyoonekana na shughuli kama matawi, kuzidisha kwa moduli, au mfuatano tofauti wa maagizo.<sup>[[1]](#references)</sup>

Usanidi halisi hutegemea lengo. Mfano ufuatao unatumia API ya sasa ya kiwango cha juu ya kunasa data ya ChipWhisperer baada ya scope na target kuunganishwa na kusanidiwa:<sup>[[1]](#references)</sup>

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
Kusanya traces nyingi, kadiria byte ya key `k`, hesabu leakage model ya Hamming-weight (HW) au Hamming-distance (HD), kisha ulinganishe na kila sample. Idadi ya traces zinazohitajika hutegemea target, noise, alignment, countermeasures na leakage model; hakuna kiwango maalum.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA ni baseline ya kawaida. Template attacks, mutual-information analysis, na mbinu za machine learning zinaweza kusaidia pale ambapo leakage si ya mstari au traces hazijapangiliwa vizuri.

---

## Uchambuzi wa Kielektroniki (EMA)
Uchambuzi wa EM wa karibu unaweza kuona shughuli zinazotegemea data bila kuweka shunt kwenye njia ya umeme. Si lazima uonyeshe signal ileile inayoonekana kwenye power trace: nafasi na mwelekeo wa probe, bandwidth, gain ya front-end, ubora wa trigger, na umbali vyote vina umuhimu.

---

## Mashambulizi ya Muda na ya Micro-architectural
CPU za kisasa hufichua siri kupitia rasilimali zinazoshirikiwa:
* **Hertzbleed (2022)** – Dynamic voltage and frequency scaling inayotegemea data huunda njia ya timing ya mbali. Onyesho la awali la kurejesha key kutoka mwanzo hadi mwisho lililenga SIKE; utafiti uliofuata unajadili primitives nyingine.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution inaweza kufichua data inayotumiwa na vector gather instructions kuvuka mipaka ya usalama.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Ushughulikiaji usio sahihi wa hali ya speculative vector-register unaweza kufichua data kutoka kwenye core ileile ya kimwili.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Shambulio la transient-execution linachanganya phantom execution na mafunzo ndani ya transient execution ili kuunda gadgets za misprediction zinazodhibitiwa na mshambuliaji.<sup>[[5]](#references)</sup>

---

## Mashambulizi ya Kielektroniki-sauti na ya Macho
Leakage ya sauti imetumiwa kurejesha RSA keys kutokana na kelele ya laptop katika jaribio lililodhibitiwa, ikiwemo kwa kutumia microphone ya simu ya mkononi iliyo karibu.<sup>[[6]](#references)</sup> Utafiti tofauti wa keyboard wa 2023 uliainisha mibofyo ya vitufe kwa usahihi wa 95% ulipofundishwa kwa rekodi zilizochukuliwa na simu iliyo karibu, na 93% ulipofundishwa kwa sauti ya Zoom; takwimu hizi zinaelezea jaribio la paper hiyo kwa kifaa kilichofundishwa, wala si keyboard au mwathiriwa yeyote.<sup>[[9]](#references)</sup> Miale ya macho kutoka kwenye status LEDs pia inaweza kulinganishwa na data iliyochakatwa. Matokeo haya hutegemea shabaha na mpangilio wa jaribio; usihitimishe kuwa yana umbali au kiwango cha mafanikio sawa kwenye vifaa vingine visivyohusiana.<sup>[[7]](#references)</sup>

---

## Fault Injection na Differential Fault Analysis (DFA)
Kuchanganya faults zinazodhibitiwa na uchunguzi wa side-channel kunaweza kupunguza utafutaji wa key kwa baadhi ya algorithms na implementations. Majukwaa ya kawaida ya maabara ni pamoja na vipengele vya voltage/clock glitching vya ChipWhisperer na zana maalumu za EM fault-injection kama ChipSHOUTER au PicoEMP. Maelezo ya awali ya “sub-1 ns” hayapaswi kutumiwa kama specifikeshini: manual iliyochapishwa ya ChipSHOUTER inaorodhesha upana wa kawaida wa pulse zilizoingizwa kuwa **15–80 ns** kwa tip ya 1 mm na **24–480 ns** kwa tip ya 4 mm (ingawa trigger/pulse jitter imeainishwa kwa picoseconds). Timing resolution inayohitajika, mahali pa kuweka probe, na idadi ya matokeo yenye makosa hutegemea shabaha na fault model.<sup>[[1]](#references)[[10]](#references)</sup>

## Vidokezo vya Utafiti Visivyothibitishwa Vilivyohifadhiwa kutoka Rasimu Iliyotangulia

Rasimu iliyotangulia pia ilidai kuwa: mpangilio wa EM wa **500 MHz–3 GHz** ulirejesha key ya STM32 kutoka umbali wa zaidi ya **10 cm** kwa kutumia RTL-SDR; LED ya shughuli ya DDR4 ilifichua AES round key ndani ya chini ya dakika moja kwenye “Black Hat 2023”; na jukwaa la open-source la RISC-V glitching la 2025 lililoitwa **GlitchKit-R5**. Hakuna paper ya msingi, nyenzo za mkutano, au repository ya mradi inayolingana iliyopatikana wakati wa ukaguzi huu. Maelezo haya mahususi yamehifadhiwa kama vidokezo vya utafutaji/uzalishaji upya, wala si matokeo yaliyothibitishwa au mapendekezo ya zana.

---

## Mtiririko wa Kawaida wa Shambulio
1. Tambua njia ya leakage na sehemu ya kuunganisha (pini ya VCC, decoupling cap, sehemu ya near-field).
2. Weka trigger (GPIO au inayotegemea pattern).  
3. Kusanya traces za kutosha kwa statistical test iliyochaguliwa, ukirekodi plaintext/ciphertext na metadata nyingine.
4. Fanya pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Rejesha key kwa mbinu za takwimu au ML (CPA, MIA, DL-SCA).
6. Thibitisha na rudia ukiondoa outliers.

---

## Ulinzi na Uimarishaji
* Implementations za **constant-time** na algorithms za memory-hard.
* **Masking/shuffling** – gawanya siri katika sehemu za nasibu; resistance ya daraja la kwanza iliyothibitishwa kwa TVLA.
* **Hiding** – voltage regulators za on-chip, clock ya nasibu, dual-rail logic, EM shields.
* **Utambuzi wa makosa** – computation ya ziada, threshold signatures.
* **Uendeshaji** – zima DVFS/turbo kwenye crypto kernels, tenga SMT, zuia co-location kwenye multi-tenant clouds.

---

## Zana na Frameworks
* **ChipWhisperer-Husky** (2024) – scope ya 500 MS/s + trigger ya Cortex-M; Python API kama ilivyo hapo juu.<sup>[[1]](#references)</sup>
* **Riscure Inspector na bidhaa za fault-injection** – zana za kibiashara za uchanganuzi na majaribio ya kiotomatiki.
* **scaaml** – zana na datasets za deep-learning SCA zinazotumia TensorFlow.<sup>[[12]](#references)</sup>
* **pyecsca** – toolkit ya open-source ya kubadili uhandisi wa black-box ECC implementations kupitia side channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [Nyaraka za ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Paper ya Shambulio la Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: Kutumia Ukusanyaji wa Data wa Speculative](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Kufichua Maeneo Mapya ya Mashambulizi kwa Mafunzo katika Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Utoaji wa RSA Key kupitia Cryptanalysis ya Sauti ya Bandwidth Ndogo](https://eprint.iacr.org/2013/857.pdf)
- [7] [Uvujaji wa Taarifa kutoka kwa Miale ya Macho](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Nyaraka za artifact ya pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Shambulio la Vitendo la Acoustic Side Channel kwenye Keyboards Linalotumia Deep Learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - Mwongozo wa mtumiaji wa ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Nyaraka za ChipWhisperer — CW503 probe power supply](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Nyaraka za Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — Kufanya mashambulizi ya bei nafuu ya electromagnetic side-channel kwa kutumia RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Kufumbua Intellectual Property: Shambulio la Acoustic na Magnetic Side-Channel kwenye Printer ya 3-D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Mashambulizi ya Acoustic Side-Channel kwenye Printers](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Upelelezi wa Halijoto kwa Kutumia DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
