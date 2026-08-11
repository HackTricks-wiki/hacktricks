# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel saldırıları, cihazın mantıksal arayüzünün parçası olmayan ancak dahili durumla *ilişkili* fiziksel veya mikro-mimari "sızıntıları" gözlemleyerek sırları ele geçirir. Örnekler, bir akıllı kartın çektiği anlık akımı ölçmekten CPU power-management etkilerini bir network üzerinden kötüye kullanmaya kadar uzanır.

---

## Main Leakage Channels

| Kanal | Tipik Hedef | Enstrümantasyon |
|---------|---------------|-----------------|
| Power consumption | Smart cards, IoT MCU'ları, FPGA'ler | Osiloskop ve shunt resistor veya differential probe; CW503, probe/LNA'lar için bir power supply'dır, kendisi bir probe değildir<sup>[[11]](#references)</sup> |
| Electromagnetic field (EM) | CPU'lar, RFID, AES accelerators | H-field/near-field probe ile low-noise amplifier ve osiloskop veya RTL-SDR gibi bir SDR receiver<sup>[[13]](#references)</sup> |
| Execution time / caches | Masaüstü ve cloud CPU'ları | High-precision timers (`rdtsc`/`rdtscp`) veya remote time-of-flight |
| Acoustic / mechanical | Klavyeler, 3-D yazıcılar, yazıcılar, röleler ve CPU voltage regulator'ları | MEMS microphone veya laser vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optical & thermal | Status LED'leri, ekranlar, DRAM ve termal olarak bağlı cihazlar | Photodiode, high-speed camera veya IR camera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCU cryptography | Clock/voltage glitch, EMFI veya laser injection |

---

## Power Analysis

### Simple Power Analysis (SPA)
*Tek* bir trace'i gözlemleyin ve görünür özellikleri branch'ler, modular multiplication veya farklı instruction sequence'leri gibi işlemlerle ilişkilendirin.<sup>[[1]](#references)</sup>

Kesin kurulum hedefe özgüdür. Aşağıdaki örnekte, scope ve target bağlanıp yapılandırıldıktan sonra güncel high-level ChipWhisperer capture API kullanılır:<sup>[[1]](#references)</sup>
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
Birden fazla trace elde edin, bir anahtar byte'ı `k` varsayın, bir Hamming-weight (HW) veya Hamming-distance (HD) leak modeli hesaplayın ve bunu her sample ile korele edin. Gerekli trace sayısı; hedef, gürültü, hizalama, countermeasure'lar ve leak modeli tarafından belirlenir; sabit bir eşik değildir.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA standart bir temel yöntemdir. Leakage doğrusal olmadığında veya izler yeterince hizalanmadığında template attacks, mutual-information analysis ve machine-learning yaklaşımları yararlı olabilir.

---

## Elektromanyetik Analiz (EMA)
Near-field EM analysis, besleme yoluna bir shunt yerleştirmeden veriye bağlı etkinliği gözlemleyebilir. Bu yöntem, power trace ile mutlaka aynı sinyali ortaya çıkarmaz: probun konumu, yönelimi, bant genişliği, front-end gain, trigger kalitesi ve mesafe önemlidir.

---

## Timing ve Micro-architectural Attacks
Modern CPU'lar, paylaşılan kaynaklar üzerinden secret bilgileri leak eder:
* **Hertzbleed (2022)** – Veriye bağlı dynamic voltage and frequency scaling, uzaktan kullanılabilen bir timing channel oluşturur. Orijinal uçtan uca key-recovery gösterimi SIKE'ı hedeflemiştir; sonraki çalışmalar diğer primitive'leri ele alır.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution, vector gather instruction'ları tarafından kullanılan verileri security boundary'leri arasında açığa çıkarabilir.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Speculative vector-register state'in hatalı işlenmesi, aynı physical core üzerindeki verileri açığa çıkarabilir.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Bir transient-execution attack, attacker-controlled misprediction gadget'ları oluşturmak için phantom execution ile transient execution içindeki training'i birleştirir.<sup>[[5]](#references)</sup>

---

## Acoustic ve Optical Attacks
Acoustic leakage, kontrollü bir deneyde laptop gürültüsünden RSA key'lerini kurtarmak için, yakındaki bir cep telefonunun mikrofonuyla da birlikte kullanılmıştır.<sup>[[6]](#references)</sup> Ayrı bir 2023 keyboard çalışması, yakındaki bir telefondan alınan kayıtlarla eğitildiğinde keystroke'ları %95 doğrulukla, Zoom audio ile eğitildiğinde ise %93 doğrulukla sınıflandırmıştır; bu oranlar çalışmadaki eğitilmiş cihaz deneyini tanımlar, rastgele bir keyboard veya victim için geçerli değildir.<sup>[[9]](#references)</sup> Status LED'lerden yayılan optical emanations da işlenen verilerle korelasyon gösterebilir. Bu sonuçlar hedefe ve kuruluma özgüdür; menzil veya başarı oranlarını ilgisiz cihazlara genelleştirmeyin.<sup>[[7]](#references)</sup>

---

## Fault Injection ve Differential Fault Analysis (DFA)
Kontrollü fault'ları side-channel gözlemleriyle birleştirmek, bazı algorithm'ler ve implementation'lar için key search alanını daraltabilir. Yaygın lab platformları arasında ChipWhisperer'ın voltage/clock glitching özellikleri ve ChipSHOUTER veya PicoEMP gibi özel EM fault-injection araçları bulunur. Önceki taslağın “sub-1 ns” açıklaması bir specification olarak kullanılmamalıdır: ChipSHOUTER'ın yayımlanmış manual'i, 1 mm tip ile tipik inserted-pulse width değerlerini **15–80 ns**, 4 mm tip ile **24–480 ns** olarak belirtir (trigger/pulse jitter değeri picosecond cinsinden belirtilmiş olsa da). Gerekli timing resolution, prob yerleşimi ve faulty output sayısı hedefe ve fault model'ine bağlıdır.<sup>[[1]](#references)[[10]](#references)</sup>

## Önceki Taslaktan Korunan Doğrulanmamış Research Lead'leri

Önceki taslak ayrıca şunları iddia etmiştir: RTL-SDR kullanılarak **500 MHz–3 GHz** bir EM setup'ı ile **10 cm**'den daha uzaktan STM32 key'i kurtarılması; DDR4 activity LED'inin “Black Hat 2023”te bir AES round key'ini bir dakikadan kısa sürede açığa çıkarması; ve **GlitchKit-R5** adlı, 2025 tarihli open-source bir RISC-V glitching platformu. Bu audit sırasında eşleşen birincil paper, conference material veya project repository bulunamamıştır. Bu kesin ayrıntılar, doğrulanmış sonuçlar veya tooling önerileri olarak değil, search/reproduction lead'leri olarak korunmuştur.

---

## Typical Attack Workflow
1. Leakage channel ve mount point'i belirleyin (VCC pin'i, decoupling cap, near-field spot).
2. Trigger ekleyin (GPIO veya pattern-based).
3. Seçilen statistical test için yeterli sayıda trace toplayın; plaintext/ciphertext ve diğer metadata'yı kaydedin.
4. Pre-process uygulayın (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical veya ML key recovery gerçekleştirin (CPA, MIA, DL-SCA).
6. Outlier'ları doğrulayın ve yineleyin.

---

## Defences ve Hardening
* **Constant-time** implementation'lar ve memory-hard algorithm'ler.
* **Masking/shuffling** – secret'ları random share'lere bölün; first-order resistance'ı TVLA ile certify edin.
* **Hiding** – on-chip voltage regulator'lar, randomised clock, dual-rail logic, EM shield'ler.
* **Fault detection** – redundant computation, threshold signature'lar.
* **Operational** – crypto kernel'lerinde DVFS/turbo'yu devre dışı bırakın, SMT'yi isolate edin, multi-tenant cloud'larda co-location'ı yasaklayın.

---

## Tools ve Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; yukarıdaki gibi Python API'si.<sup>[[1]](#references)</sup>
* **Riscure Inspector ve fault-injection ürünleri** – ticari analysis ve automated test tooling'i.
* **scaaml** – TensorFlow tabanlı deep-learning SCA tooling'i ve dataset'leri.<sup>[[12]](#references)</sup>
* **pyecsca** – black-box ECC implementation'larını side channel'lar üzerinden reverse-engineer etmek için open-source toolkit.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Training in Transient Execution ile Yeni Attack Surface'larının Ortaya Çıkarılması](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Düşük Bant Genişlikli Acoustic Cryptanalysis ile RSA Key Extraction](https://eprint.iacr.org/2013/857.pdf)
- [7] [Optical Emanations'dan Information Leakage](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca Artifact Documentation](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Keyboard'lar Üzerinde Pratik Bir Deep Learning Tabanlı Acoustic Side Channel Attack](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER User Manual](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer Documentation — CW503 Probe Power Supply](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML Documentation](https://google.github.io/scaaml/)
- [13] [FOSDEM — RTL-SDR Kullanarak Düşük Maliyetli Electromagnetic Side-Channel Attacks Gerçekleştirme](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Intellectual Property'nin Decoding'i: Bir 3-D Printer Üzerinde Acoustic ve Magnetic Side-Channel Attack](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Printer'lar Üzerinde Acoustic Side-Channel Attacks](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [DRAM Kullanarak Temperature'ı İzleme](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
