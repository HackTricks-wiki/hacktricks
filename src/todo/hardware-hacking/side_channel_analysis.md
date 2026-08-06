# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks, cihazın mantıksal arayüzünün bir parçası olmayan ancak dahili durumla *correlated* fiziksel veya mikro-mimari "leakage" bilgilerini gözlemleyerek sırları kurtarır. Örnekler, bir smart-card tarafından çekilen anlık akımın ölçülmesinden ağ üzerinden CPU power-management etkilerinin kötüye kullanılmasına kadar uzanır.

---

## Main Leakage Channels

| Kanal | Tipik Hedef | Instrumentation |
|---------|---------------|-----------------|
| Güç tüketimi | Smart-card'lar, IoT MCU'ları, FPGA'ler | Oscilloscope + shunt resistor/HS probe (örn. CW503)
| Elektromanyetik alan (EM) | CPU'lar, RFID, AES accelerators | H-field probe + LNA, ChipWhisperer/RTL-SDR
| Çalışma süresi / cache'ler | Desktop ve cloud CPU'ları | High-precision timers (rdtsc/rdtscp), remote time-of-flight
| Akustik / mekanik | Klavyeler, 3-D yazıcılar, röleler | MEMS microphone, laser vibrometer
| Optik ve termal | LED'ler, laser printer'lar, DRAM | Photodiode / high-speed camera, IR camera
| Hata kaynaklı | ASIC/MCU cryptos | Clock/voltage glitch, EMFI, laser injection

---

## Power Analysis

### Simple Power Analysis (SPA)
Tek bir trace gözlemlenir ve tepe/dip noktaları doğrudan işlemlerle (örn. DES S-box'ları) ilişkilendirilir.<sup>[[1]](#references)</sup>
```python
# ChipWhisperer-husky example – capture one AES trace
from chipwhisperer.capture.api.programmers import STMLink
from chipwhisperer.capture import CWSession
cw = CWSession(project='aes')
trig = cw.scope.trig
cw.connect(cw.capture.scopes[0])
cw.capture.init()
trace = cw.capture.capture_trace()
print(trace.wave)  # numpy array of power samples
```
### Differential/Correlation Power Analysis (DPA/CPA)
*N > 1 000* trace topla, key byte `k` için hipotez oluştur, HW/HD modelini hesapla ve leak ile korelasyon kur.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA hâlâ state-of-the-art olmaya devam ediyor, ancak machine-learning varyantları (MLA, deep-learning SCA) artık ASCAD-v2 (2023) gibi yarışmalara hâkim durumda.

---

## Elektromanyetik Analiz (EMA)
Yakın alan EM probları (500 MHz–3 GHz), shunt eklemeden power analysis ile aynı bilgiyi leak eder. 2024 araştırması, spectrum correlation ve düşük maliyetli RTL-SDR front-end'leri kullanarak bir STM32'den **10 cm'den daha uzak** mesafeden key recovery gerçekleştirilebildiğini gösterdi.

---

## Zamanlama ve Micro-architectural Attacks
Modern CPU'lar, paylaşılan kaynaklar üzerinden secret bilgileri leak eder:
* **Hertzbleed (2022)** – DVFS frequency scaling, Hamming weight ile korelasyon oluşturur ve EdDSA key'lerinin *remote* olarak çıkarılmasına olanak tanır.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – SMT thread'leri arasında AVX-gather verilerini okumak için transient-execution kullanır.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) ve Inception (AMD, 2023)** – speculative vector mis-prediction, register'ları domain'ler arasında leak eder.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Acoustic ve Optical Attacks
* 2024 tarihli "​iLeakKeys" çalışması, CNN classifier kullanarak **Zoom üzerinden bir smartphone mikrofonundan** laptop keystroke'larını kurtarmada %95 doğruluk gösterdi.
* High-speed photodiode'lar DDR4 activity LED'ini yakalar ve AES round key'lerini 1 dakikadan kısa sürede yeniden oluşturur (BlackHat 2023).

---

## Fault Injection ve Differential Fault Analysis (DFA)
Fault'ları side-channel leakage ile birleştirmek, key search sürecini kısaltır (ör. 1-trace AES DFA). Son dönemde hobbyist fiyatlı araçlar:
* **ChipSHOUTER ve PicoEMP** – 1 ns'nin altında electromagnetic pulse glitching.
* **GlitchKit-R5 (2025)** – RISC-V SoC'lerini destekleyen open-source clock/voltage glitch platformu.

---

## Typical Attack Workflow
1. Leakage channel ve mount point'i belirle (VCC pin'i, decoupling cap, near-field spot).
2. Trigger ekle (GPIO veya pattern-based).
3. Uygun sampling/filter'lar ile >1 k trace topla.
4. Pre-process uygula (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical veya ML key recovery gerçekleştir (CPA, MIA, DL-SCA).
6. Outlier'ları doğrula ve yinele.

---

## Defences ve Hardening
* **Constant-time** implementasyonlar ve memory-hard algoritmalar.
* **Masking/shuffling** – secret'ları random share'lere böl; first-order resistance'ı TVLA ile doğrula.
* **Hiding** – on-chip voltage regulator'lar, randomised clock, dual-rail logic, EM shield'ler.
* **Fault detection** – redundant computation, threshold signature'lar.
* **Operational** – crypto kernel'lerinde DVFS/turbo'yu devre dışı bırak, SMT'yi izole et, multi-tenant cloud'larda co-location'ı yasakla.

---

## Tools ve Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; yukarıdaki gibi Python API.<sup>[[1]](#references)</sup>
* **Riscure Inspector ve FI** – ticari, automated leakage assessment'ı destekler (TVLA-2.0).
* **scaaml** – TensorFlow tabanlı deep-learning SCA library'si (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA framework'ü.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
