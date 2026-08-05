# Yan Kanal Analizi Saldırıları

{{#include ../../banners/hacktricks-training.md}}

Yan kanal saldırıları, cihazın mantıksal arayüzünün parçası olmayan ancak dahili durumla *ilişkili* fiziksel veya mikro-mimari "leakage" gözlemlenerek gizli bilgileri ortaya çıkarır. Örnekler, bir smart-card tarafından anlık olarak çekilen akımın ölçülmesinden ağ üzerinden CPU power-management etkilerinin kötüye kullanılmasına kadar uzanır.

---

## Başlıca Leakage Kanalları

| Kanal | Tipik Hedef | Enstrümantasyon |
|---------|---------------|-----------------|
| Güç tüketimi | Smart-card'lar, IoT MCU'ları, FPGA'ler | Osiloskop + şönt direnç/HS probu (ör. CW503)
| Elektromanyetik alan (EM) | CPU'lar, RFID, AES accelerators | H-field probu + LNA, ChipWhisperer/RTL-SDR
| Çalışma süresi / cache'ler | Desktop ve cloud CPU'ları | Yüksek hassasiyetli zamanlayıcılar (rdtsc/rdtscp), uzaktan time-of-flight
| Akustik / mekanik | Klavyeler, 3-D yazıcılar, röleler | MEMS mikrofonu, laser vibrometer
| Optik ve termal | LED'ler, laser printer'lar, DRAM | Photodiode / high-speed camera, IR camera
| Hata kaynaklı | ASIC/MCU cryptos | Clock/voltage glitch, EMFI, laser injection

---

## Güç Analizi

### Simple Power Analysis (SPA)
*Tek* bir trace gözlemlenir ve peak/valley değerleri doğrudan işlemlerle (ör. DES S-box'ları) ilişkilendirilir.
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
CPA state-of-the-art olmaya devam ediyor, ancak machine-learning varyantları (MLA, deep-learning SCA) artık ASCAD-v2 (2023) gibi yarışmalara hakim.

---

## Electromagnetic Analysis (EMA)
Near-field EM probes (500 MHz–3 GHz), shunt eklemeden power analysis ile aynı bilgiyi leak eder. 2024 araştırması, spectrum correlation ve düşük maliyetli RTL-SDR front-end'leri kullanarak bir STM32'den **>10 cm** mesafeden key recovery gerçekleştirildiğini gösterdi.

---

## Timing & Micro-architectural Attacks
Modern CPU'lar, paylaşılan kaynaklar üzerinden secret bilgileri leak eder:
* **Hertzbleed (2022)** – DVFS frequency scaling, Hamming weight ile korelasyon göstererek EdDSA key'lerinin *remote* extraction işlemine olanak tanır.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – SMT thread'leri arasındaki AVX-gather verilerini okumak için transient-execution.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction, register'ları domain'ler arasında leak eder.

---

## Acoustic & Optical Attacks
* 2024 tarihli "​iLeakKeys", bir CNN classifier kullanarak **Zoom üzerinden bir smart-phone microphone** ile laptop keystroke'larını %95 doğrulukla recovery etti.
* High-speed photodiode'lar DDR4 activity LED'ini capture eder ve AES round key'lerini <1 dakika içinde yeniden oluşturur (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Fault'ları side-channel leakage ile birleştirmek key search işlemini kısaltır (ör. 1-trace AES DFA). Yakın zamanda hobbyist fiyatlı araçlar:
* **ChipSHOUTER & PicoEMP** – 1 ns altı electromagnetic pulse glitching.
* **GlitchKit-R5 (2025)** – RISC-V SoC'lerini destekleyen open-source clock/voltage glitch platformu.

---

## Typical Attack Workflow
1. Leakage channel ve mount point'i belirleyin (VCC pin, decoupling cap, near-field spot).
2. Trigger ekleyin (GPIO veya pattern-based).
3. Uygun sampling/filter'lar ile >1 k trace toplayın.
4. Pre-process uygulayın (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical veya ML key recovery (CPA, MIA, DL-SCA).
6. Outlier'ları validate edin ve süreci yineleyin.

---

## Defences & Hardening
* **Constant-time** implementasyonlar ve memory-hard algorithm'ler.
* **Masking/shuffling** – secret'ları random share'lere ayırın; first-order resistance, TVLA ile certify edilir.
* **Hiding** – on-chip voltage regulator'lar, randomised clock, dual-rail logic, EM shield'leri.
* **Fault detection** – redundant computation, threshold signature'lar.
* **Operational** – crypto kernel'lerinde DVFS/turbo'yu disable edin, SMT'yi isolate edin, multi-tenant cloud'larda co-location'ı yasaklayın.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; yukarıdaki gibi Python API.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – commercial, automated leakage assessment (TVLA-2.0) desteği sunar.
* **scaaml** – TensorFlow tabanlı deep-learning SCA library'si (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA framework'ü.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
