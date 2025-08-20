# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel saldırıları, fiziksel veya mikro-mimari "sızıntıları" gözlemleyerek sırları geri kazanır; bu sızıntılar, iç durumla *ilişkili* ancak cihazın mantıksal arayüzünün *bir parçası* değildir. Örnekler, bir akıllı kartın anlık akımını ölçmekten, bir ağ üzerinden CPU güç yönetimi etkilerini kötüye kullanmaya kadar uzanır.

---

## Ana Sızıntı Kanalları

| Kanal | Tipik Hedef | Aletler |
|-------|-------------|---------|
| Güç tüketimi | Akıllı kartlar, IoT MCU'lar, FPGA'lar | Osiloskop + şönt direnç/HS probu (örn. CW503) |
| Elektromanyetik alan (EM) | CPU'lar, RFID, AES hızlandırıcıları | H-alan probu + LNA, ChipWhisperer/RTL-SDR |
| İcra süresi / önbellekler | Masaüstü & bulut CPU'ları | Yüksek hassasiyetli zamanlayıcılar (rdtsc/rdtscp), uzaktan zaman uçuşu |
| Akustik / mekanik | Klavyeler, 3-D yazıcılar, röleler | MEMS mikrofon, lazer vibrometre |
| Optik & termal | LED'ler, lazer yazıcılar, DRAM | Fotodiyot / yüksek hızlı kamera, IR kamera |
| Hata kaynaklı | ASIC/MCU kriptoları | Saat/voltaj hatası, EMFI, lazer enjeksiyonu |

---

## Güç Analizi

### Basit Güç Analizi (SPA)
*Tek* bir iz gözlemleyin ve zirveleri/çukurları işlemlerle doğrudan ilişkilendirin (örn. DES S-kutuları).
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
### Diferansiyel/Korelasyon Güç Analizi (DPA/CPA)
*N > 1 000* iz elde edin, anahtar baytı `k` varsayın, HW/HD modelini hesaplayın ve sızıntı ile ilişkilendirin.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA, en son teknoloji olmayı sürdürüyor ancak makine öğrenimi varyantları (MLA, derin öğrenme SCA) artık ASCAD-v2 (2023) gibi yarışmalarda hakim durumda.

---

## Elektromanyetik Analiz (EMA)
Yakın alan EM probeleri (500 MHz–3 GHz), şant eklemeden güç analizine *eşit* bilgiler sızdırır. 2024 araştırması, spektrum korelasyonu ve düşük maliyetli RTL-SDR ön uçları kullanarak **>10 cm** mesafeden bir STM32'den anahtar kurtarma gösterdi.

---

## Zamanlama ve Mikro-mimari Saldırılar
Modern CPU'lar, paylaşılan kaynaklar aracılığıyla sırları sızdırır:
* **Hertzbleed (2022)** – DVFS frekans ölçeklendirmesi, Hamming ağırlığı ile korelasyon gösterir ve *uzaktan* EdDSA anahtarlarının çıkarılmasına olanak tanır.
* **Downfall / Gather Data Sampling (Intel, 2023)** – geçici yürütme ile SMT iş parçacıkları arasında AVX-gather verilerini okuma.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – spekülatif vektör yanlış tahmini, kayıtları alanlar arası sızdırır.

---

## Akustik ve Optik Saldırılar
* 2024 "​iLeakKeys", bir **akıllı telefon mikrofonu üzerinden Zoom** kullanarak dizüstü bilgisayar tuş vuruşlarını %95 doğrulukla kurtardığını gösterdi.
* Yüksek hızlı fotodiyotlar, DDR4 aktivite LED'ini yakalar ve AES tur anahtarlarını <1 dakikada yeniden oluşturur (BlackHat 2023).

---

## Hata Enjeksiyonu ve Diferansiyel Hata Analizi (DFA)
Hataları yan kanal sızıntısı ile birleştirmek, anahtar aramasını kısaltır (örneğin, 1-iz AES DFA). Son zamanlarda hobi fiyatlı araçlar:
* **ChipSHOUTER & PicoEMP** – alt-1 ns elektromanyetik darbe bozulması.
* **GlitchKit-R5 (2025)** – RISC-V SoC'leri destekleyen açık kaynak saat/voltaj bozulma platformu.

---

## Tipik Saldırı İş Akışı
1. Sızıntı kanalını ve montaj noktasını belirleyin (VCC pini, ayrıştırma kapasitörü, yakın alan noktası).
2. Tetikleyici ekleyin (GPIO veya desen tabanlı).
3. Uygun örnekleme/filtrelerle >1 k iz toplayın.
4. Ön işleme (hizalama, ortalama çıkarma, LP/HP filtre, dalgacık, PCA).
5. İstatistiksel veya ML anahtar kurtarma (CPA, MIA, DL-SCA).
6. Aykırı değerleri doğrulayın ve yineleyin.

---

## Savunmalar ve Sertleştirme
* **Sabit zaman** uygulamaları ve bellek-zor algoritmalar.
* **Maskeleme/karıştırma** – sırları rastgele paylara bölün; birinci dereceden direnç TVLA tarafından sertifikalandırılmıştır.
* **Gizleme** – yonga üzeri voltaj regülatörleri, rastgeleleştirilmiş saat, çift ray mantığı, EM kalkanları.
* **Hata tespiti** – yedek hesaplama, eşik imzaları.
* **Operasyonel** – kripto çekirdeklerinde DVFS/turbo'yu devre dışı bırakın, SMT'yi izole edin, çok kiracılı bulutlarda birlikte yerleştirmeyi yasaklayın.

---

## Araçlar ve Çerçeveler
* **ChipWhisperer-Husky** (2024) – 500 MS/s osiloskop + Cortex-M tetikleyici; yukarıdaki gibi Python API.
* **Riscure Inspector & FI** – ticari, otomatik sızıntı değerlendirmesini destekler (TVLA-2.0).
* **scaaml** – TensorFlow tabanlı derin öğrenme SCA kütüphanesi (v1.2 – 2025).
* **pyecsca** – ANSSI açık kaynak ECC SCA çerçevesi.

---

## Referanslar

* [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
* [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
