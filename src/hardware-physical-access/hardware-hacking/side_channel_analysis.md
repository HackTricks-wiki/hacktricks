# Yan Kanal Analizi Saldırıları

{{#include ../../banners/hacktricks-training.md}}

Yan kanal saldırıları, cihazın mantıksal arayüzünün *parçası olmayan* ancak dahili durumla *ilişkili* fiziksel veya mikro mimari "leakage" gözlemlenerek sırları ortaya çıkarır. Örnekler, akıllı kartın anlık çektiği akımı ölçmekten CPU güç yönetimi etkilerini ağ üzerinden kötüye kullanmaya kadar uzanır.

---

## Başlıca Leakage Kanalları

| Kanal | Tipik Hedef | Ölçüm Ekipmanı |
|---------|---------------|-----------------|
| Güç tüketimi | Akıllı kartlar, IoT MCU'ları, FPGA'lar | Osiloskop ve şönt direnç veya diferansiyel prob; CW503, problar/LNA'lar için bir güç kaynağıdır, probun kendisi değildir<sup>[[11]](#references)</sup> |
| Elektromanyetik alan (EM) | CPU'lar, RFID, AES hızlandırıcıları | H-alanı/yakın alan probu ve düşük gürültülü amplifikatör ile osiloskop veya RTL-SDR gibi bir SDR alıcısı<sup>[[13]](#references)</sup> |
| Çalışma süresi / önbellekler | Masaüstü ve bulut CPU'ları | Yüksek hassasiyetli zamanlayıcılar (`rdtsc`/`rdtscp`) veya uzaktan uçuş süresi ölçümü |
| Akustik / mekanik | Klavyeler, 3D yazıcılar, yazıcılar, röleler ve CPU voltaj regülatörleri | MEMS mikrofon veya lazer vibrometresi<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optik ve termal | Durum LED'leri, ekranlar, DRAM ve termal olarak eşleşmiş cihazlar | Fotodiyot, yüksek hızlı kamera veya IR kamera<sup>[[7]](#references)[[16]](#references)</sup> |
| Hata enjeksiyonu | ASIC/MCU kriptografisi | Saat/voltaj glitch'i, EMFI veya lazer enjeksiyonu |

---

## Güç Analizi

### Basit Güç Analizi (SPA)
Tek bir iz gözlemlenir ve görünür özellikler dallanma, modüler çarpma veya farklı komut dizileri gibi işlemlerle ilişkilendirilir.<sup>[[1]](#references)</sup>

Kesin kurulum hedefe özgüdür. Aşağıdaki örnekte, osiloskop ve hedef bağlanıp yapılandırıldıktan sonra güncel üst düzey ChipWhisperer capture API kullanılır:<sup>[[1]](#references)</sup>

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
Birden fazla trace edinin, `k` anahtar baytını varsayın, Hamming-weight (HW) veya Hamming-distance (HD) leak modelini hesaplayın ve her örnekle korelasyonunu bulun. Gerekli trace sayısı hedefe, gürültüye, hizalamaya, karşı önlemlere ve leak modeline bağlıdır; sabit bir eşik değildir.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA standart bir temel yöntemdir. Template attacks, mutual-information analysis ve machine-learning yaklaşımları, leakage doğrusal olmadığında veya izler kötü hizalandığında faydalı olabilir.

---

## Elektromanyetik Analiz (EMA)
Yakın alan EM analizi, besleme yoluna shunt eklemeden veriye bağlı etkinliği gözlemleyebilir. Bu analiz, güç izindeki sinyalle aynı sinyali mutlaka açığa çıkarmaz: probun konumu, yönü, bant genişliği, ön uç kazancı, tetikleme kalitesi ve mesafe önem taşır.

---

## Zamanlama ve Mikro-mimari Saldırılar
Modern CPU'lar sır paylaşılan kaynaklar üzerinden sızdırır:
* **Hertzbleed (2022)** – Veriye bağlı dinamik voltaj ve frekans ölçekleme, uzaktan kullanılabilen bir zamanlama kanalı oluşturur. Orijinal uçtan uca anahtar kurtarma gösterimi SIKE'yi hedeflemiştir; sonraki çalışmalar başka ilkelleri ele alır.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Geçici yürütme, vektör gather talimatlarının kullandığı verileri güvenlik sınırlarının ötesine taşıyıp açığa çıkarabilir.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Spekülatif vektör yazmaç durumunun hatalı işlenmesi, aynı fiziksel çekirdekteki verileri ifşa edebilir.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Geçici yürütme saldırısı, phantom execution'ı geçici yürütme sırasında eğitimle birleştirerek saldırganın kontrolündeki yanlış tahmin gadget'ları oluşturur.<sup>[[5]](#references)</sup>

---

## Akustik ve Optik Saldırılar
Akustik leakage, kontrollü bir deneyde dizüstü bilgisayar gürültüsünden RSA anahtarlarını kurtarmak için kullanılmıştır; yakındaki bir cep telefonunun mikrofonu da bu deneyde kullanılmıştır.<sup>[[6]](#references)</sup> 2023'te yapılan ayrı bir klavye çalışmasında, yakındaki bir telefonla kaydedilen seslerle eğitildiğinde tuş vuruşları %95, Zoom sesiyle eğitildiğinde ise %93 doğrulukla sınıflandırılmıştır; bu oranlar makalede incelenen, belirli cihazlarla eğitilmiş deneyi ifade eder; rastgele bir klavye veya kurban için geçerli değildir.<sup>[[9]](#references)</sup> Durum LED'lerinden yayılan optik sinyaller de işlenen verilerle ilişkilendirilebilir. Bu sonuçlar hedefe ve düzene özgüdür; menzillerini veya başarı oranlarını ilgisiz cihazlara genellemeyin.<sup>[[7]](#references)</sup>

---

## Hata Enjeksiyonu ve Diferansiyel Hata Analizi (DFA)
Kontrollü hataları side-channel gözlemleriyle birleştirmek, bazı algoritmaların ve uygulamaların anahtar arama alanını daraltabilir. Yaygın laboratuvar platformları arasında ChipWhisperer'ın voltaj/saat glitching özellikleri ile ChipSHOUTER veya PicoEMP gibi özel EM hata enjeksiyon araçları bulunur. Önceki taslaktaki “sub-1 ns” tanımı bir teknik özellik olarak kullanılmamalıdır: ChipSHOUTER'ın yayımlanmış kılavuzu, 1 mm ucuyla tipik olarak **15–80 ns**, 4 mm ucuyla ise **24–480 ns** darbe genişlikleri belirtir (tetikleme/darbe jitter'ı pikosaniye cinsinden belirtilse de). Gerekli zamanlama çözünürlüğü, prob yerleşimi ve hatalı çıktı sayısı hedefe ve hata modeline bağlıdır.<sup>[[1]](#references)[[10]](#references)</sup>

## Önceki Taslaktan Korunan Doğrulanmamış Araştırma İpuçları

Önceki taslakta ayrıca şu iddialar yer alıyordu: RTL-SDR kullanarak **10 cm**'den daha uzak bir mesafeden STM32 anahtarını kurtaran **500 MHz–3 GHz** EM düzeneği; “Black Hat 2023”te bir dakikadan kısa sürede AES tur anahtarını açığa çıkaran DDR4 etkinlik LED'i; ve **GlitchKit-R5** adlı, 2025'te yayımlanmış açık kaynaklı RISC-V glitching platformu. Bu denetim sırasında bu ayrıntılarla eşleşen birincil makale, konferans materyali veya proje deposu bulunamadı. Bu kesin ayrıntılar, doğrulanmış sonuçlar ya da araç önerileri olarak değil, arama/yeniden üretme ipuçları olarak korunmuştur.

---

## Tipik Saldırı İş Akışı
1. Leakage kanalını ve bağlantı noktasını belirleyin (VCC pini, decoupling kondansatörü, yakın alan noktası).
2. Tetikleyici ekleyin (GPIO veya örüntü tabanlı).
3. Seçilen istatistiksel test için yeterli sayıda iz toplayın; plaintext/ciphertext ve diğer meta verileri kaydedin.
4. Ön işleme uygulayın (hizalama, ortalama çıkarma, LP/HP filtre, wavelet, PCA).
5. İstatistiksel veya ML ile anahtar kurtarma (CPA, MIA, DL-SCA).
6. Aykırı değerleri doğrulayın ve yineleyin.

---

## Savunmalar ve Güçlendirme
* **Sabit zamanlı** uygulamalar ve belleği yoğun kullanan algoritmalar.
* **Masking/shuffling** – sırları rastgele paylara bölün; birinci derece direnç TVLA ile sertifikalandırılır.
* **Hiding** – çip üzeri voltaj regülatörleri, rastgeleleştirilmiş saat, çift hatlı mantık, EM kalkanları.
* **Hata tespiti** – yedekli hesaplama, eşik imzaları.
* **Operasyonel** – kripto çekirdeklerinde DVFS/turbo'yu devre dışı bırakın, SMT'yi yalıtın, çok kiracılı bulutlarda aynı ana makinede birlikte çalışmayı yasaklayın.

---

## Araçlar ve Framework'ler
* **ChipWhisperer-Husky** (2024) – 500 MS/s osiloskop + Cortex-M tetikleyicisi; yukarıdaki gibi Python API'si.<sup>[[1]](#references)</sup>
* **Riscure Inspector ve hata enjeksiyon ürünleri** – ticari analiz ve otomatik test araçları.
* **scaaml** – TensorFlow tabanlı deep-learning SCA araçları ve veri kümeleri.<sup>[[12]](#references)</sup>
* **pyecsca** – black-box ECC uygulamalarını side-channel üzerinden tersine mühendislik için açık kaynaklı araç takımı.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer Belgeleri](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Saldırı Makalesi](https://www.hertzbleed.com/)
- [3] [Downfall: Spekülatif Veri Toplamanın İstismarı](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Geçici Yürütme Sırasında Eğitimle Yeni Saldırı Yüzeylerinin Ortaya Çıkarılması](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Düşük Bant Genişlikli Akustik Kriptanalizle RSA Anahtarı Çıkarımı](https://eprint.iacr.org/2013/857.pdf)
- [7] [Optik Yayılımlardan Bilgi Sızıntısı](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca yapıt belgeleri](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Klavyelere Yönelik Uygulamalı Deep Learning Tabanlı Akustik Side-Channel Saldırısı](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER kullanıcı kılavuzu](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer belgeleri — CW503 prob güç kaynağı](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML belgeleri](https://google.github.io/scaaml/)
- [13] [FOSDEM — RTL-SDR kullanarak düşük maliyetli elektromanyetik side-channel saldırıları gerçekleştirme](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Fikri Mülkiyetin Kodunu Çözmek: 3D Yazıcıya Yönelik Akustik ve Manyetik Side-Channel Saldırısı](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Yazıcılara Yönelik Akustik Side-Channel Saldırıları](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [DRAM Kullanarak Sıcaklığı Gözetlemek](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
