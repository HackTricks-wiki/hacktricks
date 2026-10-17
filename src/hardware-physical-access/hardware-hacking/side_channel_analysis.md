# Yan Kanal Analizi Saldırıları

{{#include ../../banners/hacktricks-training.md}}

Yan kanal saldırıları, cihazın iç durumuyla *ilişkili* olan ancak cihazın mantıksal arayüzünün parçası *olmayan* fiziksel veya mikro-mimari “leakage” gözlemlenerek sırları ortaya çıkarır. Örnekler, akıllı kartın çektiği anlık akımı ölçmekten CPU güç yönetimi etkilerini ağ üzerinden kötüye kullanmaya kadar uzanır.

Erişilebilir ARM debug donanımına sahip bir hedefte, [SWO üzerinden CoreSight ETM tracing](arm-coresight-instruction-tracing.md), güç veya EM kayıtlarının yanında bir yürütme yolu referansı sağlayabilir; bu bir debug trace'dir, leakage kanalı değildir.<sup>[[17]](#references)</sup>

---

## Başlıca Leakage Kanalları

| Kanal | Tipik Hedef | Ölçüm Ekipmanı |
|---------|---------------|-----------------|
| Güç tüketimi | Akıllı kartlar, IoT MCU'ları, FPGA'ler | Osiloskop ve şönt direnç veya diferansiyel prob; CW503, problar/LNA'ler için bir güç kaynağıdır, kendisi bir prob değildir<sup>[[11]](#references)</sup> |
| Elektromanyetik alan (EM) | CPU'lar, RFID, AES hızlandırıcıları | H-alanı/yakın alan probu ve düşük gürültülü amplifikatör ile osiloskop veya RTL-SDR gibi bir SDR alıcısı<sup>[[13]](#references)</sup> |
| Yürütme süresi / cache'ler | Masaüstü ve cloud CPU'ları | Yüksek hassasiyetli zamanlayıcılar (`rdtsc`/`rdtscp`) veya uzak mesafede gidiş-dönüş süresi ölçümü |
| Akustik / mekanik | Klavyeler, 3B yazıcılar, yazıcılar, röleler ve CPU voltaj regülatörleri | MEMS mikrofon veya lazer vibrometre<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optik ve termal | Durum LED'leri, ekranlar, DRAM ve termal olarak bağlantılı cihazlar | Fotodiyot, yüksek hızlı kamera veya IR kamera<sup>[[7]](#references)[[16]](#references)</sup> |
| Hata enjeksiyonu | ASIC/MCU kriptografisi | Clock/voltage glitch, EMFI veya lazer enjeksiyonu |

---

## Güç Analizi

### Basit Güç Analizi (SPA)
Tek bir trace'i gözlemleyin ve görünür özellikleri dallanmalar, modüler çarpma veya farklı komut dizileri gibi işlemlerle ilişkilendirin.<sup>[[1]](#references)</sup>

Kesin kurulum hedefe özeldir. Aşağıdaki örnekte, osiloskop ve hedef bağlanıp yapılandırıldıktan sonra güncel üst düzey ChipWhisperer capture API kullanılır:<sup>[[1]](#references)</sup>

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
Birden fazla trace alın, `k` anahtar baytını varsayın, bir Hamming-weight (HW) veya Hamming-distance (HD) leakage modeli hesaplayın ve bunu her örnekle ilişkilendirin. Gerekli trace sayısı hedefe, gürültüye, hizalamaya, karşı önlemlere ve leakage modeline bağlıdır; sabit bir eşik değildir.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA standart bir temel yöntemdir. Template attacks, mutual-information analysis ve machine-learning yaklaşımları, leakage doğrusal olmadığında veya izler kötü hizalandığında yararlı olabilir.

---

## Elektromanyetik Analiz (EMA)
Yakın alan EM analizi, besleme hattına bir şönt eklemeden veriye bağlı etkinliği gözlemleyebilir. Bu analiz, mutlaka güç izindekiyle aynı sinyali açığa çıkarmaz: probun konumu, yönü, bant genişliği, ön uç kazancı, tetikleme kalitesi ve mesafe önemlidir.

---

## Zamanlama ve Mikro-mimari Saldırıları
Modern CPU'lar, paylaşılan kaynaklar üzerinden sırları sızdırır:
* **Hertzbleed (2022)** – Veriye bağlı dinamik voltaj ve frekans ölçekleme, uzaktan bir zamanlama kanalı oluşturur. Uçtan uca özgün anahtar kurtarma gösterimi SIKE'yi hedeflemiştir; sonraki çalışmalar başka ilkelleri de ele alır.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Geçici yürütme, vektör gather komutlarının kullandığı verileri güvenlik sınırlarının ötesine açığa çıkarabilir.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Spekülatif vektör yazmaç durumunun hatalı işlenmesi, aynı fiziksel çekirdekteki verileri açığa çıkarabilir.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Geçici yürütme saldırısı, saldırganın denetleyebildiği yanlış tahmin gadget'ları oluşturmak için phantom execution'ı geçici yürütme eğitimiyle birleştirir.<sup>[[5]](#references)</sup>

---

## Akustik ve Optik Saldırılar
Akustik leakage, yakındaki bir cep telefonunun mikrofonu kullanılarak yapılanlar da dahil olmak üzere kontrollü bir deneyde dizüstü bilgisayar gürültüsünden RSA anahtarlarını kurtarmak için kullanılmıştır.<sup>[[6]](#references)</sup> 2023'teki ayrı bir klavye çalışması, yakındaki bir telefonla alınan kayıtlarda eğitildiğinde tuş vuruşlarını %95 doğrulukla, Zoom sesinde eğitildiğinde ise %93 doğrulukla sınıflandırmıştır; bu oranlar makaledeki eğitilmiş cihaz deneyini tanımlar, herhangi bir klavye veya kurbanı değil.<sup>[[9]](#references)</sup> Durum LED'lerinden yayılan optik sinyaller de işlenen verilerle ilişkilendirilebilir. Bu sonuçlar hedefe ve düzene özgüdür; menzillerini veya başarı oranlarını ilgisiz cihazlara genellemeyin.<sup>[[7]](#references)</sup>

---

## Hata Enjeksiyonu ve Diferansiyel Hata Analizi (DFA)
Kontrollü hataları yan kanal gözlemleriyle birleştirmek, bazı algoritmalar ve uygulamalarda anahtar aramasını azaltabilir. Yaygın laboratuvar platformları arasında ChipWhisperer'ın voltaj/saat glitching özellikleri ve ChipSHOUTER veya PicoEMP gibi özel EM hata enjeksiyon araçları bulunur. Önceki taslaktaki “sub-1 ns” açıklaması bir teknik özellik olarak kullanılmamalıdır: ChipSHOUTER'ın yayımlanmış kılavuzu, 1 mm uçla tipik olarak **15–80 ns**, 4 mm uçla ise **24–480 ns** darbe genişlikleri belirtir (tetikleme/darbe jitter'ı pikosaniye cinsinden belirtilmiş olsa da). Gerekli zamanlama çözünürlüğü, prob yerleşimi ve hatalı çıktılarının sayısı hedefe ve hata modeline bağlıdır.<sup>[[1]](#references)[[10]](#references)</sup>

## Önceki Taslaktan Korunan Doğrulanmamış Araştırma İpuçları

Önceki taslak ayrıca şu iddialarda bulunmuştur: RTL-SDR kullanarak **10 cm**'den daha uzak mesafeden STM32 anahtarını kurtaran **500 MHz–3 GHz** EM düzeneği; “Black Hat 2023” etkinliğinde bir DDR4 etkinlik LED'inin bir AES tur anahtarını bir dakikadan kısa sürede açığa çıkarması; ve **GlitchKit-R5** adlı, 2025 tarihli açık kaynaklı RISC-V glitching platformu. Bu denetim sırasında bunlarla eşleşen birincil bir makale, konferans materyali veya proje deposu bulunamamıştır. Bu kesin ayrıntılar, doğrulanmış sonuçlar veya araç önerileri olarak değil, araştırma/yeniden üretim ipuçları olarak korunmuştur.

---

## Tipik Saldırı İş Akışı
1. Leakage kanalını ve bağlantı noktasını belirleyin (VCC pini, ayrıştırma kapasitörü, yakın alan noktası).
2. Tetikleyici ekleyin (GPIO veya desene dayalı).
3. Seçilen istatistiksel test için yeterli sayıda iz toplayın; açık metin/şifreli metin ve diğer meta verileri kaydedin.
4. Ön işleme uygulayın (hizalama, ortalama çıkarma, LP/HP filtresi, wavelet, PCA).
5. İstatistiksel veya ML ile anahtar kurtarma (CPA, MIA, DL-SCA).
6. Aykırı değerleri doğrulayın ve yineleyin.

---

## Savunma ve Güçlendirme
* **Sabit zamanlı** uygulamalar ve bellek yoğun algoritmalar.
* **Masking/shuffling** – Sırları rastgele paylara bölün; birinci dereceden direnç TVLA ile sertifikalandırılır.
* **Gizleme** – Yongada voltaj regülatörleri, rastgeleleştirilmiş saat, çift raylı mantık, EM kalkanları.
* **Hata tespiti** – Yedekli hesaplama, eşik imzaları.
* **Operasyonel** – Kripto çekirdeklerinde DVFS/turbo'yu devre dışı bırakın, SMT'yi yalıtın, çok kiracılı bulutlarda aynı makinede çalıştırmayı yasaklayın.

---

## Araçlar ve Çerçeveler
* **ChipWhisperer-Husky** (2024) – 500 MS/s osiloskop + Cortex-M tetikleyicisi; yukarıdaki gibi Python API'si.<sup>[[1]](#references)</sup>
* **Riscure Inspector ve fault-injection ürünleri** – Ticari analiz ve otomatik test araçları.
* **scaaml** – TensorFlow tabanlı deep-learning SCA araçları ve veri kümeleri.<sup>[[12]](#references)</sup>
* **pyecsca** – Yan kanallar aracılığıyla black-box ECC uygulamalarını tersine mühendislikle incelemek için açık kaynaklı araç takımı.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer Belgeleri](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Saldırısı Makalesi](https://www.hertzbleed.com/)
- [3] [Downfall: Spekülatif Veri Toplamanın İstismarı](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Geçici Yürütmede Eğitimle Yeni Saldırı Yüzeylerinin Ortaya Çıkarılması](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Düşük Bant Genişlikli Akustik Kriptanaliz Yoluyla RSA Anahtarı Çıkarma](https://eprint.iacr.org/2013/857.pdf)
- [7] [Optik Yayılımlardan Bilgi Sızıntısı](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca artifact belgeleri](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Klavyelere Yönelik Pratik Bir Deep Learning Tabanlı Akustik Yan Kanal Saldırısı](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER kullanıcı kılavuzu](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer belgeleri — CW503 prob güç kaynağı](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML belgeleri](https://google.github.io/scaaml/)
- [13] [FOSDEM — RTL-SDR kullanarak düşük maliyetli elektromanyetik yan kanal saldırıları gerçekleştirme](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Fikri Mülkiyetin Şifresini Çözmek: 3B Yazıcıya Yönelik Akustik ve Manyetik Yan Kanal Saldırısı](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Yazıcılara Yönelik Akustik Yan Kanal Saldırıları](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [DRAM Kullanarak Sıcaklığı Gözetleme](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [Komutları İzlemek: ETM, ITM ve TPIU ile Canlı ARM İzleme](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
