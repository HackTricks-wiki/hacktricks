# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Giriş

**Low-Power Wide Area Network** (LPWAN), düşük bit hızında **uzun menzilli iletişim** için tasarlanmış, düşük güç tüketimli geniş alan kablosuz ağ teknolojileri grubudur.
Radyo parametrelerine, antene, mevzuat bölgesine, araziye ve görev döngüsüne bağlı olarak LPWAN kurulumları; çok kilometrelik kapsama alanı ve yıllarca pil ömrü karşılığında veri aktarım hızından ödün verebilir. Üreticilerin menzil ve pil ömrü değerlerini garanti değil, tasarım hedefi olarak değerlendirin.<sup>[[3]](#references)</sup>

Long Range (**LoRa**), günümüzde en yaygın kullanılan LPWAN fiziksel katmanıdır; açık MAC katmanı spesifikasyonu ise **LoRaWAN**'dır.

---

## LPWAN, LoRa ve LoRaWAN

* LoRa – Semtech tarafından geliştirilen Chirp Spread Spectrum (CSS) fiziksel katmanı (tescilli, ancak belgelenmiştir).
* LoRaWAN – LoRa-Alliance tarafından sürdürülen açık MAC/Ağ katmanı. 1.0.x ve 1.1 sürümleri sahada yaygındır.
* Tipik mimari: *uç cihaz → ağ geçidi (packet-forwarder) → ağ sunucusu → uygulama sunucusu*.<sup>[[3]](#references)</sup>

> LoRaWAN 1.1'de **güvenlik modeli**, OTAA sırasında role özgü oturum anahtarları türetmek için ayrı AES-128 uygulama ve ağ kök anahtarları kullanır. Önceki 1.0.x kurulumlarında genellikle ağ ve uygulama oturum anahtarlarını türetmek için tek bir AppKey kullanılırken, ABP'de oturum anahtarları doğrudan sağlanır. Sızdırılmış bir anahtarın sağlayabileceği yetenek bu nedenle LoRaWAN sürümüne ve hangi anahtarın açığa çıktığına bağlıdır.<sup>[[3]](#references)</sup>

---

## Saldırı yüzeyinin özeti

| Katman | Zafiyet | Pratik etki |
|-------|----------|------------------|
| PHY | Reaktif / seçici jamming | Yerel paket kaybı; etkililik bağlantı bütçesine, zamanlamaya, bant genişliğine ve mevzuat kısıtlamalarına bağlıdır |
| MAC | Nonce/sayaç durumunun yeniden kullanıldığı durumlarda join ve veri çerçevesi replay'i | Sunucu/cihaz replay korumalarını ihlal ederse cihazın senkronizasyonunun bozulması, spoofing veya enjeksiyon |
| Ağ Sunucusu | Güvenli olmayan packet-forwarder, zayıf MQTT/UDP filtreleri, güncel olmayan ağ geçidi firmware'i | Ağ geçitlerinde RCE → OT/IT ağına geçiş |
| Uygulama | Sabit kodlanmış veya tahmin edilebilir AppKey'ler | Trafiği brute-force ile çözme/şifresini çözme, sensörleri taklit etme |

---

## Temsili uygulama zafiyetleri

* **CVE-2024-29862** – ChirpStack Gateway Bridge 4.0.11 öncesi sürümleri ve MQTT Forwarder 4.2.1 öncesi sürümleri, TLS sunucu sertifikası doğrulaması devre dışı olduğu için saldırganın kontrolündeki bir MQTT broker'a bağlanabiliyordu. Bu durum kimlik bilgilerini ve ağ geçidi trafiğini açığa çıkarabilirdi; düzeltilmiş sürümlere yükseltin.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227, indirilebilir bir yedek dosyası içeren kimlik doğrulamasız bir `/lib/` dizin listelemesini tanımlar; CVE-2022-45228 ise oturum kapatma sayfasındaki düşük önem dereceli bir CSRF zafiyetidir. Bu kayıtlar, iddia edilen LG308 etkisini, yapılandırmanın üzerine yazılmasını, etkilenen cihaz sayısını veya 2025 yama durumunu doğrulamaz.<sup>[[6]](#references)[[7]](#references)</sup>
* Bu sayfanın önceki bir sürümünde, Semtech UDP packet-forwarder'da olduğu iddia edilen bir sorun **SX130x referans ağ geçitlerinde stack smash ve RCE'ye yol açan 255 bayttan uzun, özel olarak hazırlanmış bir uplink** şeklinde açıklanmış; “LoRa Exploitation Reloaded” adlı Black Hat Europe 2023 sunumuna ve Ekim 2023'te yayımlanan özel bir yamaya atfedilmişti. Bu kesin ayrıntılar bir araştırma ipucu olarak burada korunmaktadır, ancak bunları doğrulayan eşleşen bir kamuya açık güvenlik duyurusu, sunum veya yama bulunamamıştır. Etkilenen ürün/sürüm ve doğrulanabilir bir birincil kaynak edinmeden bu sorunu bilinen bir zafiyet olarak değerlendirmeyin.

---

## Pratik saldırı teknikleri

### 1. Sniff & Decrypt traffic

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

Bu komutlar özgün iş akışını **örnek sözdizimi** olarak korur; depo düzeni ve flag'ler projeler/sürümler arasında farklılık gösterir. Pasif yakalama güçlü bir AppKey'i ortaya çıkarmaz. Çevrimdışı tahmin, yalnızca kök anahtar bulunabilecek kadar zayıfsa ve yakalanan bir join alışverişi adayları doğrulayabilecek bir değer sağlıyorsa işe yarar.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. OTAA replay korumasını ve nonce durumunu test etme

1. Yetkili bir test ağında meşru bir **JoinRequest** yakalayın.
2. Aynı isteği yeniden oynatın ve ağ sunucusunun yeniden kullanılan `DevNonce` değerini reddettiğini doğrulayın.
3. Kaybolan nonce durumunu tespit etmek için test cihazını yeniden başlatın veya sıfırlayın ve kontrolü tekrarlayın. Uyumlu bir sunucu, kullanılan nonce değerlerini izlemelidir; yalnızca bir JoinRequest'i yeniden oynatmak, yeni türetilen oturum anahtarlarını açığa çıkarmaz veya isteği yeniden oynatana oturum üzerinde kontrol vermez.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Adaptive Data-Rate (ADR) düşürme

Ağ katmanı MAC komutlarını doğrulayabilen bir saldırgan —örneğin, ilgili ağ oturum anahtarını veya ağ sunucusunu ele geçirdikten sonra— verimsiz veri hızı parametrelerini zorlamaya ve yayın süresini artırmaya çalışabilir. Yakındaki kimlik doğrulaması yapılmamış bir verici, yalnızca cihaz adresini bilerek meşru biçimde ADR komutları gönderemez.<sup>[[3]](#references)</sup>

### 4. Tepkisel jamming

Tepkisel bir jammer, LoRa preamble'ını algıladıktan sonra iletim yaparak frame'leri seçici biçimde bozabilir. Önceki sayfada, HackRF/GNU Radio kurulumunun **2 km'de ve en fazla 200 mW güçle** tam kesintiye yol açtığı iddia edilmişti; ancak bunu destekleyen bir ölçüm kaynağı sunulmamıştı. Bu sayıları beklenen sonuç olarak değil, yalnızca yeniden üretim hedefi olarak değerlendirin. Gerekli iletim gücü, zamanlama, bant genişliği, etkilenen spreading factor değerleri ve menzil ortama göre değişir. Yalnızca yetkili ve RF yalıtımlı bir kurulumda test yapın ve yerel spektrum kurallarına uyun.

---

## Saldırgan araçları (2025)

| Araç | Amaç | Notlar |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN frame'leri oluşturma/ayrıştırma/saldırma, DB destekli analiz araçları, brute-forcer | Docker image; Semtech UDP girişini destekler<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Trend Micro'nun OTAA'ya brute-force uygulamak, downlink oluşturmak ve payload'ları çözmek için geliştirdiği Python aracı | Herkese açık araştırma aracı; desteklenen donanım ve protokol sürümlerini doğrulayın<sup>[[2]](#references)</sup> |
| **LoRAttack** | Çok kanallı LoRaWAN yakalama, oturum analizi, anahtar türetme ve replay testleri için araştırma framework'ü | 2024 tarihli bir yüksek lisans tezinde açıklanmıştır; örnek flag'lere güvenmeden önce tam uygulamayı edinin ve doğrulayın<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | LoRa baseband alımı veya alıcı-verici araştırması için GNU Radio out-of-tree blokları | Projeler GNU Radio uyumluluğu ve özellik kümesi bakımından farklılık gösterir<sup>[[9]](#references)</sup> |

---

## Savunma önerileri (pentester kontrol listesi)

1. **OTAA** kullanmayı tercih edin ve cihazların ve sunucuların gerekli nonce durumunu kalıcı olarak sakladığını doğrulayın; reddedilen yinelenen join'leri izleyin.
2. Ağ işlevlerinin ayrı oturum anahtarları ve güncellenmiş nonce işleme yöntemleri kullanması için desteklenen yerlerde **LoRaWAN 1.1** kullanmayı tercih edin.<sup>[[3]](#references)</sup>
3. Frame counter değerini kalıcı bellekte saklayın (**ABP**) veya OTAA'ya geçin.
4. Root key'lerin sıradan firmware depolamasında açığa çıkma riskini azaltmak için uygun bir **secure element** (örneğin, desteklenen bir tasarımda ATECC608A) kullanın.
5. Yapılandırılmış packet-forwarder UDP listener'larını (genellikle 1700) güvenilmeyen ağlara açmayın; gateway backhaul trafiğini doğrulayın/şifreleyin veya VPN ile kısıtlayın.
6. Gateway'leri üretici tarafından desteklenen firmware sürümlerinde tutun ve tam model/sürümü ilgili güvenlik duyurularına göre doğrulayın.
7. **Trafik anomali tespiti** uygulayın (ör. LAF analyzer) – counter sıfırlamalarını, yinelenen join'leri ve ani ADR değişikliklerini işaretleyin.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Denetim Framework'ü (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN genel bakışı](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1 specification](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1 bölgesel parametreleri ve join senkronizasyonu](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU tez kataloğu - SDR Teknolojisinden Yararlanarak LPWAN Protokol Güvenlik Analizi](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio alıcı-vericisi](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
