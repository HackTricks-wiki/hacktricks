# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Giriş

**Low-Power Wide Area Network** (LPWAN), düşük bit hızında **uzun menzilli iletişim** için tasarlanmış kablosuz, düşük güç tüketimli geniş alan ağı teknolojileri grubudur.
Radyo parametrelerine, antene, mevzuat bölgesine, araziye ve duty cycle değerine bağlı olarak LPWAN kurulumları, çok kilometrelik kapsama alanı ve çok yıllık pil ömrü karşılığında throughput değerinden ödün verebilir. Üreticilerin menzil ve pil ömrü değerlerini garanti olarak değil, tasarım hedefleri olarak değerlendirin.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) şu anda en yaygın kullanılan LPWAN fiziksel katmanıdır ve açık MAC katmanı spesifikasyonu **LoRaWAN**'dır.

---

## LPWAN, LoRa ve LoRaWAN

* LoRa – Semtech tarafından geliştirilen Chirp Spread Spectrum (CSS) fiziksel katmanı (proprietary ancak belgelenmiştir).
* LoRaWAN – LoRa-Alliance tarafından sürdürülen açık MAC/Network katmanı. 1.0.x ve 1.1 sürümleri sahada yaygındır.
* Tipik mimari: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> LoRaWAN 1.1'de **security model**, OTAA sırasında role özgü session key'leri türetmek için ayrı AES-128 application ve network root key'leri kullanır. Önceki 1.0.x kurulumları normalde network ve application session key'lerini türetmek için tek bir AppKey kullanırken, ABP session key'lerini doğrudan provision eder. Leaked bir key ile elde edilebilecek yetenek, bu nedenle LoRaWAN sürümüne ve hangi key'in açığa çıktığına bağlıdır.<sup>[[3]](#references)</sup>

---

## Attack surface özeti

| Katman | Zayıflık | Pratik etki |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Yerelleştirilmiş packet loss; etkililik link budget'a, zamanlamaya, bant genişliğine ve mevzuat kısıtlamalarına bağlıdır |
| MAC | Nonce/counter state yeniden kullanıldığında join ve data-frame replay | Server/device replay korumalarını ihlal ederse cihaz senkronizasyonunun bozulması, spoofing veya injection |
| Network-Server | Güvensiz packet-forwarder, zayıf MQTT/UDP filtreleri, güncel olmayan gateway firmware'i | Gateway'lerde RCE → OT/IT ağına pivot |
| Application | Hard-coded veya öngörülebilir AppKey'ler | Traffic'i brute-force/decrypt etme, sensörleri taklit etme |

---

## Temsili implementation zafiyetleri

* **CVE-2024-29862** – 4.0.11 öncesindeki ChirpStack Gateway Bridge sürümleri ve 4.2.1 öncesindeki MQTT Forwarder sürümleri, TLS server-certificate validation devre dışı bırakıldığı için attacker-controlled bir MQTT broker'a bağlanabiliyordu. Bu durum credential'ları ve gateway traffic'ini açığa çıkarabilirdi; fixed release'lere upgrade edin.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227, indirilebilir bir backup file içeren unauthenticated `/lib/` directory listing'i tanımlar; CVE-2022-45228 ise logout page üzerinde düşük önem dereceli bir CSRF'dir. Bu kayıtlar, iddia edilen LG308 impact'ini, configuration overwrite'ını, population size'ını veya 2025 patch state'ini doğrulamaz.<sup>[[6]](#references)[[7]](#references)</sup>
* Bu sayfanın önceki bir sürümünde, “LoRa Exploitation Reloaded” Black Hat Europe 2023 sunumuna ve Ekim 2023 tarihli private patch'e atfedilen, Semtech UDP packet-forwarder'a ilişkin iddia edilen bir sorun; **greater-than-255-byte crafted uplink'in SX130x reference gateway'lerinde stack smash ve RCE'ye yol açması** şeklinde açıklanmıştı. Bu kesin ayrıntılar burada bir research lead olarak korunmuştur; ancak bunları doğrulayabilecek eşleşen bir public advisory, presentation veya patch bulunamamıştır. Etkilenen product/version bilgilerini ve doğrulanabilir bir primary source'u edinmeden bu sorunu bilinen bir zafiyet olarak değerlendirmeyin.

---

## Pratik attack teknikleri

### 1. Sniff & Decrypt traffic
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
Bu komutlar özgün iş akışını **açıklayıcı sözdizimi** olarak korur; repository yapısı ve flag'ler projeler/sürümler arasında farklılık gösterir. Pasif capture güçlü bir AppKey ortaya çıkarmaz. Offline tahmin yalnızca root key bulunabilecek kadar zayıf olduğunda ve yakalanan bir join exchange adayları doğrulayabilecek bir değer sağladığında işe yarar.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. OTAA replay protection ve nonce state testi

1. Yetkili bir test ağında geçerli bir **JoinRequest** yakalayın.
2. Aynı isteği replay edin ve network server'ın yeniden kullanılan `DevNonce` değerini reddettiğini doğrulayın.
3. Test cihazını yeniden başlatın veya resetleyin ve kaybolan nonce state'i tespit etmek için kontrolü tekrarlayın. Uyumlu bir server, kullanılan nonce'ları takip etmelidir; yalnızca bir JoinRequest'i replay etmek, yeni türetilen session key'leri açığa çıkarmaz veya replay yapan kişiye bir session üzerinde kontrol sağlamaz.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Adaptive Data-Rate (ADR) düşürme

Network-layer MAC command'larını authenticate edebilen bir attacker; örneğin ilgili network session key'i veya network server'ı compromise ettikten sonra, verimsiz data-rate parametrelerini zorlamayı ve airtime'ı artırmayı deneyebilir. Yakındaki unauthenticated bir transmitter, yalnızca bir cihaz adresini bilerek meşru biçimde ADR command'ları gönderemez.<sup>[[3]](#references)</sup>

### 4. Reactive jamming

Reactive jammer, bir LoRa preamble tespit ettikten sonra transmit ederek frame'leri seçici biçimde bozabilir. Önceki sayfa, bir HackRF/GNU Radio kurulumunun **2 km mesafede ve 200 mW'ı aşmayan güçle** tam kesintiye neden olduğunu iddia ediyordu; ancak bu iddiayı destekleyen bir ölçüm kaynağı sağlanmamıştı. Bu sayıları beklenen sonuç olarak değil, yalnızca reproduction hedefi olarak koruyun. Gerekli transmit power, timing, bandwidth, etkilenen spreading factor'lar ve range ortama özeldir. Yalnızca yetkili ve RF-contained bir kurulum içinde test yapın ve yerel spectrum kurallarına uyun.

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN frame'lerini oluşturma/parse etme/attack, DB-backed analyzer'lar, brute-forcer | Docker image; Semtech UDP input destekler<sup>[[1]](#references)</sup> |
| **LoRaPWN** | OTAA'yı brute etmek, downlink'ler oluşturmak ve payload'ları decrypt etmek için Trend Micro Python utility'si | Public research utility'si; desteklenen hardware ve protocol version'larını doğrulayın<sup>[[2]](#references)</sup> |
| **LoRAttack** | Multi-channel LoRaWAN capture, session analysis, key derivation ve replay testing için research framework'ü | 2024 tarihli bir master's thesis'te açıklanmıştır; example flag'lerine güvenmeden önce tam implementation'ı edinin ve doğrulayın<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | LoRa baseband reception veya transceiver research için GNU Radio out-of-tree block'ları | Projeler GNU Radio uyumluluğu ve feature set açısından farklılık gösterir<sup>[[9]](#references)</sup> |

---

## Defensive recommendations (pentester checklist)

1. **OTAA** kullanmayı tercih edin ve cihazların ve server'ların gerekli nonce state'i persist ettiğini doğrulayın; reddedilen duplicate join'leri izleyin.
2. Desteklendiğinde **LoRaWAN 1.1** kullanmayı tercih edin; böylece network function'ları distinct session key'ler ve güncellenmiş nonce handling kullanır.<sup>[[3]](#references)</sup>
3. Frame-counter'ı non-volatile memory'de (**ABP**) saklayın veya OTAA'ya geçin.
4. Ordinary firmware storage içindeki root key'lerin açığa çıkmasını azaltmak için uygun bir **secure element** (örneğin, desteklenen bir tasarımda ATECC608A) kullanın.
5. Configured packet-forwarder UDP listener'larını (yaygın olarak 1700) untrusted network'lere açmayın; gateway backhaul'u authenticate/encrypt edin veya VPN ile kısıtlayın.
6. Gateway'leri vendor-supported firmware üzerinde tutun ve exact model/version'ı ilgili advisory'lere göre doğrulayın.
7. **Traffic anomaly detection** (ör. LAF analyzer) uygulayın – counter reset'lerini, duplicate join'leri ve ani ADR değişikliklerini flag'leyin.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN genel bakışı](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - LoRaWAN L2 1.1 specification](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - LoRaWAN 1.1 regional parameters and join synchronization](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [CTU thesis catalogue - LPWAN Protocol Security Analysis Leveraging SDR Technology](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [EPFL `gr-lora_sdr` GNU Radio transceiver](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
