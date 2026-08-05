# Düşük Güçlü Geniş Alan Ağı

{{#include ../../banners/hacktricks-training.md}}

## Giriş

**Düşük Güçlü Geniş Alan Ağı** (LPWAN), düşük bit hızında **uzun mesafeli iletişim** için tasarlanmış kablosuz, düşük güçlü, geniş alan ağı teknolojileri grubudur.
**Altı milden** daha uzağa ulaşabilir ve **pilleri** **20 yıla** kadar dayanabilir.

Long Range (**LoRa**) günümüzde en yaygın kullanılan LPWAN fiziksel katmanıdır ve açık MAC katmanı spesifikasyonu **LoRaWAN**'dır.

---

## LPWAN, LoRa ve LoRaWAN

* LoRa – Semtech tarafından geliştirilen Chirp Spread Spectrum (CSS) fiziksel katmanı (tescilli ancak belgelenmiştir).
* LoRaWAN – LoRa-Alliance tarafından sürdürülen açık MAC/Ağ katmanı. 1.0.x ve 1.1 sürümleri sahada yaygındır.
* Tipik mimari: *uç cihazı → gateway (packet-forwarder) → network-server → application-server*.

> **Güvenlik modeli**, *join* prosedürü (OTAA) sırasında session key'ler türeten veya sabit kodlanmış olan (ABP) iki AES-128 root key'e (AppKey/NwkKey) dayanır. Herhangi bir key leak ederse saldırgan, ilgili trafik üzerinde tam okuma/yazma yeteneği kazanır.

---

## Saldırı yüzeyi özeti

| Katman | Zayıflık | Pratik etki |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Tek SDR ve <1 W çıkışla %100 paket kaybı gösterildi |
| MAC | Join-Accept ve data-frame replay (nonce yeniden kullanımı, ABP counter rollover) | Cihaz taklidi, mesaj enjeksiyonu, DoS |
| Network-Server | Güvenli olmayan packet-forwarder, zayıf MQTT/UDP filtreleri, güncel olmayan gateway firmware'i | Gateway'lerde RCE → OT/IT ağına pivot |
| Application | Sabit kodlanmış veya öngörülebilir AppKey'ler | Trafiği brute-force/decrypt etme, sensörleri taklit etme |

---

## Güncel güvenlik açıkları (2023-2025)

* **CVE-2024-29862** – *ChirpStack gateway-bridge & mqtt-forwarder*, Kerlink gateway'lerinde stateful firewall kurallarını bypass eden TCP paketlerini kabul ederek uzaktan yönetim arayüzünün açığa çıkmasına olanak sağladı. Sırasıyla 4.0.11 / 4.2.1 sürümlerinde düzeltildi .
* **Dragino LG01/LG308 series** – 2022-2024 arasındaki birden fazla CVE (ör. 2022-45227 directory traversal, 2022-45228 CSRF) 2025'te hâlâ patch uygulanmamış sistemlerde gözlemlendi; binlerce public gateway'de kimlik doğrulaması olmadan firmware dump veya config overwrite yapılmasına olanak sağlıyor .
* Semtech *packet-forwarder UDP* overflow (yayımlanmamış advisory, 2023-10'da patch'lendi): 255 B'den büyük hazırlanmış bir uplink, SX130x referans gateway'lerinde stack-smash ‑> RCE tetikledi (Black Hat EU 2023 “LoRa Exploitation Reloaded” tarafından bulundu).

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
### 2. OTAA join-replay (DevNonce reuse)

1. Meşru bir **JoinRequest** yakalayın.
2. Orijinal cihaz tekrar iletim yapmadan önce bunu hemen yeniden iletin (veya RSSI değerini artırın).
3. Network-server yeni bir DevAddr ve session keys tahsis ederken hedef cihaz eski session ile devam eder → saldırgan kullanılmayan session'ın kontrolünü ele geçirir ve sahte uplink'ler enjekte edebilir.

### 3. Adaptive Data-Rate (ADR downgrading)

Airtime'ı artırmak için SF12/125 kHz'i zorlayın → saldırgan üzerindeki batarya etkisini düşük tutarken (yalnızca network-level MAC commands göndererek) gateway'in duty-cycle'ını tüketin (denial-of-service).

### 4. Reactive jamming

*HackRF One* üzerinde çalışan GNU Radio flowgraph, preamble algılandığında geniş bantlı bir chirp tetikler – ≤200 mW TX ile tüm spreading factor'ları engeller; 2 km menzilde tam kesinti ölçülmüştür .

---

## Offensive tooling (2025)

| Tool | Amaç | Notlar |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | LoRaWAN frame'lerini oluşturma/ayrıştırma/saldırma, DB-backed analyzer'lar, brute-forcer | Docker image, Semtech UDP input desteği |
| **LoRaPWN** | OTAA'yı brute-force etmek, downlink'ler oluşturmak ve payload'ları decrypt etmek için Trend Micro Python utility'si | Demo 2023'te yayınlandı, SDR-agnostic |
| **LoRAttack** | USRP ile multi-channel sniffer + replay; PCAP/LoRaTap dışa aktarımı | İyi Wireshark entegrasyonu |
| **gr-lora / gr-lorawan** | Baseband TX/RX için GNU Radio OOT block'ları | Özel saldırılar için temel |

---

## Defensive recommendations (pentester checklist)

1. Gerçekten rastgele DevNonce kullanan **OTAA** cihazlarını tercih edin; tekrarları izleyin.
2. **LoRaWAN 1.1** uygulamasını zorunlu kılın: 32-bit frame counter'lar, birbirinden farklı FNwkSIntKey / SNwkSIntKey.
3. Frame-counter'ı non-volatile memory'de (**ABP**) saklayın veya OTAA'ya geçin.
4. Root key'leri firmware extraction'a karşı korumak için **secure-element** (ATECC608A/SX1262-TRX-SE) kullanın.
5. Remote UDP packet-forwarder port'larını (1700/1701) devre dışı bırakın veya WireGuard/VPN ile kısıtlayın.
6. Gateway'leri güncel tutun; Kerlink/Dragino 2024-patched image'lar sağlıyor.
7. **Traffic anomaly detection** (ör. LAF analyzer) uygulayın – counter reset'lerini, duplicate join'leri ve ani ADR değişikliklerini işaretleyin.<sup>[[1]](#references)</sup>



## Referanslar

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Trend Micro LoRaPWN overview](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)

{{#include ../../banners/hacktricks-training.md}}
