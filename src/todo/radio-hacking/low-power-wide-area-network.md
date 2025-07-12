# Düşük Güçlü Geniş Alan Ağı

{{#include ../../banners/hacktricks-training.md}}

## Giriş

**Düşük Güçlü Geniş Alan Ağı** (LPWAN), **uzun menzilli iletişim** için düşük bit hızında tasarlanmış kablosuz, düşük güç tüketimli geniş alan ağı teknolojilerinin bir grubudur. 
**Altı milden** fazla mesafeye ulaşabilirler ve **pilleri** **20 yıla kadar** dayanabilir.

Uzun Menzil (**LoRa**), şu anda en yaygın dağıtılan LPWAN fiziksel katmanıdır ve açık MAC katmanı spesifikasyonu **LoRaWAN**'dır.

---

## LPWAN, LoRa ve LoRaWAN

* LoRa – Semtech tarafından geliştirilen Chirp Spread Spectrum (CSS) fiziksel katmanı (mülkiyet ama belgelenmiş).
* LoRaWAN – LoRa-Alliance tarafından sürdürülen Açık MAC/Ağ katmanı. Saha da yaygın olarak 1.0.x ve 1.1 sürümleri bulunmaktadır.
* Tipik mimari: *son cihaz → ağ geçidi (paket yönlendirici) → ağ sunucusu → uygulama sunucusu*.

> **Güvenlik modeli**, *katılma* prosedürü (OTAA) sırasında oturum anahtarlarını türeten iki AES-128 kök anahtarına (AppKey/NwkKey) dayanır veya sabit kodlanmıştır (ABP). Herhangi bir anahtar sızarsa, saldırgan ilgili trafiğin tam okuma/yazma yetkisini kazanır.

---

## Saldırı yüzeyi özeti

| Katman | Zayıflık | Pratik etki |
|-------|----------|------------------|
| PHY | Reaktif / seçici sinyal bozma | Tek bir SDR ve <1 W çıkış ile %100 paket kaybı gösterildi |
| MAC | Join-Accept & veri çerçevesi tekrar oynatma (nonce yeniden kullanımı, ABP sayaç sıfırlama) | Cihaz taklidi, mesaj enjeksiyonu, DoS |
| Ağ Sunucusu | Güvensiz paket yönlendirici, zayıf MQTT/UDP filtreleri, güncel olmayan ağ geçidi yazılımı | Ağ geçitlerinde RCE → OT/IT ağına geçiş |
| Uygulama | Sabit kodlanmış veya tahmin edilebilir AppKey'ler | Trafiği kaba kuvvetle kırma/şifre çözme, sensörleri taklit etme |

---

## Son zamanlardaki zafiyetler (2023-2025)

* **CVE-2024-29862** – *ChirpStack ağ geçidi köprü & mqtt-yönlendirici*, Kerlink ağ geçitlerinde durum bilgisi olan güvenlik duvarı kurallarını atlayan TCP paketlerini kabul etti ve uzaktan yönetim arayüzü maruziyetine neden oldu. Sırasıyla 4.0.11 / 4.2.1'de düzeltildi.
* **Dragino LG01/LG308 serisi** – 2022-2024 döneminde birden fazla CVE (örneğin, 2022-45227 dizin geçişi, 2022-45228 CSRF) 2025'te hala yamanmamış olarak gözlemlendi; binlerce kamu ağ geçidinde kimlik doğrulaması gerektirmeyen yazılım dökümü veya yapılandırma üzerine yazma yetkisi sağladı.
* Semtech *paket-yönlendirici UDP* taşma (yayınlanmamış danışmanlık, 2023-10'da yamanmış): 255 B'den büyük bir yukarı akış oluşturmak, yığın çökmesine neden oldu ‑> SX130x referans ağ geçitlerinde RCE (Black Hat EU 2023 “LoRa Exploitation Reloaded” tarafından bulundu).

---

## Pratik saldırı teknikleri

### 1. Trafiği Dinleme ve Şifre Çözme
```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
--freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```
### 2. OTAA join-replay (DevNonce yeniden kullanımı)

1. Geçerli bir **JoinRequest** yakalayın.
2. Hedef cihaz tekrar iletim yapmadan önce hemen yeniden iletin (veya RSSI'yi artırın).
3. Ağ sunucusu yeni bir DevAddr ve oturum anahtarları tahsis ederken, hedef cihaz eski oturumla devam eder → saldırgan boş oturumu ele geçirir ve sahte uplink'ler enjekte edebilir.

### 3. Adaptif Veri Hızı (ADR) düşürme

Hava süresini artırmak için SF12/125 kHz zorlayın → ağ geçidinin görev döngüsünü tüketin (hizmet reddi) ve saldırgan üzerindeki pil etkisini düşük tutun (sadece ağ düzeyinde MAC komutları gönderin).

### 4. Reaktif jamming

*HackRF One* GNU Radio akış grafiği çalıştırarak, önceden belirlenen bir ön bilgi algılandığında geniş bantlı bir chirp tetikler – ≤200 mW TX ile tüm yayılma faktörlerini engeller; 2 km mesafede tam kesinti ölçülmüştür.

---

## Saldırgan araçlar (2025)

| Araç | Amaç | Notlar |
|------|---------|-------|
| **LoRaWAN Denetim Çerçevesi (LAF)** | LoRaWAN çerçevelerini oluşturma/ayrıştırma/saldırı, DB destekli analizörler, brute-forcer | Docker imajı, Semtech UDP girişi destekler |
| **LoRaPWN** | OTAA'yı brute etmek, downlink'ler oluşturmak, yükleri şifre çözmek için Trend Micro Python aracı | 2023'te demo yayımlandı, SDR bağımsız |
| **LoRAttack** | USRP ile çok kanallı sniffer + yeniden oynatma; PCAP/LoRaTap dışa aktarır | İyi Wireshark entegrasyonu |
| **gr-lora / gr-lorawan** | Temel bant TX/RX için GNU Radio OOT blokları | Özel saldırılar için temel |

---

## Savunma önerileri (pentester kontrol listesi)

1. Gerçekten rastgele DevNonce'a sahip **OTAA** cihazlarını tercih edin; kopyaları izleyin.
2. **LoRaWAN 1.1**'i zorlayın: 32 bit çerçeve sayaçları, farklı FNwkSIntKey / SNwkSIntKey.
3. Çerçeve sayacını kalıcı bellekte saklayın (**ABP**) veya OTAA'ya geçin.
4. Kök anahtarları firmware çıkarımına karşı korumak için **güvenli eleman** (ATECC608A/SX1262-TRX-SE) dağıtın.
5. Uzaktan UDP paket yönlendirici portlarını (1700/1701) devre dışı bırakın veya WireGuard/VPN ile kısıtlayın.
6. Ağ geçitlerini güncel tutun; Kerlink/Dragino 2024 yamanmış imajlar sağlar.
7. **Trafik anomali tespiti** uygulayın (örneğin, LAF analizörü) – sayaç sıfırlamalarını, kopya katılımları, ani ADR değişikliklerini işaretleyin.

## Referanslar

* LoRaWAN Denetim Çerçevesi (LAF) – https://github.com/IOActive/laf
* Trend Micro LoRaPWN genel bakış – https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a
{{#include ../../banners/hacktricks-training.md}}
