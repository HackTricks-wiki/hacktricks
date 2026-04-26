# E2EE Messengers'da Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Delivery receipt'ler modern end-to-end encrypted (E2EE) messengers içinde zorunludur çünkü clients, bir ciphertext ne zaman decrypt edildiğini bilmek zorundadır; böylece ratcheting state ve ephemeral keys'i atabilirler. Server opaque blobs iletir, bu yüzden device acknowledgements (double checkmarks) başarılı decryption sonrası recipient tarafından üretilir. Bir attacker-triggered action ile corresponding delivery receipt arasındaki round-trip time (RTT) ölçümü, device state, online presence sızdıran ve covert DoS için kötüye kullanılabilen yüksek çözünürlüklü bir timing channel açığa çıkarır. Multi-device "client-fanout" deployments leakage'i büyütür çünkü kayıtlı her device probe'u decrypt eder ve kendi receipt'ini döner.

## Delivery receipt sources vs. user-visible signals

Her zaman bir delivery receipt üreten ama victim üzerinde UI artifacts göstermeyen message types seçin. Aşağıdaki tablo empirically confirmed davranışı özetler:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Her zaman noisy → sadece state bootstrap etmek için kullanışlı. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions ve removals sessiz kalır. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; süresi geçtikten sonra da hâlâ ack’lenir. |
| | Delete for everyone | ● | ○ | UI yaklaşık ~60 h izin verir, ancak daha sonraki packets hâlâ ack’lenir. |
| **Signal** | Text message | ● | ● | WhatsApp ile aynı sınırlamalar. |
| | Reaction | ● | ◐ | Self-reactions victim için görünmez. |
| | Edit/Delete | ● | ○ | Server yaklaşık ~48 h window uygular, en fazla 10 edit’e izin verir, ancak geç paketler hâlâ ack’lenir. |
| **Threema** | Text message | ● | ● | Multi-device receipts birleştirilir, bu yüzden probe başına yalnızca bir RTT görünür. |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI davranışı satır içinde not edilmiştir. Gerekirse read receipts’i devre dışı bırakın, ancak delivery receipts WhatsApp veya Signal içinde kapatılamaz.

## Attacker goals and models

* **G1 – Device fingerprinting:** Probe başına kaç receipt geldiğini sayın, RTT’leri cluster’layarak OS/client (Android vs iOS vs desktop) çıkarın ve online/offline geçişlerini izleyin.
* **G2 – Behavioural monitoring:** Yüksek frekanslı RTT serisini (≈1 Hz stabildir) bir time-series olarak ele alın ve screen on/off, app foreground/background, commuting vs working hours vb. çıkarın.
* **G3 – Resource exhaustion:** Hiç bitmeyen silent probes göndererek her victim device’ın radios/CPUs’ini uyanık tutun, battery/data tüketin ve VoIP/RTC quality’yi düşürün.

Kötüye kullanım yüzeyini tanımlamak için iki threat actor yeterlidir:

1. **Creepy companion:** zaten victim ile bir chat paylaşır ve self-reactions, reaction removals veya mevcut message IDs’e bağlı tekrarlayan edits/deletes’i kötüye kullanır.
2. **Spooky stranger:** bir burner account kaydeder ve yerel conversation içinde hiç var olmamış message IDs’e referans veren reactions gönderir; WhatsApp ve Signal UI state change’i atsa bile bunları hâlâ decrypt eder ve acknowledge eder, bu yüzden önceden conversation gerekmez.

## Tooling for raw protocol access

UI kısıtlarının dışında packet üretebilmek, keyfi `message_id`s belirleyebilmek ve hassas timestamps loglayabilmek için alttaki E2EE protocol'ü açığa çıkaran clients’a güvenin:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) veya [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) size raw `ReactionMessage`, `ProtocolMessage` (edit/delete) ve `Receipt` frames göndermeyi, double-ratchet state’i senkron tutarken sağlar.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) ile [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) birleşimi her message type’ı CLI/API üzerinden açığa çıkarır. Örnek self-reaction toggle:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Android client source’u, delivery receipts’in device’tan çıkmadan önce nasıl consolidate edildiğini belgeleyerek bu side channel’ın neden orada ihmal edilebilir bandwidth’e sahip olduğunu açıklar.
* **Turnkey PoCs:** `device-activity-tracker` ve `careless-whisper-python` gibi public projects zaten silent delete/reaction probes ve RTT classification’ı otomatikleştirir. Bunları protocol reference’larından ziyade hazır reconnaissance yardımcıları olarak değerlendirin; ilginç olan kısım, raw client access mevcut olduğunda attack’in operasyonel olarak basit olduğunu doğrulamalarıdır.

Özel tooling mevcut olmadığında bile WhatsApp Web veya Signal Desktop üzerinden silent actions tetikleyebilir ve encrypted websocket/WebRTC channel’ını sniff edebilirsiniz, ancak raw APIs UI delays’i kaldırır ve invalid operations’a izin verir.

## Creepy companion: silent sampling loop

1. Chat içinde sizin yazdığınız herhangi bir historical message’ı seçin; böylece victim hiçbir zaman "reaction" balonlarının değiştiğini görmez.
2. Görünür bir emoji ile empty reaction payload arasında dönüşümlü gidin (WhatsApp protobufs içinde `""` olarak veya signal-cli içinde `--remove` olarak kodlanır). Her transmission, victim için UI delta olmasa da bir device ack üretir.
3. Send time ve her delivery receipt arrival zamanını timestamp’leyin. Aşağıdaki gibi 1 Hz loop, device başına RTT trace’lerini sonsuza kadar verir:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal sınırsız reaction updates kabul ettiği için attacker’ın yeni chat content post etmesine veya edit window’larıyla uğraşmasına gerek kalmaz.

## Spooky stranger: probing arbitrary phone numbers

1. Yeni bir WhatsApp/Signal account kaydedin ve target numara için public identity keys’i alın (session setup sırasında otomatik yapılır).
2. Taraflardan hiçbirinde görülmemiş rastgele bir `message_id` referansı veren bir reaction/edit/delete packet hazırlayın (WhatsApp keyfi `key.id` GUID’lerini kabul eder; Signal milisecond timestamps kullanır).
3. Hiç thread olmasa bile packet’i gönderin. Victim devices bunu decrypt eder, base message ile eşleşmeyi başarısız bulur, state change’i atar, ancak yine de incoming ciphertext’i acknowledge eder ve device receipts’i attacker’a geri yollar.
4. Victim’ın chat listesinde hiç görünmeden RTT series oluşturmak için bunu sürekli tekrarlayın.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Bir message delete-for-everyone ile bir kez silindikten sonra aynı `message_id`’ye referans veren sonraki delete packets UI üzerinde etki oluşturmaz, ancak her device yine de bunları decrypt eder ve acknowledge eder.
* **Out-of-window operations:** WhatsApp UI’da yaklaşık ~60 h delete / ~20 min edit window uygular; Signal yaklaşık ~48 h uygular. Bu window’ların dışındaki crafted protocol messages victim device üzerinde sessizce yok sayılır, ancak receipts iletilir; bu yüzden attacker’lar conversation bittikten çok sonra bile süresiz probe yapabilir.
* **Invalid payloads:** Bozuk edit bodies veya zaten purge edilmiş messages’e referans veren deletes aynı davranışı tetikler—decryption plus receipt, sıfır user-visible artefakt.

## Multi-device amplification & fingerprinting

* Her associated device (phone, desktop app, browser companion) probe’u bağımsız olarak decrypt eder ve kendi ack’ini döner. Probe başına receipt saymak, tam device sayısını açığa çıkarır.
* Bir device offline ise receipt’i queue’ya alınır ve reconnect olduğunda iletilir. Bu yüzden boşluklar online/offline döngülerini ve hatta commuting schedules’ı bile sızdırır (ör. travel sırasında desktop receipts durur).
* RTT distributions, OS power management ve push wakeups nedeniyle platforma göre farklılık gösterir. RTT’leri cluster’layın (ör. median/variance features üzerinde k-means) ve “Android handset", “iOS handset", “Electron desktop" vb. olarak etiketleyin.
* Sender’ın encrypt etmeden önce recipient’in key inventory’sini alması gerektiğinden, attacker yeni devices eşlendiğinde bunu da gözleyebilir; device count’ta ani artış veya yeni RTT cluster güçlü bir göstergedir.

## Behaviour inference from RTT traces

1. OS scheduling effects’i yakalamak için ≥1 Hz hızında sample alın. iOS üzerinde WhatsApp ile <1 s RTT’ler screen-on/foreground ile güçlü korelasyon gösterir, >1 s ise screen-off/background throttling ile ilişkilidir.
2. Her RTT’yi "active" veya "idle" olarak etiketleyen basit classifiers (thresholding veya iki-cluster k-means) kurun. Etiketleri streak’lere toplayarak bedtime, commuting, work hours veya desktop companion’ın ne zaman aktif olduğunu çıkarın.
3. Kullanıcıların mobile’dan desktop’a ne zaman geçtiğini, companions’ın ne zaman offline olduğunu ve app’in push mu yoksa persistent socket ile mi rate limited edildiğini görmek için tüm devices’a aynı anda yapılan probes’u korele edin.

## Location inference from delivery RTT

Aynı timing primitive, recipient’in yalnızca aktif olup olmadığını değil, nerede olduğunu da çıkarmak için yeniden kullanılabilir. `Hope of Delivery` çalışması, bilinen receiver locations için RTT distributions üzerinde training yapmanın, attacker’ın daha sonra victim’ın location bilgisini yalnızca delivery confirmations’tan sınıflandırmasına izin verdiğini gösterdi:

* Aynı target için, onlar birkaç bilinen yerdeyken bir baseline oluşturun (home, office, campus, country A vs country B vb.).
* Her location için birçok normal message RTT’si toplayın ve median, variance veya percentile buckets gibi basit features çıkarın.
* Gerçek attack sırasında, yeni probe series’i trained clusters ile karşılaştırın. Makale, aynı şehir içindeki locations’ın bile çoğu zaman ayrılabildiğini ve 3-location ayarında `>80%` accuracy elde edilebildiğini bildiriyor.
* Bu yöntem, attacker sender environment’ı kontrol ettiğinde ve benzer network conditions altında probe yaptığında en iyi sonucu verir; çünkü ölçülen path recipient access network, wake-up latency ve messenger infrastructure’ı içerir.

Yukarıdaki silent reaction/edit/delete attacks’tan farklı olarak, location inference invalid message IDs veya stealthy state-changing packets gerektirmez. Normal delivery confirmations’lı düz plain messages yeterlidir; bu yüzden tradeoff daha az stealth, ancak messengers genelinde daha geniş uygulanabilirliktir.

## Stealthy resource exhaustion

Her silent probe decrypt edilip acknowledge edilmek zorunda olduğundan, reaction toggles, invalid edits veya delete-for-everyone packets’i sürekli göndermek application-layer DoS oluşturur:

* Radio/modem’i her saniye transmit/receive etmeye zorlar → özellikle idle handsets’lerde fark edilir battery drain.
* TLS/WebSocket noise’una karışırken mobile data plan’lerini tüketen, ölçümlenmeyen upstream/downstream traffic üretir.
* Kullanıcı hiçbir notification görmese bile crypto threads’i meşgul eder ve latency-sensitive features’ta (VoIP, video calls) jitter oluşturur.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
