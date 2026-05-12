# E2EE Messengers'da Delivery Receipt Side-Channel Saldırıları

{{#include ../banners/hacktricks-training.md}}

Delivery receipts, modern end-to-end encrypted (E2EE) messengers içinde zorunludur; çünkü istemcilerin bir ciphertext ne zaman çözüldüğünü bilmesi gerekir ki ratcheting state ve ephemeral keys'i atabilsinler. Server opaque blob'ları iletir, bu yüzden device acknowledgements (double checkmarks) başarılı decryption sonrası alıcı tarafından üretilir. Bir attacker-tetiklemeli action ile karşılık gelen delivery receipt arasındaki round-trip time (RTT) ölçümü, device state, online presence sızdıran ve covert DoS için kötüye kullanılabilen yüksek çözünürlüklü bir timing channel ortaya çıkarır. Multi-device "client-fanout" deployments, leakage'i büyütür çünkü kayıtlı her device probe'u decrypt eder ve kendi receipt'ini döndürür.

## Delivery receipt kaynakları vs. kullanıcıya görünen sinyaller

Kurban tarafında UI artifact'ı göstermeyen ama her zaman bir delivery receipt üreten message type'larını seçin. Aşağıdaki tablo, deneysel olarak doğrulanmış davranışı özetler:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Her zaman gürültülüdür → yalnızca state bootstrap etmek için kullanışlı. |
| | Reaction | ● | ◐ (yalnızca victim message'ına reaction veriliyorsa) | Self-reaction ve removal sessiz kalır. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 dak.; expiry sonrası da hâlâ ack alınır. |
| | Delete for everyone | ● | ○ | UI yaklaşık 60 sa. izin verir, ancak daha sonraki packets hâlâ ack alınır. |
| **Signal** | Text message | ● | ● | WhatsApp ile aynı sınırlamalar. |
| | Reaction | ● | ◐ | Self-reaction victim'a görünmez. |
| | Edit/Delete | ● | ○ | Server yaklaşık 48 sa. window uygular, 10 edit'e kadar izin verir, ancak geç packets hâlâ ack alınır. |
| **Threema** | Text message | ● | ● | Multi-device receipts birleştirilir, bu yüzden probe başına yalnızca bir RTT görünür. |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI behaviour satır içinde belirtilmiştir. Gerekirse read receipts'i kapatın, ancak delivery receipts WhatsApp veya Signal'da kapatılamaz.

## Attacker goals and models

* **G1 – Device fingerprinting:** Her probe için kaç receipt geldiğini sayın, OS/client'i (Android vs iOS vs desktop) çıkarmak için RTT'leri kümelendirin ve online/offline geçişlerini izleyin.
* **G2 – Behavioural monitoring:** Yüksek frekanslı RTT serisini (≈1 Hz stabil) bir time-series gibi ele alın ve screen on/off, app foreground/background, commuting vs working hours, vb. çıkarın.
* **G3 – Resource exhaustion:** Never-ending sessiz probes göndererek her victim device'ın radio/CPU'sunu uyanık tutun, battery/data tüketin ve VoIP/RTC kalitesini düşürün.

İstismar yüzeyini tanımlamak için iki threat actor yeterlidir:

1. **Creepy companion:** Zaten victim ile bir chat paylaşır ve mevcut message ID'lerine bağlı self-reactions, reaction removals veya tekrarlanan edits/deletes kötüye kullanır.
2. **Spooky stranger:** Bir burner account kaydeder ve yerel conversation içinde hiç var olmamış message ID'lerini referanslayan reactions gönderir; WhatsApp ve Signal UI state change'i atsa bile bunları yine de decrypt eder ve acknowledge eder, bu yüzden önceden conversation gerekmez.

## Raw protocol erişimi için tooling

Altta yatan E2EE protocol'ünü açığa çıkaran clients'a güvenin; böylece UI kısıtları dışında packets oluşturabilir, keyfi `message_id`'ler belirleyebilir ve hassas timestamps kaydedebilirsiniz:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) veya [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented), double-ratchet state'i senkron tutarken raw `ReactionMessage`, `ProtocolMessage` (edit/delete) ve `Receipt` frames göndermenize izin verir.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) ile [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) birlikte, her message type'ı CLI/API üzerinden açığa çıkarır. Mevcut `signal-cli` syntax'i `sendReaction RECIPIENT --target-author --target-timestamp` kullanır; delivery receipts gerçekten toplansın diye `receive` veya `daemon` çalışır durumda olsun. Örnek self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client source'u, delivery receipts cihazdan çıkmadan önce nasıl birleştirildiğini belgeler; bu da side channel'in neden orada ihmal edilebilir bandwidth'e sahip olduğunu açıklar.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker), WhatsApp/Signal backends ile gelir, varsayılan olarak sessiz delete probes kullanır ve rolling-median threshold (`RTT < 0.9 * median`) ile `active` ve `standby` etiketler. [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python), `--delay`, `--concurrent`, CSV/Prometheus exporters ve Grafana-friendly output sunan daha hafif, WhatsApp-first bir CLI'dır. İkisini protocol reference yerine reconnaissance helper olarak değerlendirin; asıl çıkarım, raw client erişimi olduğunda ne kadar az code gerektiğidir.

Özel tooling mevcut değilse, yine de WhatsApp Web veya Signal Desktop üzerinden sessiz actions tetikleyebilir ve şifreli websocket/WebRTC channel'ını sniff edebilirsiniz; ancak raw APIs UI delay'lerini kaldırır ve invalid operations'a izin verir.

## Creepy companion: sessiz sampling loop

1. Chat'te sizin yazdığınız herhangi bir historical message'ı seçin; böylece victim "reaction" balonlarının değiştiğini hiç görmez.
2. Görünür bir emoji ile boş bir reaction payload'u arasında dönüşümlü gidin (WhatsApp protobuf'larında `""` olarak veya signal-cli'de `--remove` olarak kodlanır). Her transmission, victim için hiçbir UI delta olmasa da bir device ack üretir.
3. Gönderim zamanını ve her delivery receipt varışını zaman damgasıyla kaydedin. Aşağıdaki gibi 1 Hz bir loop, her device için süresiz RTT traces sağlar:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal sınırsız reaction update kabul ettiğinden, attacker'ın yeni chat content göndermesine veya edit windows hakkında endişelenmesine gerek kalmaz.

## Spooky stranger: rastgele phone number'ları probe etmek

1. Yeni bir WhatsApp/Signal hesabı kaydedin ve hedef numara için public identity keys'i alın (session setup sırasında otomatik yapılır).
2. Taraflardan hiçbirinin hiç görmediği rastgele bir `message_id`'yi referanslayan reaction/edit/delete packet'i oluşturun (WhatsApp key.id olarak keyfi GUID'leri kabul eder; Signal milisecond timestamps kullanır).
3. Thread mevcut olmasa bile packet'i gönderin. Victim device'ları bunu decrypt eder, base message ile eşleştiremez, state change'i atar, ancak yine de gelen ciphertext'i acknowledge eder ve device receipts'i attacker'a geri gönderir.
4. Victim chat listesinde hiç görünmeden RTT serileri oluşturmak için bunu sürekli tekrarlayın.

Önce hangi numaraların kayıtlı olduğunu keşfetmeniz gerekiyorsa veya cihaz envanterlerini ölçekte önceden doldurmak istiyorsanız, rastgele E.164 aralıklarını elle tahmin etmek yerine bunu [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) ile zincirleyin.

Son WhatsApp builds ayrıca `Settings -> Privacy -> Advanced -> Block unknown account messages` seçeneğini de açar. Bunu bir fix değil, throughput limiter olarak değerlendirin: esasen sürdürülebilir stranger-only flooding'i zorlaştırır ve zaten bilinen bir contact olduğunuzda alakasızdır.

## Edit ve delete'leri covert trigger olarak yeniden kullanma

* **Repeated deletes:** Bir message bir kez delete-for-everyone yapıldıktan sonra, aynı `message_id`'yi referanslayan sonraki delete packets'lerin UI etkisi olmaz ama her device yine de bunları decrypt eder ve acknowledge eder.
* **Out-of-window operations:** WhatsApp UI'da yaklaşık 60 sa. delete / yaklaşık 20 dak. edit window uygular; Signal yaklaşık 48 sa. uygular. Bu windows dışındaki crafted protocol messages, victim device'ta sessizce yok sayılır ancak receipts iletilir; bu yüzden attacker'lar conversation bittikten çok uzun süre sonra bile probe edebilir.
* **Invalid payloads:** Bozuk edit body'leri veya zaten purge edilmiş messages'ları referanslayan deletes de aynı davranışı tetikler—decryption artı receipt, kullanıcıya görünür artefact yok.

## Multi-device amplification & fingerprinting

* Her associated device (phone, desktop app, browser companion) probe'u bağımsız olarak decrypt eder ve kendi ack'ini döndürür. Probe başına receipt saymak, tam device sayısını ortaya çıkarır.
* Bir device offline ise receipt'i kuyruğa alınır ve yeniden bağlanınca gönderilir. Bu nedenle boşluklar online/offline cycle'larını ve hatta commuting schedule'ları sızdırır (ör. travel sırasında desktop receipts durur).
* RTT dağılımları, OS power management ve push wakeups nedeniyle platforma göre farklılık gösterir. RTT'leri kümelendirin (ör. median/variance özellikleri üzerinde k-means) ve “Android handset", “iOS handset", “Electron desktop", vb. olarak etiketleyin.
* Sender, recipient'in key inventory'sini encrypt etmeden önce almak zorunda olduğundan, attacker yeni device'ların ne zaman eşlendiğini de gözleyebilir; device sayısında ani artış veya yeni bir RTT cluster güçlü bir göstergedir.

## RTT traces'ten davranış çıkarımı

1. OS scheduling effects'i yakalamak için ≥1 Hz örnekleyin. WhatsApp on iOS ile <1 s RTT'ler güçlü biçimde screen-on/foreground ile, >1 s ise screen-off/background throttling ile koreledir.
2. Her RTT'yi "active" veya "idle" olarak etiketleyen basit classifiers (thresholding veya iki-cluster k-means) oluşturun. Etiketleri streak'lere toplayarak bedtime'ları, commuting'i, work hours'ı veya desktop companion'ın ne zaman aktif olduğunu çıkarın.
3. Kullanıcıların mobilden desktop'a ne zaman geçtiğini, companions'ın ne zaman offline olduğunu ve app'in push mu yoksa persistent socket tarafından mı rate limited edildiğini görmek için tüm device'lara eşzamanlı probes ile korelasyon yapın.
4. Gerçek ağlarda tek ve sabit bir `1 s` threshold kullanmaktan kaçının. Her device'ı kısa bir warm-up window ile bootstrap edin ve rolling baseline'ı koruyun (örneğin, `threshold = 0.9 * median RTT`) ki Wi-Fi/cellular drift classifier'ınızı çökertmesin.

## Delivery RTT'den konum çıkarımı

Aynı timing primitive, alıcının yalnızca aktif olup olmadığını değil, nerede olduğunu da çıkarmak için yeniden kullanılabilir. `Hope of Delivery` çalışması, bilinen receiver location'larındaki RTT dağılımları üzerinde eğitim yapmanın, attacker'ın daha sonra victim'ın konumunu yalnızca delivery confirmations'tan sınıflandırmasına izin verdiğini gösterdi:

* Aynı target için, onlar birkaç bilinen yerdeyken bir baseline oluşturun (ev, ofis, kampüs, ülke A vs ülke B, vb.).
* Her location için çok sayıda normal message RTT'si toplayın ve median, variance veya percentile bucket'ları gibi basit features çıkarın.
* Gerçek attack sırasında, yeni probe serisini eğitilmiş cluster'larla karşılaştırın. Paper, aynı şehir içindeki location'ların bile çoğu zaman ayrılabildiğini ve 3-location setting'de `>80%` accuracy elde edildiğini bildiriyor.
* Bu, attacker sender environment'ı kontrol ettiğinde ve benzer network conditions altında probe attığında en iyi sonucu verir; çünkü ölçülen path recipient access network'ünü, wake-up latency'sini ve messenger infrastructure'ını içerir.

Yukarıdaki sessiz reaction/edit/delete saldırılarından farklı olarak, location inference invalid message ID'ler veya stealthy state-changing packets gerektirmez. Normal delivery confirmations içeren düz messages yeterlidir; dolayısıyla tradeoff, daha düşük stealth ama messengers genelinde daha geniş uygulanabilirliktir.

## Stealthy resource exhaustion

Her sessiz probe'un decrypt edilmesi ve acknowledge edilmesi gerektiğinden, reaction toggles, invalid edits veya delete-for-everyone packets'i sürekli göndermek bir application-layer DoS yaratır:

* Radio/modem'i her saniye transmit/receive etmeye zorlar → özellikle boşta duran handsets'te fark edilir battery drain.
* TLS/WebSocket noise ile karışarak mobile data plan'larını tüketen, ölçümlenmemiş upstream/downstream traffic üretir.
* Kullanıcı hiçbir notification görmese bile crypto threads'i meşgul eder ve latency-sensitive features'ta (VoIP, video calls) jitter oluşturur.
* WhatsApp'ta invalid reactions, normal bir emoji'nin düşündüğünden çok daha fazla data kabul eder: yayınlanmış ölçümler, server-side acceptance'ın reaction başına yaklaşık `1 MB`'a kadar çıktığını buldu.
* Aşırı büyük reactions, body yaklaşık `30 bytes`'ı aştığında güvenilir delivery receipts üretmeyi bırakır; ancak yine de discard edilmeden önce forward edilir ve işlenir. ACK'lere ihtiyacınız olduğunda reaction bodies'yi küçük tutun; onları yalnızca amaç saf drain veya covert one-way transport olduğunda büyütün.
* Kamuya açık ölçümler bu modda yaklaşık `3.7 MB/s` (`~13.3 GB/h`) victim traffic'e ulaştı.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)

{{#include ../banners/hacktricks-training.md}}
