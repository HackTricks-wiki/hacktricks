# E2EE Messengers’da Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Delivery receipts, modern end-to-end encrypted (E2EE) messengers’da zorunludur çünkü clients bir ciphertext’in ne zaman decrypted edildiğini bilmek zorundadır; böylece ratcheting state ve ephemeral keys atılabilir. Server opaque blobs iletir, bu yüzden device acknowledgements (double checkmarks) başarılı decryption’dan sonra alıcı tarafından üretilir. Bir attacker-triggered action ile karşılık gelen delivery receipt arasındaki round-trip time (RTT) ölçümü, device state, online presence sızdıran ve covert DoS için kötüye kullanılabilen yüksek çözünürlüklü bir timing channel ortaya çıkarır. Multi-device "client-fanout" deployments, leakage’i büyütür çünkü kayıtlı her device probe’u decrypt eder ve kendi receipt’ini döndürür.

## Delivery receipt sources vs. user-visible signals

Her zaman delivery receipt üreten ama victim üzerinde UI artifact göstermeyen message type’larını seçin. Aşağıdaki tablo empirically confirmed davranışı özetler:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Her zaman noisy → yalnızca state bootstrap için kullanışlı. |
| | Reaction | ● | ◐ (yalnızca victim message’ına reacting yapılırsa) | Self-reactions ve removals sessiz kalır. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; expiry’den sonra da hâlâ ack’d edilir. |
| | Delete for everyone | ● | ○ | UI yaklaşık 60 h izin verir, ama daha sonraki packets hâlâ ack’d edilir. |
| **Signal** | Text message | ● | ● | WhatsApp ile aynı sınırlamalar. |
| | Reaction | ● | ◐ | Self-reactions victim’a görünmez. |
| | Edit/Delete | ● | ○ | Server yaklaşık 48 h window uygular, 10 edite kadar izin verir, ama gecikmiş packets hâlâ ack’d edilir. |
| **Threema** | Text message | ● | ● | Multi-device receipts aggregate edilir, bu yüzden her probe için yalnızca bir RTT görünür. |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI davranışı inline olarak not edilmiştir. Gerekirse read receipts devre dışı bırakın, ancak delivery receipts WhatsApp veya Signal’da kapatılamaz.

## Attacker goals and models

* **G1 – Device fingerprinting:** Her probe için kaç receipt geldiğini sayın, RTT’leri cluster’lara ayırarak OS/client (Android vs iOS vs desktop) çıkarın ve online/offline geçişlerini izleyin.
* **G2 – Behavioural monitoring:** Yüksek frekanslı RTT serisini (≈1 Hz stabildir) bir time-series olarak ele alın ve screen on/off, app foreground/background, commuting vs working hours vb. çıkarın.
* **G3 – Resource exhaustion:** Sonsuz sessiz probe’lar göndererek her victim device’ın radios/CPUs’ini uyanık tutun, battery/data tüketin ve VoIP/RTC kalitesini düşürün.

Kötüye kullanım yüzeyini tanımlamak için iki threat actor yeterlidir:

1. **Creepy companion:** zaten victim ile bir chat paylaşır ve self-reactions, reaction removals veya mevcut message ID’lere bağlı tekrarlı edits/deletes’i kötüye kullanır.
2. **Spooky stranger:** burner account kaydeder ve local conversation’da hiç var olmamış message ID’lere referans veren reactions gönderir; WhatsApp ve Signal, UI state change’i discard etse bile bunları yine de decrypt edip acknowledge eder, bu yüzden önceden konuşma gerekmemektedir.

## Tooling for raw protocol access

UI kısıtlarının dışından packet craft edebilmek, keyfi `message_id` belirleyebilmek ve hassas timestamps kaydedebilmek için underlying E2EE protocol’ü açığa vuran clients’a güvenin:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) veya [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented), double-ratchet state’i senkron tutarken raw `ReactionMessage`, `ProtocolMessage` (edit/delete) ve `Receipt` frames göndermenizi sağlar.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) ile [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) birleşimi, her message type’ı CLI/API üzerinden açığa çıkarır. Mevcut `signal-cli` syntax’i `sendReaction RECIPIENT --target-author --target-timestamp` kullanır; delivery receipts gerçekten toplansın diye `receive` veya `daemon` çalışır durumda olsun. Örnek self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client source’u, delivery receipts cihazdan çıkmadan önce nasıl consolidate edildiğini dokümante eder; bu da side channel’ın neden orada ihmal edilebilir bandwidth’e sahip olduğunu açıklar.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) WhatsApp/Signal backends ile gelir, varsayılan olarak silent delete probes kullanır ve `active` ile `standby`’yi rolling-median threshold (`RTT < 0.9 * median`) ile etiketler. [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) `--delay`, `--concurrent`, CSV/Prometheus exporters ve Grafana-friendly output içeren daha hafif bir WhatsApp-first CLI’dır. İkisini de protocol reference’tan çok reconnaissance helper olarak değerlendirin; önemli çıkarım, raw client access elde edildiğinde ne kadar az code gerektiğidir.

Özel tooling mevcut değilse, yine de WhatsApp Web veya Signal Desktop üzerinden sessiz actions tetikleyebilir ve encrypted websocket/WebRTC channel’ı sniff edebilirsiniz, ancak raw APIs UI delays’i kaldırır ve invalid operations’a izin verir.

## Creepy companion: silent sampling loop

1. Chat içinde sizin yazdığınız herhangi bir historical message’ı seçin, böylece victim hiçbir zaman "reaction" balonlarının değiştiğini görmez.
2. Görünür bir emoji ile boş reaction payload’u arasında dönüşümlü gidin (WhatsApp protobufs içinde `""` olarak veya signal-cli’de `--remove` olarak kodlanır). Her transmission, victim için UI delta olmasa da bir device ack üretir.
3. Gönderim zamanını ve gelen her delivery receipt’i zaman damgasıyla kaydedin. Aşağıdaki gibi 1 Hz loop, device başına RTT trace’lerini süresiz üretir:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal sınırsız reaction update’lerini kabul ettiğinden attacker’ın yeni chat content post etmesi veya edit windows hakkında endişelenmesi gerekmez.

## Spooky stranger: probing arbitrary phone numbers

1. Yeni bir WhatsApp/Signal account kaydedin ve target number için public identity keys’i alın (session setup sırasında otomatik yapılır).
2. Her iki tarafça da hiç görülmemiş rastgele bir `message_id`’ye referans veren bir reaction/edit/delete packet’ı hazırlayın (WhatsApp keyfi `key.id` GUID’leri kabul eder; Signal millisecond timestamps kullanır).
3. Thread hiç var olmasa bile packet’ı gönderin. Victim devices bunu decrypt eder, base message ile eşleştiremez, state change’i discard eder, fakat yine de incoming ciphertext’i acknowledge eder ve device receipts’i attacker’a geri yollar.
4. Victim chat list’inde hiç görünmeden RTT serisi oluşturmak için bunu sürekli tekrarlayın.

Önce hangi numaraların kayıtlı olduğunu keşfetmeniz veya device inventories’i ölçekli biçimde önceden doldurmak istemeniz gerekiyorsa, rastgele E.164 aralıklarını elle tahmin etmek yerine bunu [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) ile zincirleyin.

Yayınlanmış contact-discovery çalışmaları bunun operasyonel önemini gösterdi: doğru phone-prefix tabloları ve mütevazı kaynaklarla, araştırmacılar WhatsApp’ta US mobile numbers’ın yaklaşık `10%`’unu ve Signal’de `100%`’ünü hedef probing’e geçmeden önce sorgulayabildi. Pratikte, önce live accounts’u filtrelemek silent-probe bütçenizi gerçekten packets decrypt edecek numaralara odaklar.

Son WhatsApp builds ayrıca `Settings -> Privacy -> Advanced -> Block unknown account messages` seçeneğini sunar. Bunu bir fix değil, throughput limiter olarak değerlendirin: esasen sürdürülebilir stranger-only flooding’i zorlaştırır ve siz zaten known contact olduktan sonra alakasızdır.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Bir message bir kez deleted-for-everyone olduktan sonra, aynı `message_id`’ye referans veren sonraki delete packets UI etkisi yaratmaz ama her device yine de bunları decrypt edip acknowledge eder.
* **Out-of-window operations:** WhatsApp UI’da yaklaşık 60 h delete / yaklaşık 20 min edit windows uygular; Signal yaklaşık 48 h uygular. Bu windows dışındaki crafted protocol messages victim device üzerinde sessizce ignore edilir, ancak receipts iletilir; bu yüzden attacker conversation bittikten çok sonra bile süresiz probe yapabilir.
* **Invalid payloads:** Bozuk edit body’leri veya zaten purged edilmiş messages’a referans veren deletes aynı davranışı tetikler—decryption plus receipt, zero user-visible artefacts.

## Multi-device amplification & fingerprinting

* Her associated device (phone, desktop app, browser companion) probe’u bağımsız olarak decrypt eder ve kendi ack’ini döndürür. Probe başına receipt saymak tam device count’u ortaya çıkarır.
* Bir device offline ise receipt kuyruğa alınır ve reconnect olduğunda gönderilir. Bu nedenle boşluklar online/offline cycle’larını ve hatta commuting schedules’ı sızdırır (ör. travel sırasında desktop receipts durur).
* RTT distributions, OS power management ve push wakeups nedeniyle platforma göre farklılık gösterir. RTT’leri cluster’lara ayırın (ör. median/variance features üzerinde k-means) ve “Android handset", “iOS handset", “Electron desktop" vb. etiketleyin.
* Gönderenin encrypt etmeden önce alıcının key inventory’sini çekmesi gerektiğinden, attacker yeni devices pair edildiğinde de bunu gözlemleyebilir; device count’ta ani artış veya yeni RTT cluster’ı güçlü bir göstergedir.

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** Yayınlanmış ölçümler, WhatsApp’ın server-side queueing belirgin olmadan silent-reaction burst’lerini `50 ms` başına bir probe kadar hızlı kabul ettiğini bildirdi. Bu, kısa calibration burst’leri, hızlı device counting veya drain attack’i çabuk yükseltmek için kullanışlıdır.
* **Signal long-run queueing:** Signal kısa burst’lere tolerans gösterdi ama saniye başına çoklu probe’lardan oluşan sürdürülen trafiği queue etmeye başladı. Uzun süreli monitoring için cadence’i yaklaşık `1 Hz` (veya daha düşük) tutun; böylece her receipt backlog drain’i yerine mevcut device state’i yansıtır.
* **Reconnect artefacts:** Bir device yeniden online olduğunda, bazı clients birden çok gecikmiş receipt’i toplu halde veya hızla flush eder. Bu receipt burst’lerini bağımsız RTT sample’ları yerine state-transition marker olarak değerlendirin; aksi halde clustering / `active` vs `idle` classifier’ınız reconnect noise’a aşırı uyum sağlar.

## Behaviour inference from RTT traces

1. OS scheduling effects’i yakalamak için ≥1 Hz ile örnekleyin. iOS üzerinde WhatsApp’ta <1 s RTT’ler screen-on/foreground ile güçlü biçimde ilişkilidir, >1 s ise screen-off/background throttling ile.
2. Her RTT’yi "active" veya "idle" olarak etiketleyen basit classifiers (thresholding veya iki cluster’lı k-means) oluşturun. Etiketleri streak’lere toplayarak yatma saatleri, işe gidiş gelişler, çalışma saatleri veya desktop companion’ın ne zaman aktif olduğunu çıkarın.
3. Kullanıcıların mobile’dan desktop’a ne zaman geçtiğini, companions’ın ne zaman offline olduğunu ve app’in push mı yoksa persistent socket mı ile rate limited edildiğini görmek için tüm devices’a aynı anda yapılan probes’u korele edin.
4. Gerçek networks üzerinde tek bir sabit `1 s` threshold kullanmaktan kaçının. Her device’ı kısa bir warm-up window ile bootstrap edin ve rolling baseline tutun (örneğin `threshold = 0.9 * median RTT`), böylece Wi-Fi/cellular drift classifier’ınızı bozmaz.

## Location inference from delivery RTT

Aynı timing primitive, alıcının yalnızca aktif olup olmadığını değil nerede olduğunu da çıkarmak için yeniden kullanılabilir. `Hope of Delivery` çalışması, bilinen receiver locations için RTT distributions üzerinde eğitim almanın, attacker’ın daha sonra yalnızca delivery confirmations üzerinden victim’ın location’ını sınıflandırmasına izin verdiğini gösterdi:

* Aynı target için, onlar birkaç bilinen yerdeyken (home, office, campus, country A vs country B, vb.) bir baseline oluşturun.
* Her location için çok sayıda normal message RTT toplayın ve median, variance veya percentile buckets gibi basit features çıkarın.
* Gerçek attack sırasında yeni probe serisini eğitilmiş clusters ile karşılaştırın. Paper, aynı şehir içindeki locations’ın bile çoğu zaman ayrılabildiğini ve 3-location setting’de `>80%` accuracy elde edildiğini bildirir.
* Bu, en iyi sonucu attacker sender environment’ı kontrol edip benzer network conditions altında probe yaptığında verir; çünkü ölçülen path recipient access network, wake-up latency ve messenger infrastructure’ı içerir.

Yukarıdaki sessiz reaction/edit/delete attacks’tan farklı olarak location inference, invalid message IDs veya stealthy state-changing packets gerektirmez. Normal delivery confirmations içeren düz messages yeterlidir; dolayısıyla tradeoff daha az stealth ama messengers genelinde daha geniş uygulanabilirliktir.

## Stealthy resource exhaustion

Her silent probe decrypt edilip acknowledge edilmek zorunda olduğundan, reaction toggles, invalid edits veya delete-for-everyone packets’i sürekli göndermek application-layer DoS oluşturur:

* Radio/modem’i her saniye transmit/receive etmeye zorlar → özellikle idle handsets üzerinde belirgin battery drain.
* Mobile data planlarını tüketen, ancak TLS/WebSocket noise’u içine karışan unmetered upstream/downstream traffic üretir.
* Crypto threads’i meşgul eder ve user hiçbir notification görmese de latency-sensitive features (VoIP, video calls) içinde jitter oluşturur.
* WhatsApp’ta invalid reactions, normal emoji’nin düşündürdüğünden çok daha fazla data kabul eder: yayınlanmış ölçümler, server-side acceptance’ın reaction başına yaklaşık `1 MB`’a kadar çıktığını bulmuştur.
* Oversized reactions, body yaklaşık `30 bytes`’ın ötesine büyüdüğünde güvenilir delivery receipts üretmeyi bırakır, ancak yine de discard edilmeden önce forward edilip processed edilir. ACK’lere ihtiyacınız olduğunda reaction body’lerini küçük tutun; yalnızca saf drain veya covert one-way transport hedeflendiğinde büyütün.
* Public measurements bu modda yaklaşık `3.7 MB/s` (`~13.3 GB/h`) victim traffic’e ulaştı.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
