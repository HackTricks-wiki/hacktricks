# E2EE Messenger'larda Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Modern uçtan uca şifreli (E2EE) messenger'larda delivery receipt'ler zorunludur; çünkü client'ların ciphertext'in ne zaman decrypt edildiğini bilmesi, ratcheting state'i ve ephemeral key'leri atabilmesi gerekir. Server opaque blob'ları iletir; bu nedenle device acknowledgement'lar (çift onay işaretleri), başarılı decryption işleminden sonra recipient tarafından gönderilir. Attacker tarafından tetiklenen bir action ile buna karşılık gelen delivery receipt arasındaki round-trip time'ı (RTT) ölçmek; device state'i, online presence'ı açığa çıkaran yüksek çözünürlüklü bir timing channel oluşturur ve covert DoS için kötüye kullanılabilir. Multi-device "client-fanout" dağıtımları leakage'i artırır; çünkü kayıtlı her device probe'u decrypt eder ve kendi receipt'ini döndürür.<sup>[[1]](#references)</sup>

## Delivery receipt kaynakları ve user-visible sinyaller

Her zaman delivery receipt oluşturan, ancak victim üzerinde UI artefact'ları göstermeyen message type'larını seçin. Aşağıdaki tablo, deneysel olarak doğrulanmış davranışı özetler:<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Always noisy → yalnızca state'i başlatmak için kullanışlıdır. |
| | Reaction | ● | ◐ (yalnızca victim message'a reaction veriliyorsa) | Self-reaction'lar ve kaldırmalar sessiz kalır. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 dk; süre dolduktan sonra bile ack edilir. |
| | Delete for everyone | ● | ○ | UI yaklaşık 60 saate izin verir, ancak daha sonraki packet'ler yine ack edilir. |
| **Signal** | Text message | ● | ● | WhatsApp ile aynı limitations. |
| | Reaction | ● | ◐ | Self-reaction'lar victim için görünmezdir. |
| | Edit/Delete | ● | ○ | Server yaklaşık 48 saatlik window uygular ve 10 edit'e kadar izin verir, ancak geç packet'ler yine ack edilir. |
| **Threema** | Text message | ● | ● | Multi-device receipt'ler aggregate edilir; bu nedenle her probe için yalnızca bir RTT görünür hale gelir. |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI davranışı satır içinde belirtilmiştir. Gerekirse read receipt'leri disable edin, ancak WhatsApp veya Signal'da delivery receipt'ler kapatılamaz.<sup>[[1]](#references)</sup>

## Attacker hedefleri ve modelleri

* **G1 – Device fingerprinting:** Her probe başına kaç receipt geldiğini sayın, OS/client'ı (Android ile iOS veya desktop) anlamak için RTT'leri cluster'layın ve online/offline geçişlerini izleyin.
* **G2 – Behavioural monitoring:** Yüksek frekanslı RTT serisini (≈1 Hz kararlıdır) bir time-series olarak ele alın ve screen on/off, app foreground/background, commuting veya working hours gibi durumları çıkarın.
* **G3 – Resource exhaustion:** Never-ending silent probe'lar göndererek her victim device'ın radio/CPU'sunu uyanık tutun; battery/data tüketin ve VoIP/RTC kalitesini düşürün.<sup>[[1]](#references)</sup>

Abuse surface'i açıklamak için iki threat actor yeterlidir:<sup>[[1]](#references)</sup>

1. **Creepy companion:** Victim ile zaten bir chat paylaşır ve existing message ID'lere bağlı self-reaction'ları, reaction removal'larını veya tekrarlanan edit/delete işlemlerini kötüye kullanır.
2. **Spooky stranger:** Bir burner account kaydeder ve local conversation'da hiç var olmayan message ID'lere referans veren reaction'lar gönderir; WhatsApp ve Signal, UI state change'i discard etse bile bunları decrypt edip acknowledge eder. Bu nedenle önceden bir conversation gerekmez.

## Raw protocol access için tooling

UI constraints dışından packet oluşturabilmeniz, arbitrary `message_id` belirtebilmeniz ve kesin timestamp'leri loglayabilmeniz için underlying E2EE protocol'ü açığa çıkaran client'lara güvenin:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) veya [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented); double-ratchet state'i sync halinde tutarken raw `ReactionMessage`, `ProtocolMessage` (edit/delete) ve `Receipt` frame'leri göndermenizi sağlar.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) ile [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) birlikte kullanıldığında her message type'a CLI/API üzerinden erişim sağlar.<sup>[[5]](#references)[[7]](#references)</sup> Güncel `signal-cli` syntax'ı `sendReaction RECIPIENT --target-author --target-timestamp` kullanır; delivery receipt'lerin gerçekten toplanması için `receive` veya `daemon` çalışır durumda tutulmalıdır.<sup>[[6]](#references)</sup> Örnek self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client source code'u, delivery receipt'lerin device'tan çıkmadan önce nasıl consolidate edildiğini belgeler; bu durum side channel'ın neden burada negligible bandwidth'e sahip olduğunu açıklar.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker), WhatsApp/Signal backend'leriyle birlikte gelir, silent delete probe'larını default olarak kullanır ve rolling-median threshold (`RTT < 0.9 * median`) ile `active` ve `standby` etiketleri verir.<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python), `--delay`, `--concurrent`, CSV/Prometheus exporter'ları ve Grafana-friendly output sunan, WhatsApp-first daha hafif bir CLI'dır.<sup>[[9]](#references)</sup> Her ikisini de protocol reference yerine reconnaissance helper olarak değerlendirin; önemli çıkarım, raw client access mevcut olduğunda ne kadar az code gerektiğidir.

Custom tooling mevcut olmadığında WhatsApp Web veya Signal Desktop üzerinden silent action'ları yine tetikleyebilir ve encrypted websocket/WebRTC channel'ını sniff edebilirsiniz; ancak raw API'ler UI delay'lerini ortadan kaldırır ve invalid operation'lara izin verir.

## Creepy companion: silent sampling loop

1. Chat'te sizin gönderdiğiniz herhangi bir historical message'ı seçin; böylece victim "reaction" balloon'larının değiştiğini görmez.
2. Visible bir emoji ile boş bir reaction payload'u (`""` olarak WhatsApp protobuf'larında veya signal-cli'da `--remove`) dönüşümlü olarak gönderin. Her transmission, victim için hiçbir UI delta olmamasına rağmen bir device ack üretir.
3. Send time'ı ve her delivery receipt arrival'ını timestamp'leyin. Aşağıdaki gibi 1 Hz'lik bir loop, süresiz olarak device başına RTT trace'leri sağlar:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal unlimited reaction update'lerini kabul ettiğinden attacker'ın yeni chat content'i göndermesi veya edit window'ları hakkında endişelenmesi gerekmez.<sup>[[1]](#references)</sup>

## Spooky stranger: arbitrary phone number'ları probing

1. Yeni bir WhatsApp/Signal account kaydedin ve target number için public identity key'leri alın (session setup sırasında otomatik olarak yapılır).
2. Taraflardan hiçbirinin görmediği rastgele bir `message_id`'ye referans veren reaction/edit/delete packet'i oluşturun (WhatsApp arbitrary `key.id` GUID'lerini kabul eder; Signal millisecond timestamp kullanır).
3. Thread mevcut olmasa bile packet'i gönderin. Victim device'ları packet'i decrypt eder, base message'ı eşleştiremez, state change'i discard eder; ancak gelen ciphertext'i yine acknowledge ederek device receipt'lerini attacker'sa geri gönderir.
4. Victim'in chat listesinde hiç görünmeden RTT serileri oluşturmak için işlemi sürekli tekrarlayın.<sup>[[1]](#references)</sup>

Önce hangi number'ların registered olduğunu keşfetmeniz gerekiyorsa veya device inventory'lerini scale'de pre-seed etmek istiyorsanız, rastgele E.164 range'lerini elle tahmin etmek yerine bunu [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) ile chain edin.

Published contact-discovery çalışmaları bunun operational olarak neden önemli olduğunu gösterdi: doğru phone-prefix tabloları ve makul kaynaklarla araştırmacılar, targeted probing'e geçmeden önce WhatsApp'taki US mobile number'larının yaklaşık `10%`'unu ve Signal'daki number'ların `100%`'ünü query edebildi.<sup>[[11]](#references)</sup> Pratikte live account'ları önceden filter etmek, silent-probe budget'ını gerçekten packet decrypt edecek number'lara odaklar.

Güncel WhatsApp build'leri ayrıca `Settings -> Privacy -> Advanced -> Block unknown account messages` seçeneğini sunar.<sup>[[10]](#references)</sup> Bunu bir fix değil, throughput limiter olarak değerlendirin: esas olarak sustained stranger-only flooding'i zorlaştırır ve zaten known contact olduğunuz durumda önemsizdir.

## Edit ve delete işlemlerini covert trigger olarak recycling

* **Repeated deletes:** Bir message ilk kez deleted-for-everyone olduktan sonra, aynı `message_id`'ye referans veren sonraki delete packet'lerinin UI üzerinde etkisi olmaz; ancak her device bunları decrypt edip acknowledge eder.
* **Out-of-window operations:** WhatsApp UI'da yaklaşık 60 saatlik delete / yaklaşık 20 dakikalık edit window uygular; Signal ise yaklaşık 48 saat uygular. Bu window'ların dışındaki crafted protocol message'ları victim device üzerinde sessizce ignore edilir; ancak receipt'ler gönderilir. Böylece attacker conversation sona erdikten uzun süre sonra bile probing yapabilir.
* **Invalid payloads:** Malformed edit body'leri veya zaten purged message'lara referans veren delete'ler aynı davranışı oluşturur: decryption artı receipt, sıfır user-visible artefact.<sup>[[1]](#references)</sup>

## Multi-device amplification ve fingerprinting

* Her associated device (phone, desktop app, browser companion) probe'u bağımsız olarak decrypt eder ve kendi ack'ini döndürür. Probe başına receipt'leri saymak exact device count'u ortaya çıkarır.
* Bir device offline ise receipt'i queue'ya alınır ve reconnection sırasında gönderilir. Bu nedenle gaps, online/offline cycle'larını ve hatta commuting schedule'larını açığa çıkarır (örneğin desktop receipt'leri travel sırasında durur).
* RTT distribution'ları, OS power management ve push wakeup'ları nedeniyle platforma göre farklılık gösterir. “Android handset", “iOS handset", “Electron desktop" gibi etiketler vermek için RTT'leri cluster'layın (örneğin median/variance feature'ları üzerinde k-means).
* Sender'ın encrypting işleminden önce recipient'ın key inventory'sini alması gerektiğinden attacker, yeni device'ların ne zaman paired olduğunu da izleyebilir; device count'taki ani artış veya yeni RTT cluster'ı güçlü bir indicator'dır.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing ve stacked receipt'ler

* **WhatsApp burst tolerance:** Published measurement'lar, WhatsApp'ın silent-reaction burst'lerini belirgin server-side queueing olmadan probe başına `50 ms` hızında kabul ettiğini bildirdi. Bu, kısa calibration burst'leri, hızlı device counting veya drain attack'ini hızlıca artırmak için kullanışlıdır.
* **Signal long-run queueing:** Signal kısa burst'lere tolerans gösterdi, ancak sustained multi-probe-per-second traffic'i queue'lamaya başladı. Long-lived monitoring için cadence'i yaklaşık `1 Hz` (veya daha düşük) tutun; böylece her receipt backlog drain yerine current device state'i yansıtır.
* **Reconnect artefacts:** Bir device online olduğunda bazı client'lar birden fazla delayed receipt'i batch'ler veya hızla flush eder. Bu receipt burst'lerini bağımsız RTT sample'ları yerine state-transition marker olarak değerlendirin; aksi halde clustering / `active` ve `idle` classifier'ınız reconnect noise'a overfit olur.<sup>[[1]](#references)</sup>

## RTT trace'lerinden behaviour inference

1. OS scheduling effect'lerini yakalamak için ≥1 Hz hızında sample alın. WhatsApp'ın iOS sürümünde <1 s RTT'ler screen-on/foreground ile, >1 s RTT'ler ise screen-off/background throttling ile güçlü şekilde ilişkilidir.
2. Her RTT'yi "active" veya "idle" olarak etiketleyen basit classifier'lar (thresholding veya two-cluster k-means) oluşturun. Bedtime, commute, work hours veya desktop companion'ın active olduğu zamanları çıkarmak için etiketleri streak'ler halinde aggregate edin.
3. Kullanıcıların mobile'dan desktop'a ne zaman geçtiğini, companion'ların ne zaman offline olduğunu ve app'in push veya persistent socket tarafından rate limited olup olmadığını görmek için her device'a yönelik simultaneous probe'ları correlate edin.
4. Gerçek network'lerde tek bir hardcoded `1 s` threshold kullanmayın. Her device'ı kısa bir warm-up window ile bootstrap edin ve rolling baseline tutun (örneğin, `threshold = 0.9 * median RTT`); böylece Wi-Fi/cellular drift classifier'ınızı bozmaz.<sup>[[1]](#references)</sup>

## Delivery RTT'den location inference

Aynı timing primitive, recipient'ın yalnızca active olup olmadığını değil, nerede olduğunu infer etmek için de yeniden kullanılabilir. `Hope of Delivery` çalışması, known receiver location'ları için RTT distribution'ları üzerinde training yapıldığında attacker'ın daha sonra victim'ın location'ını yalnızca delivery confirmation'larından classify edebildiğini gösterdi:<sup>[[2]](#references)</sup>

* Target aynı anda birkaç known place'teyken (home, office, campus, country A ve country B vb.) baseline oluşturun.
* Her location için çok sayıda normal message RTT'si toplayın ve median, variance veya percentile bucket'ları gibi basit feature'lar çıkarın.
* Gerçek attack sırasında yeni probe serisini trained cluster'larla karşılaştırın. Paper, aynı şehir içindeki location'ların bile çoğu zaman ayrıştırılabildiğini ve 3-location setting'de `>80%` accuracy elde edildiğini bildiriyor.
* Bu yöntem, attacker sender environment'ını kontrol ettiğinde ve benzer network condition'ları altında probe yaptığında en iyi sonucu verir; çünkü ölçülen path recipient access network'ünü, wake-up latency'yi ve messenger infrastructure'ını içerir.<sup>[[2]](#references)</sup>

Yukarıdaki silent reaction/edit/delete attack'lerinin aksine location inference, invalid message ID'ler veya stealthy state-changing packet'ler gerektirmez. Normal delivery confirmation'lara sahip plain message'lar yeterlidir; bu nedenle tradeoff daha düşük stealth, ancak messenger'lar arasında daha geniş applicability'dir.

## Stealthy resource exhaustion

Her silent probe decrypt edilip acknowledge edilmek zorunda olduğundan reaction toggle'larını, invalid edit'leri veya delete-for-everyone packet'lerini sürekli göndermek application-layer DoS oluşturur:<sup>[[1]](#references)</sup>

* Radio/modem'i her saniye transmit/receive yapmaya zorlar → özellikle idle handset'lerde fark edilir battery drain oluşturur.
* TLS/WebSocket noise'u içinde normal görünürken mobile data plan'larını tüketen unmetered upstream/downstream traffic üretir.
* Crypto thread'lerini meşgul eder ve kullanıcı hiçbir notification görmese bile latency-sensitive feature'larda (VoIP, video call) jitter oluşturur.
* WhatsApp'ta invalid reaction'lar, normal bir emoji'nin ima ettiğinden çok daha fazla data kabul eder: published measurement'lar reaction başına server-side acceptance'ın yaklaşık `1 MB`'a ulaştığını gösterdi.
* Oversized reaction'lar body yaklaşık `30 bytes`'ı aştığında güvenilir delivery receipt üretmeyi durdurur; ancak discard edilmeden önce yine de forward edilir ve process edilir. ACK gerektiğinde reaction body'lerini küçük tutun; yalnızca drain veya covert one-way transport amaçlandığında büyütün.
* Public measurement'lar bu mode'da yaklaşık `3.7 MB/s` (`~13.3 GB/h`) victim traffic'e ulaştı.

## References

- [1] [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
