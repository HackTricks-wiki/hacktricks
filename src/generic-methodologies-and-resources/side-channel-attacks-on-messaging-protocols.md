# E2EE Messenger'larda Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Modern uçtan uca şifreli (E2EE) messenger'larda delivery receipt'ler zorunludur; çünkü client'ların bir ciphertext'in ne zaman çözüldüğünü bilmesi, ratcheting state ve ephemeral key'leri atabilmesi gerekir. Server opaque blob'ları iletir; bu nedenle device acknowledgement'ları (çift onay işaretleri), başarılı decryption sonrasında recipient tarafından gönderilir. Attacker tarafından tetiklenen bir action ile buna karşılık gelen delivery receipt arasındaki round-trip time'ı (RTT) ölçmek; device state, online presence ve covert DoS için kötüye kullanılabilen yüksek çözünürlüklü bir timing channel açığa çıkarır. Multi-device "client-fanout" deployment'ları leakage'ı artırır; çünkü kayıtlı her device probe'u decrypt eder ve kendi receipt'ini gönderir.<sup>[[1]](#references)</sup>

## Delivery receipt kaynakları ve user-visible sinyaller

Victim üzerinde UI artifact'ları oluşturmadan her zaman delivery receipt gönderen message type'larını seçin. Aşağıdaki tablo, deneysel olarak doğrulanmış davranışı özetler:<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Her zaman gürültülü → yalnızca state'i başlatmak için kullanışlı. |
| | Reaction | ● | ◐ (yalnızca victim message'ına reaction veriliyorsa) | Self-reaction'lar ve kaldırmalar sessiz kalır. |
| | Edit | ● | Platform'a bağlı silent push | Edit window ≈20 min; süresi dolduktan sonra bile ack gönderilir. |
| | Delete for everyone | ● | ○ | UI ~60 h izin verir, ancak sonraki packet'ler yine ack gönderilir. |
| **Signal** | Text message | ● | ● | WhatsApp ile aynı sınırlamalar. |
| | Reaction | ● | ◐ | Self-reaction'lar victim için görünmez. |
| | Edit/Delete | ● | ○ | Server ~48 h window uygular ve 10 edit'e kadar izin verir, ancak geç packet'ler yine ack gönderilir. |
| **Threema** | Text message | ● | ● | Multi-device receipt'ler aggregate edilir; bu nedenle her probe için yalnızca bir RTT görünür olur. |

Legend: ● = her zaman, ◐ = koşullu, ○ = hiçbir zaman. Platform'a bağlı UI davranışı satır içinde belirtilmiştir. Gerekirse read receipt'leri devre dışı bırakın; ancak WhatsApp veya Signal'da delivery receipt'ler kapatılamaz.<sup>[[1]](#references)</sup>

## Attacker hedefleri ve modelleri

* **G1 – Device fingerprinting:** Her probe için kaç receipt geldiğini sayın, OS/client'ı (Android ve iOS veya desktop) tahmin etmek için RTT'leri cluster'layın ve online/offline geçişlerini izleyin.
* **G2 – Behavioural monitoring:** Yüksek frekanslı RTT serisini (≈1 Hz kararlıdır) bir time-series olarak ele alın ve screen on/off, app foreground/background, işe gidip gelme ile çalışma saatleri gibi durumları çıkarın.
* **G3 – Resource exhaustion:** Never-ending silent probe'lar göndererek her victim device'ın radio/CPU'sunu uyanık tutun; battery/data tüketin ve video-call kalitesini düşürün.<sup>[[1]](#references)</sup>

Abuse surface'i açıklamak için iki threat actor yeterlidir:<sup>[[1]](#references)</sup>

1. **Creepy companion:** Victim ile zaten bir chat paylaşır ve mevcut message ID'lerine bağlı self-reaction, reaction removal veya tekrarlanan edit/delete işlemlerini kötüye kullanır.
2. **Spooky stranger:** Bir burner account kaydeder ve local conversation'da hiç var olmamış message ID'lerine referans veren reaction'lar gönderir; WhatsApp ve Signal, UI state change'i yok saysa da bunları yine decrypt edip acknowledge eder. Bu nedenle önceden bir conversation gerekmez.

## Raw protocol access için tooling

UI kısıtlamaları dışında supported packet'lar oluşturmak ve kesin timestamp'leri loglamak için, temel E2EE protocol'ün yeterli bölümünü açığa çıkaran client'lara güvenin; arbitrary message ID'leri her implementation için ayrıca kontrol edilmelidir:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API), delivery receipt gönderme ve alma işlemlerini belgeler; [Cobalt](https://github.com/Auties00/Cobalt) (unofficial Java/Kotlin Web ve mobile API), reaction verme, edit ve delete gibi message operation'larını belgeler. Her internal frame'in açığa çıktığını varsaymak yerine belgelenmiş API'lerini kullanın.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli), CLI, JSON-RPC ve D-Bus interface'lerini açığa çıkarırken [libsignal-service-java](https://github.com/signalapp/libsignal-service-java), Signal ile iletişim kurmak için bir Java library'sidir.<sup>[[5]](#references)[[7]](#references)</sup> Güncel `signal-cli` syntax'ı `sendReaction RECIPIENT --target-author --target-timestamp` kullanır; protocol update'lerinin işlenmeye devam etmesi için `receive` veya `daemon` çalışır durumda tutulmalıdır.<sup>[[6]](#references)</sup> Self-reaction toggle örneği:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Careless Whisper paper'ındaki ölçümler, delivery receipt'lerin device'lar arasında synchronize edildiğini; dolayısıyla multi-device setup'ta bile her message için yalnızca bir receipt açığa çıktığını gösterdi.<sup>[[1]](#references)</sup>
* **Turnkey PoC'ler:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker), WhatsApp/Signal backend'leri içerir, varsayılan olarak silent delete probe'ları kullanır ve rolling-median threshold (`RTT < 0.9 * median`) ile `active` ve `standby` etiketleri verir.<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python), `--delay`, `--concurrent`, CSV/Prometheus exporter'ları ve Grafana uyumlu output sunan, WhatsApp öncelikli daha hafif bir CLI'dir.<sup>[[9]](#references)</sup> Her ikisini de protocol reference yerine reconnaissance helper olarak değerlendirin; önemli nokta, raw client access sağlandığında ne kadar az code gerektiğidir.

Custom tooling kullanılamadığında official client'lar veya browser developer tools yine silent action'ları tetikleyebilir ve encrypted traffic timing'ini açığa çıkarabilir; raw API'ler UI delay'lerini ortadan kaldırır ve invalid operation'lara izin verir.<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. Chat'te sizin gönderdiğiniz herhangi bir historical message'ı seçin; böylece victim "reaction" balloon'larının değiştiğini görmez.
2. Görünür bir emoji ile boş bir reaction payload'u (`""` olarak WhatsApp protobuf'larında veya signal-cli'da `--remove`) sırayla gönderin. Her transmission, victim için herhangi bir UI delta olmamasına rağmen bir device ack üretir.
3. Send time'ı ve her delivery receipt arrival'ını timestamp'leyin. Aşağıdaki gibi 1 Hz'lik bir loop, device başına süresiz RTT trace'leri sağlar:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal unlimited reaction update'lerini kabul ettiğinden attacker'ın yeni chat content'i göndermesi veya edit window'ları konusunda endişelenmesi gerekmez.<sup>[[1]](#references)</sup>

## Spooky stranger: arbitrary phone number'ları probe etme

1. Yeni bir WhatsApp/Signal account kaydedin ve target number için public identity key'lerini alın (session setup sırasında otomatik olarak yapılır).
2. Taraflardan hiçbiri tarafından görülmemiş random bir `message_id`'ye referans veren bir reaction packet oluşturun; paper, WhatsApp ve Signal'ın bu reaction'ları kabul ettiğini ve yine delivery receipt ürettiğini bildiriyor.<sup>[[1]](#references)</sup>
3. Thread mevcut olmasa bile packet'i gönderin. Victim device'ları packet'i decrypt eder, base message ile eşleştiremez, state change'i discard eder; ancak incoming ciphertext'i yine acknowledge ederek device receipt'lerini attacker'a geri gönderir.
4. Önceden bir conversation veya görünür notification olmadan RTT serileri oluşturmak için işlemi sürekli tekrarlayın.<sup>[[1]](#references)</sup>

Hangi number'ların kayıtlı olduğunu önce keşfetmeniz gerekiyorsa veya büyük ölçekte device inventory'lerini önceden oluşturmak istiyorsanız, random E.164 range'lerini elle tahmin etmek yerine bunu [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) ile zincirleyin.

Yayımlanmış contact-discovery çalışmaları bunun operasyonel olarak neden önemli olduğunu gösterdi: doğru phone-prefix tabloları ve makul kaynaklarla araştırmacılar, hedefli probing'e geçmeden önce WhatsApp'taki US mobile number'larının yaklaşık `10%`'unu ve Signal'daki number'ların `100%`'ünü sorgulayabildi.<sup>[[11]](#references)</sup> Uygulamada, önce live account'ları filtrelemek silent-probe bütçenizi gerçekten packet decrypt edecek number'lara odaklar.

Güncel WhatsApp build'leri ayrıca `Settings -> Privacy -> Advanced -> Block unknown account messages` seçeneğini sunar.<sup>[[10]](#references)</sup> Bunu bir throughput limiter olarak değerlendirin: tracker documentation, WhatsApp'ın unknown account'lardan gelen yüksek hacimli message'ları engellediğini, ancak threshold'u açıklamadığını belirtir; dolayısıyla probe reaction'larını tamamen önlemez.<sup>[[8]](#references)</sup>

## Covert trigger olarak edit ve delete'leri yeniden kullanma

* **Repeated deletes:** Bir message ilk kez everyone için delete edildikten sonra, aynı `message_id`'ye referans veren sonraki delete packet'lerinin UI üzerinde etkisi olmaz; ancak her device bunları yine decrypt edip acknowledge eder.
* **Out-of-window operations:** WhatsApp UI'da ~60 h delete ve ~20 min edit window uygular; Signal ise ~48 h uygular. Bu window'ların dışındaki crafted protocol message'ları victim device'ında sessizce yok sayılır, ancak receipt'ler gönderilir; böylece attacker'lar conversation sona erdikten çok sonra bile süresiz probe yapabilir.
* **Invalid payloads:** Paper, invalid message'ların yine acknowledge edilebildiğini bildiriyor; malformed body'ler veya purged ID'ler için kesin davranış implementation'a bağlıdır, bu nedenle güvenmeden önce test edin.<sup>[[1]](#references)</sup>

## Multi-device amplification ve fingerprinting

* WhatsApp ve Signal'da her associated device (phone, desktop app, browser companion) probe'u bağımsız olarak decrypt eder ve kendi ack'ini gönderir. Her probe'daki receipt sayısını hesaplamak exact device count'u ortaya çıkarır.<sup>[[1]](#references)</sup>
* Bir device offline ise receipt'i queue'ya alınır ve reconnect sonrasında gönderilir. Bu nedenle boşluklar online/offline cycle'larını ve hatta işe gidip gelme programlarını açığa çıkarır (örneğin desktop receipt'leri seyahat sırasında durur).
* RTT distribution'ları platform ve environment'a göre farklılık gösterir; çünkü OS, model, client ve network condition'ları timing'i etkiler. “Android handset", “iOS handset", “Electron desktop" gibi etiketler vermek için RTT'leri cluster'layın (örneğin median/variance feature'ları üzerinde k-means).
* Sender, encrypt etmeden önce recipient'ın key inventory'sini almak zorunda olduğundan attacker yeni device'ların pair edildiği zamanı da izleyebilir; device count'taki ani artış veya yeni RTT cluster'ı güçlü bir göstergedir.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing ve stacked receipt'ler

* **WhatsApp burst tolerance:** Yayımlanmış ölçümler, WhatsApp'ın belirgin server-side queueing olmadan silent-reaction burst'lerini probe başına `50 ms` kadar hızlı kabul ettiğini bildirdi. Bu, kısa calibration burst'leri, hızlı device counting veya drain attack'ini hızla artırmak için kullanışlıdır.
* **Signal long-run queueing:** Signal kısa burst'lere tolerans gösterdi, ancak sustained multi-probe-per-second traffic'i queue'lamaya başladı. Long-lived monitoring için cadence'i yaklaşık `1 Hz` (veya daha düşük) tutun; böylece her receipt backlog drain yerine güncel device state'ini yansıtır.
* **Reconnect artefact'ları:** Bir device online olduğunda bazı client'lar birden fazla gecikmiş receipt'i batch'ler veya hızla flush eder. Bu receipt burst'lerini bağımsız RTT sample'ları olarak değil, state-transition marker olarak değerlendirin; aksi halde clustering / `active` ve `idle` classifier'ınız reconnect noise'una overfit olur.<sup>[[1]](#references)</sup>

## RTT trace'lerinden behaviour inference

1. OS scheduling effect'lerini yakalamak için ≥1 Hz hızında sample alın. iOS'ta WhatsApp kullanırken <1 s RTT'ler screen-on/foreground ile, >1 s RTT'ler ise screen-off/background throttling ile güçlü korelasyon gösterir.
2. Her RTT'yi "active" veya "idle" olarak etiketleyen basit classifier'lar (thresholding veya two-cluster k-means) oluşturun. Bedtime, commute, çalışma saatleri veya desktop companion'ın active olduğu zamanları çıkarmak için etiketleri streak'ler halinde aggregate edin.
3. Kullanıcıların mobile'dan desktop'a ne zaman geçtiğini, companion'ların ne zaman offline olduğunu ve app'in push veya persistent socket üzerinden rate limit edilip edilmediğini görmek için her device'a yönelik eşzamanlı probe'ları correlate edin.
4. Gerçek network'lerde tek bir hardcoded `1 s` threshold kullanmayın. Her device'ı kısa bir warm-up window ile bootstrap edin ve rolling baseline tutun (örneğin device-activity-tracker PoC'si `threshold = 0.9 * median RTT` kullanır); böylece Wi-Fi/cellular drift classifier'ınızı bozmaz.<sup>[[1]](#references)[[8]](#references)</sup>

## Delivery RTT'den location inference

Aynı timing primitive, recipient'ın yalnızca active olup olmadığını değil, nerede bulunduğunu çıkarmak için de yeniden kullanılabilir. `Hope of Delivery` çalışması, bilinen receiver location'ları için RTT distribution'ları üzerinde training yapılmasının, attacker'ın daha sonra delivery confirmation'lar üzerinden victim'ın location'ını classify etmesini sağladığını gösterdi:<sup>[[2]](#references)</sup>

* Aynı target ev, ofis, kampüs, ülke A ve ülke B gibi çeşitli bilinen yerlerdeyken bir baseline oluşturun.
* Her location için çok sayıda normal message RTT'si toplayın ve median, variance veya percentile bucket'ları gibi basit feature'lar çıkarın.
* Gerçek attack sırasında yeni probe serisini trained cluster'larla karşılaştırın. Paper, aynı şehir içindeki location'ların bile çoğu zaman ayırt edilebildiğini ve 3-location setting'de `>80%` accuracy elde edildiğini bildiriyor.
* Ölçülen path recipient access network'ünü, wake-up latency'yi ve messenger infrastructure'ını içerdiğinden bu yöntem attacker sender environment'ını kontrol ettiğinde ve benzer network condition'ları altında probe yaptığında en iyi sonucu verir.<sup>[[2]](#references)</sup>

Yukarıdaki silent reaction/edit/delete attack'lerinin aksine location inference, invalid message ID'leri veya stealthy state-changing packet'lar gerektirmez. Normal delivery confirmation'lara sahip plain message'lar yeterlidir; bunun karşılığında stealth daha düşüktür, ancak farklı messenger'lar arasında uygulanabilirlik daha geniştir.

## Stealthy resource exhaustion

Her silent probe decrypt edilip acknowledge edilmek zorunda olduğundan reaction toggle'larını, invalid edit'leri veya delete-for-everyone packet'lerini sürekli göndermek application-layer DoS oluşturur:<sup>[[1]](#references)</sup>

* Radio/modem'i her saniye transmit/receive etmeye zorlar → özellikle idle handset'lerde fark edilir battery drain oluşur.
* Mobile data plan'larını tüketen ve video call gibi latency-sensitive feature'larla rekabet edebilen upstream/downstream traffic üretir.<sup>[[1]](#references)</sup>
* Büyük invalid payload'lar processing work'ünü artırır; ancak paper, cryptography'nin kendisinin battery cost'unun önemsiz bir bölümü olduğunu bildiriyor.<sup>[[1]](#references)</sup>
* WhatsApp'ta invalid reaction'lar, normal bir emoji'nin düşündürdüğünden çok daha fazla data kabul eder: yayımlanmış ölçümlerde reaction başına server-side acceptance yaklaşık `1 MB`'a kadar çıktı.
* Oversized reaction'lar body yaklaşık `30 bytes`'ı aştığında güvenilir delivery receipt üretmeyi durdurur; ancak discard edilmeden önce yine de forward edilir ve process edilir. ACK gerektiğinde reaction body'lerini küçük tutun; yalnızca pure drain veya covert one-way transport hedeflendiğinde büyütün.
* Public measurement'larda bu modda yaklaşık `3.7 MB/s` (`~13.3 GB/h`) victim traffic'e ulaşıldı.

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
