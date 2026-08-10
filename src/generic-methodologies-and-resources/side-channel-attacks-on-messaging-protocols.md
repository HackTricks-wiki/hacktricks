# E2EE Messenger'larda Delivery Receipt Side-Channel Attacks

Delivery receipts, modern end-to-end encrypted (E2EE) messenger'larda zorunludur; çünkü istemcilerin bir ciphertext'in ne zaman decrypt edildiğini bilmesi gerekir. Böylece ratcheting state ve ephemeral keys silinebilir. Server opaque blob'ları iletir; bu nedenle device acknowledgements (double checkmarks), başarılı decryption sonrasında recipient tarafından gönderilir. Attacker tarafından tetiklenen bir action ile ilgili delivery receipt arasındaki round-trip time (RTT) ölçülerek device state ve online presence hakkında bilgi leak eden, ayrıca covert DoS için kötüye kullanılabilen yüksek çözünürlüklü bir timing channel ortaya çıkar. Multi-device "client-fanout" deployment'ları leakage'ı artırır; çünkü her registered device probe'u decrypt eder ve kendi receipt'ini döndürür.<sup>[[1]](#references)</sup>

## Delivery receipt sources vs. user-visible signals

Victim üzerinde UI artifact'ları oluşturmadan her zaman delivery receipt gönderen message type'larını seçin. Aşağıdaki tablo empirically confirmed davranışı özetler:<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Her zaman gürültülü → yalnızca state'i bootstrap etmek için kullanışlı. |
| | Reaction | ● | ◐ (yalnızca victim message'a reaction veriliyorsa) | Self-reactions ve removals sessiz kalır. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; expiry sonrasında bile ack gönderilir. |
| | Delete for everyone | ● | ○ | UI yaklaşık 60 h'ye izin verir, ancak sonraki packet'ler yine ack edilir. |
| **Signal** | Text message | ● | ● | WhatsApp ile aynı limitations. |
| | Reaction | ● | ◐ | Self-reactions victim için görünmezdir. |
| | Edit/Delete | ● | ○ | Server yaklaşık 48 h'lik window uygular ve 10 edit'e kadar izin verir, ancak geç packet'ler yine ack edilir. |
| **Threema** | Text message | ● | ● | Multi-device receipt'leri aggregate edilir; bu nedenle her probe için yalnızca bir RTT görünür hale gelir. |

Legend: ● = her zaman, ◐ = koşullu, ○ = hiçbir zaman. Platform-dependent UI davranışı satır içinde belirtilmiştir. Gerekirse read receipts'i disable edin; ancak WhatsApp veya Signal'da delivery receipts kapatılamaz.<sup>[[1]](#references)</sup>

## Attacker goals and models

* **G1 – Device fingerprinting:** Her probe için kaç receipt geldiğini sayın, OS/client'ı (Android vs iOS vs desktop) anlamak ve online/offline geçişlerini izlemek için RTT'leri cluster'layın.
* **G2 – Behavioural monitoring:** High-frequency RTT serisini (≈1 Hz stabildir) bir time-series olarak ele alın ve screen on/off, app foreground/background, commuting vs working hours vb. durumları çıkarın.
* **G3 – Resource exhaustion:** Never-ending silent probe'lar göndererek her victim device'ın radio/CPU'sunu uyanık tutun; battery/data tüketin ve video-call kalitesini düşürün.<sup>[[1]](#references)</sup>

Abuse surface'i açıklamak için iki threat actor yeterlidir:<sup>[[1]](#references)</sup>

1. **Creepy companion:** Victim ile zaten bir chat paylaşır ve self-reactions, reaction removals veya mevcut message ID'lerine bağlı tekrarlı edit/delete işlemlerini kötüye kullanır.
2. **Spooky stranger:** Bir burner account register eder ve local conversation'da hiç var olmamış message ID'lerine reference veren reactions gönderir; WhatsApp ve Signal, UI state change'i discard etse de bunları yine decrypt edip acknowledge eder. Bu nedenle önceden bir conversation gerekmez.

## Tooling for raw protocol access

UI constraints dışında supported packet'ler oluşturmak ve precise timestamp'leri loglamak için underlying E2EE protocol'ün yeterli bölümünü açığa çıkaran client'lara güvenin; arbitrary message ID'leri için her implementation'ı kontrol etmek gerekir:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API), delivery receipt gönderme ve alma işlemlerini document eder; [Cobalt](https://github.com/Auties00/Cobalt) (unofficial Java/Kotlin Web ve mobile API), reacting, editing ve deleting gibi message operation'larını document eder. Her internal frame'in açığa çıktığını varsaymak yerine documented API'lerini kullanın.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli), CLI, JSON-RPC ve D-Bus interface'lerini açığa çıkarırken [libsignal-service-java](https://github.com/signalapp/libsignal-service-java), Signal ile iletişim kurmak için kullanılan bir Java library'dir.<sup>[[5]](#references)[[7]](#references)</sup> Güncel `signal-cli` syntax'ı `sendReaction RECIPIENT --target-author --target-timestamp` kullanır; protocol update'lerinin işlenmeye devam etmesi için `receive` veya `daemon` çalışır durumda tutulmalıdır.<sup>[[6]](#references)</sup> Örnek self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Careless Whisper paper'ındaki measurements, delivery receipt'lerin device'lar arasında synchronize edildiğini; bu nedenle multi-device setup'ta bile her message için yalnızca bir receipt açığa çıktığını buldu.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker), WhatsApp/Signal backend'leriyle birlikte gelir, silent delete probe'larını default olarak kullanır ve rolling-median threshold (`RTT < 0.9 * median`) ile `active` ve `standby` durumlarını etiketler.<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python), `--delay`, `--concurrent`, CSV/Prometheus exporter'ları ve Grafana-friendly output sunan, WhatsApp-first daha hafif bir CLI'dir.<sup>[[9]](#references)</sup> Her ikisini de protocol reference yerine reconnaissance helper olarak değerlendirin; önemli çıkarım, raw client access mevcut olduğunda ne kadar az code gerektiğidir.

Custom tooling mevcut olmadığında official client'lar veya browser developer tools yine silent action'ları tetikleyebilir ve encrypted traffic timing'ini açığa çıkarabilir; raw API'ler UI delay'lerini ortadan kaldırır ve invalid operation'lara izin verir.<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. Chat'te sizin gönderdiğiniz herhangi bir historical message'ı seçin; böylece victim "reaction" balloon'larının değiştiğini asla görmez.
2. Visible emoji ile empty reaction payload arasında dönüşümlü geçiş yapın (WhatsApp protobuf'larında `""`, signal-cli'da `--remove` olarak encode edilir). Her transmission, victim için UI delta olmamasına rağmen bir device ack üretir.
3. Send time'ı ve her delivery receipt arrival'ını timestamp'leyin. Aşağıdaki gibi 1 Hz'lik bir loop, süresiz olarak device başına RTT trace'leri sağlar:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal unlimited reaction update'lerini kabul ettiğinden attacker'ın yeni chat content'i post etmesi veya edit window'ları hakkında endişelenmesi gerekmez.<sup>[[1]](#references)</sup>

## Spooky stranger: probing arbitrary phone numbers

1. Yeni bir WhatsApp/Signal account register edin ve target number için public identity key'lerini fetch edin (session setup sırasında otomatik olarak yapılır).
2. Taraflardan hiçbiri tarafından görülmemiş random bir `message_id`'ye reference veren bir reaction packet oluşturun; paper, hem WhatsApp'ın hem de Signal'ın bu reaction'ları kabul ettiğini ve yine delivery receipt ürettiğini bildirir.<sup>[[1]](#references)</sup>
3. Hiçbir thread mevcut olmasa bile packet'i gönderin. Victim device'ları bunu decrypt eder, base message ile eşleştiremez, state change'i discard eder; ancak incoming ciphertext'i yine acknowledge ederek device receipt'lerini attacker'a geri gönderir.
4. Önceden bir conversation veya visible notification olmadan RTT serileri oluşturmak için işlemi sürekli tekrarlayın.<sup>[[1]](#references)</sup>

Önce hangi number'ların registered olduğunu keşfetmeniz gerekiyorsa veya device inventory'lerini scale'de pre-seed etmek istiyorsanız, rastgele E.164 range'lerini elle tahmin etmek yerine bunu [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) ile chain edin.

Published contact-discovery çalışmaları bunun operational olarak neden önemli olduğunu gösterdi: accurate phone-prefix table'ları ve modest resources ile researchers, targeted probing'e geçmeden önce WhatsApp'ta US mobile number'larının yaklaşık `10%`'unu ve Signal'da `100%`'ünü query edebildi.<sup>[[11]](#references)</sup> Pratikte live account'ları önce pre-filter etmek, silent-probe budget'ını gerçekten packet decrypt edecek number'lara odaklar.

Güncel WhatsApp build'leri ayrıca `Settings -> Privacy -> Advanced -> Block unknown account messages` ayarını açığa çıkarır.<sup>[[10]](#references)</sup> Bunu bir throughput limiter olarak değerlendirin: tracker documentation, WhatsApp'ın unknown account'lardan gelen high-volume message'ları block ettiğini ancak threshold'u açıklamadığını; dolayısıyla probe reaction'larını tamamen engellemediğini söyler.<sup>[[8]](#references)</sup>

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Bir message bir kez delete-for-everyone edildikten sonra aynı `message_id`'ye reference veren sonraki delete packet'lerinin UI üzerinde etkisi olmaz; ancak her device bunları decrypt edip acknowledge eder.
* **Out-of-window operations:** WhatsApp UI'da yaklaşık 60 h delete / yaklaşık 20 min edit window uygular; Signal yaklaşık 48 h uygular. Bu window'ların dışındaki crafted protocol message'ları victim device'da sessizce ignore edilir, ancak receipt'ler gönderilir; böylece attacker conversation sona erdikten uzun süre sonra bile probe yapabilir.
* **Invalid payloads:** Paper, invalid message'ların yine acknowledge edilebildiğini bildirir; malformed body'ler veya purged ID'ler için exact behavior implementation'a bağlıdır, bu nedenle güvenmeden önce test edin.<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* WhatsApp ve Signal'da her associated device (phone, desktop app, browser companion) probe'u bağımsız olarak decrypt eder ve kendi ack'ini döndürür. Probe başına receipt'leri saymak exact device count'u ortaya çıkarır.<sup>[[1]](#references)</sup>
* Bir device offline ise receipt'i queue'ya alınır ve reconnect sonrasında gönderilir. Bu nedenle gaps, online/offline cycle'larını ve hatta commuting schedule'larını leak eder (örneğin desktop receipt'leri travel sırasında durur).
* RTT distribution'ları platform ve environment'a göre farklılık gösterir; çünkü OS, model, client ve network condition'ları timing'i etkiler. “Android handset", “iOS handset", “Electron desktop" vb. etiketleri vermek için RTT'leri cluster'layın (örneğin median/variance feature'ları üzerinde k-means).
* Sender'ın encrypting işleminden önce recipient'ın key inventory'sini retrieve etmesi gerektiğinden attacker, yeni device'ların ne zaman paired edildiğini de izleyebilir; device count'taki ani artış veya yeni RTT cluster'ı güçlü bir indicator'dır.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** Published measurements, WhatsApp'ın belirgin server-side queueing olmadan silent-reaction burst'lerini probe başına `50 ms` kadar hızlı kabul ettiğini bildirdi. Bu, kısa calibration burst'leri, hızlı device counting veya drain attack'ı hızla artırmak için kullanışlıdır.
* **Signal long-run queueing:** Signal kısa burst'lere tolerans gösterdi, ancak sustained multi-probe-per-second traffic'i queue'lamaya başladı. Long-lived monitoring için cadence'i yaklaşık `1 Hz` (veya daha düşük) tutun; böylece her receipt backlog drain yerine hâlâ mevcut device state'ini yansıtır.
* **Reconnect artefacts:** Bir device yeniden online olduğunda bazı client'lar delayed receipt'leri batch'ler veya hızla flush eder. Bu receipt burst'lerini bağımsız RTT sample'ları olarak değil, state-transition marker olarak değerlendirin; aksi halde clustering / `active` vs `idle` classifier'ınız reconnect noise'a overfit olur.<sup>[[1]](#references)</sup>

## Behaviour inference from RTT traces

1. OS scheduling effect'lerini yakalamak için ≥1 Hz'de sample alın. WhatsApp on iOS'ta <1 s RTT'ler screen-on/foreground ile güçlü biçimde koreledir; >1 s ise screen-off/background throttling ile ilişkilidir.
2. Her RTT'yi "active" veya "idle" olarak label'layan basit classifier'lar (thresholding veya two-cluster k-means) oluşturun. Bedtime, commute, work hour veya desktop companion'ın active olduğu zamanları çıkarmak için label'ları streak'ler halinde aggregate edin.
3. User'ların mobile'dan desktop'a ne zaman geçtiğini, companion'ların ne zaman offline olduğunu ve app'in push vs persistent socket nedeniyle rate limited olup olmadığını görmek için her device'a yönelik simultaneous probe'ları correlate edin.
4. Real network'lerde tek bir hardcoded `1 s` threshold kullanmayın. Her device'ı kısa bir warm-up window ile bootstrap edin ve rolling baseline tutun (örneğin device-activity-tracker PoC'si `threshold = 0.9 * median RTT` kullanır); böylece Wi-Fi/cellular drift classifier'ınızı bozmaz.<sup>[[1]](#references)[[8]](#references)</sup>

## Location inference from delivery RTT

Aynı timing primitive yalnızca recipient'ın active olup olmadığını değil, nerede bulunduğunu infer etmek için de yeniden kullanılabilir. `Hope of Delivery` çalışması, known receiver location'ları için RTT distribution'larıyla training yapıldığında attacker'ın daha sonra victim'ın location'ını yalnızca delivery confirmation'larından classify edebildiğini gösterdi:<sup>[[2]](#references)</sup>

* Target aynı anda birkaç known location'dayken (home, office, campus, country A vs country B vb.) aynı target için bir baseline oluşturun.
* Her location için çok sayıda normal message RTT'si toplayın ve median, variance veya percentile bucket'ları gibi basit feature'lar çıkarın.
* Gerçek attack sırasında yeni probe serisini trained cluster'larla karşılaştırın. Paper, aynı şehir içindeki location'ların bile çoğu zaman ayrıştırılabildiğini ve 3-location setting'de `>80%` accuracy elde edildiğini bildirir.
* Measured path recipient access network'ünü, wake-up latency'yi ve messenger infrastructure'ını içerdiğinden bu yöntem attacker sender environment'ını kontrol ettiğinde ve benzer network condition'ları altında probe yaptığında en iyi sonucu verir.<sup>[[2]](#references)</sup>

Yukarıdaki silent reaction/edit/delete attack'lerinin aksine location inference, invalid message ID'leri veya stealthy state-changing packet'leri gerektirmez. Normal delivery confirmation'ları olan plain message'lar yeterlidir; bunun karşılığında stealth daha düşüktür, ancak messenger'lar genelinde applicability daha geniştir.

## Stealthy resource exhaustion

Her silent probe decrypt edilip acknowledge edilmek zorunda olduğundan reaction toggle'larını, invalid edit'leri veya delete-for-everyone packet'lerini sürekli göndermek application-layer DoS oluşturur:<sup>[[1]](#references)</sup>

* Radio/modem'i her saniye transmit/receive yapmaya zorlar → özellikle idle handset'lerde fark edilir battery drain.
* Mobile data plan'larını tüketen ve video call gibi latency-sensitive feature'larla contention oluşturabilen upstream/downstream traffic üretir.<sup>[[1]](#references)</sup>
* Large invalid payload'lar processing work'ü artırır; ancak paper, cryptography'nin kendisinin battery cost'unun ihmal edilebilir olduğunu bildirir.<sup>[[1]](#references)</sup>
* WhatsApp'ta invalid reaction'lar, normal bir emoji'nin düşündürdüğünden çok daha fazla data kabul eder: published measurements, reaction başına server-side acceptance'ın yaklaşık `1 MB`'a kadar çıktığını buldu.
* Oversized reaction'lar body yaklaşık `30 bytes`'ı aştığında reliable delivery receipt üretmeyi bırakır, ancak discard edilmeden önce yine forward edilir ve process edilir. ACK gerektiğinde reaction body'lerini küçük tutun; yalnızca drain veya covert one-way transport hedeflendiğinde büyütün.
* Public measurements bu mode'da yaklaşık `3.7 MB/s` (`~13.3 GB/h`) victim traffic'e ulaştı.

## References

- [1] [Careless Whisper: Users'ı Mobile Instant Messenger'larda İzlemek İçin Silent Delivery Receipt'leri Exploit Etme](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Mobile Instant Messenger'lardan User Location'larını Extract Etme](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Bilinmeyen message'ların high volume'unu block etme | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Mobile Messenger'larda Contact Discovery'nin Large-scale Abuse'u](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
