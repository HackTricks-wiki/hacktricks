# E2EE mesajlaşmalarda Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Delivery receipts modern end-to-end encrypted (E2EE) mesajlaşma istemcilerinde zorunludur çünkü istemcilerin bir ciphertext’in ne zaman deşifre edildiğini bilip ratcheting state ve ephemeral anahtarları atabilmeleri gerekir. Sunucu opak blob’ları iletir, bu yüzden cihaz onayları (çift tikler) alıcı tarafından başarılı deşifre sonrası gönderilir. Bir saldırgan tetikli eylem ile ilgili delivery receipt arasındaki round-trip time (RTT) ölçümü yüksek çözünürlüklü bir zaman kanalı açar ve device state, online presence sızdırır (leaks) ve covert DoS için suistimal edilebilir. Çoklu cihaz “client-fanout” dağıtımları leakage’ı artırır çünkü kayıtlı her cihaz probe’u deşifre eder ve kendi receipt’ini geri gönderir.

## Delivery receipt kaynakları vs. kullanıcıya görünen sinyaller

Kurbandan UI artefaktı oluşturmayacak, ancak her zaman delivery receipt üreten mesaj tiplerini seçin. Aşağıdaki tablo ampirik olarak doğrulanmış davranışı özetler:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Always noisy → only useful to bootstrap state. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions and removals stay silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; still ack’d after expiry. |
| | Delete for everyone | ● | ○ | UI allows ~60 h, but later packets still ack’d. |
| **Signal** | Text message | ● | ● | Same limitations as WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions invisible to victim. |
| | Edit/Delete | ● | ○ | Server enforces ~48 h window, allows up to 10 edits, but late packets still ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts are aggregated, so only one RTT per probe becomes visible. |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI davranışı satır içinde not edilmiştir. Read receipts’leri kapatın gerekirse, ancak WhatsApp veya Signal’da delivery receipts kapatılamaz.

## Attacker goals and models

* **G1 – Device fingerprinting:** Her probe başına kaç receipt geldiğini sayın, RTT’leri kümeleyin (cluster) OS/istemci (Android vs iOS vs desktop) çıkarmak için ve online/offline geçişlerini takip edin.
* **G2 – Behavioural monitoring:** Yüksek frekanslı RTT serisini (≈1 Hz stabil) bir zaman serisi olarak ele alıp ekran açık/kapalı, uygulama foreground/background, işe gidip gelme vs mesai saatleri gibi davranışları çıkarın.
* **G3 – Resource exhaustion:** Sessiz probe’lar göndererek her kurban cihazın radio/CPU’larını uyanık tutun; böylece batarya/veri tüketimini artırıp VoIP/RTC kalitesini bozdurun.

Suistimal yüzeyini tanımlamak için iki tehdit aktörü yeterlidir:

1. **Creepy companion:** Zaten kurbanla bir sohbet paylaşıyor ve self-reactions, reaction removals veya mevcut message ID’lere bağlı tekrarlanan edit/delete’leri suistimal ediyor.
2. **Spooky stranger:** Burner hesap kaydeder ve yerel konuşmada hiç var olmayan message ID’lerine referans veren reaction’lar gönderir; WhatsApp ve Signal bunları UI durumu atsa bile hala deşifre edip acknowledge eder, bu yüzden önceden bir konuşma gerekmez.

## Tooling for raw protocol access

UI kısıtlamalarının dışından paketler oluşturup rastgele `message_id`’ler belirleyebilmek ve hassas zaman damgalarını kaydedebilmek için alttaki E2EE protokolünü açığa çıkaran istemcilere güvenin:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) veya [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) size raw `ReactionMessage`, `ProtocolMessage` (edit/delete) ve `Receipt` frame’leri göndermeyi ve double-ratchet durumunu senkron tutmayı sağlar.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) ile [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) kombinasyonu CLI/API üzerinden her mesaj tipini açığa çıkarır. Örnek self-reaction toggle:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Android istemcisinin kaynağı delivery receipt’lerin cihazdan çıkmadan önce nasıl konsolide edildiğini belgeler, bu yüzden yan kanalın burada neden ihmal edilebilir bant genişliğine sahip olduğunu açıklar.

Custom araçlar yoksa, WhatsApp Web veya Signal Desktop üzerinden sessiz eylemler tetikleyip şifreli websocket/WebRTC kanalını sniff’leyebilirsiniz; ancak raw API’ler UI gecikmelerini ortadan kaldırır ve geçersiz işlemlere izin verir.

## Creepy companion: silent sampling loop

1. Kurbanın hiç “reaction” balonu değiştirmemesi için sohbette sizin yazdığınız herhangi bir geçmiş mesajı seçin.
2. Görünür bir emoji ile boş bir reaction payload’u (WhatsApp protobuf’larında `""` olarak kodlanmış veya signal-cli’da `--remove`) arasında geçiş yapın. Her iletim cihaz ack’i üretir, kurban için UI değişikliği olmasa bile.
3. Gönderim zamanını ve her delivery receipt gelişini zaman damgalarıyla kaydedin. Aşağıdaki gibi 1 Hz döngü cihaz başına RTT izleri verir:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal sınırsız reaction güncellemelerini kabul ettiğinden, saldırgan yeni sohbet içeriği göndermek veya edit pencereleri konusunda endişelenmek zorunda kalmaz.

## Spooky stranger: probing arbitrary phone numbers

1. Yeni bir WhatsApp/Signal hesabı kaydedin ve hedef numara için public identity key’leri alın (oturum kurulumu sırasında otomatik yapılır).
2. Her iki tarafça hiç görülmemiş rastgele bir `message_id`’ye referans veren reaction/edit/delete paketi oluşturun (WhatsApp rastgele `key.id` GUID’lerini kabul eder; Signal milisaniye zaman damgalarını kullanır).
3. Thread olmasa bile paketi gönderin. Kurban cihazları bunu deşifre eder, base message ile eşleştiremez, durum değişikliğini atar ama gelen ciphertext’i yine de acknowledge edip cihaz receipt’lerini saldırgana gönderir.
4. Sohbet listesinde hiç görünmeden sürekli tekrar ederek RTT serisi inşa edin.

## Recycling edits and deletes as covert triggers

* **Tekrarlanan silmeler:** Bir mesaj bir kez delete-for-everyone yapıldıktan sonra, aynı `message_id`’yi referans eden ek delete paketlerinin UI üzerinde hiçbir etkisi olmaz ancak her cihaz yine de bunları deşifre edip acknowledge eder.
* **Pencere dışı işlemler:** WhatsApp UI’da ~60 h delete / ~20 min edit pencerelerini uygular; Signal ~48 h uygular. Bu pencerelerin dışındaki crafted protocol mesajları kurban cihazda sessizce yok sayılır, ancak receipt’ler iletildiği için saldırganlar konuşma uzun süre bittikten sonra bile sürekli probe atabilir.
* **Geçersiz payload’lar:** Bozuk edit gövdeleri veya zaten temizlenmiş mesajlara referans veren delete’ler aynı davranışı tetikler — deşifre + receipt, kullanıcı tarafında sıfır görünür artefakt.

## Multi-device amplification & fingerprinting

* İlişkili her cihaz (telefon, desktop uygulama, tarayıcı companion) probe’u bağımsız olarak deşifre eder ve kendi ack’ini döner. Probe başına gelen receipt’leri saymak kesin cihaz sayısını açığa çıkarır.
* Bir cihaz offline ise receipt kuyruğa alınır ve yeniden bağlantıda iletilir. Bu nedenle boşluklar online/offline döngülerini ve hatta işe gidip gelme programlarını sızdırır (ör. desktop receipt’leri seyahat sırasında durur).
* RTT dağılımları OS güç yönetimi ve push wakeup’lara bağlı olarak platformlar arasında farklılık gösterir. RTT’leri kümeleyin (ör. medyan/varyans özellikleri üzerinde k-means) ve “Android handset”, “iOS handset”, “Electron desktop” gibi etiketler atayın.
* Gönderen, şifrelemeden önce alıcının key envanterini almak zorunda olduğundan, saldırgan yeni cihazların eşlendiğini de gözlemleyebilir; cihaz sayısında ani artış veya yeni RTT kümesi güçlü bir gösterge olur.

## Behaviour inference from RTT traces

1. OS zamanlama etkilerini yakalamak için ≥1 Hz örnekleme yapın. iOS üzerinde WhatsApp ile <1 s RTT’ler güçlü şekilde ekran-açık/foreground ile, >1 s ise ekran-kapalı/background throttling ile korelasyon gösterir.
2. Basit sınıflandırıcılar (eşikleme veya iki küme k-means) kurun; her RTT’yi "active" veya "idle" olarak etiketleyin. Etiketleri birleşik dönemlere (streaks) toplayarak yatma saatleri, gidip gelmeler, çalışma saatleri veya desktop companion’un aktif olduğu zamanları çıkarın.
3. Her cihaza eşzamanlı probe’ları korelasyonlayarak kullanıcıların ne zaman mobile’dan desktoğa geçtiğini, companion’ların ne zaman çevrimdışı olduğunu ve uygulamanın push’a karşı persistent socket ile orantılı olarak rate limited olup olmadığını görün.

## Stealthy resource exhaustion

Her sessiz probe deşifre edilip acknowledge edilmek zorunda olduğundan, reaction toggle’larını, geçersiz edit’leri veya delete-for-everyone paketlerini sürekli gönderme uygulama katmanı DoS’u yaratır:

* Her saniye radyo/modemin transmit/receive yapmasını zorunlu kılar → özellikle idle telefonlarda belirgin batarya tükenmesi.
* TLS/WebSocket gürültüsüne karışarak mobil veri planlarını tüketen upstream/downstream trafik üretir.
* Kripto thread’lerini meşgul eder ve VoIP, video aramaları gibi gecikmeye duyarlı özelliklerde jitter oluşturur; kullanıcı hiçbir bildirim görmese bile.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
