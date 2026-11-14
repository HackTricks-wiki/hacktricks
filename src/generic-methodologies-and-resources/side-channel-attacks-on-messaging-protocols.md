# E2EE Messenger’larda Teslimat Bildirimi Yan Kanal Saldırıları

{{#include ../banners/hacktricks-training.md}}

Modern uçtan uca şifreli (E2EE) messenger’larda teslimat bildirimleri zorunludur; çünkü istemcilerin, ratchet durumunu ve ephemeral key’leri silebilmek için bir ciphertext’in ne zaman çözüldüğünü bilmesi gerekir. Sunucu opak blob’ları iletir; bu nedenle cihaz onayları (çift tik), alıcı tarafından başarılı şifre çözmenin ardından gönderilir. Saldırganın tetiklediği bir eylemle buna karşılık gelen teslimat bildirimi arasındaki gidiş-dönüş süresini (RTT) ölçmek, cihaz durumunu ve çevrimiçi varlığı açığa çıkaran yüksek çözünürlüklü bir zamanlama kanalı oluşturur ve gizli DoS için kötüye kullanılabilir. Çok cihazlı “client-fanout” dağıtımları, kayıtlı her cihaz probu çözüp kendi bildirimini gönderdiğinden bu sızıntıyı artırır.<sup>[[1]](#references)</sup>

## Teslimat bildirimi kaynakları ve kullanıcıya görünen sinyaller

Her zaman teslimat bildirimi gönderen, ancak kurbanda UI öğeleri göstermeyen mesaj türlerini seçin. Aşağıdaki tabloda deneysel olarak doğrulanmış davranış özetlenmiştir:<sup>[[1]](#references)</sup>

| Messenger | Eylem | Teslimat bildirimi | Kurban bildirimi | Notlar |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Metin mesajı | ● | ● | Her zaman gürültülü → yalnızca başlangıç durumunu belirlemek için kullanışlıdır. |
| | Reaksiyon | ● | ◐ (yalnızca kurbanın mesajına reaksiyon verildiğinde) | Kendi mesajına verilen reaksiyonlar ve kaldırmalar sessiz kalır. |
| | Düzenleme | ● | Platforma bağlı sessiz push | Düzenleme aralığı ≈20 dk; süre dolduktan sonra da ack gönderilir. |
| | Herkes için silme | ● | ○ | UI yaklaşık 60 saat izin verir, ancak daha sonraki paketler de ack alır. |
| **Signal** | Metin mesajı | ● | ● | WhatsApp ile aynı kısıtlamalar. |
| | Reaksiyon | ● | ◐ | Kullanıcının kendi mesajına verdiği reaksiyonlar kurbana görünmez. |
| | Düzenleme/Silme | ● | ○ | Sunucu yaklaşık 48 saatlik süreyi uygular ve en fazla 10 düzenlemeye izin verir; ancak geç gönderilen paketler de ack alır. |
| **Threema** | Metin mesajı | ● | ● | Çok cihazlı bildirimler birleştirilir; bu yüzden her prob için yalnızca bir RTT görünür. |

Gösterge: ● = her zaman, ◐ = koşullu, ○ = hiçbir zaman. Platforma bağlı UI davranışı notlarda belirtilmiştir. Gerekirse okundu bilgilerini devre dışı bırakın; ancak WhatsApp veya Signal’da teslimat bildirimleri kapatılamaz.<sup>[[1]](#references)</sup>

## Saldırganın hedefleri ve modelleri

* **G1 – Cihaz parmak izi çıkarma:** Her prob için kaç bildirim geldiğini sayın, RTT’leri kümeleyerek işletim sistemi/istemci türünü (Android ile iOS veya masaüstü) tahmin edin ve çevrimiçi/çevrimdışı geçişleri izleyin.
* **G2 – Davranış izleme:** Yüksek frekanslı RTT serisini (≈1 Hz kararlıdır) bir zaman serisi olarak değerlendirin ve ekranın açık/kapalı olma durumunu, uygulamanın ön planda/arka planda olmasını, işe gidip gelme saatlerini vb. çıkarın.
* **G3 – Kaynak tüketimi:** Bitmek bilmeyen sessiz problar göndererek kurbanın her cihazındaki radyoları/CPU’ları çalışır durumda tutun; pil ve veri tüketimine yol açın ve görüntülü arama kalitesini düşürün.<sup>[[1]](#references)</sup>

Kötüye kullanım yüzeyini açıklamak için iki tehdit aktörü yeterlidir:<sup>[[1]](#references)</sup>

1. **Creepy companion:** Kurbanla zaten bir sohbeti vardır ve mevcut mesaj kimliklerine bağlı kendi mesajlarına reaksiyonları, reaksiyon kaldırmalarını veya tekrarlanan düzenleme/silme işlemlerini kötüye kullanır.
2. **Spooky stranger:** Tek kullanımlık bir hesap açar ve yerel sohbette hiç var olmamış mesaj kimliklerine referans veren reaksiyonlar gönderir; WhatsApp ve Signal, UI durum değişikliğini yok saysa bile bu mesajların şifresini çözerek ack gönderir, dolayısıyla önceden bir sohbetin bulunması gerekmez.

## Ham protokol erişimi için araçlar

UI kısıtlamalarının dışında desteklenen paketler oluşturmak ve hassas zaman damgalarını kaydetmek için temel E2EE protokolünün yeterli kısmını açığa çıkaran istemciler kullanın; rastgele mesaj kimlikleri için her uygulamayı ayrı ayrı kontrol etmek gerekir:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web çok cihazlı API) teslimat bildirimleri gönderme ve alma işlemlerini belgelendirir; [Cobalt](https://github.com/Auties00/Cobalt) (resmî olmayan Java/Kotlin Web ve mobil API) reaksiyon verme, düzenleme ve silme gibi mesaj işlemlerini belgelendirir. Her dahili frame’in sunulduğunu varsaymak yerine belgelenmiş API’lerini kullanın.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) CLI, JSON-RPC ve D-Bus arayüzleri sunarken, [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) Signal ile iletişim kurmak için kullanılan bir Java kütüphanesidir.<sup>[[5]](#references)[[7]](#references)</sup> Güncel `signal-cli` sözdizimi `sendReaction RECIPIENT --target-author --target-timestamp` şeklindedir; protokol güncellemelerinin işlenmeye devam etmesi için `receive` veya `daemon` çalışır durumda tutulmalıdır.<sup>[[6]](#references)</sup> Kendi mesajına reaksiyon verme/açma örneği:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Careless Whisper makalesindeki ölçümler, teslimat makbuzlarının cihazlar arasında senkronize edildiğini ve bu nedenle çok cihazlı kurulumlarda bile mesaj başına yalnızca bir makbuzun açığa çıktığını gösterdi.<sup>[[1]](#references)</sup>
* **Hazır PoC'ler:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker), WhatsApp/Signal backend'leriyle birlikte gelir, varsayılan olarak sessiz silme yoklamalarını kullanır ve kayan medyan eşiğiyle (`RTT < 0.9 * median`) `active` ile `standby` durumlarını etiketler.<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python), `--delay`, `--concurrent`, CSV/Prometheus dışa aktarıcıları ve Grafana uyumlu çıktısı olan, WhatsApp öncelikli daha hafif bir CLI'dır.<sup>[[9]](#references)</sup> Her ikisini de protokol referansı olarak değil, keşif yardımcıları olarak değerlendirin; asıl çıkarım, ham istemci erişimi olduğunda ne kadar az kod gerektiğidir.

Özel araçlar olmadığında resmi istemciler veya tarayıcı geliştirici araçları yine de sessiz eylemleri tetikleyebilir ve şifreli trafik zamanlamasını açığa çıkarabilir; ham API'ler arayüz gecikmelerini ortadan kaldırır ve geçersiz işlemlere izin verir.<sup>[[1]](#references)</sup>

## Ürkütücü yardımcı: sessiz örnekleme döngüsü

1. Sohbette daha önce gönderdiğiniz herhangi bir mesajı seçin; böylece kurban "reaction" balonlarının değiştiğini görmez.
2. Görünür bir emoji ile boş bir reaction payload'ı arasında geçiş yapın (WhatsApp protobuf'larında `""`, signal-cli'da `--remove` olarak kodlanır). Her gönderim, kurbanın arayüzünde değişiklik olmasa da bir cihaz ack'i üretir.
3. Gönderim zamanını ve her teslimat makbuzunun geliş zamanını kaydedin. Aşağıdaki gibi bir 1 Hz döngüsü, süresiz olarak cihaz başına RTT izleri sağlar:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. WhatsApp/Signal sınırsız reaction updates kabul ettiğinden, saldırganın yeni sohbet içeriği göndermesi veya düzenleme sürelerini dert etmesi gerekmez.<sup>[[1]](#references)</sup>

## Ürkütücü yabancı: rastgele telefon numaralarını yoklama

1. Yeni bir WhatsApp/Signal hesabı kaydedin ve hedef numaranın herkese açık kimlik anahtarlarını alın (oturum kurulumu sırasında otomatik olarak yapılır).
2. Taraflardan hiçbirinin görmediği rastgele bir `message_id`'ye referans veren bir reaction paketi oluşturun; makalede hem WhatsApp'ın hem de Signal'in bu tür reaction'ları kabul ettiği ve yine de delivery receipt ürettiği bildiriliyor.<sup>[[1]](#references)</sup>
3. Hiç sohbet dizisi olmasa bile paketi gönderin. Mağdurun cihazları paketin şifresini çözer, temel mesajla eşleştiremez ve durum değişikliğini atar; ancak gelen şifreli metni yine de onaylayarak saldırgana cihaz receipt'leri gönderir.
4. Önceden bir sohbet veya görünür bildirim olmadan RTT serileri oluşturmak için bunu sürekli tekrarlayın.<sup>[[1]](#references)</sup>

Önce hangi numaraların kayıtlı olduğunu keşfetmeniz veya büyük ölçekte cihaz envanterlerini önceden oluşturmanız gerekiyorsa, rastgele E.164 aralıklarını elle tahmin etmek yerine bunu [contact-discovery / kayıt oracle'ları](../pentesting-web/registration-vulnerabilities.md) ile birleştirin.

Yayımlanmış contact-discovery çalışmaları bunun operasyonel açıdan neden önemli olduğunu gösterdi: doğru telefon öneki tabloları ve mütevazı kaynaklarla araştırmacılar, hedefli yoklamaya geçmeden önce WhatsApp'taki ABD mobil numaralarının yaklaşık `%10`'unu, Signal'deki numaraların ise `%100`'ünü sorgulayabildi.<sup>[[11]](#references)</sup> Uygulamada, önce etkin hesapları filtrelemek sessiz yoklama bütçenizi gerçekten paketlerin şifresini çözecek numaralara ayırmanızı sağlar.

Yeni WhatsApp sürümlerinde `Settings -> Privacy -> Advanced -> Block unknown account messages` seçeneği de bulunuyor.<sup>[[10]](#references)</sup> Bunu bir verim sınırlayıcı olarak değerlendirin: tracker belgeleri, WhatsApp'ın bilinmeyen hesaplardan gelen yüksek hacimli mesajları engellediğini ancak eşiği açıklamadığını belirtiyor; dolayısıyla bu seçenek probe reaction'larını tamamen önlemiyor.<sup>[[8]](#references)</sup>

## Düzenlemeleri ve silmeleri örtülü tetikleyiciler olarak yeniden kullanma

* **Tekrarlanan silmeler:** Bir mesaj herkes için bir kez silindikten sonra, aynı `message_id`'ye referans veren sonraki delete paketlerinin arayüzde etkisi olmaz; ancak her cihaz bunların şifresini çözmeye ve onaylamaya devam eder.
* **Süre penceresi dışındaki işlemler:** WhatsApp arayüzde yaklaşık 60 saatlik silme / 20 dakikalık düzenleme pencereleri uygular; Signal ise yaklaşık 48 saat uygular. Bu pencerelerin dışındaki, özel olarak oluşturulmuş protokol mesajları mağdurun cihazında sessizce yok sayılır ancak receipt'ler gönderilir; böylece saldırganlar sohbet sona erdikten çok sonra bile süresiz yoklama yapabilir.
* **Geçersiz payload'lar:** Makalede geçersiz mesajların yine de onaylanabileceği bildiriliyor; bozuk gövdeler veya silinmiş ID'ler için kesin davranış uygulamaya bağlıdır, bu nedenle buna güvenmeden önce test edin.<sup>[[1]](#references)</sup>

## Çoklu cihazla büyütme ve parmak izi çıkarma

* WhatsApp ve Signal'de her eşleştirilmiş cihaz (telefon, masaüstü uygulaması, tarayıcı eşlikçisi) probe'un şifresini bağımsız olarak çözer ve kendi ACK'sini döndürür. Her probe başına receipt'leri saymak, cihaz sayısını tam olarak ortaya çıkarır.<sup>[[1]](#references)</sup>
* Bir cihaz çevrimdışıysa receipt'i sıraya alınır ve yeniden bağlandığında gönderilir. Dolayısıyla aradaki boşluklar çevrimiçi/çevrimdışı döngülerini, hatta işe gidip gelme saatlerini bile sızdırır (ör. seyahat sırasında masaüstü receipt'leri kesilir).
* İşletim sistemi, model, istemci ve ağ koşulları zamanlamayı etkilediğinden RTT dağılımları platforma ve ortama göre değişir. RTT'leri kümelendirin (ör. medyan/varyans özellikleri üzerinde k-means) ve “Android telefon”, “iOS telefon”, “Electron masaüstü” gibi etiketler atayın.
* Gönderenin şifreleme yapmadan önce alıcının anahtar envanterini alması gerektiğinden, saldırgan yeni cihazların ne zaman eşleştirildiğini de izleyebilir; cihaz sayısındaki ani artış veya yeni bir RTT kümesi güçlü bir göstergedir.<sup>[[1]](#references)</sup>

**Sıraya alınmış receipt'lerden parmak izi çıkarma:** Hedef cihaz çevrimdışıyken farklı mesaj ID'leriyle birkaç probe gönderin. Yeniden bağlandığında, dönen delivery receipt'lerdeki ID'leri eşleştirin ve bunların ayrı mı yoksa tek bir receipt'te birleştirilmiş mi olduğunu, ayrıca birleştirilmiş ID'lerin gönderim sırasını koruyup korumadığını veya tersine çevirip çevirmediğini kontrol edin. Test edilen istemcilerde WhatsApp Android/iOS ayrı delivery receipt'ler döndürürken Web, Windows ve macOS bunları birleştirdi; macOS, birleştirilmiş sıralamayı tersine çevirdi. Signal Desktop receipt'leri birleştirirken mobil istemcileri birleştirmedi. Bu yöntem, RTT dağılımları örtüşse bile yeniden bağlanan istemciyi sınıflandırabilir. Birleştirme kuralları farklı olan delivery receipt'leri read receipt'lerle karıştırmayın.<sup>[[1]](#references)</sup>

Mesajları teslim etmeden **sunucu tarafı prekey yenilemelerini** okuyan ayrı bir WhatsApp probe'u için [Prekey Bundle Depletion and Refill Side Channel](whatsapp-prekey-bundle-side-channel.md) başlığına bakın.

## Örnekleme sıklığı, kuyruklama ve birleştirilmiş receipt'ler

* **WhatsApp burst toleransı:** Yayımlanmış ölçümler, WhatsApp'ın sunucu tarafında belirgin kuyruklama olmadan her `50 ms`'de bir probe hızına varan sessiz reaction burst'lerini kabul ettiğini bildirdi. Bu, kısa kalibrasyon burst'leri, hızlı cihaz sayımı veya drain saldırısını hızla artırmak için kullanışlıdır.
* **Signal'de uzun süreli kuyruklama:** Signal kısa burst'lere tolerans gösterdi ancak saniyede birden fazla probe içeren sürekli trafiği kuyruklamaya başladı. Uzun süreli izleme için sıklığı yaklaşık `1 Hz` (veya daha düşük) tutun; böylece her receipt birikmiş kuyruğun boşaltılmasını değil, mevcut cihaz durumunu yansıtır.
* **Yeniden bağlanma artefaktları:** Bir cihaz yeniden çevrimiçi olduğunda bazı istemciler birden çok gecikmiş receipt'i toplu halde veya hızla gönderir. Bu receipt burst'lerini bağımsız RTT örnekleri yerine durum geçişi göstergesi olarak değerlendirin; aksi takdirde kümeleme / `active` ve `idle` sınıflandırıcınız yeniden bağlanma gürültüsüne aşırı uyum sağlar.<sup>[[1]](#references)</sup>

## RTT izlerinden davranış çıkarımı

1. İşletim sistemi zamanlama etkilerini yakalamak için ≥1 Hz hızında örnek alın. WhatsApp iOS'ta 1 saniyeden kısa RTT'ler ekranın açık/ön planda olmasıyla, 1 saniyeden uzun RTT'ler ise ekranın kapalı/arka plan kısıtlamalarıyla güçlü biçimde ilişkilidir.
2. Her RTT'yi “active” veya “idle” olarak etiketleyen basit sınıflandırıcılar (eşikleme veya iki kümeli k-means) oluşturun. Yatma saatlerini, işe gidiş gelişleri, çalışma saatlerini veya masaüstü eşlikçisinin etkin olduğu zamanları çıkarmak için etiketleri ardışık gruplar halinde birleştirin.
3. Kullanıcıların mobilden masaüstüne ne zaman geçtiğini, eşlikçi cihazların ne zaman çevrimdışı olduğunu ve uygulamanın push veya kalıcı socket nedeniyle hız sınırlamasına uğrayıp uğramadığını görmek için tüm cihazlara aynı anda probe gönderip sonuçları ilişkilendirin.
4. Gerçek ağlarda sabit bir `1 s` eşiğine güvenmeyin. Her cihazı kısa bir ısınma penceresiyle başlatın ve kayan bir temel değer tutun (örneğin device-activity-tracker PoC'si `threshold = 0.9 * median RTT` kullanır); böylece Wi-Fi/hücresel ağ değişimleri sınıflandırıcınızı bozmaz.<sup>[[1]](#references)[[8]](#references)</sup>

## Teslimat RTT'sinden konum çıkarımı

Aynı zamanlama yöntemi, alıcının yalnızca etkin olup olmadığını değil, nerede olduğunu çıkarmak için de kullanılabilir. `Hope of Delivery` çalışması, bilinen alıcı konumları için RTT dağılımları üzerinde eğitim yapmanın saldırganın daha sonra yalnızca teslimat onaylarından mağdurun konumunu sınıflandırmasına olanak verdiğini gösterdi:<sup>[[2]](#references)</sup>

* Aynı hedef için, hedef birkaç bilinen konumdayken (ev, ofis, kampüs, ülke A ve ülke B gibi) bir temel değer oluşturun.
* Her konum için çok sayıda normal mesaj RTT'si toplayın ve medyan, varyans veya yüzdelik dilim aralıkları gibi basit özellikleri çıkarın.
* Gerçek saldırı sırasında yeni probe serisini eğitilmiş kümelerle karşılaştırın. Makalede, aynı şehir içindeki konumların bile çoğu zaman birbirinden ayrılabildiği ve 3 konumlu bir senaryoda doğruluğun `%80`'i aştığı bildiriliyor.
* Ölçülen yol alıcının erişim ağını, uyanma gecikmesini ve mesajlaşma altyapısını içerdiğinden, bu yöntem en iyi saldırganın gönderici ortamını kontrol ettiği ve benzer ağ koşullarında probe gönderdiği durumlarda çalışır.<sup>[[2]](#references)</sup>

Yukarıdaki sessiz reaction/düzenleme/silme saldırılarının aksine, konum çıkarımı geçersiz mesaj ID'leri veya gizli durum değiştiren paketler gerektirmez. Normal delivery confirmation içeren sıradan mesajlar yeterlidir; dolayısıyla ödünleşim daha düşük gizlilik, ancak mesajlaşma uygulamaları genelinde daha geniş uygulanabilirliktir.

## Gizli kaynak tüketimi

Her sessiz probe'un şifresinin çözülmesi ve onaylanması gerektiğinden, reaction toggle'ları, geçersiz düzenlemeler veya herkes için silme paketleri sürekli gönderilerek uygulama katmanında DoS oluşturulabilir:<sup>[[1]](#references)</sup>

* Radyoyu/modemi her saniye veri gönderip almaya zorlar → özellikle boşta duran telefonlarda fark edilir pil tüketimi yaratır.
* Mobil veri paketlerini tüketen ve görüntülü arama gibi gecikmeye duyarlı özelliklerle rekabet edebilen yukarı/aşağı yönlü trafik oluşturur.<sup>[[1]](#references)</sup>
* Büyük geçersiz payload'lar ek işlem yükü oluşturur ancak makalede kriptografinin pil maliyetinin ihmal edilebilir olduğu bildiriliyor.<sup>[[1]](#references)</sup>
* WhatsApp'ta geçersiz reaction'lar, sıradan bir emoji izlenimi verenden çok daha fazla veri kabul eder: yayımlanmış ölçümlerde sunucu tarafında reaction başına yaklaşık `1 MB`'a kadar kabul görüldü.
* Gövde yaklaşık `30 bytes`'ı aştığında aşırı büyük reaction'lar güvenilir delivery receipt üretmeyi bırakır; ancak atılmadan önce iletilir ve işlenir. ACK gerektiğinde reaction gövdelerini küçük tutun; yalnızca tüketim veya gizli tek yönlü aktarım hedeflendiğinde büyütün.
* Yayımlanmış ölçümlerde bu modda mağdur trafiği yaklaşık `3.7 MB/s` (`~13.3 GB/h`) düzeyine ulaştı.



## References

- [1] [Careless Whisper: Mobil anlık mesajlaşma uygulamalarında sessiz teslimat makbuzlarından yararlanarak kullanıcıları izleme](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Mobil anlık mesajlaşma uygulamalarından kullanıcı konumlarını çıkarma](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Bilinmeyen mesajların yüksek hacimlerini engelleme | WhatsApp Yardım Merkezi](https://faq.whatsapp.com/3379690015658337)
- [11] [Tüm numaralar ABD'den: Mobil mesajlaşma uygulamalarında contact-discovery'nin büyük ölçekli kötüye kullanımı](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
