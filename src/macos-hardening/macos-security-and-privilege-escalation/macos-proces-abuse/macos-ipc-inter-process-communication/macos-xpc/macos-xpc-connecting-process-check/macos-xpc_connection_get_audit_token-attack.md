# macOS xpc_connection_get_audit_token Saldırısı

{{#include ../../../../../../banners/hacktricks-training.md}}

**Daha fazla bilgi için orijinal gönderiyi kontrol edin:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Bu bir özet:

## Mach Mesajları Temel Bilgiler

Eğer Mach Mesajlarının ne olduğunu bilmiyorsanız bu sayfayı kontrol etmeye başlayın:

{{#ref}}
../../
{{#endref}}

Şu an için hatırlamanız gereken ([buradan tanım](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach mesajları bir _mach portu_ üzerinden gönderilir, bu da mach çekirdeğine entegre edilmiş **tek alıcı, çoklu gönderici iletişim** kanalını ifade eder. **Birden fazla süreç, bir mach portuna mesaj gönderebilir**, ancak herhangi bir anda **yalnızca bir süreç ondan okuyabilir**. Dosya tanımlayıcıları ve soketler gibi, mach portları çekirdek tarafından tahsis edilir ve yönetilir ve süreçler yalnızca hangi mach portlarını kullanmak istediklerini belirtmek için kullanabilecekleri bir tam sayı görürler.

## XPC Bağlantısı

Eğer bir XPC bağlantısının nasıl kurulduğunu bilmiyorsanız kontrol edin:

{{#ref}}
../
{{#endref}}

## Açıklama Özeti

Bilmeniz gereken ilginç bir şey, **XPC'nin soyutlamasının bire bir bağlantı** olmasıdır, ancak bu, **birden fazla göndericiye sahip olabilen** bir teknoloji üzerine inşa edilmiştir, bu nedenle:

- Mach portları tek alıcı, **çoklu gönderici**.
- Bir XPC bağlantısının denetim belirteci, **en son alınan mesajdan kopyalanan** denetim belirtecidir.
- Bir XPC bağlantısının **denetim belirtecini** elde etmek, birçok **güvenlik kontrolü** için kritik öneme sahiptir.

Önceki durum umut verici görünse de, bunun sorun yaratmayacağı bazı senaryolar vardır ([buradan](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Denetim belirteçleri genellikle bir bağlantıyı kabul edip etmeyeceğine karar vermek için bir yetkilendirme kontrolü için kullanılır. Bu, hizmet portuna bir mesaj gönderilerek gerçekleştiğinden, **henüz bir bağlantı kurulmamıştır**. Bu port üzerindeki daha fazla mesaj, yalnızca ek bağlantı talepleri olarak işlenecektir. Bu nedenle, bir bağlantıyı kabul etmeden önceki **kontroller savunmasız değildir** (bu, `-listener:shouldAcceptNewConnection:` içinde denetim belirtecinin güvende olduğu anlamına gelir). Bu nedenle, **belirli eylemleri doğrulayan XPC bağlantılarını arıyoruz**.
- XPC olay işleyicileri senkronize bir şekilde işlenir. Bu, bir mesaj için olay işleyicisinin, bir sonraki mesaj için çağrılmadan önce tamamlanması gerektiği anlamına gelir, hatta eşzamanlı dağıtım kuyruklarında bile. Bu nedenle, bir **XPC olay işleyicisinde denetim belirteci diğer normal (yanıt vermeyen!) mesajlar tarafından üzerine yazılamaz**.

İki farklı yöntem bu durumdan yararlanılabilir:

1. Varyant 1:
- **Sömürü** **hizmet A** ve **hizmet B** ile **bağlanır**
- Hizmet **B**, kullanıcının yapamayacağı hizmet A'da bir **ayrılmış işlevselliği** çağırabilir
- Hizmet **A**, bir **`dispatch_async`** içinde bir bağlantının **olay işleyicisi** içinde _**değil**_ iken **`xpc_connection_get_audit_token`** çağrısı yapar.
- Böylece, **farklı** bir mesaj **Denetim Belirteci'ni** **üzerine yazabilir** çünkü olay işleyicisinin dışında asenkron olarak dağıtılmaktadır.
- Sömürü, **hizmet B'ye hizmet A'ya gönderme hakkını** verir.
- Böylece hizmet **B**, aslında **hizmet A'ya** **mesajlar** gönderecektir.
- **Sömürü**, **ayrılmış eylemi** **çağırmaya** çalışır. Bir RC hizmet **A**, bu **eylemin** yetkilendirmesini **kontrol ederken**, **hizmet B denetim belirtecini** üzerine yazmıştır (sömürüye, ayrılmış eylemi çağırma erişimi verir).
2. Varyant 2:
- Hizmet **B**, kullanıcının yapamayacağı hizmet A'da bir **ayrılmış işlevselliği** çağırabilir
- Sömürü, **hizmet A** ile bağlanır ve **sömürüye** belirli bir **yanıt** **portunda** bir **mesaj** gönderir.
- Sömürü, **hizmet** B'ye **o yanıt portunu** geçerek bir mesaj gönderir.
- Hizmet **B yanıt verdiğinde**, **hizmet A'ya** mesaj gönderir, **bu sırada** **sömürü**, **hizmet A'ya** farklı bir **mesaj** gönderir ve **ayrılmış işlevselliğe** ulaşmaya çalışır ve hizmet B'den gelen yanıtın Denetim Belirteci'ni mükemmel bir anda üzerine yazmasını bekler (Race Condition).

## Varyant 1: xpc_connection_get_audit_token'ı bir olay işleyicisi dışında çağırma <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Senaryo:

- Bağlanabileceğimiz iki mach hizmeti **`A`** ve **`B`** (sandbox profiline ve bağlantıyı kabul etmeden önceki yetkilendirme kontrollerine dayanarak).
- _**A**_, **`B`**'nin geçebileceği belirli bir eylem için bir **yetkilendirme kontrolüne** sahip olmalıdır (ancak uygulamamız sahip olamaz).
- Örneğin, B bazı **yetkilere** sahipse veya **root** olarak çalışıyorsa, A'dan bir ayrıcalıklı eylemi gerçekleştirmesini istemesine izin verebilir.
- Bu yetkilendirme kontrolü için, **`A`**, örneğin `dispatch_async`'dan **`xpc_connection_get_audit_token`** çağrısı yaparak denetim belirtecini asenkron olarak alır.

> [!CAUTION]
> Bu durumda bir saldırgan, **A'dan bir eylem gerçekleştirmesini** istemek için **sömürü** tetikleyebilir ve **B'nin `A'ya mesajlar göndermesini** sağlarken birkaç kez yapabilir. RC **başarılı olduğunda**, **B**'nin **denetim belirteci** bellekte kopyalanacak **ve** **sömürümüzün** isteği **A** tarafından **işlenirken** gerçekleşecektir, bu da ona **yalnızca B'nin talep edebileceği ayrıcalıklı eyleme erişim** sağlar.

Bu, **`A`**'nın `smd` ve **`B`**'nin `diagnosticd` olduğu durumlarda gerçekleşti. [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) fonksiyonu, yeni bir ayrıcalıklı yardımcı araç yüklemek için kullanılabilir ( **root** olarak). Eğer **root olarak çalışan bir süreç** **smd** ile iletişime geçerse, başka kontroller yapılmayacaktır.

Bu nedenle, hizmet **B** **`diagnosticd`**'dir çünkü **root** olarak çalışır ve bir süreci **izlemek** için kullanılabilir, bu nedenle izleme başladıktan sonra, **saniyede birden fazla mesaj gönderir.**

Saldırıyı gerçekleştirmek için:

1. Standart XPC protokolünü kullanarak `smd` adlı hizmete bir **bağlantı** başlatın.
2. `diagnosticd`'ye ikincil bir **bağlantı** oluşturun. Normal prosedürün aksine, iki yeni mach portu oluşturmak ve göndermek yerine, istemci port gönderme hakkı, `smd` bağlantısıyla ilişkili **gönderme hakkının** bir kopyasıyla değiştirilir.
3. Sonuç olarak, XPC mesajları `diagnosticd`'ye dağıtılabilir, ancak `diagnosticd`'en gelen yanıtlar `smd`'ye yönlendirilir. `smd` için, hem kullanıcıdan hem de `diagnosticd`'den gelen mesajların aynı bağlantıdan geldiği görünmektedir.

![Sömürü sürecini gösteren bir görüntü](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Bir sonraki adım, `diagnosticd`'ye seçilen bir süreci (potansiyel olarak kullanıcının kendi süreci) izlemeye başlatmaktır. Aynı anda, `smd`'ye rutin 1004 mesajlarının bir seli gönderilir. Buradaki amaç, ayrıcalıklı yetkilere sahip bir aracı yüklemektir.
5. Bu eylem, `handle_bless` fonksiyonu içinde bir yarış durumu tetikler. Zamanlama kritik öneme sahiptir: `xpc_connection_get_pid` fonksiyonu, kullanıcının sürecinin PID'sini döndürmelidir (çünkü ayrıcalıklı araç kullanıcının uygulama paketinde bulunur). Ancak, `xpc_connection_get_audit_token` fonksiyonu, özellikle `connection_is_authorized` alt rutininde, `diagnosticd`'ye ait denetim belirtecini referans almalıdır.

## Varyant 2: yanıt yönlendirme

Bir XPC (Çapraz Süreç İletişimi) ortamında, olay işleyicileri eşzamanlı olarak çalışmasa da, yanıt mesajlarının işlenmesi benzersiz bir davranış sergiler. Özellikle, yanıt bekleyen mesajlar göndermenin iki ayrı yöntemi vardır:

1. **`xpc_connection_send_message_with_reply`**: Burada, XPC mesajı belirli bir kuyrukta alınır ve işlenir.
2. **`xpc_connection_send_message_with_reply_sync`**: Tersine, bu yöntemde XPC mesajı mevcut dağıtım kuyruğunda alınır ve işlenir.

Bu ayrım, **yanıt paketlerinin bir XPC olay işleyicisinin yürütülmesiyle eşzamanlı olarak ayrıştırılma olasılığını** sağlar. Özellikle, `_xpc_connection_set_creds` denetim belirtecinin kısmi olarak üzerine yazılmasını önlemek için kilitleme uygulasa da, bu korumayı tüm bağlantı nesnesine genişletmez. Sonuç olarak, bir paket ayrıştırma ile olay işleyicisinin yürütülmesi arasındaki aralıkta denetim belirtecinin değiştirilmesine neden olan bir zayıflık oluşturur.

Bu zayıflıktan yararlanmak için aşağıdaki kurulum gereklidir:

- **`A`** ve **`B`** olarak adlandırılan iki mach hizmeti, her ikisi de bir bağlantı kurabilir.
- Hizmet **`A`**, yalnızca **`B`**'nin gerçekleştirebileceği belirli bir eylem için bir yetkilendirme kontrolü içermelidir (kullanıcının uygulaması yapamaz).
- Hizmet **`A`**, bir yanıt bekleyen bir mesaj göndermelidir.
- Kullanıcı, **`B`**'ye yanıt vereceği bir mesaj gönderebilir.

Sömürü süreci aşağıdaki adımları içerir:

1. Hizmet **`A`**'nın yanıt bekleyen bir mesaj göndermesini bekleyin.
2. **`A`**'ya doğrudan yanıt vermek yerine, yanıt portu ele geçirilir ve hizmet **`B`**'ye bir mesaj göndermek için kullanılır.
3. Ardından, yasaklı eylemi içeren bir mesaj gönderilir ve bunun, **`B`**'den gelen yanıtla eşzamanlı olarak işleneceği beklenir.

Aşağıda, tanımlanan saldırı senaryosunun görsel bir temsili bulunmaktadır:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Keşif Problemleri

- **Örnekleri Bulma Zorlukları**: `xpc_connection_get_audit_token` kullanım örneklerini bulmak, hem statik hem de dinamik olarak zordu.
- **Metodoloji**: Frida, `xpc_connection_get_audit_token` fonksiyonunu yakalamak için kullanıldı ve olay işleyicilerinden gelmeyen çağrıları filtreledi. Ancak, bu yöntem yalnızca yakalanan süreçle sınırlıydı ve aktif kullanım gerektiriyordu.
- **Analiz Araçları**: Ulaşılabilir mach hizmetlerini incelemek için IDA/Ghidra gibi araçlar kullanıldı, ancak süreç zaman alıcıydı ve dyld paylaşılan önbelleği ile ilgili çağrılarla karmaşık hale geldi.
- **Betik Sınırlamaları**: `dispatch_async` bloklarından `xpc_connection_get_audit_token` çağrılarını analiz etmek için betik yazma girişimleri, blokların ayrıştırılması ve dyld paylaşılan önbelleği ile etkileşimdeki karmaşıklıklar nedeniyle engellendi.

## Çözüm <a href="#the-fix" id="the-fix"></a>

- **Bildirim Yapılan Sorunlar**: `smd` içinde bulunan genel ve özel sorunları detaylandıran bir rapor Apple'a gönderildi.
- **Apple'ın Yanıtı**: Apple, `smd` içindeki sorunu `xpc_connection_get_audit_token`'ı `xpc_dictionary_get_audit_token` ile değiştirerek ele aldı.
- **Çözümün Doğası**: `xpc_dictionary_get_audit_token` fonksiyonu, alınan XPC mesajına bağlı mach mesajından doğrudan denetim belirtecini alması nedeniyle güvenli kabul edilir. Ancak, `xpc_connection_get_audit_token` gibi kamu API'sinin bir parçası değildir.
- **Daha Kapsamlı Bir Çözümün Yokluğu**: Apple'ın, bağlantının kaydedilen denetim belirteciyle uyumlu olmayan mesajları atma gibi daha kapsamlı bir çözüm uygulamadığı nedeninin belirsizliğini koruyor. Belirli senaryolarda (örneğin, `setuid` kullanımı) meşru denetim belirteci değişikliklerinin olabileceği ihtimali bir faktör olabilir.
- **Mevcut Durum**: Sorun, iOS 17 ve macOS 14'te devam etmekte olup, bunu tanımlamaya ve anlamaya çalışanlar için bir zorluk teşkil etmektedir.

{{#include ../../../../../../banners/hacktricks-training.md}}
