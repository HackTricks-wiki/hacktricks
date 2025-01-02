# macOS xpc_connection_get_audit_token Saldırısı

{{#include ../../../../../../banners/hacktricks-training.md}}

**Daha fazla bilgi için orijinal gönderiyi kontrol edin:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Bu bir özet:

## Mach Mesajları Temel Bilgiler

Eğer Mach Mesajlarının ne olduğunu bilmiyorsanız bu sayfayı kontrol etmeye başlayın:

{{#ref}}
../../
{{#endref}}

Şu anda hatırlamanız gereken ([buradan tanım](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach mesajları bir _mach portu_ üzerinden gönderilir, bu da mach çekirdeğine entegre edilmiş **tek alıcı, çoklu gönderici iletişim** kanalını ifade eder. **Birden fazla süreç, bir mach portuna mesaj gönderebilir**, ancak herhangi bir anda **yalnızca bir süreç ondan okuyabilir**. Dosya tanımlayıcıları ve soketler gibi, mach portları çekirdek tarafından tahsis edilir ve yönetilir ve süreçler yalnızca hangi mach portlarını kullanmak istediklerini belirtmek için kullanabilecekleri bir tam sayı görürler.

## XPC Bağlantısı

Eğer bir XPC bağlantısının nasıl kurulduğunu bilmiyorsanız kontrol edin:

{{#ref}}
../
{{#endref}}

## Açıklık Özeti

Bilmeniz gereken ilginç bir şey, **XPC'nin soyutlamasının bire bir bağlantı** olmasıdır, ancak bu, **birden fazla göndericiye sahip olabilen** bir teknoloji üzerine kuruludur, bu nedenle:

- Mach portları tek alıcı, **çoklu gönderici**.
- Bir XPC bağlantısının denetim belirteci, **en son alınan mesajdan kopyalanan** denetim belirtecidir.
- Bir XPC bağlantısının **denetim belirtecini** elde etmek, birçok **güvenlik kontrolü** için kritik öneme sahiptir.

Önceki durum umut verici görünse de, bunun sorun yaratmayacağı bazı senaryolar vardır ([buradan](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Denetim belirteçleri genellikle bir bağlantıyı kabul edip etmeyeceğine karar vermek için bir yetkilendirme kontrolü için kullanılır. Bu, hizmet portuna bir mesaj gönderilerek gerçekleştiğinden, **henüz bir bağlantı kurulmamıştır**. Bu port üzerindeki daha fazla mesaj, yalnızca ek bağlantı talepleri olarak işlenecektir. Bu nedenle, bir bağlantıyı kabul etmeden önceki **kontroller savunmasız değildir** (bu, `-listener:shouldAcceptNewConnection:` içinde denetim belirtecinin güvenli olduğu anlamına gelir). Bu nedenle, **belirli eylemleri doğrulayan XPC bağlantılarını arıyoruz**.
- XPC olay işleyicileri senkronize bir şekilde işlenir. Bu, bir mesaj için olay işleyicisinin, bir sonraki mesaj için çağrılmadan önce tamamlanması gerektiği anlamına gelir, hatta eşzamanlı dağıtım kuyruklarında bile. Bu nedenle, bir **XPC olay işleyicisinde denetim belirteci diğer normal (yanıt vermeyen!) mesajlar tarafından üzerine yazılamaz**.

İki farklı yöntem bu durumdan yararlanılabilir:

1. Variant1:
- **Sömürü** **A** hizmetine ve **B** hizmetine **bağlanır**
- **B** hizmeti, kullanıcının yapamayacağı **ayrılmış bir işlevselliği** A hizmetinde çağırabilir
- **A** hizmeti, bir **`dispatch_async`** içinde **bağlantı** için **olay işleyicisi** içinde _**değil**_ iken **`xpc_connection_get_audit_token`** çağrısı yapar.
- Böylece, **farklı** bir mesaj **Denetim Belirtecini** **üzerine yazabilir** çünkü olay işleyicisi dışında asenkron olarak dağıtılmaktadır.
- Sömürü, **A** hizmetine **gönderme** hakkını **B** hizmetine verir.
- Böylece **B** hizmeti aslında **A** hizmetine **mesajlar** **gönderiyor**.
- **Sömürü**, **ayrılmış eylemi** **çağırmaya** çalışır. Bir RC'de **A** hizmeti bu **eylemin** yetkilendirmesini **kontrol ederken**, **B** hizmeti Denetim belirtecini **üzerine yazmıştır** (sömürüye ayrılmış eylemi çağırma erişimi verir).
2. Variant 2:
- **B** hizmeti, kullanıcının yapamayacağı **ayrılmış bir işlevselliği** A hizmetinde çağırabilir
- Sömürü, **A** hizmeti ile bağlantı kurar ve **yanıt bekleyen** bir **mesaj** gönderir, belirli bir **yanıt** **portuna**.
- Sömürü, **B** hizmetine **o yanıt portunu** geçerek bir mesaj gönderir.
- **B** hizmeti **yanıt verdiğinde**, **A** hizmetine mesaj gönderir, **bu sırada** **sömürü** farklı bir **mesajı A hizmetine** gönderir ve **ayrılmış bir işlevselliğe** ulaşmaya çalışır ve **B**'den gelen yanıtın Denetim belirtecini mükemmel bir anda (Race Condition) üzerine yazmasını bekler.

## Variant 1: xpc_connection_get_audit_token'ı bir olay işleyicisi dışında çağırma <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Senaryo:

- Bağlanabileceğimiz iki mach hizmeti **`A`** ve **`B`** (sandbox profiline ve bağlantıyı kabul etmeden önceki yetkilendirme kontrollerine dayanarak).
- _**A**_ belirli bir eylem için bir **yetkilendirme kontrolüne** sahip olmalıdır ki **`B`** bunu geçebilir (ancak uygulamamız geçemez).
- Örneğin, eğer B bazı **yetkiler** varsa veya **root** olarak çalışıyorsa, A'dan ayrılmış bir eylemi gerçekleştirmesini istemesine izin verebilir.
- Bu yetkilendirme kontrolü için, **`A`** denetim belirtecini asenkron olarak elde eder, örneğin `dispatch_async`'dan **`xpc_connection_get_audit_token`** çağrısı yaparak.

> [!CAUTION]
> Bu durumda bir saldırgan, **A'dan bir eylem gerçekleştirmesini istemek** için **sömürü** tetikleyebilir ve **B'nin `A`'ya mesajlar göndermesini** sağlarken birkaç kez yapabilir. RC **başarılı olduğunda**, **B**'nin **denetim belirteci** bellekte kopyalanacak **ve** **sömürümüzün** isteği **A** tarafından **işlenirken** gerçekleşecektir, bu da **yalnızca B'nin talep edebileceği ayrıcalıklı eyleme erişim sağlar**.

Bu, **`A`** olarak `smd` ve **`B`** olarak `diagnosticd` ile gerçekleşti. [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) fonksiyonu, yeni bir ayrıcalıklı yardımcı araç yüklemek için kullanılabilir ( **root** olarak). Eğer **root olarak çalışan bir süreç** **smd** ile iletişime geçerse, başka kontroller yapılmayacaktır.

Bu nedenle, **B** hizmeti **`diagnosticd`**'dir çünkü **root** olarak çalışır ve bir süreci **izlemek** için kullanılabilir, bu nedenle izleme başladıktan sonra, **saniyede birden fazla mesaj gönderir.**

Saldırıyı gerçekleştirmek için:

1. Standart XPC protokolünü kullanarak `smd` adlı hizmete bir **bağlantı** başlatın.
2. `diagnosticd`'ye ikincil bir **bağlantı** oluşturun. Normal prosedürün aksine, iki yeni mach portu oluşturup göndermek yerine, istemci portu gönderme hakkı, `smd` bağlantısıyla ilişkili **gönderme hakkının** bir kopyasıyla değiştirilir.
3. Sonuç olarak, XPC mesajları `diagnosticd`'ye dağıtılabilir, ancak `diagnosticd`'en gelen yanıtlar `smd`'ye yönlendirilir. `smd` için, hem kullanıcıdan hem de `diagnosticd`'den gelen mesajların aynı bağlantıdan geldiği izlenimi vardır.

![Sömürü sürecini gösteren bir resim](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Bir sonraki adım, `diagnosticd`'ye seçilen bir süreci (potansiyel olarak kullanıcının kendi süreci) izlemeye başlatmaktır. Aynı anda, `smd`'ye rutin 1004 mesajlarının bir seli gönderilir. Buradaki amaç, yükseltilmiş ayrıcalıklara sahip bir aracı yüklemektir.
5. Bu eylem, `handle_bless` fonksiyonu içinde bir yarış koşulunu tetikler. Zamanlama kritik öneme sahiptir: `xpc_connection_get_pid` fonksiyonu, kullanıcının sürecinin PID'sini döndürmelidir (çünkü ayrıcalıklı araç kullanıcının uygulama paketinde bulunur). Ancak, `xpc_connection_get_audit_token` fonksiyonu, özellikle `connection_is_authorized` alt rutininde, `diagnosticd`'ye ait denetim belirtecini referans almalıdır.

## Variant 2: yanıt yönlendirme

Bir XPC (Çapraz Süreç İletişimi) ortamında, olay işleyicileri eşzamanlı olarak çalışmasa da, yanıt mesajlarının işlenmesi benzersiz bir davranış sergiler. Özellikle, yanıt bekleyen mesajlar göndermek için iki farklı yöntem vardır:

1. **`xpc_connection_send_message_with_reply`**: Burada, XPC mesajı belirli bir kuyrukta alınır ve işlenir.
2. **`xpc_connection_send_message_with_reply_sync`**: Tersine, bu yöntemde XPC mesajı mevcut dağıtım kuyruğunda alınır ve işlenir.

Bu ayrım, **yanıt paketlerinin bir XPC olay işleyicisinin yürütülmesiyle eşzamanlı olarak ayrıştırılma olasılığını** sağlar. Özellikle, `_xpc_connection_set_creds` denetim belirtecinin kısmi olarak üzerine yazılmasını önlemek için kilitleme uygulasa da, bu korumayı tüm bağlantı nesnesine genişletmez. Sonuç olarak, bu, bir paket ayrıştırma ile olay işleyicisinin yürütülmesi arasındaki aralıkta denetim belirtecinin değiştirilmesine olanak tanıyan bir zayıflık yaratır.

Bu zayıflıktan yararlanmak için aşağıdaki kurulum gereklidir:

- **`A`** ve **`B`** olarak adlandırılan iki mach hizmeti, her ikisi de bir bağlantı kurabilir.
- **`A`** hizmetinin, yalnızca **`B`**'nin gerçekleştirebileceği belirli bir eylem için bir yetkilendirme kontrolü içermesi gerekir (kullanıcının uygulaması bunu yapamaz).
- **`A`** hizmetinin, bir yanıt bekleyen bir mesaj göndermesi gerekir.
- Kullanıcı, **`B`**'ye yanıt vereceği bir mesaj gönderebilir.

Sömürü süreci aşağıdaki adımları içerir:

1. **`A`** hizmetinin yanıt bekleyen bir mesaj göndermesini bekleyin.
2. **`A`**'ya doğrudan yanıt vermek yerine, yanıt portu ele geçirilir ve **`B`** hizmetine bir mesaj göndermek için kullanılır.
3. Ardından, yasaklı eylemi içeren bir mesaj gönderilir ve bunun **`B`**'den gelen yanıtla eşzamanlı olarak işleneceği beklenir.

Aşağıda, tanımlanan saldırı senaryosunun görsel bir temsili bulunmaktadır:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Keşif Problemleri

- **Örnekleri Bulma Zorlukları**: `xpc_connection_get_audit_token` kullanım örneklerini bulmak, hem statik hem de dinamik olarak zordu.
- **Metodoloji**: Frida, `xpc_connection_get_audit_token` fonksiyonunu yakalamak için kullanıldı ve olay işleyicilerinden gelmeyen çağrıları filtreledi. Ancak, bu yöntem yalnızca yakalanan süreçle sınırlıydı ve aktif kullanım gerektiriyordu.
- **Analiz Araçları**: Ulaşılabilir mach hizmetlerini incelemek için IDA/Ghidra gibi araçlar kullanıldı, ancak süreç zaman alıcıydı ve dyld paylaşılan önbelleği ile ilgili çağrılarla karmaşık hale geldi.
- **Betik Sınırlamaları**: `dispatch_async` bloklarından `xpc_connection_get_audit_token` çağrılarını analiz etmek için betik yazma girişimleri, blokların ayrıştırılması ve dyld paylaşılan önbelleği ile etkileşimdeki karmaşıklıklar nedeniyle engellendi.

## Çözüm <a href="#the-fix" id="the-fix"></a>

- **Rapor Edilen Sorunlar**: `smd` içinde bulunan genel ve özel sorunları detaylandıran bir rapor Apple'a gönderildi.
- **Apple'ın Yanıtı**: Apple, `smd` içindeki sorunu `xpc_connection_get_audit_token`'ı `xpc_dictionary_get_audit_token` ile değiştirerek ele aldı.
- **Çözümün Doğası**: `xpc_dictionary_get_audit_token` fonksiyonu, alınan XPC mesajına bağlı mach mesajından doğrudan denetim belirtecini elde ettiği için güvenli kabul edilir. Ancak, `xpc_connection_get_audit_token` gibi kamu API'sinin bir parçası değildir.
- **Daha Kapsamlı Bir Çözümün Yokluğu**: Apple'ın, bağlantının kaydedilen denetim belirteciyle uyumlu olmayan mesajları atma gibi daha kapsamlı bir çözüm uygulamadığı neden belirsizdir. Belirli senaryolarda (örneğin, `setuid` kullanımı) meşru denetim belirteci değişikliklerinin olabileceği ihtimali bir faktör olabilir.
- **Mevcut Durum**: Sorun, iOS 17 ve macOS 14'te devam etmekte olup, bunu tanımlamaya ve anlamaya çalışanlar için bir zorluk teşkil etmektedir.

{{#include ../../../../../../banners/hacktricks-training.md}}
