# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Daha fazla bilgi için original post'u inceleyin:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Bu bir özettir:

## Mach Messages Basic Info

Mach Messages'ın ne olduğunu bilmiyorsanız şu sayfayı incelemeye başlayın:


{{#ref}}
../../
{{#endref}}

Şimdilik şunu hatırlayın ([buradaki tanımdan](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages, mach kernel içine yerleşik, **tek alıcı, birden fazla gönderici iletişim** kanalı olan bir _mach port_ üzerinden gönderilir. **Birden fazla process bir mach port'a message gönderebilir**, ancak herhangi bir anda **yalnızca tek bir process buradan okuyabilir**. File descriptor'lar ve socket'ler gibi mach port'lar da kernel tarafından ayrılır ve yönetilir; process'ler yalnızca bir integer görür ve bunu kernel'e hangi mach port'larını kullanmak istediklerini belirtmek için kullanabilir.

## XPC Connection

Bir XPC connection'ın nasıl kurulduğunu bilmiyorsanız şurayı inceleyin:


{{#ref}}
../
{{#endref}}

## Vuln Summary

Bilmeniz gereken ilginç nokta, **XPC abstraction'ının bire bir connection olmasıdır**, ancak birden fazla göndericiye sahip olabilen bir teknoloji üzerine kuruludur, yani:

- Mach port'lar tek alıcılı, **birden fazla göndericilidir**.
- Bir XPC connection'ın audit token'ı, **en son alınan message'dan kopyalanan audit token'dır**.
- Bir XPC connection'ın **audit token'ını** elde etmek, birçok **security check** için kritiktir.<sup>[[1]](#references)</sup>

Önceki durum umut verici görünse de bunun sorun oluşturmayacağı bazı senaryolar vardır ([buradan](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit token'lar genellikle bir connection'ı kabul edip etmeyeceğine karar vermek için bir authorization check'te kullanılır. Bu işlem service port'a gönderilen bir message kullanılarak gerçekleştiğinden henüz **connection kurulmamıştır**. Bu port üzerindeki diğer message'lar yalnızca ek connection request'leri olarak işlenir. Bu nedenle **connection kabul edilmeden önceki check'ler vulnerable değildir** (bu aynı zamanda `-listener:shouldAcceptNewConnection:` içinde audit token'ın güvenli olduğu anlamına gelir). Bu yüzden **specific action'ları doğrulayan XPC connection'ları** arıyoruz.
- XPC event handler'ları synchronous olarak işlenir. Bu, concurrent dispatch queue'larında bile bir message'ın event handler'ının tamamlanması gerektiği, ardından sıradaki message için çağrılabileceği anlamına gelir. Dolayısıyla bir **XPC event handler içinde audit token**, diğer normal (reply olmayan!) message'lar tarafından **overwrite edilemez**.<sup>[[1]](#references)</sup>

Bunun exploit edilebileceği iki farklı yöntem vardır:

1. Variant1:
- **Exploit**, **A** ve **B** service'lerine **connect** olur.
- **Service B**, service A'da kullanıcının çağramadığı bir **privileged functionality** çağırabilir.
- **Service A**, bir **`dispatch_async`** içinde bir connection'ın **event handler'ı dışında** çalışırken **`xpc_connection_get_audit_token`** çağırır.
- Böylece **farklı bir message**, event handler dışında asynchronous olarak dispatch edildiği için **Audit Token'ı overwrite edebilir**.
- Exploit, **service A'nın SEND right'ını service B'ye** geçirir.
- Böylece svc **B**, message'ları **service A'ya gönderen** taraf olur.
- **Exploit**, **privileged action'ı çağırmayı** dener. Bir RC'de svc **A**, **svc B Audit token'ı overwrite etmişken** bu action'ın authorization'ını **check eder** (bu da exploit'e privileged action'ı çağırma erişimi verir).
2. Variant 2:
- Service **B**, service A'da kullanıcının çağramadığı bir **privileged functionality** çağırabilir.
- Exploit, **service A** ile connect olur; service A, exploit'e belirli bir **reply** port'unda yanıt bekleyen bir **message** gönderir.
- Exploit, **bu reply port'unu** geçirerek **service B'ye** bir message gönderir.
- Service **B** yanıt verdiğinde message'ı **service A'ya gönderir**; bu sırada **exploit**, privileged functionality'ye ulaşmaya çalışarak service A'ya farklı bir **message** gönderir ve service B'den gelen reply'ın doğru anda Audit token'ı overwrite etmesini bekler (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Senaryo:

- Sandbox profile ve connection kabul edilmeden önceki authorization check'lere göre her ikisine de connect olabildiğimiz iki mach service, **`A`** ve **`B`**.
- _**A**_, **`B`**'nin geçebildiği (ancak bizim app'imizin geçemediği) specific action için bir **authorization check** içermelidir.
- Örneğin B'de bazı **entitlement'lar** varsa veya root olarak çalışıyorsa, A'dan privileged action gerçekleştirmesini istemesine izin verilebilir.
- Bu authorization check için **`A`**, audit token'ı asynchronous olarak almalıdır; örneğin `dispatch_async` içinden `xpc_connection_get_audit_token` çağırarak.

> [!CAUTION]
> Bu durumda bir attacker, bir **Race Condition** tetikleyerek **A'dan bir action gerçekleştirmesini isteyen** bir **exploit**'i birkaç kez çalıştırırken **B'nin `A`'ya message göndermesini** sağlayabilir. RC **başarılı olduğunda**, **B**'nin **audit token'ı**, **exploit**'imizin request'i A tarafından **işlenirken** memory'ye kopyalanır; böylece exploit, yalnızca B'nin isteyebileceği privileged action'a erişim kazanır.

Bu durum **`A`** olarak `smd` ve **`B`** olarak `diagnosticd` ile gerçekleşti. [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) function'ı, yeni bir privileged helper tool'u ( **root** olarak) yüklemek için kullanılabilir. **Root olarak çalışan bir process `smd` ile contact kurarsa**, başka hiçbir check gerçekleştirilmez.

Bu nedenle **B service'i** **`diagnosticd`**'dir; çünkü root olarak çalışır ve bir process'i **monitor** etmek için kullanılabilir. Monitoring başladıktan sonra saniyede **birden fazla message gönderir.**

Attack'i gerçekleştirmek için:

1. Standart XPC protocol'ünü kullanarak `smd` adlı service'e bir **connection** başlatın.
2. `diagnosticd`'ye secondary bir **connection** oluşturun. Normal prosedürün aksine, iki yeni mach port oluşturup göndermek yerine client port send right'ı, `smd` connection'ıyla ilişkilendirilmiş **send right'ın** duplicate'i ile değiştirin.
3. Sonuç olarak XPC message'ları `diagnosticd`'ye dispatch edilebilir, ancak `diagnosticd`'den gelen response'lar `smd`'ye yönlendirilir. `smd` açısından hem user'dan hem de `diagnosticd`'den gelen message'lar aynı connection'dan geliyormuş gibi görünür.

![Exploit sürecini gösteren görsel](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Sonraki adım, `diagnosticd`'ye seçilen bir process'i (potansiyel olarak kullanıcının kendi process'ini) monitor etmeye başlamasını söylemektir. Aynı anda `smd`'ye rutin 1004 message'larından oluşan bir flood gönderilir. Buradaki amaç elevated privileges ile bir tool yüklemektir.
5. Bu action, `handle_bless` function'ı içinde bir race condition tetikler. Zamanlama kritiktir: `xpc_connection_get_pid` function call'u user process'inin PID'sini döndürmelidir (çünkü privileged tool, user app bundle'ında bulunur). Ancak özellikle `connection_is_authorized` subroutine'i içindeki `xpc_connection_get_audit_token` function'ı `diagnosticd`'ye ait audit token'a referans vermelidir.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

Bir XPC (Cross-Process Communication) ortamında event handler'lar concurrent olarak çalışmasa da reply message'larının işlenmesi kendine özgü bir davranışa sahiptir. Özellikle reply bekleyen message'ları göndermek için iki farklı yöntem vardır:

1. **`xpc_connection_send_message_with_reply`**: Burada XPC message, belirlenmiş bir queue üzerinde alınır ve işlenir.
2. **`xpc_connection_send_message_with_reply_sync`**: Buna karşılık bu yöntemde XPC message, mevcut dispatch queue üzerinde alınır ve işlenir.

Bu ayrım önemlidir; çünkü **reply packet'larının bir XPC event handler'ın çalışmasıyla concurrent olarak parse edilmesi** olasılığını sağlar. `_xpc_connection_set_creds`, audit token'ın partial overwrite edilmesini önlemek için locking uygulasa da bu korumayı tüm connection object'ine genişletmez. Sonuç olarak packet'ın parse edilmesi ile event handler'ının çalıştırılması arasındaki aralıkta audit token'ın değiştirilebildiği bir vulnerability oluşur.

Bu vulnerability'yi exploit etmek için aşağıdaki setup gereklidir:

- Her ikisi de connection kurabilen, **`A`** ve **`B`** olarak adlandırılan iki mach service.
- **Service `A`**, yalnızca **`B`**'nin gerçekleştirebildiği (user application'ın gerçekleştiremediği) specific action için bir authorization check içermelidir.
- **Service `A`**, bir reply bekleyen bir message göndermelidir.
- User, yanıt verecek olan **`B`**'ye bir message gönderebilmelidir.

Exploitation süreci şu adımları içerir:

1. Service **`A`**'nın reply bekleyen bir message göndermesini bekleyin.
2. Doğrudan **`A`**'ya yanıt vermek yerine reply port'u ele geçirilir ve service **`B`**'ye bir message göndermek için kullanılır.
3. Ardından forbidden action'ı içeren bir message dispatch edilir; bunun **`B`**'den gelen reply ile concurrent olarak işlenmesi beklenir.<sup>[[1]](#references)</sup>

Aşağıda açıklanan attack senaryosunun görsel bir gösterimi bulunmaktadır:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Instance'ları Bulmadaki Zorluklar**: `xpc_connection_get_audit_token` kullanım instance'larını hem static hem de dynamic olarak aramak zordu.
- **Methodology**: `xpc_connection_get_audit_token` function'ını hook'lamak ve event handler'lardan kaynaklanmayan call'ları filtrelemek için Frida kullanıldı. Ancak bu yöntem hook'lanan process ile sınırlıydı ve active kullanım gerektiriyordu.
- **Analysis Tooling**: Ulaşılabilir mach service'leri incelemek için IDA/Ghidra gibi tool'lar kullanıldı, ancak süreç zaman alıyordu; ayrıca dyld shared cache ile ilgili call'lar nedeniyle karmaşıktı.
- **Scripting Limitations**: `dispatch_async` block'larından gelen `xpc_connection_get_audit_token` call'ları için analysis'i script'leme girişimleri, block'ların parse edilmesi ve dyld shared cache ile etkileşimlerdeki karmaşıklıklar nedeniyle engellendi.<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: `smd` içinde bulunan genel ve specific sorunlar Apple'a bildirildi.
- **Apple's Response**: Apple, `xpc_connection_get_audit_token` yerine `xpc_dictionary_get_audit_token` kullanarak `smd` içindeki sorunu giderdi.<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` function'ı, audit token'ı alınan XPC message'a bağlı mach message'dan doğrudan aldığı için secure kabul edilir. Ancak `xpc_connection_get_audit_token` gibi public API'nin bir parçası değildir.
- **Absence of a Broader Fix**: Apple'ın, connection'ın kaydedilmiş audit token'ı ile eşleşmeyen message'ları discard etmek gibi daha kapsamlı bir fix uygulamamasının nedeni belirsizliğini koruyor. Bazı senaryolarda (örneğin `setuid` kullanımı) audit token'ların legitimate şekilde değişebilmesi bir etken olabilir.
- **Current Status**: Sorun iOS 17 ve macOS 14'te devam etmektedir; bu durum onu tespit edip anlamaya çalışanlar için zorluk oluşturmaktadır.<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

Bu bug class için XPC service'lerini audit ederken authorization'ın message'ın event handler'ı dışında veya reply processing sırasında concurrent olarak gerçekleştirilmesine odaklanın.

Static triage ipuçları:
- `dispatch_async`/`dispatch_after` veya event handler dışında çalışan diğer worker queue'ları üzerinden queue edilen block'lar tarafından erişilebilen `xpc_connection_get_audit_token` call'larını arayın.
- Per-connection ve per-message state'i birleştiren authorization helper'larını bulun (örneğin PID'yi `xpc_connection_get_pid` ile, audit token'ı ise `xpc_connection_get_audit_token` ile almak).
- NSXPC code'unda check'lerin `-listener:shouldAcceptNewConnection:` içinde yapıldığını veya per-message check'ler için implementation'ın per-message audit token kullandığını doğrulayın (örneğin lower-level code'da message'ın dictionary'si üzerinden `xpc_dictionary_get_audit_token` kullanılması).

Dynamic triage ipuçları:
- `xpc_connection_get_audit_token`'ı hook'layın ve user stack'inde event-delivery path bulunmayan invocation'ları işaretleyin (örneğin `_xpc_connection_mach_event`). Örnek Frida hook'u:
```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
onEnter(args) {
const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join('\n');
if (!bt.includes('_xpc_connection_mach_event')) {
console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
}
}
});
```
Notlar:
- macOS'ta protected/Apple binary'lerini instrument etmek SIP'in devre dışı bırakılmasını veya bir development environment kullanılmasını gerektirebilir; kendi build'lerinizi ya da userland servislerini test etmeyi tercih edin.
- Reply-forwarding races (Variant 2) için, `xpc_connection_send_message_with_reply` ile normal isteklerin zamanlamalarını fuzzing yaparak reply packet'lerinin eşzamanlı ayrıştırılmasını izleyin ve authorization sırasında kullanılan effective audit token'ın etkilenip etkilenemediğini kontrol edin.

## Muhtemelen ihtiyaç duyacağınız exploitation primitives

- Multi-sender setup (Variant 1): A ve B'ye bağlantılar oluşturun; A'nın client port'una ait send right'ı duplicate edin ve B'nin client port'u olarak kullanın; böylece B'nin reply'ları A'ya teslim edilir.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A’nın bekleyen isteğinden (reply port) send-once right’ı ele geçirin, ardından bu reply port’u kullanarak B’ye hazırlanmış bir mesaj gönderin; böylece privileged isteğiniz ayrıştırılırken B’nin yanıtı A’ya ulaşır.

Bunlar, XPC bootstrap ve mesaj formatları için düşük seviyeli mach mesajı oluşturmayı gerektirir; kesin packet düzenlerini ve flag’leri görmek için bu bölümdeki mach/XPC primer sayfalarını inceleyin.

## Kullanışlı araçlar

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer), bağlantıları listelemeye ve multi-sender kurulumları ile zamanlamayı doğrulamak için trafiği gözlemlemeye yardımcı olabilir. Örnek: `gxpc -p <PID> --whitelist <service-name>`.
- libxpc için klasik dyld interposing: black-box testing sırasında çağrı noktalarını ve stack’leri loglamak amacıyla `xpc_connection_send_message*` ve `xpc_connection_get_audit_token` üzerinde interpose uygulayın.



## Referanslar

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
