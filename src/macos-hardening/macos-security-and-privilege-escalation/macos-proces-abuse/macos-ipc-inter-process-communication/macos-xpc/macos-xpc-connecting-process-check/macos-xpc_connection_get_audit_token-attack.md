# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Daha fazla bilgi için orijinal gönderiyi inceleyin:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Bu bir özettir:<sup>[[1]](#references)</sup>

## Mach Messages Temel Bilgileri

Mach Messages'ın ne olduğunu bilmiyorsanız şu sayfayı incelemeye başlayın:


{{#ref}}
../../
{{#endref}}

Şimdilik şunu hatırlayın ([buradaki tanımdan](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
Mach messages, mach kernel içine yerleşik olan ve **tek alıcı, birden fazla gönderici iletişimi** sağlayan bir kanal olan _mach port_ üzerinden gönderilir. **Birden fazla process mach port'a mesaj gönderebilir**, ancak herhangi bir anda **yalnızca tek bir process bu mesajları okuyabilir**. File descriptor'lar ve socket'ler gibi mach port'lar da kernel tarafından ayrılır ve yönetilir; process'ler yalnızca bir integer görür ve bunu, hangi mach port'larını kullanmak istediklerini kernel'e belirtmek için kullanabilir.

## XPC Connection

Bir XPC connection'ın nasıl kurulduğunu bilmiyorsanız şurayı inceleyin:


{{#ref}}
../
{{#endref}}

## Vuln Summary

Bilmeniz gereken ilginç nokta, **XPC abstraction'ının bire bir connection olmasıdır**, ancak **birden fazla göndericiye sahip olabilen** bir technology üzerine kuruludur, yani:

- Mach port'lar tek alıcılı, **birden fazla göndericilidir**.
- Bir XPC connection'ın audit token'ı, **en son alınan mesajdan kopyalanan** audit token'dır.
- Bir XPC connection'ın **audit token'ını** elde etmek, birçok **security check** için kritiktir.<sup>[[1]](#references)</sup>

Önceki durum umut verici görünse de bunun sorun oluşturmayacağı bazı senaryolar vardır ([buradan](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Audit token'lar çoğunlukla bir connection'ı kabul edip etmeyeceğine karar vermek için authorization check amacıyla kullanılır. Bu işlem service port'a gönderilen bir mesaj kullanılarak gerçekleştiğinden henüz **connection kurulmamıştır**. Bu port üzerindeki diğer mesajlar yalnızca ek connection request'leri olarak işlenir. Bu nedenle **connection kabul edilmeden önce yapılan check'ler vulnerable değildir** (bu aynı zamanda `-listener:shouldAcceptNewConnection:` içinde audit token'ın güvenli olduğu anlamına gelir). Bu yüzden **specific action'ları doğrulayan XPC connection'lar** arıyoruz.
- XPC event handler'ları synchronous olarak işlenir. Bu, concurrent dispatch queue'larda bile bir mesajın event handler'ının tamamlanmasının, bir sonraki mesaj için çağrılmadan önce gerekli olduğu anlamına gelir. Bu nedenle bir **XPC event handler içinde audit token, diğer normal (reply olmayan!) mesajlar tarafından üzerine yazılamaz**.<sup>[[1]](#references)</sup>

Bunun exploit edilebileceği iki farklı yöntem vardır:

1. Variant1:
- **Exploit**, service **A** ve service **B**'ye **connect** olur.
- Service **B**, service A'da kullanıcının çağramadığı bir **privileged functionality** çağırabilir.
- Service **A**, bir **`dispatch_async`** içinde connection'ın **event handler**'ında **değilken** **`xpc_connection_get_audit_token`** çağırır.
- Böylece **farklı bir mesaj**, event handler dışında asynchronous olarak dispatch edildiği için **Audit Token'ın üzerine yazabilir**.
- Exploit, **service B'ye service A'nın SEND right'ını** geçirir.
- Böylece svc **B**, mesajları service **A**'ya **aslında kendisi gönderir**.
- **Exploit**, **privileged action'ı çağırmayı** dener. Bir RC'de svc **A**, **svc B Audit token'ın üzerine yazarken** bu **action** için authorization'ı **check eder** (bu da exploit'e privileged action'ı çağırma erişimi sağlar).
2. Variant 2:
- Service **B**, service A'da kullanıcının çağıramadığı bir **privileged functionality** çağırabilir.
- Exploit, kendisine belirli bir **reply** port'unda response bekleyen bir mesaj gönderen **service A**'ya connect olur.
- Exploit, **bu reply port'unu** içeren bir mesajı service **B**'ye gönderir.
- Service **B** reply verdiğinde, mesajı service A'ya **gönderir**; bu sırada **exploit**, service A'ya privileged functionality'ye ulaşmaya çalışan farklı bir **mesajı**, service B'den gelen reply'ın doğru anda Audit token'ın üzerine yazacağı beklentisiyle gönderir (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Senaryo:

- Sandbox profile ve connection kabul edilmeden önceki authorization check'lerine dayanarak ikisine de connect olabildiğimiz iki mach service, **`A`** ve **`B`**.
- _**A**_, **`B`**'nin geçebileceği (ancak bizim app'imizin geçemeyeceği) belirli bir action için bir **authorization check** içermelidir.
- Örneğin B'nin bazı **entitlement**'ları varsa veya root olarak çalışıyorsa, A'dan privileged action gerçekleştirmesini istemesine izin verilebilir.
- Bu authorization check için **`A`**, audit token'ı asynchronous olarak elde eder; örneğin `dispatch_async` içinden `xpc_connection_get_audit_token` çağırarak.

> [!CAUTION]
> Bu durumda bir attacker, **A'dan bir action gerçekleştirmesini isteyen** bir **exploit**'i birkaç kez çalıştırırken aynı anda **B'nin `A`'ya mesajlar göndermesini** sağlayarak bir **Race Condition** tetikleyebilir. RC **başarılı olduğunda**, **B**'nin **audit token'ı**, **exploit** request'i A tarafından işlenirken belleğe kopyalanır ve exploit'e yalnızca B'nin isteyebileceği privileged action'a erişim sağlar.

Bu durum **`A`** olarak `smd` ve **`B`** olarak `diagnosticd` kullanıldığında gerçekleşti. smb'den yeni bir privileged helper toot'u (root olarak) yüklemek için [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) function'ı kullanılabilir. **Root olarak çalışan bir process** **smd ile iletişim kurarsa**, başka hiçbir check gerçekleştirilmez.

Bu nedenle service **B**, root olarak çalıştığı ve bir process'i **monitor** etmek için kullanılabildiği için **`diagnosticd`**'dir; monitoring başladıktan sonra saniyede **birden fazla mesaj** gönderir.

Attack'i gerçekleştirmek için:

1. Standart XPC protocol'ünü kullanarak `smd` adlı service'e bir **connection** başlatın.
2. `diagnosticd`'ye secondary bir **connection** oluşturun. Normal prosedürün aksine, iki yeni mach port oluşturup göndermek yerine client port send right'ı, `smd` connection'ıyla ilişkili **send right**'ın duplicate'i ile değiştirin.
3. Bunun sonucunda XPC mesajları `diagnosticd`'ye dispatch edilebilir, ancak `diagnosticd`'den gelen response'lar `smd`'ye yönlendirilir. `smd` açısından hem user'dan hem de `diagnosticd`'den gelen mesajlar aynı connection'dan geliyormuş gibi görünür.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Sonraki adım, `diagnosticd`'ye seçilen bir process'i (potansiyel olarak kullanıcının kendi process'ini) monitor etmeye başlamasını söylemektir. Aynı anda `smd`'ye rutin 1004 mesajlarından oluşan bir flood gönderilir. Amaç elevated privileges'a sahip bir tool yüklemektir.
5. Bu action, `handle_bless` function'ı içinde bir race condition tetikler. Zamanlama kritiktir: `xpc_connection_get_pid` function call'u kullanıcının process'inin PID'sini döndürmelidir (çünkü privileged tool kullanıcının app bundle'ında bulunur). Ancak `connection_is_authorized` subroutine'i içindeki `xpc_connection_get_audit_token` function'ı `diagnosticd`'ye ait audit token'a başvurmalıdır.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

Bir XPC (Cross-Process Communication) ortamında event handler'lar concurrent olarak çalışmasa da reply mesajlarının işlenmesinde kendine özgü bir davranış vardır. Özellikle reply bekleyen mesajları göndermek için iki farklı yöntem bulunur:

1. **`xpc_connection_send_message_with_reply`**: Burada XPC mesajı belirlenmiş bir queue üzerinde alınır ve işlenir.
2. **`xpc_connection_send_message_with_reply_sync`**: Buna karşılık bu yöntemde XPC mesajı mevcut dispatch queue üzerinde alınır ve işlenir.

Bu ayrım önemlidir; çünkü **reply packet'larının bir XPC event handler'ın çalışmasıyla concurrent olarak parse edilmesine** olanak sağlar. `_xpc_connection_set_creds`, audit token'ın kısmen üzerine yazılmasını önlemek için locking uygulasa da bu korumayı connection object'in tamamına genişletmez. Sonuç olarak packet'ın parse edilmesi ile event handler'ının çalıştırılması arasındaki aralıkta audit token'ın değiştirilebildiği bir vulnerability oluşur.

Bu vulnerability'yi exploit etmek için aşağıdaki kurulum gereklidir:

- İkisinin de connection kurabildiği, **`A`** ve **`B`** olarak adlandırılan iki mach service.
- Service **`A`**, yalnızca **`B`**'nin gerçekleştirebildiği (user application'ın gerçekleştiremediği) belirli bir action için bir authorization check içermelidir.
- Service **`A`**, bir reply bekleyen mesaj göndermelidir.
- User, **`B`**'ye gönderdiği bir mesaja karşılık response vermesini sağlayabilmelidir.

Exploitation süreci şu adımları içerir:

1. Service **`A`**'nın reply bekleyen bir mesaj göndermesini bekleyin.
2. Doğrudan **`A`**'ya reply vermek yerine reply port ele geçirilir ve service **`B`**'ye mesaj göndermek için kullanılır.
3. Ardından forbidden action'ı içeren bir mesaj dispatch edilir ve bunun **`B`**'nin reply'ı ile concurrent olarak işlenmesi beklenir.<sup>[[1]](#references)</sup>

Aşağıda açıklanan attack senaryosunun görsel bir gösterimi bulunmaktadır:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Instance'ları Bulmadaki Zorluklar**: `xpc_connection_get_audit_token` kullanım instance'larını aramak hem statik hem de dynamic olarak zordu.
- **Methodology**: Frida, `xpc_connection_get_audit_token` function'ını hook'lamak ve event handler'larından kaynaklanmayan call'ları filtrelemek için kullanıldı. Ancak bu yöntem hook'lanan process ile sınırlıydı ve aktif kullanım gerektiriyordu.
- **Analysis Tooling**: IDA/Ghidra gibi tool'lar erişilebilir mach service'leri incelemek için kullanıldı; ancak süreç zaman alıyordu ve dyld shared cache ile ilişkili call'lar nedeniyle karmaşıklaşıyordu.
- **Scripting Limitations**: `dispatch_async` block'larından `xpc_connection_get_audit_token` call'ları için analysis'i script'leme girişimleri, block'ları ve dyld shared cache ile etkileşimleri parse etmenin karmaşıklığı nedeniyle engellendi.<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: Apple'a, `smd` içinde bulunan genel ve specific issue'ları açıklayan bir report gönderildi.
- **Apple's Response**: Apple, `xpc_connection_get_audit_token` yerine `xpc_dictionary_get_audit_token` koyarak `smd` içindeki issue'yu giderdi.<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` function'ı, audit token'ı alınan XPC mesajıyla ilişkili mach message'dan doğrudan aldığı için secure kabul edilir. Ancak `xpc_connection_get_audit_token` gibi public API'nin bir parçası değildir.
- **Absence of a Broader Fix**: Connection'ın kayıtlı audit token'ıyla eşleşmeyen mesajların discard edilmesi gibi daha kapsamlı bir fix'in Apple tarafından neden uygulanmadığı belirsizliğini korumaktadır. Bazı senaryolarda (örneğin `setuid` kullanımı) legitimate audit token değişikliklerinin mümkün olması bir etken olabilir.
- **Current Status**: Issue iOS 17 ve macOS 14'te devam etmekte ve bunu tespit edip anlamaya çalışanlar için zorluk oluşturmaktadır.<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

XPC service'lerini bu bug class açısından audit ederken, message'ın event handler'ı dışında veya reply processing sırasında concurrent olarak gerçekleştirilen authorization işlemlerine odaklanın.

Static triage ipuçları:
- `dispatch_async`/`dispatch_after` veya message handler dışında çalışan diğer worker queue'lar üzerinden queue edilen block'lara erişilebilen `xpc_connection_get_audit_token` call'larını arayın.
- Per-connection ve per-message state'i birleştiren authorization helper'larını arayın (örneğin PID'yi `xpc_connection_get_pid` ile, audit token'ı ise `xpc_connection_get_audit_token` ile alma).
- NSXPC code içinde check'lerin `-listener:shouldAcceptNewConnection:` içinde yapıldığını veya per-message check'leri için implementation'ın per-message audit token kullandığını doğrulayın (örneğin lower-level code'da message'ın dictionary'si üzerinden `xpc_dictionary_get_audit_token`).

Dynamic triage ipuçları:
- `xpc_connection_get_audit_token`'ı hook'layın ve user stack'i event-delivery path'i (örneğin `_xpc_connection_mach_event`) içermeyen invocation'ları işaretleyin. Örnek Frida hook:
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
- macOS'ta korunan/Apple binary'lerini instrumenting yapmak SIP'nin devre dışı bırakılmasını veya bir development environment kullanılmasını gerektirebilir; kendi build'lerinizi veya userland servislerini test etmeyi tercih edin.
- Reply-forwarding races (Variant 2) için, `xpc_connection_send_message_with_reply` ile normal request'lerin zamanlamalarını fuzzing yaparak reply packet'larının eşzamanlı parsing işlemlerini izleyin ve authorization sırasında kullanılan effective audit token'ın etkilenip etkilenemediğini kontrol edin.

## Muhtemelen ihtiyaç duyacağınız exploitation primitives

- Multi-sender setup (Variant 1): A ve B'ye connections oluşturun; A'nın client port'una ait send right'ı duplicate edin ve B'nin client port'u olarak kullanın; böylece B'nin reply'ları A'ya iletilir.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A’nın bekleyen isteğinden (reply port) send-once right’ı ele geçirin, ardından bu reply port’u kullanarak B’ye crafted bir mesaj gönderin; böylece privileged isteğiniz ayrıştırılırken B’nin yanıtı A’ya ulaşır.

Bunlar, XPC bootstrap ve mesaj formatları için düşük seviyeli mach message crafting gerektirir; kesin paket düzenlerini ve flag’leri görmek için bu bölümdeki mach/XPC primer sayfalarını inceleyin.

## Yararlı araçlar

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer), bağlantıları numaralandırmaya ve multi-sender kurulumlarını ve zamanlamayı doğrulamak üzere trafiği gözlemlemeye yardımcı olabilir. Örnek: `gxpc -p <PID> --whitelist <service-name>`.
- libxpc için Classic dyld interposing: black-box testing sırasında çağrı noktalarını ve stack’leri loglamak için `xpc_connection_send_message*` ve `xpc_connection_get_audit_token` üzerinde interpose uygulayın.



## Referanslar

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
