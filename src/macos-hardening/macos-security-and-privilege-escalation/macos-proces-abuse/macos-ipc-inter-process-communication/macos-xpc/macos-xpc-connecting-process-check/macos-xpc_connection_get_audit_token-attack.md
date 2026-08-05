# macOS xpc_connection_get_audit_token Saldırısı

{{#include ../../../../../../banners/hacktricks-training.md}}

**Daha fazla bilgi için orijinal gönderiye bakın:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Bu bir özettir:

## Mach Messages Temel Bilgileri

Mach Messages'ın ne olduğunu bilmiyorsanız şu sayfayı incelemeye başlayın:


{{#ref}}
../../
{{#endref}}

Şimdilik şunu hatırlayın ([tanım buradan](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages, mach kernel içine yerleşik **tek alıcı, birden fazla gönderici iletişim** kanalı olan bir _mach port_ üzerinden gönderilir. **Birden fazla process bir mach port'a message gönderebilir**, ancak herhangi bir anda **yalnızca tek bir process porttan okuyabilir**. File descriptor'lar ve socket'ler gibi mach port'lar kernel tarafından ayrılır ve yönetilir; process'ler yalnızca bir integer görür ve bunu hangi mach port'larını kullanmak istediklerini kernel'e belirtmek için kullanabilir.

## XPC Connection

Bir XPC connection'ın nasıl kurulduğunu bilmiyorsanız şuraya bakın:


{{#ref}}
../
{{#endref}}

## Vuln Summary

Bilmeniz gereken ilginç nokta, **XPC abstraction'ının bire bir connection olmasıdır**, ancak **birden fazla sender'a sahip olabilen bir technology üzerine kuruludur; dolayısıyla:**

- Mach port'lar tek alıcılı, **birden fazla göndericilidir**.
- Bir XPC connection'ın audit token'ı, **en son alınan message'dan kopyalanan audit token'dır**.
- Bir XPC connection'ın **audit token'ını** elde etmek, birçok **security check** için kritiktir.<sup>[1]</sup>

Önceki durum umut verici görünse de bunun sorun oluşturmayacağı bazı senaryolar vardır ([buradan](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit token'lar çoğunlukla bir connection'ı kabul edip etmeyeceğine karar vermek için authorization check amacıyla kullanılır. Bu işlem service port'a gönderilen bir message kullanılarak gerçekleştiğinden **henüz bir connection kurulmamıştır**. Bu port üzerindeki diğer message'lar yalnızca ek connection request'leri olarak işlenir. Bu nedenle **connection kabul edilmeden önceki check'ler vulnerable değildir** (bu aynı zamanda `-listener:shouldAcceptNewConnection:` içinde audit token'ın güvenli olduğu anlamına gelir). Bu yüzden **specific action'ları doğrulayan XPC connection'ları** arıyoruz.
- XPC event handler'lar synchronously olarak işlenir. Bu, concurrent dispatch queue'larında bile bir message için event handler çağrılmadan önce önceki message'ın event handler'ının tamamlanması gerektiği anlamına gelir. Dolayısıyla bir **XPC event handler içinde audit token**, diğer normal (reply olmayan!) message'lar tarafından **üzerine yazılamaz**.<sup>[1]</sup>

Bunun exploit edilebileceği iki farklı method vardır:

1. Variant1:
- **Exploit**, service **A** ve service **B**'ye **connect** olur.
- Service **B**, service A'da kullanıcının çağıramadığı **privileged functionality**'yi çağırabilir.
- Service **A**, **`dispatch_async`** içinde bir connection için **event handler** dışında çalışırken **`xpc_connection_get_audit_token`** çağırır.
- Böylece **farklı bir** message, event handler dışında asynchronously dispatch edildiği için **Audit Token'ın üzerine yazabilir**.
- Exploit, **service A'nın SEND right'ını service B'ye** geçirir.
- Böylece svc **B**, **service A'ya** gerçekte **message'ları gönderen** taraf olur.
- **Exploit**, **privileged action'ı çağırmayı** dener. Bir RC'de svc **A**, **svc B Audit token'ın üzerine yazarken** bu **action** için authorization'ı **check eder** (bu da exploit'e privileged action'ı çağırma erişimi sağlar).
2. Variant 2:
- Service **B**, service A'da kullanıcının çağıramadığı **privileged functionality**'yi çağırabilir.
- Exploit, kendisine belirli bir **replay** **port'unda** response bekleyen bir **message gönderen** **service A**'ya connect olur.
- Exploit, **bu reply port'unu** geçirerek service B'ye bir message gönderir.
- Service **B** reply verdiğinde **message'ı service A'ya gönderir**, bu sırada **exploit**, privileged functionality'ye ulaşmaya çalışan farklı bir **message'ı service A'ya** gönderir ve service B'den gelen reply'ın doğru anda Audit token'ın üzerine yazmasını bekler (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Senaryo:

- Sandbox profile ve connection kabul edilmeden önce yapılan authorization check'lere dayanarak ikisine de connect olabildiğimiz iki mach service, **`A`** ve **`B`**.
- _**A**_, **`B`**'nin geçebildiği (ancak app'imizin geçemediği) belirli bir action için bir **authorization check** içermelidir.
- Örneğin B'de bazı **entitlement**'lar varsa veya root olarak çalışıyorsa, A'dan privileged action gerçekleştirmesini istemesine izin verilebilir.
- Bu authorization check için **`A`**, audit token'ı asynchronously olarak, örneğin `dispatch_async` içinden `xpc_connection_get_audit_token` çağırarak elde eder.

> [!CAUTION]
> Bu durumda bir attacker, **A'dan bir action gerçekleştirmesini isteyen** exploit'i birkaç kez tetiklerken aynı zamanda **B'nin `A`'ya message göndermesini** sağlayarak bir **Race Condition** oluşturabilir. RC **başarılı olduğunda**, **B'nin audit token'ı**, exploit'in request'i A tarafından **işlenirken** memory'ye kopyalanır ve exploit'e yalnızca B'nin isteyebileceği privileged action'a **erişim** sağlanır.

Bu durum **`A`** olarak `smd` ve **`B`** olarak `diagnosticd` ile gerçekleşti. [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) function'ı, yeni bir privileged helper tool'u **root** olarak install etmek için kullanılabilir. **Root olarak çalışan bir process** **`smd` ile iletişim kurarsa**, başka bir check gerçekleştirilmez.

Bu nedenle service **B**, root olarak çalıştığı ve bir process'i **monitor** etmek için kullanılabildiği için **`diagnosticd`**'dir; dolayısıyla monitoring başladıktan sonra **saniyede birden fazla message gönderir.**

Attack'i gerçekleştirmek için:

1. Standart XPC protocol'ünü kullanarak `smd` adlı service'e bir **connection** başlatın.
2. `diagnosticd`'ye secondary bir **connection** kurun. Normal prosedürün aksine, iki yeni mach port oluşturup göndermek yerine client port send right'ı, `smd` connection'ıyla ilişkili **send right'ın** bir duplicate'iyle değiştirin.
3. Bunun sonucunda XPC message'ları `diagnosticd`'ye dispatch edilebilir, ancak `diagnosticd`'den gelen response'lar `smd`'ye yönlendirilir. `smd` için hem user'dan hem de `diagnosticd`'den gelen message'lar aynı connection'dan geliyormuş gibi görünür.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Sonraki adım, `diagnosticd`'ye seçilen bir process'i (potansiyel olarak kullanıcının kendi process'ini) monitoring etmeye başlamasını söylemektir. Aynı anda `smd`'ye rutin 1004 message'larından oluşan bir flood gönderilir. Buradaki amaç elevated privilege'lara sahip bir tool install etmektir.
5. Bu action, `handle_bless` function'ı içinde bir race condition tetikler. Zamanlama kritiktir: `xpc_connection_get_pid` function call'ı user process'inin PID'sini döndürmelidir (çünkü privileged tool user app bundle'ında bulunur). Ancak özellikle `connection_is_authorized` subroutine'i içindeki `xpc_connection_get_audit_token` function'ı `diagnosticd`'ye ait audit token'a referans vermelidir.<sup>[1]</sup>

## Variant 2: reply forwarding

Bir XPC (Cross-Process Communication) ortamında event handler'lar concurrently çalışmasa da reply message'larının işlenmesi kendine özgü bir davranışa sahiptir. Özellikle reply bekleyen message'ları göndermek için iki farklı method vardır:

1. **`xpc_connection_send_message_with_reply`**: Burada XPC message belirlenmiş bir queue üzerinde alınır ve işlenir.
2. **`xpc_connection_send_message_with_reply_sync`**: Buna karşılık bu method'da XPC message mevcut dispatch queue üzerinde alınır ve işlenir.

Bu ayrım kritiktir; çünkü **reply packet'larının bir XPC event handler'ın çalışmasıyla eşzamanlı olarak parse edilmesini** mümkün kılar. `_xpc_connection_set_creds`, audit token'ın partial overwrite edilmesini önlemek için locking uygular; ancak bu koruma tüm connection object'ine uygulanmaz. Sonuç olarak packet'ın parse edilmesi ile event handler'ının çalıştırılması arasındaki aralıkta audit token'ın değiştirilebildiği bir vulnerability oluşur.

Bu vulnerability'yi exploit etmek için aşağıdaki setup gereklidir:

- İkisinin de connection kurabildiği, **`A`** ve **`B`** olarak adlandırılan iki mach service.
- Service **`A`**, yalnızca **`B`**'nin gerçekleştirebildiği (user application'ın gerçekleştiremediği) belirli bir action için authorization check içermelidir.
- Service **`A`**, reply bekleyen bir message göndermelidir.
- User, response vereceği **`B`**'ye bir message gönderebilmelidir.

Exploitation süreci şu adımları içerir:

1. Service **`A`**'nın reply bekleyen bir message göndermesini bekleyin.
2. Doğrudan **`A`**'ya reply vermek yerine reply port ele geçirilir ve service **`B`**'ye bir message göndermek için kullanılır.
3. Ardından forbidden action'ı içeren bir message dispatch edilir ve bunun **`B`**'den gelen reply ile eşzamanlı olarak işlenmesi beklenir.<sup>[1]</sup>

Aşağıda açıklanan attack senaryosunun görsel bir temsili bulunmaktadır:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Instance'ları Bulma Zorlukları**: `xpc_connection_get_audit_token` kullanım instance'larını bulmak hem statically hem de dynamically zordu.
- **Methodology**: `xpc_connection_get_audit_token` function'ını hook etmek için Frida kullanıldı ve event handler'lardan kaynaklanmayan call'lar filtrelendi. Ancak bu method yalnızca hook edilen process ile sınırlıydı ve aktif kullanım gerektiriyordu.
- **Analysis Tooling**: IDA/Ghidra gibi tool'lar reachable mach service'leri incelemek için kullanıldı; ancak işlem zaman alıyordu ve dyld shared cache içeren call'lar nedeniyle karmaşıktı.
- **Scripting Limitations**: `dispatch_async` block'larından `xpc_connection_get_audit_token` call'larını bulmak için analysis'i script'leme girişimleri, block'ları parse etmenin ve dyld shared cache ile etkileşimlerin karmaşıklığı nedeniyle engellendi.<sup>[1]</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: `smd` içinde bulunan genel ve özel sorunları Apple'a açıklayan bir report gönderildi.
- **Apple's Response**: Apple, `xpc_connection_get_audit_token` yerine `xpc_dictionary_get_audit_token` kullanarak `smd` içindeki sorunu giderdi.<sup>[1][2]</sup>
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` function'ı, audit token'ı alınan XPC message'a bağlı mach message'dan doğrudan aldığı için secure kabul edilir. Ancak `xpc_connection_get_audit_token` gibi public API'nin bir parçası değildir.
- **Absence of a Broader Fix**: Apple'ın connection için kaydedilmiş audit token ile eşleşmeyen message'ları discard etmek gibi daha kapsamlı bir fix uygulamamasının nedeni belirsizliğini koruyor. Belirli senaryolarda (örneğin `setuid` kullanımı) legitimate audit token değişikliklerinin mümkün olması bir etken olabilir.
- **Current Status**: Sorun iOS 17 ve macOS 14'te devam ediyor; bu durum sorunu tespit edip anlamaya çalışanlar için bir challenge oluşturuyor.<sup>[1]</sup>

## Finding vulnerable code paths in practice (2024–2025)

XPC service'lerini bu bug class için audit ederken authorization'ın message'ın event handler'ı dışında veya reply processing ile eşzamanlı olarak gerçekleştirilmesine odaklanın.

Static triage ipuçları:
- `dispatch_async`/`dispatch_after` veya message handler dışında çalışan diğer worker queue'ları üzerinden queue edilen block'lar tarafından erişilebilen `xpc_connection_get_audit_token` call'larını arayın.
- Per-connection ve per-message state'i birlikte kullanan authorization helper'larını bulun (örneğin PID'yi `xpc_connection_get_pid` üzerinden, audit token'ı ise `xpc_connection_get_audit_token` üzerinden almak).
- NSXPC code içinde check'lerin `-listener:shouldAcceptNewConnection:` içinde yapıldığını veya per-message check'ler için implementation'ın per-message audit token kullandığını doğrulayın (örneğin lower-level code içinde message'ın dictionary'si aracılığıyla `xpc_dictionary_get_audit_token`).

Dynamic triage ipuçları:
- `xpc_connection_get_audit_token`'ı hook edin ve user stack'i event-delivery path'ini (örneğin `_xpc_connection_mach_event`) içermeyen invocation'ları flag'leyin. Örnek Frida hook'u:
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
- macOS'ta korumalı/Apple binary'lerini enstrümante etmek için SIP'nin devre dışı bırakılması veya bir development environment gerekebilir; kendi build'lerinizi ya da userland services'leri test etmeyi tercih edin.
- Reply-forwarding races (Variant 2) için, `xpc_connection_send_message_with_reply` ile normal isteklerin zamanlamalarını fuzzing yaparak reply paketlerinin eşzamanlı ayrıştırılmasını izleyin ve authorization sırasında kullanılan effective audit token'ın etkilenip etkilenemediğini kontrol edin.

## Muhtemelen ihtiyaç duyacağınız exploitation primitives

- Multi-sender setup (Variant 1): A ve B'ye connections oluşturun; A'nın client port'una ait send right'ı duplicate edin ve B'nin client port'u olarak kullanın; böylece B'nin reply'ları A'ya teslim edilir.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A’nın bekleyen isteğindeki send-once hakkını (reply port) ele geçirin, ardından bu reply portu kullanarak B’ye hazırlanmış bir mesaj gönderin; böylece ayrıcalıklı isteğiniz ayrıştırılırken B’nin yanıtı A’ya ulaşır.

Bunlar, XPC bootstrap ve mesaj biçimleri için düşük seviyeli mach mesajı oluşturmayı gerektirir; kesin paket düzenleri ve flag’ler için bu bölümdeki mach/XPC primer sayfalarını inceleyin.

## Kullanışlı araçlar

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer), bağlantıları listelemeye ve multi-sender kurulumlarını ve zamanlamayı doğrulamak üzere trafiği gözlemlemeye yardımcı olabilir. Örnek: `gxpc -p <PID> --whitelist <service-name>`.
- libxpc için klasik dyld interposing: black-box testing sırasında çağrı noktalarını ve stack’leri loglamak amacıyla `xpc_connection_send_message*` ve `xpc_connection_get_audit_token` üzerinde interpose uygulayın.



## References

- [1] [Sector 7 – Don’t Talk All at Once! macOS’ta Audit Token Spoofing ile Ayrıcalıkları Yükseltme](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – macOS Ventura 13.4’ün güvenlik içeriği hakkında (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
