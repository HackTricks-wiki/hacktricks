# Diğer Web Tricks

{{#include ../banners/hacktricks-training.md}}

## Host header

Back end'ler mutlak bağlantılar oluştururken bazen HTTP `Host` alanına güvenir. Bir password-reset e-postası saldırgan tarafından sağlanan bir host kullanıyorsa, bir kurban için reset talep etmek token içeren bir bağlantının saldırganın kontrolündeki bir domain üzerinden gönderilmesine neden olabilir. Her proxy hop'unda forwarded-host alanlarını, yinelenen Host işlemlerini ve absolute-form request target'larını da test edin.<sup>[[1]](#references)</sup>

> [!WARNING]
> Kullanıcının tıklaması gerekli olmayabilir: **mail security scanner'ları, preview servisleri veya diğer intermediary'ler saldırganın kontrolündeki bağlantıyı otomatik olarak request edebilir** ve reset token'ını açığa çıkarabilir.

## Session booleans

Bazı uygulamalar tamamlanmış bir verification işlemini session içinde boolean olarak kaydeder ve ardından farklı bir endpoint'in bu flag'e güvenmesine izin verir. Bir resource için check'i meşru şekilde geçtikten sonra aynı flag'in yanlışlıkla farklı bir user, object veya workflow için authorization sağlayıp sağlamadığını test edin. Bu, yalnızca bir IDOR değil, second-order authorization/state-reuse flaw'dur.<sup>[[2]](#references)</sup>

## Registration functionality

Zaten mevcut olan bir user olarak register olmayı deneyin. Ayrıca eşdeğer karakterleri kullanmayı da deneyin (noktalar, çok sayıda boşluk ve Unicode).

## Email-change state confusion

Bir email address register edin ve confirm etmeden önce değiştirin. New address için confirmation'ın old address'e gönderilip gönderilmediğini veya old token'ı confirm etmenin new address'i aktive edip etmediğini kontrol edin. Confirmation token'ları tam olarak aynı account'a, pending address'e, purpose'a ve current state'e bağlanmalıdır.

## Exposed Atlassian service desks


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE method

HTTP `TRACE` method'u, diagnostics amacıyla alınan request'in loop-back'ini ister. RFC 9110, recipient'ların credentials ve cookies gibi sensitive field'ları reflected content'tan çıkarmasını gerektirir; ancak güvenli olmayan implementation'lar veya intermediary tarafından eklenen header'lar internal request transformation'larını yine de açığa çıkarabilir. Browser'lar script tarafından oluşturulan TRACE request'lerini engeller; bu nedenle historical cross-site tracing attack'i, protected field'ları inject etmek için ayrıca bir yönteme de bağlıdır.<sup>[[3]](#references)</sup>![TRACE response'ını gösteren görsel](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Post için görsel](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Host Header Injection ile herhangi bir kullanıcının account'unu nasıl ele geçirebildim](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Daha az bilinen bir attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, section 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
