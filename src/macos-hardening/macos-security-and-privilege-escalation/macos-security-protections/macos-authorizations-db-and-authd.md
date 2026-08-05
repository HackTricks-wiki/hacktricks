# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Baza autorizacija**

Baza podataka koja se nalazi u `/var/db/auth.db` koristi se za čuvanje dozvola za izvršavanje osetljivih operacija. Ove operacije se u potpunosti izvršavaju u **korisničkom prostoru** i obično ih koriste **XPC services** koje treba da provere **da li je klijentski pozivalac ovlašćen** da izvrši određenu radnju, proveravajući ovu bazu podataka.

Ova baza se prvobitno kreira na osnovu sadržaja datoteke `/System/Library/Security/authorization.plist`. Zatim neke services mogu dodati ili izmeniti ovu bazu kako bi joj dodale druge dozvole.

Pravila se čuvaju u tabeli `rules` unutar baze podataka i sadrže sledeće kolone:

- **id**: Jedinstveni identifikator za svako pravilo, automatski se uvećava i služi kao primarni ključ.
- **name**: Jedinstveni naziv pravila koji se koristi za njegovo identifikovanje i referenciranje u authorization system-u.
- **type**: Navodi tip pravila, ograničen na vrednosti 1 ili 2, kako bi se definisala njegova authorization logika.
- **class**: Kategorizuje pravilo u određenu klasu, pri čemu mora biti pozitivan ceo broj.
- "allow" za dozvolu, "deny" za zabranu, "user" ako svojstvo group navodi grupu čije članstvo omogućava pristup, "rule" označava niz pravila koja treba ispuniti, a "evaluate-mechanisms" prati niz `mechanisms` čiji elementi mogu biti builtins ili naziv bundle-a unutar `/System/Library/CoreServices/SecurityAgentPlugins/` ili `/Library/Security//SecurityAgentPlugins`
- **group**: Navodi korisničku grupu povezanu sa pravilom za authorization zasnovanu na grupi.
- **kofn**: Predstavlja parametar „k-od-n“, koji određuje koliko podpravila mora biti ispunjeno od ukupnog broja pravila.
- **timeout**: Definiše trajanje u sekundama pre nego što authorization dodeljen pravilom istekne.
- **flags**: Sadrži različite zastavice koje menjaju ponašanje i karakteristike pravila.
- **tries**: Ograničava broj dozvoljenih pokušaja authorization-a radi povećanja bezbednosti.
- **version**: Prati verziju pravila radi kontrole verzija i ažuriranja.
- **created**: Beleži vremensku oznaku kreiranja pravila u svrhu revizije.
- **modified**: Čuva vremensku oznaku poslednje izmene pravila.
- **hash**: Sadrži hash vrednost pravila radi obezbeđivanja njegovog integriteta i otkrivanja neovlašćenih izmena.
- **identifier**: Obezbeđuje jedinstveni string identifikator, kao što je UUID, za spoljne reference na pravilo.
- **requirement**: Sadrži serijalizovane podatke koji definišu posebne authorization zahteve i mehanizme pravila.
- **comment**: Nudi čoveku čitljiv opis ili komentar o pravilu radi dokumentacije i jasnoće.

### Primer
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Štaviše, na [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) moguće je videti značenje prava `authenticate-admin-nonshared`:<sup>[[1]](#references)</sup>
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

To je daemon koji prima zahteve za autorizaciju klijenata za izvršavanje osetljivih radnji. Radi kao XPC service definisan unutar foldera `XPCServices/` i koristi se za zapisivanje logova u `/var/log/authd.log`.

Pored toga, pomoću security alata moguće je testirati mnoge `Security.framework` API-je. Na primer, pokretanje `AuthorizationExecuteWithPrivileges`: `security execute-with-privileges /bin/ls`

To će fork-ovati i izvršiti `/usr/libexec/security_authtrampoline /bin/ls` kao root, koji će zatražiti dozvole u promptu za izvršavanje komande ls kao root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## Reference

- [1] [authenticate-admin-nonshared - Pregled macOS prava za autorizaciju](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
