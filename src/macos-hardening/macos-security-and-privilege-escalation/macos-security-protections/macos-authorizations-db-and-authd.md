# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Authorization Database

Security framework-ov Authorization Services omogućava privilegovanim helper-ima i drugim komponentama da procenjuju imenovana authorization prava. Na aktuelnim verzijama macOS-a, mnoga od tih pravila se čuvaju u `/var/db/auth.db` i procenjuju pomoću `authd`; ovaj fajl i njegova SQLite schema predstavljaju implementation details i mogu se menjati između izdanja.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Sistemski podrazumevani podaci su se istorijski inicijalizovali iz `/System/Library/Security/authorization.plist`, a installers ili privilegovani servisi mogu dodavati imenovana prava. Prednost treba dati podržanom interfejsu `security authorizationdb read|write|remove` u odnosu na direktno menjanje baze podataka.<sup>[[3]](#references)</sup>

Tabela `rules` u dokumentovanoj build verziji sadrži sledeće kolone. Ovo treba posmatrati kao forenzičku mapu, a ne kao stabilnu javnu schemu:

- **id**: Jedinstveni identifier za svako pravilo, automatski se povećava i služi kao primary key.
- **name**: Jedinstveno ime pravila koje se koristi za njegovu identifikaciju i referenciranje unutar authorization sistema.
- **type**: Određuje tip pravila, ograničen na vrednosti 1 ili 2 kojima se definiše njegova authorization logika.
- **class**: Kategorizuje pravilo u određenu klasu, pri čemu mora biti pozitivan integer.
- Uobičajene klase pravila uključuju `allow`, `deny`, `user`, `rule` i `evaluate-mechanisms`. Mechanisms mogu biti ugrađeni ili Security Agent plug-ins u `/System/Library/CoreServices/SecurityAgentPlugins/` ili `/Library/Security/SecurityAgentPlugins/`.<sup>[[2]](#references)</sup>
- **group**: Označava user grupu povezanu sa pravilom za group-based authorization.
- **kofn**: Predstavlja parametar "k-of-n", koji određuje koliko podpravila mora biti ispunjeno od ukupnog broja.
- **timeout**: Definiše trajanje u sekundama pre nego što authorization odobren pravilom istekne.
- **flags**: Sadrži različite flags koji menjaju ponašanje i karakteristike pravila.
- **tries**: Ograničava broj dozvoljenih authorization pokušaja radi povećanja bezbednosti.
- **version**: Prati verziju pravila radi version control-a i ažuriranja.
- **created**: Beleži timestamp kreiranja pravila u svrhu audita.
- **modified**: Čuva timestamp poslednje izmene pravila.
- **hash**: Sadrži hash vrednost pravila radi provere njegovog integriteta i otkrivanja tamperinga.
- **identifier**: Obezbeđuje jedinstveni string identifier, kao što je UUID, za spoljne reference na pravilo.
- **requirement**: Sadrži serialized podatke koji definišu specifične authorization zahteve i mechanisms pravila.
- **comment**: Nudi ljudima čitljiv opis ili komentar o pravilu radi dokumentacije i jasnoće.

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
Sledeće dekodirano pravilo ilustruje `authenticate-admin-nonshared` na dokumentovanoj verziji macOS-a:<sup>[[1]](#references)</sup>
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

`authd` je XPC servis koji procenjuje zahteve Authorization Services. U aktuelnim macOS buildovima njegov bundle može da se pregleda na adresi `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc`; ova putanja je detalj implementacije i može se razlikovati između izdanja. Starija izdanja su upisivala podatke u `/var/log/authd.log`; aktuelna izdanja prvenstveno koriste unified logging system, koji se može upititi pomoću `log show`/`log stream` uz predicate za proces `authd`.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

Alat `security` izlaže nekoliko operacija Authorization Services. Istorijski primer poziva `AuthorizationExecuteWithPrivileges` pomoću `security execute-with-privileges /bin/ls`. Apple je deprecated-ovao ovaj API u macOS 10.7; moderni privileged helpers treba da koriste launchd-managed helper i XPC authorization.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

Na izdanjima koja ga i dalje podržavaju, ovo koristi `/usr/libexec/security_authtrampoline` i prikazuje authorization prompt pre pokretanja komande kao root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Pregled macOS Authorization Right-a](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Apple Authorization Services Programming Guide (arhiva)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [`security(1)` macOS stranica priručnika](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Daemons and Services Programming Guide: Kreiranje launchd poslova](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Apple open-source Security projekat - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
