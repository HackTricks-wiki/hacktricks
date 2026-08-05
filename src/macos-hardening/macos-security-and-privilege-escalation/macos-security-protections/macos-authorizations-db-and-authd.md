# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Magtigingsdatabasis**

Die databasis in `/var/db/auth.db` is ’n databasis wat gebruik word om toestemmings te stoor om sensitiewe bewerkings uit te voer. Hierdie bewerkings word volledig in **user space** uitgevoer en word gewoonlik deur **XPC services** gebruik wat moet kontroleer **of die kliënt wat die versoek doen gemagtig is** om ’n bepaalde aksie uit te voer deur hierdie databasis na te gaan.

Aanvanklik word hierdie databasis geskep vanuit die inhoud van `/System/Library/Security/authorization.plist`. Daarna kan sommige services hierdie databasis byvoeg of wysig om ander toestemmings daarby te voeg.

Die reëls word in die `rules`-tabel binne die databasis gestoor en bevat die volgende kolomme:

- **id**: ’n Unieke identifiseerder vir elke reël, wat outomaties verhoog word en as die primêre sleutel dien.
- **name**: Die unieke naam van die reël wat gebruik word om dit binne die magtigingstelsel te identifiseer en daarna te verwys.
- **type**: Spesifiseer die tipe reël, beperk tot waardes 1 of 2 om die magtigingslogika daarvan te definieer.
- **class**: Kategoriseer die reël in ’n spesifieke klas en verseker dat dit ’n positiewe heelgetal is.
- "allow" vir toelaat, "deny" vir weier, "user" indien die groep-eienskap ’n groep aandui waarvan lidmaatskap toegang toelaat, "rule" dui in ’n skikking ’n reël aan waaraan voldoen moet word, "evaluate-mechanisms" gevolg deur ’n `mechanisms`-skikking waarvan die elemente óf builtins óf ’n naam van ’n bundle binne `/System/Library/CoreServices/SecurityAgentPlugins/` of `/Library/Security//SecurityAgentPlugins` is
- **group**: Dui die gebruikersgroep aan wat met die reël vir groepgebaseerde magtiging geassosieer word.
- **kofn**: Verteenwoordig die "k-of-n"-parameter, wat bepaal hoeveel subreëls uit ’n totale aantal nagekom moet word.
- **timeout**: Definieer die duur in sekondes voordat die magtiging wat deur die reël verleen is, verval.
- **flags**: Bevat verskeie vlae wat die gedrag en eienskappe van die reël wysig.
- **tries**: Beperk die aantal toegelate magtigingspogings om sekuriteit te verbeter.
- **version**: Hou die weergawe van die reël vir weergawebeheer en opdaterings dop.
- **created**: Teken die tydstempel aan waarop die reël geskep is vir ouditdoeleindes.
- **modified**: Stoor die tydstempel van die laaste wysiging wat aan die reël gemaak is.
- **hash**: Bevat ’n hash-waarde van die reël om die integriteit daarvan te verseker en peutering op te spoor.
- **identifier**: Verskaf ’n unieke string-identifiseerder, soos ’n UUID, vir eksterne verwysings na die reël.
- **requirement**: Bevat geserialiseerde data wat die reël se spesifieke magtigingsvereistes en meganismes definieer.
- **comment**: Bied ’n mensleesbare beskrywing of opmerking oor die reël vir dokumentasie en duidelikheid.

### Voorbeeld
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
Boonop is dit in [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) moontlik om die betekenis van `authenticate-admin-nonshared` te sien:<sup>[1]</sup>
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

Dit is ’n daemon wat versoeke ontvang om kliënte te magtig om sensitiewe handelinge uit te voer. Dit werk as ’n XPC-diens wat binne die `XPCServices/`-vouer gedefinieer is en skryf sy logs na `/var/log/authd.log`.

Verder is dit met die security tool moontlik om baie `Security.framework`-API’s te toets. Byvoorbeeld, om `AuthorizationExecuteWithPrivileges` uit te voer: `security execute-with-privileges /bin/ls`

Dit sal as root ` /usr/libexec/security_authtrampoline /bin/ls` forking en uitvoer, waarna dit in ’n prompt vir toestemming sal vra om ls as root uit te voer:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## Verwysings

- [1] [authenticate-admin-nonshared - Oorsig van die macOS-magtigingsreg](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
