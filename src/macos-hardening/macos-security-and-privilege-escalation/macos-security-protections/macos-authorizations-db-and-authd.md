# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Authorizations DB**

Die databasis in `/var/db/auth.db` word gebruik om toestemmings te stoor om sensitiewe bewerkings uit te voer. Hierdie bewerkings word volledig in **user space** uitgevoer en word gewoonlik deur **XPC services** gebruik wat moet nagaan **of die calling client gemagtig is** om 'n sekere aksie uit te voer deur hierdie databasis te raadpleeg.

Aanvanklik word hierdie databasis geskep uit die inhoud van `/System/Library/Security/authorization.plist`. Daarna kan sommige services hierdie databasis bywerk of wysig om ander toestemmings daarby te voeg.

Die reëls word in die `rules`-tabel binne die databasis gestoor en bevat die volgende kolomme:

- **id**: 'n Unieke identifiseerder vir elke reël, wat outomaties verhoog word en as die primêre sleutel dien.
- **name**: Die unieke naam van die reël wat gebruik word om dit binne die authorization system te identifiseer en daarna te verwys.
- **type**: Spesifiseer die tipe reël, beperk tot waardes 1 of 2 om die authorization logic te definieer.
- **class**: Kategoriseer die reël in 'n spesifieke klas en verseker dat dit 'n positiewe heelgetal is.
- "allow" vir toelaat, "deny" vir weier, "user" as die group-eienskap 'n groep aandui waarvan lidmaatskap toegang toelaat, "rule" dui in 'n array 'n reël aan waaraan voldoen moet word, "evaluate-mechanisms" gevolg deur 'n `mechanisms`-array wat óf builtins óf 'n bundle-naam binne `/System/Library/CoreServices/SecurityAgentPlugins/` of /Library/Security//SecurityAgentPlugins is.
- **group**: Dui die user group aan wat met die reël vir group-based authorization geassosieer word.
- **kofn**: Verteenwoordig die "k-of-n"-parameter wat bepaal hoeveel subreëls uit 'n totale aantal nagekom moet word.
- **timeout**: Definieer die duur in sekondes voordat die authorization wat deur die reël toegestaan is, verval.
- **flags**: Bevat verskeie flags wat die gedrag en eienskappe van die reël verander.
- **tries**: Beperk die aantal toegelate authorization-pogings om security te verbeter.
- **version**: Hou die weergawe van die reël dop vir version control en updates.
- **created**: Teken die tydstempel aan waarop die reël geskep is vir auditing-doeleindes.
- **modified**: Stoor die tydstempel van die laaste wysiging aan die reël.
- **hash**: Bevat 'n hash-waarde van die reël om die integriteit daarvan te verseker en tampering op te spoor.
- **identifier**: Verskaf 'n unieke string-identifiseerder, soos 'n UUID, vir eksterne verwysings na die reël.
- **requirement**: Bevat serialized data wat die spesifieke authorization requirements en mechanisms van die reël definieer.
- **comment**: Bied 'n mensleesbare beskrywing of kommentaar oor die reël vir dokumentasie en duidelikheid.

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
Boonop is dit in [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) moontlik om die betekenis van `authenticate-admin-nonshared` te sien:<sup>[[1]](#references)</sup>
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

Dit is 'n daemon wat versoeke ontvang om kliënte te magtig om sensitiewe aksies uit te voer. Dit werk as 'n XPC-diens wat binne die `XPCServices/`-lêergids gedefinieer is en gebruik om sy logs in `/var/log/authd.log` te skryf.

Verder is dit, deur die security tool te gebruik, moontlik om baie `Security.framework` APIs te toets. Byvoorbeeld, om `AuthorizationExecuteWithPrivileges` uit te voer: `security execute-with-privileges /bin/ls`

Dit sal `/usr/libexec/security_authtrampoline /bin/ls` as root fork en exec, wat in 'n prompt vir toestemming sal vra om ls as root uit te voer:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## Verwysings

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
