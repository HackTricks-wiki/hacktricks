# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Authorization Database

Die Security-framework se Authorization Services stel gepriviligeerde helpers en ander komponente in staat om benoemde authorization rights te evalueer. Op huidige macOS-weergawes word baie van hierdie reëls in `/var/db/auth.db` bewaar en deur `authd` geëvalueer; hierdie lêer en sy SQLite-skema is implementasiebesonderhede en kan tussen vrystellings verander.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Stelselverstekwaardes is histories vanuit `/System/Library/Security/authorization.plist` gelaai, en installers of gepriviligeerde dienste kan benoemde rights byvoeg. Gebruik verkieslik die ondersteunde `security authorizationdb read|write|remove`-koppelvlak eerder as om die databasis direk te wysig.<sup>[[3]](#references)</sup>

Die `rules`-tabel wat op die gedokumenteerde build waargeneem is, bevat die volgende kolomme. Beskou dit as ’n forensiese kaart, nie as ’n stabiele publieke skema nie:

- **id**: ’n Unieke identifiseerder vir elke reël, wat outomaties geïnk better word en as die primary key dien.
- **name**: Die unieke naam van die reël wat gebruik word om dit binne die authorization-stelsel te identifiseer en daarna te verwys.
- **type**: Spesifiseer die tipe van die reël, beperk tot waardes 1 of 2 om die authorization-logika daarvan te definieer.
- **class**: Kategoriseer die reël in ’n spesifieke klas, wat ’n positiewe heelgetal moet wees.
- Algemene reëlklasse sluit `allow`, `deny`, `user`, `rule` en `evaluate-mechanisms` in. Mechanisms kan ingeboude komponente of Security Agent plug-ins onder `/System/Library/CoreServices/SecurityAgentPlugins/` of `/Library/Security/SecurityAgentPlugins/` wees.<sup>[[2]](#references)</sup>
- **group**: Dui die user group aan wat met die reël geassosieer word vir group-based authorization.
- **kofn**: Verteenwoordig die "k-of-n"-parameter, wat bepaal hoeveel subreëls uit ’n totale aantal bevredig moet word.
- **timeout**: Definieer die duur in sekondes voordat die authorization wat deur die reël verleen is, verval.
- **flags**: Bevat verskeie flags wat die gedrag en eienskappe van die reël verander.
- **tries**: Beperk die aantal toegelate authorization-pogings om sekuriteit te verbeter.
- **version**: Volg die weergawe van die reël vir weergawebeheer en updates.
- **created**: Teken die tydstempel aan waarop die reël geskep is vir ouditdoeleindes.
- **modified**: Stoor die tydstempel van die laaste wysiging wat aan die reël gemaak is.
- **hash**: Bevat ’n hash-waarde van die reël om die integriteit daarvan te verseker en tampering op te spoor.
- **identifier**: Verskaf ’n unieke string-identifiseerder, soos ’n UUID, vir eksterne verwysings na die reël.
- **requirement**: Bevat geserialiseerde data wat die reël se spesifieke authorization-vereistes en mechanisms definieer.
- **comment**: Bied ’n mensleesbare beskrywing of opmerking oor die reël vir dokumentasie en duidelikheid.

### Example
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
Die volgende gedekodeerde reël illustreer `authenticate-admin-nonshared` op 'n gedokumenteerde macOS-weergawe:<sup>[[1]](#references)</sup>
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

`authd` is die XPC-diens wat Authorization Services-versoeke evalueer. Op huidige macOS-bouwe kan sy bondel by `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc` geïnspekteer word; die pad is ’n implementasiebesonderheid en kan tussen vrystellings verskil. Ouer vrystellings het na `/var/log/authd.log` geskryf; huidige vrystellings gebruik hoofsaaklik die unified logging-stelsel, wat met `log show`/`log stream` deur ’n `authd`-proses-predikaat navraag gedoen kan word.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

Die `security`-nutsding stel verskeie Authorization Services-bewerkings bloot. ’n Historiese voorbeeld roep `AuthorizationExecuteWithPrivileges` aan met `security execute-with-privileges /bin/ls`. Apple het daardie API in macOS 10.7 afgekeur; moderne bevoorregte helpers behoort eerder ’n launchd-bestuurde helper en XPC authorization te gebruik.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

Op vrystellings wat dit steeds ondersteun, gebruik dit `/usr/libexec/security_authtrampoline` en vertoon dit ’n authorization-prompt voordat die opdrag as root uitgevoer word:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Oorsig van die macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Apple Authorization Services Programming Guide (argief)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [`security(1)` macOS-handleidingbladsy](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Daemons and Services Programming Guide: Creating launchd jobs](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Apple open-source Security-projek - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
