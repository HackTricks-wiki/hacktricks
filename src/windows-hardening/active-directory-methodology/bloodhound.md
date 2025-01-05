# BloodHound & Ander AD Enum Gereedskap

{{#include ../../banners/hacktricks-training.md}}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) is van die Sysinternal Suite:

> 'n Gevorderde Active Directory (AD) kyker en redigeerder. Jy kan AD Explorer gebruik om maklik deur 'n AD-databasis te navigeer, gunsteling plekke te definieer, objek eienskappe en kenmerke te besigtig sonder om dialoogvensters te open, regte te redigeer, 'n objek se skema te besigtig, en gesofistikeerde soektogte uit te voer wat jy kan stoor en weer uitvoer.

### Snapshots

AD Explorer kan snapshots van 'n AD skep sodat jy dit buitelyn kan nagaan.\
Dit kan gebruik word om kwesbaarhede buitelyn te ontdek, of om verskillende toestande van die AD DB oor tyd te vergelyk.

Jy sal die gebruikersnaam, wagwoord, en rigting benodig om te verbind (enige AD-gebruiker is benodig).

Om 'n snapshot van AD te neem, gaan na `File` --> `Create Snapshot` en voer 'n naam vir die snapshot in.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) is 'n gereedskap wat verskeie artefakte uit 'n AD-omgewing onttrek en kombineer. Die inligting kan in 'n **spesiaal geformateerde** Microsoft Excel **verslag** aangebied word wat opsommingsoorsigte met metrieke insluit om analise te fasiliteer en 'n holistiese prentjie van die huidige toestand van die teiken AD-omgewing te bied.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound is 'n enkele bladsy Javascript webtoepassing, gebou op [Linkurious](http://linkurio.us/), saamgestel met [Electron](http://electron.atom.io/), met 'n [Neo4j](https://neo4j.com/) databasis wat gevoed word deur 'n C# data versamelaar.

BloodHound gebruik grafteorie om die versteekte en dikwels onbedoelde verhoudings binne 'n Active Directory of Azure omgewing te onthul. Aanvallers kan BloodHound gebruik om maklik hoogs komplekse aanvalspaaie te identifiseer wat andersins onmoontlik sou wees om vinnig te identifiseer. Verdedigers kan BloodHound gebruik om daardie selfde aanvalspaaie te identifiseer en te elimineer. Beide blou en rooi spanne kan BloodHound gebruik om maklik 'n dieper begrip van privilige verhoudings in 'n Active Directory of Azure omgewing te verkry.

So, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound)is 'n wonderlike hulpmiddel wat 'n domein outomaties kan opnoem, al die inligting kan stoor, moontlike privilige eskalasiepaaie kan vind en al die inligting kan vertoon met behulp van grafieke.

Booldhound bestaan uit 2 hoofdele: **ingestors** en die **visualiseringstoepassing**.

Die **ingestors** word gebruik om **die domein op te noem en al die inligting te onttrek** in 'n formaat wat die visualiseringstoepassing sal verstaan.

Die **visualiseringstoepassing gebruik neo4j** om te wys hoe al die inligting verwant is en om verskillende maniere te wys om privilige in die domein te eskaleer.

### Installation

Na die skepping van BloodHound CE, is die hele projek opgedateer vir gebruiksgemak met Docker. Die maklikste manier om te begin is om sy vooraf-gekonfigureerde Docker Compose konfigurasie te gebruik.

1. Installeer Docker Compose. Dit behoort ingesluit te wees met die [Docker Desktop](https://www.docker.com/products/docker-desktop/) installasie.
2. Loop:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Vind die ewekansig gegenereerde wagwoord in die terminaluitvoer van Docker Compose.  
4. Gaan in 'n blaaskie na http://localhost:8080/ui/login. Teken in met 'n gebruikersnaam van admin en die ewekansig gegenereerde wagwoord uit die logs.  

Na hierdie sal jy die ewekansig gegenereerde wagwoord moet verander en jy sal die nuwe koppelvlak gereed hê, waarvandaan jy direk die ingestors kan aflaai.  

### SharpHound  

Hulle het verskeie opsies, maar as jy SharpHound vanaf 'n PC wat by die domein aangesluit is, wil uitvoer, met jou huidige gebruiker en al die inligting wil onttrek, kan jy doen:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Jy kan meer lees oor **CollectionMethod** en lus sessie [hier](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

As jy SharpHound met verskillende akrediteerbesonderhede wil uitvoer, kan jy 'n CMD netonly-sessie skep en SharpHound van daar af uitvoer:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Leer meer oor Bloodhound in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) is 'n hulpmiddel om **kwesbaarhede** in Active Directory geassosieer met **Groep Beleid** te vind. \
Jy moet **group3r** vanaf 'n gasheer binne die domein gebruik met **enige domein gebruiker**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **evalueer die sekuriteitsposisie van 'n AD-omgewing** en bied 'n mooi **verslag** met grafieke.

Om dit te laat loop, kan jy die binêre `PingCastle.exe` uitvoer en dit sal 'n **interaktiewe sessie** begin wat 'n menu van opsies aanbied. Die standaardopsie om te gebruik is **`healthcheck`** wat 'n basislyn **oorsig** van die **domein** sal vestig, en **misconfigurasies** en **kwesbaarhede** sal vind.

{{#include ../../banners/hacktricks-training.md}}
