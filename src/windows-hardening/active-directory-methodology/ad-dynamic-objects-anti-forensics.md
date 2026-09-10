# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Meganika & Basiese Opsporing

- Enige object wat met die auxiliary class **`dynamicObject`** geskep word, kry **`entryTTL`** (aftelling in sekondes) en **`msDS-Entry-Time-To-Die`** (absolute vervaldatum). Wanneer `entryTTL` 0 bereik **en die object geen afstammelinge het nie**, verwyder die Garbage Collector dit sonder tombstone/recycle-bin, wat die skepper en tydstempels uitwis en herstel blokkeer.<sup>[[4]](#references)</sup>
- **`entryTTL` is ’n operational/constructed attribute**: versoek dit eksplisiet in LDAP-navrae. TTL kan verfris word deur `entryTTL` voor vervaldatum op te dateer of via LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL minimum/verstekwaardes is forest-wide AVAs in **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**: `DynamicObjectMinTTLSeconds=<seconds>` en `DynamicObjectDefaultTTLSeconds=<seconds>`. Microsoft dokumenteer **86400s** as die verstek-TTL en **900s** as die verstek minimum geldige TTL; die `entryTTL`-schemareeks is **1–31557600s** (een sekonde tot een jaar).<sup>[[3]](#references)</sup> Dynamic objects word **nie in Configuration/Schema-partisies ondersteun nie**.
- Daar is **geen static→dynamic conversion nie** en geen tombstone-fase ná vervaldatum nie. IR-spanne kan nie op deleted-object-kontroles of Recycle Bin staatmaak nie; hulle moet die lewende object/metadata vaslê voordat GC dit verwyder.
- Refresh is **replica-sensitive**: indien TTL te naby aan vervaldatum hernu word, kan ’n ander writable replica of GC steeds die object plaaslik verwyder voordat die refresh gerepliseer word. Baie kort TTL’s werk dus die beste wanneer die aanvaller weet watter DC die misbruik sal hanteer, terwyl verdedigers tydens triage **alle naming contexts / replicas** moet navraag doen.
- Verwydering kan ’n paar minute vertraag word op DC’s met kort uptime (<24h), wat ’n beperkte reaksievenster laat om attributes te navraag of te rugsteun. Bespeur dit deur **waarskuwings op nuwe objects met `entryTTL`/`msDS-Entry-Time-To-Die`** te aktiveer en met orphan SIDs/broken links te korreleer.<sup>[[1]](#references)</sup>

### Verval-grafiek en uitsonderings vir verwysingsopruiming

- Elke afstammeling onder ’n dynamic object moet self dynamic wees. ’n Vervalde dynamic parent word slegs garbage-collected nadat dit ’n leaf geword het; indien ’n afstammeling ’n later `msDS-Entry-Time-To-Die` het, verleng die DC die parent se vervaldatum tot ná die maksimum vervaldatum van die afstammelinge. Gevolglik kan ’n writable dynamic subtree ’n **parent wat blykbaar op die punt is om te verdwyn, vaspen/verleng**: enumerateer die hele subtree en moenie die parent se waargenome `entryTTL` as die opruimingsperdatum gebruik nie.<sup>[[4]](#references)</sup>
- Vervalopruiming is **schema-link-aware**. Replicas verwyder linked attribute values wat na die deleted dynamic object verwys, maar behou nonlinked values. Verwag dat gewone forward/back-link-lidmaatskap skoongemaak word, terwyl integer/SID/string-verwysings soos `primaryGroupID`, SIDs wat in `nTSecurityDescriptor` ingebed is, of `gPLink`-teks as forensiese residue kan oorbly.<sup>[[4]](#references)</sup>

## Vinnige Enumerasie / Live Triage

- Doen navraag oor **alle `namingContexts` vanaf RootDSE**, nie net die domain NC nie. Dynamic abuse kan in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) of in application partitions voorkom.
- Terwyl die object nog lewendig is, dump onmiddellik **replication metadata** en enige linked attributes/ACLs. Ná vervaldatum kan slegs **broken `gPLink` values, orphan SIDs, of cached DNS-antwoorde** oorbly.<sup>[[1]](#references)</sup>
```powershell
(Get-ADForest).Domains | ForEach-Object {
Get-ADDomainController -Filter * -Server $_ | ForEach-Object {
$dc = $_.HostName
(Get-ADRootDSE -Server $dc).namingContexts | ForEach-Object {
Get-ADObject -Server $dc -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object @{n='DC';e={$dc}},DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
}
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion met Self-Deleting Computers

- Verstek **`ms-DS-MachineAccountQuota` = 10** laat enige geauthentiseerde gebruiker toe om rekenaars te skep. Voeg `dynamicObject` tydens skepping by om die rekenaar homself te laat uitvee en die kwotaslot **vry te stel** terwyl bewyse uitgewis word.
- Powermad-aanpassing binne `New-MachineAccount` (objectClass-lys):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Indien die aangevraagde TTL **laer as `DynamicObjectMinTTL`** is, verwag bedienerkant-aanpassing of verwerping, afhangend van die skeppingspad; in baie domains is die effektiewe minimum **900s**, en die terugval/verstek bly **86400s**. ADUC mag `entryTTL` versteek, maar LDP/LDAP-navrae wys dit.
- Terwyl die object bestaan, kan defenders steeds die ongeprivilegieerde skepper van **`msDS-CreatorSID`** op die rekenaarobject aflei. Sodra die dynamic computer verval, verdwyn daardie attribusie saam met die object.<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- Skep ’n **dynamic security group**, en stel dan ’n gebruiker se **`primaryGroupID`** op daardie groep se RID om effektiewe lidmaatskap te verkry wat **nie in `memberOf` wys nie**, maar wel in Kerberos/access tokens erken word.<sup>[[1]](#references)</sup>
- TTL-verval **vee die groep uit ondanks primary-group delete protection**, wat die gebruiker laat met ’n beskadigde `primaryGroupID` wat na ’n nie-bestaande RID wys, en sonder ’n tombstone om te ondersoek hoe die privilege toegeken is.
- Rapportering is tool-afhanklik: **`Get-ADGroupMember` / `net group`** bepaal gewoonlik lidmaatskap wat van die primary group afgelei is, terwyl **`memberOf`** en **`Get-ADGroup -Properties member`** dit nie doen nie. Vir breër `primaryGroupID`-tradecraft, sien [hierdie ander bladsy oor DCShadow en PGID abuse](dcshadow.md).
- Vir teikens wat **nie deur AdminSDHolder beskerm word nie**, kan attackers die dynamic-group-truuk kombineer met ’n **DACL deny op die lees van `primaryGroupID`** (of die groep se `member`-attribuut) om die skakel vir baie LDAP/PowerShell-workflows te versteek selfs voordat die groep verval.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- Voeg ACEs vir ’n **kortstondige dynamic user/group** by **`CN=AdminSDHolder,CN=System,...`**. Ná TTL-verval word die SID **onoplosbaar (“Unknown SID”)** in die template ACL, en **SDProp (~60 min)** versprei daardie orphan SID oor alle beskermde Tier-0-objects.
- Forensics verloor attribusie omdat die principal weg is (geen deleted-object DN nie). Monitor vir **nuwe dynamic principals + skielike orphan SIDs op AdminSDHolder/privileged ACLs**.<sup>[[1]](#references)</sup>

## Dynamic GPO Execution met Self-Destructing Evidence

- Skep ’n **dynamic `groupPolicyContainer`**-object met ’n malicious **`gPCFileSysPath`** (byvoorbeeld ’n SMB share à la GPODDITY) en **koppel dit via `gPLink`** aan ’n teiken-OU.
- Clients verwerk die policy en haal content van attacker-SMB af. Wanneer TTL verval, verdwyn die GPO-object (en `gPCFileSysPath`); slegs ’n **broken `gPLink`** GUID bly oor, wat LDAP-bewyse van die uitgevoerde payload verwyder.
- Dit is operasioneel netjieser as klassieke **GPODDITY-style** cleanup: in plaas daarvan om die oorspronklike `gPCFileSysPath` self terug te stel, verwyder AD die malicious GPC outomaties wanneer die timer verval.<sup>[[1]](#references)</sup> Sien [ACL persistence abuse](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) vir die protokol- en toolingbesonderhede eerder as om dit hier te dupliseer.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS-records is **`dnsNode`**-objects in **DomainDnsZones/ForestDnsZones**. Deur hulle as **dynamic objects** te skep, word tydelike host redirection (credential capture/MITM) moontlik. Clients cache die malicious A/AAAA-response; die record vee homself later uit sodat die zone skoon lyk (DNS Manager mag ’n zone reload benodig om die aansig te verfris).
- Detection: genereer ’n alert vir **enige DNS-record wat `dynamicObject`/`entryTTL` bevat** via replication/event logs; transient records verskyn selde in standaard DNS-logs.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Nota)

- Entra Connect delta sync steun op **tombstones** om deletes op te spoor. ’n **Dynamic on-prem user** kan na Entra ID sync, verval en sonder ’n tombstone uitgevee word—delta sync sal nie die cloud-account verwyder nie, wat ’n **orphaned active Entra user** laat totdat ’n **initial/full sync** of handmatige cloud-cleanup gedwing word.<sup>[[1]](#references)</sup>



## References

- [1] [Dynamic Objects in Active Directory: Die Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [Configuration of TTL Limits](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: DynamicObject Requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
