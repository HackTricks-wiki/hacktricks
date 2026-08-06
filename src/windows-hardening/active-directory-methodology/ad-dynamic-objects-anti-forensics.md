# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Meganika & Basiese Opsporing

- Enige objek wat met die auxiliary class **`dynamicObject`** geskep word, kry **`entryTTL`** (aftelling in sekondes) en **`msDS-Entry-Time-To-Die`** (absolute vervaldatum). Wanneer `entryTTL` 0 bereik, vee die **Garbage Collector** dit uit sonder tombstone/recycle-bin, wat die skepper en tydstempels uitwis en herstel blokkeer.
- **`entryTTL` is ’n operational/constructed attribute**: versoek dit eksplisiet in LDAP-navrae. TTL kan verfris word deur `entryTTL` voor verstryking op te dateer of via LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL-minimum en -standaardwaardes word afgedwing in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft dokumenteer **86400s** as die standaard TTL en **900s** as die standaard minimum geldige TTL; albei ondersteun **1s–1y**. Dynamic objects word nie in Configuration/Schema-partisies ondersteun nie.
- Daar is **geen static→dynamic conversion** nie en geen tombstone-fase ná verstryking nie. IR-spanne kan nie op deleted-object-kontroles of Recycle Bin staatmaak nie; hulle moet die lewende objek/metadata vaslê voordat GC dit verwyder.
- Verfrissing is **replica-sensitive**: as TTL te naby aan verstryking hernu word, kan ’n ander writable replica of GC steeds die objek plaaslik uitvee voordat die verfrissing repliseer. Baie kort TTL’s werk dus die beste wanneer die aanvaller weet watter DC die misbruik sal hanteer, terwyl defenders tydens triage **alle naming contexts / replicas** moet navraag doen.
- Verwydering kan ’n paar minute op DC’s met kort uptime (<24h) vertraag word, wat ’n nou response window laat om attributes te navraag of te rugsteun. Bespeur dit deur **te waarsku oor nuwe objekte wat `entryTTL`/`msDS-Entry-Time-To-Die` bevat** en dit met orphan SIDs/broken links te korreleer.<sup>[[1]](#references)</sup>

## Fast Enumeration / Live Triage

- Navraag oor **alle `namingContexts` vanaf RootDSE**, nie net die domain NC nie. Dynamic abuse kan in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) of in application partitions voorkom.
- Terwyl die objek nog leef, dump onmiddellik **replication metadata** en enige linked attributes/ACLs. Ná verstryking kan jy moontlik net met **broken `gPLink` values, orphan SIDs, of cached DNS answers** agterbly.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ-ontwyking met self-uitwissende rekenaars

- Die verstek **`ms-DS-MachineAccountQuota` = 10** laat enige geauthentiseerde gebruiker toe om rekenaars te skep. Voeg `dynamicObject` tydens skepping by om die rekenaar homself te laat uitvee en die kwotasleuf vry te stel terwyl bewyse uitgevee word.
- Powermad-aanpassing binne `New-MachineAccount` (objectClass-lys):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Indien die aangevraagde TTL onder `DynamicObjectMinTTL` is, verwag bedienerkant-aanpassing of verwerping, afhangend van die skeppingsroete; in baie domeine is die effektiewe minimum **900s** en die terugval/verstek bly **86400s**. ADUC mag `entryTTL` versteek, maar LDP/LDAP-navrae wys dit.
- Terwyl die objek bestaan, kan verdedigers steeds die ongeprivilegieerde skepper uit **`msDS-CreatorSID`** op die rekenaarobjek herwin. Sodra die dinamiese rekenaar verval, verdwyn daardie toeskrywing saam met die objek.<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- Skep ’n **dynamic security group**, en stel dan ’n gebruiker se **`primaryGroupID`** op daardie groep se RID om effektiewe lidmaatskap te verkry wat **nie in `memberOf` verskyn nie**, maar wel in Kerberos/toegangstokens erken word.<sup>[[1]](#references)</sup>
- TTL-verval **vee die groep uit ondanks beskerming teen uitvee van die primêre groep**, wat die gebruiker met ’n korrupte `primaryGroupID` laat wat na ’n nie-bestaande RID wys, sonder ’n tombstone om te ondersoek hoe die privilege toegestaan is.
- Rapportering is hulpmiddelafhanklik: **`Get-ADGroupMember` / `net group`** los gewoonlik lidmaatskap af wat uit die primêre groep voortspruit, terwyl **`memberOf`** en **`Get-ADGroup -Properties member`** dit nie doen nie. Vir breër `primaryGroupID`-tradecraft, sien [this other page about DCShadow and PGID abuse](dcshadow.md).
- Vir teikens wat **nie deur AdminSDHolder beskerm word nie**, kan aanvallers die dynamic-group-truuk kombineer met ’n **DACL-deny op die lees van `primaryGroupID`** (of die groep se `member`-attribute) om die koppeling vir baie LDAP/PowerShell-werkvloeie te versteek, selfs voordat die groep verval.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID-besoedeling

- Voeg ACEs vir ’n **kortlewende dynamic user/group** by **`CN=AdminSDHolder,CN=System,...`**. Ná TTL-verval word die SID **onoplosbaar (“Unknown SID”)** in die template-ACL, en **SDProp (~60 min)** versprei daardie orphan SID oor alle beskermde Tier-0-objekte.
- Forensiese ondersoeke verloor toeskrywing omdat die principal weg is (geen deleted-object-DN nie). Monitor vir **nuwe dynamic principals + skielike orphan SIDs op AdminSDHolder/privileged ACLs**.<sup>[[1]](#references)</sup>

## Dynamic GPO-uitvoering met self-vernietigende bewyse

- Skep ’n **dynamic `groupPolicyContainer`**-objek met ’n kwaadwillige **`gPCFileSysPath`** (byvoorbeeld ’n SMB-share à la GPODDITY) en koppel dit via **`gPLink`** aan ’n teiken-OU.
- Kliënte verwerk die beleid en haal inhoud van die aanvaller se SMB af. Wanneer die TTL verval, verdwyn die GPO-objek (en `gPCFileSysPath`); slegs ’n **gebreekte `gPLink`**-GUID bly oor, wat LDAP-bewyse van die uitgevoerde payload verwyder.
- Dit is operasioneel skoner as klassieke **GPODDITY-styl**-opruiming: in plaas daarvan om die oorspronklike `gPCFileSysPath` self terug te stel, verwyder AD die kwaadwillige GPC outomaties wanneer die timer verval.<sup>[[1]](#references)</sup>

## Ephemeral AD-Integrated DNS-herleiding

- AD DNS-rekords is **`dnsNode`**-objekte in **DomainDnsZones/ForestDnsZones**. Deur hulle as **dynamic objects** te skep, word tydelike gasheerherleiding moontlik (credential capture/MITM). Kliënte cache die kwaadwillige A/AAAA-antwoord; die rekord vee homself later uit sodat die sone skoon lyk (DNS Manager mag ’n sone-herlaai vereis om die aansig te verfris).
- Opsporing: waarsku oor **enige DNS-rekord wat `dynamicObject`/`entryTTL` bevat** via replisering-/event logs; tydelike rekords verskyn selde in standaard DNS-logs.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Nota)

- Entra Connect delta sync maak staat op **tombstones** om uitvee-aksies op te spoor. ’n **dynamic on-prem user** kan met Entra ID sinkroniseer, verval en sonder ’n tombstone uitgevee word—delta sync sal nie die cloud-rekening verwyder nie, wat ’n **weesgebruiker met ’n aktiewe Entra-rekening** laat totdat ’n **initial/full sync** of handmatige cloud-opruiming afgedwing word.<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
