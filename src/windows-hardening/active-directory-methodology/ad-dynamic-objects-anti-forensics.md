# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Enige objek wat geskep is met die auxiliary class **`dynamicObject`** kry **`entryTTL`** (sekondes aftelling) en **`msDS-Entry-Time-To-Die`** (absolute vervaldatum). Wanneer `entryTTL` 0 bereik, verwyder die **Garbage Collector** dit sonder tombstone/recycle-bin, wat skepper/tydstempels uitwis en herstel blokkeer.
- **`entryTTL` is 'n operational/constructed attribute**: versoek dit eksplisiet in LDAP queries. TTL kan verfris word óf deur `entryTTL` op te dateer voor verval óf via LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL min/default word afgedwing in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft dokumenteer **86400s** as die default TTL en **900s** as die default minimum geldige TTL; albei ondersteun **1s–1y**. Dynamic objects is **unsupported in Configuration/Schema partitions**.
- Daar is **geen static→dynamic conversion** en geen tombstone-fase na verval nie. IR teams kan nie op deleted-object controls of Recycle Bin staatmaak nie; hulle moet die live object/metadata vasvang voordat GC dit verwyder.
- Refresh is **replica-sensitive**: as TTL te naby aan verval vernuwe word, kan 'n ander writable replica of GC steeds die object lokaal verwyder voordat die refresh replikeer. Baie kort TTLs werk dus die beste wanneer die attacker weet watter DC die abuse sal hanteer, terwyl defenders **all naming contexts / replicas** tydens triage moet query.
- Verwydering kan 'n paar minute agterbly op DCs met kort uptime (<24h), wat 'n nou response window laat om attributes te query/backup. Detecteer deur **alerting op nuwe objects wat `entryTTL`/`msDS-Entry-Time-To-Die` dra** en dit te korreleer met orphan SIDs/broken links.

## Fast Enumeration / Live Triage

- Query **all `namingContexts` from RootDSE**, nie net die domain NC nie. Dynamic abuse kan leef in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) of in application partitions.
- Terwyl die object nog leef, dump onmiddellik **replication metadata** en enige linked attributes/ACLs. Na verval kan jy net oorbly met **broken `gPLink` values, orphan SIDs, of cached DNS answers**.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion met Self-Deleting Computers

- Default **`ms-DS-MachineAccountQuota` = 10** laat enige geverifieerde gebruiker toe om computers te skep. Voeg **`dynamicObject`** by tydens skepping sodat die rekenaar homself uitvee en die **quota-sleuf vrystel** terwyl bewyse uitgevee word.
- Powermad tweak binne **`New-MachineAccount`** (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- As die aangevraagde TTL **onder `DynamicObjectMinTTL`** is, verwag server-side aanpassing of verwerping, afhangend van die creation path; in baie domains is die effektiewe vloer **900s** en die fallback/default bly **86400s**. ADUC mag **`entryTTL`** versteek, maar LDP/LDAP queries wys dit.
- Terwyl die object bestaan, kan defenders steeds die unprivileged creator herwin uit **`msDS-CreatorSID`** op die computer object. Sodra die dynamic computer verval, verdwyn daardie attribution saam met die object.

## Stealth Primary Group Membership

- Skep 'n **dynamic security group**, en stel dan 'n user se **`primaryGroupID`** na daardie group se RID om effektiewe membership te kry wat **nie in `memberOf` wys nie** maar wel in Kerberos/access tokens erken word.
- TTL expiry **delete die group ondanks primary-group delete protection**, wat die user met 'n korrupte **`primaryGroupID`** laat wat na 'n nie-bestaande RID wys en geen tombstone laat om te ondersoek hoe die privilege toegeken is nie.
- Reporting is tool-dependent: **`Get-ADGroupMember` / `net group`** los gewoonlik primary-group-derived membership op, terwyl **`memberOf`** en **`Get-ADGroup -Properties member`** dit nie doen nie. Vir breër **`primaryGroupID`** tradecraft, sien [this other page about DCShadow and PGID abuse](dcshadow.md).
- Vir **non-AdminSDHolder-protected** targets kan attackers die dynamic-group trick kombineer met 'n **DACL deny op lees van `primaryGroupID`** (of die group **`member`** attribute) om die link vir baie LDAP/PowerShell workflows te verberg selfs voordat die group verval.

## AdminSDHolder Orphan-SID Pollution

- Voeg ACEs by vir 'n **short-lived dynamic user/group** na **`CN=AdminSDHolder,CN=System,...`**. Na TTL expiry word die SID **onoplosbaar (“Unknown SID”)** in die template ACL, en **SDProp (~60 min)** versprei daardie orphan SID oor alle protected Tier-0 objects.
- Forensics verloor attribution omdat die principal weg is (geen deleted-object DN). Monitor vir **new dynamic principals + sudden orphan SIDs on AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution met Self-Destructing Evidence

- Skep 'n **dynamic `groupPolicyContainer`** object met 'n kwaadwillige **`gPCFileSysPath`** (bv. SMB share à la GPODDITY) en **link dit via `gPLink`** na 'n target OU.
- Clients verwerk die policy en trek content van attacker SMB af. Wanneer TTL verval, verdwyn die GPO object (en **`gPCFileSysPath`**); net 'n **broken `gPLink`** GUID bly oor, wat die LDAP-bewyse van die uitgevoerde payload verwyder.
- Dit is operasioneel skoner as klassieke **GPODDITY-style** cleanup: in plaas daarvan om die oorspronklike **`gPCFileSysPath`** self te herstel, verwyder AD die kwaadwillige GPC outomaties sodra die timer verval.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records is **`dnsNode`** objects in **DomainDnsZones/ForestDnsZones**. Om hulle as **dynamic objects** te skep, laat tydelike host redirection (credential capture/MITM) toe. Clients cache die kwaadwillige A/AAAA response; die record delete later self sodat die zone skoon lyk (DNS Manager mag 'n zone reload nodig hê om die view te refresh).
- Detection: alert op **enige DNS record wat `dynamicObject`/`entryTTL` dra** via replication/event logs; transient records verskyn selde in standaard DNS logs.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync maak staat op **tombstones** om deletes op te spoor. 'n **dynamic on-prem user** kan na Entra ID sync, verval, en delete sonder tombstone—delta sync sal nie die cloud account verwyder nie, wat 'n **orphaned active Entra user** laat totdat 'n **initial/full sync** of handmatige cloud cleanup afgedwing word.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
