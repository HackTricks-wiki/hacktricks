# AD Dynamiese Objekte (dynamicObject) Anti-Forensika

{{#include ../../banners/hacktricks-training.md}}

## Werking & Opsporing Basies

- Enige objek wat geskep is met die hulpklas **`dynamicObject`** kry **`entryTTL`** (sekondes-aflopende klok) en **`msDS-Entry-Time-To-Die`** (absolute verstryking). Wanneer `entryTTL` 0 bereik, verwyder die **Garbage Collector dit sonder tombstone/recycle-bin**, wat skepper/timestamp-gegevens uitvee en herstel blokkeer.
- TTL kan herverfris word deur `entryTTL` op te dateer; minimum/standaard word afgedwing in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (ondersteun 1s–1j maar gewoonlik verstel op 86,400s/24h). Dynamiese objekte word **nie ondersteun in Configuration/Schema-partisies**.
- Verwydering kan met 'n paar minute agterbly op DCs met kort uptime (<24h), wat 'n noue reaksievenster laat om attribuute te navraag/te rugsteun. Bespeur dit deur **waarskuwings te gee op nuwe objekte wat `entryTTL`/`msDS-Entry-Time-To-Die` dra** en te korreleer met orphan SIDs/broken links.

## MAQ Ontduiking met Self-Verwyderende Rekenars

- Standaard **`ms-DS-MachineAccountQuota` = 10** laat enige geverifieerde gebruiker toe om rekenaars te skep. Voeg `dynamicObject` tydens skepping by sodat die rekenaar self kan uitvee en die kwotaslot vrymaak terwyl bewyse uitgevee word.
- Powermad tweak binne `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Kort TTL (bv. 60s) misluk dikwels vir standaard gebruikers; AD val terug op **`DynamicObjectDefaultTTL`** (byvoorbeeld: 86,400s). ADUC mag `entryTTL` wegsteek, maar LDP/LDAP navrae openbaar dit.

## Sluip Primêre Groeplidmaatskap

- Skep 'n **dynamiese sekuriteitsgroep**, stel dan 'n gebruiker se **`primaryGroupID`** op daardie groep se RID om effektiewe lidmaatskap te kry wat **nie in `memberOf` vertoon nie** maar in Kerberos/access tokens erken word.
- Wanneer TTL verstryk, **verwyder dit die groep ondanks primary-group delete protection**, wat die gebruiker met 'n korrupte `primaryGroupID` los wat na 'n nie-bestaande RID wys en geen tombstone het om te ondersoek hoe die voorreg gegee is nie.

## AdminSDHolder Orphan-SID Besoedeling

- Voeg ACEs vir 'n **kortlewende dynamic user/group** by **`CN=AdminSDHolder,CN=System,...`**. Na TTL verstryk raak die SID **onoplosbaar (“Unknown SID”)** in die templaat-ACL, en **SDProp (~60 min)** propagteer daardie wees-SID oor alle beskermde Tier-0-objekte.
- Forensika verloor toeskrywing omdat die principal weg is (geen deleted-object DN). Monitor vir **nuwe dynamic principals + skielike orphan SIDs op AdminSDHolder/privileged ACLs**.

## Dynamiese GPO-uitvoering met selfvernietigende bewyse

- Skep 'n **dynamic `groupPolicyContainer`** objek met 'n kwaadwillige **`gPCFileSysPath`** (bv. SMB share à la GPODDITY) en **skakel dit via `gPLink`** aan 'n teiken OU.
- Kliënte verwerk die beleid en trek inhoud vanaf die attacker SMB. Wanneer TTL verstryk, verdwyn die GPO-objek (en `gPCFileSysPath`); slegs 'n **gebroke `gPLink`** GUID bly oor, wat die LDAP-bewyse van die uitgevoerde payload verwyder.

## Kortstondige AD-geïntegreerde DNS-omleiding

- AD DNS-records is **`dnsNode`**-objekte in **DomainDnsZones/ForestDnsZones**. Om dit as **dynamic objects** te skep laat tydelike gasheeromleiding toe (credential capture/MITM). Kliënte kas die kwaadwillige A/AAAA-antwoord; die rekord self-verwyder later sodat die zone skoon lyk (DNS Manager mag 'n zone-herlaai benodig om die siening te verfris).
- Opsporing: waarsku op **enige DNS-rekord wat `dynamicObject`/`entryTTL` dra** via replication/event logs; transiente rekords verskyn selde in standaard DNS-logs.

## Hybrid Entra ID Delta-Sync Gap (Nota)

- Entra Connect delta sync vertrou op **tombstones** om deletes te detecteer. 'n **dynamic on-prem user** kan na Entra ID sinchroniseer, verstryk en verwyder sonder tombstone—delta sync sal nie die cloud-rekening verwyder nie, en laat 'n **orphaned active Entra user** totdat 'n handmatige **full sync** gedwing word.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
