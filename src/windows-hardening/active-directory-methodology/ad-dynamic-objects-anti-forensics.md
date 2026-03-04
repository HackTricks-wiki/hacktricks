# AD Dynamiese Objekte (dynamicObject) Anti-Forensies

{{#include ../../banners/hacktricks-training.md}}

## Meganiese en opsporingsbeginsels

- Enige objek wat met die hulpklas **`dynamicObject`** geskep is, kry **`entryTTL`** (sekondes aftelling) en **`msDS-Entry-Time-To-Die`** (absolute vervaldatum). Wanneer `entryTTL` 0 bereik, verwyder die **Garbage Collector dit sonder tombstone/recycle-bin**, wis die skepper/timestamp en blokkeer herstel.
- TTL kan verfris word deur `entryTTL` op te dateer; min/standaard word afgedwing in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (ondersteun 1s–1y maar val gewoonlik terug na 86,400s/24h). Dynamic objects word nie in Configuration/Schema-partisies ondersteun nie.
- Verwydering kan 'n paar minute agterloop op DCs met kort uptime (<24h), wat 'n noue reaksievenster loslaat om attributte te navraag/backup. Detecteer deur te waarsku oor nuwe objekte wat `entryTTL`/`msDS-Entry-Time-To-Die` dra en dit te korreleer met orphan SIDs/broken links.

## MAQ-ontduiking met selfverwyderende rekenaars

- Verstek **`ms-DS-MachineAccountQuota` = 10** laat enige geauthentiseerde gebruiker rekenaars skep. Voeg `dynamicObject` tydens skepping by om die rekenaar self te laat verwyder en die kwotaslot vry te maak terwyl bewyse uitgevee word.
- Powermad-aanpassing binne `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Kort TTL (bv. 60s) misluk dikwels vir standaardgebruikers; AD val terug na **`DynamicObjectDefaultTTL`** (voorbeeld: 86,400s). ADUC kan `entryTTL` verberg, maar LDP/LDAP-navrae openbaar dit.

## Stil primêre groepslidmaatskap

- Skep 'n dinamiese sekuriteitsgroep, stel dan 'n gebruiker se **`primaryGroupID`** na daardie groep se RID om effektiewe lidmaatskap te verkry wat nie in `memberOf` vertoon nie, maar in Kerberos/toegangs-tokens gehonoreer word.
- Wanneer die TTL verstryk, verwyder dit die groep ondanks primêre-groep verwyderingsbeskerming, wat die gebruiker met 'n gekorrupte `primaryGroupID` laat wat na 'n nie-bestaande RID wys en geen tombstone het om te ondersoek hoe die regte verleen is nie.

## AdminSDHolder wees-SID-besoedeling

- Voeg ACEs vir 'n kortlewende dinamiese gebruiker/groep by `CN=AdminSDHolder,CN=System,...`. Na TTL-verstrykking word die SID onoplosbaar (“Unknown SID”) in die sjabloon ACL, en SDProp (~60 min) propagandeer daardie wees-SID oor alle beskermde Tier-0 objeke.
- Forensika verloor attributie omdat die principal weg is (geen deleted-object DN). Moniteer vir nuwe dinamiese principals + skielike wees-SIDs op AdminSDHolder/privileged ACLs.

## Dinamiese GPO-uitvoering met selfvernietigende bewyse

- Skep 'n dinamiese `groupPolicyContainer`-objek met 'n kwaadwillige **`gPCFileSysPath`** (bv. SMB share à la GPODDITY) en koppel dit via `gPLink` aan 'n teiken-OU.
- Clients verwerk die beleid en trek inhoud van die aanvaler's SMB. Wanneer die TTL verstryk, verdwyn die GPO-objek (en `gPCFileSysPath`); slegs 'n **broken `gPLink`** GUID bly oor, wat LDAP-bewyse van die uitgevoerde payload verwyder.

## Kortstondige AD-geïntegreerde DNS-omleiding

- AD DNS-rekords is `dnsNode`-objekte in DomainDnsZones/ForestDnsZones. Deur dit as dinamiese objekte te skep, is tydelike host-omleidings moontlik (credential capture/MITM). Clients onthou die kwaadwillige A/AAAA-antwoord in cache; die rekord selfverwyder later sodat die zone skoon lyk (DNS Manager mag 'n zone-herlaai benodig om die siening te verfris).
- Detectie: waarsku op enige DNS-rekord wat `dynamicObject`/`entryTTL` dra via replikasie/evet logs; transiente rekords verskyn selde in standaard DNS-logs.

## Hibriede Entra ID Delta-Sync-gat (Nota)

- Entra Connect delta sync berus op tombstones om verwyderings op te spoor. 'n Dynamiese on-prem gebruiker kan na Entra ID sinchroniseer, verval en sonder tombstone verwyder word—delta sync sal nie die cloud-rekening verwyder nie, wat 'n wees-aktiewe Entra-gebruiker agterlaat totdat 'n handmatige full sync gedwing word.

## Verwysings

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
