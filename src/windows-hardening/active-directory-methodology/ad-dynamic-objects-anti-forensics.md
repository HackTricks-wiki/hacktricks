# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanika & Opsporing Basies

- Enige objek geskep met die auxiliary class **`dynamicObject`** kry **`entryTTL`** (sekondes aftelling) en **`msDS-Entry-Time-To-Die`** (absolute vervaldatum). Wanneer `entryTTL` 0 bereik, verwyder die **Garbage Collector** dit sonder tombstone/recycle-bin, wat creator/timestamps uitwis en herstel blokkeer.
- **`entryTTL` is an operational/constructed attribute**: versoek dit eksplisiet in LDAP queries. TTL kan hernu word óf deur `entryTTL` voor verval op te dateer óf via LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL min/default word afgedwing in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft dokumenteer **86400s** as die default TTL en **900s** as die default minimum valid TTL; albei ondersteun **1s–1y**. Dynamic objects is **unsupported in Configuration/Schema partitions**.
- Daar is **no static→dynamic conversion** en geen tombstone-fase na verval nie. IR teams kan nie op deleted-object controls of Recycle Bin staatmaak nie; hulle moet die live object/metadata vasvang voordat GC dit verwyder.
- Refresh is **replica-sensitive**: as TTL te naby aan verval hernu word, kan ’n ander writable replica of GC steeds die objek plaaslik verwyder voordat die refresh replikeer. Baie kort TTLs werk dus die beste wanneer die attacker weet watter DC die abuse sal diens, terwyl defenders **all naming contexts / replicas** tydens triage moet query.
- Verwydering kan ’n paar minute vertraag op DCs met kort uptime (<24h), wat ’n nou response window laat om attributes te query/backup. Detect deur **alerting on new objects carrying `entryTTL`/`msDS-Entry-Time-To-Die`** en korreleer met orphan SIDs/broken links.

## Fast Enumeration / Live Triage

- Query **all `namingContexts` from RootDSE**, nie net die domain NC nie. Dynamic abuse kan leef in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) of in application partitions.
- Terwyl die objek nog leef, dump onmiddellik **replication metadata** en enige linked attributes/ACLs. Ná verval mag jy net met **broken `gPLink` values, orphan SIDs, or cached DNS answers** oorbly.
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

- Default **`ms-DS-MachineAccountQuota` = 10** laat enige geverifieerde gebruiker toe om computers te skep. Voeg `dynamicObject` by tydens skepping om die computer self te laat delete en die **quota slot vry te maak** terwyl bewyse uitgevee word.
- Powermad tweak inside `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- If the requested TTL is **below `DynamicObjectMinTTL`**, expect server-side adjustment or rejection depending on the creation path; in many domains the effective floor is **900s** and the fallback/default remains **86400s**. ADUC may hide `entryTTL`, but LDP/LDAP queries reveal it.
- While the object exists, defenders can still recover the unprivileged creator from **`msDS-CreatorSID`** on the computer object. Once the dynamic computer expires, that attribution disappears with the object.

## Stealth Primary Group Membership

- Create a **dynamic security group**, then set a user’s **`primaryGroupID`** to that group’s RID to gain effective membership that **doesn’t show in `memberOf`** but is honored in Kerberos/access tokens.
- TTL expiry **deletes the group despite primary-group delete protection**, leaving the user with a corrupted `primaryGroupID` pointing to a non-existent RID and no tombstone to investigate how the privilege was granted.
- Reporting is tool-dependent: **`Get-ADGroupMember` / `net group`** usually resolve primary-group-derived membership, while **`memberOf`** and **`Get-ADGroup -Properties member`** do not. For broader `primaryGroupID` tradecraft, see [this other page about DCShadow and PGID abuse](dcshadow.md).
- For **non-AdminSDHolder-protected** targets, attackers can pair the dynamic-group trick with a **DACL deny on reading `primaryGroupID`** (or the group `member` attribute) to hide the link from many LDAP/PowerShell workflows even before the group expires.

## AdminSDHolder Orphan-SID Pollution

- Add ACEs for a **short-lived dynamic user/group** to **`CN=AdminSDHolder,CN=System,...`**. After TTL expiry the SID becomes **unresolvable (“Unknown SID”)** in the template ACL, and **SDProp (~60 min)** propagates that orphan SID across all protected Tier-0 objects.
- Forensics lose attribution because the principal is gone (no deleted-object DN). Monitor for **new dynamic principals + sudden orphan SIDs on AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Create a **dynamic `groupPolicyContainer`** object with a malicious **`gPCFileSysPath`** (e.g., SMB share à la GPODDITY) and **link it via `gPLink`** to a target OU.
- Clients process the policy and pull content from attacker SMB. When TTL expires, the GPO object (and `gPCFileSysPath`) vanishes; only a **broken `gPLink`** GUID remains, removing LDAP evidence of the executed payload.
- This is operationally cleaner than classic **GPODDITY-style** cleanup: instead of restoring the original `gPCFileSysPath` yourself, AD removes the malicious GPC automatically once the timer expires.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records are **`dnsNode`** objects in **DomainDnsZones/ForestDnsZones**. Creating them as **dynamic objects** allows temporary host redirection (credential capture/MITM). Clients cache the malicious A/AAAA response; the record later self-deletes so the zone looks clean (DNS Manager may need zone reload to refresh view).
- Detection: alert on **any DNS record carrying `dynamicObject`/`entryTTL`** via replication/event logs; transient records rarely appear in standard DNS logs.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync relies on **tombstones** to detect deletes. A **dynamic on-prem user** can sync to Entra ID, expire, and delete without tombstone—delta sync won’t remove the cloud account, leaving an **orphaned active Entra user** until an **initial/full sync** or manual cloud cleanup is forced.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
