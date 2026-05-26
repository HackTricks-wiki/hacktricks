# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- किसी भी object को auxiliary class **`dynamicObject`** के साथ बनाया गया हो, उसे **`entryTTL`** (seconds countdown) और **`msDS-Entry-Time-To-Die`** (absolute expiry) मिलते हैं। जब `entryTTL` 0 पर पहुंचता है, **Garbage Collector** उसे **tombstone/recycle-bin** के बिना delete कर देता है, जिससे creator/timestamps मिट जाते हैं और recovery block हो जाती है।
- **`entryTTL` एक operational/constructed attribute** है: इसे LDAP queries में explicitly request करें। TTL को या तो expiry से पहले `entryTTL` update करके, या LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** के जरिए refresh किया जा सकता है।
- TTL min/default **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** में enforced होते हैं। Microsoft default TTL के रूप में **86400s** और default minimum valid TTL के रूप में **900s** document करता है; दोनों **1s–1y** support करते हैं। Dynamic objects **Configuration/Schema partitions** में unsupported हैं।
- static→dynamic conversion नहीं होती और expiry के बाद tombstone phase भी नहीं आता। IR teams deleted-object controls या Recycle Bin पर भरोसा नहीं कर सकतीं; उन्हें GC द्वारा हटाए जाने से पहले live object/metadata capture करना होगा।
- Refresh **replica-sensitive** है: अगर TTL को expiry के बहुत पास renew किया जाए, तो कोई दूसरा writable replica या GC refresh replicate होने से पहले ही object को locally delete कर सकता है। इसलिए बहुत short TTLs तब सबसे अच्छे होते हैं जब attacker को पता हो कि abuse किस DC पर service होगा, जबकि defenders triage के दौरान **all naming contexts / replicas** query करें।
- Deletion कुछ minutes तक lag कर सकती है उन DCs पर जिनका uptime short हो (<24h), जिससे attributes query/backup करने के लिए एक narrow response window मिलता है। Detection के लिए **new objects जिनमें `entryTTL`/`msDS-Entry-Time-To-Die` हो** पर alert करें और orphan SIDs/broken links के साथ correlate करें।

## Fast Enumeration / Live Triage

- केवल domain NC नहीं, बल्कि RootDSE से **all `namingContexts`** query करें। Dynamic abuse **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) या application partitions में हो सकती है।
- जब object अभी भी alive हो, तुरंत **replication metadata** और कोई भी linked attributes/ACLs dump करें। Expiry के बाद आपके पास सिर्फ **broken `gPLink` values, orphan SIDs, या cached DNS answers** रह सकते हैं।
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion with Self-Deleting Computers

- Default **`ms-DS-MachineAccountQuota` = 10** lets any authenticated user create computers. Add `dynamicObject` during creation to have the computer self-delete and **free the quota slot** while wiping evidence.
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
