# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Any object created with the auxiliary class **`dynamicObject`** gains **`entryTTL`** (seconds countdown) and **`msDS-Entry-Time-To-Die`** (absolute expiry). When `entryTTL` reaches 0 the **Garbage Collector deletes it without tombstone/recycle-bin**, erasing creator/timestamps and blocking recovery.
- **`entryTTL` is an operational/constructed attribute**: request it explicitly in LDAP queries. TTL can be refreshed either by updating `entryTTL` before expiry or via LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL min/default are enforced in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft documents **86400s** as the default TTL and **900s** as the default minimum valid TTL; both support **1s–1y**. Dynamic objects are **unsupported in Configuration/Schema partitions**.
- There is **no static→dynamic conversion** and no tombstone phase after expiry. IR teams cannot rely on deleted-object controls or Recycle Bin; they must capture the live object/metadata before GC removes it.
- Refresh is **replica-sensitive**: if TTL is renewed too close to expiry, another writable replica or GC can still delete the object locally before the refresh replicates. Very short TTLs therefore work best when the attacker knows which DC will service the abuse, while defenders should query **all naming contexts / replicas** during triage.
- Deletion can lag a few minutes on DCs with short uptime (<24h), leaving a narrow response window to query/backup attributes. Detect by **alerting on new objects carrying `entryTTL`/`msDS-Entry-Time-To-Die`** and correlating with orphan SIDs/broken links.<sup>[[1]](#references)</sup>

## Fast Enumeration / Live Triage

- Query **all `namingContexts` from RootDSE**, not only the domain NC. Dynamic abuse can live in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) or in application partitions.
- While the object is still alive, immediately dump **replication metadata** and any linked attributes/ACLs. After expiry you may be left only with **broken `gPLink` values, orphan SIDs, or cached DNS answers**.<sup>[[1]](#references)</sup>

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
- While the object exists, defenders can still recover the unprivileged creator from **`msDS-CreatorSID`** on the computer object. Once the dynamic computer expires, that attribution disappears with the object.<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- Create a **dynamic security group**, then set a user’s **`primaryGroupID`** to that group’s RID to gain effective membership that **doesn’t show in `memberOf`** but is honored in Kerberos/access tokens.<sup>[[1]](#references)</sup>
- TTL expiry **deletes the group despite primary-group delete protection**, leaving the user with a corrupted `primaryGroupID` pointing to a non-existent RID and no tombstone to investigate how the privilege was granted.
- Reporting is tool-dependent: **`Get-ADGroupMember` / `net group`** usually resolve primary-group-derived membership, while **`memberOf`** and **`Get-ADGroup -Properties member`** do not. For broader `primaryGroupID` tradecraft, see [this other page about DCShadow and PGID abuse](dcshadow.md).
- For **non-AdminSDHolder-protected** targets, attackers can pair the dynamic-group trick with a **DACL deny on reading `primaryGroupID`** (or the group `member` attribute) to hide the link from many LDAP/PowerShell workflows even before the group expires.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- Add ACEs for a **short-lived dynamic user/group** to **`CN=AdminSDHolder,CN=System,...`**. After TTL expiry the SID becomes **unresolvable (“Unknown SID”)** in the template ACL, and **SDProp (~60 min)** propagates that orphan SID across all protected Tier-0 objects.
- Forensics lose attribution because the principal is gone (no deleted-object DN). Monitor for **new dynamic principals + sudden orphan SIDs on AdminSDHolder/privileged ACLs**.<sup>[[1]](#references)</sup>

## Dynamic GPO Execution with Self-Destructing Evidence

- Create a **dynamic `groupPolicyContainer`** object with a malicious **`gPCFileSysPath`** (e.g., SMB share à la GPODDITY) and **link it via `gPLink`** to a target OU.
- Clients process the policy and pull content from attacker SMB. When TTL expires, the GPO object (and `gPCFileSysPath`) vanishes; only a **broken `gPLink`** GUID remains, removing LDAP evidence of the executed payload.
- This is operationally cleaner than classic **GPODDITY-style** cleanup: instead of restoring the original `gPCFileSysPath` yourself, AD removes the malicious GPC automatically once the timer expires.<sup>[[1]](#references)</sup>

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records are **`dnsNode`** objects in **DomainDnsZones/ForestDnsZones**. Creating them as **dynamic objects** allows temporary host redirection (credential capture/MITM). Clients cache the malicious A/AAAA response; the record later self-deletes so the zone looks clean (DNS Manager may need zone reload to refresh view).
- Detection: alert on **any DNS record carrying `dynamicObject`/`entryTTL`** via replication/event logs; transient records rarely appear in standard DNS logs.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync relies on **tombstones** to detect deletes. A **dynamic on-prem user** can sync to Entra ID, expire, and delete without tombstone—delta sync won’t remove the cloud account, leaving an **orphaned active Entra user** until an **initial/full sync** or manual cloud cleanup is forced.<sup>[[1]](#references)</sup>

## References

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
