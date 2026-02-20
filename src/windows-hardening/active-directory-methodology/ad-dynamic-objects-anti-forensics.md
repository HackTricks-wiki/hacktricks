# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Any object created with the auxiliary class **`dynamicObject`** gains **`entryTTL`** (seconds countdown) and **`msDS-Entry-Time-To-Die`** (absolute expiry). When `entryTTL` reaches 0 the **Garbage Collector deletes it without tombstone/recycle-bin**, erasing creator/timestamps and blocking recovery.
- TTL can be refreshed by updating `entryTTL`; min/default are enforced in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (supports 1s–1y but commonly defaults to 86,400s/24h). Dynamic objects are **unsupported in Configuration/Schema partitions**.
- Deletion can lag a few minutes on DCs with short uptime (<24h), leaving a narrow response window to query/backup attributes. Detect by **alerting on new objects carrying `entryTTL`/`msDS-Entry-Time-To-Die`** and correlating with orphan SIDs/broken links.

## MAQ Evasion with Self-Deleting Computers

- Default **`ms-DS-MachineAccountQuota` = 10** lets any authenticated user create computers. Add `dynamicObject` during creation to have the computer self-delete and **free the quota slot** while wiping evidence.
- Powermad tweak inside `New-MachineAccount` (objectClass list):
  ```powershell
  $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
  ```
- Short TTL (e.g., 60s) often fails for standard users; AD falls back to **`DynamicObjectDefaultTTL`** (example: 86,400s). ADUC may hide `entryTTL`, but LDP/LDAP queries reveal it.

## Stealth Primary Group Membership

- Create a **dynamic security group**, then set a user’s **`primaryGroupID`** to that group’s RID to gain effective membership that **doesn’t show in `memberOf`** but is honored in Kerberos/access tokens.
- TTL expiry **deletes the group despite primary-group delete protection**, leaving the user with a corrupted `primaryGroupID` pointing to a non-existent RID and no tombstone to investigate how the privilege was granted.

## AdminSDHolder Orphan-SID Pollution

- Add ACEs for a **short-lived dynamic user/group** to **`CN=AdminSDHolder,CN=System,...`**. After TTL expiry the SID becomes **unresolvable (“Unknown SID”)** in the template ACL, and **SDProp (~60 min)** propagates that orphan SID across all protected Tier-0 objects.
- Forensics lose attribution because the principal is gone (no deleted-object DN). Monitor for **new dynamic principals + sudden orphan SIDs on AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Create a **dynamic `groupPolicyContainer`** object with a malicious **`gPCFileSysPath`** (e.g., SMB share à la GPODDITY) and **link it via `gPLink`** to a target OU.
- Clients process the policy and pull content from attacker SMB. When TTL expires, the GPO object (and `gPCFileSysPath`) vanishes; only a **broken `gPLink`** GUID remains, removing LDAP evidence of the executed payload.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records are **`dnsNode`** objects in **DomainDnsZones/ForestDnsZones**. Creating them as **dynamic objects** allows temporary host redirection (credential capture/MITM). Clients cache the malicious A/AAAA response; the record later self-deletes so the zone looks clean (DNS Manager may need zone reload to refresh view).
- Detection: alert on **any DNS record carrying `dynamicObject`/`entryTTL`** via replication/event logs; transient records rarely appear in standard DNS logs.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync relies on **tombstones** to detect deletes. A **dynamic on-prem user** can sync to Entra ID, expire, and delete without tombstone—delta sync won’t remove the cloud account, leaving an **orphaned active Entra user** until a manual **full sync** is forced.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
