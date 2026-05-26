# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Будь-який об’єкт, створений з допоміжним класом **`dynamicObject`**, отримує **`entryTTL`** (зворотний відлік у секундах) і **`msDS-Entry-Time-To-Die`** (абсолютний час завершення). Коли `entryTTL` досягає 0, **Garbage Collector видаляє його без tombstone/recycle-bin**, стираючи creator/timestamps і блокуючи відновлення.
- **`entryTTL` — це operational/constructed attribute**: запитуйте його явно в LDAP queries. TTL можна оновити або шляхом зміни `entryTTL` до завершення терміну, або через LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- Мінімальний/default TTL застосовуються в **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft документує **86400s** як default TTL і **900s** як default minimum valid TTL; обидва підтримують **1s–1y**. Dynamic objects **не підтримуються в Configuration/Schema partitions**.
- Немає переходу **static→dynamic** і немає tombstone-фази після завершення терміну. IR teams не можуть покладатися на deleted-object controls або Recycle Bin; вони мають захопити живий об’єкт/metadata до того, як GC його видалить.
- Refresh є **replica-sensitive**: якщо TTL поновити занадто близько до завершення, інша writable replica або GC все ще можуть локально видалити об’єкт до того, як refresh реплікується. Тому дуже короткі TTL найкраще працюють, коли атакувальник знає, який DC обслуговуватиме abuse, тоді як захисникам слід запитувати **all naming contexts / replicas** під час triage.
- Видалення може затримуватися на кілька хвилин на DCs з коротким uptime (<24h), залишаючи вузьке вікно реагування для запиту/backup атрибутів. Виявляйте це через **alerting on new objects carrying `entryTTL`/`msDS-Entry-Time-To-Die`** та кореляцію з orphan SIDs/broken links.

## Fast Enumeration / Live Triage

- Запитуйте **all `namingContexts` з RootDSE**, не лише domain NC. Dynamic abuse може жити в **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) або в application partitions.
- Поки об’єкт ще живий, негайно витягніть **replication metadata** і будь-які linked attributes/ACLs. Після завершення терміну ви можете залишитися лише з **broken `gPLink` values, orphan SIDs, або cached DNS answers**.
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
