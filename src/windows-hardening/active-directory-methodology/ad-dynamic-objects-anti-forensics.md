# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mehanika & Osnove Detekcije

- Svaki objekat kreiran sa pomoćnom klasom **`dynamicObject`** dobija **`entryTTL`** (brojanje unazad u sekundama) i **`msDS-Entry-Time-To-Die`** (apsolutni rok isteka). Kada `entryTTL` dostigne 0, **Garbage Collector ga briše bez tombstone/recycle-bin**, čime se brišu creator/timestamps i blokira oporavak.
- **`entryTTL` je operativni/constructed attribute**: zatraži ga eksplicitno u LDAP upitima. TTL može da se osveži ili ažuriranjem `entryTTL` pre isteka ili preko LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL minimum/default se primenjuju u **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft dokumentuje **86400s** kao podrazumevani TTL i **900s** kao podrazumevani minimalni validni TTL; oba podržavaju **1s–1y**. Dynamic objects su **unsupported u Configuration/Schema partitions**.
- Ne postoji **static→dynamic conversion** i nema tombstone faze nakon isteka. IR timovi ne mogu da se oslanjaju na deleted-object kontrole ili Recycle Bin; moraju da uhvate live objekat/metadata pre nego što ga GC ukloni.
- Osvežavanje je **replica-sensitive**: ako se TTL obnovi preblizu isteku, drugi writable replica ili GC i dalje može lokalno da obriše objekat pre nego što se refresh replicira. Zato veoma kratki TTL-ovi rade najbolje kada napadač zna koji DC će opsluživati abuse, dok defanzivci treba da upituju **sve naming contexts / replica** tokom triage.
- Brisanje može da kasni nekoliko minuta na DC-jevima sa kratkim uptime (<24h), ostavljajući uzak response window za upit/backup atributa. Detektuj tako što ćeš **alertovati na nove objekte koji nose `entryTTL`/`msDS-Entry-Time-To-Die`** i korelisati sa orphan SIDs/broken links.

## Brza Enumeracija / Live Triage

- Upituј **sve `namingContexts` iz RootDSE**, ne samo domain NC. Dynamic abuse može da živi u **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) ili u application partitions.
- Dok je objekat još živ, odmah dumpuj **replication metadata** i sve linked attributes/ACLs. Nakon isteka možda će ostati samo **broken `gPLink` values, orphan SIDs, ili cached DNS answers**.
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
