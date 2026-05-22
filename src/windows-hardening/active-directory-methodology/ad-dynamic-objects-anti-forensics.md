# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanisms & Detection Basics

- **`dynamicObject`** という補助クラスで作成された任意のオブジェクトは、**`entryTTL`**（秒カウントダウン）と **`msDS-Entry-Time-To-Die`**（絶対期限切れ）を取得します。`entryTTL` が 0 に達すると、**Garbage Collector が tombstone/recycle-bin なしで削除**し、作成者/タイムスタンプを消去して復旧を妨げます。
- **`entryTTL` は operational/constructed attribute** です。LDAP クエリで明示的に要求してください。TTL は、期限前に `entryTTL` を更新するか、LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** を使って更新できます。
- TTL の最小値/デフォルトは **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** で適用されます。Microsoft はデフォルト TTL を **86400s**、デフォルトの最小有効 TTL を **900s** と文書化しており、どちらも **1s–1y** をサポートします。Dynamic objects は **Configuration/Schema partitions では unsupported** です。
- 期限切れ後に static→dynamic 変換は **なく**、tombstone フェーズもありません。IR チームは削除済みオブジェクト制御や Recycle Bin に頼れず、GC が削除する前にライブオブジェクト/メタデータを取得する必要があります。
- 更新は **replica-sensitive** です。TTL を期限ぎりぎりで更新すると、別の writable replica または GC が、更新がレプリケートされる前にローカルでオブジェクトを削除する可能性があります。したがって、非常に短い TTL は、攻撃者が悪用を処理する DC を把握している場合に最も有効です。一方、防御側はトリアージ時に **すべての naming contexts / replicas** を照会すべきです。
- 24時間未満の短い稼働時間の DC では、削除が数分遅れることがあり、属性を照会/バックアップするための短い対応ウィンドウが残る場合があります。**`entryTTL`/`msDS-Entry-Time-To-Die` を持つ新規オブジェクトをアラート**し、孤立した SID や壊れたリンクと相関させて検出してください。

## Fast Enumeration / Live Triage

- domain NC だけでなく、RootDSE から **すべての `namingContexts`** を照会してください。Dynamic abuse は **`DomainDnsZones`/`ForestDnsZones`**（`dnsNode`）や application partitions に存在することがあります。
- オブジェクトがまだ生きているうちに、直ちに **replication metadata** と、リンクされた属性/ACL をダンプしてください。期限切れ後に残るのは **壊れた `gPLink` 値、孤立した SID、またはキャッシュされた DNS 応答** だけかもしれません。
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
