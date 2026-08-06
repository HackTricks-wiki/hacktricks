# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## 仕組みと検出の基礎

- **`dynamicObject`** auxiliary class を使用して作成されたオブジェクトは、**`entryTTL`**（秒単位のカウントダウン）と **`msDS-Entry-Time-To-Die`**（絶対有効期限）を持つようになります。**`entryTTL`** が 0 になると、**Garbage Collector** が tombstone/recycle-bin を経由せずに削除するため、作成者やタイムスタンプが消去され、復旧できなくなります。
- **`entryTTL`** は operational/constructed attribute です。LDAP クエリで明示的に要求してください。TTL は、有効期限前に **`entryTTL`** を更新するか、LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** によって更新できます。
- TTL の最小値とデフォルト値は、**Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** で適用されます。Microsoft のドキュメントでは、デフォルト TTL は **86400s**、有効な TTL のデフォルト最小値は **900s** とされており、どちらも **1s～1y** をサポートします。Dynamic objects は **Configuration/Schema partitions** ではサポートされません。
- **static→dynamic conversion** は存在せず、有効期限後に tombstone フェーズもありません。IR チームは deleted-object controls や Recycle Bin に依存できないため、GC が削除する前に live object/metadata を取得する必要があります。
- Refresh は **replica-sensitive** です。TTL の更新が有効期限に近すぎる場合、別の writable replica または GC が、refresh のレプリケーション前にローカルでオブジェクトを削除する可能性があります。そのため、非常に短い TTL は、攻撃者が abuse を処理する DC を把握している場合に最も効果的です。一方、defender は triage 中に **すべての naming contexts / replicas** をクエリする必要があります。
- 削除は、uptime が短い（<24h）DC では数分遅延することがあり、属性をクエリ/backup できる狭い response window が残ります。**`entryTTL`** / **`msDS-Entry-Time-To-Die`** を持つ新規オブジェクトに対して **alerting** を行い、orphan SIDs/broken links と相関させて検出します。<sup>[[1]](#references)</sup>

## Fast Enumeration / Live Triage

- **RootDSE からすべての `namingContexts` をクエリ**してください。domain NC だけを対象にしてはいけません。Dynamic abuse は **`DomainDnsZones`/`ForestDnsZones`**（`dnsNode`）や application partitions に存在する可能性があります。
- オブジェクトがまだ live の間に、直ちに **replication metadata** と、関連する linked attributes/ACLs を dump してください。有効期限後には、**broken `gPLink` values、orphan SIDs、または cached DNS answers** だけが残る可能性があります。<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Self-Deleting ComputersによるMAQ Evasion

- デフォルトの **`ms-DS-MachineAccountQuota` = 10** により、認証済みユーザーは誰でもコンピューターを作成できます。作成時に `dynamicObject` を追加すると、そのコンピューターは自動削除され、証拠を消去しながら quota slot を解放します。
- `New-MachineAccount` 内のPowermad tweak（objectClass list）:
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 要求したTTLが `DynamicObjectMinTTL` 未満の場合、作成パスに応じて server-side adjustment または rejection が発生します。多くのドメインでは実効的な下限は **900s** で、fallback/default は **86400s** のままです。ADUCでは `entryTTL` が非表示になる場合がありますが、LDP/LDAP queriesでは確認できます。
- オブジェクトが存在する間は、defendersはコンピューターオブジェクトの **`msDS-CreatorSID`** からunprivileged creatorを特定できます。dynamic computerの期限が切れると、オブジェクトとともにその attributionも消失します。<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- **dynamic security group** を作成し、ユーザーの **`primaryGroupID`** をそのグループのRIDに設定すると、`memberOf` には表示されない一方で、Kerberos/access tokensでは有効なmembershipを得られます。<sup>[[1]](#references)</sup>
- TTL expiryにより、primary-group delete protectionにもかかわらずグループが削除されます。その結果、ユーザーには存在しないRIDを指す壊れた `primaryGroupID` が残り、権限がどのように付与されたかを調査するtombstoneも残りません。
- Reportingはtool-dependentです。通常、**`Get-ADGroupMember` / `net group`** はprimary-group-derived membershipを解決しますが、**`memberOf`** と **`Get-ADGroup -Properties member`** は解決しません。より広範な `primaryGroupID` tradecraftについては、[this other page about DCShadow and PGID abuse](dcshadow.md)を参照してください。
- **non-AdminSDHolder-protected** targetsでは、attackersはdynamic-group trickと **`primaryGroupID` の読み取りに対するDACL deny**（またはグループの `member` attributeへのdeny）を組み合わせることで、グループの期限が切れる前から、多くのLDAP/PowerShell workflowsでこのlinkを隠せます。<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- **short-lived dynamic user/group** のACEを **`CN=AdminSDHolder,CN=System,...`** に追加します。TTL expiry後、template ACL内のSIDは**解決不能（“Unknown SID”）**となり、**SDProp（~60 min）** がそのorphan SIDを保護対象のTier-0 objects全体にpropagateします。
- principalが消失するため（deleted-object DNなし）、forensicsではattributionが失われます。**new dynamic principals + AdminSDHolder/privileged ACLs上のsudden orphan SIDs** をmonitorしてください。<sup>[[1]](#references)</sup>

## Self-Destructing EvidenceによるDynamic GPO Execution

- 悪意のある **`gPCFileSysPath`**（GPODDITYのようなSMB shareなど）を持つ **dynamic `groupPolicyContainer`** objectを作成し、**`gPLink`** 経由でtarget OUにlinkします。
- Clientsはpolicyを処理し、attacker SMBからcontentを取得します。TTLが期限切れになると、GPO object（および `gPCFileSysPath`）が消失します。実行されたpayloadのLDAP evidenceは削除され、**broken `gPLink`** GUIDだけが残ります。
- これはclassic **GPODDITY-style** cleanupよりもoperationally cleanerです。元の `gPCFileSysPath` を自分でrestoreする代わりに、timerの期限切れ時にADが悪意のあるGPCを自動的に削除します。<sup>[[1]](#references)</sup>

## Ephemeral AD-Integrated DNS Redirection

- AD DNS recordsは **DomainDnsZones/ForestDnsZones** 内の **`dnsNode`** objectsです。これらをdynamic objectsとして作成すると、一時的なhost redirection（credential capture/MITM）が可能になります。Clientsは悪意のあるA/AAAA responseをcacheし、その後recordが自動削除されるため、zoneはcleanに見えます（viewをrefreshするにはDNS Managerでzone reloadが必要な場合があります）。
- Detection: replication/event logs経由で **`dynamicObject`/`entryTTL`** を持つ**あらゆるDNS record**にalertを設定します。一時的なrecordsはstandard DNS logsにはほとんど現れません。<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap（Note）

- Entra Connect delta syncは、deleteを検出するために **tombstones** に依存します。**dynamic on-prem user** はEntra IDにsyncされた後、期限切れとなり、tombstoneなしでdeleteされる可能性があります。この場合、delta syncではcloud accountが削除されず、**initial/full sync** またはmanual cloud cleanupを強制するまで、**orphaned active Entra user** が残ります。<sup>[[1]](#references)</sup>

## References

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
