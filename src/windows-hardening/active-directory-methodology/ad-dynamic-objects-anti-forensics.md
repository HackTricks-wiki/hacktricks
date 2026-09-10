# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- 補助クラス **`dynamicObject`** で作成されたオブジェクトには、**`entryTTL`**（秒単位のカウントダウン）と **`msDS-Entry-Time-To-Die`**（絶対有効期限）が付与されます。`entryTTL` が 0 に達し、**かつオブジェクトに子孫が存在しない場合**、Garbage Collector は tombstone/recycle-bin を経由せずに削除します。これにより作成者やタイムスタンプが消去され、復旧が阻止されます。<sup>[[4]](#references)</sup>
- **`entryTTL` は operational/constructed attribute** です。LDAP クエリで明示的に要求してください。TTL は、有効期限前に `entryTTL` を更新するか、LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** を使用して更新できます。
- TTL の最小値およびデフォルト値は、**`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`** にある forest 全体の AVA で、`DynamicObjectMinTTLSeconds=<seconds>` および `DynamicObjectDefaultTTLSeconds=<seconds>` として設定されます。Microsoft のドキュメントでは、デフォルト TTL は **86400s**、有効な TTL のデフォルト最小値は **900s** とされています。`entryTTL` の schema 範囲は **1–31557600s**（1 秒から 1 年）です。<sup>[[3]](#references)</sup> Dynamic objects は **Configuration/Schema partitions** ではサポートされません。
- **static→dynamic conversion** は存在せず、有効期限切れ後に tombstone フェーズもありません。IR チームは deleted-object controls や Recycle Bin に依存できず、GC が削除する前に live object/metadata を取得する必要があります。
- Refresh は **replica-sensitive** です。TTL の更新が有効期限の直前すぎる場合、別の writable replica や GC が、refresh のレプリケーション前にそのローカル上のオブジェクトを削除する可能性があります。そのため、非常に短い TTL は、攻撃者が abuse を処理する DC を把握している場合に最も効果的です。一方、防御側は triage 中に **すべての naming contexts / replicas** をクエリする必要があります。
- 短い uptime（<24h）の DC では削除が数分遅延することがあり、属性をクエリ/バックアップするための狭い response window が残る可能性があります。**`entryTTL`/`msDS-Entry-Time-To-Die` を持つ新規オブジェクト**に対する alert と、orphan SID/broken link を相関させて検出します。<sup>[[1]](#references)</sup>

### Expiry graph and reference-cleanup edge cases

- Dynamic object 配下のすべての子孫も dynamic でなければなりません。有効期限切れの dynamic parent は leaf になった後でのみ garbage-collected されます。子孫の `msDS-Entry-Time-To-Die` がより遅い場合、DC は parent の有効期限を、子孫の有効期限の最大値を超えるように延長します。その結果、writable dynamic subtree が、まもなく消えるように見える parent を **pin/extend** できます。subtree 全体を列挙し、parent で観測した `entryTTL` を cleanup deadline として使用しないでください。<sup>[[4]](#references)</sup>
- Expiry cleanup は **schema-link-aware** です。Replica は、削除された dynamic object を参照する linked attribute の値を削除しますが、nonlinked value は保持します。通常の forward/back-link membership は cleanup される一方、`primaryGroupID`、`nTSecurityDescriptor` に埋め込まれた SID、`gPLink` の text などの integer/SID/string reference は forensic residue として残る可能性があります。<sup>[[4]](#references)</sup>

## Fast Enumeration / Live Triage

- **RootDSE からすべての `namingContexts` をクエリ**し、domain NC だけに限定しないでください。Dynamic abuse は **`DomainDnsZones`/`ForestDnsZones`**（`dnsNode`）または application partitions に存在する可能性があります。
- オブジェクトがまだ live である間に、**replication metadata** と linked attributes/ACLs を直ちに dump してください。有効期限切れ後は、**broken `gPLink` values、orphan SID、cached DNS answers** だけが残る可能性があります。<sup>[[1]](#references)</sup>
```powershell
(Get-ADForest).Domains | ForEach-Object {
Get-ADDomainController -Filter * -Server $_ | ForEach-Object {
$dc = $_.HostName
(Get-ADRootDSE -Server $dc).namingContexts | ForEach-Object {
Get-ADObject -Server $dc -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object @{n='DC';e={$dc}},DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
}
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Self-Deleting Computersによる MAQ Evasion

- デフォルトの **`ms-DS-MachineAccountQuota` = 10** により、認証済みユーザーは誰でもコンピューターを作成できます。作成時に `dynamicObject` を追加すると、コンピューターが自動削除され、証拠を消去しながら **quota slot** を解放できます。
- `New-MachineAccount` 内の Powermad tweak（objectClass list）:
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 要求した TTL が **`DynamicObjectMinTTL`** 未満の場合、作成経路に応じて server-side adjustment または rejection が発生します。多くの domain では実効的な下限が **900s** で、fallback/default は **86400s** のままです。ADUC では `entryTTL` が非表示になることがありますが、LDP/LDAP queries では確認できます。
- オブジェクトが存在する間は、defender は computer object の **`msDS-CreatorSID`** から unprivileged creator を特定できます。dynamic computer が期限切れになると、その attribution もオブジェクトとともに消失します。<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- **dynamic security group** を作成し、ユーザーの **`primaryGroupID`** をその group の RID に設定すると、`memberOf` には表示されないものの、Kerberos/access tokens では認識される実効的な membership を取得できます。<sup>[[1]](#references)</sup>
- TTL expiry により、primary-group delete protection にもかかわらず group が削除されます。その結果、ユーザーには存在しない RID を指す壊れた `primaryGroupID` が残り、privilege がどのように付与されたかを調査する tombstone も残りません。
- Reporting は tool に依存します。**`Get-ADGroupMember` / `net group`** は通常、primary-group-derived membership を解決しますが、**`memberOf`** と **`Get-ADGroup -Properties member`** は解決しません。より広範な `primaryGroupID` tradecraft については、[DCShadow と PGID abuse に関するこちらの別ページ](dcshadow.md)を参照してください。
- **non-AdminSDHolder-protected** な target では、attackers は dynamic-group trick と **`primaryGroupID` の読み取りに対する DACL deny**（または group の `member` attribute に対する deny）を組み合わせることで、group が expiry する前から多くの LDAP/PowerShell workflows で link を隠せます。<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- **short-lived dynamic user/group** の ACEs を **`CN=AdminSDHolder,CN=System,...`** に追加します。TTL expiry 後、SID は template ACL 内で **unresolvable（“Unknown SID”）** になり、**SDProp（約60分）** がその orphan SID をすべての protected Tier-0 objects に伝播します。
- principal が存在しないため（deleted-object DN もない）、forensics では attribution が失われます。**new dynamic principals + AdminSDHolder/privileged ACLs 上の sudden orphan SIDs** を監視してください。<sup>[[1]](#references)</sup>

## Self-Destructing Evidenceによる Dynamic GPO Execution

- 悪意のある **`gPCFileSysPath`**（GPODDITY のような SMB share など）を持つ **dynamic `groupPolicyContainer`** object を作成し、**`gPLink`** で target OU に link します。
- Clients は policy を処理し、attacker の SMB から content を取得します。TTL が expiry すると、GPO object（および `gPCFileSysPath`）が消失します。**broken `gPLink`** GUID だけが残り、実行された payload の LDAP evidence が除去されます。
- これは classic **GPODDITY-style** cleanup より operationally cleaner です。元の `gPCFileSysPath` を自分で復元する代わりに、timer の expiry 時に AD が悪意のある GPC を自動的に削除します。<sup>[[1]](#references)</sup> protocol と tooling の詳細については、ここで重複して説明する代わりに [ACL persistence abuse](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) を参照してください。

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records は **`dnsNode`** objects として **DomainDnsZones/ForestDnsZones** に存在します。これらを **dynamic objects** として作成すると、一時的な host redirection（credential capture/MITM）が可能になります。Clients は悪意のある A/AAAA response を cache し、その後 record は自動削除されるため、zone は clean に見えます（view を更新するには DNS Manager で zone reload が必要な場合があります）。
- Detection: replication/event logs を通じて、**`dynamicObject`/`entryTTL`** を持つ **any DNS record** に alert を設定します。一時的な records は standard DNS logs にほとんど現れません。<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap（Note）

- Entra Connect delta sync は deletes の検出に **tombstones** を使用します。**dynamic on-prem user** は Entra ID に sync された後、expiry して tombstone なしで delete される可能性があります。delta sync では cloud account が削除されず、**initial/full sync** または手動の cloud cleanup が強制されるまで、**orphaned active Entra user** が残ります。<sup>[[1]](#references)</sup>



## References

- [1] [Active Directory の Dynamic Objects: Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Primary Group の動作、Reporting、Exploit に関する Adventures](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [TTL Limits の設定](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: DynamicObject Requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
