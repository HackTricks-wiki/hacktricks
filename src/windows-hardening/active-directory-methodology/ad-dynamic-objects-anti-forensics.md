# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- **`dynamicObject`** の補助クラスで作成された任意のオブジェクトは、**`entryTTL`**（秒カウントダウン）と **`msDS-Entry-Time-To-Die`**（絶対有効期限）を取得します。`entryTTL` が 0 になると、**Garbage Collector が tombstone/recycle-bin なしで削除**し、作成者/タイムスタンプを消去して復旧を妨げます。
- **`entryTTL` は operational/constructed attribute** です。LDAP クエリで明示的に要求してください。TTL は、有効期限前に `entryTTL` を更新するか、LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** を使って更新できます。
- TTL の最小値/デフォルト値は **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** で強制されます。Microsoft はデフォルト TTL を **86400s**、デフォルトの最小有効 TTL を **900s** と文書化しており、どちらも **1s–1y** をサポートします。Dynamic objects は **Configuration/Schema partitions では unsupported** です。
- **static→dynamic の変換はなく**、有効期限切れ後の tombstone フェーズもありません。IR チームは deleted-object controls や Recycle Bin に依存できず、GC が削除する前に live object/metadata を取得する必要があります。
- Refresh は **replica-sensitive** です。TTL の更新が有効期限に近すぎると、別の writable replica や GC が refresh の replication より先にローカルでオブジェクトを削除する可能性があります。そのため、非常に短い TTL は、攻撃者が abuse を処理する DC を把握している場合に最も有効です。一方、防御側は triage 時に **all naming contexts / replicas** を照会すべきです。
- 削除は uptime が短い DC（<24h）で数分遅れることがあり、属性の照会/バックアップのための狭い対応ウィンドウが残ります。**新規オブジェクトに `entryTTL`/`msDS-Entry-Time-To-Die` が付与されていないかを alerting** し、orphan SIDs/broken links と相関させて検出します。

## Fast Enumeration / Live Triage

- domain NC だけでなく、RootDSE から **all `namingContexts`** を照会してください。Dynamic abuse は **`DomainDnsZones`/`ForestDnsZones`**（`dnsNode`）や application partitions に存在し得ます。
- オブジェクトがまだ生きている間に、直ちに **replication metadata** とリンクされた属性/ACL をダンプしてください。期限切れ後は、**broken `gPLink` values、orphan SIDs、または cached DNS answers** しか残らない可能性があります。
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## 自己削除するComputerによるMAQ Evasion

- デフォルトの **`ms-DS-MachineAccountQuota` = 10** により、認証済みユーザーなら誰でもcomputerを作成できる。作成時に `dynamicObject` を追加すると、そのcomputerは自己削除し、**quotaスロットを解放**しつつ証拠も消せる。
- Powermad の `New-MachineAccount` 内の調整（objectClass list）:
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 要求した TTL が **`DynamicObjectMinTTL`** を下回る場合、作成経路に応じてサーバー側で調整されるか拒否される。多くのドメインでは有効な下限は **900s** で、fallback/default は **86400s** のまま。ADUC は `entryTTL` を隠すことがあるが、LDP/LDAP クエリでは確認できる。
- object が存在している間、defender は computer object 上の **`msDS-CreatorSID`** から、権限のない作成者をまだ復元できる。dynamic computer が期限切れになると、その attribution も object と一緒に消える。

## ステルス Primary Group Membership

- **dynamic security group** を作成し、ユーザーの **`primaryGroupID`** をその group の RID に設定すると、`memberOf` には表示されないが Kerberos/access tokens では有効な membership を得られる。
- TTL 期限切れは、**primary-group delete protection を無視して group を削除**するため、ユーザーには存在しない RID を指す壊れた `primaryGroupID` だけが残り、権限がどう付与されたかを調べる tombstone も残らない。
- レポート結果は tool 依存: **`Get-ADGroupMember` / `net group`** は通常 primary-group 由来の membership を解決する一方、**`memberOf`** と **`Get-ADGroup -Properties member`** はしない。`primaryGroupID` のより広い tradecraft については、[DCShadow と PGID abuse に関する別ページ](dcshadow.md) を参照。
- **AdminSDHolder 保護されていない** target では、attacker は dynamic-group の手法に加えて、**`primaryGroupID`**（または group の `member` attribute）の読み取りに対する **DACL deny** を組み合わせることで、group が期限切れになる前から多くの LDAP/PowerShell ワークフローから link を隠せる。

## AdminSDHolder Orphan-SID Pollution

- **短命の dynamic user/group** に対する ACE を **`CN=AdminSDHolder,CN=System,...`** に追加する。TTL 期限切れ後、その SID は template ACL 内で **解決不能（“Unknown SID”）** となり、**SDProp (~60 min)** がその orphan SID をすべての保護された Tier-0 object に伝播する。
- principal が消えるため（deleted-object DN もない）、forensics では attribution を失う。**新しい dynamic principal + AdminSDHolder/privileged ACL 上の突然の orphan SID** を監視する。

## 自己破壊する証拠を使う Dynamic GPO Execution

- 悪意ある **`gPCFileSysPath`**（例: GPODDITY 風の SMB share）を持つ **dynamic `groupPolicyContainer`** object を作成し、**`gPLink`** 経由で target OU に **link** する。
- client は policy を処理して attacker の SMB から content を取得する。TTL が切れると GPO object（および `gPCFileSysPath`）は消え、残るのは壊れた **`gPLink`** GUID だけになり、実行済み payload の LDAP 証拠が消える。
- これは従来の **GPODDITY-style** cleanup より運用上きれいで、元の `gPCFileSysPath` を自分で復元する代わりに、timer 期限切れ時に AD が悪意ある GPC を自動削除する。

## 一時的な AD-Integrated DNS Redirection

- AD DNS record は **DomainDnsZones/ForestDnsZones** 内の **`dnsNode`** object である。これを **dynamic objects** として作成すると、一時的な host redirection（credential capture/MITM）が可能になる。client は悪意ある A/AAAA 応答を cache し、record は後で自己削除されるため zone はきれいに見える（DNS Manager は表示更新に zone reload が必要な場合がある）。
- Detection: replication/event logs 経由で **`dynamicObject`/`entryTTL`** を持つ任意の DNS record に alert を出す。短命の record は標準の DNS logs にはほとんど現れない。

## ハイブリッド Entra ID Delta-Sync Gap (Note)

- Entra Connect の delta sync は delete 検出に **tombstones** を使う。**dynamic on-prem user** は Entra ID に sync された後、期限切れで削除されても tombstone を残さないため、delta sync では cloud account を削除できず、**orphaned active Entra user** が残る。これが解消されるのは **initial/full sync** または手動の cloud cleanup を強制した場合のみ。

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
