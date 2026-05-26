# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- **`dynamicObject`** 보조 클래스로 생성된 모든 object는 **`entryTTL`**(초 카운트다운)과 **`msDS-Entry-Time-To-Die`**(절대 만료)을 얻습니다. `entryTTL`이 0에 도달하면 **Garbage Collector가 tombstone/recycle-bin 없이 삭제**하여 creator/timestamps를 지우고 복구를 차단합니다.
- **`entryTTL`은 operational/constructed attribute**입니다: LDAP queries에서 명시적으로 요청해야 합니다. TTL은 만료 전에 `entryTTL`을 업데이트하거나 LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**을 통해 갱신할 수 있습니다.
- TTL min/default는 **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**에서 enforced 됩니다. Microsoft는 기본 TTL로 **86400s**, 기본 minimum valid TTL로 **900s**를 문서화하며; 둘 다 **1s–1y**를 지원합니다. Dynamic objects는 **Configuration/Schema partitions에서 unsupported**입니다.
- 만료 후 static→dynamic conversion은 **없으며**, tombstone phase도 없습니다. IR teams는 deleted-object controls나 Recycle Bin에 의존할 수 없고; GC가 제거하기 전에 live object/metadata를 캡처해야 합니다.
- Refresh는 **replica-sensitive**입니다: TTL이 만료에 너무 가깝게 갱신되면, 다른 writable replica 또는 GC가 refresh가 replicate되기 전에 로컬에서 object를 삭제할 수 있습니다. 따라서 매우 짧은 TTL은 공격자가 어떤 DC가 abuse를 처리할지 알고 있을 때 가장 잘 작동하며, defender는 triage 동안 **모든 naming contexts / replicas**를 query해야 합니다.
- Deletion은 uptime이 짧은 DC들(<24h)에서 몇 분 지연될 수 있어, attributes를 query/backup할 수 있는 좁은 response window가 남습니다. **`entryTTL`/`msDS-Entry-Time-To-Die`를 가진 새 object에 alert**하고 orphan SIDs/broken links와 correlation 하여 탐지합니다.

## Fast Enumeration / Live Triage

- domain NC만이 아니라 RootDSE의 **모든 `namingContexts`**를 query하세요. Dynamic abuse는 **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) 또는 application partitions에 존재할 수 있습니다.
- object가 아직 살아 있는 동안, 즉시 **replication metadata**와 link된 attributes/ACLs를 dump하세요. 만료 후에는 **broken `gPLink` values, orphan SIDs, 또는 cached DNS answers**만 남을 수 있습니다.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Self-Deleting Computers를 이용한 MAQ Evasion

- 기본 **`ms-DS-MachineAccountQuota` = 10**은 인증된 모든 사용자가 컴퓨터를 만들 수 있게 한다. 생성 시 `dynamicObject`를 추가하면 컴퓨터가 스스로 삭제되어 **quota 슬롯을 해제**하고 증거도 지운다.
- Powermad의 `New-MachineAccount` 내부(objectClass list) 수정:
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 요청한 TTL이 **`DynamicObjectMinTTL`보다 낮으면**, 생성 경로에 따라 서버 측 조정 또는 거부가 발생할 수 있다. 많은 도메인에서 실제 하한은 **900s**이고 fallback/default는 **86400s**다. ADUC는 `entryTTL`을 숨길 수 있지만, LDP/LDAP 쿼리에서는 보인다.
- 객체가 존재하는 동안 방어자는 컴퓨터 객체의 **`msDS-CreatorSID`**에서 비권한 생성자를 복구할 수 있다. dynamic computer가 만료되면, 그 attribution도 객체와 함께 사라진다.

## Stealth Primary Group Membership

- **dynamic security group**을 만든 뒤, 사용자의 **`primaryGroupID`**를 그 그룹의 RID로 설정하면 **`memberOf`에는 보이지 않지만** Kerberos/access tokens에서는 인정되는 effective membership을 얻을 수 있다.
- TTL 만료는 **primary-group delete protection을 무시하고 그룹을 삭제**하므로, 사용자는 존재하지 않는 RID를 가리키는 손상된 `primaryGroupID`만 남고, 권한이 어떻게 부여됐는지 조사할 tombstone도 없다.
- 리포팅은 도구 의존적이다: **`Get-ADGroupMember` / `net group`**은 보통 primary-group 기반 membership을 해석하지만, **`memberOf`**와 **`Get-ADGroup -Properties member`**는 그렇지 않다. 더 넓은 `primaryGroupID` tradecraft는 [DCShadow 및 PGID abuse에 관한 다른 페이지](dcshadow.md)를 보라.
- **AdminSDHolder로 보호되지 않는** 대상의 경우, 공격자는 dynamic-group trick과 **`primaryGroupID` 읽기에 대한 DACL deny**(또는 그룹의 `member` attribute)를 결합해, 그룹이 만료되기 전에도 많은 LDAP/PowerShell workflow에서 링크를 숨길 수 있다.

## AdminSDHolder Orphan-SID Pollution

- **수명이 짧은 dynamic user/group**에 대한 ACE를 **`CN=AdminSDHolder,CN=System,...`**에 추가한다. TTL 만료 후 SID는 템플릿 ACL에서 **resolve되지 않는 (“Unknown SID”)** 상태가 되고, **SDProp (~60 min)**이 그 orphan SID를 모든 protected Tier-0 object에 전파한다.
- 주체가 사라지므로(삭제된 object DN도 없음) forensics는 attribution을 잃는다. **새로운 dynamic principal + AdminSDHolder/privileged ACL의 갑작스러운 orphan SID**를 모니터링하라.

## Self-Destructing Evidence를 이용한 Dynamic GPO Execution

- 악성 **`gPCFileSysPath`**(예: GPODDITY처럼 SMB share)를 가진 **dynamic `groupPolicyContainer`** object를 만들고, **`gPLink`**로 target OU에 **link**한다.
- Client는 policy를 처리하고 attacker SMB에서 content를 가져온다. TTL이 만료되면 GPO object(및 `gPCFileSysPath`)가 사라지고, **깨진 `gPLink`** GUID만 남아 실행된 payload의 LDAP 증거를 제거한다.
- 이는 classic **GPODDITY-style** cleanup보다 운영상 더 깔끔하다: 원래 `gPCFileSysPath`를 직접 복원하는 대신, timer가 만료되면 AD가 malicious GPC를 자동으로 제거한다.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS record는 **DomainDnsZones/ForestDnsZones**의 **`dnsNode`** object다. 이를 **dynamic objects**로 만들면 일시적인 host redirection(credential capture/MITM)이 가능하다. Client는 악성 A/AAAA response를 cache하고, record는 나중에 self-delete되어 zone이 깨끗해 보인다(DNS Manager는 view 갱신을 위해 zone reload가 필요할 수 있다).
- Detection: replication/event logs를 통해 **`dynamicObject`/`entryTTL`을 포함한 모든 DNS record**를 alert하라. transient record는 표준 DNS log에 거의 나타나지 않는다.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync는 delete를 감지하기 위해 **tombstone**에 의존한다. **dynamic on-prem user**는 Entra ID로 sync된 뒤 만료 및 삭제될 수 있지만 tombstone이 없으므로, delta sync는 cloud account를 제거하지 못하고 **orphaned active Entra user**가 남는다. 이는 **initial/full sync** 또는 수동 cloud cleanup이 강제될 때까지 지속된다.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
