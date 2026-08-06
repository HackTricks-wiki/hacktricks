# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- auxiliary class **`dynamicObject`**로 생성된 모든 객체는 **`entryTTL`**(초 단위 카운트다운)과 **`msDS-Entry-Time-To-Die`**(절대 만료 시간)를 획득합니다. **`entryTTL`**이 0에 도달하면 **Garbage Collector가 tombstone/recycle-bin 없이 객체를 삭제**하므로 생성자와 timestamp가 지워지고 복구가 차단됩니다.
- **`entryTTL`은 operational/constructed attribute**이므로 LDAP query에서 명시적으로 요청해야 합니다. TTL은 만료 전에 **`entryTTL`**을 업데이트하거나 LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**을 통해 새로 고칠 수 있습니다.
- TTL의 최소값/기본값은 **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**에서 적용됩니다. Microsoft 문서에는 기본 TTL이 **86400s**, 유효한 기본 최소 TTL이 **900s**로 명시되어 있으며, 두 설정 모두 **1s–1y**를 지원합니다. Dynamic objects는 **Configuration/Schema partitions**에서 지원되지 않습니다.
- **static→dynamic 변환은 존재하지 않으며**, 만료 후 tombstone 단계도 없습니다. IR 팀은 deleted-object controls나 Recycle Bin에 의존할 수 없으며, GC가 객체를 제거하기 전에 live object/metadata를 수집해야 합니다.
- Refresh는 **replica-sensitive**합니다. TTL을 만료에 너무 임박해서 갱신하면, 다른 writable replica나 GC가 refresh가 복제되기 전에 해당 replica에서 객체를 삭제할 수 있습니다. 따라서 매우 짧은 TTL은 attacker가 abuse를 처리할 DC를 알고 있을 때 가장 효과적이며, defender는 triage 중 **모든 naming contexts / replicas**를 조회해야 합니다.
- 짧은 uptime(<24h)을 가진 DC에서는 삭제가 몇 분 지연될 수 있어 attributes를 query/backup할 수 있는 좁은 response window가 남습니다. **`entryTTL`/`msDS-Entry-Time-To-Die`를 포함하는 새 객체에 alert를 설정**하고 orphan SIDs/broken links와 상관 분석하여 탐지합니다.<sup>[[1]](#references)</sup>

## Fast Enumeration / Live Triage

- Domain NC만 조회하지 말고 **RootDSE에서 모든 `namingContexts`를 query**합니다. Dynamic abuse는 **`DomainDnsZones`/`ForestDnsZones`**(`dnsNode`) 또는 application partitions에 존재할 수 있습니다.
- 객체가 아직 live인 동안 즉시 **replication metadata**와 모든 linked attributes/ACLs를 dump합니다. 만료 후에는 **broken `gPLink` values, orphan SIDs 또는 cached DNS answers**만 남을 수 있습니다.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## 자기 삭제 컴퓨터를 이용한 MAQ Evasion

- 기본 **`ms-DS-MachineAccountQuota` = 10**은 인증된 모든 사용자가 컴퓨터를 생성할 수 있도록 합니다. 생성 시 `dynamicObject`를 추가하면 컴퓨터가 스스로 삭제되어 **quota slot을 해제**하고 흔적을 제거합니다.
- `New-MachineAccount` 내부의 Powermad 수정 사항(objectClass 목록):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 요청한 TTL이 **`DynamicObjectMinTTL`보다 낮으면**, 생성 경로에 따라 서버에서 조정하거나 거부할 수 있습니다. 많은 도메인에서 실제 최솟값은 **900초**이며 fallback/default 값은 **86400초**입니다. ADUC에서는 `entryTTL`이 숨겨질 수 있지만 LDP/LDAP 쿼리에서는 확인할 수 있습니다.
- 객체가 존재하는 동안에는 defender가 컴퓨터 객체의 **`msDS-CreatorSID`**를 통해 권한이 제한된 생성자를 여전히 확인할 수 있습니다. dynamic computer가 만료되면 해당 객체와 함께 이 attribution도 사라집니다.<sup>[[1]](#references)</sup>

## 은밀한 Primary Group Membership

- **dynamic security group**을 생성한 다음 사용자의 **`primaryGroupID`**를 해당 그룹의 RID로 설정하면, **`memberOf`에는 표시되지 않지만** Kerberos/access token에서 유효한 membership으로 처리되는 권한을 얻을 수 있습니다.<sup>[[1]](#references)</sup>
- TTL이 만료되면 **primary-group delete protection**에도 불구하고 그룹이 삭제됩니다. 그 결과 사용자는 존재하지 않는 RID를 가리키는 손상된 `primaryGroupID`를 보유하게 되며, 해당 권한이 어떻게 부여되었는지 조사할 tombstone도 남지 않습니다.
- Reporting 결과는 도구에 따라 다릅니다. **`Get-ADGroupMember` / `net group`**은 일반적으로 primary-group에서 파생된 membership을 확인하지만, **`memberOf`** 및 **`Get-ADGroup -Properties member`**는 확인하지 못합니다. 더 폭넓은 `primaryGroupID` tradecraft는 [this other page about DCShadow and PGID abuse](dcshadow.md)를 참고하세요.
- **AdminSDHolder-protected** 상태가 아닌 대상의 경우, attackers는 dynamic-group 기법을 **`primaryGroupID` 읽기 또는 그룹의 `member` attribute 읽기에 대한 DACL deny**와 결합할 수 있습니다. 이렇게 하면 그룹 만료 전에도 다수의 LDAP/PowerShell workflow에서 해당 연결을 숨길 수 있습니다.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- **short-lived dynamic user/group**에 대한 ACE를 **`CN=AdminSDHolder,CN=System,...`**에 추가합니다. TTL이 만료되면 해당 SID는 template ACL에서 **확인할 수 없는 SID(“Unknown SID”)**가 되며, **SDProp(~60분)**가 이 orphan SID를 보호되는 모든 Tier-0 객체에 전파합니다.
- principal이 사라지므로 forensics에서 attribution을 잃게 됩니다(삭제된 객체 DN도 없음). **새 dynamic principal과 AdminSDHolder/privileged ACL에서 갑자기 나타나는 orphan SID**를 모니터링하세요.<sup>[[1]](#references)</sup>

## Self-Destructing Evidence를 이용한 Dynamic GPO Execution

- 악성 **`gPCFileSysPath`**(예: GPODDITY와 같은 SMB share)를 가진 **dynamic `groupPolicyContainer`** 객체를 생성하고, **`gPLink`**를 통해 대상 OU에 연결합니다.
- Client가 policy를 처리하고 attacker SMB에서 content를 가져옵니다. TTL이 만료되면 GPO 객체와 **`gPCFileSysPath`**가 사라지고, **broken `gPLink`** GUID만 남아 실행된 payload의 LDAP evidence가 제거됩니다.
- 이는 기존의 **GPODDITY-style** cleanup보다 operationally cleaner합니다. 원래 `gPCFileSysPath`를 직접 복원하는 대신, timer 만료 시 AD가 악성 GPC를 자동으로 제거합니다.<sup>[[1]](#references)</sup>

## Ephemeral AD-Integrated DNS Redirection

- AD DNS record는 **DomainDnsZones/ForestDnsZones**의 **`dnsNode`** 객체입니다. 이를 dynamic object로 생성하면 일시적인 host redirection(credential capture/MITM)이 가능합니다. Client는 악성 A/AAAA response를 cache하며, 이후 record가 스스로 삭제되어 zone이 깨끗한 것처럼 보입니다(DNS Manager는 view를 갱신하기 위해 zone reload가 필요할 수 있음).
- Detection: replication/event log를 통해 **`dynamicObject`/`entryTTL`을 포함하는 모든 DNS record**에 alert를 설정하세요. 일시적인 record는 standard DNS log에 거의 나타나지 않습니다.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync는 삭제를 감지하기 위해 **tombstone**에 의존합니다. **dynamic on-prem user**가 Entra ID로 sync된 뒤 만료되어 tombstone 없이 삭제되면, delta sync는 cloud account를 제거하지 못합니다. 그 결과 **orphaned active Entra user**가 남으며, **initial/full sync** 또는 수동 cloud cleanup을 강제로 수행해야 제거됩니다.<sup>[[1]](#references)</sup>

## References

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
