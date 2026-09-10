# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## 동작 원리 및 탐지 기본 사항

- 보조 클래스 **`dynamicObject`**를 사용해 생성된 모든 객체에는 **`entryTTL`**(초 단위 카운트다운)과 **`msDS-Entry-Time-To-Die`**(절대 만료 시간)가 추가됩니다. `entryTTL`이 0에 도달하고 **객체에 하위 객체가 없으면**, Garbage Collector가 tombstone/recycle-bin 없이 객체를 삭제하므로 생성자와 타임스탬프가 지워지고 복구가 차단됩니다.<sup>[[4]](#references)</sup>
- **`entryTTL`은 operational/constructed attribute**이므로 LDAP 쿼리에서 명시적으로 요청해야 합니다. TTL은 만료 전에 `entryTTL`을 업데이트하거나 LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**을 통해 갱신할 수 있습니다.
- TTL의 최솟값/기본값은 **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**에 있는 forest-wide AVA입니다: `DynamicObjectMinTTLSeconds=<seconds>` 및 `DynamicObjectDefaultTTLSeconds=<seconds>`. Microsoft 문서에서는 기본 TTL을 **86400s**, 유효한 기본 최소 TTL을 **900s**로 설명하며, `entryTTL` 스키마 범위는 **1–31557600s**(1초~1년)입니다.<sup>[[3]](#references)</sup> Dynamic objects는 **Configuration/Schema partitions에서 지원되지 않습니다**.
- **static→dynamic 변환은 존재하지 않으며**, 만료 후 tombstone 단계도 없습니다. IR 팀은 삭제된 객체 제어나 Recycle Bin에 의존할 수 없으므로 GC가 객체를 제거하기 전에 live object/metadata를 수집해야 합니다.
- Refresh는 **replica-sensitive**합니다. TTL을 만료 직전에 갱신하면 다른 writable replica 또는 GC가 refresh가 복제되기 전에 해당 객체를 로컬에서 삭제할 수 있습니다. 따라서 매우 짧은 TTL은 공격자가 abuse를 처리할 DC를 알고 있을 때 가장 효과적이며, defenders는 triage 중 **모든 naming contexts / replicas**를 조회해야 합니다.
- 가동 시간이 짧은(<24h) DC에서는 삭제가 몇 분 지연될 수 있어 attributes를 조회/백업할 수 있는 짧은 대응 시간이 남습니다. **`entryTTL`/`msDS-Entry-Time-To-Die`를 포함한 새 객체**에 alert를 설정하고 orphan SIDs/broken links와 상관 분석하여 탐지합니다.<sup>[[1]](#references)</sup>

### 만료 그래프 및 reference-cleanup 예외 사례

- Dynamic object 아래의 모든 descendant도 dynamic object여야 합니다. 만료된 dynamic parent는 leaf가 된 후에만 garbage-collected되며, descendant의 `msDS-Entry-Time-To-Die`가 더 늦으면 DC는 parent의 만료 시간을 descendant 중 가장 늦은 만료 시간 이후로 연장합니다. 결과적으로 writable dynamic subtree가 **곧 사라질 것처럼 보이는 parent를 고정하거나 연장**할 수 있습니다. 전체 subtree를 열거하고 parent에서 관찰된 `entryTTL`을 cleanup deadline으로 사용하지 마십시오.<sup>[[4]](#references)</sup>
- 만료 cleanup은 **schema-link-aware**합니다. Replicas는 삭제된 dynamic object를 참조하는 linked attribute values를 제거하지만, nonlinked values는 유지합니다. 일반적인 forward/back-link membership은 정리되지만 `primaryGroupID`, `nTSecurityDescriptor`에 포함된 SIDs 또는 `gPLink` text와 같은 integer/SID/string references는 forensic residue로 남을 수 있습니다.<sup>[[4]](#references)</sup>

## Fast Enumeration / Live Triage

- domain NC만 조회하지 말고 **RootDSE에서 모든 `namingContexts`를 조회**하십시오. Dynamic abuse는 **`DomainDnsZones`/`ForestDnsZones`**(`dnsNode`) 또는 application partitions에 존재할 수 있습니다.
- 객체가 아직 살아 있을 때 즉시 **replication metadata**와 모든 linked attributes/ACLs를 dump하십시오. 만료 후에는 **broken `gPLink` values, orphan SIDs 또는 cached DNS answers**만 남을 수 있습니다.<sup>[[1]](#references)</sup>
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
## 자체 삭제 컴퓨터를 이용한 MAQ Evasion

- 기본 **`ms-DS-MachineAccountQuota` = 10** 설정에서는 모든 인증된 사용자가 컴퓨터를 생성할 수 있습니다. 생성 시 `dynamicObject`를 추가하면 컴퓨터가 스스로 삭제되어 **quota slot을 해제**하는 동시에 흔적을 제거할 수 있습니다.
- `New-MachineAccount` 내부의 Powermad 수정 사항(objectClass 목록):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 요청한 TTL이 **`DynamicObjectMinTTL`보다 낮으면**, 생성 경로에 따라 서버 측 조정 또는 거부가 발생할 수 있습니다. 많은 도메인에서 실제 최소값은 **900s**이며, fallback/default 값은 **86400s**로 유지됩니다. ADUC에서는 `entryTTL`이 숨겨질 수 있지만, LDP/LDAP 쿼리로 확인할 수 있습니다.
- 객체가 존재하는 동안에는 방어자가 컴퓨터 객체의 **`msDS-CreatorSID`**를 통해 권한이 낮은 생성자를 확인할 수 있습니다. 동적 컴퓨터가 만료되면 해당 객체와 함께 이 귀속 정보도 사라집니다.<sup>[[1]](#references)</sup>

## 은밀한 Primary Group Membership

- **dynamic security group**을 생성한 다음, 사용자의 **`primaryGroupID`**를 해당 그룹의 RID로 설정하면 **`memberOf`에는 표시되지 않지만** Kerberos/access token에서는 적용되는 실질적인 멤버십을 얻을 수 있습니다.<sup>[[1]](#references)</sup>
- TTL이 만료되면 **primary-group delete protection**에도 불구하고 그룹이 삭제됩니다. 그 결과 사용자는 존재하지 않는 RID를 가리키는 손상된 `primaryGroupID`를 가지게 되며, 해당 권한이 어떻게 부여되었는지 조사할 tombstone도 남지 않습니다.
- Reporting은 도구에 따라 다릅니다. **`Get-ADGroupMember` / `net group`**은 일반적으로 primary-group에서 파생된 멤버십을 확인하지만, **`memberOf`** 및 **`Get-ADGroup -Properties member`**는 확인하지 못합니다. 더 폭넓은 `primaryGroupID` tradecraft는 [DCShadow 및 PGID abuse에 관한 다른 페이지](dcshadow.md)를 참조하세요.
- **AdminSDHolder-protected** 대상이 아닌 경우, 공격자는 dynamic-group 기법을 **`primaryGroupID` 읽기 또는 그룹의 `member` attribute 읽기에 대한 DACL deny**와 결합할 수 있습니다. 이를 통해 그룹이 만료되기 전에도 여러 LDAP/PowerShell workflow에서 해당 연결을 숨길 수 있습니다.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- **short-lived dynamic user/group**에 대한 ACE를 **`CN=AdminSDHolder,CN=System,...`**에 추가합니다. TTL이 만료되면 SID가 template ACL에서 **확인 불가(“Unknown SID”)** 상태가 되며, **SDProp(~60 min)**가 해당 orphan SID를 보호되는 모든 Tier-0 객체에 전파합니다.
- principal이 사라지므로(삭제된 객체 DN 없음) Forensics에서 귀속 정보를 잃게 됩니다. **새 dynamic principal 및 AdminSDHolder/privileged ACL에서 갑자기 나타나는 orphan SID**를 모니터링하세요.<sup>[[1]](#references)</sup>

## 자체 파괴되는 증거를 이용한 Dynamic GPO Execution

- 악성 **`gPCFileSysPath`**(예: GPODDITY 방식의 SMB share)를 가진 **dynamic `groupPolicyContainer`** 객체를 생성하고, **`gPLink`**를 통해 대상 OU에 연결합니다.
- 클라이언트는 policy를 처리하고 attacker SMB에서 content를 가져옵니다. TTL이 만료되면 GPO 객체와 `gPCFileSysPath`가 사라지고, **broken `gPLink`** GUID만 남아 실행된 payload의 LDAP evidence가 제거됩니다.
- 이는 기존의 **GPODDITY-style** cleanup보다 operationally cleaner합니다. 원래 `gPCFileSysPath`를 직접 복원하는 대신, timer가 만료되면 AD가 악성 GPC를 자동으로 제거합니다.<sup>[[1]](#references)</sup> protocol 및 tooling details는 여기서 중복하지 않고 [ACL persistence abuse](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity)를 참조하세요.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records는 **DomainDnsZones/ForestDnsZones**의 **`dnsNode`** 객체입니다. 이를 **dynamic objects**로 생성하면 임시 host redirection(credential capture/MITM)이 가능합니다. 클라이언트는 악성 A/AAAA response를 cache하며, 이후 record가 스스로 삭제되어 zone이 깨끗해 보입니다(DNS Manager는 view를 refresh하려면 zone reload가 필요할 수 있습니다).
- Detection: replication/event logs를 통해 **`dynamicObject`/`entryTTL`을 포함한 모든 DNS record**에 alert를 설정하세요. 일시적인 record는 standard DNS logs에 거의 나타나지 않습니다.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (참고)

- Entra Connect delta sync는 삭제를 감지하기 위해 **tombstone**에 의존합니다. **dynamic on-prem user**가 Entra ID로 sync된 후 만료되어 tombstone 없이 삭제되면, delta sync는 cloud account를 제거하지 못합니다. 그 결과 **orphaned active Entra user**가 남으며, **initial/full sync**를 수행하거나 manual cloud cleanup을 강제해야 제거됩니다.<sup>[[1]](#references)</sup>



## References

- [1] [Active Directory의 Dynamic Objects: 은밀한 위협](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Primary Group 동작, Reporting 및 Exploitation에 관한 탐구](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [TTL Limits 구성](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: DynamicObject Requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
