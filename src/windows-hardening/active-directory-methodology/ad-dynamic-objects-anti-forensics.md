# AD Dynamic Objects (dynamicObject) 안티 포렌식

{{#include ../../banners/hacktricks-training.md}}

## 메커니즘 및 탐지 기본

- 보조 클래스 **`dynamicObject`**로 생성된 모든 객체는 **`entryTTL`**(초 단위 카운트다운)과 **`msDS-Entry-Time-To-Die`**(절대 만료)를 갖습니다. `entryTTL`이 0이 되면 **Garbage Collector가 tombstone/recycle-bin 없이 이를 삭제**하여 생성자/타임스탬프를 지우고 복구를 차단합니다.
- TTL은 `entryTTL`을 업데이트하여 갱신할 수 있습니다; 최소/기본값은 **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**에서 강제됩니다(지원 범위 1s–1y, 일반적으로 기본값은 86,400s/24h). Dynamic objects는 **Configuration/Schema partitions에서 지원되지 않습니다**.
- 가동 시간이 짧은 DC(<24h)에서는 삭제가 몇 분 지연될 수 있어 속성 쿼리/백업을 위한 좁은 대응 창이 남습니다. **`entryTTL`/`msDS-Entry-Time-To-Die`를 가진 새 객체에 대해 경고**를 발생시키고 고아 SID/깨진 링크와 상관관계 분석하여 탐지하세요.

## MAQ 회피(자체 삭제하는 컴퓨터)

- 기본값 **`ms-DS-MachineAccountQuota` = 10**은 인증된 사용자라면 누구나 컴퓨터를 생성할 수 있게 합니다. 생성 시 `dynamicObject`를 추가하면 컴퓨터가 자체 삭제되어 증거를 지우면서 **quota 슬롯을 해제**합니다.
- Powermad tweak inside `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 짧은 TTL(예: 60s)은 일반 사용자에게는 종종 실패합니다; AD는 **`DynamicObjectDefaultTTL`**으로 대체됩니다(예: 86,400s). ADUC는 `entryTTL`을 숨길 수 있지만 LDP/LDAP 쿼리는 이를 드러냅니다.

## Stealth Primary Group Membership

- **dynamic security group**을 생성한 뒤 사용자 **`primaryGroupID`**를 해당 그룹의 RID로 설정하면 `memberOf`에는 표시되지 않지만 Kerberos/액세스 토큰에서는 인식되는 실질적 멤버십을 얻게 됩니다.
- TTL 만료 시 **primary-group 삭제 보호에도 불구하고 그룹이 삭제**되어 사용자는 존재하지 않는 RID를 가리키는 손상된 `primaryGroupID`를 갖게 되고 조사할 수 있는 tombstone이 남지 않습니다.

## AdminSDHolder 고아-SID 오염

- **단명하는 dynamic user/group**에 대한 ACE를 **`CN=AdminSDHolder,CN=System,...`**에 추가하세요. TTL 만료 후 템플릿 ACL에서 SID는 **해결 불가(“Unknown SID”)**가 되고, **SDProp (~60 min)**가 그 고아 SID를 모든 보호된 Tier-0 객체로 전파합니다.
- 주체가 사라져 포렌식이 속성 추적을 못합니다(삭제된 객체 DN 없음). **새로운 dynamic principals + AdminSDHolder/특권 ACL에서의 갑작스러운 고아 SID**를 모니터링하세요.

## 자체 소멸 증거를 가진 Dynamic GPO 실행

- 악성 **`gPCFileSysPath`**(예: SMB share à la GPODDITY)를 가진 **dynamic `groupPolicyContainer`** 객체를 생성하고 대상 OU에 **`gPLink`로 연결**하세요.
- 클라이언트는 정책을 처리하고 공격자 SMB에서 콘텐츠를 가져옵니다. TTL이 만료되면 GPO 객체(및 `gPCFileSysPath`)는 사라지고 **깨진 `gPLink`** GUID만 남아 실행된 페이로드의 LDAP 증거가 제거됩니다.

## 일시적 AD-통합 DNS 리디렉션

- AD DNS 레코드는 **DomainDnsZones/ForestDnsZones**의 **`dnsNode`** 객체입니다. 이를 **dynamic objects**로 생성하면 일시적인 호스트 리디렉션(credential capture/MITM)이 가능합니다. 클라이언트는 악성 A/AAAA 응답을 캐시하고, 해당 레코드는 이후 자체 삭제되어 존이 깨끗해 보입니다(DNS Manager는 보기 갱신을 위해 존을 다시 로드해야 할 수 있습니다).
- 탐지: 복제/이벤트 로그를 통해 **`dynamicObject`/`entryTTL`를 가진 DNS 레코드**에 경고를 설정하세요; 일시적 레코드는 표준 DNS 로그에 거의 나타나지 않습니다.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync는 삭제를 감지하기 위해 **tombstones**에 의존합니다. **dynamic on-prem user**가 Entra ID로 동기화된 후 만료되어 tombstone 없이 삭제되면 delta sync는 클라우드 계정을 제거하지 못해 수동으로 **full sync**를 강제할 때까지 **고아화된 활성 Entra 사용자**가 남게 됩니다.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
