# AD Dynamic Objects (dynamicObject) 반포렌식

{{#include ../../banners/hacktricks-training.md}}

## 작동 원리 및 탐지 기본

- 보조 클래스 **`dynamicObject`** 로 생성된 모든 객체는 **`entryTTL`**(초 단위 카운트다운) 및 **`msDS-Entry-Time-To-Die`**(절대 만료)를 갖습니다. `entryTTL` 이 0이 되면 **Garbage Collector가 tombstone/recycle-bin 없이 삭제**하여 생성자/타임스탬프를 지우고 복구를 차단합니다.
- TTL은 `entryTTL` 업데이트로 갱신할 수 있으며 최소/기본값은 **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** 에서 강제됩니다(1s–1y 지원, 일반적으로 86,400s/24h로 기본). Dynamic objects는 **Configuration/Schema 파티션에서는 지원되지 않습니다**.
- 삭제는 업타임이 짧은 DC(<24h)에서 몇 분 지연될 수 있어 속성 조회/백업을 위한 좁은 대응 창이 남습니다. 새 객체에 `entryTTL`/`msDS-Entry-Time-To-Die`가 포함되는 것을 경고하고 고아 SID/깨진 링크와 상관관계하여 탐지하세요.

## MAQ 우회: 자체 삭제 컴퓨터

- 기본 **`ms-DS-MachineAccountQuota` = 10** 은 인증된 사용자가 컴퓨터를 생성할 수 있게 합니다. 생성 시 `dynamicObject`를 추가하면 컴퓨터가 스스로 삭제되어 **quota 슬롯을 비우고** 증거를 지웁니다.
- Powermad 수정사항 (`New-MachineAccount` 내부, objectClass 목록):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 짧은 TTL(예: 60s)은 일반 사용자에게 종종 실패하며, AD는 **DynamicObjectDefaultTTL**(예: 86,400s)로 대체합니다. ADUC는 `entryTTL`을 숨길 수 있지만 LDP/LDAP 쿼리는 이를 드러냅니다.

## 은밀한 Primary Group 멤버십

- **dynamic security group** 을 만들고 사용자의 **`primaryGroupID`** 를 해당 그룹의 RID로 설정하면 `memberOf`에 표시되지 않지만 Kerberos/액세스 토큰에서는 유효한 멤버십을 얻습니다.
- TTL 만료는 **primary-group 삭제 보호에도 불구하고 그룹을 삭제**하여 사용자의 `primaryGroupID`가 존재하지 않는 RID를 가리키는 손상된 상태가 되고, 권한이 어떻게 부여되었는지 조사할 tombstone이 남지 않습니다.

## AdminSDHolder 고아-SID 오염

- 짧은 수명의 dynamic user/group에 대한 ACE를 **`CN=AdminSDHolder,CN=System,...`** 에 추가하세요. TTL 만료 후 템플릿 ACL에서 SID는 **해결 불가("Unknown SID")** 가 되고, **SDProp (~60분)** 가 그 고아 SID를 모든 보호된 Tier-0 객체에 전파합니다.
- 포렌식은 주체가 사라졌기 때문에 귀속을 잃습니다(삭제된 객체 DN이 없음). **새로운 dynamic principal + AdminSDHolder/권한 ACL에서 갑작스러운 고아 SID**를 모니터링하세요.

## 자체 파괴 증거를 남기는 Dynamic GPO 실행

- 악성 **`gPCFileSysPath`**(예: GPODDITY 스타일 SMB 공유)를 가진 **dynamic `groupPolicyContainer`** 객체를 만들고 대상 OU에 `gPLink`로 링크하세요.
- 클라이언트는 정책을 처리하고 공격자의 SMB에서 컨텐츠를 가져옵니다. TTL 만료 시 GPO 객체(및 `gPCFileSysPath`)는 사라지고, LDAP에 실행된 페이로드의 증거는 GUID가 깨진 `gPLink`만 남기게 됩니다.

## 일시적 AD 통합 DNS 리디렉션

- AD DNS 레코드는 **`dnsNode`** 객체로 **DomainDnsZones/ForestDnsZones** 에 있습니다. 이를 **dynamic objects** 로 생성하면 일시적인 호스트 리다이렉션(자격 증명 캡처/MITM)이 가능합니다. 클라이언트는 악성 A/AAAA 응답을 캐시하고 레코드는 이후 자체 삭제되어 존이 깨끗해 보입니다(DNS Manager는 보기 갱신을 위해 존 리로드가 필요할 수 있음).
- 탐지: 복제/이벤트 로그를 통해 **`dynamicObject`/`entryTTL`** 을 가진 DNS 레코드에 대해 경고하세요; 일시적 레코드는 표준 DNS 로그에 드물게 나타납니다.

## Hybrid Entra ID Delta-Sync 갭 (참고)

- Entra Connect delta sync는 삭제를 감지하기 위해 **tombstones** 에 의존합니다. 온프레미스의 **dynamic user** 가 Entra ID로 동기화되고 만료되어 tombstone 없이 삭제되면 delta sync는 클라우드 계정을 제거하지 못해 수동 **full sync** 가 강제될 때까지 **고아화된 활성 Entra 사용자**가 남습니다.

## 참고자료

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
