# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL)은 객체와 해당 속성에 적용되는 보호 규칙을 지정하는 Access Control Entry (ACE)의 정렬된 집합입니다. 기본적으로 ACL은 특정 객체에 대해 어떤 보안 주체(사용자 또는 그룹)가 어떤 작업을 허용받거나 거부당하는지 정의합니다.

ACL에는 두 가지 유형이 있습니다.

- **Discretionary Access Control List (DACL):** 객체에 대한 액세스 권한이 있는 사용자와 그룹을 지정합니다.
- **System Access Control List (SACL):** 객체에 대한 액세스 시도를 감사하는 방식을 관리합니다.

파일에 액세스할 때 시스템은 객체의 보안 설명자를 사용자의 액세스 토큰과 대조하여 액세스 허용 여부와 허용 범위를 ACE에 따라 결정합니다.<sup>[[1]](#references)</sup>

상위 디렉터리에서 Full Control을 부여하더라도 하위 파일에서 읽기가 거부된다면, **하위 파일 자체의** 유효 DACL, 소유자 및 상속 설정을 각각 확인하세요. 해당 파일의 DACL을 변경하려면 파일에 대한 `WRITE_DAC` 권한 또는 해당 소유자 권한이 필요합니다. [Microsoft는 `WRITE_DAC`을 정의하고](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights), [소유자의 암시적 액세스 권한을 설명합니다](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). 상위 디렉터리 권한만으로 하위 파일을 읽을 수 있거나 해당 DACL을 변경할 수 있다고 단정할 수는 없습니다.

### **주요 구성 요소**

- **DACL:** 객체에 대해 사용자와 그룹의 액세스 권한을 허용하거나 거부하는 ACE를 포함합니다. 액세스 권한을 지정하는 주요 ACL입니다.
- **SACL:** 객체에 대한 액세스를 감사하는 데 사용됩니다. ACE는 Security Event Log에 기록할 액세스 유형을 정의합니다. 무단 액세스 시도를 탐지하거나 액세스 문제를 해결할 때 유용합니다.<sup>[[1]](#references)</sup>

### **ACL과 시스템의 상호 작용**

각 사용자 세션은 해당 세션에 필요한 보안 정보를 포함하는 액세스 토큰과 연결됩니다. 여기에는 사용자 및 그룹 ID와 권한이 포함됩니다. 이 토큰에는 세션을 고유하게 식별하는 logon SID도 포함됩니다.

Local Security Authority (LSASS)는 객체에 대한 액세스 요청을 처리할 때 DACL을 살펴보고 액세스를 시도하는 보안 주체와 일치하는 ACE가 있는지 확인합니다. 관련 ACE가 없으면 액세스가 즉시 허용됩니다. 그렇지 않으면 LSASS는 ACE를 액세스 토큰의 보안 주체 SID와 대조해 액세스 가능 여부를 결정합니다.<sup>[[1]](#references)</sup>

### **요약**

- **ACL:** DACL을 통해 액세스 권한을 정의하고 SACL을 통해 감사 규칙을 정의합니다.
- **액세스 토큰:** 세션의 사용자, 그룹 및 권한 정보를 포함합니다.
- **액세스 결정:** DACL의 ACE를 액세스 토큰과 대조해 결정합니다. SACL은 감사에 사용됩니다.<sup>[[1]](#references)</sup>

### ACE

Access Control Entry (ACE)에는 **세 가지 주요 유형**이 있습니다.<sup>[[1]](#references)</sup>

- **Access Denied ACE**: 이 ACE는 DACL에서 지정된 사용자나 그룹의 객체 액세스를 명시적으로 거부합니다.
- **Access Allowed ACE**: 이 ACE는 DACL에서 지정된 사용자나 그룹의 객체 액세스를 명시적으로 허용합니다.
- **System Audit ACE**: System Access Control List (SACL)에 포함되는 이 ACE는 사용자나 그룹이 객체에 액세스를 시도할 때 감사 로그를 생성합니다. 액세스 허용 또는 거부 여부와 액세스 유형을 기록합니다.

각 ACE에는 **네 가지 핵심 구성 요소**가 있습니다.<sup>[[1]](#references)</sup>

1. 사용자 또는 그룹의 **Security Identifier (SID)**(또는 그래픽으로 표시할 때의 주체 이름)
2. ACE 유형(액세스 거부, 허용 또는 시스템 감사)을 식별하는 **플래그**
3. 하위 객체가 부모 객체로부터 ACE를 상속할 수 있는지 결정하는 **상속 플래그**
4. 객체에 부여된 권한을 지정하는 32비트 값인 [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)

액세스 여부는 각 ACE를 순서대로 검토하여 다음 조건 중 하나가 충족될 때 결정됩니다.<sup>[[1]](#references)</sup>

- **Access-Denied ACE**가 액세스 토큰에 있는 trustee에게 요청된 권한을 명시적으로 거부합니다.
- 하나 이상의 **Access-Allowed ACE**가 액세스 토큰에 있는 trustee에게 요청된 권한을 모두 명시적으로 부여합니다.
- 모든 ACE를 확인했는데도 요청된 권한 중 하나라도 **명시적으로 허용되지 않았다면**, 액세스는 암시적으로 **거부됩니다**.

### ACE 순서

**ACE**(누가 어떤 항목에 액세스할 수 있는지 지정하는 규칙)를 **DACL**이라는 목록에 배치하는 순서는 매우 중요합니다. 시스템이 이 규칙에 따라 액세스를 허용하거나 거부하면 나머지 규칙은 더 이상 확인하지 않기 때문입니다.<sup>[[1]](#references)</sup>

ACE를 정렬하는 권장 방식은 **"canonical order"**라고 합니다. 이 방식은 모든 규칙이 원활하고 일관되게 적용되도록 합니다. **Windows 2000** 및 **Windows Server 2003**과 같은 시스템에서는 다음 순서를 따릅니다.

- 먼저 부모 폴더 등 다른 곳에서 상속된 규칙보다 **이 항목에만 적용되는 규칙**을 배치합니다.
- 이 항목에만 적용되는 규칙 중에서는 **"거부"** 규칙을 **"허용"** 규칙보다 먼저 배치합니다.
- 상속된 규칙은 **가장 가까운 원본**(예: 부모 폴더)의 규칙부터 배치하고, 그다음 더 상위 원본의 규칙을 배치합니다. 이때도 **"거부"** 규칙을 **"허용"** 규칙보다 먼저 배치합니다.

이 설정은 다음 두 가지 중요한 이점을 제공합니다.

- 다른 **"허용"** 규칙이 있더라도 특정 **"거부"** 규칙이 우선 적용됩니다.
- 부모 폴더나 그보다 상위에 있는 규칙이 적용되기 전에 항목의 소유자가 액세스 권한을 **최종 결정**할 수 있습니다.

이 방식을 사용하면 파일이나 폴더의 소유자는 누가 액세스할 수 있는지 세밀하게 지정하여, 적절한 사용자는 액세스하고 다른 사용자는 액세스할 수 없도록 할 수 있습니다.

![NTFS 액세스 제어 항목 순서 다이어그램](https://www.ntfs.com/images/screenshots/ACEs.gif)

따라서 **"canonical order"**는 액세스 규칙을 명확하고 효율적으로 적용하기 위한 방식으로, 구체적인 규칙을 먼저 배치하고 나머지 규칙도 체계적으로 정렬합니다.

### GUI 예제

[**여기의 예제**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

다음은 ACL, DACL 및 ACE가 표시된 폴더의 기본 보안 탭입니다.

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

**Advanced button**을 클릭하면 상속과 같은 추가 옵션이 표시됩니다.

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Security Principal을 추가하거나 편집하면 다음과 같은 화면이 표시됩니다.

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

마지막으로 Auditing 탭에서 SACL을 확인할 수 있습니다.

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### 액세스 제어를 쉽게 이해하기

폴더와 같은 리소스에 대한 액세스를 관리할 때 Access Control List (ACL)와 Access Control Entry (ACE)라는 목록과 규칙을 사용합니다. 이를 통해 특정 데이터에 액세스할 수 있는 사용자를 지정합니다.<sup>[[1]](#references)</sup>

#### 특정 그룹의 액세스 거부

Cost라는 폴더가 있고 마케팅 팀을 제외한 모든 사람이 액세스할 수 있도록 하려 한다고 가정해 보겠습니다. 규칙을 올바르게 설정하면 다른 모든 사용자에게 액세스를 허용하기 전에 마케팅 팀의 액세스를 명시적으로 거부할 수 있습니다. 이를 위해 마케팅 팀의 액세스를 거부하는 규칙을 모든 사용자에게 액세스를 허용하는 규칙보다 먼저 배치합니다.

#### 액세스가 거부된 그룹의 특정 구성원에게 액세스 허용

마케팅 팀은 일반적으로 액세스할 수 없지만 마케팅 책임자인 Bob은 Cost 폴더에 액세스해야 한다고 가정해 보겠습니다. Bob에게 액세스를 허용하는 특정 규칙(ACE)을 추가하고, 이를 마케팅 팀의 액세스를 거부하는 규칙보다 먼저 배치할 수 있습니다. 그러면 팀 전체에 적용되는 제한에도 불구하고 Bob은 액세스할 수 있습니다.

#### Access Control Entry 이해하기

ACE는 ACL을 구성하는 개별 규칙입니다. ACE는 사용자나 그룹을 식별하고, 허용하거나 거부할 액세스 권한을 지정하며, 이러한 규칙이 하위 항목에 어떻게 적용되는지(상속)를 결정합니다. ACE에는 두 가지 주요 유형이 있습니다.

- **Generic ACEs**: 모든 유형의 객체에 적용하거나 컨테이너(폴더 등)와 비컨테이너(파일 등)를 구분하는 방식으로 광범위하게 적용됩니다. 예를 들어, 사용자가 폴더의 내용을 볼 수는 있지만 폴더 안의 파일에는 액세스할 수 없도록 허용하는 규칙이 있습니다.
- **Object-Specific ACEs**: 특정 유형의 객체나 객체 내 개별 속성에 규칙을 설정할 수 있어 더 세밀하게 제어합니다. 예를 들어 사용자 디렉터리에서 사용자가 전화번호는 변경할 수 있지만 로그인 시간은 변경할 수 없도록 하는 규칙이 있습니다.

각 ACE에는 규칙의 적용 대상(SID 사용), 허용하거나 거부하는 권한(access mask 사용), 다른 객체에 상속되는 방식 등의 중요한 정보가 포함됩니다.

#### ACE 유형 간 주요 차이점

- **Generic ACEs**는 객체의 모든 요소 또는 컨테이너 내 모든 객체에 동일한 규칙을 적용하는 단순한 액세스 제어 상황에 적합합니다.
- **Object-Specific ACEs**는 특히 Active Directory와 같은 환경에서 사용됩니다. 이러한 환경에서는 객체의 특정 속성에 대한 액세스를 서로 다르게 제어해야 할 수 있습니다.

요약하면 ACL과 ACE는 세밀한 액세스 제어를 정의해 민감한 정보나 리소스에 적절한 사용자나 그룹만 액세스할 수 있도록 합니다. 또한 개별 속성이나 객체 유형별로 액세스 권한을 맞춤 설정할 수 있습니다.

### Access Control Entry 레이아웃

| ACE 필드   | 설명                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | ACE 유형을 나타내는 플래그입니다. Windows 2000 및 Windows Server 2003은 여섯 가지 ACE 유형을 지원합니다. 보호 가능한 모든 객체에 연결되는 일반 ACE 유형 세 가지와 Active Directory 객체에 사용될 수 있는 객체별 ACE 유형 세 가지입니다.                                                                                                                                                                                                                                                            |
| Flags       | 상속과 감사를 제어하는 비트 플래그 집합입니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | ACE에 할당된 메모리의 크기(바이트)입니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | 비트별로 객체의 액세스 권한에 대응하는 32비트 값입니다. 비트를 설정하거나 해제할 수 있지만, 그 의미는 ACE 유형에 따라 달라집니다. 예를 들어 권한 읽기에 해당하는 비트가 설정되어 있고 ACE 유형이 Deny라면, 해당 ACE는 객체의 권한을 읽을 권리를 거부합니다. 같은 비트가 설정되어 있더라도 ACE 유형이 Allow라면 객체의 권한을 읽을 권리를 부여합니다. Access mask에 대한 자세한 내용은 다음 표를 참조하세요. |
| SID         | 이 ACE가 액세스를 제어하거나 모니터링하는 사용자 또는 그룹을 식별합니다.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask 레이아웃

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | 객체별 액세스 권한      | 데이터 읽기, 실행, 데이터 추가           |
| 16 - 22     | 표준 액세스 권한             | 삭제, ACL 쓰기, 소유자 쓰기            |
| 23          | 보안 ACL에 액세스 가능            |                                           |
| 24 - 27     | 예약됨                           |                                           |
| 28          | Generic ALL (읽기, 쓰기, 실행) | 아래의 모든 항목                          |
| 29          | Generic Execute                    | 프로그램 실행에 필요한 모든 권한 |
| 30          | Generic Write                      | 파일에 쓰는 데 필요한 모든 권한   |
| 31          | Generic Read                       | 파일을 읽는 데 필요한 모든 권한       |

## References

- [1] [시스템이 ACL을 사용하는 방식 - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL 및 ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
{{#include ../../banners/hacktricks-training.md}}
