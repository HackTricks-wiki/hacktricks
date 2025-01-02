# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 구동되는 **워크플로우**를 쉽게 구축하고 **자동화**하세요.\
지금 액세스하세요:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL)은 객체와 그 속성에 대한 보호를 지시하는 순서가 있는 Access Control Entries (ACEs) 집합으로 구성됩니다. 본질적으로 ACL은 특정 객체에 대해 어떤 보안 주체(사용자 또는 그룹)의 어떤 행동이 허용되거나 거부되는지를 정의합니다.

ACL에는 두 가지 유형이 있습니다:

- **Discretionary Access Control List (DACL):** 특정 사용자와 그룹이 객체에 접근할 수 있는지 여부를 지정합니다.
- **System Access Control List (SACL):** 객체에 대한 접근 시도의 감사를 관리합니다.

파일에 접근하는 과정은 시스템이 객체의 보안 설명자를 사용자의 접근 토큰과 비교하여 접근이 허용되어야 하는지와 그 접근의 범위를 결정하는 것입니다.

### **Key Components**

- **DACL:** 객체에 대한 사용자와 그룹의 접근 권한을 부여하거나 거부하는 ACE를 포함합니다. 본질적으로 접근 권한을 지시하는 주요 ACL입니다.
- **SACL:** 객체에 대한 접근을 감사하는 데 사용되며, ACE는 보안 이벤트 로그에 기록될 접근 유형을 정의합니다. 이는 무단 접근 시도를 감지하거나 접근 문제를 해결하는 데 매우 유용할 수 있습니다.

### **System Interaction with ACLs**

각 사용자 세션은 해당 세션과 관련된 보안 정보를 포함하는 접근 토큰과 연결되어 있으며, 여기에는 사용자, 그룹 신원 및 권한이 포함됩니다. 이 토큰에는 세션을 고유하게 식별하는 로그온 SID도 포함됩니다.

로컬 보안 권한(LSASS)은 접근 요청을 처리하기 위해 DACL에서 접근을 시도하는 보안 주체와 일치하는 ACE를 검사합니다. 관련 ACE가 발견되지 않으면 접근이 즉시 허용됩니다. 그렇지 않으면 LSASS는 접근 토큰의 보안 주체 SID와 ACE를 비교하여 접근 자격을 결정합니다.

### **Summarized Process**

- **ACLs:** DACL을 통해 접근 권한을 정의하고 SACL을 통해 감사 규칙을 정의합니다.
- **Access Token:** 세션에 대한 사용자, 그룹 및 권한 정보를 포함합니다.
- **Access Decision:** DACL ACE와 접근 토큰을 비교하여 이루어지며, SACL은 감사를 위해 사용됩니다.

### ACEs

**세 가지 주요 유형의 Access Control Entries (ACEs)**가 있습니다:

- **Access Denied ACE**: 이 ACE는 특정 사용자 또는 그룹에 대해 객체에 대한 접근을 명시적으로 거부합니다( DACL에서).
- **Access Allowed ACE**: 이 ACE는 특정 사용자 또는 그룹에 대해 객체에 대한 접근을 명시적으로 허용합니다( DACL에서).
- **System Audit ACE**: 시스템 접근 제어 목록(SACL) 내에 위치하며, 사용자 또는 그룹이 객체에 접근을 시도할 때 감사 로그를 생성하는 역할을 합니다. 접근이 허용되었는지 거부되었는지와 접근의 성격을 문서화합니다.

각 ACE는 **네 가지 중요한 구성 요소**를 가지고 있습니다:

1. 사용자 또는 그룹의 **Security Identifier (SID)** (또는 그래픽 표현에서의 주체 이름).
2. ACE 유형을 식별하는 **플래그** (접근 거부, 허용 또는 시스템 감사).
3. 자식 객체가 부모로부터 ACE를 상속할 수 있는지를 결정하는 **상속 플래그**.
4. 객체의 부여된 권한을 지정하는 32비트 값인 [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN).

접근 결정은 각 ACE를 순차적으로 검사하여 수행됩니다:

- **Access-Denied ACE**가 접근 토큰에서 식별된 수탁자에게 요청된 권한을 명시적으로 거부합니다.
- **Access-Allowed ACE**가 접근 토큰의 수탁자에게 요청된 모든 권한을 명시적으로 부여합니다.
- 모든 ACE를 확인한 후, 요청된 권한이 **명시적으로 허용되지 않은 경우**, 접근은 암묵적으로 **거부**됩니다.

### Order of ACEs

**ACEs**(누가 무엇에 접근할 수 있는지를 말하는 규칙)가 **DACL**이라는 목록에 배치되는 방식은 매우 중요합니다. 시스템이 이러한 규칙에 따라 접근을 부여하거나 거부하면 나머지를 더 이상 살펴보지 않기 때문입니다.

이 ACE를 정리하는 최선의 방법은 **"정준 순서(canonical order)"**라고 불립니다. 이 방법은 모든 것이 원활하고 공정하게 작동하도록 보장하는 데 도움이 됩니다. **Windows 2000** 및 **Windows Server 2003**와 같은 시스템에 대한 방법은 다음과 같습니다:

- 먼저, **이 항목을 위해 특별히 만들어진** 모든 규칙을 다른 곳에서 온 규칙(예: 부모 폴더)보다 앞에 배치합니다.
- 이러한 특정 규칙 중에서 **"아니오"(deny)**라고 말하는 규칙을 **"예"(allow)**라고 말하는 규칙보다 먼저 배치합니다.
- 다른 곳에서 온 규칙의 경우, **가장 가까운 출처**(예: 부모)에서 온 규칙부터 시작하고 그 뒤로 거슬러 올라갑니다. 다시 말해, **"아니오"**를 **"예"**보다 먼저 배치합니다.

이 설정은 두 가지 큰 방식으로 도움이 됩니다:

- 특정 **"아니오"**가 있을 경우, 다른 **"예"** 규칙이 있더라도 존중됩니다.
- 항목의 소유자가 부모 폴더나 더 먼 곳의 규칙이 적용되기 전에 누가 들어갈 수 있는지에 대한 **최종 결정권**을 가집니다.

이렇게 함으로써 파일이나 폴더의 소유자는 누가 접근할 수 있는지에 대해 매우 정확하게 설정할 수 있으며, 올바른 사람들이 접근할 수 있도록 하고 잘못된 사람들은 접근할 수 없도록 합니다.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

따라서 이 **"정준 순서"**는 접근 규칙이 명확하고 잘 작동하도록 보장하며, 특정 규칙을 먼저 배치하고 모든 것을 스마트하게 정리하는 것입니다.

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 구동되는 **워크플로우**를 쉽게 구축하고 **자동화**하세요.\
지금 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### GUI Example

[**여기에서 예시**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/) 

이것은 ACL, DACL 및 ACE를 보여주는 폴더의 고전적인 보안 탭입니다:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

**고급 버튼**을 클릭하면 상속과 같은 더 많은 옵션을 얻을 수 있습니다:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

보안 주체를 추가하거나 편집하면 다음과 같습니다:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

마지막으로 감사 탭에서 SACL을 확인할 수 있습니다:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

리소스에 대한 접근을 관리할 때, 폴더와 같은 리소스에 대해 우리는 Access Control Lists (ACLs) 및 Access Control Entries (ACEs)라는 목록과 규칙을 사용합니다. 이들은 누가 특정 데이터에 접근할 수 있는지 또는 없는지를 정의합니다.

#### 특정 그룹에 대한 접근 거부

Cost라는 이름의 폴더가 있고, 마케팅 팀을 제외한 모든 사람이 접근할 수 있도록 하고 싶다고 가정해 보겠습니다. 규칙을 올바르게 설정함으로써, 마케팅 팀이 접근을 명시적으로 거부당하도록 하고 나머지 모든 사람에게 접근을 허용할 수 있습니다. 이는 마케팅 팀에 대한 접근 거부 규칙을 모든 사람에게 접근을 허용하는 규칙보다 먼저 배치함으로써 이루어집니다.

#### 거부된 그룹의 특정 구성원에게 접근 허용

마케팅 디렉터인 Bob이 Cost 폴더에 접근해야 한다고 가정해 보겠습니다. 일반적으로 마케팅 팀은 접근할 수 없어야 합니다. 우리는 Bob에게 접근을 허용하는 특정 규칙(ACE)을 추가하고, 이를 마케팅 팀에 대한 접근 거부 규칙보다 먼저 배치할 수 있습니다. 이렇게 하면 Bob은 그의 팀에 대한 일반적인 제한에도 불구하고 접근할 수 있습니다.

#### Access Control Entries 이해하기

ACE는 ACL 내의 개별 규칙입니다. 이들은 사용자 또는 그룹을 식별하고, 어떤 접근이 허용되거나 거부되는지를 지정하며, 이러한 규칙이 하위 항목에 어떻게 적용되는지를 결정합니다(상속). ACE에는 두 가지 주요 유형이 있습니다:

- **Generic ACEs**: 이들은 광범위하게 적용되며, 모든 유형의 객체에 영향을 미치거나 컨테이너(폴더)와 비컨테이너(파일)만 구분합니다. 예를 들어, 사용자가 폴더의 내용을 볼 수 있지만 그 안의 파일에 접근할 수 없는 규칙입니다.
- **Object-Specific ACEs**: 이들은 더 정밀한 제어를 제공하며, 특정 유형의 객체 또는 객체 내의 개별 속성에 대해 규칙을 설정할 수 있습니다. 예를 들어, 사용자 디렉토리에서 사용자가 자신의 전화번호를 업데이트할 수 있지만 로그인 시간을 업데이트할 수 없는 규칙이 있을 수 있습니다.

각 ACE는 규칙이 적용되는 대상(보안 식별자 또는 SID 사용), 규칙이 허용하거나 거부하는 내용(접근 마스크 사용), 그리고 다른 객체에 의해 어떻게 상속되는지를 포함하는 중요한 정보를 포함합니다.

#### ACE 유형 간의 주요 차이점

- **Generic ACEs**는 객체의 모든 측면 또는 컨테이너 내의 모든 객체에 동일한 규칙이 적용되는 간단한 접근 제어 시나리오에 적합합니다.
- **Object-Specific ACEs**는 Active Directory와 같은 환경에서 특정 객체의 특정 속성에 대한 접근을 다르게 제어해야 할 때 더 복잡한 시나리오에 사용됩니다.

요약하자면, ACL과 ACE는 정밀한 접근 제어를 정의하는 데 도움을 주며, 올바른 개인이나 그룹만이 민감한 정보나 리소스에 접근할 수 있도록 보장하며, 접근 권한을 개별 속성이나 객체 유형 수준까지 조정할 수 있는 능력을 제공합니다.

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | ACE 유형을 나타내는 플래그입니다. Windows 2000 및 Windows Server 2003은 모든 보안 객체에 부착된 세 가지 일반 ACE 유형과 Active Directory 객체에 발생할 수 있는 세 가지 객체 특정 ACE 유형을 지원합니다.                                                                                                                                                                                                                                                                                                                            |
| Flags       | 상속 및 감사를 제어하는 비트 플래그 집합입니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | ACE에 할당된 메모리의 바이트 수입니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | 객체에 대한 접근 권한에 해당하는 비트의 32비트 값입니다. 비트는 켜거나 끌 수 있지만, 설정의 의미는 ACE 유형에 따라 다릅니다. 예를 들어, 읽기 권한에 해당하는 비트가 켜져 있고 ACE 유형이 Deny인 경우, ACE는 객체의 권한을 읽을 수 있는 권리를 거부합니다. 동일한 비트가 켜져 있지만 ACE 유형이 Allow인 경우, ACE는 객체의 권한을 읽을 수 있는 권리를 부여합니다. 접근 마스크에 대한 더 많은 세부정보는 다음 표에 나타납니다. |
| SID         | 이 ACE에 의해 제어되거나 모니터링되는 사용자 또는 그룹을 식별합니다.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Object Specific Access Rights      | Read data, Execute, Append data           |
| 16 - 22     | Standard Access Rights             | Delete, Write ACL, Write Owner            |
| 23          | Can access security ACL            |                                           |
| 24 - 27     | Reserved                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | Everything below                          |
| 29          | Generic Execute                    | All things necessary to execute a program |
| 30          | Generic Write                      | All things necessary to write to a file   |
| 31          | Generic Read                       | All things necessary to read a file       |

## References

- [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
- [https://www.coopware.in2.info/\_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 구동되는 **워크플로우**를 쉽게 구축하고 **자동화**하세요.\
지금 액세스하세요:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}
