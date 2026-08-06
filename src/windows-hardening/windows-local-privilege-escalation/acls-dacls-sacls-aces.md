# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List(ACL)은 객체와 해당 속성에 대한 보호를 지정하는 Access Control Entry(ACE)의 정렬된 집합입니다. 즉, ACL은 특정 객체에 대해 어떤 security principal(사용자 또는 그룹)의 어떤 작업이 허용되거나 거부되는지를 정의합니다.

ACL에는 두 가지 유형이 있습니다.

- **Discretionary Access Control List (DACL):** 어떤 사용자와 그룹이 객체에 액세스할 수 있거나 없는지를 지정합니다.
- **System Access Control List (SACL):** 객체에 대한 액세스 시도의 auditing을 관리합니다.

파일에 액세스하는 과정에서 시스템은 객체의 security descriptor를 사용자의 access token과 대조하여 ACE에 따라 액세스를 허용할지와 허용 범위를 결정합니다.<sup>[[1]](#references)</sup>

### **주요 구성 요소**

- **DACL:** 객체에 대해 사용자와 그룹의 액세스 권한을 허용하거나 거부하는 ACE를 포함합니다. 기본적으로 액세스 권한을 지정하는 주요 ACL입니다.
- **SACL:** 객체에 대한 액세스를 auditing하는 데 사용되며, ACE는 Security Event Log에 기록할 액세스 유형을 정의합니다. 이는 무단 액세스 시도를 탐지하거나 액세스 문제를 troubleshooting하는 데 매우 유용합니다.<sup>[[1]](#references)</sup>

### **ACL과 시스템의 상호 작용**

각 사용자 세션은 해당 세션과 관련된 security 정보를 포함하는 access token과 연결됩니다. 여기에는 사용자 및 그룹 identity와 privileges가 포함됩니다. 또한 이 token에는 세션을 고유하게 식별하는 logon SID가 포함됩니다.

Local Security Authority(LSASS)는 객체에 대한 액세스 요청을 처리할 때 DACL에서 액세스를 시도하는 security principal과 일치하는 ACE를 확인합니다. 관련 ACE를 찾지 못하면 액세스가 즉시 허용됩니다. 그렇지 않으면 LSASS는 access token의 security principal SID와 ACE를 비교하여 액세스 가능 여부를 결정합니다.<sup>[[1]](#references)</sup>

### **요약된 과정**

- **ACLs:** DACL을 통해 액세스 권한을 정의하고 SACL을 통해 auditing 규칙을 정의합니다.
- **Access Token:** 세션에 대한 사용자, 그룹 및 privilege 정보를 포함합니다.
- **액세스 결정:** DACL ACE와 access token을 비교하여 이루어지며, SACL은 auditing에 사용됩니다.<sup>[[1]](#references)</sup>

### ACEs

**Access Control Entry(ACE)**에는 세 가지 주요 유형이 있습니다.<sup>[[1]](#references)</sup>

- **Access Denied ACE**: 지정된 사용자 또는 그룹이 객체에 액세스하는 것을 명시적으로 거부하는 ACE입니다(DACL에 포함).
- **Access Allowed ACE**: 지정된 사용자 또는 그룹의 객체 액세스를 명시적으로 허용하는 ACE입니다(DACL에 포함).
- **System Audit ACE**: System Access Control List(SACL)에 배치되며, 사용자 또는 그룹이 객체에 액세스를 시도할 때 audit log를 생성합니다. 액세스가 허용되었는지 거부되었는지와 액세스의 종류를 기록합니다.

각 ACE에는 네 가지 중요한 구성 요소가 있습니다.<sup>[[1]](#references)</sup>

1. 사용자 또는 그룹의 **Security Identifier (SID)** (또는 graphical representation에서 해당 principal name).
2. ACE 유형(access denied, allowed 또는 system audit)을 식별하는 **flag**.
3. 자식 객체가 부모로부터 ACE를 상속할 수 있는지를 결정하는 **inheritance flags**.
4. 객체에 부여된 권한을 지정하는 32비트 값인 [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN).

액세스 결정은 다음 조건 중 하나가 충족될 때까지 각 ACE를 순차적으로 확인하여 수행됩니다.<sup>[[1]](#references)</sup>

- **Access-Denied ACE**가 access token에 식별된 trustee에 요청된 권한을 명시적으로 거부합니다.
- **Access-Allowed ACE(s)**가 access token에 포함된 trustee에 요청된 모든 권한을 명시적으로 허용합니다.
- 모든 ACE를 확인한 후 요청된 권한 중 하나라도 명시적으로 허용되지 않았다면 액세스는 암시적으로 **거부**됩니다.

### ACE의 순서

**ACEs**(무언가에 액세스할 수 있는 주체와 없는 주체를 지정하는 규칙)를 **DACL**이라는 목록에 배치하는 방식은 매우 중요합니다. 시스템은 이러한 규칙에 따라 액세스를 허용하거나 거부한 후 나머지 규칙을 더 이상 확인하지 않기 때문입니다.<sup>[[1]](#references)</sup>

ACEs를 구성하는 가장 좋은 방식은 **"canonical order"**라고 합니다. 이 방식은 모든 항목이 원활하고 일관되게 동작하도록 합니다. 다음은 **Windows 2000** 및 **Windows Server 2003**과 같은 시스템에서의 방식입니다.

- 먼저 이 항목에 대해 **명시적으로 설정된** 모든 규칙을 부모 폴더와 같은 다른 위치에서 상속된 규칙보다 앞에 배치합니다.
- 이러한 명시적 규칙 중에서는 **"no"(deny)** 규칙을 **"yes"(allow)** 규칙보다 앞에 배치합니다.
- 다른 위치에서 상속된 규칙은 **가장 가까운 source**(예: 부모)에서 온 규칙부터 시작하여 순서대로 배치합니다. 이 경우에도 **"no"**를 **"yes"**보다 앞에 배치합니다.

이 구성은 두 가지 중요한 이점을 제공합니다.

- 특정한 **"no"** 규칙이 존재하면 다른 **"yes"** 규칙이 있더라도 해당 거부가 적용되도록 합니다.
- 항목의 소유자가 부모 폴더 또는 더 상위 위치의 규칙이 적용되기 전에 누가 액세스할 수 있는지 **최종적으로 결정**할 수 있도록 합니다.

이와 같이 구성하면 파일 또는 폴더의 소유자는 누가 액세스할 수 있는지 매우 정확하게 지정하여, 올바른 사용자는 액세스하고 권한이 없는 사용자는 액세스하지 못하도록 할 수 있습니다.

![NTFS access control entry ordering diagram](https://www.ntfs.com/images/screenshots/ACEs.gif)

따라서 이 **"canonical order"**는 액세스 규칙을 명확하고 효과적으로 적용하기 위한 것으로, 명시적인 규칙을 먼저 배치하고 모든 규칙을 합리적인 방식으로 정렬합니다.

### GUI 예시

[**여기에서 가져온 예시**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

다음은 ACL, DACL 및 ACE를 표시하는 폴더의 일반적인 security tab입니다.

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

**Advanced button**을 클릭하면 inheritance와 같은 추가 옵션이 표시됩니다.

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

그리고 Security Principal을 추가하거나 편집할 수 있습니다.

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

마지막으로 Auditing tab에서 SACL을 확인할 수 있습니다.

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### 액세스 제어를 간단하게 설명하기

폴더와 같은 resource에 대한 액세스를 관리할 때는 Access Control List(ACL) 및 Access Control Entry(ACE)라는 목록과 규칙을 사용합니다. 이를 통해 특정 데이터를 누가 액세스할 수 있거나 없는지를 정의합니다.<sup>[[1]](#references)</sup>

#### 특정 그룹의 액세스 거부

Cost라는 폴더가 있고 marketing team을 제외한 모든 사용자가 해당 폴더에 액세스하도록 하려는 상황을 생각해 보겠습니다. 규칙을 올바르게 설정하면 다른 모든 사용자에게 액세스를 허용하기 전에 marketing team의 액세스를 명시적으로 거부할 수 있습니다. 이를 위해 marketing team의 액세스를 거부하는 규칙을 모든 사용자에게 액세스를 허용하는 규칙보다 앞에 배치합니다.

#### 거부된 그룹의 특정 구성원에게 액세스 허용

marketing director인 Bob은 marketing team에 일반적으로 액세스 권한이 없더라도 Cost 폴더에 액세스해야 한다고 가정해 보겠습니다. Bob에게 액세스 권한을 부여하는 특정 규칙(ACE)을 추가하고, 이를 marketing team의 액세스를 거부하는 규칙보다 앞에 배치할 수 있습니다. 이렇게 하면 team 전체에 대한 일반적인 제한이 있더라도 Bob은 액세스할 수 있습니다.

#### Access Control Entry 이해하기

ACE는 ACL에 포함된 개별 규칙입니다. ACE는 사용자 또는 그룹을 식별하고, 허용 또는 거부되는 액세스를 지정하며, 이러한 규칙이 하위 항목에 어떻게 적용되는지(inheritance)를 결정합니다. ACE에는 두 가지 주요 유형이 있습니다.

- **Generic ACEs**: 광범위하게 적용되며 모든 유형의 객체에 영향을 주거나 container(예: 폴더)와 non-container(예: 파일)만 구분합니다. 예를 들어 사용자가 폴더의 내용을 볼 수 있지만 폴더 안의 파일에는 액세스할 수 없도록 허용하는 규칙이 있습니다.
- **Object-Specific ACEs**: 보다 정확한 제어를 제공하며, 특정 유형의 객체 또는 객체 내의 개별 property에 대해서도 규칙을 설정할 수 있습니다. 예를 들어 사용자 directory에서 사용자가 자신의 phone number는 업데이트할 수 있지만 login hours는 변경할 수 없도록 하는 규칙을 설정할 수 있습니다.

각 ACE에는 규칙의 적용 대상(해당 Security Identifier 또는 SID 사용), 규칙이 허용하거나 거부하는 내용(access mask 사용), 다른 객체에 상속되는 방식과 같은 중요한 정보가 포함됩니다.

#### ACE 유형 간의 주요 차이점

- **Generic ACEs**는 객체의 모든 측면 또는 container 내의 모든 객체에 동일한 규칙을 적용하는 단순한 액세스 제어 시나리오에 적합합니다.
- **Object-Specific ACEs**는 더 복잡한 시나리오에서 사용되며, 특히 Active Directory와 같은 환경에서 객체의 특정 property에 대한 액세스를 서로 다르게 제어해야 할 때 유용합니다.

요약하면 ACL과 ACE는 정밀한 액세스 제어를 정의하여, 올바른 개인 또는 그룹만 민감한 정보나 resource에 액세스하도록 합니다. 또한 개별 property 또는 객체 유형 수준까지 액세스 권한을 세부적으로 조정할 수 있습니다.

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | ACE 유형을 나타내는 flag입니다. Windows 2000 및 Windows Server 2003은 여섯 가지 ACE 유형을 지원합니다. 세 가지 generic ACE 유형은 모든 securable object에 연결됩니다. 세 가지 object-specific ACE 유형은 Active Directory 객체에 대해 사용될 수 있습니다.                                                                                                                                                                                                                                                            |
| Flags       | inheritance와 auditing을 제어하는 bit flag 집합입니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | ACE에 할당된 memory의 byte 수입니다.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | bit가 객체에 대한 access rights에 대응하는 32비트 값입니다. bit는 on 또는 off로 설정할 수 있지만, 설정의 의미는 ACE 유형에 따라 달라집니다. 예를 들어 permissions를 읽을 권한에 해당하는 bit가 켜져 있고 ACE 유형이 Deny이면 ACE는 객체의 permissions를 읽을 권한을 거부합니다. 같은 bit가 켜져 있고 ACE 유형이 Allow이면 ACE는 객체의 permissions를 읽을 권한을 부여합니다. Access mask에 대한 자세한 내용은 다음 표에 나와 있습니다. |
| SID         | 이 ACE에 의해 액세스가 제어되거나 모니터링되는 사용자 또는 그룹을 식별합니다.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Object Specific Access Rights      | 데이터 읽기, Execute, 데이터 Append           |
| 16 - 22     | Standard Access Rights             | Delete, ACL 쓰기, Owner 쓰기            |
| 23          | Security ACL에 액세스 가능           |                                           |
| 24 - 27     | Reserved                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | 아래의 모든 항목                          |
| 29          | Generic Execute                    | 프로그램을 실행하는 데 필요한 모든 항목 |
| 30          | Generic Write                      | 파일에 쓰는 데 필요한 모든 항목   |
| 31          | Generic Read                       | 파일을 읽는 데 필요한 모든 항목       |

## References

- [1] [시스템이 ACL을 사용하는 방법 - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL and the ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}
