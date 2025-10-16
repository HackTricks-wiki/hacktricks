# Tokensの悪用

{{#include ../../banners/hacktricks-training.md}}

## Tokens

もし **Windows Access Tokens が何か分からない** 場合は、先にこのページを読んでください：


{{#ref}}
access-tokens.md
{{#endref}}

**既に持っている Tokens を悪用して権限昇格できる可能性があります**

### SeImpersonatePrivilege

この特権は、プロセスがそのトークンへのハンドルを取得できる場合に、任意のトークンのインパーソネーション（作成ではない）を許可します。特権付きトークンは、Windows サービス（DCOM）に対して NTLM 認証を行わせ、それをエクスプロイトに向けさせることで取得でき、結果として SYSTEM 権限でプロセスを実行できます。この脆弱性は [juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（winrm を無効化している必要があります）、[SweetPotato](https://github.com/CCob/SweetPotato)、[PrintSpoofer](https://github.com/itm4n/PrintSpoofer) などのツールで悪用可能です。


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

**SeImpersonatePrivilege** と非常に似ており、**同じ手法**で特権トークンを取得します。\
その後、この特権は **新規/サスペンドされたプロセスに primary token を割り当てる** ことを許可します。特権的なインパーソネーショントークンから primary token を派生（DuplicateTokenEx）できます。\
取得したトークンを使い、'CreateProcessAsUser' で **新しいプロセス** を作成するか、プロセスをサスペンドして **トークンを設定** できます（一般に、実行中のプロセスの primary token を変更することはできません）。

### SeTcbPrivilege

このトークンが有効であれば、**KERB_S4U_LOGON** を使って資格情報を知らなくても任意のユーザの **インパーソネーショントークン** を取得し、トークンに任意のグループ（admins）を **追加** し、トークンの **integrity level** を "**medium**" に設定し、そのトークンを **現在のスレッド** に割り当てる（SetThreadToken）ことができます。

### SeBackupPrivilege

この特権はシステムに対して任意のファイルに対する **すべての読み取りアクセス** を付与させます（読み取り操作に限定）。レジストリからローカル Administrator のパスワードハッシュを **読み取る** のに利用され、その後ハッシュを使って "psexec" や "wmiexec" のようなツールを使う（Pass-the-Hash 技術）ことができます。ただし、この手法はローカル Administrator アカウントが無効化されている場合、またはリモート接続時にローカル Administrators から管理権限を削除するポリシーがある場合には失敗します。\
この特権は以下で **悪用** できます：

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- IppSec の以下の解説に従う: [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- または、次の「escalating privileges with Backup Operators」セクションで説明されている方法：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

この特権はファイルの Access Control List (ACL) に関係なく、任意のシステムファイルへの **書き込みアクセス** を許可します。これにより、サービスの **変更**、DLL Hijacking の実行、Image File Execution Options を利用した **デバッガ設定** など、さまざまな昇格手法が可能になります。

### SeCreateTokenPrivilege

SeCreateTokenPrivilege は強力な権限で、特にユーザがトークンをインパーソネートできる場合に有用ですが、SeImpersonatePrivilege が無い状況でも役立ちます。この機能は、同じユーザを表すトークンで、かつそのトークンの integrity level が現在のプロセスのものを超えない場合にインパーソネートできることに依存します。

**要点:**

- **SeImpersonatePrivilege が無くてもインパーソネーション:** 特定の条件下でトークンをインパーソネートすることで、SeCreateTokenPrivilege を使った EoP が可能です。
- **トークンインパーソネーションの条件:** 成功するには、対象トークンが同一ユーザに属し、かつその integrity level がインパーソネートを試みるプロセスの integrity level 以下である必要があります。
- **インパーソネーショントークンの作成・修正:** インパーソネーショントークンを作成し、特権グループの SID（Security Identifier）を追加して拡張することが可能です。

### SeLoadDriverPrivilege

この特権は `ImagePath` と `Type` に特定の値を持つレジストリエントリを作成することで、デバイスドライバを **ロード／アンロード** することを可能にします。`HKLM` (HKEY_LOCAL_MACHINE) への直接書き込みが制限されているため、代わりに `HKCU` (HKEY_CURRENT_USER) を使用する必要があります。しかし、カーネルがドライバ構成のために `HKCU` を認識するようにするには、特定のパスを辿る必要があります。

このパスは `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` で、`<RID>` は現在のユーザの Relative Identifier です。`HKCU` 内にこの全パスを作成し、次の二つの値を設定する必要があります：

- `ImagePath` — 実行するバイナリへのパス
- `Type` — `SERVICE_KERNEL_DRIVER` (`0x00000001`) の値

**手順:**

1. 書き込みが制限されているため `HKLM` ではなく `HKCU` にアクセスする。
2. `HKCU` 内に `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` を作成する（`<RID>` は現在のユーザの Relative Identifier）。
3. `ImagePath` を実行するバイナリのパスに設定する。
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
この特権を乱用する他の方法は次を参照してください: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

これは**SeRestorePrivilege**と同様です。主な機能はプロセスが**オブジェクトの所有権を取得する**ことを可能にし、WRITE_OWNER アクセス権の付与によって明示的な任意アクセス制御の要件を回避します。手順としてはまず書き込み対象のレジストリキーの所有権を確保し、その後 DACL を変更して書き込みを可能にする、というものです。
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

この特権は、**debug other processes**（メモリの読み書きを含む）を許可します。ほとんどのアンチウイルスやホスト侵入防止ソリューションを回避できるような、様々なメモリ注入の手法をこの特権で実行できます。

#### Dump memory

[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) を使用して **capture the memory of a process** することができます。特に、これは **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** プロセスに適用されます。このプロセスは、ユーザーがシステムに正常にログインした後にユーザー資格情報を格納する役割があります。

そのダンプをmimikatzに読み込ませてパスワードを取得できます:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` shell を取得したい場合は、次を使用できます:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

この権利 (Perform volume maintenance tasks) により、NTFS ACLs をバイパスして生のボリュームデバイスハンドル（例: \\.\C:）を開き、直接ディスクI/O を行うことができます。これを使うと、基底ブロックを読み取ることでボリューム上の任意のファイルのバイトをコピーでき、機械の秘密鍵（%ProgramData%\Microsoft\Crypto\、レジストリハイブ、VSS 経由の SAM/NTDS など）といった機密データの任意読み取りが可能になります。CA サーバーでは特に影響が大きく、CA の秘密鍵を持ち出すことで Golden Certificate を偽造し任意のプリンシパルになりすますことができます。

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 権限の確認
```
whoami /priv
```
The **無効と表示されているトークン**は有効化できます。実際に、_有効_ および _無効_ トークンの両方を悪用できます。

### すべてのトークンを有効化

トークンが無効化されている場合は、スクリプト [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) を使用してすべてのトークンを有効化できます:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
またはこの[**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)に埋め込まれた**script**。

## 表

Full token privileges cheatsheet は [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) を参照。以下の要約は、特権を悪用して管理者セッションを取得する、または機密ファイルを読み取るための直接的な方法のみを列挙しています。

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | ありがとうございました [Aurélien Chalot](https://twitter.com/Defte_)。近日中にもっとレシピ風に言い換えてみます。                                                                                                                                                                                                                     |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` を使用して機密ファイルを読み取る                                                                                                                                                                                                                                                                                                  | <p>- %WINDIR%\MEMORY.DMP を読み取れるならより興味深い可能性があります<br><br>- <code>SeBackupPrivilege</code>（および robocopy）は開いているファイルには役立ちません。<br><br>- Robocopy は /b パラメータで動作するために SeBackup と SeRestore の両方を必要とします。</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` を用いてローカル管理者権限を含む任意のトークンを作成する。                                                                                                                                                                                                                                                                       |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | <code>lsass.exe</code> のトークンを複製する。                                                                                                                                                                                                                                                                                                     | スクリプトは [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) にあります。                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. <code>szkg64.sys</code> のようなバグのあるカーネルドライバをロードする<br>2. ドライバの脆弱性を悪用する<br><br>代替として、この権限は <code>ftlMC</code> 組み込みコマンドを使用してセキュリティ関連のドライバをアンロードするために使えます。例： <code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code> の脆弱性は <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> として登録されています。<br>2. <code>szkg64</code> の <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> は <a href="https://twitter.com/parvezghh">Parvez Anwar</a> によって作成されました。</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore 権限が付与された状態で PowerShell/ISE を起動する。<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> で権限を有効化する。<br>3. utilman.exe を utilman.old にリネームする。<br>4. cmd.exe を utilman.exe にリネームする。<br>5. コンソールをロックして Win+U を押す。</p> | <p>一部の AV ソフトウェアにより検知される可能性があります。</p><p>代替手段として、同じ権限を使って "Program Files" にあるサービスバイナリを置き換える方法があります。</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe を utilman.exe にリネームする。<br>4. コンソールをロックして Win+U を押す。</p>                                                                                                                                       | <p>一部の AV ソフトウェアにより検知される可能性があります。</p><p>代替手段として、同じ権限を使って "Program Files" にあるサービスバイナリを置き換える方法があります。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>トークンを操作してローカル管理者権限を含める。SeImpersonate を必要とする場合があります。</p><p>確認中。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## 参考

- Windows tokens を定義したこの表を参照: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- トークンを用いた privesc に関する [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) を参照してください。
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
