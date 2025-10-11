# トークンの悪用

{{#include ../../banners/hacktricks-training.md}}

## Tokens

もし、**Windows Access Tokens が何か分からない**場合は、先にこのページを読んでください:


{{#ref}}
access-tokens.md
{{#endref}}

**既に持っているトークンを悪用して権限昇格できる可能性があります**

### SeImpersonatePrivilege

この特権を保持するプロセスは、トークンの「作成」ではなく「インパーソネーション（委任）」を行うことができます（そのトークンへのハンドルが得られることが条件）。特権付きトークンは、Windows サービス（DCOM）を利用して、そのサービスに対して NTLM 認証を誘発させることで取得でき、結果として SYSTEM 権限でプロセスを実行できます。この脆弱性は、[juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（winrm を無効化している必要あり）、[SweetPotato](https://github.com/CCob/SweetPotato)、[PrintSpoofer](https://github.com/itm4n/PrintSpoofer) などのツールで悪用できます。


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

SeImpersonatePrivilege と非常に似ており、特権トークンを得るために**同じ方法**を使用します。\
この特権は新規もしくはサスペンドされたプロセスに**primary token を割り当てる**ことを可能にします。特権を持つインパーソネーショントークンから primary token を派生させることができます（DuplicateTokenEx）。\
得たトークンを用いれば、'CreateProcessAsUser' で**新しいプロセス**を作成したり、プロセスをサスペンド状態で作成してからそのプロセスに**トークンを設定**することができます（一般に、実行中のプロセスの primary token を変更することはできません）。

### SeTcbPrivilege

このトークンが有効であれば、**KERB_S4U_LOGON** を使ってクレデンシャルを知らなくても任意のユーザの**インパーソネーション・トークン**を取得でき、トークンに任意のグループ（例: admins）を追加し、トークンの**整合性レベル**を「**medium**」に設定し、このトークンを**現在のスレッド**に割り当てる（SetThreadToken）ことができます。

### SeBackupPrivilege

この特権は任意のファイルに対して（読み取り操作に限定して）**全ての読み取りアクセス**をシステムが与えるようにします。これを利用してレジストリから Local Administrator アカウントのパスワードハッシュを読み取り、その後 "psexec" や "wmiexec" のようなツールでハッシュを使う（Pass-the-Hash 手法）ことが可能です。ただし、Local Administrator アカウントが無効化されている場合、またはリモート接続時に Local Administrators から管理権限を取り除くポリシーが適用されている場合はこの手法は失敗します。\
この特権は次の方法で悪用できます:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- IppSec の説明に従う: [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- または次のセクションで説明されているように（escalating privileges with Backup Operators）:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

この特権は、ファイルの Access Control List (ACL) に関係なく任意のシステムファイルへの**書き込みアクセス**を許可します。サービスの改変、DLL Hijacking、Image File Execution Options による **debugger 設定** など、多くの昇格手法に利用できます。

### SeCreateTokenPrivilege

SeCreateTokenPrivilege は強力な権限で、特にユーザがトークンのインパーソネーション能力を持っている場合に有用ですが、SeImpersonatePrivilege がなくても活用できます。この能力は、同一ユーザを表すトークンをインパーソネートでき、かつそのトークンの整合性レベルが現在のプロセスの整合性レベルを超えない場合に成り立ちます。

主なポイント:

- SeImpersonatePrivilege がなくてもインパーソネーションで EoP に利用できる可能性がある。
- トークンのインパーソネーション条件: 対象トークンが同一ユーザに属し、かつその整合性レベルがインパーソネーションを試みるプロセスの整合性レベル以下であること。
- インパーソネーショントークンの作成と改変: インパーソネーショントークンを作成し、特権グループの SID を追加して強化することができる。

### SeLoadDriverPrivilege

この特権は、特定の `ImagePath` と `Type` の値を持つレジストリエントリを作成することで **デバイスドライバのロード/アンロード** を可能にします。HKLM への直接書き込みは制限されているため、代わりに HKCU を利用する必要があります。しかし、カーネルがドライバ構成として認識するためには特定のパスを辿る必要があります。

そのパスは `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` で、`<RID>` は現在ユーザの Relative Identifier です。HKCU の中にこの完全なパスを作成し、次の二つの値を設定する必要があります:

- `ImagePath` — 実行されるバイナリへのパス
- `Type` — `SERVICE_KERNEL_DRIVER` (`0x00000001`) の値

**実施手順:**

1. 書き込み制限のために HKLM の代わりに HKCU にアクセスする。  
2. HKCU 内に `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` のパスを作成する（`<RID>` は現在のユーザの Relative Identifier）。  
3. `ImagePath` をバイナリの実行パスに設定する。  
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
この特権を悪用するその他の方法は [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege) にあります。

### SeTakeOwnershipPrivilege

これは **SeRestorePrivilege** と似ています。主な機能はプロセスが **オブジェクトの所有権を取得する** ことを可能にし、WRITE_OWNER アクセス権の付与によって明示的な裁量アクセスの要件を回避します。手順としては、まず書き込み対象の registry key の所有権を確保し、次に DACL を変更して書き込みを許可します。
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

この特権により、**debug other processes**（メモリの読み書きを含む）が許可されます。さまざまなメモリ注入の手法は、この特権を利用してほとんどのアンチウイルスやホスト侵入防止ソリューションを回避できます。

#### Dump memory

[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) を使用して、**プロセスのメモリを取得**できます。特に、これは **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** プロセスに当てはまり、ユーザーがシステムに正常にログオンした後にユーザー資格情報を格納する役割を担っています。

そのダンプを mimikatz に読み込んでパスワードを取得できます:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` のシェルを取得したい場合は、次を使用できます：

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

この権利（Perform volume maintenance tasks）は、生のボリュームデバイスハンドル（例: \\.\C:）を開いて、NTFS ACL をバイパスする直接的なディスク I/O を行うことを許可します。これにより、基盤となるブロックを読み取ってボリューム上の任意のファイルのバイトをコピーでき、機密データの任意のファイル読み取りが可能になります（例: %ProgramData%\Microsoft\Crypto\ にあるマシンの秘密鍵、レジストリハイブ、VSS 経由の SAM/NTDS）。CA サーバーでは特に影響が大きく、CA の秘密鍵を外部流出させることで Golden Certificate を偽造し、任意のプリンシパルを偽装できるようになります。

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 特権の確認
```
whoami /priv
```
**tokens that appear as Disabled** と表示されるものは有効化できます。実際には _Enabled_ と _Disabled_ の両方の tokens を悪用できます。

### すべての tokens を有効化する

もし tokens が無効になっている場合は、スクリプト [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) を使用してすべての tokens を有効化できます:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
またはこの [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) に埋め込まれた **script**。

## テーブル

Full token privileges cheatsheet は [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) にあり、以下の要約は特権を悪用して admin session を取得するか機密ファイルを読み取るための直接的な方法のみを列挙します。

| 特権                       | 影響        | ツール                  | 実行経路                                                                                                                                                                                                                                                                                                                                          | 備考                                                                                                                                                                                                                                                                                                                           |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SeAssignPrimaryToken`** | _**Admin**_ | サードパーティツール    | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                       | 更新ありがとうございます [Aurélien Chalot](https://twitter.com/Defte_)。近日中にもう少しレシピ風に言い換えてみます。                                                                                                                                                                                                                 |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` を使って機密ファイルを読み取る                                                                                                                                                                                                                                                                                                     | <p>- %WINDIR%\MEMORY.DMP を読み取れる場合はより興味深い可能性があります<br><br>- <code>SeBackupPrivilege</code>（および robocopy）はオープンファイルに対しては有用ではありません。<br><br>- Robocopy が /b パラメータで動作するには SeBackup と SeRestore の両方が必要です。</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | サードパーティツール    | 任意のトークンを `NtCreateToken` で作成し、local admin 権限を含める。                                                                                                                                                                                                                                                                            |                                                                                                                                                                                                                                                                                                                               |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | `lsass.exe` のトークンを複製する。                                                                                                                                                                                                                                                                                                                | スクリプトは [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) にあります。                                                                                                                                                                                                        |
| **`SeLoadDriver`**         | _**Admin**_ | サードパーティツール    | <p>1. <code>szkg64.sys</code> のような脆弱なカーネルドライバをロードする<br>2. ドライバの脆弱性を悪用する<br><br>あるいは、特権を使ってセキュリティ関連ドライバを <code>ftlMC</code> 組み込みコマンドでアンロードすることも可能。例: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code> の脆弱性は <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> として記載されています。<br>2. <code>szkg64</code> の <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> は <a href="https://twitter.com/parvezghh">Parvez Anwar</a> によって作成されました。</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore 特権を持った状態で PowerShell/ISE を起動する。<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> で特権を有効化する。<br>3. utilman.exe を utilman.old にリネームする。<br>4. cmd.exe を utilman.exe にリネームする。<br>5. コンソールをロックして Win+U を押す。</p> | <p>一部の AV ソフトウェアによって検知される可能性があります。</p><p>代替手段として、同じ特権を使って "Program Files" に保存されたサービス実行ファイルを置き換える方法があります。</p>                                                                                                      |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe を utilman.exe にリネームする。<br>4. コンソールをロックして Win+U を押す。</p>                                                                                                                                       | <p>一部の AV ソフトウェアによって検知される可能性があります。</p><p>代替手段として、同じ特権を使って "Program Files" に保存されたサービス実行ファイルを置き換える方法があります。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | サードパーティツール    | <p>トークンを操作してローカル管理者権限を含める。SeImpersonate が必要になる場合があります。</p><p>要確認。</p>                                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                                                                                               |

## 参照

- Windows トークンを定義しているこの表を参照: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- トークンを用いた privesc に関する [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) を参照してください。
- Microsoft – ボリュームの保守タスクを実行する (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
