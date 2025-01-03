# トークンの悪用

{{#include ../../banners/hacktricks-training.md}}

## トークン

もし**Windows Access Tokensが何か分からない場合**は、続ける前にこのページを読んでください：

{{#ref}}
access-tokens.md
{{#endref}}

**既に持っているトークンを悪用して特権を昇格できるかもしれません**

### SeImpersonatePrivilege

これは、ハンドルを取得できる限り、任意のトークンの偽装（ただし作成は不可）を許可するプロセスが保持する特権です。特権トークンは、Windowsサービス（DCOM）からNTLM認証を悪用して取得でき、その後、SYSTEM特権でプロセスを実行することが可能になります。この脆弱性は、[juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（winrmが無効である必要があります）、[SweetPotato](https://github.com/CCob/SweetPotato)、および[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)などのさまざまなツールを使用して悪用できます。

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

これは**SeImpersonatePrivilege**に非常に似ており、特権トークンを取得するために**同じ方法**を使用します。\
この特権は**新しい/一時停止中のプロセスにプライマリトークンを割り当てる**ことを許可します。特権の偽装トークンを使用してプライマリトークンを派生させることができます（DuplicateTokenEx）。\
このトークンを使用して、'CreateProcessAsUser'で**新しいプロセス**を作成するか、一時停止したプロセスを作成して**トークンを設定**できます（一般的に、実行中のプロセスのプライマリトークンを変更することはできません）。

### SeTcbPrivilege

このトークンが有効になっている場合、**KERB_S4U_LOGON**を使用して、資格情報を知らなくても他のユーザーの**偽装トークン**を取得でき、**任意のグループ**（管理者）をトークンに追加し、トークンの**整合性レベル**を「**中**」に設定し、このトークンを**現在のスレッド**に割り当てることができます（SetThreadToken）。

### SeBackupPrivilege

この特権により、システムは任意のファイルに対して**すべての読み取りアクセス**制御を付与します（読み取り操作に制限されます）。これは、レジストリからローカル管理者アカウントのパスワードハッシュを**読み取る**ために利用され、その後、ハッシュを使用して「**psexec**」や「**wmiexec**」などのツールを使用できます（Pass-the-Hash技術）。ただし、この技術は、ローカル管理者アカウントが無効になっている場合や、リモート接続するローカル管理者から管理権限を削除するポリシーが適用されている場合に失敗します。\
この特権を**悪用する**ことができます：

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)の**IppSec**をフォローする
- または、以下のセクションの**バックアップオペレーターによる特権の昇格**で説明されているように：

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

この特権は、ファイルのアクセス制御リスト（ACL）に関係なく、任意のシステムファイルへの**書き込みアクセス**を提供します。これにより、サービスの**変更**、DLLハイジャックの実行、さまざまな他の技術の中でImage File Execution Optionsを介して**デバッガー**を設定するなど、特権昇格の多くの可能性が開かれます。

### SeCreateTokenPrivilege

SeCreateTokenPrivilegeは強力な権限であり、特にユーザーがトークンを偽装する能力を持っている場合に有用ですが、SeImpersonatePrivilegeがない場合にも役立ちます。この能力は、同じユーザーを表すトークンを偽装する能力に依存し、その整合性レベルが現在のプロセスの整合性レベルを超えないことが条件です。

**重要なポイント：**

- **SeImpersonatePrivilegeなしの偽装：** 特定の条件下でトークンを偽装することで、EoPのためにSeCreateTokenPrivilegeを利用することが可能です。
- **トークン偽装の条件：** 成功する偽装には、ターゲットトークンが同じユーザーに属し、整合性レベルが偽装を試みるプロセスの整合性レベル以下である必要があります。
- **偽装トークンの作成と変更：** ユーザーは偽装トークンを作成し、特権グループのSID（セキュリティ識別子）を追加することで強化できます。

### SeLoadDriverPrivilege

この特権は、特定の値を持つレジストリエントリを作成することで**デバイスドライバをロードおよびアンロード**することを許可します。`HKLM`（HKEY_LOCAL_MACHINE）への直接書き込みアクセスが制限されているため、`HKCU`（HKEY_CURRENT_USER）を代わりに使用する必要があります。ただし、ドライバ構成のために`HKCU`をカーネルに認識させるには、特定のパスに従う必要があります。

このパスは`\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`であり、`<RID>`は現在のユーザーの相対識別子です。`HKCU`内にこの全パスを作成し、2つの値を設定する必要があります：

- `ImagePath`、実行されるバイナリへのパス
- `Type`、値は`SERVICE_KERNEL_DRIVER`（`0x00000001`）。

**従うべき手順：**

1. 制限された書き込みアクセスのために`HKLM`の代わりに`HKCU`にアクセスします。
2. `HKCU`内に`\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`のパスを作成し、`<RID>`は現在のユーザーの相対識別子を表します。
3. `ImagePath`をバイナリの実行パスに設定します。
4. `Type`を`SERVICE_KERNEL_DRIVER`（`0x00000001`）として割り当てます。
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
より多くの方法でこの特権を悪用することができます [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

これは **SeRestorePrivilege** に似ています。その主な機能は、プロセスが **オブジェクトの所有権を引き受ける** ことを可能にし、WRITE_OWNER アクセス権の提供を通じて明示的な裁量的アクセスの要件を回避します。このプロセスは、まず書き込み目的のために対象のレジストリキーの所有権を確保し、その後 DACL を変更して書き込み操作を有効にすることを含みます。
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

この特権は、**他のプロセスをデバッグする**ことを許可し、メモリの読み書きが可能です。この特権を使用して、ほとんどのアンチウイルスおよびホスト侵入防止ソリューションを回避できるメモリ注入のさまざまな戦略を採用できます。

#### メモリのダンプ

[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)を使用して、[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)から**プロセスのメモリをキャプチャ**できます。具体的には、ユーザーがシステムに正常にログインした後にユーザー資格情報を保存する**ローカルセキュリティ機関サブシステムサービス（**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**）**プロセスに適用できます。

その後、このダンプをmimikatzにロードしてパスワードを取得できます：
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` シェルを取得したい場合は、次のものを使用できます：

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## 権限を確認する
```
whoami /priv
```
**無効として表示されるトークン**は有効にすることができ、実際に_有効_および_無効_トークンを悪用することができます。

### すべてのトークンを有効にする

トークンが無効になっている場合は、スクリプト[**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)を使用してすべてのトークンを有効にすることができます：
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embed in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"ユーザーがトークンを偽装し、potato.exe、rottenpotato.exe、juicypotato.exeなどのツールを使用してntシステムに昇格することを可能にします"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b`を使用して機密ファイルを読み取る                                                                                                                                                                                                                                                                                                             | <p>- %WINDIR%\MEMORY.DMPを読み取ることができる場合、より興味深いかもしれません。<br><br>- <code>SeBackupPrivilege</code>（およびrobocopy）は、オープンファイルに関しては役に立ちません。<br><br>- Robocopyは、/bパラメータで動作するためにSeBackupとSeRestoreの両方を必要とします。</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken`を使用してローカル管理者権限を含む任意のトークンを作成する。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | `lsass.exe`トークンを複製する。                                                                                                                                                                                                                                                                                                                   | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. <code>szkg64.sys</code>のようなバグのあるカーネルドライバをロードする<br>2. ドライバの脆弱性を悪用する<br><br>または、<code>ftlMC</code>ビルトインコマンドを使用してセキュリティ関連のドライバをアンロードするためにこの特権を使用することができます。すなわち：<code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code>の脆弱性は<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a>としてリストされています。<br>2. <code>szkg64</code>の<a href="https://www.greyhathacker.net/?p=1025">エクスプロイトコード</a>は<a href="https://twitter.com/parvezghh">Parvez Anwar</a>によって作成されました。</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore特権を持つ状態でPowerShell/ISEを起動します。<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>を使用して特権を有効にします。<br>3. utilman.exeをutilman.oldに名前変更します。<br>4. cmd.exeをutilman.exeに名前変更します。<br>5. コンソールをロックし、Win+Uを押します。</p> | <p>攻撃は一部のAVソフトウェアによって検出される可能性があります。</p><p>代替手法は、同じ特権を使用して「Program Files」に保存されたサービスバイナリを置き換えることに依存します。</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exeをutilman.exeに名前変更します。<br>4. コンソールをロックし、Win+Uを押します。</p>                                                                                                                                       | <p>攻撃は一部のAVソフトウェアによって検出される可能性があります。</p><p>代替手法は、同じ特権を使用して「Program Files」に保存されたサービスバイナリを置き換えることに依存します。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>トークンを操作してローカル管理者権限を含める。SeImpersonateが必要な場合があります。</p><p>確認が必要です。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.

{{#include ../../banners/hacktricks-training.md}}
