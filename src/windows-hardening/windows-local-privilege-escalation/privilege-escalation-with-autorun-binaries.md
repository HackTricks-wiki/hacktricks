# Autoruns による Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** は**起動時**にプログラムを実行するために使用できます。起動時に実行されるよう設定されたバイナリを確認するには、次のコマンドを使用します。
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## スケジュールされたタスク

**タスク**は、**特定の頻度**で実行されるようにスケジュールできます。次のコマンドを使用して、実行がスケジュールされているバイナリを確認します。
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## フォルダ

**スタートアップフォルダにあるすべてのバイナリは、起動時に実行されます**。一般的なスタートアップフォルダは以下に示すものですが、スタートアップフォルダはレジストリで指定されています。[場所についてはこちらを参照してください。](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* vulnerabilities (such as the one abused in WinRAR prior to 7.13 – CVE-2025-8088) can be leveraged to **解凍中にこれらのStartup folders内へ直接payloadsを配置し**, resulting in code execution on the next user logon.  For a deep-dive into this technique see:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## レジストリ

> [!TIP]
> [ここからの注記](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** registry entryは、64-bit Windows versionを実行していることを示します。operating systemはこのkeyを使用して、64-bit Windows versions上で実行される32-bit applications向けにHKEY_LOCAL_MACHINE\SOFTWAREの別のviewを表示します。

### Runs

**Commonly known** AutoRun registry:

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

**Run**および**RunOnce**として知られるregistry keysは、userがsystemにlog inするたびにprogramsを自動的に実行するよう設計されています。keyのdata valueとして割り当てられるcommand lineは、260 characters以下に制限されています。<sup>[[2]](#references)</sup>

**Service runs**（boot中のservicesのautomatic startupを制御可能）:

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

Windows Vista以降のversionsでは、**Run**および**RunOnce** registry keysは自動的に生成されません。これらのkeys内のentriesは、programsを直接起動することも、dependenciesとして指定することもできます。例えば、logon時にDLL fileをloadするには、"Depend" keyとともに**RunOnceEx** registry keyを使用できます。これは、system start-up中に"C:\temp\evil.dll"を実行するregistry entryを追加することで実現できます。<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: **HKLM** 内に記載されているいずれかの registry に書き込みできる場合、別の user がログインした際に privileges を escalate できます。

> [!TIP]
> **Exploit 2**: **HKLM** 内のいずれかの registry に指定されている binary を overwrite できる場合、別の user がログインした際にその binary を backdoor 付きで modify して privileges を escalate できます。
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

**Startup** フォルダーに配置されたショートカットは、ユーザーのログオン時またはシステムの再起動時に、サービスやアプリケーションの起動を自動的にトリガーします。**Startup** フォルダーの場所は、**Local Machine** と **Current User** の両方のスコープについてレジストリで定義されています。つまり、指定された **Startup** の場所にショートカットを追加すると、ログオンまたは再起動の処理後に、リンク先のサービスやプログラムが確実に起動します。これは、プログラムを自動的に実行するようスケジュールする簡単な方法です。<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> **HKLM** 配下のいずれかの \[User] Shell Folder を上書きできる場合、自分が管理するフォルダーを指すように設定し、ユーザーがシステムにログインするたびに実行されて特権を昇格する backdoor を配置できます。
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

このユーザーごとのレジストリ値には、そのユーザーのログオン時に実行される script または command を指定できます。影響を受けるユーザーのコンテキストでのみ実行されるため、主に **persistence** の手段ですが、post-exploitation や autoruns のレビュー時にも確認する価値があります。<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 現在のユーザーに対してこの値へ書き込める場合、admin rights なしで次回の interactive logon 時に実行を再トリガーできます。別のユーザーの hive に書き込める場合は、そのユーザーのログオン時に code execution を取得できる可能性があります。
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
注:

- 対象ユーザーがすでに読み取り可能な `.bat`、`.cmd`、`.ps1`、またはその他の launcher ファイルへのフルパスを優先します。
- これは、値が削除されるまで logoff/reboot 後も維持されます。
- `HKLM\...\Run` とは異なり、これ自体で elevation が付与されるわけではありません。これは user-scope persistence です。

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

通常、**Userinit** key には **userinit.exe** が設定されています。ただし、この key が変更されると、指定された executable もユーザーの logon 時に **Winlogon** によって起動されます。同様に、**Shell** key は **explorer.exe** を指すように設定されます。これは Windows の default shell です。<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> レジストリ値またはバイナリを上書きできる場合、privilegesをescalateできます。

### ポリシー設定

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** keyを確認します。
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Safe Mode Command Prompt の変更

Windows Registry の `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` には、デフォルトで `cmd.exe` に設定された **`AlternateShell`** value があります。これは、起動時に F8 キーを押して「Safe Mode with Command Prompt」を選択すると、`cmd.exe` が使用されることを意味します。ただし、F8 キーを押して手動で選択しなくても、コンピューターが自動的にこの mode で起動するように設定できます。

「Safe Mode with Command Prompt」で自動的に起動する boot option を作成する手順:<sup>[[5]](#references)</sup>

1. `boot.ini` file の attributes を変更して、read-only、system、hidden flags を削除します: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` を開いて編集します。
3. 次のような line を挿入します: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` への変更を保存します。
5. 元の file attributes を再適用します: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key を変更すると、custom command shell を設定でき、不正 access に利用される可能性があります。
- **Exploit 2 (PATH Write Permissions):** system の **PATH** variable の一部に write permissions がある場合、特に `C:\Windows\system32` より前の部分にある場合、custom `cmd.exe` を実行できます。これは system が Safe Mode で起動された場合に backdoor になる可能性があります。
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini` への write access があると、自動的な Safe Mode startup が可能になり、次回の reboot 時に不正 access を容易にします。

現在の **AlternateShell** setting を確認するには、次の commands を使用します:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup は、**desktop environment が完全に読み込まれる前に開始される** Windows の feature です。特定の command の実行を優先し、user logon の処理を続行する前に完了させる必要があります。この process は、Run や RunOnce registry sections など、他の startup entries が trigger されるよりも前に実行されます。

Active Setup は、以下の registry keys を通じて管理されます。

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

これらの keys には複数の subkeys が存在し、それぞれが特定の component に対応しています。特に注目すべき key values は以下のとおりです。

- **IsInstalled:**
- `0` は、component の command が execute されないことを示します。
- `1` は、command が user ごとに一度 execute されることを意味します。`IsInstalled` value が存在しない場合の default behavior です。
- **StubPath:** Active Setup によって execute される command を定義します。`notepad` の起動など、任意の有効な command line を指定できます。

**Security Insights:**

- **`IsInstalled`** が `"1"` に設定され、特定の **`StubPath`** が指定された key を modify または write すると、unauthorized command execution が発生し、privilege escalation につながる可能性があります。
- 十分な permissions がある場合、いずれかの **`StubPath`** value が参照する binary file を変更することでも privilege escalation を実現できる可能性があります。

Active Setup components 全体の **`StubPath`** configurations を確認するには、以下の commands を使用できます:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Browser Helper Objects (BHOs) の概要

Browser Helper Objects (BHOs) は、Microsoft の Internet Explorer に追加機能を提供する DLL モジュールです。Internet Explorer と Windows Explorer の起動時に読み込まれます。ただし、**NoExplorer** key を 1 に設定することで実行をブロックでき、Windows Explorer のインスタンスとともに読み込まれないようにできます。<sup>[[1]](#references)</sup>

BHOs は Internet Explorer 11 を介して Windows 10 と互換性がありますが、新しいバージョンの Windows でデフォルト browser となっている Microsoft Edge ではサポートされていません。

システムに登録されている BHOs を確認するには、次の registry keys を調査します。

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

各 BHO は registry 内で **CLSID** によって表され、一意の identifier として機能します。各 CLSID の詳細情報は、`HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` にあります。

registry 内の BHOs を query するには、次の commands を使用できます：
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer 拡張機能

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

レジストリには各 dll ごとに 1 つの新しいレジストリ エントリが含まれ、**CLSID** で表されます。CLSID の情報は `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` で確認できます。

### フォント ドライバー

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### 開くコマンド

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

autorun が存在するすべての場所は、**[winpeas.exe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) によってすでに検索されている**ことに注意してください。ただし、**自動実行される**ファイルのより包括的な一覧が必要な場合は、systinternals の [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) を使用できます。
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## さらに

**[https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) でレジストリのような Autoruns をさらに探す**<sup>[[4]](#references)</sup>

## References

- [1] [一般的な malware の persistence mechanisms](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart categories (Troubleshooting with the Windows Sysinternals Tools, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [alternate shell を起動する boot option を追加する方法](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
