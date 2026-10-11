# AutorunsによるPrivilege Escalation

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic**は**startup**時にプログラムを実行するために使用できます。startup時に実行されるよう設定されているバイナリを確認するには、次を実行します。

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## スケジュールされたタスク

**タスク**は**特定の頻度**で実行されるようにスケジュールできます。実行がスケジュールされているバイナリを確認するには、次のコマンドを使用します。

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

SYSTEM として実行される有効なタスクは、タスク定義とアクションファイルが保護されていても確認する価値があります。[タスク スケジューラでタスクをオンデマンド実行するには、そのタスクに対する実行権限が必要です](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)。低権限ユーザーがその権限を持っている場合は、実行されるアクションを正確に確認してください。特に、Active Directory の ACL を変更したり、アカウント保護の設定をリセットしたりする PowerShell スクリプトに注意が必要です。タスクの `AllowDemandStart` 設定を確認し、スクリプトの入力と影響を検証してください。固定されたタスクを開始する権限だけでは、任意のコードを実行できるとは限りません。

## フォルダー

**Startup フォルダーにあるすべてのバイナリは、起動時に実行されます**。一般的な Startup フォルダーは以下に示しますが、Startup フォルダーの場所はレジストリで指定されています。[場所はこちらを参照してください。](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

より高い権限を持つユーザーのStartupエントリが、別のユーザーが書き込み可能なディレクトリから繰り返しファイルを開く保護されたスクリプトを起動することがあります。そのディレクトリを権限昇格経路と見なす前に、エントリの**実際のログオンID**、スクリプトの入力ディレクトリとACL、そして正確な処理内容を確認してください。特に、[`hh.exe` はコンパイル済みHTML Help（`.chm`）ファイルを開きます](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program)。呼び出し元から渡されたファイルを`hh.exe`に渡すスクリプトは、ファイル名や先頭のバイトをチェックしていても、コンテンツの信頼境界を越えます。[HTML Helpポリシーによって実行可能なショートカットを制限できるため](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands)、適用されているポリシーと、アクセス可能なコンテンツの挙動を確認してください。`.chm`拡張子やマジックバイトだけでは、より高い権限でのコード実行を証明できません。列挙中に信頼できないファイルを開かず、autorun、プロセスのコマンドライン、パスのアクセス許可を調査してください。

同じコンテンツ境界は、より高い権限を持つユーザーが、別のユーザーによって置き換え可能なドキュメントフォルダー内の`.chm`を**手動で開く**場合にも存在します。正確なファイルと親ディレクトリへの書き込み権限、実際のビューアーの実行IDとファイルを開いたイベント、適用されるHTML Helpポリシーを確認してください。フォルダーが書き込み可能であることや、ドキュメントの確認を依頼されたことだけでは、より高い権限のユーザーが攻撃者の管理下にあるコンテンツを開いたとは言えません。

> **参考**: Archive extraction *path traversal*の脆弱性（WinRAR 7.13より前のバージョンで悪用されたCVE-2025-8088など）を利用すると、展開時にこれらのStartupフォルダーへ直接ペイロードを**配置**でき、次回のユーザーログオン時にコードが実行される可能性があります。この手法の詳細については、以下を参照してください。


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## レジストリ

> [!TIP]
> [こちらの注記](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node**レジストリエントリは、64ビット版Windowsを実行していることを示します。オペレーティングシステムはこのキーを使用して、64ビット版Windows上で動作する32ビットアプリケーション向けに、HKEY_LOCAL_MACHINE\SOFTWAREの別のビューを表示します。

### 実行

**一般に知られている**AutoRunレジストリ:

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

**Run**および**RunOnce**として知られるレジストリキーは、ユーザーがシステムにログインするたびにプログラムを自動実行するよう設計されています。キーのデータ値に割り当てられるコマンドラインは、260文字以内に制限されています。<sup>[[2]](#references)</sup>

**サービスの実行**（起動時のサービス自動起動を制御できます）:

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

Windows Vista以降では、**Run**および**RunOnce**レジストリキーは自動生成されません。これらのキーのエントリは、プログラムを直接起動するか、依存関係として指定できます。たとえば、ログオン時にDLLファイルを読み込むには、**RunOnceEx**レジストリキーと「Depend」キーを使用できます。これは、システム起動時に「C:\temp\evil.dll」を実行するレジストリエントリを追加することで実現できます。<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: **HKLM** 内の記載されたレジストリのいずれかに書き込める場合、別のユーザーがログインしたときに権限昇格できます。

> [!TIP]
> **Exploit 2**: **HKLM** 内のレジストリに指定されたバイナリのいずれかを上書きできる場合、別のユーザーがログインしたときに、そのバイナリをバックドア付きで改変して権限昇格できます。

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

### スタートアップ パス

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**Startup** フォルダーに配置されたショートカットは、ユーザーのログオン時またはシステムの再起動時に、サービスやアプリケーションを自動的に起動します。**Startup** フォルダーの場所は、**Local Machine** と **Current User** の両方のスコープについてレジストリで定義されています。つまり、指定された **Startup** の場所にショートカットを追加すると、ログオンまたは再起動後にリンク先のサービスやプログラムが起動するため、プログラムを自動実行するようスケジュールする簡単な方法となります。<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> **HKLM** 配下の [User] Shell Folder を上書きできる場合、その場所を自分が管理するフォルダーに変更し、ユーザーがシステムにログインするたびに実行される backdoor を配置して、権限を昇格できます。

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

このユーザー単位のレジストリ値には、そのユーザーのログオン時に実行されるスクリプトまたはコマンドを指定できます。影響を受けるユーザーのコンテキストでのみ実行されるため、主に**persistence**の手段ですが、post-exploitationやautorunsの確認時にもチェックする価値があります。<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 現在のユーザーに対してこの値を書き込める場合、管理者権限がなくても、次回の対話型ログオン時に再度実行させることができます。別のユーザーのハイブに書き込める場合、そのユーザーのログオン時にコードを実行できる可能性があります。

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Notes:

- 対象ユーザーがすでに読み取り可能な `.bat`、`.cmd`、`.ps1` などの launcher ファイルは、フルパスを指定することを推奨します。
- 値が削除されるまで、ログオフや再起動後もこの設定は維持されます。
- `HKLM\...\Run` とは異なり、この設定だけでは昇格権限は付与されません。ユーザースコープの永続化です。

### Winlogonキー

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

通常、**Userinit** キーには **userinit.exe** が設定されています。ただし、このキーが変更されている場合、指定された実行ファイルもユーザーのログオン時に **Winlogon** によって起動されます。同様に、**Shell** キーは **explorer.exe** を指すように設定されています。これはWindowsのデフォルトのシェルです。<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> registry value または binary を上書きできれば、privilege escalation が可能です。

### Policy Settings

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

### セーフ モードのコマンド プロンプトを変更する

`HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` の Windows Registry では、**`AlternateShell`** の値がデフォルトで `cmd.exe` に設定されています。つまり、起動時に F8 キーを押して「コマンド プロンプトを使用するセーフ モード」を選択すると、`cmd.exe` が使用されます。ただし、F8 キーを押して手動で選択しなくても、コンピューターが自動的にこのモードで起動するように設定できます。

「コマンド プロンプトを使用するセーフ モード」で自動起動するブート オプションを作成する手順:<sup>[[5]](#references)</sup>

1. `boot.ini` ファイルの属性を変更し、読み取り専用、システム、隠し属性を解除します: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` を開いて編集します。
3. 次のような行を挿入します: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` への変更を保存します。
5. ファイルに元の属性を再適用します: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** Registry key を変更すると、カスタムのコマンド シェルを設定でき、不正アクセスにつながる可能性があります。
- **Exploit 2 (PATH Write Permissions):** システムの **PATH** 変数のいずれかの部分、特に `C:\Windows\system32` より前の部分への書き込み権限があると、カスタムの `cmd.exe` を実行できます。システムがセーフ モードで起動された場合、これはバックドアになる可能性があります。
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini` への書き込み権限があると、セーフ モードで自動起動するよう設定でき、次回の再起動時に不正アクセスが可能になります。

現在の **AlternateShell** の設定を確認するには、次のコマンドを使用します:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### インストール済みコンポーネント

Active Setup は、**デスクトップ環境が完全に読み込まれる前に開始する** Windows の機能です。ユーザーのログオン処理が進む前に完了する必要がある特定のコマンドを優先的に実行します。この処理は、Run や RunOnce レジストリセクションなど、ほかのスタートアップエントリが実行されるよりも前に行われます。

Active Setup は、次のレジストリキーで管理されています。

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

これらのキーには、特定のコンポーネントに対応する複数のサブキーがあります。特に注目すべきキー値は次のとおりです。

- **IsInstalled:**
  - `0` は、コンポーネントのコマンドが実行されないことを示します。
  - `1` は、各ユーザーにつき 1 回コマンドが実行されることを示します。`IsInstalled` の値が存在しない場合も、これがデフォルトの動作です。
- **StubPath:** Active Setup が実行するコマンドを定義します。`notepad` の起動など、有効なコマンドラインを指定できます。

**セキュリティに関する考察:**

- **`IsInstalled`** が `"1"` に設定されたキーの **`StubPath`** を変更または書き換えると、不正なコマンド実行につながり、権限昇格に利用される可能性があります。
- 十分な権限があれば、いずれかの **`StubPath`** 値が参照するバイナリファイルを改変することでも、権限昇格が可能です。

Active Setup コンポーネントの **`StubPath`** 設定を調べるには、次のコマンドを使用できます。

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Browser Helper Objects (BHOs) の概要

Browser Helper Objects（BHO）は、Microsoft Internet Explorer に機能を追加する DLL モジュールです。起動するたびに Internet Explorer と Windows Explorer に読み込まれます。ただし、**NoExplorer** キーを 1 に設定すると実行をブロックでき、Windows Explorer のインスタンスへの読み込みを防止できます。<sup>[[1]](#references)</sup>

BHO は Internet Explorer 11 を介して Windows 10 と互換性がありますが、新しいバージョンの Windows で既定のブラウザーとなっている Microsoft Edge ではサポートされていません。

システムに登録されている BHO を調べるには、次のレジストリキーを確認します。

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

各 BHO はレジストリ内で **CLSID** によって表され、一意の識別子として機能します。各 CLSID の詳細情報は、`HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` の下にあります。

レジストリ内の BHO を検索するには、次のコマンドを利用できます。

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer 拡張機能

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

各 dll ごとに新しいレジストリ エントリが 1 つ作成され、**CLSID** で表されます。CLSID の情報は `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` で確認できます。

### フォント ドライバー

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Open コマンド

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### コンテキストメニューの COM ハンドラー

Explorer のコンテキストメニューハンドラーは、`HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` や `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers` などのキーに登録されたシェル拡張機能です。ハンドラーの既定値、または場合によってはキー名が CLSID です。その CLSID をたどって `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32` を確認します。既定値には、ハンドラーの呼び出し時に読み込まれる DLL の名前が指定されています。

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

32-bit と 64-bit の両方のレジストリビューを確認してください。`HKCR` はユーザーごとのクラス登録とコンピューター全体のクラス登録を統合するため、プロセスがどの基になるキーを参照するか確認してください。低権限のユーザーがコンピューター全体の `InprocServer32` の値を変更できる場合、より高い権限で動作するプロセスを別の DLL にリダイレクトできる可能性があります。ただし、権限昇格には、そのプロセスがハンドラーを呼び出す必要があります。レジストリの値自体が保護されていても、書き込み可能な DLL パスが同様のリスクを生む場合があります。

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

autoruns が見つかる場所はすべて、[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) によって**すでに検索済み**である点に注意してください。ただし、自動実行されるファイルを**より包括的に一覧表示**するには、systinternals の [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) を使用できます。

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## その他

**レジストリなどのAutorunsをさらに確認するには** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [マルウェアの一般的な永続化メカニズム](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: レジストリのRunキー / Startupフォルダー](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – 自動起動カテゴリ (Windows Sysinternals Tools 第2版によるトラブルシューティング)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [別のシェルを起動するブートオプションを追加する方法](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit まとめ 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
