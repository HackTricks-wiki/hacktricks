# Autoruns による権限昇格

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** を使うと、**startup** 時にプログラムを実行できます。startup 時に実行されるよう設定されているバイナリを確認するには、次のコマンドを実行します:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## スケジュールされたタスク

**タスク**は、**特定の頻度**で実行するようスケジュールできます。実行が予定されているバイナリを確認するには、以下のコマンドを使用します。

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

`/sc ONLOGON /rl HIGHEST` で作成されたタスクは、登録されたプリンシパルで**利用可能な**最高の実行レベルを要求します。このスイッチだけでは、そのプリンシパルは変更されず、UAC も回避できません。低い権限のプロセスは、最高の実行レベルのタスクを登録したり、タスクの実行 ID として SYSTEM を指定したりできません。上記の例は、標準ユーザーから SYSTEM に昇格する手段ではなく、すでに昇格済みの呼び出し元が実行する操作として扱ってください。<sup>[[8]](#references)</sup>

SYSTEM として実行される有効なタスクは、タスク定義とアクションファイルが保護されている場合でも、確認する価値があります。[タスク スケジューラでタスクをオンデマンド実行するには、そのタスクに対する実行権限が必要です](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)。低い権限のユーザーがその権限を持っている場合は、正確なアクションを確認してください。特に、Active Directory ACL を変更したり、アカウント保護設定をリセットしたりする PowerShell スクリプトに注意してください。タスクの `AllowDemandStart` 設定を確認し、スクリプトの入力と影響を検証してください。固定タスクを開始する権限があっても、それだけで任意のコードを実行できるわけではありません。

## フォルダー

**Startup フォルダー**にあるすべてのバイナリは、起動時に実行されます。一般的な Startup フォルダーは以下に列挙されていますが、Startup フォルダーの場所はレジストリに示されています。[場所はこちらを参照してください。](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

より高い権限を持つユーザーの Startup エントリが、別のユーザーが書き込み可能なディレクトリ内のファイルを繰り返し開く保護されたスクリプトを起動する場合があります。このディレクトリを権限昇格経路とみなす前に、エントリの**実際のログオン ID**、スクリプトの入力ディレクトリと ACL、実行される正確な処理を確認してください。特に、[`hh.exe` はコンパイル済み HTML Help (`.chm`) ファイルを開きます](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program)。呼び出し元が指定したファイルをこのプログラムに渡すスクリプトは、ファイル名や先頭のバイトを確認していても、コンテンツの信頼境界を越えています。[HTML Help のポリシーでは、実行可能なショートカットを制限できます](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands)。そのため、インストールされているポリシーと、アクセス可能なコンテンツの動作を確認してください。`.chm` 拡張子やマジックバイトだけでは、より高い権限でのコード実行を証明できません。列挙中に信頼できないファイルを開かずに、autorun、プロセスのコマンドライン、パスのアクセス許可を調べてください。

同じコンテンツの信頼境界は、より高い権限を持つ人が、別のユーザーが置き換え可能なドキュメントフォルダーから `.chm` を**手動で開く**場合にも存在します。正確なファイルと親ディレクトリへの書き込み権限、実際のビューアーの実行 ID とファイルを開いたイベント、有効な HTML Help ポリシーを確認してください。フォルダーが書き込み可能であることや、ドキュメントのレビューを依頼されたことだけでは、より高い権限のユーザーが攻撃者の制御下にあるコンテンツを開いたことにはなりません。

> **参考情報**: アーカイブ展開時の *path traversal* 脆弱性（WinRAR 7.13 より前のバージョンで悪用されたもの – CVE-2025-8088 など）を利用して、展開中に payload をこれらの Startup フォルダー内へ直接配置し、次回のユーザーログオン時にコード実行を引き起こすことができます。この手法の詳細については、以下を参照してください。


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## レジストリ

> [!TIP]
> [こちらからの注記](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** レジストリエントリは、64-bit Windows バージョンを実行していることを示します。オペレーティングシステムはこのキーを使用し、64-bit Windows バージョン上で動作する 32-bit アプリケーション向けに HKEY_LOCAL_MACHINE\SOFTWARE の別のビューを表示します。

### 実行

**よく知られている** AutoRun レジストリ:

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

**Run** および **RunOnce** として知られるレジストリキーは、ユーザーがシステムにログインするたびにプログラムを自動実行するよう設計されています。キーのデータ値として割り当てられるコマンドラインは、260 文字以下に制限されています。<sup>[[2]](#references)</sup>

**サービスの実行**（起動時のサービスの自動起動を制御可能）:

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

Windows Vista 以降では、**Run** および **RunOnce** レジストリキーは自動的に生成されません。これらのキーのエントリは、プログラムを直接起動することも、依存関係として指定することもできます。たとえば、ログオン時に DLL ファイルを読み込むには、"Depend" キーとともに **RunOnceEx** レジストリキーを使用できます。これは、システム起動時に "C:\temp\evil.dll" を実行するレジストリエントリを追加することで実現できます。<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: **HKLM** 内の記載されたレジストリのいずれかに書き込める場合、別のユーザーがログインしたときに権限昇格できます。

> [!TIP]
> **Exploit 2**: **HKLM** 内のいずれかのレジストリで指定されたバイナリを上書きできる場合、そのバイナリにバックドアを仕込むことで、別のユーザーがログインしたときに権限昇格できます。

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

**Startup** フォルダーに配置されたショートカットは、ユーザーのログオン時またはシステムの再起動時に、サービスやアプリケーションを自動的に起動します。**Startup** フォルダーの場所は、**Local Machine** と **Current User** の両方のスコープについてレジストリで定義されています。つまり、指定された **Startup** の場所にショートカットを追加すると、ログオンまたは再起動の後にリンク先のサービスやプログラムが起動するため、プログラムを自動実行するための簡単な方法になります。<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> **HKLM** 配下の \[User] Shell Folder を上書きできる場合、その場所を自分が管理するフォルダーに変更し、ユーザーがシステムにログインするたびに実行される backdoor を配置して、権限を昇格できます。

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

このユーザーごとのレジストリ値には、そのユーザーのログオン時に実行されるスクリプトまたはコマンドを指定できます。影響を受けるユーザーのコンテキストでのみ実行されるため、主に**persistence**の手段ですが、post-exploitationやautorunsの確認時にも調べる価値があります。<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 現在のユーザーのこの値に書き込める場合、管理者権限がなくても、次回の対話型ログオン時に実行を再トリガーできます。別のユーザーのハイブに書き込める場合は、そのユーザーのログオン時にコードを実行できる可能性があります。

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

メモ:

- 対象ユーザーがすでに読み取り可能な `.bat`、`.cmd`、`.ps1` などのランチャーファイルは、フルパスで指定してください。
- この値が削除されるまで、ログオフや再起動後も有効です。
- `HKLM\...\Run` とは異なり、これだけでは昇格権限は付与されません。ユーザースコープの永続化です。

### Winlogon キー

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

通常、**Userinit** キーには **userinit.exe** が設定されています。ただし、このキーが変更されると、指定された実行ファイルもユーザーのログオン時に **Winlogon** によって起動されます。同様に、**Shell** キーには **explorer.exe** を指定することが意図されています。これは Windows のデフォルトシェルです。<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> レジストリ値またはバイナリを上書きできれば、権限を昇格できます。

### ポリシー設定

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run**キーを確認します。

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### セーフ モードのコマンド プロンプトを変更する

Windows Registry の `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` には、既定で `cmd.exe` に設定された **`AlternateShell`** 値があります。これは、起動時に F8 キーを押して「コマンド プロンプトを使用したセーフ モード」を選択すると、`cmd.exe` が使用されることを意味します。ただし、F8 キーを押して手動で選択しなくても、このモードでコンピューターが自動的に起動するように設定できます。

「コマンド プロンプトを使用したセーフ モード」で自動起動するブート オプションを作成する手順:<sup>[[5]](#references)</sup>

1. `boot.ini` ファイルの属性を変更し、読み取り専用、システム、隠し属性を解除します: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` を開いて編集します。
3. 次のような行を挿入します: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` への変更を保存します。
5. ファイルに元の属性を再設定します: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key を変更すると、カスタムのコマンド シェルを設定でき、不正アクセスにつながる可能性があります。
- **Exploit 2 (PATH Write Permissions):** システムの **PATH** 変数のいずれかの部分、特に `C:\Windows\system32` より前の部分に書き込み権限があると、カスタムの `cmd.exe` を実行できます。システムがセーフ モードで起動した場合、これはバックドアになる可能性があります。
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini` への書き込み権限があると、セーフ モードでの自動起動を設定でき、次回の再起動時に不正アクセスを容易にします。

現在の **AlternateShell** 設定を確認するには、次のコマンドを使用します:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### インストール済みコンポーネント

Active Setup は、**デスクトップ環境が完全に読み込まれる前に開始される** Windows の機能です。ユーザーのログオン処理が続行される前に完了する必要がある特定のコマンドを優先的に実行します。この処理は、Run や RunOnce のレジストリセクションにあるエントリなど、他のスタートアップエントリが実行されるよりも前に行われます。

Active Setup は、次のレジストリキーで管理されます。

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

これらのキーには、特定のコンポーネントに対応するさまざまなサブキーがあります。特に注目すべきキー値は次のとおりです。

- **IsInstalled:**
  - `0` は、コンポーネントのコマンドが実行されないことを示します。
  - `1` は、ユーザーごとにコマンドが一度実行されることを示します。`IsInstalled` の値が存在しない場合は、これがデフォルトの動作です。
- **StubPath:** Active Setup によって実行されるコマンドを定義します。`notepad` の起動など、有効なコマンドラインを指定できます。

**セキュリティに関する知見:**

- **`IsInstalled`** が `"1"` に設定され、特定の **`StubPath`** が指定されたキーを変更または書き込むと、不正なコマンド実行につながり、権限昇格に悪用される可能性があります。
- 十分な権限があれば、任意の **`StubPath`** 値が参照するバイナリファイルを変更することでも、権限昇格が可能です。

Active Setup コンポーネント全体の **`StubPath`** の設定を確認するには、次のコマンドを使用できます。

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Browser Helper Objects (BHOs) の概要

Browser Helper Objects (BHOs) は、Microsoft Internet Explorer に追加機能を提供する DLL モジュールです。起動するたびに Internet Explorer と Windows Explorer に読み込まれます。ただし、**NoExplorer** キーを 1 に設定すると実行をブロックでき、Windows Explorer のインスタンスへの読み込みを防げます。<sup>[[1]](#references)</sup>

BHO は Internet Explorer 11 を介して Windows 10 と互換性がありますが、新しいバージョンの Windows の既定のブラウザーである Microsoft Edge ではサポートされていません。

システムに登録されている BHO を調べるには、次のレジストリキーを確認します。

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

各 BHO はレジストリ内で **CLSID** によって表され、一意の識別子として機能します。各 CLSID の詳細情報は、`HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` にあります。

レジストリ内の BHO を照会するには、次のコマンドを利用できます。

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer 拡張機能

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

各 DLL に対してレジストリに新しいエントリが 1 つ作成され、**CLSID** で表されます。CLSID の情報は `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` で確認できます。

### フォント ドライバー

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### 起動コマンド

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

32-bit と 64-bit の両方のレジストリビューを確認してください。`HKCR` はユーザーごとのクラス登録とマシン全体のクラス登録を統合するため、プロセスがどの基になるキーを参照するか確認してください。マシン全体の `InprocServer32` 値を変更できる低権限の ID は、より高い権限で実行されるプロセスを別の DLL にリダイレクトできますが、権限昇格にはそのプロセスがハンドラーを呼び出す必要があります。レジストリ値自体が保護されていても、書き込み可能な DLL のパスが同様のリスクを生むことがあります。

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

autoruns のエントリが見つかる場所はすべて、[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) によって**すでに検索されています**。ただし、自動実行されるファイルを**より網羅的に一覧表示**するには、systinternals の [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) を使用できます。

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## 詳細

**レジストリなどの Autoruns の詳細はこちら:** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [一般的なマルウェアの永続化メカニズム](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – 自動起動カテゴリ (Windows Sysinternals ツールによるトラブルシューティング、第2版)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [代替シェルを起動するブート オプションを追加する方法](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit まとめ 2026年4月3日](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – タスクのセキュリティ コンテキスト](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
