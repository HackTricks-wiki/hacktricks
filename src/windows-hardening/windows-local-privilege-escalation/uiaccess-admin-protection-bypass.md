# UIAccess による Admin Protection Bypass

{{#include ../../banners/hacktricks-training.md}}

## 概要
- Windows AppInfo は、UIAccess プロセスを spawn するための `RAiLaunchAdminProcess` を公開している（accessibility 用に意図された機能）。UIAccess は User Interface Privilege Isolation (UIPI) の message filtering の大部分を bypass するため、accessibility software はより高い IL の UI を操作できる。
- UIAccess を直接有効化するには **SeTcbPrivilege** を持つ `NtSetInformationToken(TokenUIAccess)` が必要であるため、low-priv caller は service に依存する。service は UIAccess を設定する前に、対象 binary に対して次の 3 つのチェックを実行する。
- Embedded manifest に `uiAccess="true"` が含まれている。
- Local Machine root store が信頼する任意の certificate によって signed されている（EKU/Microsoft 要件はない）。
- system drive 上の administrator-only path（例: `C:\Windows`、`C:\Windows\System32`、`C:\Program Files`）に配置されている（特定の writable subpath は除外）。
- `RAiLaunchAdminProcess` は UIAccess launch に対して consent prompt を表示しない（そうでなければ accessibility tooling は prompt を操作できない）。<sup>[[1]](#references)</sup>

## Token shaping と integrity levels
- チェックに成功すると、AppInfo は **caller token をコピー**し、UIAccess を有効化して Integrity Level (IL) を引き上げる。
- Limited admin user（user は Administrators に所属しているが filtered 実行中） ➜ **High IL**。
- Non-admin user ➜ IL を **+16 levels** 引き上げ、最大で **High** まで（System IL が割り当てられることはない）。
- caller token がすでに UIAccess を持っている場合、IL は変更されない。
- 「Ratchet」 trick: UIAccess process は自身の UIAccess を無効化し、`RAiLaunchAdminProcess` 経由で relaunch することで、さらに +16 IL increment を得られる。Medium➜High には 255 回の relaunch が必要（noisy だが動作する）。<sup>[[1]](#references)</sup>

## UIAccess によって Admin Protection escape が可能になる理由
- UIAccess により、lower-IL process は higher-IL window に window message を送信できる（UIPI filter を bypass）。**同じ IL** では、`SetWindowsHookEx` のような classic UI primitive によって、window を所有する任意の process（COM が使用する **message-only window** を含む）への code injection/DLL loading が可能になる。
- Admin Protection は UIAccess process を **limited user の identity** で、ただし **High IL** かつ silent に起動する。いったんその High-IL UIAccess process 内で arbitrary code が実行されると、attacker は desktop 上の他の High-IL process（異なる user に属するものも含む）へ inject でき、意図された separation を破壊できる。<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ では API が Win32k に移され（`NtUserGetWindowProcessHandle`）、caller が指定した `DesiredAccess` を使用して process handle を open できる。kernel path は `ObOpenObjectByPointer(..., KernelMode, ...)` を使用するため、通常の user-mode access check を bypass する。<sup>[[2]](#references)</sup>
- 実際の precondition: target window が同じ desktop 上にあり、UIPI check に pass する必要がある。以前は UIAccess を持つ caller が UIPI failure を bypass し、kernel-mode handle を取得できた（CVE-2023-41772 として修正）。
- Impact: window handle が、caller が通常は open できない強力な process handle（一般的には `PROCESS_DUP_HANDLE`、`PROCESS_VM_READ`、`PROCESS_VM_WRITE`、`PROCESS_VM_OPERATION`）を取得するための **capability** になる。これにより cross-sandbox access が可能になり、target が何らかの window（message-only window を含む）を公開している場合、Protected Process / PPL boundary を破壊できる。
- Practical abuse flow: HWND を enumerate または locate し（例: `EnumWindows`/`FindWindowEx`）、owner PID を resolve し（`GetWindowThreadProcessId`）、`GetProcessHandleFromHwnd` を call して、返された handle を memory read/write または code-hijack primitive に使用する。
- Post-fix behavior: UIAccess は UIPI failure 時に kernel-mode open を許可しなくなり、許可される access rights は legacy hook set に制限された。Windows 11 24H2 では process-protection check と feature-flagged safer path が追加されている。UIPI を system-wide で無効化（`EnforceUIPI=0`）すると、これらの protection が弱体化する。<sup>[[2]](#references)</sup>

## Secure-directory validation の弱点（AppInfo `AiCheckSecureApplicationDirectory`）
AppInfo は `GetFinalPathNameByHandle` を使用して指定された path を resolve し、その後、hardcoded root/exclusion に対して **string allow/deny check** を適用する。この単純な validation により、複数の bypass class が生じる。
- **Directory named streams**: Excluded writable directory（例: `C:\Windows\tracing`）は、directory 自体の named stream を使用することで bypass できる。例: `C:\Windows\tracing:file.exe`。string check は `C:\Windows\` を検出するが、excluded subpath を見逃す。
- **Allowed root 内の writable file/directory**: `CreateProcessAsUser` は **`.exe` extension を要求しない**。allowed root 内の writable file を executable payload で overwrite するか、signed `uiAccess="true"` EXE を任意の writable subdirectory（存在する場合は `Tasks_Migrated` などの update leftover）へ copy すれば、secure-path check を pass できる。
- **MSIX を `C:\Program Files\WindowsApps` に配置（修正済み）**: Non-admin は signed MSIX package を install でき、それが `WindowsApps` に配置されていたが、この path は除外されていなかった。MSIX 内に UIAccess binary を package し、`RAiLaunchAdminProcess` 経由で launch すると、**promptless High-IL UIAccess process** を取得できた。Microsoft はこの path を除外することで mitigation した。なお、`uiAccess` restricted MSIX capability 自体にはすでに admin install が必要である。<sup>[[1]](#references)</sup>

## Attack workflow（prompt なしで High IL）
1. **signed UIAccess binary**（manifest に `uiAccess="true"`）を obtain/build する。
2. AppInfo の allowlist が accept する場所に配置する（または上記の path-validation edge case/writable artifact を abuse する）。
3. `RAiLaunchAdminProcess` を call し、UIAccess + elevated IL で **silently** spawn する。
4. その High-IL foothold から、**window hook/DLL injection** またはその他の same-IL primitive を使用して desktop 上の別の High-IL process を target し、admin context を完全に compromise する。<sup>[[1]](#references)</sup>

## Candidate writable path の enumerate
PowerShell helper を実行して、選択した token の perspective から、nominally secure root 内の writable/overwritable object を discover する。<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- より広い可視性を得るには Administrator として実行し、`-ProcessId` に低権限プロセスを指定して、その token のアクセス権を再現します。
- `RAiLaunchAdminProcess` で候補を使用する前に、既知の許可されていないサブディレクトリを手動で除外します。

## 関連項目

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## 参考資料

- [1] [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
