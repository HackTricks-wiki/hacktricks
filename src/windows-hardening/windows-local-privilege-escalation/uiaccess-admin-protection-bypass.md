# UIAccess による Admin Protection Bypass

{{#include ../../banners/hacktricks-training.md}}

## 概要
- Windows AppInfo は、accessibility 用の UIAccess applications を起動するために使用される内部 `RAiLaunchAdminProcess` path を公開します。UIAccess は、User Interface Privilege Isolation (UIPI) の境界を越えた限定的な interaction を許可しますが、すべての process-security boundary を一般的に bypass するものではありません。<sup>[[1]](#references)[[3]](#references)</sup>
- UIAccess を直接有効にするには **SeTcbPrivilege** を持つ `NtSetInformationToken(TokenUIAccess)` が必要なため、low-priv caller は service に依存します。service は UIAccess を設定する前に、target binary に対して次の 3 つの checks を実行します:
- Embedded manifest に `uiAccess="true"` が含まれている。
- Local Machine root store が信頼する任意の certificate によって signed されている (EKU/Microsoft 要件なし)。
- system drive 上の administrator-only path (例: `C:\Windows`、`C:\Windows\System32`、`C:\Program Files`。特定の writable subpath は除外) に配置されている。
- `RAiLaunchAdminProcess` は UIAccess launch に対して consent prompt を表示しません (そうでなければ accessibility tooling で prompt を操作できません)。<sup>[[1]](#references)</sup>

## Token shaping と integrity levels
- checks に成功すると、AppInfo は **caller token を copy** し、UIAccess を有効化して Integrity Level (IL) を引き上げます:
- Limited admin user (user は Administrators に所属しているが filtered 状態で実行) ➜ **High IL**。
- Non-admin user ➜ IL を **+16 levels** 引き上げ、最大で **High** まで (System IL が割り当てられることはありません)。
- caller token がすでに UIAccess を持っている場合、IL は変更されません。
- “Ratchet” trick: UIAccess process は自身の UIAccess を無効化し、`RAiLaunchAdminProcess` 経由で relaunch することで、さらに +16 IL increment を獲得できます。Medium➜High には 255 回の relaunch が必要です (noisy ですが動作します)。<sup>[[1]](#references)</sup>

## UIAccess が Admin Protection escape を可能にする理由
- UIAccess により、lower-IL process は higher-IL window に window message を送信できます (UIPI filter を bypass)。**同じ IL** では、`SetWindowsHookEx` などの classic UI primitive によって、window を所有する任意の process (COM が使用する **message-only window** を含む) への code injection/DLL loading が可能です。
- Admin Protection は UIAccess process を **limited user の identity** で、しかし **High IL** かつ prompt なしで起動します。その High-IL UIAccess process 内で arbitrary code が実行されると、attacker は desktop 上の他の High-IL process (異なる user に属するものも含む) に inject でき、意図された separation を破壊できます。<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Windows 10 1803+ では API が Win32k に移され (`NtUserGetWindowProcessHandle`)、caller が指定した `DesiredAccess` を使用して process handle を open できます。kernel path は `ObOpenObjectByPointer(..., KernelMode, ...)` を使用するため、通常の user-mode access check を bypass します。<sup>[[2]](#references)</sup>
- 実際の precondition: target window が同じ desktop 上にあり、UIPI checks に pass する必要があります。以前は、UIAccess を持つ caller が UIPI failure を bypass して kernel-mode handle を取得できました (CVE-2023-41772 として修正済み)。
- Historical impact: window handle が、caller が通常取得できない `PROCESS_DUP_HANDLE`、`PROCESS_VM_READ`、`PROCESS_VM_WRITE`、`PROCESS_VM_OPERATION` などの process access に対する **capability** になっていました。documented fix より前は、target が window (message-only window を含む) を公開していれば、sandbox および protected-process boundary を越えることが可能でした。<sup>[[2]](#references)</sup>
- Practical abuse flow: HWND を enumerate または locate し (例: `EnumWindows`/`FindWindowEx`)、所有する PID を resolve し (`GetWindowThreadProcessId`)、`GetProcessHandleFromHwnd` を call して、返された handle を memory read/write または code-hijack primitive に使用します。
- Post-fix behavior: UIPI failure 時に UIAccess が kernel-mode open を許可することはなくなり、許可される access rights は legacy hook set に制限されました。Windows 11 24H2 では process-protection checks と feature-flagged safer path が追加されています。UIPI を system-wide で無効化 (`EnforceUIPI=0`) すると、これらの protections が弱まります。<sup>[[2]](#references)</sup>

## Secure-directory validation の弱点 (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo は `GetFinalPathNameByHandle` を使用して指定された path を resolve し、その後 hardcoded root/exclusion に対して **string allow/deny checks** を適用します。この単純な validation により、複数の bypass class が発生します:
- **Directory named streams**: Excluded writable directory (例: `C:\Windows\tracing`) は、directory 自体の named stream を使用することで bypass できます。例: `C:\Windows\tracing:file.exe`。string checks は `C:\Windows\` を検出しますが、excluded subpath を見落とします。
- **Allowed root 内の writable file/directory**: `CreateProcessAsUser` は **`.exe` extension を要求しません**。allowed root 内の writable file を executable payload で overwrite すれば動作します。または、signed `uiAccess="true"` EXE を任意の writable subdirectory (存在する場合の `Tasks_Migrated` などの update leftover) に copy すると、secure-path check を pass できます。
- **MSIX を `C:\Program Files\WindowsApps` に配置 (fixed)**: Non-admin は signed MSIX package を install でき、それが `WindowsApps` に配置されていましたが、この path は excluded ではありませんでした。MSIX 内に UIAccess binary を package し、`RAiLaunchAdminProcess` 経由で launch すると、**promptless High-IL UIAccess process** が生成されました。Microsoft はこの path を除外することで mitigate しました。`uiAccess` restricted MSIX capability 自体には、すでに admin install が必要です。<sup>[[1]](#references)</sup>

## Attack workflow (prompt なしの High IL)
1. **signed UIAccess binary** (`uiAccess="true"` manifest) を obtain/build します。realistic assessment では、lab 用に明示的に authorized された trust material と path を使用して test してください。production machine の Local Machine root store に attacker certificate を追加しないでください。
2. AppInfo の allowlist が accept する場所に配置します (または、上記の path-validation edge case/writable artifact を abuse します)。
3. `RAiLaunchAdminProcess` を call して、UIAccess + elevated IL を持つ process を **silently** spawn します。
4. その High-IL foothold から、**window hooks/DLL injection** またはその他の same-IL primitive を使用して desktop 上の別の High-IL process を target し、admin context を完全に compromise します。<sup>[[1]](#references)</sup>

## Candidate writable path の列挙
PowerShell helper を実行して、選択した token の観点から、nominally secure root 内にある writable/overwritable object を discover します:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- より広い可視性を得るには、Administratorとして実行します。`-ProcessId`には低権限のプロセスを指定し、そのtokenのアクセス権を再現します。
- `RAiLaunchAdminProcess`で候補を使用する前に、既知の許可されていないサブディレクトリを手動で除外します。

## 関連

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [UI Accessの悪用によるAdministrator Protectionのバイパス](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH)の詳細解説](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — UIAccessアプリケーション](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
