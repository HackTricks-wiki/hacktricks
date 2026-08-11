# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari
- Windows AppInfo hufichua njia ya ndani ya `RAiLaunchAdminProcess` inayotumika kuanzisha UIAccess applications kwa ajili ya accessibility. UIAccess huruhusu interaction iliyochaguliwa kuvuka mipaka ya User Interface Privilege Isolation (UIPI); si bypass ya jumla ya kila process-security boundary.<sup>[[1]](#references)[[3]](#references)</sup>
- Kuwasha UIAccess moja kwa moja kunahitaji `NtSetInformationToken(TokenUIAccess)` pamoja na **SeTcbPrivilege**, hivyo low-priv callers hutegemea service. Service hufanya checks tatu kwenye binary lengwa kabla ya kuweka UIAccess:
- Embedded manifest ina `uiAccess="true"`.
- Imesainiwa na certificate yoyote inayoaminika na Local Machine root store (hakuna sharti la EKU/Microsoft).
- Iko kwenye administrator-only path kwenye system drive (kwa mfano, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, huku subpaths maalum zinazoweza kuandikwa zikiondolewa).
- `RAiLaunchAdminProcess` haifanyi consent prompt kwa UIAccess launches (vinginevyo accessibility tooling haingeweza kuendesha prompt).<sup>[[1]](#references)</sup>

## Token shaping na integrity levels
- Checks zikifaulu, AppInfo **hunakili caller token**, huwezesha UIAccess, na huongeza Integrity Level (IL):
- Limited admin user (user yuko kwenye Administrators lakini anaendesha filtered) ➜ **High IL**.
- Non-admin user ➜ IL huongezwa kwa **+16 levels** hadi kikomo cha **High** (System IL haigawiwi kamwe).
- Ikiwa caller token tayari ina UIAccess, IL huachwa bila kubadilishwa.
- Mbinu ya “Ratchet”: UIAccess process inaweza kujizima UIAccess, kujianzisha tena kupitia `RAiLaunchAdminProcess`, na kupata nyongeza nyingine ya +16 IL. Medium➜High inahitaji relaunch 255 (inaonekana wazi, lakini inafanya kazi).<sup>[[1]](#references)</sup>

## Kwa nini UIAccess huwezesha Admin Protection escape
- UIAccess huruhusu lower-IL process kutuma window messages kwa higher-IL windows (ikivuka UIPI filters). Katika **equal IL**, classic UI primitives kama `SetWindowsHookEx` **huruhusu code injection/DLL loading** ndani ya process yoyote inayomiliki window (ikiwemo **message-only windows** zinazotumiwa na COM).
- Admin Protection huanzisha UIAccess process kwa utambulisho wa **limited user** lakini katika **High IL**, bila prompt. Baada ya arbitrary code kuendeshwa ndani ya High-IL UIAccess process hiyo, attacker anaweza ku-inject kwenye High-IL processes nyingine kwenye desktop (hata zikiwa za users tofauti), na kuvunja separation iliyokusudiwa.<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Kwenye Windows 10 1803+ API ilihamishiwa Win32k (`NtUserGetWindowProcessHandle`) na inaweza kufungua process handle kwa kutumia `DesiredAccess` iliyotolewa na caller. Kernel path hutumia `ObOpenObjectByPointer(..., KernelMode, ...)`, ambayo hupita normal user-mode access checks.<sup>[[2]](#references)</sup>
- Preconditions kwa vitendo: target window lazima iwe kwenye desktop hiyo hiyo, na UIPI checks lazima zipite. Kihistoria, caller mwenye UIAccess angeweza kupita UIPI failure na bado kupata kernel-mode handle (ilirekebishwa kama CVE-2023-41772).
- Historical impact: window handle ikawa **capability** ya process access kama `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, au `PROCESS_VM_OPERATION` ambayo caller hangeweza kupata kwa kawaida. Kabla ya documented fixes, hii ingeweza kuvuka sandbox na protected-process boundaries wakati target ilipowasilisha window, ikiwemo message-only window.<sup>[[2]](#references)</sup>
- Practical abuse flow: enumerate au locate HWNDs (kwa mfano, `EnumWindows`/`FindWindowEx`), tambua PID inayomiliki (`GetWindowThreadProcessId`), ita `GetProcessHandleFromHwnd`, kisha tumia handle iliyorejeshwa kwa memory read/write au code-hijack primitives.
- Post-fix behavior: UIAccess haitoi tena kernel-mode opens wakati wa UIPI failure, na allowed access rights zimewekewa mipaka ya legacy hook set; Windows 11 24H2 huongeza process-protection checks na safer paths zenye feature flags. Kuzima UIPI system-wide (`EnforceUIPI=0`) hudhoofisha protections hizi.<sup>[[2]](#references)</sup>

## Udhaifu wa secure-directory validation (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo hutatua supplied path kupitia `GetFinalPathNameByHandle` na kisha hutumia **string allow/deny checks** dhidi ya hardcoded roots/exclusions. Multiple bypass classes hutokana na validation hiyo rahisi:
- **Directory named streams**: Excluded writable directories (kwa mfano, `C:\Windows\tracing`) zinaweza kubypass kwa named stream kwenye directory yenyewe, kwa mfano `C:\Windows\tracing:file.exe`. String checks huona `C:\Windows\` na hukosa excluded subpath.
- **Writable file/directory ndani ya allowed root**: `CreateProcessAsUser` **haihitaji `.exe` extension**. Ku-overwrite writable file yoyote iliyo chini ya allowed root kwa executable payload hufanya kazi, au kunakili signed `uiAccess="true"` EXE kwenye writable subdirectory yoyote (kwa mfano, update leftovers kama `Tasks_Migrated` inapokuwepo) huiwezesha ipite secure-path check.
- **MSIX ndani ya `C:\Program Files\WindowsApps` (fixed)**: Non-admins wangeweza kusakinisha signed MSIX packages ambazo ziliishia kwenye `WindowsApps`, ambayo haikuwa imeondolewa. Kuweka UIAccess binary ndani ya MSIX kisha kuizindua kupitia `RAiLaunchAdminProcess` kulitoa **promptless High-IL UIAccess process**. Microsoft ilipunguza tatizo kwa kuondoa path hii; `uiAccess` restricted MSIX capability yenyewe tayari inahitaji admin install.<sup>[[1]](#references)</sup>

## Attack workflow (High IL bila prompt)
1. Pata/jenga **signed UIAccess binary** (manifest `uiAccess="true"`). Kwa assessment halisi, test kwa trust material na paths zilizoidhinishwa waziwazi kwa lab; usiongeze attacker certificate kwenye Local Machine root store ya production machine.
2. Iweke mahali ambapo AppInfo’s allowlist inaikubali (au tumia vibaya path-validation edge case/writable artifact kama ilivyoelezwa hapo juu).
3. Ita `RAiLaunchAdminProcess` ili kuizindua **kimya** ikiwa na UIAccess + elevated IL.
4. Kutoka kwenye High-IL foothold hiyo, lenga High-IL process nyingine kwenye desktop ukitumia **window hooks/DLL injection** au other same-IL primitives ili ku-compromise kikamilifu admin context.<sup>[[1]](#references)</sup>

## Kuhesabu candidate writable paths
Endesha PowerShell helper ili kugundua writable/overwritable objects ndani ya secure roots zinazoonekana kuwa salama, kwa mtazamo wa token iliyochaguliwa:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Endesha kama Administrator kwa mwonekano mpana zaidi; weka `-ProcessId` iwe mchakato wa low-priv ili kuakisi ufikiaji wa token hiyo.
- Chuja kwa mikono ili kuondoa subdirectories zinazojulikana kuwa haziruhusiwi kabla ya kutumia candidates pamoja na `RAiLaunchAdminProcess`.

## Zinazohusiana

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Kupita Ulinzi wa Administrator kwa Kutumia Vibaya UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Uchambuzi wa Kina wa GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — Programu za UIAccess](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
