# Bypasses za Admin Protection kupitia UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari
- Windows AppInfo hufichua `RAiLaunchAdminProcess` kwa ajili ya kuanzisha michakato ya UIAccess (iliyokusudiwa kwa accessibility). UIAccess hupita filtering nyingi za ujumbe za User Interface Privilege Isolation (UIPI), ili software ya accessibility iweze kudhibiti UI yenye IL ya juu.
- Kuwezesha UIAccess moja kwa moja kunahitaji `NtSetInformationToken(TokenUIAccess)` pamoja na **SeTcbPrivilege**, hivyo callers wenye privilege ndogo hutegemea service. Service hufanya ukaguzi huu mitatu kwenye binary lengwa kabla ya kuweka UIAccess:
- Manifest iliyopachikwa ina `uiAccess="true"`.
- Imesainiwa na certificate yoyote inayoaminika na Local Machine root store (hakuna hitaji la EKU/Microsoft).
- Iko kwenye administrator-only path kwenye system drive (kwa mfano, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), isipokuwa subpaths fulani zinazoweza kuandikwa.
- `RAiLaunchAdminProcess` haionyeshi consent prompt kwa UIAccess launches (vinginevyo accessibility tooling isingeweza kudhibiti prompt).<sup>[[1]](#references)</sup>

## Token shaping na integrity levels
- Ukaguzi ukifaulu, AppInfo **hunakili caller token**, huwezesha UIAccess, na huongeza Integrity Level (IL):
- Limited admin user (user yuko kwenye Administrators lakini anaendesha filtered) ➜ **High IL**.
- Non-admin user ➜ IL huongezwa kwa **+16 levels** hadi kufikia kikomo cha **High** (System IL haipewi kamwe).
- Ikiwa caller token tayari ina UIAccess, IL hubaki bila kubadilishwa.
- Ujanja wa “Ratchet”: mchakato wa UIAccess unaweza kuzima UIAccess yenyewe, kuanzishwa tena kupitia `RAiLaunchAdminProcess`, na kupata ongezeko jingine la +16 la IL. Medium➜High huhitaji relaunch mara 255 (inaonekana, lakini inafanya kazi).<sup>[[1]](#references)</sup>

## Kwa nini UIAccess huwezesha kutoroka Admin Protection
- UIAccess huwezesha mchakato wenye IL ya chini kutuma window messages kwenye windows zenye IL ya juu (ukipita UIPI filters). Kwenye **IL sawa**, classic UI primitives kama `SetWindowsHookEx` **huruhusu code injection/DLL loading** kwenye mchakato wowote unaomiliki window (ikiwemo **message-only windows** zinazotumiwa na COM).
- Admin Protection huanzisha mchakato wa UIAccess kwa identity ya **limited user** lakini kwenye **High IL**, bila prompt. Mara tu arbitrary code inapotekelezwa ndani ya mchakato huo wa High-IL UIAccess, attacker anaweza ku-inject kwenye michakato mingine ya High-IL iliyo kwenye desktop (hata ikiwa ni ya users wengine), na kuvunja separation iliyokusudiwa.<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Kwenye Windows 10 1803+ API ilihamishwa hadi Win32k (`NtUserGetWindowProcessHandle`) na inaweza kufungua process handle kwa kutumia `DesiredAccess` iliyotolewa na caller. Kernel path hutumia `ObOpenObjectByPointer(..., KernelMode, ...)`, ambayo hupita normal user-mode access checks.<sup>[[2]](#references)</sup>
- Preconditions kwa vitendo: target window lazima iwe kwenye desktop ileile, na UIPI checks lazima zipite. Kihistoria, caller mwenye UIAccess angeweza kupita UIPI failure na bado kupata kernel-mode handle (iliwekwa sawa kama CVE-2023-41772).
- Impact: window handle huwa **capability** ya kupata process handle yenye nguvu (mara nyingi `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) ambayo caller kwa kawaida hangeweza kufungua. Hii huwezesha cross-sandbox access na inaweza kuvunja mipaka ya Protected Process / PPL ikiwa target inafichua window yoyote (ikiwemo message-only windows).
- Practical abuse flow: enumerate au locate HWNDs (kwa mfano, `EnumWindows`/`FindWindowEx`), tambua PID inayomiliki (`GetWindowThreadProcessId`), ita `GetProcessHandleFromHwnd`, kisha tumia handle iliyorejeshwa kwa memory read/write au code-hijack primitives.
- Tabia baada ya fix: UIAccess haitoi tena kernel-mode opens kwenye UIPI failure, na access rights zinazoruhusiwa zimewekewa mipaka kwenye legacy hook set; Windows 11 24H2 huongeza process-protection checks na paths salama zaidi zinazoendeshwa na feature flags. Kuzima UIPI system-wide (`EnforceUIPI=0`) hudhoofisha protections hizi.<sup>[[2]](#references)</sup>

## Udhaifu wa secure-directory validation (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo hutatua path iliyotolewa kupitia `GetFinalPathNameByHandle`, kisha hutumia **string allow/deny checks** dhidi ya roots/exclusions zilizowekwa hardcoded. Aina kadhaa za bypass zinatokana na validation hiyo rahisi:
- **Directory named streams**: Directories zilizotengwa zinazoweza kuandikwa (kwa mfano, `C:\Windows\tracing`) zinaweza kupitwa kwa kutumia named stream kwenye directory yenyewe, kwa mfano `C:\Windows\tracing:file.exe`. String checks huona `C:\Windows\` na hukosa subpath iliyotengwa.
- **Writable file/directory ndani ya allowed root**: `CreateProcessAsUser` **haihitaji `.exe` extension**. Ku-overwrite file yoyote inayoweza kuandikwa chini ya allowed root kwa executable payload hufanya kazi, au kunakili EXE iliyosainiwa yenye `uiAccess="true"` kwenye writable subdirectory yoyote (kwa mfano, update leftovers kama `Tasks_Migrated` inapokuwepo) huiruhusu kupita secure-path check.
- **MSIX ndani ya `C:\Program Files\WindowsApps` (fixed)**: Non-admins waliweza kusakinisha signed MSIX packages ambazo ziliishia kwenye `WindowsApps`, ambayo haikuwa imetengwa. Kupakia UIAccess binary ndani ya MSIX na kisha kuizindua kupitia `RAiLaunchAdminProcess` kulitoa **promptless High-IL UIAccess process**. Microsoft ilipunguza tatizo kwa kutenga path hii; restricted MSIX capability ya `uiAccess` yenyewe tayari inahitaji admin install.<sup>[[1]](#references)</sup>

## Attack workflow (High IL bila prompt)
1. Pata/jenga **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Iweke mahali ambapo AppInfo allowlist inakubali (au tumia edge case ya path-validation/writable artifact kama ilivyoelezwa hapo juu).
3. Ita `RAiLaunchAdminProcess` ili kuianzisha **kwa siri** ikiwa na UIAccess + elevated IL.
4. Kutoka kwenye High-IL foothold hiyo, lenga mchakato mwingine wa High-IL kwenye desktop ukitumia **window hooks/DLL injection** au primitives nyingine za same-IL ili ku-compromise kikamilifu admin context.<sup>[[1]](#references)</sup>

## Kuhesabu candidate writable paths
Endesha PowerShell helper ili kugundua objects zinazoweza kuandikwa/ku-overwrite ndani ya secure roots kwa mtazamo wa token iliyochaguliwa:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Endesha kama Administrator kwa mwonekano mpana zaidi; weka `-ProcessId` iwe ya low-priv process ili kuiga access ya token hiyo.
- Filteri manually ili kuondoa subdirectories zinazojulikana kuwa haziruhusiwi kabla ya kutumia candidates pamoja na `RAiLaunchAdminProcess`.

## Zinazohusiana

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Marejeo

- [1] [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
