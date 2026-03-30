# Kupitisha Kinga ya Admin kupitia UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari
- Windows AppInfo inafichua `RAiLaunchAdminProcess` kuanzisha michakato ya UIAccess (iliyokusudiwa kwa upatikanaji/accessibility). UIAccess hupitisha vichujio vya User Interface Privilege Isolation (UIPI) vya ujumbe ili programu za accessibility ziweze kuendesha UI yenye IL ya juu.
- Kuwezesha UIAccess moja kwa moja kunahitaji `NtSetInformationToken(TokenUIAccess)` kwa **SeTcbPrivilege**, hivyo wapiga simu wenye ruhusa ndogo hutegemea service. Service hufanya ukaguzi tatu kwenye binary lengwa kabla ya kuweka UIAccess:
- Manifest iliyoungwa ndani ina `uiAccess="true"`.
- Imeasishwa kwa vyeti vyovyote vinavyotumika na root store ya Local Machine (hakuna hitaji la EKU/Microsoft).
- Iko katika njia ambayo ni ya watumiaji admin pekee kwenye drive ya mfumo (mfano, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, ikiondoa subpaths maalum zinazoweza kuandikwa).
- `RAiLaunchAdminProcess` haitoi prompt ya consent kwa uzinduzi wa UIAccess (vinginevyo tooling za accessibility zusingeweza kuendesha prompt).

## Kuunda tokeni na viwango vya uadilifu
- Ikiwa ukaguzi unafanikiwa, AppInfo **inakopa tokeni ya mpiga simu**, inawasha UIAccess, na inaongeza Integrity Level (IL):
- Mtumiaji admin mwenye mipaka (user yuko katika Administrators lakini anafanya kazi chini ya uchujaji) ➜ **High IL**.
- Mtumiaji asiyo-admin ➜ IL inaongezwa kwa **+16 levels** hadi cap ya **High** (System IL haitelekezwi).
- Ikiwa tokeni ya mpiga simu tayari ina UIAccess, IL haibadiliki.
- “Ratchet” trick: mchakato wa UIAccess unaweza kuzima UIAccess kwa nafsi yake, kuanzisha tena kupitia `RAiLaunchAdminProcess`, na kupata ongezeko jingine la +16 IL. Medium➜High inachukua uzinduzi 255 (inatoa kelele, lakini inafanya kazi).

## Kwa nini UIAccess inaruhusu kutoroka kwa Admin Protection
- UIAccess inamruhusu mchakato wa IL ya chini kutuma ujumbe wa windows kwa windows za IL ya juu (kupitisha vichujio vya UIPI). Kwa **IL sawa**, primitives za kawaida za UI kama `SetWindowsHookEx` **zinaweza kuruhusu code injection/loading ya DLL** ndani ya mchakato wowote unaomilikiwa na window (pamoja na **message-only windows** zinazotumika na COM).
- Admin Protection inaanzisha mchakato wa UIAccess chini ya **kitambulisho cha mtumiaji mwenye mipaka** lakini kwa **High IL**, kimya. Mara code yoyote inapoendeshwa ndani ya mchakato huo wa High-IL UIAccess, mshambuliaji anaweza kuingiza ndani ya michakato mingine ya High-IL kwenye desktop (hata inayomilikiwa na watumiaji tofauti), akivunja mgawanyo uliokusudiwa.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Katika Windows 10 1803+ API ilihamishiwa ndani ya Win32k (`NtUserGetWindowProcessHandle`) na inaweza kufungua handle ya mchakato ikitumia `DesiredAccess` iliyotolewa na mpiga simu. Njia ya kernel inatumia `ObOpenObjectByPointer(..., KernelMode, ...)`, ambayo hupitisha ukaguzi wa kawaida wa upatikanaji wa user-mode.
- Masharti ya awali kwa vitendo: window lengwa lazima iwe kwenye desktop ile ile, na ukaguzi wa UIPI lazima upite. Kivuli, mpiga simu mwenye UIAccess angeweza kupitisha kushindwa kwa UIPI na bado kupata handle ya kernel-mode (imerekebishwa kama CVE-2023-41772).
- Athari: handle ya window inakuwa **sifa (capability)** ya kupata handle yenye nguvu ya mchakato (kwa kawaida `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) ambayo mpiga simu angeweza asifungue kawaida. Hii inaruhusu upatikanaji kati ya sandbox na inaweza kuvunja mipaka ya Protected Process / PPL ikiwa lengwa linaonyesha window yoyote (pamoja na message-only windows).
- Mtiririko wa matumizi ya vitendo: orodhesha au pata HWNDs (mfano `EnumWindows`/`FindWindowEx`), tambua PID inayomilikiwa (`GetWindowThreadProcessId`), itumie `GetProcessHandleFromHwnd`, kisha tumia handle iliyorejeshwa kwa kusoma/kuandika memory au primitives za kukamata code.
- Tabia baada ya fix: UIAccess haingewapa tena funguo za kernel-mode kwa kushindwa kwa UIPI na haki zinazokubaliwa zimepunguzwa kwa seti ya legacy hooks; Windows 11 24H2 inaongeza ukaguzi wa ulinzi wa mchakato na njia salama zinazokuzwa kwa feature-flag. Kuzima UIPI kwa mfumo mzima (`EnforceUIPI=0`) kunaporomosha ulinzi huu.

## Udhaifu wa uhakiki wa saraka salama (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo inaamua path iliyotolewa kupitia `GetFinalPathNameByHandle` kisha inatumia **ukaguzi wa string allow/deny** dhidi ya mizizi/exclusions zilizopachikwa. Aina kadhaa za bypass zinatokana na uhakiki huo wa msingi:
- **Directory named streams**: Saraka zilizokataliwa kwa sababu zinaweza kuandikwa (mfano, `C:\Windows\tracing`) zinaweza kupitishwa kwa stream yenye jina kwenye saraka yenyewe, mfano `C:\Windows\tracing:file.exe`. Ukaguzi wa string unaona `C:\Windows\` na hupotoka exclusion ya subpath.
- **Faili/saraka inayoweza kuandikwa ndani ya root inayoruhusiwa**: `CreateProcessAsUser` **hainahitaji kiendelezi `.exe`**. Kuandika juu ya faili yoyote inayoweza kuandikwa chini ya root inayoruhusiwa kwa payload ya executable inafanya kazi, au kunakili EXE iliyosainiwa yenye `uiAccess="true"` ndani ya subdirectory yoyote inayoweza kuandikwa (mfano, mabaki ya update kama `Tasks_Migrated` pale inapokuwepo) kunaiwezesha kupita uhakiki wa secure-path.
- **MSIX into `C:\Program Files\WindowsApps` (imedhibitiwa)**: Wasio-admin wangeweza kusanidi packages za MSIX zilizosasishwa ndani ya `WindowsApps`, ambayo haikuwekwa kama excluded. Kufunga binary ya UIAccess ndani ya MSIX kisha kuianzisha kupitia `RAiLaunchAdminProcess` kulitoa **mchakato wa High-IL UIAccess bila prompt**. Microsoft ilitatua kwa kuhusisha njia hiyo; uwezo uliokandamizwa wa `uiAccess` kwenye MSIX tayari unahitaji install ya admin.

## Mtiririko wa mashambulizi (High IL bila prompt)
1. Pata/jenga binary iliyosainiwa ya UIAccess (manifest `uiAccess="true"`).
2. Iweke mahali ambapo allowlist ya AppInfo inakubali (au tumia mbinu ya kukiuka uhakiki wa path/artefact inayoweza kuandikwa kama ilivyoelezwa hapo juu).
3. Piga `RAiLaunchAdminProcess` kuizindua kimya kimya na UIAccess + IL iliyoinuliwa.
4. Kutoka kwenye ngalawa ya High-IL, lengwa mchakato mwingine wa High-IL kwenye desktop kwa kutumia **window hooks/DLL injection** au primitives nyingine za same-IL ili kunyakua muktadha wa admin kikamilifu.

## Kuhesabu njia zinazoweza kuandikwa
Endesha helper ya PowerShell kugundua vitu vinavyoweza kuandikwa/kurudishwa ndani ya mizizi inayochukuliwa kuwa salama kutoka mtazamo wa tokeni uliyochaguliwa:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Endesha kama Administrator kwa uonekano mpana; weka `-ProcessId` kwa mchakato wenye vibali vichache ili kuiga ufikiaji wa token hiyo.
- Chuja kwa mkono ili kuondoa folda ndogo zilizojulikana kutoruhusiwa kabla ya kutumia wagombea na `RAiLaunchAdminProcess`.

## Inayohusiana

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Marejeo
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
