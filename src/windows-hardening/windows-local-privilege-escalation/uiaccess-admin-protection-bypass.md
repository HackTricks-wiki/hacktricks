# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari
- Windows AppInfo inaonyesha `RAiLaunchAdminProcess` ili kuanzisha mchakato wa UIAccess (iliokusudiwa kwa accessibility). UIAccess hupitisha nyingi za User Interface Privilege Isolation (UIPI) message filtering ili programu za accessibility ziweze kuendesha UI za IL ya juu.
- Kuwezesha UIAccess moja kwa moja kunahitaji `NtSetInformationToken(TokenUIAccess)` na **SeTcbPrivilege**, hivyo wito wa kiwango cha chini hutegemea service. Service hufanya ukaguzi tatu kwenye binary lengwa kabla ya kuweka UIAccess:
  - Manifest iliyowekwa ndani ina `uiAccess="true"`.
  - Imesainiwa na cheti chochote kinachotumika na Local Machine root store (hakuna sharti la EKU/Microsoft).
  - Iko kwenye njia inayomilikiwa na administrator pekee kwenye system drive (mfano, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, ukiondoa subpaths maalum zinazoweza kuandikwa).
- `RAiLaunchAdminProcess` haufanyi prompt ya consent kwa uzinduzi wa UIAccess (vinginevyo tooling za accessibility zingekuwa zikiwajibika kuendesha prompt).

## Token shaping and integrity levels
- Ikiwa ukaguzi unafanikiwa, AppInfo **huiga token ya mwito**, inaiwezesha UIAccess, na inapandisha Integrity Level (IL):
  - Limited admin user (user yupo kwenye Administrators lakini akiendesha kwa filtered) ➜ **High IL**.
  - Non-admin user ➜ IL inapanuka kwa **+16 levels** hadi kofia ya **High** (System IL haijatengwa kamwe).
- Ikiwa token ya mwito tayari ina UIAccess, IL haibadilishwi.
- “Ratchet” trick: mchakato wa UIAccess unaweza kuzima UIAccess kwa nafsi yake, kuanzisha upya kupitia `RAiLaunchAdminProcess`, na kupata ongezeko lingine la +16 IL. Medium➜High inachukua uzinduzi upya 255 mara (inatoa kelele, lakini inafanya kazi).

## Kwa nini UIAccess inaruhusu kutokea kwa Admin Protection escape
- UIAccess inaruhusu mchakato wa IL ya chini kupeleka window messages kwa windows za IL ya juu (kuvuka vichujio vya UIPI). Kwa **IL sawa**, primitives za jadi za UI kama `SetWindowsHookEx` **huruhusu code injection/loading ya DLL** katika mchakato wowote unaomiliki window (ikijumuisha **message-only windows** zinazotumiwa na COM).
- Admin Protection huanzisha mchakato wa UIAccess chini ya **kitambulisho cha user aliye na restricted** lakini kwa **High IL**, bila onyo. Mara tu code yoyote inapokuwa ikitenda ndani ya mchakato huo wa High-IL UIAccess, mwakilishi anaweza kuingiza katika michakato mingine ya High-IL kwenye desktop (hata zinazo milikiwa na watumiaji tofauti), kuvunja mgawanyiko uliokusudiwa.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Kwenye Windows 10 1803+ API ilihamishwa ndani ya Win32k (`NtUserGetWindowProcessHandle`) na inaweza kufungua process handle kwa kutumia `DesiredAccess` iliyotolewa na mwito. Njia ya kernel inatumia `ObOpenObjectByPointer(..., KernelMode, ...)`, ambayo inavuka ukaguzi wa kawaida wa access ya user-mode.
- Masharti ya awali katika vitendo: window lengwa lazima iwe kwenye desktop ile ile, na vipimo vya UIPI visifae. Kihistoria, mwito mwenye UIAccess angeweza kuvuka kushindwa kwa UIPI na bado kupata handle ya kernel-mode (imedhibitiwa kama CVE-2023-41772).
- Athari: handle ya window inakuwa **capability** ya kupata process handle yenye nguvu (kwa kawaida `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) ambayo mwito hangeweza kufungua kawaida. Hii inawezesha upitishaji wa sandbox na inaweza kuvunja mipaka ya Protected Process / PPL ikiwa lengwa linaonyesha window yoyote (ikijumuisha message-only windows).
- Mtiririko wa matumizi kwa vitendo: sijiita au kutafuta HWNDs (mfano, `EnumWindows`/`FindWindowEx`), tambua PID inayomilikwa (`GetWindowThreadProcessId`), piga `GetProcessHandleFromHwnd`, kisha tumia handle iliyorejeshwa kwa primitives za kusoma/kuandika kumbukumbu au hijack ya code.
- Baada ya kurekebishwa: UIAccess haiziiwezi tena kutoa ufunguzi wa kernel-mode kwenye kushindwa kwa UIPI na haki za kufikia zimepunguzwa hadi seti ya hooks ya urithi; Windows 11 24H2 inaongeza ukaguzi wa ulinzi wa mchakato na njia salama zilizo kwenye feature-flag. Kuzima UIPI kwa mfumo mzima (`EnforceUIPI=0`) kunapunguza ulinzi huu.

## Udobu wa uhalali wa directory iliyo salama (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo inatatua path iliyotolewa kupitia `GetFinalPathNameByHandle` kisha inatumia **ukaguzi wa string allow/deny** dhidi ya mizizi/exclusions yaliyo hardcoded. Aina kadhaa za mbinu za kuzuia zinatokana na uhakiki huo wa kiwango cha chini:
- **Directory named streams**: Directory zilizo kwenye exclude za writable (mfano, `C:\Windows\tracing`) zinaweza kuepukwa kwa kutumia named stream kwenye directory yenyewe, mfano `C:\Windows\tracing:file.exe`. ukaguzi wa string unaona `C:\Windows\` na kupitisha subpath iliyokataliwa.
- **File/directory inayoweza kuandikwa ndani ya root inayoruhusiwa**: `CreateProcessAsUser` **hainahitaji kiendelezi cha `.exe`**. Kubadilisha faili yoyote inayoweza kuandikwa chini ya root inayoruhusiwa kwa payload ya executable kunafanya ifae, au kunakili EXE iliyosainiwa yenye `uiAccess="true"` ndani ya subdirectory inayoweza kuandikwa (mfano, mabaki ya update kama `Tasks_Migrated` wakati yanapatikana) inayoiwezesha kupita ukaguzi wa secure-path.
- **MSIX ndani ya `C:\Program Files\WindowsApps` (imedhibitiwa)**: Non-admin walikuwa wanaweza kusanikisha packages za MSIX zilizosasishwa ambazo ziliwekwa katika `WindowsApps`, ambayo haikuwekwa kwenye exclude. Kuweka binary ya UIAccess ndani ya MSIX kisha kuizindua kupitia `RAiLaunchAdminProcess` ilitoa mchakato wa **High-IL UIAccess bila prompt**. Microsoft ilirekebisha kwa kuzuia njia hii; uwezo wa MSIX wa `uiAccess` wenyewe tayari unahitaji install ya admin.

## Mtiririko wa shambulio (High IL bila prompt)
1. Pata/tengeneza binary ya **signed UIAccess** (manifest `uiAccess="true"`).
2. Iiweke pale AppInfo’s allowlist inakubali (au tumia kouta kwa ukaguzi wa njia/artefact inayoweza kuandikwa kama hapo juu).
3. Piga `RAiLaunchAdminProcess` ili kuianzisha kwa siri na UIAccess + IL iliyopandishwa.
4. Kutoka kwenye foothold hiyo ya High-IL, lengwa mchakato mwingine wa High-IL kwenye desktop kwa kutumia **window hooks/DLL injection** au primitives nyingine za same-IL ili kukamata muktadha wa admin kikamilifu.

## Kuorodhesha njia zinazowezekana za kuandikwa
Endesha helper wa PowerShell kugundua vitu vinavyoweza kuandikwa/kuandikizwa tena ndani ya mizizi inayoonekana kuwa salama kutoka mtazamo wa token iliyochaguliwa:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Endesha kama Administrator kwa uonekano mpana; weka `-ProcessId` kwa mchakato wa low-priv ili kuiga ruhusa za token hiyo.
- Chuja kwa mkono ili kuondoa saraka ndogo zilizojulikana kuwa haziruhusiwi kabla ya kutumia candidates na `RAiLaunchAdminProcess`.

## Marejeo
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
