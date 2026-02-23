# Kupitisha Admin Protection kupitia UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari
- Windows AppInfo inatoa `RAiLaunchAdminProcess` ili kuanza michakato ya UIAccess (iliyokusudiwa kwa ajili ya accessibility). UIAccess inapita kwenye vichujio vya User Interface Privilege Isolation (UIPI) ili programu za accessibility ziweze kuendesha UI yenye IL ya juu.
- Kuwezesha UIAccess moja kwa moja kunahitaji `NtSetInformationToken(TokenUIAccess)` na **SeTcbPrivilege**, kwa hivyo waitelezaji wenye haki ndogo hutegemea service. Service hufanya ukaguzi tatu kwenye binary lengwa kabla ya kuweka UIAccess:
  - Manifest iliyojazwa ndani ina `uiAccess="true"`.
  - Imewekwa saini na cheti chochote kinachotendewa kuaminiwa na Local Machine root store (hakuna mahitaji ya EKU/Microsoft).
  - Iko kwenye njia inayotengwa kwa administrators tu kwenye drive ya mfumo (mfano, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, isipokuwa subpaths maalum zinazoweza kuandikwa).
- `RAiLaunchAdminProcess` haufanyi ombi la idhini (consent prompt) kwa ajili ya uzinduzi wa UIAccess (vinginevyo zana za accessibility zisingeweza kuendesha prompt).

## Uundaji wa token na viwango vya integriti
- Iwapo ukaguzi unafanikiwa, AppInfo **hunaakili token ya mwito**, inawawezesha UIAccess, na inaongeza Integrity Level (IL):
  - Limited admin user (mtumiaji yako katika Administrators lakini anafanya kazi kwa kuchujwa) ➜ **High IL**.
  - Non-admin user ➜ IL inaongezwa kwa **+16 levels** hadi kifani cha **High** (System IL haitegemei kamwe).
- Iwapo token ya mwito tayari ina UIAccess, IL haibadiliki.
- “Ratchet” trick: mchakato wa UIAccess unaweza kuzima UIAccess kwa nafsi yake, kuzirudisha tena kupitia `RAiLaunchAdminProcess`, na kupata ongezeko lingine la +16 IL. Medium➜High inachukua uzinduzi 255 (sauti, lakini inafanya kazi).

## Kwa nini UIAccess inaruhusu kukwepa Admin Protection
- UIAccess inamruhusu mchakato wenye IL ya chini kutuma window messages kwa windows zilizo na IL ya juu (kupita vichujio vya UIPI). Kwa **IL sawa**, primitives za kawaida za UI kama `SetWindowsHookEx` **zinaweza kuruhusu code injection/kuingiza DLL** ndani ya mchakato wowote unaomiliki window (pamoja na **message-only windows** zinazotumika na COM).
- Admin Protection huanza mchakato wa UIAccess chini ya **utambulisho wa user iliyopunguzwa** lakini kwa **High IL**, bila sauti. Mara tu code yoyote inapoanza ndani ya mchakato huyo wa High-IL UIAccess, mshambuliaji anaweza kuingiza ndani ya michakato mingine ya High-IL kwenye desktop (hata zikiwa za watumiaji tofauti), kuvunja utenganisho uliokusudiwa.

## Udhaifu wa uthibitishaji wa saraka salama (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo inatatua njia iliyotolewa kupitia `GetFinalPathNameByHandle` kisha inatumia **mizunguko ya string allow/deny** dhidi ya mizizi/exclusions iliyowekwa kwa hardcoded. Daraja tofauti za kupitisha hutokana na uthibitishaji huo wa simplistiki:
- **Directory named streams**: Saraka zilizokataliwa lakini zinazoruhusiwa kuandikwa (mfano, `C:\Windows\tracing`) zinaweza kupitishwa kwa kutumia named stream juu ya saraka yenyewe, mfano `C:\Windows\tracing:file.exe`. Ukaguzi wa string unaona `C:\Windows\` na hupoteza subpath iliyokataliwa.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` haitegemei kuwa na `.exe` extension. Kuandika juu ya faili yoyote inayoweza kuandikwa chini ya root iliyoruhusiwa kwa payload ya executable kunafanya kazi, au kunakilipia `uiAccess="true"` EXE iliyosainiwa katika yoyote subdirectory inayoweza kuandikwa (mfano, mabaki ya update kama `Tasks_Migrated` endapo yapo) kunaifanya ipite ukaguzi wa secure-path.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins waliweza kusakinisha packages za MSIX zilizosasishwa ambazo zilifika `WindowsApps`, ambayo haikuwekwa kwenye excluded. Kufungasha binary ya UIAccess ndani ya MSIX kisha kuizindua kupitia `RAiLaunchAdminProcess` kulitoa mchakato wa UIAccess wa High IL bila prompt. Microsoft ilirekebisha kwa kujumuisha njia hiyo; capability ya `uiAccess` iliyozuiwa kwa MSIX yenyewe tayari inahitaji install ya admin.

## Mtiririko wa mashambulizi (High IL bila ombi la idhini)
1. Pata/unda binary ya **sainiwa yenye UIAccess** (manifest `uiAccess="true"`).
2. Iweke mahali ambapo allowlist ya AppInfo inaikubali (au udanganye kwa edge case ya uthibitishaji wa njia / artefact inayoweza kuandikwa kama ilivyoelezwa hapo juu).
3. Piga simu `RAiLaunchAdminProcess` kuikuza kimfumo kwa ukimya na UIAccess + IL iliyoongezeka.
4. Kutoka kwenye nafasi hiyo ya High-IL, lenga mchakato mwingine wa High-IL kwenye desktop ukitumia **window hooks/DLL injection** au primitives nyingine za same-IL ili kuathiri kabisa muktadha wa admin.

## Kuita orodha ya njia zinazoweza kuandikwa
Endesha msaidizi wa PowerShell kugundua vitu vinavyoweza kuandikwa/kuandikishwa upya ndani ya mizizi inayodaiwa kuwa salama kutoka mtazamo wa token iliyochaguliwa:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Endesha kama Administrator kwa uonekano mpana; weka `-ProcessId` kwa low-priv process ili kuiga ufikiaji wa token hiyo.
- Chuja kwa mikono ili kuondoa saraka ndogo zilizojulikana kuwa zisizoruhusiwa kabla ya kutumia wagombea na `RAiLaunchAdminProcess`.

## Marejeo
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
