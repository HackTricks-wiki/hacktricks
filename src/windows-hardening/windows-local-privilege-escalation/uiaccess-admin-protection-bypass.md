# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Oorsig
- Windows AppInfo stel `RAiLaunchAdminProcess` beskikbaar om UIAccess-processen te spawn (bedoel vir toegankelijkheid). UIAccess omseil die meeste User Interface Privilege Isolation (UIPI) boodskapfiltrering sodat toegankelijkheidsagteware hoër-IL UI kan bestuur.
- UIAccess aktiveer direk vereis `NtSetInformationToken(TokenUIAccess)` met **SeTcbPrivilege**, dus lae-privilege oproepers vertrou op die diens. Die diens voer drie kontroles op die teiken-binary uit voordat UIAccess gestel word:
- Embedded manifest bevat `uiAccess="true"`.
- Signed deur enige sertifikaat wat deur die Local Machine root store vertrou word (geen EKU/Microsoft vereiste nie).
- Geleë in 'n administrator-only pad op die stelselry (bv. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, uitgesonderd spesifieke skryfbare subpaaie).
- `RAiLaunchAdminProcess` voer geen consent prompt uit vir UIAccess launches nie (anders sou toegankelijkheidstoerusting nie die prompt kon bestuur nie).

## Token shaping and integrity levels
- As die kontroles slaag, AppInfo **kopieer die caller token**, skakel UIAccess aan, en verhoog die Integrity Level (IL):
- Limited admin user (user is in Administrators maar draai gefiltreer) ➜ **High IL**.
- Non-admin user ➜ IL verhoog met **+16 levels** tot 'n **High** kap (System IL word nooit toegewys nie).
- As die caller token reeds UIAccess het, bly IL onveranderd.
- “Ratchet” trick: 'n UIAccess-proses kan UIAccess op sigself deaktiveer, weerlanseer via `RAiLaunchAdminProcess`, en nog 'n +16 IL verhoging kry. Medium➜High neem 255 herlanserings (noisy, maar werk).

## Why UIAccess enables an Admin Protection escape
- UIAccess laat 'n laer-IL proses toe om window messages na hoër-IL vensters te stuur (omseil UIPI-filters). By **gelyke IL**, laat klassieke UI-primitiewe soos `SetWindowsHookEx` **toe dat kode-inspuiting/DLL-lading** in enige proses wat 'n venster besit (insluitend **message-only windows** wat deur COM gebruik word) plaasvind.
- Admin Protection lanseer die UIAccess-proses onder die **limited user’s identity** maar by **High IL**, stilletjies. Sodra arbitrêre kode binne daardie High-IL UIAccess-proses loop, kan die aanvaller in ander High-IL prosesse op die desktop inspuit (selfs dié van verskillende gebruikers), wat die beoogde skeiding breek.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Op Windows 10 1803+ het die API na Win32k beweeg (`NtUserGetWindowProcessHandle`) en kan 'n proses-handle open met 'n caller-gespesifiseerde `DesiredAccess`. Die kernelpad gebruik `ObOpenObjectByPointer(..., KernelMode, ...)`, wat normale user-mode toegangskontroles omseil.
- Praktiese voorwaardes: die teiken-venster moet op dieselfde desktop wees, en UIPI-kontroles moet slaag. Histories kon 'n caller met UIAccess UIPI-faling omseil en steeds 'n kernel-mode handle kry (gefikseer as CVE-2023-41772).
- Impak: 'n window-handle word 'n **capability** om 'n kragtige proses-handle te bekom (gereeld `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) wat die caller normaalweg nie kon open nie. Dit maak cross-sandbox toegang moontlik en kan Protected Process / PPL-grense breek as die teiken enige venster blootstel (insluitend message-only windows).
- Praktiese misbruikvloei: enumereer of lokaliseer HWNDs (bv. `EnumWindows`/`FindWindowEx`), los die eienaar PID op (`GetWindowThreadProcessId`), roep `GetProcessHandleFromHwnd` aan, en gebruik dan die teruggegewe handle vir geheue lees/skryf of kode-hyjack primitiewe.
- Na-fix gedrag: UIAccess verleen nie meer kernel-mode opens op UIPI-faling nie en toegestane toegangregte is beperk tot die legacy hook stel; Windows 11 24H2 voeg proces-beskermingskontroles en feature-flagged veiliger paaie by. Deaktiveer UIPI stelselwyd (`EnforceUIPI=0`) verswak hierdie beskermings.

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo los die verskafde pad op via `GetFinalPathNameByHandle` en pas dan **string allow/deny checks** toe teen hardcoded roots/uitsluitings. Meervoudige omseilklasses spruit uit daardie simplistiese validasie:
- **Directory named streams**: Uitgeslote skryfbare directories (bv. `C:\Windows\tracing`) kan omseil word met 'n named stream op die directory self, bv. `C:\Windows\tracing:file.exe`. Die stringkontroles sien `C:\Windows\` en mis die uitgeslote subpad.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` vereis **nie 'n `.exe` extension** nie. Oorskryf enige skryfbare lêer onder 'n toegelate root met 'n uitvoerbare payload werk, of kopieer 'n signed `uiAccess="true"` EXE in enige skryfbare subdirectory (bv. update leftovers soos `Tasks_Migrated` as dit bestaan) laat dit die secure-path check slaag.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins kon signed MSIX packages installeer wat in `WindowsApps` beland het, wat nie uitgesluit was nie. Pak 'n UIAccess-binary in die MSIX en lanseer dit via `RAiLaunchAdminProcess` het 'n **promptless High-IL UIAccess process** gegee. Microsoft het dit versag deur hierdie pad uit te sluit; die `uiAccess` beperkte MSIX capability self vereis reeds admin install.

## Attack workflow (High IL without a prompt)
1. Verkry/bou 'n **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Plaas dit waar AppInfo se allowlist dit aanvaar (of misbruik 'n pad-validasie edge case/skryfbare artefak soos hierbo).
3. Roep `RAiLaunchAdminProcess` om dit **stilletjies** met UIAccess + verhoogde IL te spawn.
4. Vanaf daardie High-IL foothold, teiken 'n ander High-IL proses op die desktop met behulp van **window hooks/DLL injection** of ander same-IL primitiewe om die admin-konteks volledig te kompromitteer.

## Enumerating candidate writable paths
Voer die PowerShell-helper uit om skryfbare/oor-skryfbare voorwerpe binne nominale secure roots te ontdek vanaf die perspektief van 'n gekose token:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Voer as Administrator uit vir groter sigbaarheid; stel `-ProcessId` op 'n low-priv proses om daardie token se toegang te spiegel.
- Filtreer handmatig om bekende nie-toegelate subgidse uit te sluit voordat u kandidate met `RAiLaunchAdminProcess` gebruik.

## Verwysings
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
