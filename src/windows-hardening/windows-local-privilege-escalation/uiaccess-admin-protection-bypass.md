# Admin Protection-omseilings deur UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Oorsig
- Windows AppInfo maak `RAiLaunchAdminProcess` beskikbaar om UIAccess-processen te skep (bedoel vir toegankelijkheid). UIAccess omseil die meeste User Interface Privilege Isolation (UIPI) boodskapfiltrering sodat toegankelijkheidssagteware hoër-IL UI kan aanstuur.
- Om UIAccess direk te aktiveer vereis `NtSetInformationToken(TokenUIAccess)` met **SeTcbPrivilege**, dus laag-privilege-aanroepers vertrou op die diens. Die diens voer drie kontroles op die teiken-binary uit voordat UIAccess gestel word:
  - Ingeslote manifest bevat `uiAccess="true"`.
  - Onderteken deur enige sertifikaat wat deur die Local Machine root store vertrou word (geen EKU/Microsoft-vereiste nie).
  - Geleë in 'n administrator-only-pad op die stelselstasie (bv., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, uitgesonder spesifieke skryfbare subpaaie).
- `RAiLaunchAdminProcess` voer geen toestemmingsprompt uit vir UIAccess-lanseer nie (anders sou accessibility-instrumente nie die prompt kon bestuur nie).

## Token-vorming en integriteitsvlakke
- Indien die kontroles slaag, kopieer AppInfo **die aanroeper-token**, skakel UIAccess aan, en verhoog die Integrity Level (IL):
  - Beperkte admin-gebruiker (gebruiker is in Administrators maar loop gefiltreerd) ➜ **High IL**.
  - Nie-admin-gebruiker ➜ IL verhoog met **+16 vlakke** tot 'n **High** plafon (System IL word nooit toegewys nie).
- As die aanroeper-token reeds UIAccess het, bly IL onveranderd.
- “Ratchet”-truuk: 'n UIAccess-proses kan UIAccess op homself deaktiveer, herlancer via `RAiLaunchAdminProcess`, en 'n ander +16 IL-toename kry. Medium➜High verg 255 herlanceringe (luidrugtig, maar werk).

## Waarom UIAccess 'n Admin Protection-ontsnapping moontlik maak
- UIAccess laat 'n laer-IL-proses toe om vensterboodskappe na hoër-IL-vensters te stuur (om UIPI-filtre te omseil). By **gelyke IL**, klassieke UI-primitiewe soos `SetWindowsHookEx` **laat wel kode-inspuiting/DLL-lading toe** in enige proses wat 'n venster besit (insluitend **message-only windows** wat deur COM gebruik word).
- Admin Protection lanseer die UIAccess-proses onder die **beperkte gebruiker se identiteit** maar by **High IL**, stilweg. Sodra ewekansige kode binne daardie High-IL UIAccess-proses loop, kan die aanvaller inspuit in ander High-IL-prosesse op die lessenaar (selfs van verskillende gebruikers), wat die beoogde skeiding breek.

## HWND-na-proses-handvatsel primitief (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Op Windows 10 1803+ is die API na Win32k verskuif (`NtUserGetWindowProcessHandle`) en kan 'n proses-handvatsel oopmaak met 'n deur die aanroeper verskafde `DesiredAccess`. Die kernel-pad gebruik `ObOpenObjectByPointer(..., KernelMode, ...)`, wat normale gebruiker-modus toegangskontroles omseil.
- Voorwaardes in die praktyk: die teiken-venster moet op dieselfde lessenaar wees, en UIPI-kontroles moet slaag. Histories kon 'n aanroeper met UIAccess UIPI-fout omseil en steeds 'n kernel-mode-handvatsel kry (geregstel as CVE-2023-41772).
- Impak: 'n venster-handvatsel word 'n **vermoë** om 'n kragtige proses-handvatsel te verkry (gewoonlik `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) wat die aanroeper normaalweg nie kon oopmaak nie. Dit maak kruis-sandbox toegang moontlik en kan Protected Process / PPL-grense breek as die teiken enige venster blootstel (insluitend message-only windows).
- Praktiese misbruikvloei: enumereer of vind HWNDs (bv., `EnumWindows`/`FindWindowEx`), los die eienaar PID op (`GetWindowThreadProcessId`), roep `GetProcessHandleFromHwnd` aan, en gebruik dan die teruggegewe handvatsel vir geheue lees/skryf of kode-kaping-primitiewe.
- Post-fix-gedrag: UIAccess verleen nie meer kernel-mode oopmaak by UIPI-fout nie en toegelate toegangregte is beperk tot die legacy hook-stel; Windows 11 24H2 voeg proses-beskermingskontroles en feature-flagged veiliger patrone by. Deaktiveer UIPI sistemies (`EnforceUIPI=0`) verswak hierdie beskermings.

## Kwessies in veilige-gids-validasie (AppInfo `AiCheckSecureApplicationDirectory`)
- AppInfo los die verskafte pad op via `GetFinalPathNameByHandle` en pas dan **string allow/deny checks** toe teen hardkodede wortels/uitsluitings. Meerdere omseilklasses spruit uit daardie simplistiese validering:
  - **Directory named streams**: Uitsluitende skryfbare gidse (bv., `C:\Windows\tracing`) kan omseil word met 'n named stream op die gids self, bv. `C:\Windows\tracing:file.exe`. Die string-kontroles sien `C:\Windows\` en mis die uitgeslote subpad.
  - **Writable file/directory inside an allowed root**: `CreateProcessAsUser` vereis **nie 'n `.exe` uitbreiding nie**. Oorskrywing van enige skryfbare lêer onder 'n toegelate wortel met 'n uitvoerbare payload werk, of die kopie van 'n signed `uiAccess="true"` EXE in enige skryfbare subgids (bv., update-restante soos `Tasks_Migrated` as teenwoordig) laat dit die secure-path check slaag.
  - **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Nie-admins kon signed MSIX-pakkette installeer wat in `WindowsApps` beland het, wat nie uitgesluit was nie. Verpak 'n UIAccess-binary binne die MSIX en lanseer dit dan via `RAiLaunchAdminProcess` het 'n **promptless High-IL UIAccess process** gegee. Microsoft het dit opgelos deur hierdie pad uit te sluit; die `uiAccess`-beperkte MSIX-vaardigheid self vereis reeds admin-installasie.

## Aanval-werkstroom (High IL sonder 'n prompt)
1. Verkry/bou 'n **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Plaas dit waar AppInfo se allowlist dit aanvaar (of misbruik 'n pad-validasie randgeval/skryfbare artefak soos hierbo).
3. Roep `RAiLaunchAdminProcess` om dit **stilweg** te spawn met UIAccess + verhoogde IL.
4. Vanuit daardie High-IL-voetspoor, teiken 'n ander High-IL-proses op die lessenaar deur gebruik te maak van **window hooks/DLL injection** of ander same-IL-primitiewe om die admin-konteks volledig te kompromitteer.

## Opsomming van kandidaat-skryfbare paaie
Voer die PowerShell-hulpmiddel uit om skryfbare/oorskryfbare objekke binne nominale veilige wortels van die perspektief van 'n gekose token te ontdek:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Voer as Administrator uit vir groter sigbaarheid; stel `-ProcessId` op 'n lae-priv-proses om daardie token se toegang te weerspieël.
- Filtreer handmatig om bekende verbode subgidse uit te sluit voordat jy kandidate met `RAiLaunchAdminProcess` gebruik.

## Verwysings
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
