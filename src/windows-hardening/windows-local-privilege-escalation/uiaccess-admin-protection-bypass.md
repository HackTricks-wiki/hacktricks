# Admin Protection Omseilings via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Oorsig
- Windows AppInfo openbaar `RAiLaunchAdminProcess` om UIAccess prosesse te spawn (bedoel vir accessibility). UIAccess omseil die meeste User Interface Privilege Isolation (UIPI) boodskapfiltrering sodat accessibility-sagteware hoër-IL UI kan bestuur.
- Om UIAccess direk aan te skakel vereis `NtSetInformationToken(TokenUIAccess)` met **SeTcbPrivilege**, dus lae-priv caller(s) staatmaak op die diens. Die diens voer drie kontroles op die geteikende binêre uit voordat UIAccess gestel word:
- Ingebedde manifest bevat `uiAccess="true"`.
- Onderteken deur enige sertifikaat wat deur die Local Machine root store vertrou word (geen EKU/Microsoft vereiste nie).
- Geleë in ’n administrator-only pad op die stelselstasie (bv., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, uitgesluit spesifieke beskryfbare subpade).
- `RAiLaunchAdminProcess` voer geen consent prompt uit vir UIAccess launches nie (anders sou accessibility-instrumente nie die prompt kon bestuur nie).

## Token-vorming en integriteitsvlakke
- Indien die kontroles slaag, kopieer AppInfo die caller-token, skakel UIAccess aan, en verhoog die Integrity Level (IL):
- Limited admin user (gebruiker is in Administrators maar hardloop gefilter) ➜ **High IL**.
- Non-admin user ➜ IL verhoog met **+16 vlakke** tot ’n **High** plafon (System IL word nooit toegewys nie).
- As die caller-token reeds UIAccess het, bly IL onveranderd.
- “Ratchet” truuk: ’n UIAccess proses kan UIAccess op sigself deaktiveer, weer via `RAiLaunchAdminProcess` herlaai, en nog ’n +16 IL increment verkry. Medium➜High neem 255 herlaaislae (luidrugtig, maar werk).

## Waarom UIAccess ’n Admin Protection-ontsnapping moontlik maak
- UIAccess laat ’n laer-IL proses toe om vensterboodskappe na hoër-IL vensters te stuur (omseil UIPI-filtre). By gelyke IL laat klassieke UI-primitiewe soos `SetWindowsHookEx` toe dat kode-inspuiting/DLL-laai in enige proses wat ’n venster besit plaasvind (insluitend **message-only windows** wat deur COM gebruik word).
- Admin Protection loods die UIAccess-proses onder die beperkte gebruiker se identiteit maar by **High IL**, stilweg. Wanneer arbitrêre kode binne daardie High-IL UIAccess-proses loop, kan die aanvaller in ander High-IL prosesse op die desktop inspuit (selfs dié wat aan ander gebruikers behoort), en sodoende die bedoelde skeiding verbreek.

## Kwesbaarhede in secure-directory validatie (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo los die aangeleverde pad op via `GetFinalPathNameByHandle` en pas dan **string allow/deny kontroles** toe teen hardgekodeerde wortels/uitsluitings. Meerdere omseilingklasse spruit uit daardie simplistiese validering:
- Directory named streams: Uitgeslote beskryfbare gidse (bv., `C:\Windows\tracing`) kan omseil word met ’n named stream op die gids self, bv. `C:\Windows\tracing:file.exe`. Die stringkontroles sien `C:\Windows\` en mis die uitgeslote subpad.
- Beskryfbare lêer/gids binne ’n toegelate wortel: `CreateProcessAsUser` vereis **nie ’n `.exe` uitbreiding** nie. Oorskryf van enige beskryfbare lêer onder ’n toegelate wortel met ’n uitvoerbare payload werk, of kopieer ’n ondertekende `uiAccess="true"` EXE in enige beskryfbare subgids (bv., update leftovers soos `Tasks_Migrated` wanneer teenwoordig) laat dit die secure-path kontrole slaag.
- MSIX in `C:\Program Files\WindowsApps` (gemaak reg): Non-admins kon onderteken MSIX pakkette installeer wat in `WindowsApps` beland het, wat nie uitgesluit was nie. Paketiseer ’n UIAccess binêre binne die MSIX en loods dit via `RAiLaunchAdminProcess` het ’n **promptless High-IL UIAccess-proses** gegee. Microsoft het dit versag deur hierdie pad uit te sluit; die `uiAccess` beperkte MSIX-vaardigheid self vereis reeds admin-installasie.

## Attack workflow (High IL sonder ’n prompt)
1. Verkry/bou ’n **ondertekende UIAccess binêre** (manifest `uiAccess="true"`).
2. Plaas dit waar AppInfo se allowlist dit aanvaar (of misbruik ’n path-validation edge case/beskryfbare artefak soos hierbo).
3. Roep `RAiLaunchAdminProcess` op om dit **stilweg** met UIAccess + verhoogde IL te spawn.
4. Vanaf daardie High-IL voetjie, mik na ’n ander High-IL proses op die desktop deur gebruik te maak van **window hooks/DLL injection** of ander same-IL primitiewe om die admin-konteks volledig te kompromiteer.

## Enumerasie van kandidaat-beskryfbare pade
Loop die PowerShell helper uit om beskryfbare/oorskryfbare objekte binne nominale secure roots vanaf die perspektief van ’n gekose token te ontdek:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Voer as Administrator uit vir wyer sigbaarheid; stel `-ProcessId` op 'n low-priv process om daardie token se toegang te weerspieël.
- Filtreer handmatig om bekende nie-toegelate subgidse uit te sluit voordat jy kandidate met `RAiLaunchAdminProcess` gebruik.

## Verwysings
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
