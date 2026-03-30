# Admin-beskerming-omseilings via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Oorsig
- Windows AppInfo openbaar `RAiLaunchAdminProcess` om UIAccess-prosesse te spawn (bedoel vir toeganklikheid). UIAccess omseil die meeste User Interface Privilege Isolation (UIPI) boodskapfiltrering sodat toeganklikheid-sagteware hoër-IL UI kan beheer.
- Om UIAccess direk aan te skakel vereis `NtSetInformationToken(TokenUIAccess)` met **SeTcbPrivilege**, dus lae-priv oproepers vertrou op die diens. Die diens voer drie kontrole op die teiken-binaire uit voordat UIAccess gestel word:
- Ingebedde manifest bevat `uiAccess="true"`.
- Onderteken deur enige sertifikaat wat deur die Local Machine root store vertrou word (geen EKU/Microsoft-vereiste nie).
- Geleë in ’n administrateur-alleen pad op die stelseldrywer (bv. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, uitgesonderde spesifieke skryfbare subpaaie).
- `RAiLaunchAdminProcess` gee geen toestemming-prompt vir UIAccess-lansings nie (anders kon toeganklikheid-instrumente nie die prompt bestuur nie).

## Token-vorming en integriteitsvlakke
- As die kontrole slaag, AppInfo **kopieer die oproeper-token**, skakel UIAccess aan, en verhoog die Integriteitsvlak (IL):
- Beperkte admin-gebruiker (gebruiker is in Administrators maar hardloop gefilter) ➜ **High IL**.
- Nie-admin-gebruiker ➜ IL verhoog met **+16 vlakke** tot ’n **High** plafon (System IL word nooit toegewys nie).
- As die oproeper-token reeds UIAccess het, word IL onveranderd gelaat.
- “Ratchet”-trick: ’n UIAccess-proses kan UIAccess op sigself deaktiveer, weer opstart via `RAiLaunchAdminProcess`, en nog ’n +16 IL-increment kry. Medium➜High neem 255 herstartes (luidrugtig, maar werk).

## Waarom UIAccess 'n Admin Protection-omseiling moontlik maak
- UIAccess laat ’n laer-IL proses toe om vensterboodskappe na hoër-IL vensters te stuur (omseil UIPI-filtering). By **gelyke IL** laat klassieke UI-primitiewe soos `SetWindowsHookEx` **toe dat kode-inspuiting/DLL-lading plaasvind** in enige proses wat ’n venster besit (insluitend **message-only windows** wat deur COM gebruik word).
- Admin Protection lanseer die UIAccess-proses onder die **beperkte gebruiker se identiteit** maar by **High IL**, stilweg. Sodra arbitrêre kode binne daardie High-IL UIAccess-proses loop, kan die aanvaller in ander High-IL prosesse op die desktop inspuit (selfs van ander gebruikers), en sodoende die beoogde skeiding verbreek.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Op Windows 10 1803+ is die API na Win32k verskuif (`NtUserGetWindowProcessHandle`) en kan ’n proses-handle oopgemaak word met ’n oproeper-gespesifiseerde `DesiredAccess`. Die kernel-pad gebruik `ObOpenObjectByPointer(..., KernelMode, ...)`, wat normale user-mode toegangs kontrole omseil.
- Voorwaardes in praktyk: die teiken-venster moet op dieselfde desktop wees, en UIPI-kontroles moet slaag. Histories kon ’n oproeper met UIAccess UIPI-fout omseil en steeds ’n kernel-mode handle kry (vasgestel as CVE-2023-41772).
- Impak: ’n venster-handle word ’n **vermoë** om ’n kragtige proses-handle te verkry (gewoonlik `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) wat die oproeper normaalweg nie kon oopmaak nie. Dit maak kruis-sandbox toegang moontlik en kan Protected Process / PPL-grense breek as die teiken enige venster blootstel (insluitend message-only windows).
- Praktiese misbruikvloeistroom: enumereer of lokaliseer HWNDs (bv. `EnumWindows`/`FindWindowEx`), los die eienaars-PID op (`GetWindowThreadProcessId`), roep `GetProcessHandleFromHwnd` aan, en gebruik dan die teruggegewe handle vir geheue lees/skryf of kode-oormatiging-primitiewe.
- Na-vasstelling gedrag: UIAccess gee nie meer kernel-mode opens op UIPI-fout nie en toegestane toegangregte is beperk tot die klassieke hook-set; Windows 11 24H2 voeg proses-beskermingskontroles en feature-flagged veiliger paaie by. Stelselwyd UIPI deaktiveer (`EnforceUIPI=0`) verswak hierdie beskermings.

## Secure-directory validasie swakpunte (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo los die gegewe pad op via `GetFinalPathNameByHandle` en pas dan **string allow/deny kontroles** toe teen hardgekodeerde wortels/uitsluitings. Meerdere omseilingsklasse spruit uit daardie simplistiese validasie:
- **Directory named streams**: Uitgeslote skryfbare directories (bv. `C:\Windows\tracing`) kan omseil word met ’n named stream op die directory self, bv. `C:\Windows\tracing:file.exe`. Die string-kontroles sien `C:\Windows\` en mis die uitgeslote subpad.
- **Skryfbare lêer/directory binne ’n toegelate wortel**: `CreateProcessAsUser` vereis **nie ’n `.exe` uitbreiding** nie. Oorskryf enige skryfbare lêer onder ’n toegelate wortel met ’n uitvoerbare payload werk, of kopieer ’n ondertekende `uiAccess="true"` EXE in enige skryfbare subgids (bv. opdaterings-restante soos `Tasks_Migrated` as dit teenwoordig is) sodat dit die secure-path kontrole slaag.
- **MSIX in `C:\Program Files\WindowsApps` (vasgestel)**: Nie-admins kon ondertekende MSIX-pakkette installeer wat in `WindowsApps` beland het, wat nie uitgesluit was nie. Om ’n UIAccess-binaire in die MSIX te verpakk en dit dan via `RAiLaunchAdminProcess` te lanseer het ’n **prompt-loos High-IL UIAccess-proses** gegee. Microsoft het dit gekompenseer deur hierdie pad uit te sluit; die `uiAccess` beperkte MSIX-vaardigheid self vereis reeds admin-installasie.

## Aanvalswerkvloei (High IL sonder 'n prompt)
1. Verkry/bou ’n **ondertekende UIAccess-binaire** (manifest `uiAccess="true"`).
2. Plaas dit waar AppInfo se allowlist dit aanvaar (of misbruik ’n pad-validasie randgeval/skryfbare artefak soos hierbo).
3. Roep `RAiLaunchAdminProcess` aan om dit **stilweg** met UIAccess + verhoogde IL te spawn.
4. Vanuit daardie High-IL voet-in-deur, teiken ’n ander High-IL proses op die desktop met **venster hooks/DLL-inspuiting** of ander selfde-IL primitiewe om die admin-konteks volledig te kompromitteer.

## Opsomming van kandidaat-skryfbare paaie
Hardloop die PowerShell-helper om skryfbare/oorskryfbare objekte binne nominaal veilige wortels te ontdek vanuit die perspektief van ’n gekose token:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Voer uit as Administrator vir wyer sigbaarheid; stel `-ProcessId` op 'n low-priv process om daardie token se toegang te weerspieël.
- Filtreer handmatig om bekende ontoegelate subgidse uit te sluit voordat u die kandidaten met `RAiLaunchAdminProcess` gebruik.

## Verwante

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Verwysings
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
