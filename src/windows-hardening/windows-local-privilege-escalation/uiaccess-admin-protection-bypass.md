# Admin Protection-omseilings via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Oorsig
- Windows AppInfo stel die interne `RAiLaunchAdminProcess`-pad bloot wat gebruik word om UIAccess-toepassings vir accessibility te begin. UIAccess laat geselekteerde interaksie oor User Interface Privilege Isolation (UIPI)-grense toe; dit is nie ’n algemene omseiling van elke proses-sekuriteitsgrens nie.<sup>[[1]](#references)[[3]](#references)</sup>
- Om UIAccess direk te aktiveer, vereis `NtSetInformationToken(TokenUIAccess)` met **SeTcbPrivilege**, dus maak low-priv callers op die diens staat. Die diens voer drie kontroles op die teiken-binary uit voordat dit UIAccess stel:
- Ingebedde manifest bevat `uiAccess="true"`.
- Geteken deur enige sertifikaat wat deur die Local Machine root store vertrou word (geen EKU/Microsoft-vereiste nie).
- Geleë in ’n administrator-only path op die stelselaandrywer (byvoorbeeld `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, met spesifieke writable subpaths uitgesluit).
- `RAiLaunchAdminProcess` vertoon geen consent prompt vir UIAccess launches nie (anders sou accessibility tooling nie die prompt kon beheer nie).<sup>[[1]](#references)</sup>

## Token shaping en integrity levels
- As die kontroles slaag, **kopieer** AppInfo die caller token, aktiveer UIAccess en verhoog Integrity Level (IL):
- Limited admin user (user is in Administrators but running filtered) ➜ **High IL**.
- Non-admin user ➜ IL increased by **+16 levels** up to a **High** cap (System IL is never assigned).
- As die caller token reeds UIAccess het, bly IL onveranderd.
- “Ratchet”-truuk: ’n UIAccess-proses kan UIAccess op homself deaktiveer, via `RAiLaunchAdminProcess` herbegin en nog ’n +16 IL-increment kry. Medium➜High neem 255 relaunches (lawaaierig, maar dit werk).<sup>[[1]](#references)</sup>

## Waarom UIAccess ’n Admin Protection-ontsnapping moontlik maak
- UIAccess laat ’n lower-IL-proses window messages na higher-IL-windows stuur (deur UIPI-filters te omseil). By **gelyke IL** laat klassieke UI-primitives soos `SetWindowsHookEx` **wel code injection/DLL loading** toe in enige proses wat ’n window besit (insluitend **message-only windows** wat deur COM gebruik word).
- Admin Protection begin die UIAccess-proses onder die **limited user** se identity, maar by **High IL**, stilweg. Sodra arbitrary code binne daardie High-IL UIAccess-proses loop, kan die attacker in ander High-IL-prosesse op die desktop inject (selfs wanneer hulle aan verskillende users behoort), wat die beoogde separation verbreek.<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Op Windows 10 1803+ het die API na Win32k (`NtUserGetWindowProcessHandle`) verskuif en kan dit ’n process handle open deur ’n caller-supplied `DesiredAccess` te gebruik. Die kernel path gebruik `ObOpenObjectByPointer(..., KernelMode, ...)`, wat normale user-mode access checks omseil.<sup>[[2]](#references)</sup>
- Preconditions in die praktyk: die target window moet op dieselfde desktop wees, en UIPI checks moet slaag. Histories kon ’n caller met UIAccess UIPI failure omseil en steeds ’n kernel-mode handle kry (reggestel as CVE-2023-41772).
- Historiese impak: ’n window handle het ’n **capability** geword vir process access soos `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` of `PROCESS_VM_OPERATION` wat die caller normaalweg nie kon verkry nie. Voor die gedokumenteerde fixes kon dit sandbox- en protected-process-grense oorsteek wanneer ’n target ’n window blootgestel het, insluitend ’n message-only window.<sup>[[2]](#references)</sup>
- Practical abuse flow: enumerateer of vind HWNDs (byvoorbeeld `EnumWindows`/`FindWindowEx`), bepaal die owning PID (`GetWindowThreadProcessId`), roep `GetProcessHandleFromHwnd` aan en gebruik dan die returned handle vir memory read/write- of code-hijack-primitives.
- Post-fix behavior: UIAccess verleen nie meer kernel-mode opens op UIPI failure nie, en toegelate access rights is beperk tot die legacy hook set; Windows 11 24H2 voeg process-protection checks en feature-flagged safer paths by. Deur UIPI system-wide te disable (`EnforceUIPI=0`), word hierdie protections verswak.<sup>[[2]](#references)</sup>

## Swakhede in secure-directory validation (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resolve die supplied path via `GetFinalPathNameByHandle` en pas dan **string allow/deny checks** teen hardcoded roots/exclusions toe. Veelvuldige bypass-klasse spruit uit daardie simplistiese validation:
- **Directory named streams**: Excluded writable directories (byvoorbeeld `C:\Windows\tracing`) kan met ’n named stream op die directory self omseil word, byvoorbeeld `C:\Windows\tracing:file.exe`. Die string checks sien `C:\Windows\` en mis die excluded subpath.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` **vereis nie ’n `.exe`-extension nie**. Enige writable file onder ’n allowed root kan met ’n executable payload oorgeskryf word, of ’n signed `uiAccess="true"` EXE kan na enige writable subdirectory gekopieer word (byvoorbeeld update leftovers soos `Tasks_Migrated` wanneer dit teenwoordig is), sodat dit die secure-path check slaag.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins kon signed MSIX packages installeer wat in `WindowsApps` beland het, wat nie uitgesluit was nie. Deur ’n UIAccess-binary binne die MSIX te package en dit dan via `RAiLaunchAdminProcess` te launch, is ’n **promptless High-IL UIAccess-proses** verkry. Microsoft het dit versag deur hierdie path uit te sluit; die `uiAccess` restricted MSIX capability vereis reeds ’n admin install.<sup>[[1]](#references)</sup>

## Aanvalswerkvloei (High IL sonder ’n prompt)
1. Verkry/bou ’n **signed UIAccess binary** (manifest `uiAccess="true"`). Vir ’n realistiese assessment, toets met trust material en paths wat uitdruklik vir die lab gemagtig is; moenie ’n attacker certificate by ’n production machine se Local Machine root store voeg nie.
2. Plaas dit waar AppInfo se allowlist dit aanvaar (of abuse ’n path-validation edge case/writable artifact soos hierbo).
3. Roep `RAiLaunchAdminProcess` aan om dit **stilweg** met UIAccess + elevated IL te spawn.
4. Vanaf daardie High-IL foothold, target ’n ander High-IL-proses op die desktop deur **window hooks/DLL injection** of ander same-IL-primitives te gebruik om die admin-context volledig te kompromitteer.<sup>[[1]](#references)</sup>

## Enumerating candidate writable paths
Run die PowerShell-helper om writable/overwritable objects binne nominaal secure roots te ontdek vanuit die perspektief van ’n gekose token:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Run as Administrator vir breër sigbaarheid; stel `-ProcessId` op ’n lae-privilege-proses om daardie token se toegang te weerspieël.
- Filter handmatig om bekende ontoelaatbare subgidse uit te sluit voordat kandidate met `RAiLaunchAdminProcess` gebruik word.

## Verwant

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Om Administrator Protection te omseil deur UI Access te misbruik](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GPHFH Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — UIAccess-toepassings](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
