# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Oorsig
- Windows AppInfo stel `RAiLaunchAdminProcess` bloot om UIAccess-prosesse te spawn (bedoel vir accessibility). UIAccess omseil die meeste User Interface Privilege Isolation (UIPI)-boodskapfiltrering, sodat accessibility-sagteware UI met ’n hoër IL kan beheer.
- Om UIAccess direk te aktiveer, vereis `NtSetInformationToken(TokenUIAccess)` met **SeTcbPrivilege**, dus maak low-priv callers staat op die diens. Die diens voer drie kontroles op die teikenbinary uit voordat dit UIAccess stel:
- Ingebedde manifest bevat `uiAccess="true"`.
- Geteken deur enige sertifikaat wat deur die Local Machine-root store vertrou word (geen EKU/Microsoft-vereiste nie).
- Geleë in ’n administrator-only-pad op die stelselskyf (byvoorbeeld `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), met spesifieke skryfbare subpaaie uitgesluit.
- `RAiLaunchAdminProcess` vertoon geen consent prompt vir UIAccess-launches nie (anders sou accessibility tooling nie die prompt kon beheer nie).<sup>[[1]](#references)</sup>

## Token shaping en integrity levels
- Indien die kontroles slaag, **kopieer** AppInfo die caller token, aktiveer UIAccess en verhoog Integrity Level (IL):
- Limited admin user (user is in Administrators but running filtered) ➜ **High IL**.
- Non-admin user ➜ IL verhoog met **+16 levels** tot ’n **High**-limiet (System IL word nooit toegeken nie).
- Indien die caller token reeds UIAccess het, bly IL onveranderd.
- “Ratchet”-truuk: ’n UIAccess-proses kan UIAccess op homself deaktiveer, via `RAiLaunchAdminProcess` herbegin word en nog ’n +16 IL-increment kry. Medium➜High neem 255 relaunches (geraasvol, maar dit werk).<sup>[[1]](#references)</sup>

## Waarom UIAccess ’n Admin Protection-ontwyking moontlik maak
- UIAccess laat ’n proses met ’n laer IL toe om window messages na windows met ’n hoër IL te stuur (deur UIPI-filters te omseil). By **dieselfde IL** laat klassieke UI-primitives soos `SetWindowsHookEx` **wel code injection/DLL loading** toe in enige proses wat ’n window besit (insluitend **message-only windows** wat deur COM gebruik word).
- Admin Protection launch die UIAccess-proses onder die **limited user** se identiteit, maar met **High IL**, stilweg. Sodra arbitrêre code binne daardie High-IL UIAccess-proses loop, kan die aanvaller in ander High-IL-prosesse op die desktop inject (selfs wanneer dit aan ander users behoort), wat die beoogde skeiding verbreek.<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Op Windows 10 1803+ is die API na Win32k geskuif (`NtUserGetWindowProcessHandle`) en kan dit ’n process handle open met ’n caller-supplied `DesiredAccess`. Die kernel path gebruik `ObOpenObjectByPointer(..., KernelMode, ...)`, wat normale user-mode access checks omseil.<sup>[[2]](#references)</sup>
- Voorvereistes in die praktyk: die target window moet op dieselfde desktop wees, en UIPI-checks moet slaag. Histories kon ’n caller met UIAccess UIPI-failure omseil en steeds ’n kernel-mode handle kry (reggestel as CVE-2023-41772).
- Impak: ’n window handle word ’n **capability** om ’n kragtige process handle te verkry (algemeen `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) wat die caller normaalweg nie kon open nie. Dit maak cross-sandbox access moontlik en kan Protected Process / PPL-grense verbreek indien die target enige window blootstel (insluitend message-only windows).
- Praktiese abuse flow: enumerate of locate HWNDs (byvoorbeeld `EnumWindows`/`FindWindowEx`), resolve die owning PID (`GetWindowThreadProcessId`), call `GetProcessHandleFromHwnd`, en gebruik dan die returned handle vir memory read/write of code-hijack primitives.
- Post-fix behavior: UIAccess verleen nie meer kernel-mode opens wanneer UIPI-failure voorkom nie, en toegelate access rights is beperk tot die legacy hook set; Windows 11 24H2 voeg process-protection checks en feature-flagged safer paths by. Deur UIPI stelselwyd te deaktiveer (`EnforceUIPI=0`) word hierdie protections verswak.<sup>[[2]](#references)</sup>

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resolve die supplied path via `GetFinalPathNameByHandle` en pas dan **string allow/deny checks** toe teen hardcoded roots/exclusions. Verskeie bypass-klasse spruit uit dié simplistiese validasie:
- **Directory named streams**: Excluded writable directories (byvoorbeeld `C:\Windows\tracing`) kan met ’n named stream op die directory self omseil word, byvoorbeeld `C:\Windows\tracing:file.exe`. Die string checks sien `C:\Windows\` en mis die excluded subpath.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` **vereis nie ’n `.exe`-extension nie**. Deur enige writable file onder ’n allowed root met ’n executable payload te overwrite, werk dit; of deur ’n signed `uiAccess="true"` EXE na enige writable subdirectory te copy (byvoorbeeld update leftovers soos `Tasks_Migrated` wanneer dit teenwoordig is), slaag dit die secure-path check.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins kon signed MSIX packages installeer wat in `WindowsApps` beland het, wat nie uitgesluit was nie. Deur ’n UIAccess-binary binne die MSIX te package en dit dan via `RAiLaunchAdminProcess` te launch, is ’n **promptless High-IL UIAccess-proses** verkry. Microsoft het dit versag deur hierdie path uit te sluit; die `uiAccess` restricted MSIX capability vereis self reeds ’n admin install.<sup>[[1]](#references)</sup>

## Attack workflow (High IL without a prompt)
1. Obtain/build ’n **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Place dit waar AppInfo se allowlist dit aanvaar (of abuse ’n path-validation edge case/writable artifact soos hierbo).
3. Call `RAiLaunchAdminProcess` om dit **silently** met UIAccess + elevated IL te spawn.
4. Vanuit dié High-IL foothold, target ’n ander High-IL-proses op die desktop met **window hooks/DLL injection** of ander same-IL-primitives om die admin context volledig te compromise.<sup>[[1]](#references)</sup>

## Enumerating candidate writable paths
Run die PowerShell-helper om writable/overwritable objects binne nominaal secure roots vanuit die perspektief van ’n gekose token te discover:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Run as Administrator vir breër sigbaarheid; stel `-ProcessId` op ’n lae-privilegie-proses om daardie token se toegang na te boots.
- Filter handmatig om bekende ontoelaatbare subgidse uit te sluit voordat kandidate met `RAiLaunchAdminProcess` gebruik word.

## Verwant

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Verwysings

- [1] [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
