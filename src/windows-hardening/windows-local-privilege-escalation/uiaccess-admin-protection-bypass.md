# Bypasses Admin Protection preko UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Pregled
- Windows AppInfo izlaže `RAiLaunchAdminProcess` za pokretanje UIAccess procesa (namenjeno accessibility funkcijama). UIAccess zaobilazi većinu filtriranja poruka User Interface Privilege Isolation (UIPI), tako da accessibility software može da upravlja UI elementima sa višim IL-om.
- Direktno omogućavanje UIAccess zahteva `NtSetInformationToken(TokenUIAccess)` sa **SeTcbPrivilege**, pa se low-priv caller oslanja na servis. Servis obavlja tri provere ciljnog binary-ja pre postavljanja UIAccess-a:
- Ugrađeni manifest sadrži `uiAccess="true"`.
- Potpisan je bilo kojim certificate-om kome veruje Local Machine root store (nisu potrebni EKU/Microsoft zahtevi).
- Nalazi se u path-u na system drive-u kojem pristup imaju samo administratori (npr. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, uz izuzimanje određenih writable subpath-ova).
- `RAiLaunchAdminProcess` ne prikazuje consent prompt za UIAccess launch-e (u suprotnom accessibility tooling ne bi mogao da upravlja prompt-om).<sup>[[1]](#references)</sup>

## Oblikovanje tokena i integrity level-i
- Ako provere uspeju, AppInfo **kopira caller token**, omogućava UIAccess i povećava Integrity Level (IL):
- Limited admin user (user je u grupi Administrators, ali radi sa filtered token-om) ➜ **High IL**.
- Non-admin user ➜ IL se povećava za **+16 level-a**, do **High** granice (System IL se nikada ne dodeljuje).
- Ako caller token već ima UIAccess, IL ostaje nepromenjen.
- „Ratchet“ trik: UIAccess process može da onemogući UIAccess na sebi, da se ponovo pokrene preko `RAiLaunchAdminProcess` i dobije još jedno povećanje od +16 IL level-a. Medium➜High zahteva 255 relaunch-ova (upadljivo, ali funkcioniše).<sup>[[1]](#references)</sup>

## Zašto UIAccess omogućava escape iz Admin Protection-a
- UIAccess omogućava procesu sa nižim IL-om da šalje window message-ove window-ima sa višim IL-om (zaobilazeći UIPI filtere). Pri **jednakom IL-u**, klasični UI primitives kao što je `SetWindowsHookEx` **dozvoljavaju code injection/DLL loading** u bilo koji process koji poseduje window (uključujući **message-only windows** koje koristi COM).
- Admin Protection pokreće UIAccess process pod identitetom **limited user-a**, ali sa **High IL-om**, bez prikazivanja prompt-a. Kada se arbitrary code izvrši unutar tog High-IL UIAccess process-a, attacker može da izvrši injection u druge High-IL process-e na desktop-u (čak i ako pripadaju drugim user-ima), čime se narušava predviđena izolacija.<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Na Windows 10 1803+ API je premešten u Win32k (`NtUserGetWindowProcessHandle`) i može da otvori process handle koristeći `DesiredAccess` koji prosleđuje caller. Kernel path koristi `ObOpenObjectByPointer(..., KernelMode, ...)`, čime se zaobilaze uobičajene user-mode access provere.<sup>[[2]](#references)</sup>
- Preduslovi u praksi: ciljni window mora biti na istom desktop-u, a UIPI provere moraju proći. Istorijski, caller sa UIAccess-om mogao je da zaobiđe UIPI failure i ipak dobije kernel-mode handle (ispravljeno kroz CVE-2023-41772).
- Uticaj: window handle postaje **capability** za dobijanje moćnog process handle-a (često `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) koji caller inače ne bi mogao normalno da otvori. Ovo omogućava cross-sandbox access i može da naruši Protected Process / PPL granice ako target izlaže bilo koji window (uključujući message-only windows).
- Praktičan abuse flow: enumerisati ili pronaći HWND-ove (npr. `EnumWindows`/`FindWindowEx`), odrediti PID koji ih poseduje (`GetWindowThreadProcessId`), pozvati `GetProcessHandleFromHwnd`, a zatim koristiti dobijeni handle za memory read/write ili code-hijack primitives.
- Ponašanje nakon ispravke: UIAccess više ne omogućava kernel-mode opens kada UIPI provera ne uspe, a dozvoljena access prava su ograničena na legacy hook set; Windows 11 24H2 dodaje process-protection provere i bezbednije path-ove kontrolisane feature flag-ovima. Globalno onemogućavanje UIPI-ja (`EnforceUIPI=0`) slabi ove zaštite.<sup>[[2]](#references)</sup>

## Slabosti validacije secure-directory-ja (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo razrešava prosleđeni path preko `GetFinalPathNameByHandle`, a zatim primenjuje **string allow/deny provere** nad hardcoded root-ovima/exclusion-ima. Više klasa bypass-a proističe iz te jednostavne validacije:
- **Named streams direktorijuma**: Excluded writable direktorijumi (npr. `C:\Windows\tracing`) mogu se zaobići pomoću named stream-a na samom direktorijumu, npr. `C:\Windows\tracing:file.exe`. String provere vide `C:\Windows\` i propuštaju excluded subpath.
- **Writable file/directory unutar dozvoljenog root-a**: `CreateProcessAsUser` **ne zahteva `.exe` ekstenziju**. Prepisivanje bilo kog writable file-a unutar dozvoljenog root-a executable payload-om funkcioniše, ili kopiranje potpisanog EXE-a sa `uiAccess="true"` u bilo koji writable subdirectory (npr. update leftovers kao što je `Tasks_Migrated`, kada postoji) omogućava mu da prođe secure-path proveru.
- **MSIX u `C:\Program Files\WindowsApps` (ispravljeno)**: Non-admin user-i su mogli da instaliraju potpisane MSIX package-e koji su završavali u `WindowsApps`, što nije bilo excluded. Packaging UIAccess binary-ja unutar MSIX-a, a zatim njegovo pokretanje preko `RAiLaunchAdminProcess`, davalo je **High-IL UIAccess process bez prompt-a**. Microsoft je ublažio problem izuzimanjem ovog path-a; sam `uiAccess` restricted MSIX capability već zahteva admin install.<sup>[[1]](#references)</sup>

## Attack workflow (High IL bez prompt-a)
1. Nabaviti/izgraditi **potpisani UIAccess binary** (manifest `uiAccess="true"`).
2. Postaviti ga tamo gde ga AppInfo allowlist prihvata (ili zloupotrebiti edge case u path-validaciji/writable artifact kao što je opisano iznad).
3. Pozvati `RAiLaunchAdminProcess` da ga pokrene **nečujno**, sa UIAccess-om i elevated IL-om.
4. Sa tog High-IL foothold-a, targetirati drugi High-IL process na desktop-u koristeći **window hooks/DLL injection** ili druge same-IL primitives, kako bi se u potpunosti kompromitovao admin context.<sup>[[1]](#references)</sup>

## Enumerisanje potencijalno writable path-ova
Pokrenite PowerShell helper da biste otkrili writable/overwritable objekte unutar nominalno secure root-ova iz perspektive izabranog token-a:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Pokrenite kao Administrator radi šire vidljivosti; postavite `-ProcessId` na proces sa niskim privilegijama kako biste oponašali pristup tog tokena.
- Ručno filtrirajte rezultate da biste isključili poznate nedozvoljene poddirektorijume pre korišćenja kandidata sa `RAiLaunchAdminProcess`.

## Povezano

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Reference

- [1] [Zaobilaženje Administrator Protection iskorišćavanjem UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Detaljna analiza funkcije GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
