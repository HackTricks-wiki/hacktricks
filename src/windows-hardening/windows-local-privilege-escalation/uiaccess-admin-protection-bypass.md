# Zaobilaženja Admin Protection mehanizma putem UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Pregled
- Windows AppInfo izlaže internu putanju `RAiLaunchAdminProcess`, koja se koristi za pokretanje UIAccess aplikacija namenjenih pristupačnosti. UIAccess dozvoljava odabranu interakciju preko granica User Interface Privilege Isolation (UIPI); nije opšte zaobilaženje svake bezbednosne granice procesa.<sup>[[1]](#references)[[3]](#references)</sup>
- Direktno omogućavanje UIAccess zahteva `NtSetInformationToken(TokenUIAccess)` sa **SeTcbPrivilege**, pa se pozivaoci sa niskim privilegijama oslanjaju na servis. Servis obavlja tri provere ciljne binarne datoteke pre postavljanja UIAccess:
- Ugrađeni manifest sadrži `uiAccess="true"`.
- Potpisan je bilo kojim sertifikatom kome veruje root store Local Machine (bez zahteva za EKU/Microsoft).
- Nalazi se u putanji na sistemskom disku kojoj mogu pristupati samo administratori (npr. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), uz izuzetak određenih podputanja sa dozvolom upisa.
- `RAiLaunchAdminProcess` ne prikazuje consent prompt za UIAccess pokretanja (u suprotnom alati za pristupačnost ne bi mogli da upravljaju promptom).<sup>[[1]](#references)</sup>

## Oblikovanje tokena i nivoi integriteta
- Ako provere uspeju, AppInfo **kopira token pozivaoca**, omogućava UIAccess i povećava Integrity Level (IL):
- Ograničeni admin korisnik (korisnik je u grupi Administrators, ali radi sa filtriranim tokenom) ➜ **High IL**.
- Korisnik koji nije administrator ➜ IL se povećava za **+16 nivoa**, do granice **High** (System IL se nikada ne dodeljuje).
- Ako token pozivaoca već ima UIAccess, IL ostaje nepromenjen.
- Trik sa „ratchet“-om: UIAccess proces može da onemogući UIAccess na sebi, da se ponovo pokrene putem `RAiLaunchAdminProcess` i dobije još jedno povećanje IL-a za +16. Za prelazak Medium➜High potrebno je 255 ponovnih pokretanja (bučno, ali funkcioniše).<sup>[[1]](#references)</sup>

## Zašto UIAccess omogućava zaobilaženje Admin Protection mehanizma
- UIAccess omogućava procesu sa nižim IL-om da šalje poruke prozorima sa višim IL-om (zaobilazeći UIPI filtere). Pri **istom IL-u**, klasični UI mehanizmi kao što je `SetWindowsHookEx` **dozvoljavaju ubacivanje koda/učitavanje DLL-a** u svaki proces koji poseduje prozor (uključujući **message-only windows** koje koristi COM).
- Admin Protection pokreće UIAccess proces pod identitetom **ograničenog korisnika**, ali sa **High IL**, bez obaveštenja. Kada se proizvoljni kod izvrši unutar tog High-IL UIAccess procesa, napadač može da izvrši ubacivanje u druge High-IL procese na desktopu (čak i kada pripadaju drugim korisnicima), čime se narušava predviđeno razdvajanje.<sup>[[1]](#references)</sup>

## Primitiv za dobijanje handle-a procesa na osnovu HWND-a (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Na Windows 10 1803+ API je premešten u Win32k (`NtUserGetWindowProcessHandle`) i može da otvori handle procesa koristeći `DesiredAccess` koji prosleđuje pozivalac. Kernel putanja koristi `ObOpenObjectByPointer(..., KernelMode, ...)`, čime se zaobilaze uobičajene provere pristupa u user-mode-u.<sup>[[2]](#references)</sup>
- Praktični preduslovi: ciljni prozor mora biti na istom desktopu, a UIPI provere moraju proći. Istorijski, pozivalac sa UIAccess-om mogao je da zaobiđe UIPI grešku i ipak dobije handle u kernel-mode-u (ispravljeno kroz CVE-2023-41772).
- Istorijski uticaj: handle prozora postao je **sposobnost** za pristup procesu, kao što su `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` ili `PROCESS_VM_OPERATION`, koji pozivalac inače ne bi mogao da dobije. Pre dokumentovanih ispravki, ovo je moglo da pređe granice sandbox-a i zaštićenih procesa kada je cilj izlagao prozor, uključujući message-only window.<sup>[[2]](#references)</sup>
- Praktičan tok zloupotrebe: nabrojati ili pronaći HWND-ove (npr. `EnumWindows`/`FindWindowEx`), utvrditi PID vlasnika (`GetWindowThreadProcessId`), pozvati `GetProcessHandleFromHwnd`, a zatim koristiti vraćeni handle za čitanje/upis u memoriju ili primitive za preuzimanje kontrole nad kodom.
- Ponašanje nakon ispravke: UIAccess više ne omogućava otvaranje u kernel-mode-u kada UIPI provera ne uspe, a dozvoljena prava pristupa ograničena su na legacy hook skup; Windows 11 24H2 dodaje provere zaštite procesa i bezbednije putanje kontrolisane feature flag-ovima. Globalno onemogućavanje UIPI-ja (`EnforceUIPI=0`) slabi ove zaštite.<sup>[[2]](#references)</sup>

## Slabosti validacije bezbednih direktorijuma (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo razrešava prosleđenu putanju pomoću `GetFinalPathNameByHandle`, a zatim primenjuje **provere stringova za dozvolu/zabranu** u odnosu na hardkodirane root putanje/isključenja. Više klasa bypass-a potiče od te pojednostavljene validacije:
- **Imenovani stream-ovi direktorijuma**: Isključeni direktorijumi sa dozvolom upisa (npr. `C:\Windows\tracing`) mogu se zaobići imenovanim stream-om na samom direktorijumu, npr. `C:\Windows\tracing:file.exe`. Provere stringova vide `C:\Windows\` i propuštaju isključenu podputanju.
- **Datoteka/direktorijum sa dozvolom upisa unutar dozvoljenog root-a**: `CreateProcessAsUser` **ne zahteva ekstenziju `.exe`**. Prepisivanje bilo koje datoteke sa dozvolom upisa unutar dozvoljenog root-a izvršnim payload-om funkcioniše, ili kopiranje potpisanog EXE-a sa `uiAccess="true"` u bilo koji poddirektorijum sa dozvolom upisa (npr. preostale datoteke nakon ažuriranja, kao što je `Tasks_Migrated`, kada postoje) omogućava prolazak provere bezbedne putanje.
- **MSIX u `C:\Program Files\WindowsApps` (ispravljeno)**: Korisnici koji nisu administratori mogli su da instaliraju potpisane MSIX pakete koji su završavali u `WindowsApps`, a ta putanja nije bila isključena. Pakovanje UIAccess binarne datoteke unutar MSIX-a, a zatim njeno pokretanje putem `RAiLaunchAdminProcess`, davalo je **UIAccess proces sa High-IL-om bez prompta**. Microsoft je ublažio problem isključivanjem ove putanje; sama MSIX capability `uiAccess` već zahteva administratorsku instalaciju.<sup>[[1]](#references)</sup>

## Tok napada (High IL bez prompta)
1. Nabavite/izgradite **potpisanu UIAccess binarnu datoteku** (manifest `uiAccess="true"`). Za realističnu procenu testirajte sa materijalom za proveru poverenja i putanjama koje su izričito odobrene za lab; nemojte dodavati napadački sertifikat u root store Local Machine produkcione mašine.
2. Postavite je na mesto koje AppInfo-ova allowlist prihvata (ili zloupotrebite rubni slučaj validacije putanje/datoteku sa dozvolom upisa, kao što je opisano iznad).
3. Pozovite `RAiLaunchAdminProcess` da je **nečujno** pokrene sa UIAccess-om i povišenim IL-om.
4. Sa tog High-IL uporišta ciljajte drugi High-IL proces na desktopu pomoću **window hook-ova/DLL injection-a** ili drugih primitiva pri istom IL-u, kako biste u potpunosti kompromitovali admin kontekst.<sup>[[1]](#references)</sup>

## Nabrajanje potencijalnih putanja sa dozvolom upisa
Pokrenite PowerShell helper da biste otkrili objekte sa dozvolom upisa/prepisivanja unutar nominalno bezbednih root-ova iz perspektive izabranog tokena:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Pokrenite kao Administrator za širu vidljivost; postavite `-ProcessId` na proces sa niskim privilegijama kako biste oponašali pristup tog tokena.
- Ručno filtrirajte kako biste isključili poznate nedozvoljene poddirektorijume pre korišćenja kandidata sa `RAiLaunchAdminProcess`.

## Povezano

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Zaobilaženje Administrator Protection zloupotrebom UI Access-a](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Detaljna analiza GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — UIAccess aplikacije](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
