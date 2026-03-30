# Zaobilaženje Admin Protection-a pomoću UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Pregled
- Windows AppInfo izlaže `RAiLaunchAdminProcess` za pokretanje UIAccess procesa (namenjeno accessibility alatima). UIAccess zaobilazi većinu User Interface Privilege Isolation (UIPI) filtriranja poruka tako da accessibility softver može upravljati UI koji je višeg IL.
- Direktno omogućavanje UIAccess zahteva `NtSetInformationToken(TokenUIAccess)` sa **SeTcbPrivilege**, pa pozivaoci sa malim privilegijama oslanjaju se na servis. Servis primenjuje tri provere na ciljnom binarnom fajlu pre nego što postavi UIAccess:
  - Ugrađeni manifest sadrži `uiAccess="true"`.
  - Potpisan je bilo kojim sertifikatom kome veruje Local Machine root store (bez zahteva za EKU/Microsoft).
  - Smešten je u putanju dostupnu samo administratorima na sistemskom disku (npr. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, isključujući određene upisive podputanje).
- `RAiLaunchAdminProcess` ne prikazuje consent prompt za UIAccess pokretanja (inače accessibility alati ne bi mogli upravljati promptom).

## Token shaping i integrity levels
- Ako provere uspeju, AppInfo **kopira token pozivaoca**, omogućava UIAccess i podiže Integrity Level (IL):
  - Limited admin user (korisnik je u Administrators ali radi filtrirano) ➜ **High IL**.
  - Non-admin user ➜ IL se povećava za **+16 nivoa** do ograničenja **High** (System IL se nikad ne dodeljuje).
- Ako token pozivaoca već ima UIAccess, IL ostaje nepromenjen.
- “Ratchet” trik: UIAccess proces može onemogućiti UIAccess na sebi, ponovo se pokrenuti preko `RAiLaunchAdminProcess` i dobiti još jedan +16 IL inkrement. Medium➜High zahteva 255 ponovnih pokretanja (zvuči bučno, ali radi).

## Zašto UIAccess omogućava bekstvo iz Admin Protection-a
- UIAccess dozvoljava procesu sa nižim IL da šalje window poruke prozorima sa višim IL (zaobilazeći UIPI filtere). Na **jednakom IL**, klasične UI primitive poput `SetWindowsHookEx` **dozvoljavaju injektovanje koda/učitavanje DLL-a** u bilo koji proces koji poseduje prozor (uključujući **message-only prozore** koje koristi COM).
- Admin Protection pokreće UIAccess proces pod identitetom ograničenog korisnika ali na **High IL**, tiho. Kada proizvoljni kod krene da radi unutar tog High-IL UIAccess procesa, napadač može injektovati u druge High-IL procese na desktopu (čak i koji pripadaju različitim korisnicima), čime se krši zamišljena separacija.

## HWND-to-process handle primitiva (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Na Windows 10 1803+ API je premešten u Win32k (`NtUserGetWindowProcessHandle`) i može otvoriti process handle koristeći `DesiredAccess` koji dodeli pozivalac. Kernel putanja koristi `ObOpenObjectByPointer(..., KernelMode, ...)`, što zaobilazi normalne user-mode provere pristupa.
- Preduslovi u praksi: ciljni prozor mora biti na istom desktopu i UIPI provere moraju proći. Istorijski, pozivaoc sa UIAccess je mogao zaobići UIPI neuspeh i ipak dobiti kernel-mode handle (ispravljeno kao CVE-2023-41772).
- Uticaj: window handle postaje **kapabilitet** za dobijanje moćnog process handle-a (obično `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) koji pozivalac normalno ne bi mogao otvoriti. Ovo omogućava pristup između sandboxa i može prekinuti Protected Process / PPL granice ako cilj izlaže bilo koji prozor (uključujući message-only prozore).
- Praktičan zloupotrebni tok: izbrojati ili pronaći HWND-ove (npr. `EnumWindows`/`FindWindowEx`), rešiti vlasnički PID (`GetWindowThreadProcessId`), pozvati `GetProcessHandleFromHwnd`, zatim koristiti vraćeni handle za čitanje/pisanje memorije ili primitive za preuzimanje kontrole nad kodom.
- Post-fix ponašanje: UIAccess više ne daje kernel-mode otvaranja pri UIPI neuspehu i dozvoljena prava pristupa su ograničena na legacy hook set; Windows 11 24H2 dodaje provere zaštite procesa i feature-flagged sigurnije putanje. Onemogućavanje UIPI sistem-wide (`EnforceUIPI=0`) slabi ove zaštite.

## Slabosti validacije sigurnih direktorijuma (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo rešava prosleđenu putanju preko `GetFinalPathNameByHandle` i zatim primenjuje **string allow/deny provere** naspram hardkodiranih root-ova/isključenja. Više klasa zaobilaženja proističe iz te simplističke validacije:
- **Directory named streams**: Isključene upisive direktorijume (npr. `C:\Windows\tracing`) može se zaobići imenovanim streamom na samom direktorijumu, npr. `C:\Windows\tracing:file.exe`. String provere vide `C:\Windows\` i preskoče isključeni podput.
- **Upisivi fajl/direktorijum unutar dozvoljenog roota**: `CreateProcessAsUser` **ne zahteva `.exe` ekstenziju**. Overrajtovanje bilo kog upisivog fajla pod dozvoljenim root-om sa izvršnim payload-om radi, ili kopiranje potpisanog `uiAccess="true"` EXE u bilo koji upisivi poddirektorijum (npr. ostaci update-a kao `Tasks_Migrated` kada postoje) dopušta prolaz kroz secure-path proveru.
- **MSIX u `C:\Program Files\WindowsApps` (ispravljeno)**: Non-admini su mogli instalirati potpisane MSIX pakete koji su završavali u `WindowsApps`, koji nije bio izuzet. Pakovanje UIAccess binarnog u MSIX i njegovo pokretanje preko `RAiLaunchAdminProcess` davalo je **bezpromptni High-IL UIAccess proces**. Microsoft je ublažio problem isključivanjem te putanje; `uiAccess` ograničena MSIX capability ionako zahteva admin instalaciju.

## Tok napada (High IL bez prompta)
1. Nabaviti/izgraditi **potpisani UIAccess binarni** (manifest `uiAccess="true"`).
2. Postaviti ga tamo gde AppInfo-jev allowlist prihvata (ili iskoristiti edge case validacije putanje/upisivi artefakt kako je gore opisano).
3. Pozvati `RAiLaunchAdminProcess` da ga pokrene **tiho** sa UIAccess + povišenim IL.
4. Iz te High-IL pozicije, ciljati drugi High-IL proces na desktopu koristeći **window hooks/DLL injection** ili druge primitive istog IL da potpuno kompromituje admin kontekst.

## Enumeracija kandidata za upisive putanje
Pokrenite PowerShell helper da otkrijete upisive/overwritable objekte unutar nominalno sigurnih root-ova iz perspektive izabranog tokena:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Pokrenite kao Administrator za veću preglednost; podesite `-ProcessId` na low-priv process da biste zrcalili pristup tog tokena.
- Ručno filtrirajte da biste isključili poznate nedozvoljene poddirektorijume pre korišćenja kandidata sa `RAiLaunchAdminProcess`.

## Povezano

Propagacija registra pristupačnosti Secure Desktop-a LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Reference
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
