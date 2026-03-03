# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Pregled
- Windows AppInfo izlaže `RAiLaunchAdminProcess` za pokretanje UIAccess procesa (namenjeno za accessibility). UIAccess zaobilazi većinu User Interface Privilege Isolation (UIPI) filtriranja poruka tako da accessibility softver može upravljati UI-jem višeg IL.
- Direktno omogućavanje UIAccess zahteva `NtSetInformationToken(TokenUIAccess)` sa **SeTcbPrivilege**, pa pozivaoci sa niskim privilegijama oslanjaju se na servis. Servis vrši tri provere ciljnog binarnog fajla pre nego što postavi UIAccess:
- Ugrađeni manifest sadrži `uiAccess="true"`.
- Potpisan od strane bilo kog sertifikata kojem veruje Local Machine root store (bez EKU/Microsoft zahteva).
- Nalazi se u putanji koja je dostupna samo administratoru na sistemskom disku (npr. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, isključujući specifične podputanje koja su upisiva).
- `RAiLaunchAdminProcess` ne prikazuje consent prompt za UIAccess pokretanja (inače accessibility alati ne bi mogli upravljati promptom).

## Token shaping i integrity levels
- Ako provere uspeju, AppInfo **kopira token pozivaoca**, omogućava UIAccess i podiže Integrity Level (IL):
- Limited admin user (korisnik je u Administrators ali radi filtrirano) ➜ **High IL**.
- Non-admin user ➜ IL se povećava za **+16 nivoa** do maksimuma **High** (System IL se nikada ne dodeljuje).
- Ako caller token već ima UIAccess, IL ostaje nepromenjen.
- “Ratchet” trik: UIAccess proces može onemogućiti UIAccess na sebi, ponovo se pokrenuti preko `RAiLaunchAdminProcess`, i dobiti još jedan +16 IL inkrement. Medium➜High zahteva 255 ponovnih pokretanja (bučno, ali funkcioniše).

## Zašto UIAccess omogućava bekstvo iz Admin Protection
- UIAccess dozvoljava procesu nižeg IL da šalje window poruke prozorima višeg IL (zaobilazeći UIPI filtere). Na **jednakom IL**, klasični UI primitivni poput `SetWindowsHookEx` **dozvoljavaju injektovanje koda/učitavanje DLL-a** u bilo koji proces koji poseduje prozor (uključujući **message-only windows** koje koristi COM).
- Admin Protection pokreće UIAccess proces pod identitetom **limited user-a** ali na **High IL**, tiho. Kada proizvoljni kod krene da se izvršava u tom High-IL UIAccess procesu, napadač može injektovati u druge High-IL procese na desktopu (pa čak i koji pripadaju različitim korisnicima), čime lomi predviđenu separaciju.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Na Windows 10 1803+ API je premješten u Win32k (`NtUserGetWindowProcessHandle`) i može otvoriti process handle koristeći caller-supplied `DesiredAccess`. Kernel putanja koristi `ObOpenObjectByPointer(..., KernelMode, ...)`, što zaobilazi normalne user-mode provere pristupa.
- Preduslovi u praksi: ciljni prozor mora biti na istom desktopu, i UIPI provere moraju proći. Istorijski, caller sa UIAccess je mogao zaobići UIPI neuspeh i ipak dobiti kernel-mode handle (ispravljeno kao CVE-2023-41772).
- Uticaj: window handle postaje **sposobnost (capability)** da se dobije moćan process handle (obično `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) koji pozivalac normalno ne bi mogao otvoriti. Ovo omogućava cross-sandbox pristup i može razbiti Protected Process / PPL granice ako cilj izlaže bilo koji prozor (uključujući message-only windows).
- Praktičan tok zloupotrebe: enumerisati ili pronaći HWND-ove (npr. `EnumWindows`/`FindWindowEx`), razrešiti vlasnički PID (`GetWindowThreadProcessId`), pozvati `GetProcessHandleFromHwnd`, zatim koristiti vraćeni handle za čitanje/pisanje memorije ili primitive za otmicu koda.
- Nakon ispravke: UIAccess više ne daje kernel-mode otvaranja pri UIPI neuspehu i dozvoljena prava pristupa su ograničena na legacy hook set; Windows 11 24H2 dodaje provere zaštite procesa i feature-flagged sigurnije putanje. Onemogućavanje UIPI sistema-wide (`EnforceUIPI=0`) slabi ove zaštite.

## Slabosti u validaciji sigurnih direktorijuma (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo rešava prosleđenu putanju preko `GetFinalPathNameByHandle` i potom primenjuje **string allow/deny provere** protiv hardkodiranih rootova/isključenja. Više klasa zaobilaženja proizilazi iz te jednostavne validacije:
- **Directory named streams**: Isključeni upisivi direktorijumi (npr. `C:\Windows\tracing`) mogu se zaobići pomoću named stream-a na samom direktorijumu, npr. `C:\Windows\tracing:file.exe`. String provere vide `C:\Windows\` i propuste isključeni podput.
- **Upisiv fajl/direktorijum unutar dozvoljenog root-a**: `CreateProcessAsUser` **ne zahteva `.exe` ekstenziju**. Overwrite bilo kog upisivog fajla pod dozvoljenim root-om izvršnim payload-om radi, ili kopiranje potpisanog `uiAccess="true"` EXE u bilo koji upisivi poddirektorijum (npr. update leftovers kao `Tasks_Migrated` kada je prisutan) omogućava prolaz secure-path provere.
- **MSIX u `C:\Program Files\WindowsApps` (ispravljeno)**: Non-admini su mogli instalirati potpisane MSIX pakete koji su završavali u `WindowsApps`, što nije bilo isključeno. Pakovanje UIAccess binarnog u MSIX i pokretanje preko `RAiLaunchAdminProcess` je rezultovalo u **promptless High-IL UIAccess procesu**. Microsoft je ublažio problem isključivanjem te putanje; `uiAccess` ograničena MSIX capability već zahteva admin instalaciju.

## Tijek napada (High IL bez prompta)
1. Nabaviti/izgraditi **potpisani UIAccess binary** (manifest `uiAccess="true"`).
2. Postaviti ga tamo gde AppInfo-jev allowlist prihvata (ili iskoristiti edge case validacije putanje/upisivi artefakt kao gore).
3. Pozvati `RAiLaunchAdminProcess` da ga pokrene **tiho** sa UIAccess + povišenim IL.
4. Iz tog High-IL uporišta ciljati drugi High-IL proces na desktopu koristeći **window hooks/DLL injection** ili druge same-IL primitive da u potpunosti kompromituje admin kontekst.

## Enumeracija kandidata upisivih putanja
Pokrenite PowerShell helper da otkrijete upisive/overwrite-abilne objekte unutar nominalno secure root-ova iz perspektive izabranog tokena:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Pokrenite kao Administrator za širi uvid; postavite `-ProcessId` na proces sa niskim privilegijama da odražava pristup tog tokena.
- Filtrirajte ručno da isključite poznate nedozvoljene poddirektorijume pre nego što koristite kandidate sa `RAiLaunchAdminProcess`.

## References
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
