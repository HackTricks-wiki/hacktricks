# Zaobilaženja Admin Protection putem UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Pregled
- Windows AppInfo izlaže `RAiLaunchAdminProcess` za pokretanje UIAccess procesa (namenjeno za accessibility). UIAccess zaobilazi većinu User Interface Privilege Isolation (UIPI) filtriranja poruka tako da accessibility softver može upravljati UI-jem višeg IL.
- Direktno omogućavanje UIAccess zahteva `NtSetInformationToken(TokenUIAccess)` sa **SeTcbPrivilege**, pa niskoprivilegovani pozivaoci zavise od servisa. Servis obavlja tri provere ciljnog binarnog fajla pre nego što postavi UIAccess:
- Ugrađeni manifest sadrži `uiAccess="true"`.
- Potpisan je bilo kojim sertifikatom kome veruje Local Machine root store (bez EKU/Microsoft zahteva).
- Smešten je u direktorijumu dostupan samo administratorima na sistemskom drajvu (npr. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, isključujući specifične podputanje koja su upisiva).
- `RAiLaunchAdminProcess` ne prikazuje prompt za consent za UIAccess pokretanja (u suprotnom accessibility alati ne bi mogli upravljati promptom).

## Token shaping i integrity levels
- Ako provere uspeju, AppInfo **kopira caller token**, omogućava UIAccess i podiže Integrity Level (IL):
- Limited admin user (user je u Administrators ali radi filtrirano) ➜ **High IL**.
- Non-admin user ➜ IL se povećava za **+16 nivoa** do maksimuma **High** (System IL nikada nije dodeljen).
- Ako caller token već ima UIAccess, IL ostaje nepromenjen.
- “Ratchet” trik: UIAccess proces može onemogućiti UIAccess na sebi, ponovo se pokrenuti preko `RAiLaunchAdminProcess`, i dobiti još jedan +16 IL inkrement. Medium➜High zahteva 255 ponovnih pokretanja (buka, ali radi).

## Zašto UIAccess omogućava bekstvo iz Admin Protection
- UIAccess omogućava procesu nižeg IL da šalje window poruke ka prozorima višeg IL (zaobilazeći UIPI filtere). Na **jednakom IL**, klasične UI primitive poput `SetWindowsHookEx` **dozvoljavaju code injection/DLL loading** u bilo koji proces koji poseduje prozor (uključujući **message-only windows** koje koristi COM).
- Admin Protection pokreće UIAccess proces pod identitetom **limited user-a** ali na **High IL**, bez upozorenja. Kada proizvoljni kod zaživi u tom High-IL UIAccess procesu, napadač može inject-ovati u druge High-IL procese na desktopu (čak i one koji pripadaju različitim korisnicima), razbijajući predviđenu separaciju.

## HWND-to-process handle primitiva (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Na Windows 10 1803+ API je premesten u Win32k (`NtUserGetWindowProcessHandle`) i može otvoriti process handle koristeći caller-om prosleđeni `DesiredAccess`. Kernel putanja koristi `ObOpenObjectByPointer(..., KernelMode, ...)`, što zaobilazi normalne user-mode provere pristupa.
- Preduslovi u praksi: ciljni prozor mora biti na istom desktopu, i UIPI provere moraju proći. Istorijski, caller sa UIAccess je mogao zaobići UIPI neuspeh i ipak dobiti kernel-mode handle (ispravljeno kao CVE-2023-41772).
- Uticaj: window handle postaje **sposobnost (capability)** da se dobije moćan process handle (obično `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) koji caller inače ne bi mogao normalno da otvori. Ovo omogućava cross-sandbox pristup i može razbiti Protected Process / PPL granice ako cilj izlaže bilo koji prozor (uključujući message-only windows).
- Praktični zloupotrebljivački tok: enumerišite ili pronađite HWND-ove (npr. `EnumWindows`/`FindWindowEx`), razrešite owning PID (`GetWindowThreadProcessId`), pozovite `GetProcessHandleFromHwnd`, pa koristite vraćeni handle za memory read/write ili code-hijack primitive.
- Nakon ispravke: UIAccess više ne daje kernel-mode opens na UIPI neuspeh i dozvoljena prava pristupa su ograničena na legacy hook skup; Windows 11 24H2 dodaje provere process-protection i feature-flagged sigurnije putanje. Onemogućavanje UIPI sistemski (`EnforceUIPI=0`) oslabljuje ove zaštite.

## Slabosti validacije sigurnih direktorijuma (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo rešava prosleđeni path preko `GetFinalPathNameByHandle` i zatim primenjuje **string allow/deny provere** naspram hardkodiranih root-ova/isključenja. Više klasa zaobilaženja proizilazi iz te pojednostavljene validacije:
- **Directory named streams**: Izuzeti upisivi direktorijumi (npr. `C:\Windows\tracing`) mogu se zaobići sa named stream-om na samom direktorijumu, npr. `C:\Windows\tracing:file.exe`. String provere vide `C:\Windows\` i propuste isključeni podput.
- **Writable file/directory unutar dozvoljenog root-a**: `CreateProcessAsUser` **ne zahteva `.exe` ekstenziju**. Prepisivanje bilo kog upisivog fajla pod dozvoljenim root-om sa izvršnim payload-om radi, ili kopiranje potpisanog `uiAccess="true"` EXE u bilo koji upisivi poddirektorijum (npr. ostaci nadogradnje poput `Tasks_Migrated` kada postoje) omogućava prolaz sigurnosne-provere puta.
- **MSIX u `C:\Program Files\WindowsApps` (ispravljeno)**: Non-admin korisnici su mogli instalirati potpisane MSIX pakete koji su završavali u `WindowsApps`, koji nije bio isključen. Pakovanje UIAccess binarnog u MSIX i njegovo pokretanje preko `RAiLaunchAdminProcess` rezultovalo je u **promptless High-IL UIAccess procesu**. Microsoft je ublažio problem isključivanjem ovog puta; `uiAccess` ograničena MSIX capability sama po sebi već zahteva admin instalaciju.

## Attack workflow (High IL bez prompta)
1. Nabavite/izgradite **potpisani UIAccess binary** (manifest `uiAccess="true"`).
2. Postavite ga tamo gde AppInfo-ev allowlist prihvata (ili zloupotrebite edge case validacije putanje/upisivog artefakta kao gore).
3. Pozovite `RAiLaunchAdminProcess` da ga pokrenete **tiho** sa UIAccess + povišenim IL.
4. Iz tog High-IL uporišta, ciljajte drugi High-IL proces na desktopu koristeći **window hooks/DLL injection** ili druge same-IL primitive da potpuno kompromitujete admin kontekst.

## Enumeracija kandidata upisivih putanja
Pokrenite PowerShell helper da otkrijete upisive/ponovno-upisive objekte unutar nominalno sigurnih root-ova iz perspektive izabranog token-a:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Pokrenite kao Administrator radi veće preglednosti; podesite `-ProcessId` na proces sa niskim privilegijama da preslika pristup tog tokena.
- Ručno filtrirajte da isključite poznate nedozvoljene poddirektorijume pre korišćenja kandidata sa `RAiLaunchAdminProcess`.

## References
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
