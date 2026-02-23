# Zaobilaženja Admin Protection putem UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Pregled
- Windows AppInfo izlaže `RAiLaunchAdminProcess` za pokretanje UIAccess procesa (namenjeno softveru za pristupačnost). UIAccess zaobilazi većinu filtriranja poruka User Interface Privilege Isolation (UIPI) tako da softver za pristupačnost može upravljati UI-jem višeg IL.
- Direktno omogućavanje UIAccess zahteva `NtSetInformationToken(TokenUIAccess)` sa **SeTcbPrivilege**, pa pozivaoci sa niskim privilegijama zavise od servisa. Servis obavlja tri provere ciljnog binarnog fajla pre nego što postavi UIAccess:
- Ugrađeni manifest sadrži `uiAccess="true"`.
- Potpisan je bilo kojim sertifikatom kojem veruje Local Machine root store (nema zahteva za EKU/Microsoft).
- Smešten je u putanju koja je samo za administratore na sistemskom disku (npr., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, osim specifičnih podstaza u koje se može pisati).
- `RAiLaunchAdminProcess` ne prikazuje prompt za pristanak pri pokretanju UIAccess procesa (inače alatke za pristupačnost ne bi mogle da upravljaju promptom).

## Oblikovanje tokena i nivoi integriteta
- Ako provere uspeju, AppInfo **kopira token pozivaoca**, omogućava UIAccess i povećava Integrity Level (IL):
- Limited admin user (korisnik je u Administrators ali radi filtrirano) ➜ **High IL**.
- Non-admin user ➜ IL se povećava za **+16 nivoa** do maksimalnog **High** (System IL se nikad ne dodeljuje).
- Ako pozivaocev token već ima UIAccess, IL ostaje nepromenjen.
- „Ratchet“ trik: UIAccess proces može onemogućiti UIAccess na sebi, ponovno se pokrenuti preko `RAiLaunchAdminProcess` i dobiti još jedan +16 porast IL. Medium➜High zahteva 255 ponovnih pokretanja (bučno, ali funkcioniše).

## Zašto UIAccess omogućava zaobilaženje Admin Protection-a
- UIAccess dozvoljava procesu nižeg IL da šalje window poruke prozorima višeg IL (zaobilazeći UIPI filtere). Na **jednakom IL**, klasične UI primitive poput `SetWindowsHookEx` **dozvoljavaju injekciju koda/učitavanje DLL-a** u bilo koji proces koji poseduje prozor (uključujući **message-only windows** koje koristi COM).
- Admin Protection pokreće UIAccess proces pod identitetom **ograničenog korisnika** ali na **High IL**, bez obaveštenja. Kada proizvoljni kod počne da radi unutar tog High-IL UIAccess procesa, napadač može izvršiti injekciju u druge High-IL procese na desktopu (čak i one koji pripadaju različitim korisnicima), čime se narušava predviđena separacija.

## Slabosti validacije sigurnih direktorijuma (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo rešava prosleđenu putanju preko `GetFinalPathNameByHandle` i onda primenjuje **string allow/deny provere** protiv hardkodovanih root-ova/izuzeća. Više klasa zaobilaženja potiče iz te pojednostavljene validacije:
- Imenovani streamovi direktorijuma: Izuzete direktorijume u koje se može pisati (npr., `C:\Windows\tracing`) može se zaobići imenovanim streamom na samom direktorijumu, npr. `C:\Windows\tracing:file.exe`. String provere vide `C:\Windows\` i ne detektuju izuzetu podputanju.
- Upisivi fajl/direktorijum unutar dozvoljenog root-a: `CreateProcessAsUser` **ne zahteva `.exe` ekstenziju**. Prepisivanje bilo kog fajla koji se može upisati pod dozvoljenim root-om izvršnim payload-om radi, ili kopiranje potpisanog `uiAccess="true"` EXE-a u bilo koju poddirektorijum u koji se može pisati (npr., ostaci update-a poput `Tasks_Migrated` kada postoje) omogućava prolaz sigurnosne provere putanje.
- MSIX u `C:\Program Files\WindowsApps` (ispravljeno): Non-admin korisnici su mogli instalirati potpisane MSIX pakete koji su završavali u `WindowsApps`, koja nije bila izuzeta. Pakovanje UIAccess binarnog fajla unutar MSIX-a i njegovo pokretanje preko `RAiLaunchAdminProcess` vodilo je do **promptless High-IL UIAccess procesa**. Microsoft je ublažio problem isključivanjem ove putanje; `uiAccess` ograničena MSIX capability sama po sebi već zahteva administratorsku instalaciju.

## Attack workflow (High IL without a prompt)
1. Nabaviti/izgraditi **potpisani UIAccess binar** (manifest `uiAccess="true"`).
2. Postaviti ga tamo gde AppInfo-jev allowlist prihvata (ili iskoristiti edge case validacije putanje/upisivi artefakt kao gore).
3. Pozvati `RAiLaunchAdminProcess` da ga pokrene **tihо** sa UIAccess + povišenim IL.
4. Iz te High-IL pozicije ciljajte drugi High-IL proces na desktopu koristeći **window hooks/DLL injection** ili druge primitive istog IL-a da potpuno kompromitujete administratorski kontekst.

## Enumeracija kandidata upisivih putanja
Pokrenite PowerShell helper da otkrijete objekte koji se mogu upisati/prepisati unutar nominalno sigurnih root-ova iz perspektive izabranog tokena:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Pokrenite kao Administrator za širu vidljivost; postavite `-ProcessId` na low-priv proces kako biste preslikali pristup tog tokena.
- Ručno filtrirajte da biste isključili poznate nedozvoljene poddirektorijume pre korišćenja kandidata sa `RAiLaunchAdminProcess`.

## References
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
