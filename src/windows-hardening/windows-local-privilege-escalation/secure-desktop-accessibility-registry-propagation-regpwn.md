# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Windows Accessibility funkcije čuvaju korisničku konfiguraciju u HKCU i propagiraju je na HKLM lokacije po sesijama. Tokom prelaska na **Secure Desktop** (zaključani ekran ili UAC prompt), **SYSTEM** komponente ponovo kopiraju ove vrednosti. Ako korisnik može da upisuje u **per-session HKLM ključ**, on postaje privilegovana tačka za upis koja može biti preusmerena pomoću **registry symbolic links**, što omogućava **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

RegPwn tehnika zloupotrebljava ovaj lanac propagacije pomoću malog race prozora koji se stabilizuje putem **opportunistic lock (oplock)** mehanizma nad datotekom koju koristi `osk.exe`.<sup>[[1]](#references)</sup>

## Lanac propagacije registra (Accessibility -> Secure Desktop)

Primer funkcije: **On-Screen Keyboard** (`osk`). Relevantne lokacije su:

- **Lista funkcija na nivou sistema**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Konfiguracija po korisniku (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **HKLM konfiguracija po sesiji (kreira je `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagacija tokom prelaska na secure desktop (pojednostavljeno):

1. **Korisnički `atbroker.exe`** kopira `HKCU\...\ATConfig\osk` u `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** kopira `HKLM\...\Session<session id>\ATConfig\osk` u `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** kopira `HKU\.DEFAULT\...\ATConfig\osk` nazad u `HKLM\...\Session<session id>\ATConfig\osk`.

Ako korisnik može da upisuje u HKLM podstablo sesije, koraci 2/3 omogućavaju SYSTEM upis preko lokacije koju korisnik može da zameni.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write putem Registry Links

Zamenite per-session ključ u koji korisnik može da upisuje pomoću **registry symbolic link**-a koji pokazuje na odredište koje odabere attacker. Kada se izvrši SYSTEM kopiranje, ono prati link i upisuje vrednosti pod kontrolom attackera u proizvoljni ciljni ključ.

Ključna ideja:

- Cilj upisa žrtve (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Attacker zamenjuje taj ključ pomoću **registry link**-a koji pokazuje na bilo koji drugi ključ.
- SYSTEM izvršava kopiranje i upisuje u ključ koji je odabrao attacker, sa SYSTEM permissions.

Ovo omogućava **arbitrary SYSTEM registry write** primitive.<sup>[[1]](#references)</sup>

## Dobijanje race prozora pomoću Oplocks

Postoji kratak timing prozor između pokretanja **SYSTEM `osk.exe`** i upisa u per-session ključ. Da bi exploit bio pouzdan, postavlja **oplock** nad:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Kada se oplock aktivira, napadač zamenjuje HKLM ključ po sesiji registry linkom, omogućava da se upis SYSTEM-a izvrši, a zatim uklanja link.<sup>[[1]](#references)</sup>

## Primer toka eksploatacije (visok nivo)

1. Preuzmite trenutni **ID sesije** iz access tokena.
2. Pokrenite skrivenu instancu `osk.exe` i kratko sačekajte (kako biste osigurali da se oplock aktivira).
3. Upišite vrednosti pod kontrolom napadača u:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Postavite **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Aktivirajte **Secure Desktop** (`LockWorkstation()`), čime se pokreću SYSTEM `atbroker.exe` / `osk.exe`.
6. Kada se oplock aktivira, zamenite `HKLM\...\Session<session id>\ATConfig\osk` **registry linkom** ka proizvoljnoj meti.
7. Kratko sačekajte da se SYSTEM kopiranje završi, a zatim uklonite link.<sup>[[1]](#references)</sup>

## Pretvaranje primitive u SYSTEM izvršavanje

Jedan jednostavan lanac je prepisivanje vrednosti **service configuration** (npr. `ImagePath`), a zatim pokretanje servisa. RegPwn PoC prepisuje `ImagePath` servisa **`msiserver`** i aktivira ga instanciranjem **MSI COM object**-a, što dovodi do izvršavanja koda kao **SYSTEM**.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## Povezano

Za druga ponašanja Secure Desktop / UIAccess pogledajte:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
