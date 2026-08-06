# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows Accessibility funkcije čuvaju korisničku konfiguraciju u HKCU i propagiraju je na per-session HKLM lokacije. Tokom prelaska na **Secure Desktop** (lock screen ili UAC prompt), **SYSTEM** komponente ponovo kopiraju ove vrednosti. Ako je **per-session HKLM ključ** upisiv korisniku, on postaje privilegovana tačka za upis, koja se može preusmeriti pomoću **registry symbolic links**, čime se dobija **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

RegPwn tehnika zloupotrebljava ovaj lanac propagacije pomoću malog race window-a stabilizovanog preko **opportunistic lock (oplock)** mehanizma na fajlu koji koristi `osk.exe`.<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Primer funkcije: **On-Screen Keyboard** (`osk`). Relevantne lokacije su:

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagacija tokom prelaska na secure desktop (pojednostavljeno):

1. **User `atbroker.exe`** kopira `HKCU\...\ATConfig\osk` u `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** kopira `HKLM\...\Session<session id>\ATConfig\osk` u `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** kopira `HKU\.DEFAULT\...\ATConfig\osk` nazad u `HKLM\...\Session<session id>\ATConfig\osk`.

Ako je HKLM podstablo sesije upisivo korisniku, koraci 2/3 omogućavaju SYSTEM upis preko lokacije koju korisnik može da zameni.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Zamenite user-writable per-session ključ **registry symbolic link**-om koji pokazuje na odredište izabrano od strane napadača. Kada se izvrši SYSTEM kopiranje, ono prati link i upisuje vrednosti pod kontrolom napadača u proizvoljni ciljni ključ.

Ključna ideja:

- Cilj victim write-a (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Napadač zamenjuje taj ključ **registry link**-om ka bilo kom drugom ključu.
- SYSTEM izvršava kopiranje i upisuje u ključ koji je izabrao napadač, sa SYSTEM privilegijama.

Ovim se dobija **arbitrary SYSTEM registry write** primitive.<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

Postoji kratak timing window između pokretanja **SYSTEM `osk.exe`** procesa i njegovog upisa u per-session ključ. Da bi exploit bio pouzdan, na sledeću lokaciju se postavlja **oplock**:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Kada se oplock aktivira, napadač zamenjuje HKLM ključ po sesiji registry linkom, omogućava da se upis SYSTEM-a izvrši, a zatim uklanja link.<sup>[[1]](#references)</sup>

## Primer toka eksploatacije (visok nivo)

1. Preuzmite trenutni **session ID** iz access tokena.
2. Pokrenite skrivenu instancu `osk.exe` i kratko sačekajte (kako biste osigurali da se oplock aktivira).
3. Upišite vrednosti pod kontrolom napadača u:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Postavite **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Aktivirajte **Secure Desktop** (`LockWorkstation()`), čime se pokreću SYSTEM `atbroker.exe` / `osk.exe`.
6. Kada se oplock aktivira, zamenite `HKLM\...\Session<session id>\ATConfig\osk` **registry linkom** ka proizvoljnoj meti.
7. Kratko sačekajte da se SYSTEM kopiranje završi, a zatim uklonite link.<sup>[[1]](#references)</sup>

## Pretvaranje primitive u SYSTEM izvršavanje

Jedan jednostavan lanac sastoji se od prepisivanja vrednosti **service configuration** (npr. `ImagePath`), a zatim pokretanja servisa. RegPwn PoC prepisuje `ImagePath` servisa **`msiserver`** i pokreće ga instanciranjem **MSI COM objekta**, što dovodi do izvršavanja koda u kontekstu **SYSTEM**.<sup>[[1]](#references)[[2]](#references)</sup>

## Povezano

Za druga Secure Desktop / UIAccess ponašanja pogledajte:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Reference

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
