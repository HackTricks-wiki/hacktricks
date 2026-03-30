# Propagacija registra pristupačnosti Secure Desktop LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Windows Accessibility funkcije čuvaju korisničke konfiguracije pod HKCU i propagiraju ih u per-session lokacije pod HKLM. Tokom prelaza na Secure Desktop (zaključani ekran ili UAC prompt), SYSTEM komponente ponovo kopiraju ove vrednosti. Ako je per-session HKLM ključ dostupan za pisanje od strane korisnika, on postaje privilegovana tačka pisanja koja se može preusmeriti pomoću simboličkih veza registra, što rezultuje proizvoljnim SYSTEM pisanjem u registar.

Tehnika RegPwn zloupotrebljava taj lanac propagacije sa kratkim vremenskim prozorom za trku, stabilizovanim preko opportunistic lock (oplock) na fajl koji koristi `osk.exe`.

## Lanac propagacije registra (Accessibility -> Secure Desktop)

Primer funkcije: **On-Screen Keyboard** (`osk`). Relevantne lokacije su:

- **Lista funkcija na nivou sistema**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Konfiguracija po korisniku (korisnik može pisati)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Konfiguracija po sesiji u HKLM (kreirana od strane `winlogon.exe`, korisnik može pisati)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Hive podrazumevanog korisnika / Secure desktop (kontekst SYSTEM-a)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagacija tokom prelaza na Secure Desktop (pojednostavljeno):

1. **Korisnička instanca `atbroker.exe`** kopira `HKCU\...\ATConfig\osk` u `HKLM\...\Session<session id>\ATConfig\osk`.
2. **SYSTEM `atbroker.exe`** kopira `HKLM\...\Session<session id>\ATConfig\osk` u `HKU\.DEFAULT\...\ATConfig\osk`.
3. **SYSTEM `osk.exe`** kopira `HKU\.DEFAULT\...\ATConfig\osk` nazad u `HKLM\...\Session<session id>\ATConfig\osk`.

Ako je HKLM podstabla za sesiju dostupna za pisanje od strane korisnika, koraci 2/3 omogućavaju SYSTEM pisanje kroz lokaciju koju korisnik može zameniti.

## Primitiv: Proizvoljno SYSTEM pisanje u registar preko simboličkih veza registra

Zamenite korisnički pisivi per-session ključ sa simboličkom vezom registra koja pokazuje na destinaciju po izboru napadača. Kada dođe do SYSTEM kopije, ona sledi vezu i upisuje vrednosti pod kontrolom napadača u proizvoljni ciljni ključ.

Ključna ideja:

- Metа za pisanje žrtve (pisivo od strane korisnika):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Napadač zamenjuje taj ključ simboličkom vezom registra ka bilo kom drugom ključu.
- SYSTEM izvršava kopiju i upisuje u cilj koji je napadač odabrao sa SYSTEM privilegijama.

Ovo daje primitiv za **proizvoljno SYSTEM pisanje u registar**.

## Dobijanje vremenskog prozora trke pomoću oplock-a

Postoji kratak vremenski prozor između pokretanja SYSTEM `osk.exe` i pisanja per-session ključa. Da bi bio pouzdan, exploit postavlja oplock na:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Kada se oplock pokrene, napadač zamenjuje per-session HKLM ključ registrija za registry link, dopušta SYSTEM-u da upiše, a zatim uklanja link.

## Primer toka eksploatacije (visok nivo)

1. Preuzmite trenutni **session ID** iz access token-a.
2. Pokrenite skriveni `osk.exe` proces i kratko sačekajte (osigurajte da će oplock biti pokrenut).
3. Upišite vrednosti pod kontrolom napadača u:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Postavite **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Pokrenite **Secure Desktop** (`LockWorkstation()`), što prouzrokuje pokretanje SYSTEM `atbroker.exe` / `osk.exe`.
6. Kada se oplock aktivira, zamenite `HKLM\...\Session<session id>\ATConfig\osk` sa **registry link**-om ka proizvoljnom cilju.
7. Sačekajte kratko da SYSTEM kopiranje završi, zatim uklonite link.

## Pretvaranje primitiva u izvršenje kao SYSTEM

Jedan jednostavan lanac je prepisivanje vrednosti **konfiguracije servisa** (npr. `ImagePath`) i zatim pokretanje servisa. RegPwn PoC prepisuje `ImagePath` za **`msiserver`** i pokreće ga instanciranjem **MSI COM object**, što dovodi do izvršenja koda kao **SYSTEM**.

## Povezano

Za druga ponašanja vezana za Secure Desktop / UIAccess, pogledajte:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Reference

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
