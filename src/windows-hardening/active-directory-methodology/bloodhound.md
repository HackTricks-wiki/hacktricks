# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> UWAGA: Ta strona grupuje niektóre z najbardziej przydatnych narzędzi do **enumeracji** i **wizualizacji** relacji Active Directory. Aby zbierać dane przez ukryty kanał **Active Directory Web Services (ADWS)** sprawdź referencję powyżej.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) to zaawansowany **AD viewer & editor**, który umożliwia:

* Graficzne (GUI) przeglądanie drzewa katalogu
* Edycję atrybutów obiektów i deskryptorów zabezpieczeń
* Tworzenie zrzutów stanu oraz ich porównywanie do analizy offline

### Quick usage

1. Uruchom narzędzie i połącz się z `dc01.corp.local` używając dowolnych poświadczeń domenowych.
2. Utwórz zrzut offline przez `File ➜ Create Snapshot`.
3. Porównaj dwa zrzuty za pomocą `File ➜ Compare`, aby wykryć zmiany uprawnień.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) wyodrębnia duży zestaw artefaktów z domeny (ACLs, GPOs, trusts, CA templates …) i generuje **raport Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (wizualizacja grafu)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) używa teorii grafów + Neo4j, aby ujawnić ukryte relacje uprawnień w on-prem AD & Azure AD.

### Wdrożenie (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Kolektory

* `SharpHound.exe` / `Invoke-BloodHound` – wariant natywny lub PowerShell
* `AzureHound` – enumeracja Azure AD
* **SoaPy + BOFHound** – zbieranie ADWS (zobacz link powyżej)

#### Typowe tryby SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Kolektory generują JSON, który jest wczytywany przez BloodHound GUI.

---

## Priorytetyzacja Kerberoastingu z BloodHound

Kontekst grafu jest kluczowy, aby uniknąć hałaśliwego, nieselektywnego Kerberoastingu. Lekki przebieg pracy:

1. **Zbierz wszystko raz** używając kolektora zgodnego z ADWS (np. RustHound-CE), aby móc pracować offline i ćwiczyć ścieżki bez ponownego kontaktu z DC:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Importuj ZIP, oznacz skompromitowany principal jako owned**, a następnie uruchom wbudowane zapytania takie jak *Kerberoastable Users* i *Shortest Paths to Domain Admins*. To natychmiast wyróżnia konta posiadające SPN z użytecznymi członkostwami w grupach (Exchange, IT, tier0 service accounts, etc.).
3. **Priorytetyzuj według blast radius** – skup się na SPN, które kontrolują współdzieloną infrastrukturę lub mają prawa administratora, i sprawdź `pwdLastSet`, `lastLogon` oraz dozwolone typy szyfrowania zanim poświęcisz zasoby na łamanie.
4. **Request only the tickets you care about**. Narzędzia takie jak NetExec mogą targetować wybrane `sAMAccountName`s, tak aby każde żądanie LDAP ROAST miało jasne uzasadnienie:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, a następnie natychmiast ponownie odpytać BloodHound, aby zaplanować post-exploitation z wykorzystaniem nowych uprawnień.

Takie podejście utrzymuje wysoki stosunek sygnału do szumu, zmniejsza wykrywalną objętość (brak masowych żądań SPN) i zapewnia, że każdy cracked ticket przekłada się na istotne kroki eskalacji uprawnień.

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumeruje **Group Policy Objects** i wskazuje nieprawidłowe konfiguracje.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) wykonuje **sprawdzenie stanu** Active Directory i generuje raport HTML z oceną ryzyka.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referencje

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
