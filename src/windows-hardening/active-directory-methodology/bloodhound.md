# BloodHound & Inne Narzędzia do Enumeracji Active Directory

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> UWAGA: Ta strona grupuje niektóre z najprzydatniejszych narzędzi do **enumeracji** i **wizualizacji** relacji Active Directory. Aby zebrać dane przez dyskretny kanał **Active Directory Web Services (ADWS)**, sprawdź powyższy odnośnik.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) to zaawansowany **wyświetlacz i edytor AD**, który umożliwia:

* Przeglądanie drzewa katalogów w GUI
* Edytowanie atrybutów obiektów i deskryptorów zabezpieczeń
* Tworzenie / porównywanie zrzutów do analizy offline

### Szybkie użycie

1. Uruchom narzędzie i połącz się z `dc01.corp.local` za pomocą dowolnych poświadczeń domenowych.
2. Utwórz zrzut offline za pomocą `Plik ➜ Utwórz zrzut`.
3. Porównaj dwa zrzuty za pomocą `Plik ➜ Porównaj`, aby zauważyć różnice w uprawnieniach.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) wyodrębnia dużą liczbę artefaktów z domeny (ACL, GPO, zaufania, szablony CA …) i generuje **raport Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (wizualizacja grafów)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) wykorzystuje teorię grafów + Neo4j do ujawnienia ukrytych relacji uprawnień w lokalnym AD i Azure AD.

### Wdrożenie (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Zbieracze

* `SharpHound.exe` / `Invoke-BloodHound` – natywna lub PowerShell wersja
* `AzureHound` – enumeracja Azure AD
* **SoaPy + BOFHound** – zbieranie ADWS (zobacz link na górze)

#### Typowe tryby SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Kolektorzy generują JSON, który jest wczytywany za pomocą interfejsu BloodHound.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumeruje **Group Policy Objects** i podkreśla błędne konfiguracje.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) przeprowadza **sprawdzenie stanu** Active Directory i generuje raport HTML z oceną ryzyka.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
