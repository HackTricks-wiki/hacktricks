# BloodHound i inne narzędzia do enumeracji Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> UWAGA: Ta strona grupuje niektóre z najbardziej przydatnych narzędzi do **enumerowania** i **wizualizowania** zależności w Active Directory. Aby zbierać dane za pośrednictwem ukrytego kanału **Active Directory Web Services (ADWS)**, sprawdź powyższy odnośnik.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) to zaawansowana aplikacja do **przeglądania i edycji AD**, która umożliwia:

* Przeglądanie drzewa katalogu za pomocą GUI
* Edycję atrybutów obiektów i deskryptorów zabezpieczeń
* Tworzenie i porównywanie snapshotów na potrzeby analizy offline

### Szybkie użycie

1. Uruchom narzędzie i połącz się z `dc01.corp.local` przy użyciu dowolnych poświadczeń domenowych.
2. Utwórz snapshot offline za pomocą `File ➜ Create Snapshot`.
3. Porównaj dwa snapshoty za pomocą `File ➜ Compare`, aby wykryć zmiany uprawnień.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) wyodrębnia duży zestaw artefaktów z domeny (ACL, GPO, zaufania, szablony CA …) i tworzy **raport Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (wizualizacja grafowa)

[BloodHound](https://github.com/SpecterOps/BloodHound) wykorzystuje teorię grafów do ujawniania ukrytych relacji uprawnień w lokalnym AD, Entra ID oraz wszelkich dodatkowych danych o powierzchni ataku, które pozyskasz za pośrednictwem OpenGraph.

### Wdrożenie (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Kolektory

* `SharpHound.exe` / `Invoke-BloodHound` – wariant natywny lub PowerShell
* `RustHound-CE` – wieloplatformowy collector CE dla Linux, macOS i Windows
* `NetExec --bloodhound` – szybkie zbieranie danych z użyciem LDAP z Linux
* `AzureHound` – enumeracja Entra ID
* **SoaPy + BOFHound** – zbieranie danych przez ADWS (zobacz link na górze)

> BloodHound CE `v8+` zmienił format wyjściowy collectora po wprowadzeniu OpenGraph. Po aktualizacji ze starszego BloodHound lub starszych instalacji CE uruchom ponownie discovery za pomocą aktualnych collectorów przed zaimportowaniem danych.

#### Typowe tryby SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Kolektory generują JSON, który jest importowany za pomocą GUI BloodHound.

#### SharpHound z hosta Windows nienależącego do domeny

Jeśli maszyna operatora nie jest dołączona do docelowej domeny, skieruj DNS na kontroler domeny (DC), uruchom powłokę **network-only**, sprawdź, czy możesz wyświetlić `SYSVOL`/`NETLOGON` na kontrolerze domeny, a następnie wykonaj zbieranie danych zdalnej domeny:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Jest to przydatne w przypadku jednorazowych jump boxów lub stacji roboczych operatorów, które nie powinny być dołączane do domeny.

#### Zbieranie danych z Linux/macOS na różnych platformach
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` to dobry wybór domyślny, gdy chcesz uzyskać output kompatybilny z CE z hosta innego niż Windows. `NetExec` jest wygodny, gdy już używasz go do walidacji LDAP lub spraying i chcesz szybko zaimportować graf. W przypadku datasetów innych niż AD funkcjonalność BloodHound OpenGraph można rozszerzyć za pomocą collectorów, takich jak [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### ADPathFinder (priorytetyzacja ścieżek OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) działa na bazie BloodHound CE/OpenGraph, gdy graf jest zbyt duży, aby ręcznie wykonywać pivoting. Zamiast pytać tylko, czy jeden principal może uzyskać dostęp do jednego celu, narzędzie oblicza najkrótsze ścieżki od wielu użytkowników i komputerów o niskich uprawnieniach do obiektów o wysokiej wartości, grupuje ścieżki wykorzystujące te same krawędzie i wskazuje wspólne wąskie gardło, które powinno zostać naprawione w pierwszej kolejności.
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Po zaimportowaniu danych `MSSQLHound` i `ConfigManBearPig` jedno ustalenie może łączyć [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) i [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md), zamiast pozostawiać je jako osobne tropy. Przykładowa wspólna ścieżka:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Śledź **effective security context** na każdej krawędzi. Ścieżka staje się krytyczna dla domeny, gdy tylko jedna tranzycja zostanie wykonana jako uprzywilejowana tożsamość domenowa, nawet jeśli rozpoczęła się od zwykłego użytkownika.
- Zgrupowane ustalenia są idealne do **remediacji punktów krytycznych**: usunięcie jednego uprawnienia do impersonacji SQL, zaufania linked-server, ścieżki nadużycia certificate-template lub przypisania SCCM może jednocześnie zlikwidować wiele najkrótszych ścieżek.
- Nadaj ponownie priorytet ustaleniom oznaczonym jako „medium”, uwzględniając **kontekst grafu**. Wyłączone SMB signing, ekspozycja WebClient, błędy w delegacji lub podatne na NTLM relay serwery SQL zasługują na wyższy priorytet, gdy przejęty węzeł ma dalsze ścieżki do Domain Admins, Domain Controllers, CAs lub SCCM site servers.
- Jeśli masz również wynik `NTDS.dit` i plik potfile programu hashcat, opcja `--pwd` koreluje złamane hasła z właściwościami BloodHound, dzięki czemu możesz szybko oddzielić zwykłe ponowne użycie haseł od złamanych poświadczeń na kontach uprzywilejowanych, podatnych na Kerberoasting, AS-REP roasting lub istotnych dla ścieżki.

### Zbieranie uprawnień i praw logowania

Windows **token privileges** (np. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) mogą omijać kontrole DACL, dlatego mapowanie ich w całej domenie ujawnia lokalne krawędzie LPE, których brakuje w grafach opartych wyłącznie na ACL. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` oraz odpowiadające im `SeDeny*`) są egzekwowane przez LSA, zanim token w ogóle powstanie, a odmowy mają pierwszeństwo, więc istotnie ograniczają ruch lateralny (logowanie przez RDP/SMB/zaplanowane zadanie/usługę).

**Uruchamiaj collectory z podniesionymi uprawnieniami**, gdy jest to możliwe: UAC tworzy filtered token dla administratorów interaktywnych (przez `NtFilterToken`), usuwając wrażliwe uprawnienia i oznaczając SID-y administratorów jako deny-only. Jeśli wyliczasz uprawnienia z niepodniesionej powłoki, uprawnienia o wysokiej wartości będą niewidoczne, a BloodHound nie zaimportuje tych krawędzi.

Obecnie istnieją dwie uzupełniające się strategie zbierania danych przez SharpHound:

- **Parsowanie GPO/SYSVOL (stealthy, z niskimi uprawnieniami):**
1. Wylicz GPO przez LDAP (`(objectCategory=groupPolicyContainer)`) i odczytaj `gPCFileSysPath` każdego z nich.
2. Pobierz `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` z SYSVOL i sparsuj sekcję `[Privilege Rights]`, która mapuje nazwy uprawnień/praw logowania na SID-y.
3. Rozwiąż linki GPO za pomocą `gPLink` na OU/sites/domains, wyświetl komputery w połączonych kontenerach i przypisz te prawa do odpowiednich maszyn.
4. Zaleta: działa ze zwykłym użytkownikiem i jest ciche; wada: pokazuje tylko prawa wdrażane przez GPO (lokalne modyfikacje zostaną pominięte).

- **Wyliczanie przez LSA RPC (głośne, dokładne):**
- Z kontekstu z lokalnym administratorem na celu otwórz Local Security Policy i wywołaj `LsaEnumerateAccountsWithUserRight` dla każdego uprawnienia/prawa logowania, aby przez RPC wyliczyć przypisane principals.
- Zaleta: obejmuje prawa ustawione lokalnie lub poza GPO; wada: generuje głośny ruch sieciowy i wymaga uprawnień administratora na każdym hoście.

**Przykładowa ścieżka nadużycia ujawniona przez te krawędzie:** `CanRDP` ➜ host, na którym użytkownik ma również `SeBackupPrivilege` ➜ uruchomienie elevated shell w celu uniknięcia filtered tokens ➜ użycie backup semantics do odczytu hive-ów `SAM` i `SYSTEM` pomimo restrykcyjnych DACL ➜ eksfiltracja i uruchomienie `secretsdump.py` offline w celu odzyskania lokalnego NT hash Administratora do ruchu lateralnego/podniesienia uprawnień.

### Priorytetyzacja Kerberoasting z użyciem BloodHound

Używaj kontekstu grafu, aby utrzymać ukierunkowany charakter roastingu:

1. Zbierz dane raz za pomocą collectora kompatybilnego z ADWS i pracuj offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Zaimportuj ZIP, oznacz przejęty principal jako owned i uruchom wbudowane zapytania (*Kerberoastable Users*, *Shortest Paths to Domain Admins*), aby ujawnić konta SPN z uprawnieniami administratora/infrastruktury.
3. Ustal priorytet SPN na podstawie blast radius; przed crackingiem sprawdź `pwdLastSet`, `lastLogon` oraz dozwolone typy szyfrowania.
4. Zażądaj tylko wybranych ticketów, złam je offline, a następnie ponownie zapytaj BloodHound z wykorzystaniem nowego dostępu:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) wylicza **Group Policy Objects** i wskazuje błędne konfiguracje.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) wykonuje **health-check** Active Directory i generuje raport HTML z oceną ryzyka.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Odnośniki

- [BloodHound Community Edition v8 Launches with OpenGraph: Ścieżki ataku na tożsamość poza Active Directory i Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapowanie ścieżek eskalacji uprawnień w Windows za pomocą BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [ADPathFinder: Mapowanie ścieżek ataku OpenGraph w BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
