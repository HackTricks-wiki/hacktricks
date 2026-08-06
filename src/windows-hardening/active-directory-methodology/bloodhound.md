# BloodHound i inne narzędzia do enumeracji Active Directory

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> UWAGA: Ta strona grupuje niektóre z najbardziej użytecznych narzędzi do **enumeracji** i **wizualizacji** relacji w Active Directory. Aby zbierać dane za pośrednictwem stealthy kanału **Active Directory Web Services (ADWS)**, sprawdź powyższe odwołanie.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) to zaawansowany **AD viewer & editor**, który umożliwia:

* Przeglądanie drzewa katalogów za pomocą GUI
* Edycję atrybutów obiektów i deskryptorów zabezpieczeń
* Tworzenie i porównywanie snapshotów na potrzeby analizy offline

### Szybkie użycie

1. Uruchom narzędzie i połącz się z `dc01.corp.local`, używając dowolnych credentials domeny.
2. Utwórz snapshot offline za pomocą `File ➜ Create Snapshot`.
3. Porównaj dwa snapshoty za pomocą `File ➜ Compare`, aby wykryć zmiany uprawnień.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extracts a large set of artefacts from a domain (ACLs, GPOs, trusts, CA templates …) and produces an **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (wizualizacja grafu)

[BloodHound](https://github.com/SpecterOps/BloodHound) wykorzystuje teorię grafów do ujawniania ukrytych relacji uprawnień w lokalnym AD, Entra ID oraz wszelkich dodatkowych danych dotyczących powierzchni ataku, które importujesz za pomocą OpenGraph.<sup>[[1]](#references)</sup>

### Wdrożenie (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Kolektory

* `SharpHound.exe` / `Invoke-BloodHound` – natywny wariant lub wariant PowerShell
* `RustHound-CE` – wieloplatformowy kolektor CE dla Linux, macOS i Windows
* `NetExec --bloodhound` – szybkie zbieranie danych oparte na LDAP z Linux
* `AzureHound` – enumeracja Entra ID
* **SoaPy + BOFHound** – zbieranie danych przez ADWS (zobacz link na górze)

> BloodHound CE `v8+` zmienił format danych wyjściowych kolektora po wprowadzeniu OpenGraph. Po aktualizacji ze starszego BloodHound lub starszych instalacji CE ponownie przeprowadź rozpoznanie za pomocą aktualnych kolektorów przed zaimportowaniem danych.<sup>[[1]](#references)</sup>

#### Typowe tryby SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Kolektory generują kod JSON, który jest importowany za pośrednictwem interfejsu BloodHound GUI.

#### SharpHound z hosta Windows nieprzyłączonego do domeny

Jeśli Twoja maszyna wirtualna operatora nie jest przyłączona do docelowej domeny, ustaw DNS na kontroler domeny (DC), uruchom powłokę **network-only**, sprawdź, czy możesz uzyskać dostęp do `SYSVOL`/`NETLOGON` na kontrolerze domeny, a następnie zbierz dane ze zdalnej domeny:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Jest to przydatne w przypadku jednorazowych jump boxów lub stacji roboczych operatora, które nie powinny być przyłączone do domeny.

#### Zbieranie danych między platformami z systemów Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` to dobry wybór domyślny, gdy potrzebujesz danych wyjściowych kompatybilnych z CE z hosta non-Windows.<sup>[[2]](#references)</sup> `NetExec` jest wygodny, gdy już używasz go do walidacji LDAP lub spraying i chcesz szybko zaimportować graf. W przypadku datasetów innych niż AD BloodHound OpenGraph można rozszerzyć o collectory, takie jak [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).<sup>[[1]](#references)</sup>

### ADPathFinder (priorytetyzacja ścieżek OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) działa na warstwie BloodHound CE/OpenGraph, gdy graf jest zbyt duży, aby ręcznie wykonywać pivoting. Zamiast pytać tylko, czy jeden principal może dotrzeć do jednego celu, oblicza najkrótsze ścieżki od wielu użytkowników i komputerów o niskich uprawnieniach do obiektów o wysokiej wartości, grupuje ścieżki wykorzystujące te same krawędzie i wskazuje wspólny choke point, który powinien zostać naprawiony w pierwszej kolejności.<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Po zaimportowaniu danych `MSSQLHound` i `ConfigManBearPig` jedno ustalenie może łączyć [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) oraz [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md), zamiast pozostawiać je jako oddzielne tropy.<sup>[[4]](#references)</sup> Przykładowa wspólna ścieżka:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Śledź **effective security context** na każdej krawędzi. Ścieżka staje się krytyczna dla domeny, gdy tylko jedna z tranzycji jest wykonywana jako uprzywilejowana tożsamość domenowa, nawet jeśli zaczynała się od zwykłego użytkownika.
- Grupowane ustalenia są idealne do **remediacji punktów wąskiego gardła**: usunięcie jednego uprawnienia do impersonacji SQL, zaufania linked-server, ścieżki nadużycia certificate-template lub przypisania SCCM może jednocześnie zlikwidować wiele najkrótszych ścieżek.
- Nadaj ponownie priorytet ustaleniom o „średnim” poziomie, uwzględniając **kontekst grafu**. Wyłączone SMB signing, ekspozycja WebClient, błędy konfiguracji delegacji lub serwery SQL podatne na NTLM-relay zasługują na wyższy priorytet, gdy przejęty węzeł ma dalsze ścieżki do Domain Admins, Domain Controllers, CA lub serwerów witryn SCCM.
- Jeśli masz również dane wyjściowe `NTDS.dit` i plik potfile Hashcat, opcja `--pwd` koreluje złamane hasła z właściwościami BloodHound, dzięki czemu możesz szybko oddzielić zwykłe ponowne użycie haseł od złamanych poświadczeń należących do uprzywilejowanych, Kerberoastable, AS-REP roastable lub istotnych dla ścieżki kont.

### Zbieranie uprawnień i praw logowania

Windows **token privileges** (np. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) mogą omijać kontrole DACL, więc mapowanie ich w całej domenie ujawnia lokalne krawędzie LPE, których nie pokazują grafy oparte wyłącznie na ACL. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` oraz odpowiadające im `SeDeny*`) są egzekwowane przez LSA, zanim token w ogóle powstanie, a prawa odmowy mają pierwszeństwo, przez co w istotny sposób ograniczają lateral movement (logowanie przez RDP/SMB/zaplanowane zadanie/usługę).<sup>[[3]](#references)</sup>

**Uruchamiaj collectory z podwyższonymi uprawnieniami**, gdy jest to możliwe: UAC tworzy przefiltrowany token dla interaktywnych administratorów (przez `NtFilterToken`), usuwając wrażliwe uprawnienia i oznaczając SID-y administratorów jako deny-only. Jeśli wyliczasz uprawnienia z niepodwyższonej powłoki, cenne uprawnienia będą niewidoczne, a BloodHound nie zaimportuje tych krawędzi.<sup>[[3]](#references)</sup>

Obecnie istnieją dwie uzupełniające się strategie zbierania danych przez SharpHound:<sup>[[3]](#references)</sup>

- **Analiza GPO/SYSVOL (stealthy, z niskimi uprawnieniami):**
1. Wylicz GPO przez LDAP (`(objectCategory=groupPolicyContainer)`) i odczytaj dla każdego `gPCFileSysPath`.
2. Pobierz `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` z SYSVOL i przeanalizuj sekcję `[Privilege Rights]`, która mapuje nazwy privilege/logon-right na SID-y.
3. Rozwiąż linki GPO za pomocą `gPLink` na poziomie OU/site/domain, wyświetl komputery w połączonych kontenerach i przypisz te prawa do tych maszyn.
4. Zaleta: działa ze zwykłym użytkownikiem i jest ciche; wada: widoczne są wyłącznie prawa wdrażane przez GPO (lokalne modyfikacje zostaną pominięte).

- **Wyliczanie przez LSA RPC (głośne, dokładne):**
- Z kontekstu z lokalnymi uprawnieniami administratora na celu otwórz Local Security Policy i wywołaj `LsaEnumerateAccountsWithUserRight` dla każdego privilege/logon right, aby przez RPC wyliczyć przypisane podmioty.
- Zaleta: przechwytuje prawa ustawione lokalnie lub poza GPO; wada: generuje głośny ruch sieciowy i wymaga uprawnień administratora na każdym hoście.

**Przykładowa ścieżka nadużycia ujawniona przez te krawędzie:** `CanRDP` ➜ host, na którym użytkownik ma również `SeBackupPrivilege` ➜ uruchomienie podwyższonej powłoki w celu uniknięcia przefiltrowanych tokenów ➜ użycie semantyki backupu do odczytu gałęzi `SAM` i `SYSTEM` pomimo restrykcyjnych DACL ➜ eksfiltracja i uruchomienie offline `secretsdump.py` w celu odzyskania NT hash lokalnego Administratora do lateral movement/eskalacji uprawnień.<sup>[[3]](#references)</sup>

### Ustalanie priorytetów Kerberoasting z BloodHound

Używaj kontekstu grafu, aby kierować roasting na konkretne cele:

1. Zbierz dane raz za pomocą collectora kompatybilnego z ADWS i pracuj offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Zaimportuj ZIP, oznacz przejęty podmiot jako owned i uruchom wbudowane zapytania (*Kerberoastable Users*, *Shortest Paths to Domain Admins*), aby ujawnić konta SPN z uprawnieniami administratora/infrastruktury.
3. Ustal priorytet SPN na podstawie blast radius; przed crackingiem przeanalizuj `pwdLastSet`, `lastLogon` oraz dozwolone typy szyfrowania.
4. Zażądaj wyłącznie wybranych ticketów, złam je offline, a następnie ponownie wykonaj zapytania w BloodHound z nowym dostępem:
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

[PingCastle](https://www.pingcastle.com/documentation/) wykonuje **kontrolę stanu** Active Directory i generuje raport HTML z oceną ryzyka.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Odnośniki

- [1] [BloodHound Community Edition v8 Launches with OpenGraph: Ścieżki ataku na tożsamość wykraczające poza Active Directory i Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [Poza ACL: Mapowanie ścieżek eskalacji uprawnień w Windows za pomocą BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: Mapowanie ścieżek ataku OpenGraph w BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
