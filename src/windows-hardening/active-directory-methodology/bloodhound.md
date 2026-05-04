# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: Ta strona grupuje niektóre z najbardziej przydatnych narzędzi do **enumerate** i wizualizacji relacji Active Directory.  Do zbierania danych przez dyskretny kanał **Active Directory Web Services (ADWS)** sprawdź odwołanie powyżej.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) to zaawansowany **AD viewer & editor**, który umożliwia:

* Przeglądanie drzewa katalogu przez GUI
* Edycję atrybutów obiektów i deskryptorów bezpieczeństwa
* Tworzenie/porównywanie snapshotów do analizy offline

### Quick usage

1. Uruchom narzędzie i połącz się z `dc01.corp.local` używając dowolnych poświadczeń domenowych.
2. Utwórz offline snapshot przez `File ➜ Create Snapshot`.
3. Porównaj dwa snapshoty za pomocą `File ➜ Compare`, aby wykryć zmiany uprawnień.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) wyodrębnia duży zestaw artefaktów z domeny (ACLs, GPOs, trusts, CA templates …) i generuje **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (wizualizacja grafu)

[BloodHound](https://github.com/SpecterOps/BloodHound) uses graph theory to reveal hidden privilege relationships inside on-prem AD, Entra ID, and any extra attack-surface data you ingest through OpenGraph.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – natywny lub wariant PowerShell
* `RustHound-CE` – wieloplatformowy collector CE dla Linux, macOS i Windows
* `NetExec --bloodhound` – szybkie collection oparte na LDAP z Linux
* `AzureHound` – enumeracja Entra ID
* **SoaPy + BOFHound** – collection ADWS (zobacz link na górze)

> BloodHound CE `v8+` zmienił format output collectorów, gdy pojawił się OpenGraph. Po upgrade z legacy BloodHound lub starszych instalacji CE, uruchom discovery ponownie z aktualnymi collectorami przed importem danych.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Collectory generują JSON, który jest wczytywany przez GUI BloodHound.

#### SharpHound z hosta Windows niebędącego w domenie

Jeśli Twoja VM operatora nie jest dołączona do docelowej domeny, ustaw DNS na DC, uruchom powłokę **network-only**, sprawdź, czy widzisz `SYSVOL`/`NETLOGON` na DC, a następnie zbierz dane zdalnie z domeny:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
To jest przydatne dla jednorazowych jump boxów lub stacji roboczych operatora, które nie powinny być dołączone do domeny.

#### Cross-platform collection from Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` jest dobrym wyborem domyślnym, gdy chcesz uzyskać wyjście zgodne z CE z hosta spoza Windows. `NetExec` jest wygodny, gdy już używasz go do walidacji LDAP lub spraying i chcesz szybko zaimportować graph. Dla zbiorów danych spoza AD, BloodHound OpenGraph można rozszerzyć o collectory takie jak [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### Zbieranie privilege & logon-right

Windows **token privileges** (np. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) mogą omijać sprawdzenia DACL, więc mapowanie ich w całej domenie ujawnia lokalne edges LPE, których graphy oparte wyłącznie na ACL pomijają. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` oraz ich odpowiedniki `SeDeny*`) są egzekwowane przez LSA zanim token w ogóle istnieje, a deny mają pierwszeństwo, więc realnie ograniczają lateral movement (RDP/SMB/scheduled task/service logon).

**Uruchamiaj collectory z podniesionymi uprawnieniami**, gdy to możliwe: UAC tworzy przefiltrowany token dla interaktywnych adminów (przez `NtFilterToken`), usuwając wrażliwe privileges i oznaczając SID-y adminów jako deny-only. Jeśli enumerujesz privileges z niepodniesionej powłoki, wartościowe privileges będą niewidoczne i BloodHound nie zaimportuje tych edges.

Istnieją teraz dwie uzupełniające się strategie zbierania SharpHound:

- **Analiza GPO/SYSVOL (stealthy, niskie uprawnienia):**
1. Wylicz GPO przez LDAP (`(objectCategory=groupPolicyContainer)`) i odczytaj każde `gPCFileSysPath`.
2. Pobierz `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` z SYSVOL i przeanalizuj sekcję `[Privilege Rights]`, która mapuje nazwy privilege/logon-right na SID-y.
3. Rozwiąż linki GPO przez `gPLink` na OU/site/domainach, wypisz komputery w powiązanych kontenerach i przypisz rights do tych maszyn.
4. Plus: działa z normalnym userem i jest cicha; minus: widzi tylko rights nadane przez GPO (lokalne zmiany są pomijane).

- **Enumeracja LSA RPC (głośna, dokładna):**
- Z kontekstu z local admin na celu otwórz Local Security Policy i wywołaj `LsaEnumerateAccountsWithUserRight` dla każdego privilege/logon right, aby wyliczyć przypisane principals przez RPC.
- Plus: obejmuje rights ustawione lokalnie lub poza GPO; minus: głośny ruch sieciowy i wymagany admin na każdym hoście.

**Przykładowa ścieżka abuse ujawniona przez te edges:** `CanRDP` ➜ host, na którym twój user ma też `SeBackupPrivilege` ➜ uruchom elevated shell, aby uniknąć filtered tokens ➜ użyj backup semantics do odczytu hive’ów `SAM` i `SYSTEM` mimo restrykcyjnych DACLs ➜ exfiltrate i uruchom `secretsdump.py` offline, aby odzyskać local Administrator NT hash do lateral movement/privilege escalation.

### Nadawanie priorytetu Kerberoasting z BloodHound

Używaj graph context, aby roasting był targetowany:

1. Zbierz dane raz za pomocą collectora zgodnego z ADWS i pracuj offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Zaimportuj ZIP, oznacz skompromitowany principal jako owned i uruchom wbudowane zapytania (*Kerberoastable Users*, *Shortest Paths to Domain Admins*), aby wyodrębnić konta SPN z uprawnieniami admin/infra.
3. Uszereguj SPN-y według blast radius; przejrzyj `pwdLastSet`, `lastLogon` oraz dozwolone encryption types przed cracking.
4. Zażądaj tylko wybranych ticketów, crack offline, a następnie ponownie odpytaj BloodHound z nowym access:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumeruje **Group Policy Objects** i wskazuje misconfigurations.
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
## References

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
