# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> UWAGA: Ta strona grupuje niektóre z najbardziej przydatnych narzędzi do **enumerate** i **visualise** relacji Active Directory. Dla zbierania przez stealthy **Active Directory Web Services (ADWS)** channel sprawdź powyższy odnośnik.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) to zaawansowany **AD viewer & editor**, który pozwala na:

* Przeglądanie drzewa katalogu przez GUI
* Edycję atrybutów obiektów i deskryptorów zabezpieczeń
* Tworzenie snapshotów / porównywanie do analizy offline

### Quick usage

1. Uruchom narzędzie i połącz się z `dc01.corp.local` przy użyciu dowolnych poświadczeń domenowych.
2. Utwórz snapshot offline przez `File ➜ Create Snapshot`.
3. Porównaj dwa snapshoty za pomocą `File ➜ Compare`, aby wykryć permission drifts.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) wyciąga dużą liczbę artefaktów z domeny (ACLs, GPOs, trusts, CA templates …) i generuje raport w **Excelu**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (wizualizacja grafu)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) używa teorii grafów + Neo4j, aby ujawnić ukryte relacje uprawnień w on-prem AD i Azure AD.

### Wdrożenie (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Kolektory

* `SharpHound.exe` / `Invoke-BloodHound` – wariant natywny lub PowerShell
* `AzureHound` – enumeracja Azure AD
* **SoaPy + BOFHound** – kolekcja ADWS (zobacz link powyżej)

#### Typowe tryby SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Kolektory generują JSON, który jest importowany przez BloodHound GUI.

### Zbieranie uprawnień i praw logowania

Windows **token privileges** (np. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) mogą omijać kontrole DACL, więc ich mapowanie w całej domenie ujawnia lokalne krawędzie LPE, które grafy oparte wyłącznie na ACL mogą przeoczyć. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` oraz ich odpowiedniki `SeDeny*`) są egzekwowane przez LSA zanim token w ogóle powstanie, a deny mają pierwszeństwo, więc w praktyce ograniczają lateral movement (RDP/SMB/zadanie zaplanowane/logowanie usługi).

Uruchamiaj kolektory z uprawnieniami, gdy to możliwe: UAC tworzy przefiltrowany token dla interaktywnych adminów (przez `NtFilterToken`), usuwając wrażliwe przywileje i oznaczając SIDy administratorów jako deny-only. Jeśli enumerujesz uprawnienia z niewywyższonej powłoki, wartościowe przywileje będą niewidoczne i BloodHound nie zaimportuje tych krawędzi.

Są teraz dwie komplementarne strategie kolekcji SharpHound:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Wyenumeruj GPO przez LDAP (`(objectCategory=groupPolicyContainer)`) i odczytaj każde `gPCFileSysPath`.
2. Pobierz `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` z SYSVOL i parsuj sekcję `[Privilege Rights]`, która mapuje nazwy przywilejów/praw logowania na SIDy.
3. Rozwiąż linki GPO przez `gPLink` na OU/sites/domenach, wypisz komputery w powiązanych kontenerach i przypisz prawa do tych maszyn.
4. Zaleta: działa z normalnym użytkownikiem i jest ciche; wada: widzi tylko prawa nadane przez GPO (lokalne modyfikacje są pominięte).

- **LSA RPC enumeration (noisy, accurate):**
- Z kontekstu z lokalnym adminem na celu, otwórz Local Security Policy i wywołaj `LsaEnumerateAccountsWithUserRight` dla każdego przywileju/prawa logowania, aby wyenumerować przypisane podmioty przez RPC.
- Zaleta: uchwyci prawa ustawione lokalnie lub poza GPO; wada: głośny ruch sieciowy i wymóg admina na każdym hoście.

**Przykładowa ścieżka nadużycia ujawniona przez te krawędzie:** `CanRDP` ➜ host, na którym twój użytkownik ma także `SeBackupPrivilege` ➜ uruchom podwyższoną powłokę, aby uniknąć przefiltrowanych tokenów ➜ użyj semantyki backupu, aby odczytać hives `SAM` i `SYSTEM` pomimo restrykcyjnych DACLs ➜ wyeksfiltruj i uruchom `secretsdump.py` offline, aby odzyskać NT hash lokalnego Administratora dla lateral movement/privilege escalation.

### Priorytetyzacja Kerberoastingu przy użyciu BloodHound

Wykorzystaj kontekst grafu, aby utrzymać Kerberoasting ukierunkowany:

1. Zbierz raz przy pomocy kolektora kompatybilnego z ADWS i pracuj offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Zaimportuj ZIP, oznacz skompromitowany principal jako owned i uruchom wbudowane zapytania (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) aby ujawnić konta SPN z uprawnieniami admin/infra.
3. Priorytetyzuj SPNy według blast radius; sprawdź `pwdLastSet`, `lastLogon` i dozwolone typy szyfrowania przed łamaniem.
4. Żądaj tylko wybranych ticketów, crackuj offline, a następnie ponownie zapytaj BloodHound z nowym dostępem:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumeruje **Group Policy Objects** i wyróżnia nieprawidłowe konfiguracje.
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
## Źródła

- [HackTheBox Mirage: Łączenie NFS Leaks, nadużycie Dynamic DNS, kradzież poświadczeń NATS, sekrety JetStream i Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapowanie ścieżek Privilege Escalation w Windows za pomocą BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
