# BloodHound e altri strumenti di enumerazione di Active Directory

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Questa pagina raggruppa alcune delle utility più utili per **enumerare** e **visualizzare** le relazioni di Active Directory. Per la raccolta tramite il canale stealthy **Active Directory Web Services (ADWS)**, consulta il riferimento sopra.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) è un avanzato **visualizzatore ed editor di AD** che consente di:

* Navigare nell'albero della directory tramite GUI
* Modificare gli attributi degli oggetti e i descrittori di sicurezza
* Creare e confrontare snapshot per l'analisi offline

### Utilizzo rapido

1. Avvia lo strumento e connettiti a `dc01.corp.local` con credenziali di dominio qualsiasi.
2. Crea uno snapshot offline tramite `File ➜ Create Snapshot`.
3. Confronta due snapshot con `File ➜ Compare` per individuare variazioni nelle autorizzazioni.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) estrae un ampio insieme di artefatti da un dominio (ACL, GPO, trust, template delle CA …) e produce un **report Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualizzazione dei grafi)

[BloodHound](https://github.com/SpecterOps/BloodHound) usa la teoria dei grafi per rivelare relazioni di privilegi nascoste all'interno di AD on-prem, Entra ID e di qualsiasi dato aggiuntivo sulla superficie d'attacco acquisito tramite OpenGraph.<sup>[[1]](#references)</sup>

### Installazione (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collector

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa o PowerShell
* `RustHound-CE` – collector CE cross-platform per Linux, macOS e Windows
* `NetExec --bloodhound` – raccolta rapida basata su LDAP da Linux
* `AzureHound` – enumerazione di Entra ID
* **SoaPy + BOFHound** – raccolta tramite ADWS (vedi il link in alto)

> BloodHound CE `v8+` ha modificato il formato di output del collector con l'introduzione di OpenGraph. Dopo l'aggiornamento da BloodHound legacy o da installazioni CE meno recenti, esegui nuovamente la discovery con i collector attuali prima di importare i dati.<sup>[[1]](#references)</sup>

#### Modalità comuni di SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
I collectors generano JSON, che viene importato tramite la GUI di BloodHound.

#### SharpHound da un host Windows non aggiunto al dominio

Se la VM dell’operatore non è aggiunta al dominio target, configura il DNS in modo che punti a un DC, avvia una shell **network-only**, verifica di poter visualizzare `SYSVOL`/`NETLOGON` su un DC, quindi esegui la raccolta dal dominio remoto:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Questo è utile per jump box usa e getta o workstation degli operatori che non dovrebbero essere aggiunte al dominio.

#### Raccolta cross-platform da Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` è una buona scelta predefinita quando vuoi un output compatibile con CE da un host non-Windows.<sup>[[2]](#references)</sup> `NetExec` è comodo quando lo stai già usando per la validazione LDAP o lo spraying e vuoi una rapida importazione del grafo. Per i dataset non-AD, BloodHound OpenGraph può essere esteso con collector come [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).<sup>[[1]](#references)</sup>

### ADPathFinder (prioritizzazione dei percorsi OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) si basa su BloodHound CE/OpenGraph quando il grafo è troppo grande per eseguire pivot manualmente. Invece di chiedere soltanto se un principal può raggiungere un target, calcola i percorsi più brevi da molti utenti e computer con bassi privilegi verso oggetti di alto valore, raggruppa i percorsi che riutilizzano gli stessi edge e mette in evidenza il choke point condiviso da correggere per primo.<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Con i dati di `MSSQLHound` e `ConfigManBearPig` importati, una singola evidenza può collegare [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) e [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md), anziché lasciarli come lead separati.<sup>[[4]](#references)</sup> Esempio di percorso condiviso:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Traccia il **contesto di sicurezza effettivo** a ogni edge. Un percorso diventa critico per il dominio non appena una transizione viene eseguita come identità di dominio privilegiata, anche se è iniziato da un utente normale.
- I risultati raggruppati sono ideali per la **remediation dei choke point**: rimuovere una permission di SQL impersonation, una trust di linked-server, un percorso di abuso di un certificate template o un'assegnazione SCCM può eliminare contemporaneamente molti shortest path.
- Riassegna la priorità ai finding "medium" con il **contesto del grafo**. SMB signing disabilitato, esposizione di WebClient, errori di delegation o SQL server esposti a NTLM relay meritano una priorità maggiore quando il nodo compromesso ha percorsi successivi verso Domain Admins, Domain Controllers, CA o SCCM site servers.
- Se disponi anche dell'output di `NTDS.dit` e di un potfile di hashcat, `--pwd` mette in correlazione le password crackate con le proprietà di BloodHound, così puoi distinguere rapidamente il normale riutilizzo delle password dalle credenziali crackate di account privilegiati, Kerberoastable, AS-REP roastable o rilevanti per i percorsi.

### Raccolta di privilegi e diritti di logon

I **token privileges** di Windows (ad esempio `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) possono aggirare i controlli DACL; mapparli sull'intero dominio espone quindi gli edge di local LPE che i grafi basati solo sugli ACL non rilevano. I **logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` e le controparti `SeDeny*`) vengono applicati da LSA prima ancora che esista un token, e i deny hanno la precedenza; pertanto limitano concretamente il lateral movement (logon tramite RDP/SMB/scheduled task/service).<sup>[[3]](#references)</sup>

**Esegui i collector con privilegi elevati** quando possibile: UAC crea un token filtrato per gli amministratori interattivi (tramite `NtFilterToken`), rimuovendo i privilegi sensibili e contrassegnando i SID degli amministratori come deny-only. Se enumeri i privilegi da una shell non elevata, i privilegi di alto valore saranno invisibili e BloodHound non importerà gli edge.<sup>[[3]](#references)</sup>

Ora esistono due strategie di raccolta SharpHound complementari:<sup>[[3]](#references)</sup>

- **Parsing di GPO/SYSVOL (stealthy, con privilegi ridotti):**
1. Enumera le GPO tramite LDAP (`(objectCategory=groupPolicyContainer)`) e leggi ogni `gPCFileSysPath`.
2. Recupera `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` da SYSVOL e analizza la sezione `[Privilege Rights]`, che associa i nomi dei privilegi/logon-right ai SID.
3. Risolvi i link delle GPO tramite `gPLink` su OU/site/domain, elenca i computer nei container collegati e assegna tali diritti alle macchine.
4. Vantaggio: funziona con un utente normale ed è silenzioso; svantaggio: rileva solo i diritti applicati tramite GPO (le modifiche locali non vengono rilevate).

- **Enumerazione LSA RPC (rumorosa, accurata):**
- Da un contesto con local admin sul target, apri la Local Security Policy e chiama `LsaEnumerateAccountsWithUserRight` per ogni privilegio/logon right, così da enumerare tramite RPC i principal assegnati.
- Vantaggio: rileva i diritti impostati localmente o al di fuori delle GPO; svantaggio: genera traffico di rete rumoroso e richiede privilegi amministrativi su ogni host.

**Esempio di percorso di abuso evidenziato da questi edge:** `CanRDP` ➜ host sul quale il tuo utente dispone anche di `SeBackupPrivilege` ➜ avvia una shell elevata per evitare i token filtrati ➜ usa la semantica di backup per leggere gli hive `SAM` e `SYSTEM` nonostante le DACL restrittive ➜ esfiltra i dati ed esegui `secretsdump.py` offline per recuperare l'hash NT dell'Administrator locale, utile per il lateral movement o la privilege escalation.<sup>[[3]](#references)</sup>

### Definizione delle priorità per il Kerberoasting con BloodHound

Usa il contesto del grafo per mantenere il roasting mirato:

1. Esegui una raccolta una sola volta con un collector compatibile con ADWS e lavora offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importa lo ZIP, contrassegna il principal compromesso come posseduto ed esegui le query integrate (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) per individuare gli account SPN con diritti di amministrazione o infrastrutturali.
3. Dai priorità agli SPN in base al blast radius; controlla `pwdLastSet`, `lastLogon` e i tipi di crittografia consentiti prima del cracking.
4. Richiedi solo i ticket selezionati, esegui il cracking offline, quindi interroga nuovamente BloodHound con il nuovo accesso:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera i **Group Policy Objects** ed evidenzia le misconfigurazioni.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) esegue un **controllo dello stato** di Active Directory e genera un report HTML con valutazione del rischio.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Riferimenti

- [1] [BloodHound Community Edition v8 viene lanciato con OpenGraph: percorsi di attacco alle identità oltre Active Directory ed Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [Oltre gli ACL: mappatura dei percorsi di privilege escalation in Windows con BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: mappatura dei percorsi di attacco OpenGraph in BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
