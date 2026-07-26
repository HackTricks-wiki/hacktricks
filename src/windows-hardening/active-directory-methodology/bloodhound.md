# BloodHound e altri strumenti di Enumerazione di Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Questa pagina raggruppa alcune delle utility più utili per **enumerare** e **visualizzare** le relazioni di Active Directory. Per la raccolta tramite il canale stealthy **Active Directory Web Services (ADWS)**, consulta il riferimento sopra.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) è un **visualizzatore ed editor di AD** avanzato che consente di:

* Navigare nella struttura ad albero della directory tramite GUI
* Modificare gli attributi degli oggetti e i descrittori di sicurezza
* Creare e confrontare snapshot per l'analisi offline

### Utilizzo rapido

1. Avvia lo strumento e connettiti a `dc01.corp.local` con qualsiasi credenziale di dominio.
2. Crea uno snapshot offline tramite `File ➜ Create Snapshot`.
3. Confronta due snapshot con `File ➜ Compare` per individuare le variazioni nelle autorizzazioni.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) estrae un ampio insieme di artefatti da un dominio (ACL, GPO, trust, template delle CA …) e produce un **report Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualizzazione dei grafi)

[BloodHound](https://github.com/SpecterOps/BloodHound) usa la teoria dei grafi per rivelare relazioni di privilegio nascoste all'interno di AD on-prem, Entra ID e qualsiasi dato aggiuntivo sulla superficie di attacco acquisito tramite OpenGraph.

### Distribuzione (Docker CE)
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

> BloodHound CE `v8+` ha modificato il formato di output del collector con l'introduzione di OpenGraph. Dopo l'aggiornamento da BloodHound legacy o da installazioni CE precedenti, esegui nuovamente la discovery con i collector correnti prima di importare i dati.

#### Modalità comuni di SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
I collector generano JSON che viene acquisito tramite la GUI di BloodHound.

#### SharpHound da un host Windows non aggiunto al dominio

Se la VM dell'operatore non è aggiunta al dominio target, imposta il DNS su un DC, avvia una shell **network-only**, verifica di poter visualizzare `SYSVOL`/`NETLOGON` su un DC, quindi esegui la raccolta sul dominio remoto:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Questo è utile per jump box usa e getta o postazioni di lavoro degli operatori che non dovrebbero essere aggiunte al dominio.

#### Raccolta cross-platform da Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` è una buona scelta predefinita quando vuoi un output compatibile con CE da un host non-Windows. `NetExec` è comodo quando lo stai già utilizzando per la validazione LDAP o lo spraying e vuoi una rapida importazione nel grafo. Per dataset non-AD, BloodHound OpenGraph può essere esteso con collector come [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### ADPathFinder (prioritizzazione dei percorsi OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) si basa su BloodHound CE/OpenGraph quando il grafo è troppo grande per eseguire pivot manualmente. Invece di chiedere soltanto se un principal può raggiungere un target, calcola i percorsi più brevi da molti utenti e computer con privilegi ridotti verso oggetti di alto valore, raggruppa i percorsi che riutilizzano gli stessi edge e mette in evidenza il punto di strozzatura condiviso da sottoporre per primo a remediation.
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Con i dati di `MSSQLHound` e `ConfigManBearPig` importati, una singola scoperta può collegare [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) e [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md), anziché lasciarli come piste separate. Esempio di percorso condiviso:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Tieni traccia del **contesto di sicurezza effettivo** a ogni edge. Un percorso diventa critico per il dominio non appena una transizione viene eseguita come identità di dominio privilegiata, anche se è iniziato da un utente normale.
- I risultati raggruppati sono ideali per la **remediation dei choke point**: rimuovere una permission di impersonation SQL, una trust di linked server, un percorso di abuso dei certificate template o un'assegnazione SCCM può eliminare molti shortest path contemporaneamente.
- Dai una nuova priorità ai risultati "medium" usando il **contesto del grafo**. SMB signing disabilitato, esposizione di WebClient, errori di delegation o SQL server sfruttabili tramite NTLM relay meritano una priorità maggiore quando il nodo compromesso ha percorsi successivi verso Domain Admins, Domain Controllers, CA o site server SCCM.
- Se disponi anche dell'output di `NTDS.dit` e di un hashcat potfile, `--pwd` mette in correlazione le password crackate con le proprietà di BloodHound, così puoi distinguere rapidamente il normale riutilizzo delle password dalle credenziali crackate di account privilegiati, Kerberoastable, AS-REP roastable o rilevanti per un path.

### Raccolta dei privilegi e dei diritti di logon

I **privilegi dei token** Windows (ad esempio `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) possono bypassare i controlli DACL; mapparli sull'intero dominio espone quindi gli edge di local LPE che i grafi basati solo sulle ACL non mostrano. I **diritti di logon** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` e le rispettive controparti `SeDeny*`) vengono applicati da LSA prima ancora che esista un token, e i deny hanno la precedenza; per questo regolano concretamente il lateral movement (logon tramite RDP/SMB/scheduled task/service).

**Esegui i collector con privilegi elevati** quando possibile: UAC crea un token filtrato per gli amministratori interattivi (tramite `NtFilterToken`), rimuovendo i privilegi sensibili e contrassegnando i SID degli amministratori come deny-only. Se enumeri i privilegi da una shell non elevata, quelli di maggior valore saranno invisibili e BloodHound non acquisirà gli edge.

Ora esistono due strategie complementari di collection con SharpHound:

- **Parsing GPO/SYSVOL (stealthy, con privilegi ridotti):**
1. Enumera le GPO tramite LDAP (`(objectCategory=groupPolicyContainer)`) e leggi il valore `gPCFileSysPath` di ciascuna.
2. Recupera `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` da SYSVOL e analizza la sezione `[Privilege Rights]`, che associa i nomi dei privilegi/diritti di logon ai SID.
3. Risolvi i link delle GPO tramite `gPLink` su OU/siti/domini, elenca i computer nei container collegati e attribuisci i diritti a quelle macchine.
4. Vantaggio: funziona con un utente normale ed è silenzioso; svantaggio: vede solo i diritti distribuiti tramite GPO (le modifiche locali non vengono rilevate).

- **Enumerazione LSA RPC (rumorosa, accurata):**
- Da un contesto con local admin sul target, apri la Local Security Policy e chiama `LsaEnumerateAccountsWithUserRight` per ogni privilegio/diritto di logon, così da enumerare tramite RPC i principal assegnati.
- Vantaggio: acquisisce i diritti impostati localmente o al di fuori delle GPO; svantaggio: genera traffico di rete rumoroso e richiede privilegi admin su ogni host.

**Esempio di abuse path evidenziato da questi edge:** `CanRDP` ➜ host sul quale il tuo utente dispone anche di `SeBackupPrivilege` ➜ avvia una shell elevata per evitare i token filtrati ➜ usa la backup semantics per leggere gli hive `SAM` e `SYSTEM` nonostante le DACL restrittive ➜ esfiltra i dati ed esegui `secretsdump.py` offline per recuperare l'hash NT dell'Administrator locale e procedere con lateral movement/privilege escalation.

### Dare priorità al Kerberoasting con BloodHound

Usa il contesto del grafo per mantenere il roasting mirato:

1. Esegui una sola collection con un collector compatibile con ADWS e lavora offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importa lo ZIP, contrassegna il principal compromesso come owned ed esegui le query integrate (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) per individuare gli account SPN con diritti admin/infra.
3. Dai priorità agli SPN in base al blast radius; esamina `pwdLastSet`, `lastLogon` e i tipi di crittografia consentiti prima del cracking.
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

[PingCastle](https://www.pingcastle.com/documentation/) esegue un **controllo dello stato** di Active Directory e genera un report HTML con un punteggio dei rischi.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Riferimenti

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [ADPathFinder: OpenGraph Attack Path Mapping in BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
