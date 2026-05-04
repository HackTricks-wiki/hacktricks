# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: Questa pagina raggruppa alcune delle utility più utili per **enumerate** e **visualizzare** le relazioni di Active Directory. Per la raccolta tramite il canale stealthy **Active Directory Web Services (ADWS)** consulta il riferimento sopra.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) è un avanzato **AD viewer & editor** che consente:

* navigazione GUI dell'albero della directory
* modifica degli attributi degli oggetti e dei security descriptors
* creazione/confronto di snapshot per analisi offline

### Quick usage

1. Avvia lo strumento e connettiti a `dc01.corp.local` con qualsiasi credenziale di dominio.
2. Crea uno snapshot offline tramite `File ➜ Create Snapshot`.
3. Confronta due snapshot con `File ➜ Compare` per individuare permission drifts.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) estrae un ampio set di artefatti da un domain (ACLs, GPOs, trusts, CA templates …) e produce un **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualizzazione grafica)

[BloodHound](https://github.com/SpecterOps/BloodHound) usa la teoria dei grafi per rivelare relazioni di privilegio nascoste all'interno di AD on-prem, Entra ID e qualsiasi dato aggiuntivo sulla attack-surface che importi tramite OpenGraph.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa o PowerShell
* `RustHound-CE` – collector cross-platform CE per Linux, macOS e Windows
* `NetExec --bloodhound` – raccolta rapida guidata da LDAP da Linux
* `AzureHound` – enumerazione Entra ID
* **SoaPy + BOFHound** – raccolta ADWS (vedi link in alto)

> BloodHound CE `v8+` ha cambiato il formato di output del collector quando è arrivato OpenGraph. Dopo l'upgrade da BloodHound legacy o da installazioni CE più vecchie, riesegui la discovery con i collector attuali prima di importare i dati.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
I collector generano JSON che viene ingerito tramite la GUI di BloodHound.

#### SharpHound da un host Windows non joinato al dominio

Se la tua VM operativa non è joinata al dominio di destinazione, punta il DNS a un DC, avvia una shell **network-only**, verifica di poter vedere `SYSVOL`/`NETLOGON` su un DC, e poi esegui la raccolta contro il dominio remoto:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Questo è utile per jump box usa e getta o workstation dell’operatore che non dovrebbero essere domain-joined.

#### Raccolta cross-platform da Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` è una buona scelta predefinita quando vuoi output compatibile con CE da un host non-Windows. `NetExec` è comodo quando lo stai già usando per la validazione LDAP o lo spraying e vuoi una rapida importazione del grafo. Per dataset non-AD, BloodHound OpenGraph può essere esteso con collector come [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### Raccolta di privilege e logon-right

I **token privileges** di Windows (ad es. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) possono bypassare i controlli DACL, quindi mapparli a livello di dominio espone edge di LPE locali che i grafi basati solo su ACL perdono. I **logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` e i rispettivi `SeDeny*`) vengono applicati da LSA prima che esista persino un token, e i deny hanno precedenza, quindi influenzano in modo diretto il lateral movement (RDP/SMB/scheduled task/service logon).

**Esegui i collector elevati** quando possibile: UAC crea un token filtrato per gli admin interattivi (tramite `NtFilterToken`), rimuovendo i privilege sensibili e marcando i SID admin come deny-only. Se fai l’enumerazione dei privilege da una shell non elevata, i privilege ad alto valore non saranno visibili e BloodHound non importerà gli edge.

Ora esistono due strategie complementari di raccolta SharpHound:

- **Parsing GPO/SYSVOL (stealthy, low-privilege):**
1. Enumera i GPO via LDAP (`(objectCategory=groupPolicyContainer)`) e leggi ogni `gPCFileSysPath`.
2. Recupera `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` da SYSVOL e analizza la sezione `[Privilege Rights]` che mappa i nomi di privilege/logon-right ai SID.
3. Risolvi i link GPO tramite `gPLink` su OU/site/domain, elenca i computer nei container collegati e attribuisci i right a quelle macchine.
4. Vantaggio: funziona con un utente normale ed è silenzioso; svantaggio: vede solo i right distribuiti via GPO (le modifiche locali vengono perse).

- **Enumerazione LSA RPC (noisy, accurate):**
- Da un contesto con local admin sul target, apri Local Security Policy e chiama `LsaEnumerateAccountsWithUserRight` per ogni privilege/logon right per enumerare i principal assegnati via RPC.
- Vantaggio: cattura i right impostati localmente o fuori da GPO; svantaggio: traffico di rete rumoroso e richiesta di admin su ogni host.

**Esempio di abuso mostrato da questi edge:** `CanRDP` ➜ host dove il tuo utente ha anche `SeBackupPrivilege` ➜ avvia una shell elevata per evitare i token filtrati ➜ usa le backup semantics per leggere gli hive `SAM` e `SYSTEM` nonostante DACL restrittive ➜ esfiltra e lancia `secretsdump.py` offline per recuperare l’NT hash dell’Administrator locale per lateral movement/privilege escalation.

### Dare priorità al Kerberoasting con BloodHound

Usa il contesto del grafo per mantenere mirato il roasting:

1. Raccogli una volta con un collector compatibile con ADWS e lavora offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importa lo ZIP, marca il principal compromesso come owned e lancia le query integrate (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) per evidenziare gli account SPN con rights admin/infra.
3. Prioritizza gli SPN in base al blast radius; rivedi `pwdLastSet`, `lastLogon` e i tipi di encryption consentiti prima di fare cracking.
4. Richiedi solo i ticket selezionati, fai cracking offline, poi riesegui la query su BloodHound con il nuovo accesso:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera gli **Group Policy Objects** e evidenzia le misconfigurazioni.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) esegue un **health-check** di Active Directory e genera un report HTML con un risk scoring.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Riferimenti

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
