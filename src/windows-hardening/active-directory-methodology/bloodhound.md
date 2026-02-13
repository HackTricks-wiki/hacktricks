# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Questa pagina raggruppa alcune delle utilità più utili per **enumerare** e **visualizzare** le relazioni in Active Directory. Per la raccolta tramite il canale furtivo **Active Directory Web Services (ADWS)** controlla il riferimento sopra.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) è un avanzato **AD viewer & editor** che permette:

* Navigazione GUI dell'albero della directory
* Modifica degli attributi degli oggetti e dei descrittori di sicurezza
* Creazione e confronto di snapshot per analisi offline

### Uso rapido

1. Avvia lo strumento e connettiti a `dc01.corp.local` con qualsiasi credenziale di dominio.
2. Crea uno snapshot offline tramite `File ➜ Create Snapshot`.
3. Confronta due snapshot con `File ➜ Compare` per individuare deriva delle autorizzazioni.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) estrae un ampio set di artefatti da un dominio (ACLs, GPOs, trusts, CA templates …) e produce un **report Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualizzazione a grafo)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) utilizza la teoria dei grafi + Neo4j per rivelare relazioni di privilegio nascoste all'interno dell'AD on-prem e di Azure AD.

### Distribuzione (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Raccoglitori

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa o PowerShell
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – raccolta ADWS (vedi link in alto)

#### Modalità comuni di SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
The collectors generate JSON which is ingested via the BloodHound GUI.

### Raccolta di privilegi e diritti di accesso

Windows **token privileges** (es., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) possono bypassare i controlli DACL, quindi mapparle a livello di dominio espone edge di LPE locali che i grafi basati solo su ACL perdono. I **logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` e i loro corrispondenti `SeDeny*`) sono applicati da LSA prima ancora che esista un token, e i deny hanno priorità, quindi regolano materialmente la lateral movement (RDP/SMB/scheduled task/service logon).

**Esegui i collector con privilegi elevati** quando possibile: UAC crea un filtered token per gli admin interattivi (via `NtFilterToken`), rimuovendo privilegi sensibili e marcando gli SID admin come deny-only. Se enumeri i privilegi da una shell non elevata, i privilegi ad alto valore saranno invisibili e BloodHound non importerà gli edge.

Esistono due strategie complementari di raccolta SharpHound:

- **Parsing GPO/SYSVOL (stealthy, low-privilege):**
1. Enumera i GPO via LDAP (`(objectCategory=groupPolicyContainer)`) e leggi ogni `gPCFileSysPath`.
2. Recupera `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` da SYSVOL e analizza la sezione `[Privilege Rights]` che mappa i nomi dei privilegi/diritti di accesso agli SID.
3. Risolvi i link GPO tramite `gPLink` su OU/sites/domains, elenca i computer nei contenitori linkati e attribuisci i diritti a quelle macchine.
4. Vantaggio: funziona con un utente normale ed è silenzioso; svantaggio: vede solo i diritti imposti via GPO (le modifiche locali vengono perse).

- **LSA RPC enumeration (noisy, accurate):**
- Da un contesto con amministrazione locale sul target, apri la Local Security Policy e chiama `LsaEnumerateAccountsWithUserRight` per ogni privilege/logon right per enumerare i principals assegnati via RPC.
- Vantaggio: cattura i diritti impostati localmente o fuori dal GPO; svantaggio: traffico di rete rumoroso e requisito di admin su ogni host.

**Esempio di percorso di abuso evidenziato da questi edge:** `CanRDP` ➜ host dove il tuo utente ha anche `SeBackupPrivilege` ➜ avviare una shell elevata per evitare i filtered token ➜ usare le semantics di backup per leggere i hive `SAM` e `SYSTEM` nonostante DACL restrittive ➜ esfiltrare ed eseguire `secretsdump.py` offline per recuperare l'NT hash dell'Administrator locale per lateral movement/privilege escalation.

### Dare priorità al Kerberoasting con BloodHound

Usa il contesto del grafo per mantenere il roasting mirato:

1. Raccolta una volta con un collector compatibile ADWS e lavora offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importa lo ZIP, marca il principal compromesso come owned, ed esegui le query builtin (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) per evidenziare account SPN con diritti admin/infra.
3. Prioritizza gli SPN per blast radius; verifica `pwdLastSet`, `lastLogon` e i tipi di crittografia consentiti prima di crackare.
4. Richiedi solo i ticket selezionati, crackali offline, quindi re-query BloodHound con il nuovo accesso:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera **Group Policy Objects** e mette in evidenza misconfigurazioni.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) esegue un **health-check** di Active Directory e genera un report HTML con valutazione del rischio.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Riferimenti

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
