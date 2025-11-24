# BloodHound & Altri strumenti di enumerazione di Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Questa pagina raggruppa alcune delle utilità più utili per **enumerare** e **visualizzare** le relazioni di Active Directory. Per la raccolta tramite il canale stealthy **Active Directory Web Services (ADWS)** controlla il riferimento sopra.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) è un avanzato **AD viewer & editor** che permette:

* Navigazione GUI dell'albero della directory
* Modifica degli attributi degli oggetti e dei descrittori di sicurezza
* Creazione / confronto di snapshot per analisi offline

### Uso rapido

1. Avvia lo strumento e connettiti a `dc01.corp.local` con qualsiasi credenziale di dominio.
2. Crea uno snapshot offline tramite `File ➜ Create Snapshot`.
3. Confronta due snapshot con `File ➜ Compare` per individuare variazioni nelle autorizzazioni.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) estrae un ampio insieme di artefatti da un dominio (ACLs, GPOs, trusts, CA templates …) e produce un **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualizzazione del grafo)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) usa la teoria dei grafi + Neo4j per rivelare relazioni di privilegi nascoste all'interno di AD on-prem e Azure AD.

### Distribuzione (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Raccoglitori

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa o variante PowerShell
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – raccolta ADWS (see link at top)

#### Modalità comuni di SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
I collectors generate JSON which is ingested via the BloodHound GUI.

---

## Prioritizzare il Kerberoasting con BloodHound

Il contesto del grafo è fondamentale per evitare Kerberoasting rumoroso e indiscriminato. Un flusso di lavoro leggero:

1. **Raccogli tutto una volta** usando un collector compatibile con ADWS (e.g. RustHound-CE) così puoi lavorare offline e provare i percorsi senza toccare di nuovo il DC:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Import the ZIP, mark the compromised principal as owned**, poi esegui query integrate come *Kerberoastable Users* e *Shortest Paths to Domain Admins*. Questo mette subito in evidenza gli account con SPN che hanno appartenenze a gruppi utili (Exchange, IT, account di servizio tier0, ecc.).
3. **Prioritise by blast radius** – concentrati sugli SPN che controllano infrastrutture condivise o hanno diritti di amministrazione, e verifica `pwdLastSet`, `lastLogon` e i tipi di crittografia consentiti prima di spendere cicli di cracking.
4. **Request only the tickets you care about**. Strumenti come NetExec possono mirare `sAMAccountName`s selezionati in modo che ogni richiesta LDAP ROAST abbia una giustificazione chiara:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, quindi esegui immediatamente una nuova query su BloodHound per pianificare il post-exploitation con i nuovi privilegi.

Questo approccio mantiene alto il rapporto segnale/rumore, riduce il volume rilevabile (nessuna richiesta SPN di massa), e garantisce che ogni cracked ticket si traduca in passaggi significativi per l'escalation dei privilegi.

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumera **Group Policy Objects** e evidenzia le misconfigurazioni.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) esegue un **controllo di integrità** di Active Directory e genera un report HTML con una valutazione del rischio.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Riferimenti

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
