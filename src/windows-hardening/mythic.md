# Mythic

{{#include ../banners/hacktricks-training.md}}

## Che cos'è Mythic?

Mythic è un framework open-source e modulare di comando e controllo (C2) progettato per il red teaming. Permette ai professionisti della sicurezza di gestire e distribuire vari agenti (payload) su diversi sistemi operativi, tra cui Windows, Linux e macOS. Mythic fornisce un'interfaccia web user-friendly per gestire gli agenti, eseguire comandi e raccogliere risultati, rendendolo uno strumento potente per simulare attacchi del mondo reale in un ambiente controllato.

### Installazione

Per installare Mythic, segui le istruzioni nel **[repo ufficiale di Mythic](https://github.com/its-a-feature/Mythic)**.

### Agenti

Mythic supporta più agenti, che sono i **payload che eseguono compiti sui sistemi compromessi**. Ogni agente può essere personalizzato in base a esigenze specifiche e può funzionare su diversi sistemi operativi.

Per impostazione predefinita, Mythic non ha agenti installati. Tuttavia, offre alcuni agenti open source in [**https://github.com/MythicAgents**](https://github.com/MythicAgents).

Per installare un agente da quel repo, devi semplicemente eseguire:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```
Puoi aggiungere nuovi agenti con il comando precedente anche se Mythic è già in esecuzione.

### Profili C2

I profili C2 in Mythic definiscono **come gli agenti comunicano con il server Mythic**. Specificano il protocollo di comunicazione, i metodi di crittografia e altre impostazioni. Puoi creare e gestire profili C2 tramite l'interfaccia web di Mythic.

Per impostazione predefinita, Mythic è installato senza profili, tuttavia, è possibile scaricare alcuni profili dal repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) eseguendo:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo è un agente Windows scritto in C# utilizzando il .NET Framework 4.0 progettato per essere utilizzato nelle offerte di formazione di SpecterOps.

Installalo con:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Questo agente ha molti comandi che lo rendono molto simile al Beacon di Cobalt Strike con alcune aggiunte. Tra questi, supporta:

### Azioni comuni

- `cat`: Stampa il contenuto di un file
- `cd`: Cambia la directory di lavoro corrente
- `cp`: Copia un file da una posizione a un'altra
- `ls`: Elenca file e directory nella directory corrente o nel percorso specificato
- `pwd`: Stampa la directory di lavoro corrente
- `ps`: Elenca i processi in esecuzione sul sistema target (con informazioni aggiuntive)
- `download`: Scarica un file dal sistema target alla macchina locale
- `upload`: Carica un file dalla macchina locale al sistema target
- `reg_query`: Interroga chiavi e valori del registro sul sistema target
- `reg_write_value`: Scrive un nuovo valore a una chiave di registro specificata
- `sleep`: Cambia l'intervallo di sonno dell'agente, che determina con quale frequenza controlla il server Mythic
- E molti altri, usa `help` per vedere l'elenco completo dei comandi disponibili.

### Escalation dei privilegi

- `getprivs`: Abilita il maggior numero possibile di privilegi sul token del thread corrente
- `getsystem`: Apre un handle a winlogon e duplica il token, aumentando effettivamente i privilegi a livello SYSTEM
- `make_token`: Crea una nuova sessione di accesso e la applica all'agente, consentendo l'impersonificazione di un altro utente
- `steal_token`: Ruba un token primario da un altro processo, consentendo all'agente di impersonare l'utente di quel processo
- `pth`: Attacco Pass-the-Hash, che consente all'agente di autenticarsi come un utente utilizzando il proprio hash NTLM senza bisogno della password in chiaro
- `mimikatz`: Esegue comandi Mimikatz per estrarre credenziali, hash e altre informazioni sensibili dalla memoria o dal database SAM
- `rev2self`: Ripristina il token dell'agente al suo token primario, riducendo effettivamente i privilegi al livello originale
- `ppid`: Cambia il processo padre per i lavori di post-exploitation specificando un nuovo ID processo padre, consentendo un migliore controllo sul contesto di esecuzione del lavoro
- `printspoofer`: Esegue comandi PrintSpoofer per bypassare le misure di sicurezza dello spooler di stampa, consentendo l'escalation dei privilegi o l'esecuzione di codice
- `dcsync`: Sincronizza le chiavi Kerberos di un utente sulla macchina locale, consentendo la decifratura offline delle password o ulteriori attacchi
- `ticket_cache_add`: Aggiunge un biglietto Kerberos alla sessione di accesso corrente o a una specificata, consentendo il riutilizzo del biglietto o l'impersonificazione

### Esecuzione dei processi

- `assembly_inject`: Consente di iniettare un caricatore di assembly .NET in un processo remoto
- `execute_assembly`: Esegue un assembly .NET nel contesto dell'agente
- `execute_coff`: Esegue un file COFF in memoria, consentendo l'esecuzione in memoria di codice compilato
- `execute_pe`: Esegue un eseguibile non gestito (PE)
- `inline_assembly`: Esegue un assembly .NET in un AppDomain usa e getta, consentendo l'esecuzione temporanea di codice senza influenzare il processo principale dell'agente
- `run`: Esegue un binario sul sistema target, utilizzando il PATH del sistema per trovare l'eseguibile
- `shinject`: Inietta shellcode in un processo remoto, consentendo l'esecuzione in memoria di codice arbitrario
- `inject`: Inietta shellcode dell'agente in un processo remoto, consentendo l'esecuzione in memoria del codice dell'agente
- `spawn`: Genera una nuova sessione dell'agente nell'eseguibile specificato, consentendo l'esecuzione di shellcode in un nuovo processo
- `spawnto_x64` e `spawnto_x86`: Cambia il binario predefinito utilizzato nei lavori di post-exploitation a un percorso specificato invece di utilizzare `rundll32.exe` senza parametri, che è molto rumoroso.

### Mithic Forge

Questo consente di **caricare file COFF/BOF** dalla Mythic Forge, che è un repository di payload e strumenti precompilati che possono essere eseguiti sul sistema target. Con tutti i comandi che possono essere caricati sarà possibile eseguire azioni comuni eseguendoli nel processo corrente dell'agente come BOF (più stealth di solito).

Inizia a installarli con:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Poi, usa `forge_collections` per mostrare i moduli COFF/BOF dal Mythic Forge per poterli selezionare e caricare nella memoria dell'agente per l'esecuzione. Per impostazione predefinita, le seguenti 2 collezioni sono aggiunte in Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Dopo che un modulo è stato caricato, apparirà nell'elenco come un altro comando come `forge_bof_sa-whoami` o `forge_bof_sa-netuser`.

### Esecuzione di Powershell e scripting

- `powershell_import`: Importa un nuovo script PowerShell (.ps1) nella cache dell'agente per un'esecuzione successiva
- `powershell`: Esegue un comando PowerShell nel contesto dell'agente, consentendo scripting avanzato e automazione
- `powerpick`: Inietta un'assembly loader PowerShell in un processo sacrificabile ed esegue un comando PowerShell (senza logging di PowerShell).
- `psinject`: Esegue PowerShell in un processo specificato, consentendo l'esecuzione mirata di script nel contesto di un altro processo
- `shell`: Esegue un comando shell nel contesto dell'agente, simile all'esecuzione di un comando in cmd.exe

### Movimento Laterale

- `jump_psexec`: Usa la tecnica PsExec per muoversi lateralmente verso un nuovo host copiando prima l'eseguibile dell'agente Apollo (apollo.exe) ed eseguendolo.
- `jump_wmi`: Usa la tecnica WMI per muoversi lateralmente verso un nuovo host copiando prima l'eseguibile dell'agente Apollo (apollo.exe) ed eseguendolo.
- `wmiexecute`: Esegue un comando sul sistema locale o remoto specificato utilizzando WMI, con credenziali opzionali per impersonificazione.
- `net_dclist`: Recupera un elenco di controller di dominio per il dominio specificato, utile per identificare potenziali obiettivi per il movimento laterale.
- `net_localgroup`: Elenca i gruppi locali sul computer specificato, predefinito a localhost se non viene specificato alcun computer.
- `net_localgroup_member`: Recupera l'appartenenza ai gruppi locali per un gruppo specificato sul computer locale o remoto, consentendo l'enumerazione degli utenti in gruppi specifici.
- `net_shares`: Elenca le condivisioni remote e la loro accessibilità sul computer specificato, utile per identificare potenziali obiettivi per il movimento laterale.
- `socks`: Abilita un proxy compatibile con SOCKS 5 sulla rete target, consentendo il tunneling del traffico attraverso l'host compromesso. Compatibile con strumenti come proxychains.
- `rpfwd`: Inizia ad ascoltare su una porta specificata sull'host target e inoltra il traffico attraverso Mythic a un IP e una porta remoti, consentendo l'accesso remoto ai servizi sulla rete target.
- `listpipes`: Elenca tutte le pipe nominate sul sistema locale, che possono essere utili per il movimento laterale o l'escalation dei privilegi interagendo con i meccanismi IPC.

### Comandi Vari
- `help`: Mostra informazioni dettagliate su comandi specifici o informazioni generali su tutti i comandi disponibili nell'agente.
- `clear`: Segna i compiti come 'cancellati' in modo che non possano essere ripresi dagli agenti. Puoi specificare `all` per cancellare tutti i compiti o `task Num` per cancellare un compito specifico.


## [Poseidon Agent](https://github.com/MythicAgents/Poseidon)

Poseidon è un agente Golang che si compila in eseguibili **Linux e macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/Poseidon.git
```
Quando si utilizza Linux, ci sono alcuni comandi interessanti:

### Azioni comuni

- `cat`: Stampa il contenuto di un file
- `cd`: Cambia la directory di lavoro corrente
- `chmod`: Cambia i permessi di un file
- `config`: Visualizza la configurazione attuale e le informazioni sull'host
- `cp`: Copia un file da una posizione a un'altra
- `curl`: Esegui una singola richiesta web con intestazioni e metodo opzionali
- `upload`: Carica un file sul target
- `download`: Scarica un file dal sistema target alla macchina locale
- E molti altri

### Cerca informazioni sensibili

- `triagedirectory`: Trova file interessanti all'interno di una directory su un host, come file sensibili o credenziali.
- `getenv`: Ottieni tutte le variabili ambientali correnti.

### Muoversi lateralmente

- `ssh`: SSH su host utilizzando le credenziali designate e apri un PTY senza avviare ssh.
- `sshauth`: SSH su host specificati utilizzando le credenziali designate. Puoi anche usarlo per eseguire un comando specifico sui host remoti tramite SSH o usarlo per SCP file.
- `link_tcp`: Collega a un altro agente tramite TCP, consentendo comunicazioni dirette tra agenti.
- `link_webshell`: Collega a un agente utilizzando il profilo P2P webshell, consentendo l'accesso remoto all'interfaccia web dell'agente.
- `rpfwd`: Avvia o ferma un Reverse Port Forward, consentendo l'accesso remoto ai servizi sulla rete target.
- `socks`: Avvia o ferma un proxy SOCKS5 sulla rete target, consentendo il tunneling del traffico attraverso l'host compromesso. Compatibile con strumenti come proxychains.
- `portscan`: Scansiona host per porte aperte, utile per identificare potenziali obiettivi per il movimento laterale o ulteriori attacchi.

### Esecuzione di processi

- `shell`: Esegui un singolo comando shell tramite /bin/sh, consentendo l'esecuzione diretta di comandi sul sistema target.
- `run`: Esegui un comando dal disco con argomenti, consentendo l'esecuzione di binari o script sul sistema target.
- `pty`: Apri un PTY interattivo, consentendo l'interazione diretta con la shell sul sistema target.


{{#include ../banners/hacktricks-training.md}}
