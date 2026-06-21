# Mythic

{{#include ../banners/hacktricks-training.md}}

## Cos’è Mythic?

Mythic è un framework open-source, modulare e collaborativo di command and control (C2) progettato per il red teaming. Consente agli operatori di gestire e distribuire agent (payload) su diversi sistemi operativi, inclusi Windows, Linux e macOS. Mythic offre un’interfaccia browser per il tasking multi-operatore, la gestione dei file, la gestione di SOCKS/rpfwd e la generazione di payload.

A differenza dei framework monolitici, il repository di Mythic di per sé **non** include tipi di payload o profili C2. Gli agent, i wrapper e i profili C2 sono in genere installati come componenti esterni e possono essere aggiornati indipendentemente dal core di Mythic.

### Installazione

Per installare Mythic, segui le istruzioni nel **[Mythic repo](https://github.com/its-a-feature/Mythic)** ufficiale. Un bootstrap comune dalla directory di Mythic è:
```bash
sudo make
sudo ./mythic-cli start
```
Se Mythic è già in esecuzione, normalmente puoi aggiungere un nuovo agent o profile con `./mythic-cli install github ...` e poi riavviare Mythic oppure avviare direttamente il nuovo componente.

### Agents

Mythic supporta più agent, che sono i **payload che eseguono task sui sistemi compromessi**. Ogni agent può essere adattato a esigenze specifiche e può essere eseguito su diversi sistemi operativi.

Per impostazione predefinita Mythic non ha alcun agent installato. Gli agent open-source della community si trovano in [**https://github.com/MythicAgents**](https://github.com/MythicAgents), e la [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) è utile per controllare rapidamente i sistemi operativi supportati, i formati dei payload, i wrapper e i profile C2.

Per installare un agent da quell'org puoi eseguire:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
La forma `sudo -E` è utile quando stai installando da un ambiente non-root. Puoi aggiungere nuovi agenti con il comando precedente anche se Mythic è già in esecuzione.

### C2 Profiles

I C2 profiles in Mythic definiscono **come gli agenti comunicano con il server Mythic**. Specificano il protocollo di comunicazione, i metodi di encryption e altre impostazioni. Puoi creare e gestire i C2 profiles tramite l'interfaccia web di Mythic.

Per impostazione predefinita Mythic viene installato senza profiles; tuttavia, è possibile scaricare alcuni profiles dal repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) in esecuzione:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Profili attuali rilevanti per l'operator da tenere a mente:

- [`http`](https://github.com/MythicC2Profiles/http): traffico GET/POST asincrono di base.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): traffico HTTP più flessibile con più callback domains, rotazione fail-over/round-robin, header/query parameters personalizzati e trasformazioni dei messaggi (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) inserite in cookies, header, query parameters o body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): shaping dei messaggi HTTP guidato da JSON/TOML quando il profilo statico `http` è troppo riconoscibile.

### Note attuali sulla piattaforma

- Molti agent e profile pubblici ora si installano con immagini remote dei container precompilate.
Se fai fork di un componente o lo patchi localmente e Mythic continua a usare il vecchio
comportamento, ispeziona le voci `.env` generate per `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` e `*_USE_VOLUME`; abilitare
`*_USE_BUILD_CONTEXT="true"` è di solito ciò che fa sì che Mythic ricompili dal tuo
Docker context locale invece di riusare silenziosamente l'immagine remota.
- Gli script del browser sono una delle funzionalità di quality-of-life più preziose di Mythic
per gli operator: possono trasformare l'output grezzo dei comandi in tabelle, viewer di screenshot,
link di download e pulsanti che inviano tasking successivi direttamente
dalla UI. Questo è particolarmente utile per workflow ripetitivi di `ls`, `ps`, triage
e file-browser.
- Le build più recenti di Mythic supportano anche interactive tasking e pattern Push C2
che riducono la necessità di polling `sleep 0` durante operazioni pesanti di PTY/SOCKS/rpfwd. Quando un agent/profile lo supporta, questo è di solito meno costoso
che martellare il server con check-in costanti solo per mantenere utilizzabile
un canale interattivo.

### Wrapper payloads

I wrapper payloads ti permettono di mantenere la stessa logica dell'agent cambiando però la rappresentazione su disco che viene consegnata o persistita.

- `service_wrapper`: trasforma un altro payload in un eseguibile Windows service, utile quando il percorso di esecuzione richiede un binary di servizio valido.
- `scarecrow_wrapper`: wrappa shellcode compatibile con il loader ScareCrow per generare output basati su loader come EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo è un agent Windows scritto in C# usando .NET Framework 4.0, progettato per essere usato nelle offerte di training di SpecterOps.

Installarlo con:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo può attualmente emettere payload `WinExe`, `Shellcode`, `Service` e `Source`.
- I profili Apollo comunemente usati sono `http`, `httpx`, `smb`, `tcp` e `websocket`.
- `httpx` è di solito l'opzione più flessibile quando servono domain rotation, supporto proxy, posizionamento personalizzato dei messaggi e message transforms invece del vecchio profilo `http` statico.
- Apollo supporta wrapper payloads come `service_wrapper` e `scarecrow_wrapper`.
- `register_file` e `register_assembly` sono le primitive di staging per `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` e `powerpick`. Nelle build attuali di Apollo, questi artifact staged vengono memorizzati nella cache lato client come blob AES256 protetti da DPAPI.
- I risultati di `ls` e `ps` si integrano particolarmente bene con gli script del browser di Mythic e con il browser di file/processi, il che rende il triage dell'operatore sensibilmente più rapido nelle operazioni collaborative.
- I job fork-and-run di Apollo ereditano le impostazioni del processo sacrificabile da
`spawnto_x86` / `spawnto_x64`, ereditano la selezione del parent da `ppid`, e
poi usano la primitive di injection attualmente selezionata. In pratica, questo significa
che il tuning OPSEC per un comando spesso influisce su `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` e `spawn` allo
stesso tempo.
- I backend di injection di Apollo attualmente documentati includono `CreateRemoteThread`,
`QueueUserAPC` (stile early-bird) e `NtCreateThreadEx` tramite syscalls. Usa
`get_injection_techniques` prima di post-exploitation rumorose e
`set_injection_technique` se devi passare da una primitive che
si scontra con il target o con il comando che vuoi eseguire.
- `blockdlls` influisce solo sui processi sacrificabili creati per i job di post-exploitation.
Combinato con un target `spawnto_x64` meno sospetto del default
`rundll32.exe` nudo, questo è uno dei cambiamenti lato Apollo più facili da fare
prima di eseguire tasking pesanti in assembly/PowerShell.

This agent has a lot of commands that makes it very similar to Cobalt Strike's Beacon with some extras. Among them, it supports:

### Common actions

- `cat`: Stampa il contenuto di un file
- `cd`: Cambia la directory di lavoro corrente
- `cp`: Copia un file da una posizione a un'altra
- `ls`: Elenca file e directory nella directory corrente o nel path specificato
- `ifconfig`: Ottieni gli adapter e le interfacce di rete
- `netstat`: Ottieni informazioni sulle connessioni TCP e UDP
- `pwd`: Stampa la directory di lavoro corrente
- `ps`: Elenca i processi in esecuzione sul sistema target (con info aggiuntive)
- `jobs`: Elenca tutti i job in esecuzione associati a tasking di lunga durata
- `download`: Scarica un file dal sistema target alla macchina locale
- `upload`: Carica un file dalla macchina locale al sistema target
- `reg_query`: Interroga chiavi e valori del registro sul sistema target
- `reg_write_value`: Scrive un nuovo valore in una chiave di registro specificata
- `sleep`: Cambia l'intervallo di sleep dell'agent, che determina quanto spesso effettua il check-in con il server Mythic
- E molti altri, usa `help` per vedere l'elenco completo dei comandi disponibili.

### Privilege escalation

- `getprivs`: Abilita il maggior numero possibile di privilegi sul token del thread corrente
- `getsystem`: Apre un handle a winlogon e duplica il token, elevando di fatto i privilegi a livello SYSTEM
- `make_token`: Crea una nuova sessione di logon e la applica all'agent, consentendo l'impersonation di un altro utente
- `steal_token`: Ruba un token primario da un altro processo, consentendo all'agent di impersonare l'utente di quel processo
- `pth`: Attacco Pass-the-Hash, che consente all'agent di autenticarsi come un utente usando il suo hash NTLM senza bisogno della password in chiaro
- `mimikatz`: Esegue comandi Mimikatz per estrarre credenziali, hash e altre informazioni sensibili dalla memoria o dal database SAM
- `rev2self`: Riporta il token dell'agent al suo token primario, rimuovendo di fatto i privilegi fino al livello originale
- `ppid`: Cambia il processo padre per i job di post-exploitation specificando un nuovo parent process ID, consentendo un controllo migliore sul contesto di esecuzione del job
- `printspoofer`: Esegue comandi PrintSpoofer per aggirare le misure di sicurezza dello spooler di stampa, consentendo privilege escalation o code execution
- `dcsync`: Sincronizza le Kerberos keys di un utente sulla macchina locale, consentendo offline password cracking o ulteriori attacchi
- `ticket_cache_add`: Aggiunge un ticket Kerberos alla sessione di logon corrente o a una specificata, consentendo il riutilizzo del ticket o l'impersonation

### Process execution

- `assembly_inject`: Consente di injectare un loader di assembly .NET in un processo remoto
- `blockdlls`: Blocca il caricamento di DLL firmate non Microsoft nei job di post-exploitation
- `execute_assembly`: Esegue un assembly .NET nel contesto dell'agent
- `execute_coff`: Esegue un file COFF in memoria, consentendo l'esecuzione in-memory di codice compilato
- `execute_pe`: Esegue un eseguibile unmanaged (PE)
- `keylog_inject`: Injecta un keylogger in un altro processo e trasmette i tasti premuti nella vista keylog di Mythic
- `screenshot` / `screenshot_inject`: Cattura direttamente il desktop corrente oppure
injectando un assembly di screenshot in un processo/sessione target
- `get_injection_techniques`: Mostra le tecniche di injection disponibili e quella attualmente selezionata
- `inline_assembly`: Esegue un assembly .NET in un AppDomain usa e getta, consentendo l'esecuzione temporanea di codice senza influenzare il processo principale dell'agent
- `register_assembly`: Registra un assembly .NET per esecuzione successiva
- `register_file`: Registra un file nella cache dell'agent per successivi tasking `execute_*` o PowerShell
- `run`: Esegue un binario sul sistema target, usando il PATH di sistema per trovare l'eseguibile
- `set_injection_technique`: Cambia la primitive di injection usata dai job di post-exploitation
- `shinject`: Injecta shellcode in un processo remoto, consentendo l'esecuzione in-memory di codice arbitrario
- `inject`: Injecta shellcode dell'agent in un processo remoto, consentendo l'esecuzione in-memory del codice dell'agent
- `spawn`: Avvia una nuova sessione dell'agent nell'eseguibile specificato, consentendo l'esecuzione di shellcode in un nuovo processo
- `spawnto_x64` and `spawnto_x86`: Cambia il binario predefinito usato nei job di post-exploitation in un path specificato invece di usare `rundll32.exe` senza parametri, che è molto rumoroso.

### Mythic Forge

Questo consente di **caricare file COFF/BOF** dalla Mythic Forge, che è un repository di payload e strumenti precompilati che possono essere eseguiti sul sistema target. Con tutti i comandi che possono essere caricati sarà possibile eseguire azioni comuni eseguendoli nel processo corrente dell'agent come BOFs (di solito con una OPSEC migliore rispetto all'avvio di un processo separato).

Start installing them with:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, usa `forge_collections` per mostrare i moduli COFF/BOF dal Mythic Forge per poterli selezionare e caricare nella memoria dell'agent per l'esecuzione. Per default, le seguenti 2 collection vengono aggiunte in Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Dopo che un modulo è caricato, apparirà nella lista come un altro command tipo `forge_bof_sa-whoami` o `forge_bof_sa-netuser`.

Per i BOF, ricorda che Forge **non** passa semplicemente una stringa piatta di argomenti
ad Apollo. Mappa i parametri BOF nel formato typed-array di Mythic e poi
li inoltra nel flow `execute_coff` di Apollo. Se un BOF caricato da Forge si comporta
in modo strano, controlla i tipi di argomento BOF attesi / entrypoint invece di guardare solo
la command line che hai digitato.

### PowerShell & scripting execution

- `powershell_import`: Importa un nuovo PowerShell script (.ps1) nella cache dell'agent per un'esecuzione successiva
- `powershell`: Esegue un command PowerShell nel contesto dell'agent, consentendo scripting avanzato e automation
- `powerpick`: Inietta una PowerShell loader assembly in un sacrificial process ed esegue un command PowerShell (senza powershell logging).
- `psinject`: Esegue PowerShell in un processo specificato, consentendo l'esecuzione mirata di script nel contesto di un altro process
- `shell`: Esegue un command shell nel contesto dell'agent, simile all'esecuzione di un command in cmd.exe

### Lateral Movement

- `jump_psexec`: Usa la tecnica PsExec per muoversi lateralmente verso un nuovo host copiando prima l'eseguibile dell'agent Apollo (apollo.exe) ed eseguendolo.
- `jump_wmi`: Usa la tecnica WMI per muoversi lateralmente verso un nuovo host copiando prima l'eseguibile dell'agent Apollo (apollo.exe) ed eseguendolo.
- `link` and `unlink`: Creano e rimuovono link P2P (ad esempio via SMB/TCP) tra callbacks.
- `wmiexecute`: Esegue un command sul sistema locale o remoto specificato usando WMI, con credenziali opzionali per l'impersonation.
- `net_dclist`: Recupera una lista di domain controller per il dominio specificato, utile per identificare potenziali target per il lateral movement.
- `net_localgroup`: Elenca i gruppi locali sul computer specificato, usando localhost come default se non viene specificato alcun computer.
- `net_localgroup_member`: Recupera l'appartenenza a un gruppo locale per un gruppo specificato sul computer locale o remoto, consentendo l'enumeration degli utenti in gruppi specifici.
- `net_shares`: Elenca gli share remoti e la loro accessibilità sul computer specificato, utile per identificare potenziali target per il lateral movement.
- `socks`: Abilita un proxy conforme a SOCKS 5 sulla rete target, consentendo il tunneling del traffico attraverso l'host compromesso. Compatibile con tools come proxychains.
- `rpfwd`: Avvia l'ascolto su una porta specificata sull'host target e inoltra il traffico attraverso Mythic verso un IP e una porta remoti, consentendo l'accesso remoto ai servizi sulla rete target.
- `listpipes`: Elenca tutte le named pipes sul sistema locale, cosa che può essere utile per il lateral movement o la privilege escalation interagendo con meccanismi IPC.

Per i primitive di esecuzione WMI di livello inferiore usate sotto `jump_wmi` o `wmiexecute`, controlla [WmiExec](lateral-movement/wmiexec.md). Per pattern di pivoting più ampi, controlla [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Mostra informazioni dettagliate su command specifici o informazioni generali su tutti i command disponibili nell'agent.
- `clear`: Segna i task come 'cleared' così non possono essere presi dagli agent. Puoi specificare `all` per cancellare tutti i task o `task Num` per cancellare un task specifico.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon è un agent Golang che compila in eseguibili **Linux and macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Note attuali di build/profile

- Le build attuali di Poseidon targettizzano Linux e macOS su entrambi `x86_64` e `arm64`.
- I formati di output supportati includono eseguibili nativi più output in stile shared-library come `dylib` e `so`.
- Poseidon supporta `http`, `websocket`, `tcp`, e `dynamichttp`, e gli attuali builder espongono impostazioni multi-egress come `egress_order` e soglie di failover.
- Opzioni di build-time come `proxy_bypass` e `garble` vale la pena controllarle quando ti serve un comportamento di rete più pulito o ulteriore offuscamento del binario Go.
- `pty` è uno dei nuovi comandi più utili per Linux/macOS in ottica quality-of-life
operazioni perché apre un PTY interattivo e può esporre una porta lato Mythic per un’interazione terminale più completa senza ricorrere al vecchio workaround `sleep 0`
+ SOCKS.
- La documentazione attuale di Poseidon è particolarmente interessante per tradecraft molto orientato a macOS: `jxa` esegue JavaScript for Automation in-memory,
`screencapture` cattura il desktop dell’utente loggato, `clipboard_monitor` trasmette i cambiamenti del pasteboard, `execute_library` carica un dylib locale e chiama una funzione da esso, e `libinject` forza un processo remoto a caricare un dylib su disco.
- Per job di lunga durata, ricorda che Poseidon esegue il post-exploitation work
in goroutine/thread che sono cooperative piuttosto che hard-killable. La
documentazione nota anche esplicitamente che al momento non esiste un agente
integrato per l’offuscamento, quindi il tradecraft a livello di build/profile conta più che con implant commerciali molto offuscati.

Per tradecraft specifico per macOS su operazioni basate su Mythic, abuso di JAMF, o idee MDM-as-C2, consulta [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Quando usato su Linux o macOS ha alcuni comandi interessanti:

### Azioni comuni

- `cat`: Stampa il contenuto di un file
- `cd`: Cambia la directory di lavoro corrente
- `chmod`: Cambia i permessi di un file
- `config`: Visualizza la config corrente e le informazioni dell’host
- `cp`: Copia un file da una posizione a un’altra
- `curl`: Esegue una singola richiesta web con header e metodo opzionali
- `upload`: Carica un file sul target
- `download`: Scarica un file dal sistema target alla macchina locale
- E molti altri

### Cerca informazioni sensibili

- `triagedirectory`: Trova file interessanti all’interno di una directory su un host, come file sensibili o credenziali.
- `getenv`: Ottiene tutte le variabili d’ambiente correnti.

### Tradecraft specifico per macOS

- `jxa`: Esegue JavaScript for Automation in-memory tramite `OSAScript`, il che è
utile per post-exploitation nativa su macOS senza depositare file script separati.
- `clipboard_monitor`: Interroga il pasteboard e riporta i cambiamenti a Mythic,
utile per workflow di furto di credenziali/token che si basano su copia/incolla.
- `screencapture`: Cattura il desktop dell’utente su macOS.
- `execute_library`: Carica un dylib da disco e chiama una specifica funzione esportata.
- `libinject`: Inietta uno stub shellcode che forza un altro processo macOS a caricare un dylib da disco.
- `persist_launchd`: Crea persistenza LaunchAgent / LaunchDaemon direttamente dall’agente.

### Movimento laterale

- `ssh`: SSH verso un host usando le credenziali designate e apre un PTY senza avviare ssh.
- `sshauth`: SSH verso l’host o gli host specificati usando le credenziali designate. Puoi usare questo anche per eseguire un comando specifico sugli host remoti via SSH oppure per usare SCP per copiare file.
- `link_tcp`: Collega un altro agente via TCP, consentendo comunicazione diretta tra agenti.
- `link_webshell`: Collega un agente usando il profilo P2P webshell, consentendo accesso remoto all’interfaccia web dell’agente.
- `rpfwd`: Avvia o interrompe un Reverse Port Forward, consentendo accesso remoto a servizi sulla rete target.
- `socks`: Avvia o interrompe un proxy SOCKS5 sulla rete target, consentendo il tunneling del traffico attraverso l’host compromesso. Compatibile con tool come proxychains.
- `portscan`: Esegue la scansione delle porte aperte sugli host, utile per identificare potenziali target per il movimento laterale o attacchi successivi.

### Esecuzione di processi

- `shell`: Esegue un singolo comando shell tramite /bin/sh, consentendo l’esecuzione diretta di comandi sul sistema target.
- `run`: Esegue un comando da disco con argomenti, consentendo l’esecuzione di binari o script sul sistema target.
- `pty`: Apre un PTY interattivo, consentendo l’interazione diretta con la shell sul sistema target.




## Riferimenti

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
