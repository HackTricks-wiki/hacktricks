# Mythic

{{#include ../banners/hacktricks-training.md}}

## Cos'è Mythic?

Mythic è un framework open-source, modulare e collaborativo di command and control (C2) progettato per il red teaming. Consente agli operatori di gestire e distribuire agenti (payload) su diversi sistemi operativi, tra cui Windows, Linux e macOS. Mythic fornisce una UI browser per il tasking multi-operatore, la gestione dei file, la gestione di SOCKS/rpfwd e la generazione dei payload.

A differenza dei framework monolitici, il repository di Mythic non include di per sé tipi di payload o profili C2. Gli agenti, i wrapper e i profili C2 vengono generalmente installati come componenti esterni e possono essere aggiornati indipendentemente dal core di Mythic.

### Installazione

Per installare Mythic, segui le istruzioni nel **[Mythic repo](https://github.com/its-a-feature/Mythic)** ufficiale. Un bootstrap comune dalla directory di Mythic è:
```bash
sudo make
sudo ./mythic-cli start
```
Se Mythic è già in esecuzione, normalmente puoi aggiungere un nuovo agent o profile con `./mythic-cli install github ...` e poi riavviare Mythic oppure avviare direttamente il nuovo componente.

### Agents

Mythic supporta più agents, ovvero i **payloads che eseguono attività sui sistemi compromessi**. Ogni agent può essere personalizzato in base a esigenze specifiche e può funzionare su diversi sistemi operativi.

Per impostazione predefinita, Mythic non ha alcun agent installato. Gli agents open source della community si trovano su [**https://github.com/MythicAgents**](https://github.com/MythicAgents), mentre la [**matrice delle funzionalità della community**](https://mythicmeta.github.io/overview/agent_matrix.html) è utile per verificare rapidamente i sistemi operativi supportati, i formati dei payload, i wrapper e i profili C2.<sup>[[1]](#references)</sup>

Per installare un agent da quell'organizzazione puoi eseguire:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
La forma `sudo -E` es útil cuando se instala desde un entorno non-root. Puedes añadir nuevos agents con el comando anterior incluso si Mythic ya está en ejecución.

### C2 Profiles

Los C2 profiles en Mythic definen **cómo se comunican los agents con el servidor de Mythic**. Especifican el protocolo de comunicación, los métodos de cifrado y otros ajustes. Puedes crear y gestionar C2 profiles mediante la interfaz web de Mythic.

Por defecto, Mythic se instala sin profiles; sin embargo, es posible descargar algunos profiles desde el repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) ejecutando:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Currenti profili rilevanti per gli operatori da tenere presenti:

- [`http`](https://github.com/MythicC2Profiles/http): traffico asincrono GET/POST di base.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): traffico HTTP più flessibile con più domini di callback, rotazione fail-over/round-robin, header e parametri di query personalizzati e trasformazioni dei messaggi (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) inserite in cookie, header, parametri di query o body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): definizione della struttura dei messaggi HTTP basata su JSON/TOML quando il profilo statico `http` è troppo riconoscibile.

### Note attuali sulle piattaforme

- Molti agent e profili pubblici ora vengono installati con immagini remote precompilate dei container.
Se esegui il fork di un componente o applichi una patch localmente e Mythic continua a usare il comportamento precedente, controlla le voci `.env` generate per `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` e `*_USE_VOLUME`; abilitare
`*_USE_BUILD_CONTEXT="true"` è solitamente ciò che fa ricostruire Mythic dal tuo
contesto Docker locale invece di riutilizzare silenziosamente l'immagine remota.
- Gli script del browser sono tra le funzionalità di Mythic con il miglior rapporto valore/praticità
per gli operatori: possono trasformare l'output grezzo dei comandi in tabelle,
visualizzatori di screenshot, link per il download, link di ricerca e pulsanti
che inviano tasking successivi direttamente dall'interfaccia. Le build attuali di Mythic consentono a ogni operatore di mantenere i propri script, di abilitarli o disabilitarli globalmente o per singolo task e offrono i risultati migliori quando gli agent restituiscono JSON strutturato invece di testo semplice. Questo è particolarmente utile per workflow ripetitivi con `ls`, `ps`, triage e file browser.<sup>[[4]](#references)[[6]](#references)</sup>
- Le build più recenti di Mythic supportano anche il tasking interattivo e i pattern Push C2, riducendo la necessità del polling `sleep 0` durante operazioni intensive con PTY/SOCKS/rpfwd. Quando un agent/profilo lo supporta, questo genera solitamente un overhead inferiore rispetto a martellare il server con check-in costanti solo per mantenere utilizzabile un canale interattivo.<sup>[[3]](#references)</sup>
- Gli attuali builder Mythic dell'era 3.4 sono più consapevoli del contesto di quanto lascino intendere i writeup più vecchi: ora i parametri di build possono essere raggruppati o nascosti in base al sistema operativo selezionato o ad altre opzioni di build, i tipi di payload possono dichiarare se supportano più profili C2 o più istanze dello stesso C2 in una singola build e le deviazioni dei parametri C2 consentono a un agent di nascondere i campi che non implementa realmente. Questo è importante quando passi da `http`, `httpx`, `smb`,
`tcp` e `websocket`, perché la superficie di build sicura/valida non è più un modulo statico piatto.<sup>[[5]](#references)</sup>
- Se stai creando una coppia agent/profilo personalizzata e non vuoi che il formato dei messaggi JSON di Mythic o la crittografia predefinita siano trasmessi via wire, usa un
`translation_container`: Mythic rimuove l'UUID, consegna il blob cifrato e il materiale delle chiavi al translator tramite gRPC e si aspetta in risposta i byte nativi dell'agent. Questo è il modo corretto per supportare protocolli binari, framing personalizzato o crittografia lato agent senza riscrivere l'intero server.
- Ricorda che i callback linked/P2P non si limitano a inoltrare il tasking. Il flusso
`get_tasking` può trasportare anche risposte e dati `delegates`, `socks`,
`rpfwd` e `interactive`. In pratica, un callback di egress può gestire callback interni e canali pivot nello stesso ciclo di polling; se gli agent figli eseguono i propri check-in periodici, `get_delegate_tasks=false` impedisce al parent di consumare accidentalmente i job accodati del callback interno.

### Wrapper payloads

I wrapper payloads consentono di mantenere la stessa logica dell'agent modificando al contempo la rappresentazione su disco che viene distribuita o salvata.

- `service_wrapper`: trasforma un altro payload in un eseguibile di servizio Windows, utile quando il percorso di esecuzione richiede un service binary valido.
- `scarecrow_wrapper`: avvolge shellcode compatibile con il loader ScareCrow per generare output basati sul loader, come EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo è un agent Windows scritto in C# usando il framework .NET 4.0, progettato per essere utilizzato nelle offerte formative di SpecterOps.<sup>[[2]](#references)</sup>

Installalo con:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Note sulla build/profilazione corrente

- Apollo può attualmente generare payload `WinExe`, `Shellcode`, `Service` e `Source`.
- I profili Apollo comunemente utilizzati sono `http`, `httpx`, `smb`, `tcp` e `websocket`.
- `httpx` è solitamente l'opzione più flessibile quando servono domain rotation, supporto proxy, posizionamento personalizzato dei messaggi e message transforms, invece del più vecchio profilo statico `http`.
- Apollo è uno degli agent community più completi e attualmente espone integrazioni lato Mythic come browser scripts, viste file/process browser, screenshot, keylogging, SOCKS, rpfwd, Push C2 e P2P routing.
- Apollo supporta wrapper payload come `service_wrapper` e `scarecrow_wrapper`.
- Apollo supporta il caricamento dinamico dei comandi, quindi è possibile mantenere leggero il payload iniziale e caricare in seguito comandi aggiuntivi o moduli Forge, invece di compilare ogni capacità post-exploitation nella prima build.
- Quando genera output shellcode, l'attuale builder di Apollo espone anche le opzioni di formato Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) e il comportamento di bypass di Donut (`None`, `Abort on fail`, `Continue on fail`). Questo è utile se l'obiettivo finale è riavvolgere lo shellcode con `service_wrapper`, `scarecrow_wrapper` o un custom loader.
- `register_file` e `register_assembly` sono le primitive di staging per `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` e `powerpick`. Nelle build Apollo correnti, questi artefatti sottoposti a staging vengono memorizzati nella cache client-side come blob AES256 protetti da DPAPI.
- I risultati di `ls` e `ps` si integrano particolarmente bene con i browser scripts e il file/process browser di Mythic, rendendo il triage dell'operatore sensibilmente più rapido nelle operazioni collaborative.
- I job fork-and-run ereditano le impostazioni del processo sacrificale da
`spawnto_x86` / `spawnto_x64`, ereditano la selezione del parent da `ppid` e
utilizzano quindi la injection primitive attualmente selezionata. In pratica, ciò significa che
il tuning OPSEC per un comando spesso influenza contemporaneamente
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` e `spawn`.
- Gli injection backend Apollo attualmente documentati includono `CreateRemoteThread`,
`QueueUserAPC` (in stile early-bird) e `NtCreateThreadEx` tramite syscalls. Utilizzare
`get_injection_techniques` prima di attività post-exploitation rumorose e
`set_injection_technique` se è necessario sostituire una primitive che
entra in conflitto con il target o con il comando da eseguire.
- `blockdlls` influisce solo sui processi sacrificali creati per i job post-exploitation.
Abbinato a un target `spawnto_x64` meno sospetto del
`rundll32.exe` vuoto predefinito, questo è uno dei cambiamenti più semplici lato Apollo da effettuare
prima di eseguire tasking basati pesantemente su assembly/PowerShell.

Questo agent dispone di numerosi comandi che lo rendono molto simile al Beacon di Cobalt Strike, con alcune funzionalità aggiuntive. Tra questi, supporta:

### Azioni comuni

- `cat`: Stampa il contenuto di un file
- `cd`: Cambia la directory di lavoro corrente
- `cp`: Copia un file da una posizione a un'altra
- `ls`: Elenca file e directory nella directory corrente o nel path specificato
- `ifconfig`: Recupera gli adattatori e le interfacce di rete
- `netstat`: Recupera le informazioni sulle connessioni TCP e UDP
- `pwd`: Stampa la directory di lavoro corrente
- `ps`: Elenca i processi in esecuzione sul sistema target (con informazioni aggiuntive)
- `jobs`: Elenca tutti i job in esecuzione associati a tasking di lunga durata
- `download`: Scarica un file dal sistema target alla macchina locale
- `upload`: Carica un file dalla macchina locale al sistema target
- `reg_query`: Interroga le chiavi e i valori del registry sul sistema target
- `reg_write_value`: Scrive un nuovo valore in una chiave del registry specificata
- `sleep`: Modifica l'intervallo di sleep dell'agent, che determina la frequenza con cui effettua il check-in con il server Mythic
- E molti altri; utilizzare `help` per visualizzare l'elenco completo dei comandi disponibili.

### Privilege escalation

- `getprivs`: Abilita il maggior numero possibile di privilegi nel token del thread corrente
- `getsystem`: Apre un handle verso winlogon e duplica il token, effettuando di fatto l'escalation dei privilegi al livello SYSTEM
- `make_token`: Crea una nuova logon session e la applica all'agent, consentendo l'impersonation di un altro utente
- `steal_token`: Ruba un primary token da un altro processo, consentendo all'agent di impersonare l'utente di quel processo
- `pth`: Attacco Pass-the-Hash, che consente all'agent di autenticarsi come un utente utilizzando il suo hash NTLM senza aver bisogno della password in chiaro
- `mimikatz`: Esegue comandi Mimikatz per estrarre credenziali, hash e altre informazioni sensibili dalla memoria o dal database SAM
- `rev2self`: Ripristina il token dell'agent al suo primary token, rimuovendo di fatto i privilegi fino al livello originale
- `ppid`: Cambia il processo parent per i job post-exploitation specificando un nuovo process ID parent, consentendo un maggiore controllo sul contesto di esecuzione del job
- `printspoofer`: Esegue comandi PrintSpoofer per bypassare le misure di sicurezza dello print spooler, consentendo privilege escalation o code execution
- `dcsync`: Sincronizza le chiavi Kerberos di un utente sulla macchina locale, consentendo password cracking offline o ulteriori attacchi
- `ticket_cache_add`: Aggiunge un ticket Kerberos alla logon session corrente o a una sessione specificata, consentendo il riutilizzo del ticket o l'impersonation

### Esecuzione dei processi

- `assembly_inject`: Consente di iniettare un .NET assembly loader in un processo remoto
- `blockdlls`: Impedisce il caricamento di DLL non firmate da Microsoft nei job post-exploitation
- `execute_assembly`: Esegue un .NET assembly nel contesto dell'agent
- `execute_coff`: Esegue un file COFF in memoria, consentendo l'esecuzione in-memory di codice compilato
- `execute_pe`: Esegue un eseguibile unmanaged (PE)
- `keylog_inject`: Inietta un keylogger in un altro processo e invia i keystroke alla keylog view di Mythic
- `screenshot` / `screenshot_inject`: Acquisisce il desktop corrente direttamente oppure
iniettando uno screenshot assembly in un processo/sessione target
- `get_injection_techniques`: Mostra le tecniche di injection disponibili e quella attualmente selezionata
- `inline_assembly`: Esegue un .NET assembly in un AppDomain disposable, consentendo l'esecuzione temporanea di codice senza influire sul processo principale dell'agent
- `register_assembly`: Registra un .NET assembly per l'esecuzione successiva
- `register_file`: Registra un file nella cache dell'agent per il successivo tasking `execute_*` o PowerShell
- `run`: Esegue un binary sul sistema target, utilizzando il PATH del sistema per trovare l'eseguibile
- `set_injection_technique`: Cambia la injection primitive utilizzata dai job post-exploitation
- `shinject`: Inietta shellcode in un processo remoto, consentendo l'esecuzione in-memory di codice arbitrario
- `inject`: Inietta lo shellcode dell'agent in un processo remoto, consentendo l'esecuzione in-memory del codice dell'agent
- `spawn`: Avvia una nuova sessione agent nell'eseguibile specificato, consentendo l'esecuzione dello shellcode in un nuovo processo
- `spawnto_x64` e `spawnto_x86`: Cambiano il binary predefinito utilizzato nei job post-exploitation impostandolo su un path specificato, invece di usare `rundll32.exe` senza parametri, che è molto rumoroso.

### Mythic Forge

Questo consente di **caricare** file COFF/BOF da Mythic Forge, che è un repository di payload e tool pre-compilati che possono essere eseguiti sul sistema target. Con tutti i comandi che possono essere caricati, sarà possibile eseguire azioni comuni nel processo dell'agent corrente come BOF (solitamente con un OPSEC migliore rispetto all'avvio di un processo separato).

Iniziare a installarli con:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Quindi, usa `forge_collections` per mostrare i moduli COFF/BOF dal Mythic Forge, così da poterli selezionare e caricare nella memoria dell'agent per l'esecuzione. Per impostazione predefinita, in Apollo vengono aggiunte le seguenti 2 collection:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Dopo il caricamento di un modulo, questo apparirà nell'elenco come un altro comando, ad esempio `forge_bof_sa-whoami` o `forge_bof_sa-netuser`.

Per i BOF, ricorda che Forge **non** passa semplicemente una singola stringa piatta di argomenti ad Apollo. Esegue il mapping dei parametri BOF nel formato typed-array di Mythic e poi li inoltra al flow `execute_coff` di Apollo. Se un BOF caricato tramite Forge si comporta in modo anomalo, controlla i tipi di argomenti BOF previsti e l'entrypoint, invece di verificare soltanto la command line digitata. Nota inoltre che il nuovo loader BOF di Apollo ha modificato la gestione degli argomenti rispetto alle build molto più vecchie dell'era 2.3.1; di conseguenza, BOF obsoleti o vecchie collection possono fallire semplicemente perché le aspettative di marshaling sono cambiate.

### Esecuzione di PowerShell e scripting

- `powershell_import`: Importa un nuovo script PowerShell (.ps1) nella cache dell'agent per l'esecuzione successiva
- `powershell`: Esegue un comando PowerShell nel contesto dell'agent, consentendo scripting e automazione avanzati
- `powerpick`: Inietta un assembly loader di PowerShell in un processo sacrificabile ed esegue un comando PowerShell (senza logging di PowerShell).
- `psinject`: Esegue PowerShell in un processo specificato, consentendo l'esecuzione mirata di script nel contesto di un altro processo
- `shell`: Esegue un comando shell nel contesto dell'agent, in modo simile all'esecuzione di un comando in cmd.exe

### Lateral Movement

- `jump_psexec`: Usa la tecnica PsExec per eseguire il lateral movement verso un nuovo host, copiando prima l'eseguibile dell'agent Apollo (apollo.exe) ed eseguendolo.
- `jump_wmi`: Usa la tecnica WMI per eseguire il lateral movement verso un nuovo host, copiando prima l'eseguibile dell'agent Apollo (apollo.exe) ed eseguendolo.
- `link` e `unlink`: Creano e terminano link P2P (ad esempio tramite SMB/TCP) tra callback.
- `wmiexecute`: Esegue un comando sul sistema locale o remoto specificato usando WMI, con credenziali opzionali per l'impersonation.
- `net_dclist`: Recupera un elenco dei domain controller per il dominio specificato, utile per identificare potenziali target per il lateral movement.
- `net_localgroup`: Elenca i gruppi locali sul computer specificato, usando localhost per impostazione predefinita se non viene specificato alcun computer.
- `net_localgroup_member`: Recupera i membri di un gruppo locale specificato sul computer locale o remoto, consentendo l'enumeration degli utenti appartenenti a gruppi specifici.
- `net_shares`: Elenca le share remote e la loro accessibilità sul computer specificato, utile per identificare potenziali target per il lateral movement.
- `socks`: Abilita un proxy compatibile con SOCKS 5 sulla rete target, consentendo il tunneling del traffico attraverso l'host compromesso. Compatibile con strumenti come proxychains.
- `rpfwd`: Avvia l'ascolto su una porta specificata dell'host target e inoltra il traffico tramite Mythic verso un IP e una porta remoti, consentendo l'accesso remoto ai servizi sulla rete target.
- `listpipes`: Elenca tutte le named pipe sul sistema locale, che possono essere utili per il lateral movement o la privilege escalation interagendo con i meccanismi IPC.

Per le primitive di esecuzione WMI di livello inferiore utilizzate da `jump_wmi` o `wmiexecute`, consulta [WmiExec](lateral-movement/wmiexec.md). Per pattern di pivoting più ampi, consulta [Tunneling e Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Comandi vari
- `help`: Mostra informazioni dettagliate su comandi specifici o informazioni generali su tutti i comandi disponibili nell'agent.
- `clear`: Contrassegna i task come "cleared", impedendo agli agent di recuperarli. È possibile specificare `all` per cancellare tutti i task oppure `task Num` per cancellare un task specifico.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon è un agent Golang che viene compilato in eseguibili per **Linux e macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Note attuali su build/profilo

- Le build attuali di Poseidon sono destinate a Linux e macOS su `x86_64` e `arm64`.
- I formati di output supportati includono eseguibili nativi e output in stile shared-library come `dylib` e `so`.
- Poseidon supporta `http`, `websocket`, `tcp` e `dynamichttp`, e i builder attuali espongono impostazioni multi-egress come `egress_order` e soglie di failover.
- Gli attuali metadati delle capacità di Poseidon pubblicizzano anche browser scripts, integrazione con file/process browser, interactive tasking, keylogging, screenshot, Push C2, SOCKS, rpfwd e P2P, consentendogli di funzionare come un vero nodo pivot Linux/macOS, anziché solo come una semplice remote shell.
- Le opzioni in fase di build come `proxy_bypass` e `garble` meritano di essere controllate quando servono rispettivamente un comportamento di rete più trasparente o un'ulteriore obfuscation dei binari Go.
- `pty` è uno dei più utili comandi recenti per migliorare la qualità delle operazioni su Linux/macOS, perché apre un PTY interattivo e può esporre una porta lato Mythic per un'interazione più completa con il terminale, senza ricorrere al vecchio workaround `sleep 0` + SOCKS.
- La documentazione attuale di Poseidon è particolarmente interessante per il tradecraft focalizzato su macOS: `jxa` esegue JavaScript for Automation in-memory, `screencapture` cattura il desktop dell'utente connesso, `clipboard_monitor` trasmette le modifiche al pasteboard, `execute_library` carica una dylib locale e ne chiama una funzione, mentre `libinject` forza un processo remoto a caricare una dylib dal disco.
- Per i job di lunga durata, ricorda che Poseidon esegue le attività di post-exploitation in goroutine/thread cooperativi, che non possono essere terminati forzatamente. La documentazione nota inoltre esplicitamente che attualmente non esiste una built-in agent obfuscation, quindi il tradecraft a livello di build/profilo è più importante rispetto a implant commerciali fortemente obfuscati.

Per il tradecraft specifico di macOS relativo alle operazioni basate su Mythic, all'abuso di JAMF o alle idee di MDM-as-C2, consulta [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Quando viene usato su Linux o macOS, dispone di alcuni comandi interessanti:

### Azioni comuni

- `cat`: Stampa il contenuto di un file
- `cd`: Cambia la directory di lavoro corrente
- `chmod`: Cambia i permessi di un file
- `config`: Visualizza la configurazione attuale e le informazioni sull'host
- `cp`: Copia un file da una posizione a un'altra
- `curl`: Esegue una singola richiesta web con header e metodo opzionali
- `upload`: Carica un file sul target
- `download`: Scarica un file dal sistema target alla macchina locale
- E molti altri

### Ricerca di informazioni sensibili

- `triagedirectory`: Cerca file interessanti all'interno di una directory su un host, come file sensibili o credenziali.
- `getenv`: Recupera tutte le variabili d'ambiente attuali.

### Tradecraft specifico di macOS

- `jxa`: Esegue JavaScript for Automation in-memory tramite `OSAScript`, utile per la post-exploitation nativa su macOS senza rilasciare file di script separati.
- `clipboard_monitor`: Esegue il polling del pasteboard e comunica le modifiche a Mythic, risultando utile nei workflow di credential/token theft basati sul copia-incolla.
- `screencapture`: Cattura il desktop dell'utente su macOS.
- `execute_library`: Carica una dylib dal disco e chiama una specifica funzione esportata.
- `libinject`: Inietta uno stub di shellcode che forza un altro processo macOS a caricare una dylib dal disco.
- `persist_launchd`: Crea direttamente la persistenza tramite LaunchAgent / LaunchDaemon dall'agent.

### Movimento laterale

- `ssh`: Esegue SSH verso l'host usando le credenziali designate e apre un PTY senza generare ssh.
- `sshauth`: Esegue SSH verso gli host specificati usando le credenziali designate. Può anche essere usato per eseguire un comando specifico sugli host remoti tramite SSH o per copiare file con SCP.
- `link_tcp`: Collega un altro agent tramite TCP, consentendo la comunicazione diretta tra agent.
- `link_webshell`: Collega un agent usando il profilo P2P webshell, consentendo l'accesso remoto all'interfaccia web dell'agent.
- `rpfwd`: Avvia o arresta un Reverse Port Forward, consentendo l'accesso remoto ai servizi sulla rete target.
- `socks`: Avvia o arresta un proxy SOCKS5 sulla rete target, consentendo il tunneling del traffico attraverso l'host compromesso. Compatibile con strumenti come proxychains.
- `portscan`: Esegue la scansione degli host alla ricerca di porte aperte, utile per identificare potenziali target per il movimento laterale o ulteriori attacchi.

### Esecuzione dei processi

- `shell`: Esegue un singolo comando shell tramite /bin/sh, consentendo l'esecuzione diretta dei comandi sul sistema target.
- `run`: Esegue un comando dal disco con gli argomenti specificati, consentendo l'esecuzione di binari o script sul sistema target.
- `pty`: Apre un PTY interattivo, consentendo l'interazione diretta con la shell sul sistema target.

## Riferimenti

- [1] [Matrice delle funzionalità degli agent della community Mythic](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [README di Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transforming Red Team Ops with Mythic's Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
