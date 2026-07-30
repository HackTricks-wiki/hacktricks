# Mythic

{{#include ../banners/hacktricks-training.md}}

## Cos'è Mythic?

Mythic è un framework open-source, modulare e collaborativo di command and control (C2) progettato per il red teaming. Consente agli operatori di gestire e distribuire agenti (payloads) su diversi sistemi operativi, tra cui Windows, Linux e macOS. Mythic fornisce un'interfaccia browser per il tasking multi-operatore, la gestione dei file, la gestione di SOCKS/rpfwd e la generazione di payloads.

A differenza dei framework monolitici, il repository di Mythic non include direttamente tipi di payload o profili C2. Gli agenti, i wrapper e i profili C2 vengono generalmente installati come componenti esterni e possono essere aggiornati indipendentemente dal core di Mythic.

### Installazione

Per installare Mythic, segui le istruzioni nel **[repository ufficiale di Mythic](https://github.com/its-a-feature/Mythic)**. Un bootstrap comune dalla directory di Mythic è:
```bash
sudo make
sudo ./mythic-cli start
```
Se Mythic è già in esecuzione, normalmente puoi aggiungere un nuovo agent o profile con `./mythic-cli install github ...` e poi riavviare Mythic oppure avviare direttamente il nuovo componente.

### Agents

Mythic supporta più agent, ovvero i **payload che eseguono attività sui sistemi compromessi**. Ogni agent può essere adattato a esigenze specifiche ed essere eseguito su diversi sistemi operativi.

Per impostazione predefinita, Mythic non ha agent installati. Gli agent open-source della community sono disponibili su [**https://github.com/MythicAgents**](https://github.com/MythicAgents), mentre la [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) è utile per verificare rapidamente i sistemi operativi supportati, i formati dei payload, i wrapper e i profili C2.

Per installare un agent da quell'organizzazione puoi eseguire:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
La forma `sudo -E` è utile quando installi da un ambiente non-root. Puoi aggiungere nuovi agent con il comando precedente anche se Mythic è già in esecuzione.

### C2 Profiles

I C2 profiles in Mythic definiscono **il modo in cui gli agent comunicano con il server Mythic**. Specificano il protocollo di comunicazione, i metodi di crittografia e altre impostazioni. Puoi creare e gestire i C2 profiles tramite l'interfaccia web di Mythic.

Per impostazione predefinita, Mythic viene installato senza profiles; tuttavia, è possibile scaricare alcuni profiles dal repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) eseguendo:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Profili rilevanti per l'operator da tenere presenti:

- [`http`](https://github.com/MythicC2Profiles/http): traffico asincrono GET/POST di base.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): traffico HTTP più flessibile con più domini di callback, rotazione fail-over/round-robin, header e query parameters personalizzati e message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) inseriti in cookie, header, query parameters o body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): definizione della struttura dei messaggi HTTP basata su JSON/TOML quando il profilo statico `http` è troppo riconoscibile.

### Note attuali sulla piattaforma

- Molti agent e profili pubblici ora vengono installati con immagini remote precompilate dei container.
Se esegui il fork di un componente o applichi una patch localmente e Mythic continua a utilizzare il comportamento precedente, controlla le voci `.env` generate per `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` e `*_USE_VOLUME`; abilitare
`*_USE_BUILD_CONTEXT="true"` è solitamente ciò che fa ricostruire Mythic dal tuo
contesto Docker locale invece di riutilizzare silenziosamente l'immagine remota.
- Gli script del browser sono una delle feature con il miglior rapporto valore/qualità della vita di Mythic per gli operator: possono trasformare l'output grezzo dei comandi in tabelle, visualizzatori di screenshot, link per il download, link di ricerca e pulsanti che inviano tasking successivi direttamente dalla UI. Le build attuali di Mythic consentono a ogni operator di mantenere i propri script, abilitarli o disabilitarli globalmente o per task e ottenere i risultati migliori quando gli agent restituiscono JSON strutturato invece di testo semplice. Questo è particolarmente utile per i workflow ripetitivi con `ls`, `ps`, triage e file browser.
- Le build più recenti di Mythic supportano anche interactive tasking e i pattern Push C2, riducendo la necessità di eseguire polling con `sleep 0` durante le operazioni intensive in PTY/SOCKS/rpfwd. Quando un agent/profile lo supporta, questo genera solitamente un overhead inferiore rispetto a bombardare il server con check-in costanti solo per mantenere utilizzabile un canale interattivo.
- I builder Mythic dell'era 3.4 sono più consapevoli del contesto rispetto a quanto suggeriscano i writeup più vecchi: i parametri di build possono ora essere raggruppati o nascosti in base al sistema operativo selezionato o ad altre opzioni di build, i payload type possono dichiarare se supportano più profili C2 o più istanze dello stesso C2 in una singola build e le C2 parameter deviations consentono a un agent di nascondere i campi che non implementa realmente. Questo è importante quando si passa tra `http`, `httpx`, `smb`,
`tcp` e `websocket`, perché la superficie di build sicura/valida non è più un form statico e piatto.
- Se stai creando una coppia custom agent/profile e non vuoi che il formato dei messaggi JSON o la crittografia predefinita di Mythic siano presenti on the wire, utilizza un
`translation_container`: Mythic rimuove l'UUID, trasferisce il blob crittografato e il key material al translator tramite gRPC e si aspetta in risposta byte nativi dell'agent. Questo è il modo corretto per supportare protocolli binari, framing personalizzato o crittografia lato agent senza riscrivere l'intero server.
- Ricorda che i callback linked/P2P non si limitano a trasferire tasking. Il flow `get_tasking` di Mythic può trasportare anche risposte e dati `delegates`,
`socks`, `rpfwd` e `interactive`. In pratica, un callback di egress può gestire callback interni e canali di pivot nello stesso polling loop; se gli agent figli eseguono i propri check-in periodici, `get_delegate_tasks=false` impedisce al parent di consumare accidentalmente i job in coda del callback interno.

### Wrapper payload

I wrapper payload consentono di mantenere la stessa logica dell'agent modificando al contempo la rappresentazione su disco che viene distribuita o persistita.

- `service_wrapper`: trasforma un altro payload in un eseguibile Windows per un servizio, utile quando il percorso di esecuzione richiede un service binary valido.
- `scarecrow_wrapper`: esegue il wrapping di shellcode compatibile con il loader ScareCrow per generare output basati sul loader, come EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo è un agent Windows scritto in C# utilizzando il framework .NET 4.0, progettato per essere usato nelle offerte formative di SpecterOps.

Installalo con:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Note attuali su build/profilo

- Apollo può attualmente generare payload `WinExe`, `Shellcode`, `Service` e `Source`.
- I profili Apollo comunemente utilizzati sono `http`, `httpx`, `smb`, `tcp` e `websocket`.
- `httpx` è generalmente l'opzione più flessibile quando servono domain rotation, supporto proxy, posizionamento personalizzato dei messaggi e message transforms, invece del vecchio profilo statico `http`.
- Apollo è uno degli agent community più completi e attualmente espone integrazioni lato Mythic come browser scripts, viste browser per file/processi, screenshot, keylogging, SOCKS, rpfwd, Push C2 e routing P2P.
- Apollo supporta wrapper payload come `service_wrapper` e `scarecrow_wrapper`.
- Apollo supporta il caricamento dinamico dei comandi, quindi è possibile mantenere leggero il payload iniziale e caricare successivamente comandi aggiuntivi o moduli Forge invece di compilare ogni funzionalità di post-exploitation nella prima build.
- Quando genera un output shellcode, l'attuale builder di Apollo espone anche le scelte di formato Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) e il comportamento di bypass di Donut (`None`, `Abort on fail`, `Continue on fail`). Questo è utile se l'obiettivo finale è re-wrappare lo shellcode con `service_wrapper`, `scarecrow_wrapper` o un loader personalizzato.
- `register_file` e `register_assembly` sono le primitive di staging per `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` e `powerpick`. Nelle build attuali di Apollo, questi artefatti staged vengono memorizzati nella cache lato client come blob AES256 protetti da DPAPI.
- I risultati di `ls` e `ps` si integrano particolarmente bene con i browser scripts e il file/process browser di Mythic, rendendo il triage dell'operatore sensibilmente più rapido nelle operazioni collaborative.
- I job fork-and-run ereditano le impostazioni del processo sacrificabile da
`spawnto_x86` / `spawnto_x64`, ereditano la selezione del parent da `ppid` e
utilizzano quindi la primitive di injection attualmente selezionata. In pratica, ciò significa che il tuning OPSEC per un comando spesso influisce contemporaneamente su `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` e `spawn`.
- Gli attuali backend di injection documentati di Apollo includono `CreateRemoteThread`,
`QueueUserAPC` (in stile early-bird) e `NtCreateThreadEx` tramite syscalls. Usa
`get_injection_techniques` prima di attività rumorose di post-exploitation e
`set_injection_technique` se devi cambiare una primitive che entra in conflitto con il target o con il comando che vuoi eseguire.
- `blockdlls` influisce solo sui processi sacrificabili creati per i job di post-exploitation. In combinazione con un target `spawnto_x64` meno sospetto rispetto al `rundll32.exe` bare predefinito, questa è una delle modifiche più semplici lato Apollo da effettuare prima di eseguire tasking pesanti basati su assembly/PowerShell.

Questo agent dispone di numerosi comandi che lo rendono molto simile al Beacon di Cobalt Strike, con alcune funzionalità aggiuntive. Tra questi, supporta:

### Azioni comuni

- `cat`: Stampa il contenuto di un file
- `cd`: Cambia la working directory corrente
- `cp`: Copia un file da una posizione a un'altra
- `ls`: Elenca file e directory nella directory corrente o nel path specificato
- `ifconfig`: Recupera gli adattatori e le interfacce di rete
- `netstat`: Recupera informazioni sulle connessioni TCP e UDP
- `pwd`: Stampa la working directory corrente
- `ps`: Elenca i processi in esecuzione sul sistema target (con informazioni aggiuntive)
- `jobs`: Elenca tutti i job in esecuzione associati a tasking di lunga durata
- `download`: Scarica un file dal sistema target alla macchina locale
- `upload`: Carica un file dalla macchina locale al sistema target
- `reg_query`: Interroga le chiavi e i valori del registro sul sistema target
- `reg_write_value`: Scrive un nuovo valore in una chiave del registro specificata
- `sleep`: Modifica l'intervallo di sleep dell'agent, che determina la frequenza con cui effettua il check-in con il server Mythic
- E molti altri; usa `help` per visualizzare l'elenco completo dei comandi disponibili.

### Privilege escalation

- `getprivs`: Abilita il maggior numero possibile di privilegi nel token del thread corrente
- `getsystem`: Apre un handle a winlogon e duplica il token, effettuando di fatto una privilege escalation al livello SYSTEM
- `make_token`: Crea una nuova logon session e la applica all'agent, consentendo l'impersonation di un altro utente
- `steal_token`: Ruba un primary token da un altro processo, consentendo all'agent di impersonare l'utente di quel processo
- `pth`: Attacco Pass-the-Hash, che consente all'agent di autenticarsi come un utente usando il relativo hash NTLM senza dover conoscere la password in chiaro
- `mimikatz`: Esegue comandi Mimikatz per estrarre credenziali, hash e altre informazioni sensibili dalla memoria o dal database SAM
- `rev2self`: Riporta il token dell'agent al primary token, rimuovendo di fatto i privilegi e tornando al livello originale
- `ppid`: Cambia il processo parent per i job di post-exploitation specificando un nuovo process ID parent, consentendo un controllo migliore sul contesto di esecuzione del job
- `printspoofer`: Esegue comandi PrintSpoofer per bypassare le misure di sicurezza del print spooler, consentendo privilege escalation o code execution
- `dcsync`: Sincronizza le chiavi Kerberos di un utente sulla macchina locale, consentendo il password cracking offline o ulteriori attacchi
- `ticket_cache_add`: Aggiunge un ticket Kerberos alla logon session corrente o a una sessione specificata, consentendo il riutilizzo del ticket o l'impersonation

### Esecuzione dei processi

- `assembly_inject`: Consente di iniettare un .NET assembly loader in un processo remoto
- `blockdlls`: Impedisce il caricamento di DLL non firmate da Microsoft nei job di post-exploitation
- `execute_assembly`: Esegue un .NET assembly nel contesto dell'agent
- `execute_coff`: Esegue un file COFF in memoria, consentendo l'esecuzione in-memory di codice compilato
- `execute_pe`: Esegue un eseguibile unmanaged (PE)
- `keylog_inject`: Inietta un keylogger in un altro processo e invia i keystroke alla keylog view di Mythic
- `screenshot` / `screenshot_inject`: Acquisisce il desktop corrente direttamente oppure
iniettando uno screenshot assembly in un processo/sessione target
- `get_injection_techniques`: Mostra le tecniche di injection disponibili e quella attualmente selezionata
- `inline_assembly`: Esegue un .NET assembly in un AppDomain usa-e-getta, consentendo l'esecuzione temporanea di codice senza influire sul processo principale dell'agent
- `register_assembly`: Registra un .NET assembly per l'esecuzione successiva
- `register_file`: Registra un file nella cache dell'agent per un successivo tasking `execute_*` o PowerShell
- `run`: Esegue un binary sul sistema target, usando il PATH di sistema per individuare l'eseguibile
- `set_injection_technique`: Cambia la primitive di injection utilizzata dai job di post-exploitation
- `shinject`: Inietta shellcode in un processo remoto, consentendo l'esecuzione in-memory di codice arbitrario
- `inject`: Inietta lo shellcode dell'agent in un processo remoto, consentendo l'esecuzione in-memory del codice dell'agent
- `spawn`: Avvia una nuova agent session nell'eseguibile specificato, consentendo l'esecuzione di shellcode in un nuovo processo
- `spawnto_x64` e `spawnto_x86`: Cambiano il binary predefinito utilizzato nei job di post-exploitation con un path specificato, invece di usare `rundll32.exe` senza parametri, che è molto rumoroso.

### Mythic Forge

Consente di **caricare file COFF/BOF** da Mythic Forge, un repository di payload e tool precompilati che possono essere eseguiti sul sistema target. Con tutti i comandi caricabili, sarà possibile eseguire azioni comuni nel processo dell'agent corrente come BOF, generalmente con un OPSEC migliore rispetto all'avvio di un processo separato.

Inizia installandoli con:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Quindi, usa `forge_collections` per mostrare i moduli COFF/BOF dal Mythic Forge, così da poterli selezionare e caricare nella memoria dell'agent per l'esecuzione. Per impostazione predefinita, in Apollo vengono aggiunte le seguenti 2 collection:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Dopo il caricamento di un modulo, questo apparirà nell'elenco come un altro comando, ad esempio `forge_bof_sa-whoami` o `forge_bof_sa-netuser`.

Per i BOF, ricorda che Forge **non** passa semplicemente una stringa piatta di argomenti
ad Apollo. Mappa i parametri BOF nel formato typed-array di Mythic e poi li inoltra al flusso `execute_coff` di Apollo. Se un BOF caricato tramite Forge si comporta in modo anomalo, controlla i tipi di argomento BOF previsti e l'entrypoint, invece di verificare soltanto la riga di comando digitata. Tieni inoltre presente che il loader BOF più recente di Apollo ha modificato la gestione degli argomenti rispetto alle build molto più vecchie dell'era 2.3.1; pertanto, i BOF obsoleti o le collection precedenti possono non funzionare semplicemente perché le aspettative di marshaling sono cambiate.

### Esecuzione di PowerShell e scripting

- `powershell_import`: Importa un nuovo script PowerShell (.ps1) nella cache dell'agent per l'esecuzione successiva
- `powershell`: Esegue un comando PowerShell nel contesto dell'agent, consentendo scripting e automazione avanzati
- `powerpick`: Inietta un assembly loader di PowerShell in un processo sacrificabile ed esegue un comando PowerShell (senza logging di powershell).
- `psinject`: Esegue PowerShell in un processo specificato, consentendo l'esecuzione mirata di script nel contesto di un altro processo
- `shell`: Esegue un comando shell nel contesto dell'agent, in modo simile all'esecuzione di un comando in cmd.exe

### Lateral Movement

- `jump_psexec`: Utilizza la tecnica PsExec per eseguire il Lateral Movement verso un nuovo host, copiando prima l'eseguibile dell'agent Apollo (apollo.exe) ed eseguendolo.
- `jump_wmi`: Utilizza la tecnica WMI per eseguire il Lateral Movement verso un nuovo host, copiando prima l'eseguibile dell'agent Apollo (apollo.exe) ed eseguendolo.
- `link` e `unlink`: Creano e interrompono link P2P (ad esempio tramite SMB/TCP) tra callback.
- `wmiexecute`: Esegue un comando sul sistema locale o su quello remoto specificato utilizzando WMI, con credenziali opzionali per l'impersonation.
- `net_dclist`: Recupera un elenco dei domain controller per il dominio specificato, utile per identificare potenziali target per il Lateral Movement.
- `net_localgroup`: Elenca i gruppi locali sul computer specificato; per impostazione predefinita utilizza localhost se non viene specificato alcun computer.
- `net_localgroup_member`: Recupera i membri di un gruppo locale specificato sul computer locale o remoto, consentendo l'enumerazione degli utenti appartenenti a gruppi specifici.
- `net_shares`: Elenca le condivisioni remote e la relativa accessibilità sul computer specificato, utile per identificare potenziali target per il Lateral Movement.
- `socks`: Abilita un proxy compatibile con SOCKS 5 sulla rete target, consentendo il tunneling del traffico attraverso l'host compromesso. Compatibile con strumenti come proxychains.
- `rpfwd`: Inizia l'ascolto su una porta specificata sull'host target e inoltra il traffico tramite Mythic verso un IP e una porta remoti, consentendo l'accesso remoto ai servizi sulla rete target.
- `listpipes`: Elenca tutte le named pipe sul sistema locale, utili per il Lateral Movement o la privilege escalation interagendo con i meccanismi IPC.

Per le primitive di esecuzione WMI di livello inferiore utilizzate da `jump_wmi` o `wmiexecute`, consulta [WmiExec](lateral-movement/wmiexec.md). Per i pattern di pivoting più generali, consulta [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Comandi vari
- `help`: Visualizza informazioni dettagliate su comandi specifici o informazioni generali su tutti i comandi disponibili nell'agent.
- `clear`: Contrassegna i task come "cleared", in modo che non possano essere recuperati dagli agent. Puoi specificare `all` per cancellare tutti i task oppure `task Num` per cancellare un task specifico.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon è un agent scritto in Golang che viene compilato in eseguibili per **Linux e macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Note attuali su build/profilo

- Le build attuali di Poseidon sono destinate a Linux e macOS su `x86_64` e `arm64`.
- I formati di output supportati includono eseguibili nativi e output in stile shared library come `dylib` e `so`.
- Poseidon supporta `http`, `websocket`, `tcp` e `dynamichttp`, e i builder attuali espongono impostazioni multi-egress come `egress_order` e le soglie di failover.
- Gli attuali metadata delle capacità di Poseidon pubblicizzano anche browser scripts, integrazione per la navigazione di file/processi, interactive tasking, keylogging, screenshot, Push C2, SOCKS, rpfwd e P2P; pertanto può funzionare come un vero nodo pivot Linux/macOS e non solo come una semplice remote shell.
- Vale la pena verificare le opzioni in fase di build come `proxy_bypass` e `garble` quando servono rispettivamente un comportamento di rete più pulito o ulteriore offuscamento dei binari Go.
- `pty` è uno dei più utili comandi QoL recenti per le
operazioni Linux/macOS, perché apre una PTY interattiva e può esporre una
porta lato Mythic per un'interazione più completa con il terminale senza
ricorrere alla vecchia soluzione alternativa
`sleep 0` + SOCKS.
- La documentazione attuale di Poseidon è particolarmente interessante per le
tradecraft incentrate su macOS: `jxa` esegue JavaScript for Automation in-memory,
`screencapture` cattura il desktop dell'utente autenticato,
`clipboard_monitor` trasmette le modifiche al pasteboard,
`execute_library` carica una dylib locale e ne chiama una
funzione, mentre `libinject` forza un processo remoto a caricare una dylib
presente su disco.
- Per i job di lunga durata, ricorda che Poseidon esegue le attività di
post-exploitation in goroutine/thread cooperativi, che non possono essere
terminati forzatamente. La documentazione nota inoltre esplicitamente che
attualmente non esiste alcuna obfuscation integrata dell'agent, quindi le
tradecraft a livello di build/profilo sono più importanti rispetto a impianti commerciali fortemente offuscati.

Per le tradecraft specifiche di macOS relative alle operazioni basate su Mythic, all'abuso di JAMF o alle idee MDM-as-C2, consulta [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Quando viene utilizzato su Linux o macOS, dispone di alcuni comandi interessanti:

### Azioni comuni

- `cat`: Stampa il contenuto di un file
- `cd`: Cambia la directory di lavoro corrente
- `chmod`: Modifica i permessi di un file
- `config`: Visualizza la configurazione corrente e le informazioni sull'host
- `cp`: Copia un file da una posizione a un'altra
- `curl`: Esegue una singola richiesta web con header e metodo opzionali
- `upload`: Carica un file sul target
- `download`: Scarica un file dal sistema target alla macchina locale
- E molti altri

### Ricerca di informazioni sensibili

- `triagedirectory`: Trova file interessanti all'interno di una directory su un host, come file sensibili o credenziali.
- `getenv`: Recupera tutte le variabili d'ambiente correnti.

### Tradecraft specifiche di macOS

- `jxa`: Esegue JavaScript for Automation in-memory tramite `OSAScript`, utile per la post-exploitation nativa di macOS senza lasciare separati file di script.
- `clipboard_monitor`: Interroga il pasteboard e invia le modifiche a Mythic, utile nei workflow di furto di credenziali/token che si basano sul copia e incolla.
- `screencapture`: Cattura il desktop dell'utente su macOS.
- `execute_library`: Carica una dylib dal disco e chiama una specifica funzione esportata.
- `libinject`: Inietta uno stub di shellcode che forza un altro processo macOS a caricare una dylib dal disco.
- `persist_launchd`: Crea direttamente la persistenza tramite LaunchAgent / LaunchDaemon dall'agent.

### Movimento laterale

- `ssh`: Esegue SSH verso l'host utilizzando le credenziali designate e apre una PTY senza avviare ssh.
- `sshauth`: Esegue SSH verso gli host specificati utilizzando le credenziali designate. Puoi anche usarlo per eseguire un comando specifico sugli host remoti tramite SSH o per utilizzarlo con SCP per i file.
- `link_tcp`: Collega un altro agent tramite TCP, consentendo la comunicazione diretta tra agent.
- `link_webshell`: Collega un agent utilizzando il profilo P2P webshell, consentendo l'accesso remoto all'interfaccia web dell'agent.
- `rpfwd`: Avvia o arresta un Reverse Port Forward, consentendo l'accesso remoto ai servizi sulla rete target.
- `socks`: Avvia o arresta un proxy SOCKS5 sulla rete target, consentendo il tunneling del traffico attraverso l'host compromesso. Compatibile con strumenti come proxychains.
- `portscan`: Esegue la scansione degli host alla ricerca di porte aperte, utile per identificare potenziali target per il movimento laterale o ulteriori attacchi.

### Esecuzione dei processi

- `shell`: Esegue un singolo comando shell tramite /bin/sh, consentendo l'esecuzione diretta dei comandi sul sistema target.
- `run`: Esegue un comando dal disco con argomenti, consentendo l'esecuzione di binari o script sul sistema target.
- `pty`: Apre una PTY interattiva, consentendo l'interazione diretta con la shell sul sistema target.






## Riferimenti

- [Matrice delle funzionalità degli agent della community Mythic](https://mythicmeta.github.io/overview/agent_matrix.html)
- [README di Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2: interactive tasking, Push C2 e dynamic file browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - documentazione di Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Aggiornamenti da Mythic 3.3 a 3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Trasformare le operazioni di Red Team con le funzionalità nascoste di Mythic: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
