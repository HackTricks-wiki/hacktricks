# Mythic

{{#include ../banners/hacktricks-training.md}}

## Cos'è Mythic?

Mythic è un framework command and control (C2) open-source, modulare e collaborativo progettato per il red teaming. Consente agli operatori di gestire e distribuire agenti (payload) su diversi sistemi operativi, tra cui Windows, Linux e macOS. Mythic fornisce un'interfaccia browser per tasking multi-operatore, gestione dei file, gestione SOCKS/rpfwd e generazione di payload.

A differenza dei framework monolitici, il repository Mythic di per sé **non** include tipi di payload o profili C2. Agent, wrapper e profili C2 vengono in genere installati come componenti esterni e possono essere aggiornati indipendentemente dal core di Mythic.

### Installazione

Per installare Mythic, segui le istruzioni nel repo ufficiale **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Un bootstrap comune dalla directory di Mythic è:
```bash
sudo make
sudo ./mythic-cli start
```
Se Mythic è già in esecuzione, normalmente puoi aggiungere un nuovo agent o profile con `./mythic-cli install github ...` e poi riavviare Mythic oppure avviare direttamente il nuovo componente.

### Agents

Mythic supporta più agents, che sono i **payloads che eseguono task sui sistemi compromessi**. Ogni agent può essere adattato a esigenze specifiche e può essere eseguito su diversi sistemi operativi.

Per impostazione predefinita Mythic non ha alcun agent installato. Gli agent open-source della community si trovano in [**https://github.com/MythicAgents**](https://github.com/MythicAgents), e la [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) è utile per verificare rapidamente i sistemi operativi supportati, i formati dei payload, i wrappers e i profili C2.

Per installare un agent da quell'org puoi eseguire:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
La forma `sudo -E` è utile quando stai installando da un ambiente non-root. Puoi aggiungere nuovi agent con il comando precedente anche se Mythic è già in esecuzione.

### C2 Profiles

I C2 profiles in Mythic definiscono **come gli agent comunicano con il Mythic server**. Specificano il protocollo di comunicazione, i metodi di crittografia e altre impostazioni. Puoi creare e gestire i C2 profiles tramite l'interfaccia web di Mythic.

Per impostazione predefinita Mythic è installato senza profile; tuttavia, è possibile scaricare alcuni profile dal repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) eseguendo:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Profili rilevanti per l'operatore da tenere a mente:

- [`http`](https://github.com/MythicC2Profiles/http): traffico GET/POST asincrono di base.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): traffico HTTP più flessibile con più domini di callback, rotazione fail-over/round-robin, header/parametri di query personalizzati e trasformazioni dei messaggi (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) inserite in cookie, header, parametri di query o body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): shaping dei messaggi HTTP guidato da JSON/TOML quando il profilo statico `http` è troppo riconoscibile.

### Wrapper payloads

I wrapper payloads ti permettono di mantenere la stessa logica dell'agent cambiando però la rappresentazione su disco che viene consegnata o persistita.

- `service_wrapper`: trasforma un altro payload in un eseguibile Windows service, utile quando il percorso di esecuzione richiede un binario service valido.
- `scarecrow_wrapper`: avvolge shellcode compatibile con il loader ScareCrow per generare output basati su loader come EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo è un agent Windows scritto in C# usando il .NET Framework 4.0, progettato per essere usato nelle offerte di training di SpecterOps.

Installalo con:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Note sulla build/profile attuale

- Apollo può attualmente emettere payload `WinExe`, `Shellcode`, `Service`, e `Source`.
- I profili Apollo comunemente usati sono `http`, `httpx`, `smb`, `tcp`, e `websocket`.
- `httpx` è di solito l'opzione più flessibile quando servono domain rotation, supporto proxy, custom message placement, e message transforms invece del vecchio profilo statico `http`.
- Apollo supporta wrapper payloads come `service_wrapper` e `scarecrow_wrapper`.
- `register_file` e `register_assembly` sono le primitive di staging per `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, e `powerpick`. Nelle build attuali di Apollo, questi staged artifacts sono cacheati lato client come blob AES256 protetti da DPAPI.
- I risultati di `ls` e `ps` si integrano במיוחד bene con i browser scripts di Mythic e con il file/process browser, il che rende il triage dell'operatore notevolmente più veloce nelle operazioni collaborative.

Questo agent ha molti comandi che lo rendono molto simile a Beacon di Cobalt Strike con alcune aggiunte. Tra questi, supporta:

### Azioni comuni

- `cat`: Stampa il contenuto di un file
- `cd`: Cambia la directory di lavoro corrente
- `cp`: Copia un file da una posizione a un'altra
- `ls`: Elenca file e directory nella directory corrente o nel path specificato
- `ifconfig`: Ottiene gli adattatori e le interfacce di rete
- `netstat`: Ottiene informazioni sulle connessioni TCP e UDP
- `pwd`: Stampa la directory di lavoro corrente
- `ps`: Elenca i processi in esecuzione sul sistema target (con info aggiuntive)
- `jobs`: Elenca tutti i job in esecuzione associati a tasking di lunga durata
- `download`: Scarica un file dal sistema target alla macchina locale
- `upload`: Carica un file dalla macchina locale al sistema target
- `reg_query`: Interroga chiavi e valori del registry sul sistema target
- `reg_write_value`: Scrive un nuovo valore in una chiave specificata del registry
- `sleep`: Cambia l'intervallo di sleep dell'agent, che determina quanto spesso effettua il check-in con il server Mythic
- E molti altri, usa `help` per vedere l'elenco completo dei comandi disponibili.

### Privilege escalation

- `getprivs`: Abilita quanti più privilegi possibile sul token del thread corrente
- `getsystem`: Apre un handle verso winlogon e duplica il token, elevando di fatto i privilegi a livello SYSTEM
- `make_token`: Crea una nuova sessione di logon e la applica all'agent, consentendo l'impersonation di un altro utente
- `steal_token`: Ruba un token primario da un altro processo, consentendo all'agent di impersonare l'utente di quel processo
- `pth`: Attacco Pass-the-Hash, che consente all'agent di autenticarsi come un utente usando il loro hash NTLM senza bisogno della password in chiaro
- `mimikatz`: Esegue comandi Mimikatz per estrarre credenziali, hash e altre informazioni sensibili dalla memoria o dal database SAM
- `rev2self`: Ripristina il token dell'agent al suo token primario, abbassando di fatto i privilegi al livello originale
- `ppid`: Cambia il processo padre per i job di post-exploitation specificando un nuovo parent process ID, consentendo un miglior controllo sul contesto di esecuzione dei job
- `printspoofer`: Esegue comandi PrintSpoofer per bypassare le misure di sicurezza dello spooler di stampa, consentendo privilege escalation o code execution
- `dcsync`: Sincronizza le chiavi Kerberos di un utente sulla macchina locale, consentendo offline password cracking o ulteriori attacchi
- `ticket_cache_add`: Aggiunge un ticket Kerberos alla sessione di logon corrente o a una specificata, consentendo il riutilizzo del ticket o l'impersonation

### Esecuzione di processi

- `assembly_inject`: Consente di iniettare un .NET assembly loader in un processo remoto
- `blockdlls`: Blocca il caricamento di DLL non firmate da Microsoft nei job di post-exploitation
- `execute_assembly`: Esegue un .NET assembly nel contesto dell'agent
- `execute_coff`: Esegue un file COFF in memoria, consentendo l'esecuzione in-memory di codice compilato
- `execute_pe`: Esegue un eseguibile unmanaged (PE)
- `get_injection_techniques`: Mostra le tecniche di injection disponibili e quella attualmente selezionata
- `inline_assembly`: Esegue un .NET assembly in un AppDomain usa e getta, consentendo l'esecuzione temporanea di codice senza influire sul processo principale dell'agent
- `register_assembly`: Registra un .NET assembly per un'esecuzione successiva
- `register_file`: Registra un file nella cache dell'agent per successivi tasking `execute_*` o PowerShell
- `run`: Esegue un binario sul sistema target, usando il PATH del sistema per trovare l'eseguibile
- `set_injection_technique`: Cambia la primitive di injection usata dai job di post-exploitation
- `shinject`: Inietta shellcode in un processo remoto, consentendo l'esecuzione in-memory di codice arbitrario
- `inject`: Inietta shellcode dell'agent in un processo remoto, consentendo l'esecuzione in-memory del codice dell'agent
- `spawn`: Avvia una nuova sessione dell'agent nell'eseguibile specificato, consentendo l'esecuzione di shellcode in un nuovo processo
- `spawnto_x64` and `spawnto_x86`: Cambia il binario predefinito usato nei job di post-exploitation con un path specificato invece di usare `rundll32.exe` senza parametri, che è molto rumoroso.

### Mythic Forge

Questo consente di **caricare file COFF/BOF** dalla Mythic Forge, che è un repository di payload e strumenti precompilati che possono essere eseguiti sul sistema target. Con tutti i comandi che possono essere caricati sarà possibile eseguire azioni comuni lanciandoli nel processo corrente dell'agent come BOF (di solito con una migliore OPSEC rispetto all'avvio di un processo separato).

Inizia a installarli con:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Poi, usa `forge_collections` per mostrare i moduli COFF/BOF dal Mythic Forge, così da poterli selezionare e caricarli nella memoria dell'agent per l'esecuzione. Per default, le seguenti 2 collection vengono aggiunte in Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Dopo che un modulo è caricato, apparirà nella lista come un altro comando, ad esempio `forge_bof_sa-whoami` o `forge_bof_sa-netuser`.

### PowerShell & scripting execution

- `powershell_import`: Importa un nuovo script PowerShell (.ps1) nella cache dell'agent per una successiva esecuzione
- `powershell`: Esegue un comando PowerShell nel contesto dell'agent, consentendo scripting avanzato e automazione
- `powerpick`: Inietta un assembly loader PowerShell in un processo sacrificabile ed esegue un comando PowerShell (senza logging di powershell).
- `psinject`: Esegue PowerShell in un processo specificato, consentendo l'esecuzione mirata di script nel contesto di un altro processo
- `shell`: Esegue un comando shell nel contesto dell'agent, simile all'esecuzione di un comando in cmd.exe

### Lateral Movement

- `jump_psexec`: Usa la tecnica PsExec per muoversi lateralmente verso un nuovo host copiando prima l'eseguibile dell'agent Apollo (apollo.exe) ed eseguendolo.
- `jump_wmi`: Usa la tecnica WMI per muoversi lateralmente verso un nuovo host copiando prima l'eseguibile dell'agent Apollo (apollo.exe) ed eseguendolo.
- `link` and `unlink`: Crea e rimuove collegamenti P2P (ad esempio via SMB/TCP) tra callback.
- `wmiexecute`: Esegue un comando sul sistema locale o remoto specificato usando WMI, con credenziali opzionali per l'impersonation.
- `net_dclist`: Recupera un elenco di domain controller per il dominio specificato, utile per identificare potenziali target per lateral movement.
- `net_localgroup`: Elenca i gruppi locali sul computer specificato, usando localhost per default se non viene specificato alcun computer.
- `net_localgroup_member`: Recupera l'appartenenza a un gruppo locale per un gruppo specificato sul computer locale o remoto, consentendo l'enumeration di utenti in gruppi specifici.
- `net_shares`: Elenca le share remote e la loro accessibilità sul computer specificato, utile per identificare potenziali target per lateral movement.
- `socks`: Abilita un proxy conforme a SOCKS 5 sulla rete target, consentendo il tunneling del traffico attraverso l'host compromesso. Compatibile con strumenti come proxychains.
- `rpfwd`: Avvia l'ascolto su una porta specificata sull'host target e inoltra il traffico attraverso Mythic verso un IP e una porta remoti, consentendo l'accesso remoto ai servizi sulla rete target.
- `listpipes`: Elenca tutte le named pipe sul sistema locale, cosa che può essere utile per lateral movement o privilege escalation interagendo con i meccanismi IPC.

Per le primitive di esecuzione WMI di livello inferiore usate sotto `jump_wmi` o `wmiexecute`, consulta [WmiExec](lateral-movement/wmiexec.md). Per pattern di pivoting più ampi, consulta [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Mostra informazioni dettagliate su comandi specifici o informazioni generali su tutti i comandi disponibili nell'agent.
- `clear`: Contrassegna i task come 'cleared' così non possono essere presi dagli agent. Puoi specificare `all` per cancellare tutti i task oppure `task Num` per cancellare un task specifico.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon è un agent Golang che compila in eseguibili **Linux e macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Note sulla build/profilo attuali

- Le build attuali di Poseidon targettizzano Linux e macOS su entrambi `x86_64` e `arm64`.
- I formati di output supportati includono eseguibili nativi oltre a output in stile shared-library come `dylib` e `so`.
- Poseidon supporta `http`, `websocket`, `tcp`, e `dynamichttp`, e i builder attuali espongono impostazioni multi-egress come `egress_order` e threshold di failover.
- Opzioni di build-time come `proxy_bypass` e `garble` vale la pena controllarle quando ti serve un comportamento di rete più pulito o un'ulteriore offuscazione del binary Go.

Per tradecraft specifico su macOS relativo a operazioni basate su Mythic, abuso di JAMF, o idee di MDM-as-C2, consulta [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Quando usato su Linux o macOS ha alcuni comandi interessanti:

### Azioni comuni

- `cat`: Stampa il contenuto di un file
- `cd`: Cambia la directory di lavoro corrente
- `chmod`: Cambia i permessi di un file
- `config`: Visualizza la config corrente e le informazioni dell'host
- `cp`: Copia un file da una posizione a un'altra
- `curl`: Esegue una singola richiesta web con header e metodo opzionali
- `upload`: Carica un file sul target
- `download`: Scarica un file dal sistema target alla macchina locale
- E molti altri

### Cerca informazioni sensibili

- `triagedirectory`: Trova file interessanti all'interno di una directory su un host, come file sensibili o credenziali.
- `getenv`: Ottiene tutte le variabili d'ambiente correnti.

### Movimento laterale

- `ssh`: SSH verso l'host usando le credenziali designate e apre una PTY senza avviare ssh.
- `sshauth`: SSH verso l'host o gli host specificati usando le credenziali designate. Puoi anche usarlo per eseguire un comando specifico sugli host remoti via SSH o per usare SCP per i file.
- `link_tcp`: Collega a un altro agent over TCP, consentendo la comunicazione diretta tra agent.
- `link_webshell`: Collega a un agent usando il profilo P2P webshell, consentendo accesso remoto all'interfaccia web dell'agent.
- `rpfwd`: Avvia o interrompe un Reverse Port Forward, consentendo accesso remoto ai servizi sulla rete target.
- `socks`: Avvia o interrompe un proxy SOCKS5 sulla rete target, consentendo il tunneling del traffico attraverso l'host compromesso. Compatibile con tool come proxychains.
- `portscan`: Scansiona gli host per porte aperte, utile per identificare potenziali target per movimento laterale o ulteriori attacchi.

### Esecuzione dei processi

- `shell`: Esegue un singolo comando shell via /bin/sh, consentendo l'esecuzione diretta di comandi sul sistema target.
- `run`: Esegue un comando da disco con argomenti, consentendo l'esecuzione di binary o script sul sistema target.
- `pty`: Apre una PTY interattiva, consentendo l'interazione diretta con la shell sul sistema target.




## Riferimenti

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
