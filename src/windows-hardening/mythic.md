# Mythic

{{#include ../banners/hacktricks-training.md}}

## Cos'è Mythic?

Mythic è un framework open-source, modulare e collaborativo di command and control (C2), progettato per il red teaming. Consente agli operatori di gestire e distribuire agenti (payload) su diversi sistemi operativi, tra cui Windows, Linux e macOS. Mythic offre un'interfaccia utente browser per la gestione delle attività di più operatori, la gestione dei file, la gestione di SOCKS/rpfwd e la generazione di payload.

A differenza dei framework monolitici, il repository Mythic non include tipi di payload o profili C2. Gli agenti, i wrapper e i profili C2 vengono in genere installati come componenti esterni e possono essere aggiornati indipendentemente dal core di Mythic.

### Installazione

Per installare Mythic, segui le istruzioni nel **[repository Mythic](https://github.com/its-a-feature/Mythic)** ufficiale. Una procedura di bootstrap comune, eseguita dalla directory Mythic, è:

```bash
sudo make
sudo ./mythic-cli start
```

Se Mythic è già in esecuzione, di solito puoi aggiungere un nuovo agent o profile con `./mythic-cli install github ...` e poi riavviare Mythic oppure avviare direttamente il nuovo componente.

### Agents

Mythic supporta più agent, ovvero i **payload che eseguono attività sui sistemi compromessi**. Ogni agent può essere personalizzato in base a esigenze specifiche ed eseguito su diversi sistemi operativi.

Per impostazione predefinita, Mythic non ha agent installati. Gli agent della community open source si trovano in [**https://github.com/MythicAgents**](https://github.com/MythicAgents); la [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) è utile per verificare rapidamente i sistemi operativi supportati, i formati dei payload, i wrapper e i profili C2.<sup>[[1]](#references)</sup>

Per installare un agent da questa organizzazione, puoi eseguire:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

La forma `sudo -E` è utile quando installi da un ambiente non root. Puoi aggiungere nuovi agent con il comando precedente anche se Mythic è già in esecuzione.

### C2 Profiles

I profili C2 in Mythic definiscono **come gli agent comunicano con il server Mythic**. Specificano il protocollo di comunicazione, i metodi di crittografia e altre impostazioni. Puoi creare e gestire i profili C2 tramite l'interfaccia web di Mythic.

Per impostazione predefinita, Mythic viene installato senza profili; tuttavia, è possibile scaricarne alcuni dal repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) eseguendo:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Profili attualmente rilevanti per gli operatori da tenere a mente:

- [`http`](https://github.com/MythicC2Profiles/http): traffico GET/POST asincrono di base.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): traffico HTTP più flessibile, con più domini callback, rotazione fail-over/round-robin, intestazioni/parametri di query personalizzati e trasformazioni dei messaggi (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) inserite nei cookie, nelle intestazioni, nei parametri di query o nel corpo.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): modellazione dei messaggi HTTP basata su JSON/TOML, quando il profilo statico `http` è troppo riconoscibile.

### Note aggiornate sulle piattaforme

- Molti agent e profili pubblici ora vengono installati con immagini remote di container precompilate.
  Se fai il fork di un componente o applichi una patch localmente e Mythic continua a usare il vecchio
  comportamento, controlla le voci `.env` generate per `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT` e `*_USE_VOLUME`; impostare
  `*_USE_BUILD_CONTEXT="true"` è solitamente ciò che fa ricompilare Mythic dal tuo contesto Docker locale,
  invece di riutilizzare silenziosamente l'immagine remota.
- Gli script del browser sono una delle funzionalità di Mythic più utili per migliorare la qualità del lavoro degli operatori: possono trasformare l'output grezzo dei comandi in tabelle, visualizzatori di screenshot, link di download, link di ricerca e pulsanti che avviano tasking successivi direttamente dall'interfaccia utente. Le versioni attuali di Mythic consentono a ogni operatore di mantenere i propri script, attivarli o disattivarli globalmente o per singolo task e ottenere i risultati migliori quando gli agent restituiscono JSON strutturato anziché testo semplice. Sono particolarmente utili per i flussi di lavoro ripetitivi con `ls`, `ps`, triage e file browser.<sup>[[4]](#references)[[6]](#references)</sup>
- Le versioni più recenti di Mythic supportano anche il tasking interattivo e i pattern Push C2, che riducono la necessità di polling con `sleep 0` durante operazioni intensive di PTY/SOCKS/rpfwd. Quando un agent/profilo li supporta, in genere comportano un overhead inferiore rispetto a martellare il server con check-in continui solo per mantenere utilizzabile un canale interattivo.<sup>[[3]](#references)</sup>
- I builder di Mythic dell'era 3.4 sono più consapevoli del contesto di quanto lascino intendere le guide meno recenti: ora i parametri di build possono essere raggruppati o nascosti in base al sistema operativo selezionato o ad altre opzioni di build; i tipi di payload possono dichiarare se supportano più profili C2 o più istanze dello stesso C2 in una singola build; inoltre, le deviazioni dei parametri C2 consentono a un agent di nascondere i campi che non implementa. Questo è importante quando si passa da `http`, `httpx`, `smb`, `tcp` e `websocket`, perché le opzioni di build valide e sicure non sono più presentate in un unico modulo statico.<sup>[[5]](#references)</sup>
- Se stai creando una coppia agent/profilo personalizzata e non vuoi il formato dei messaggi JSON di Mythic o la crittografia predefinita sul wire, usa un
  `translation_container`: Mythic rimuove l'UUID, passa il blob crittografato e il materiale della chiave al translator tramite gRPC e si aspetta in risposta byte nativi dell'agent. È il modo più pulito per supportare protocolli binari, framing personalizzato o crittografia lato agent senza riscrivere l'intero server.
- Ricorda che le callback collegate/P2P non si limitano a inoltrare il tasking. Il flusso `get_tasking` di Mythic può trasportare anche risposte e dati `delegates`,
  `socks`, `rpfwd` e `interactive`. In pratica, una callback di egress può gestire callback interne e canali pivot nello stesso ciclo di polling; se gli agent figli effettuano autonomamente check-in periodici, `get_delegate_tasks=false` impedisce al parent di consumare accidentalmente i job in coda della callback interna.

### Payload wrapper

I payload wrapper consentono di mantenere la stessa logica dell'agent modificando la rappresentazione su disco che viene consegnata o salvata.

- `service_wrapper`: trasforma un altro payload in un eseguibile Windows service, utile quando il percorso di esecuzione richiede un binario service valido.
- `scarecrow_wrapper`: avvolge shellcode compatibile con il loader ScareCrow per generare output basati su loader, come EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo è un agent Windows scritto in C# usando .NET Framework 4.0, progettato per essere utilizzato nei programmi di formazione di SpecterOps.<sup>[[2]](#references)</sup>

Installalo con:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Note sulla build e sui profili attuali

- Apollo può attualmente generare payload `WinExe`, `Shellcode`, `Service` e `Source`.
- I profili Apollo più usati sono `http`, `httpx`, `smb`, `tcp` e `websocket`.
- `httpx` è di solito l’opzione più flessibile quando servono rotazione dei domini, supporto proxy, posizionamento personalizzato dei messaggi e trasformazioni dei messaggi, invece del vecchio profilo statico `http`.
- Apollo è uno degli agent community più completi e attualmente espone integrazioni lato Mythic come browser scripts, viste file/processo, screenshot, keylogging, SOCKS, rpfwd, Push C2 e routing P2P.
- Apollo supporta payload wrapper come `service_wrapper` e `scarecrow_wrapper`.
- Apollo supporta il caricamento dinamico dei comandi: puoi mantenere leggero il payload iniziale e caricare altri comandi o moduli Forge in seguito, invece di compilare tutte le funzionalità post-ex nel primo build.
- Quando genera output shellcode, il builder attuale di Apollo espone anche le opzioni di formato Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) e il comportamento di bypass Donut (`None`, `Abort on fail`, `Continue on fail`). È utile se l’obiettivo finale è riavvolgere lo shellcode con `service_wrapper`, `scarecrow_wrapper` o un loader personalizzato.
- `register_file` e `register_assembly` sono le primitive di staging per `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` e `powerpick`. Nei build Apollo attuali, questi artefatti staged vengono memorizzati nella cache lato client come blob AES256 protetti con DPAPI.
- I risultati di `ls` e `ps` si integrano particolarmente bene con i browser scripts di Mythic e con il browser di file/processi, velocizzando sensibilmente il triage dell’operator nelle operazioni collaborative.
- I job fork-and-run ereditano le impostazioni del processo sacrificabile da
  `spawnto_x86` / `spawnto_x64`, la selezione del parent da `ppid` e
  poi usano la primitiva di injection attualmente selezionata. In pratica, ciò significa
  che le impostazioni OPSEC per un comando spesso influiscono contemporaneamente su
  `execute_assembly`,
  `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` e `spawn`.
- I backend di injection Apollo attualmente documentati includono `CreateRemoteThread`,
  `QueueUserAPC` (stile early-bird) e `NtCreateThreadEx` tramite syscall. Usa
  `get_injection_techniques` prima di attività post-ex rumorose e
  `set_injection_technique` se devi passare da una primitiva
  incompatibile con il target o con il comando che vuoi eseguire.
- `blockdlls` influisce solo sui processi sacrificabili creati per i job post-exploitation. Insieme a un target `spawnto_x64` meno sospetto del predefinito `rundll32.exe` senza argomenti, è una delle modifiche più semplici da applicare lato Apollo
  prima di eseguire task basati intensamente su assembly/PowerShell.

### Pipeline di build di un agent .NET consapevole delle detection

Un fork di Apollo consapevole delle detection va considerato un **problema dell’intero sistema di build**, non un passaggio finale con `obfuscate.exe`. Questo case study integra la [metodologia generale di AV evasion](av-bypass.md) e gli [strumenti di ispezione .NET](../reversing/reversing-tools-basic-methods/README.md): le modifiche agli identificatori wire, ai metadati IL, al packaging delle dipendenze, alla reflection e ai task compilati dinamicamente formano un unico confine di compatibilità.<sup>[[8]](#references)</sup>

#### Mutazione del protocollo consapevole di YARA

Esamina le regole pubbliche per file e memoria prima di modificare il codice. Per esempio, `Multi_Trojan_Mythic_4beb7e17` di Elastic scatta quando sono presenti almeno **7 elementi su 11** tra le stringhe JSON/action di Mythic, tra cui `task_id`, `post_response`, `c2_profile`, `get_tasking` e `get_delegate_tasks`. Rinominare abbastanza campi può aggirare tale soglia, ma si tratta di valori del protocollo, non di simboli cosmetici: l’agent e l’implementazione corrispondente del server/profilo devono essere modificati insieme.<sup>[[7]](#references)[[8]](#references)</sup>

Questo rimuove solo un insieme di caratteristiche statiche. La cadenza dei check-in, la struttura dei messaggi, il flusso task/response e la ricostruzione delle stringhe runtime possono restare indicatori comportamentali o di memoria; quindi, convalida sia l’artefatto compilato sia una callback effettivamente eseguita, invece di considerare una scansione delle stringhe senza risultati come un successo.<sup>[[8]](#references)</sup>

#### Esegui il merge prima di applicare trasformazioni globali

L’embedded delle risorse con strumenti come Costura lascia gli assembly di supporto come risorse compresse. Un obfuscator che esamina solo il modulo esterno non rileva quindi i nomi dei tipi e i metadati al loro interno; obfuscando ogni DLL separatamente, si rischia invece di assegnare nomi incompatibili ai contratti tra assembly. Esegui prima il merge degli output di build a livello IL (per esempio con [ILRepack](https://github.com/gluck/il-repack)), poi applica un’unica mappa di rinomina al modulo risultante.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

Un pass personalizzato può usare [dnlib](https://github.com/0xd4d/dnlib) per le trasformazioni di IL/metadata gestiti e [AsmResolver](https://github.com/Washi1337/AsmResolver) per il patching di PE/risorse dopo la scrittura. Nel caso di studio, le istruzioni `ldstr` idonee sono state convertite in chiamate a token interi/decryptor, supportate da una nuova chiave rolling-XOR di 16 byte, mentre i simboli e i namespace sono stati associati a nomi plausibili, in stile aziendale, anziché a identificatori brevi e sequenziali. Altri pass hanno rimosso attributi selezionati del compilatore/debugger, ripulito riferimenti a merger/embedding, rinominato risorse e modificato le informazioni sulla versione. Genera nuovi nomi, dead code e materiale di cifratura per ogni build indipendente: cambiare il testo cifrato rimuove i byte stabili, ma un decryptor stabile o uno schema di trasformazione riconoscibile costituisce a sua volta una signature.<sup>[[8]](#references)</sup>

#### Mantieni sincronizzati i task dinamici con il payload

Apollo può compilare il codice sorgente dei task lato server, inviare i byte della DLL e caricarli con `Assembly.Load()`. Dopo aver rinominato i tipi pubblici del base agent, i task successivi compilati in base all'API originale non vengono più risolti. Considera la mappa di rinomina esportata come un artefatto ABI specifico del payload:<sup>[[8]](#references)</sup>

1. Associa la mappa e il contesto dei tipi all'identificatore esatto del payload/build.
2. Per ogni build di un task, recupera la mappa e riscrivi un albero sorgente temporaneo.
3. Riscrivi solo i riferimenti risolti a namespace, tipi, tipi annidati/generici, campi e proprietà, quindi compila in base all'assembly unito e offuscato.
4. Rifiuta le mappe mancanti o non corrispondenti prima di distribuire il task ed esegui un test di inizializzazione dopo la compilazione.

La sostituzione globale alla cieca non è sicura, perché un identificatore può comparire anche in una stringa, una dichiarazione locale, un accesso a un membro, un tipo del framework o un namespace non correlato. Se si mantiene un riscrittore basato su testo/regex, proteggi esplicitamente questi contesti e testalo con test di regressione ogni volta che cambia lo schema della mappa o un pass di rinomina.<sup>[[8]](#references)</sup>

#### Rendi i contratti di reflection indipendenti dai namespace

Il codice di discovery che verifica `t.FullName.StartsWith("Tasks.")` rende il namespace determinante e smette di funzionare dopo la rimappatura dei namespace. Esegui la discovery in base a una relazione stabile tra tipi, mantenendo invariati i nomi delle classi di comando se il dispatch usa ancora `t.Name`:<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Mantieni una allowlist esplicita di nomi visibili tramite reflection, campi del serializer, entry point e API tra assembly che non devono essere rinominati. Infine, decompila il risultato con ILSpy/dnSpy, analizza sia le rappresentazioni su file che in memoria e prova ogni percorso dei comandi e del loader in un EDR lab; una build che si avvia correttamente può comunque contenere task compromessi dalla rinomina o comportamenti rilevati solo durante l'esecuzione.<sup>[[8]](#references)</sup>

Questo agent dispone di molti comandi che lo rendono molto simile al Beacon di Cobalt Strike, con alcune funzionalità aggiuntive. Tra questi, supporta:

### Azioni comuni

- `cat`: Stampa il contenuto di un file
- `cd`: Cambia la directory di lavoro corrente
- `cp`: Copia un file da una posizione a un'altra
- `ls`: Elenca i file e le directory nella directory corrente o nel percorso specificato
- `ifconfig`: Recupera informazioni sulle schede e interfacce di rete
- `netstat`: Recupera informazioni sulle connessioni TCP e UDP
- `pwd`: Stampa la directory di lavoro corrente
- `ps`: Elenca i processi in esecuzione sul sistema target (con informazioni aggiuntive)
- `jobs`: Elenca tutti i job in esecuzione associati a task di lunga durata
- `download`: Scarica un file dal sistema target al computer locale
- `upload`: Carica un file dal computer locale al sistema target
- `reg_query`: Interroga le chiavi e i valori del registro sul sistema target
- `reg_write_value`: Scrive un nuovo valore nella chiave di registro specificata
- `sleep`: Modifica l'intervallo di sleep dell'agent, che determina la frequenza con cui contatta il server Mythic
- E molti altri: usa `help` per visualizzare l'elenco completo dei comandi disponibili.

### Escalation dei privilegi

- `getprivs`: Abilita il maggior numero possibile di privilegi nel token del thread corrente
- `getsystem`: Apre un handle a winlogon e duplica il token, effettuando di fatto un'escalation dei privilegi al livello SYSTEM
- `make_token`: Crea una nuova sessione di logon e la applica all'agent, consentendo di impersonare un altro utente
- `steal_token`: Ruba un token primario da un altro processo, consentendo all'agent di impersonare l'utente di quel processo
- `pth`: Attacco Pass-the-Hash, consente all'agent di autenticarsi come utente usando il suo hash NTLM senza bisogno della password in chiaro
- `mimikatz`: Esegue comandi Mimikatz per estrarre credenziali, hash e altre informazioni sensibili dalla memoria o dal database SAM
- `rev2self`: Ripristina il token primario dell'agent, rimuovendo di fatto i privilegi acquisiti e tornando al livello originale
- `ppid`: Cambia il processo padre dei job di post-exploitation specificando un nuovo ID di processo padre, consentendo un maggiore controllo sul contesto di esecuzione dei job
- `printspoofer`: Esegue comandi PrintSpoofer per aggirare le misure di sicurezza dello spooler di stampa e consentire l'escalation dei privilegi o l'esecuzione di codice
- `dcsync`: Sincronizza le chiavi Kerberos di un utente sul computer locale, consentendo il cracking offline delle password o ulteriori attacchi
- `ticket_cache_add`: Aggiunge un ticket Kerberos alla sessione di logon corrente o a una sessione specificata, consentendo di riutilizzare il ticket o di impersonare un utente

### Esecuzione dei processi

- `assembly_inject`: Consente di iniettare un loader di assembly .NET in un processo remoto
- `blockdlls`: Impedisce il caricamento di DLL non firmate da Microsoft nei job di post-exploitation
- `execute_assembly`: Esegue un assembly .NET nel contesto dell'agent
- `execute_coff`: Esegue un file COFF in memoria, consentendo l'esecuzione in memoria di codice compilato
- `execute_pe`: Esegue un eseguibile non gestito (PE)
- `keylog_inject`: Inietta un keylogger in un altro processo e trasmette le battute di tastiera alla vista keylog di Mythic
- `screenshot` / `screenshot_inject`: Cattura direttamente il desktop corrente oppure
  inietta un assembly per gli screenshot in un processo/sessione target
- `get_injection_techniques`: Mostra le tecniche di injection disponibili e quella attualmente selezionata
- `inline_assembly`: Esegue un assembly .NET in un AppDomain temporaneo, consentendo l'esecuzione temporanea di codice senza influire sul processo principale dell'agent
- `register_assembly`: Registra un assembly .NET per eseguirlo in seguito
- `register_file`: Registra un file nella cache dell'agent per i successivi task `execute_*` o PowerShell
- `run`: Esegue un binario sul sistema target, usando il PATH di sistema per individuare l'eseguibile
- `set_injection_technique`: Cambia la primitiva di injection usata dai job di post-exploitation
- `shinject`: Inietta shellcode in un processo remoto, consentendo l'esecuzione in memoria di codice arbitrario
- `inject`: Inietta shellcode dell'agent in un processo remoto, consentendo l'esecuzione in memoria del codice dell'agent
- `spawn`: Avvia una nuova sessione agent nell'eseguibile specificato, consentendo l'esecuzione di shellcode in un nuovo processo
- `spawnto_x64` e `spawnto_x86`: Cambiano il binario predefinito usato nei job di post-exploitation impostando un percorso specifico, invece di usare `rundll32.exe` senza parametri, che è molto rumoroso.

### Mythic Forge

Consente di **caricare file COFF/BOF** da Mythic Forge, un repository di payload e strumenti precompilati che possono essere eseguiti sul sistema target. Grazie a tutti i comandi caricabili, sarà possibile svolgere azioni comuni eseguendoli come BOF nel processo corrente dell'agent (di solito con un OPSEC migliore rispetto all'avvio di un processo separato).

Inizia a installarli con:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Quindi, usa `forge_collections` per mostrare i moduli COFF/BOF di Mythic Forge, così da poterli selezionare e caricare nella memoria dell'agent per l'esecuzione. Per impostazione predefinita, in Apollo vengono aggiunte le seguenti 2 collection:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Una volta caricato un modulo, apparirà nell'elenco come un altro comando, ad esempio `forge_bof_sa-whoami` o `forge_bof_sa-netuser`.

Per i BOF, ricorda che Forge **non** passa semplicemente ad Apollo un'unica stringa di argomenti. Mappa i parametri BOF nel formato typed-array di Mythic e poi li inoltra al flusso `execute_coff` di Apollo. Se un BOF caricato da Forge si comporta in modo strano, controlla i tipi di argomenti BOF previsti e l'entrypoint, invece di limitarti a verificare la riga di comando inserita. Nota inoltre che il loader BOF più recente di Apollo ha modificato la gestione degli argomenti rispetto alle build molto più vecchie dell'era 2.3.1: i BOF obsoleti o le vecchie collection possono quindi non funzionare semplicemente perché sono cambiate le aspettative di marshaling.

### Esecuzione di PowerShell e script

- `powershell_import`: Importa un nuovo script PowerShell (.ps1) nella cache dell'agent per eseguirlo in seguito
- `powershell`: Esegue un comando PowerShell nel contesto dell'agent, consentendo scripting e automazione avanzati
- `powerpick`: Inietta un assembly loader PowerShell in un processo sacrificabile ed esegue un comando PowerShell (senza logging di PowerShell).
- `psinject`: Esegue PowerShell in un processo specificato, consentendo l'esecuzione mirata di script nel contesto di un altro processo
- `shell`: Esegue un comando shell nel contesto dell'agent, come se si eseguisse un comando in cmd.exe

### Movimento laterale

- `jump_psexec`: Usa la tecnica PsExec per spostarsi lateralmente su un nuovo host, copiandovi prima l'eseguibile dell'agent Apollo (apollo.exe) ed eseguendolo.
- `jump_wmi`: Usa la tecnica WMI per spostarsi lateralmente su un nuovo host, copiandovi prima l'eseguibile dell'agent Apollo (apollo.exe) ed eseguendolo.
- `link` e `unlink`: Creano e interrompono link P2P (ad esempio tramite SMB/TCP) tra callback.
- `wmiexecute`: Esegue un comando sul sistema locale o su quello remoto specificato usando WMI, con credenziali facoltative per l'impersonificazione.
- `net_dclist`: Recupera un elenco di domain controller per il dominio specificato, utile per individuare potenziali obiettivi per il movimento laterale.
- `net_localgroup`: Elenca i gruppi locali sul computer specificato; se non viene specificato alcun computer, usa localhost.
- `net_localgroup_member`: Recupera l'appartenenza a un gruppo locale specificato sul computer locale o remoto, consentendo l'enumerazione degli utenti appartenenti a gruppi specifici.
- `net_shares`: Elenca le condivisioni remote e la loro accessibilità sul computer specificato, utile per individuare potenziali obiettivi per il movimento laterale.
- `socks`: Abilita un proxy compatibile con SOCKS 5 sulla rete di destinazione, consentendo il tunneling del traffico attraverso l'host compromesso. Compatibile con strumenti come proxychains.
- `rpfwd`: Avvia l'ascolto su una porta specificata sull'host di destinazione e inoltra il traffico tramite Mythic a un IP e una porta remoti, consentendo l'accesso remoto ai servizi sulla rete di destinazione.
- `listpipes`: Elenca tutte le named pipe sul sistema locale, utili per il movimento laterale o l'escalation dei privilegi tramite l'interazione con i meccanismi IPC.

Per le primitive WMI di esecuzione a basso livello usate da `jump_wmi` o `wmiexecute`, consulta [WmiExec](lateral-movement/wmiexec.md). Per una panoramica più ampia delle tecniche di pivoting, consulta [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Comandi vari
- `help`: Mostra informazioni dettagliate su comandi specifici o informazioni generali su tutti i comandi disponibili nell'agent.
- `clear`: Contrassegna le attività come «cancellate», impedendo agli agent di recuperarle. Puoi specificare `all` per cancellare tutte le attività o `task Num` per cancellare un'attività specifica.  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon è un agent Golang che viene compilato in eseguibili per **Linux e macOS**.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Note attuali su build/profilo

- Le build attuali di Poseidon sono destinate a Linux e macOS su `x86_64` e `arm64`.
- I formati di output supportati includono eseguibili nativi e output in stile libreria condivisa, come `dylib` e `so`.
- Poseidon supporta `http`, `websocket`, `tcp` e `dynamichttp`; i builder attuali espongono impostazioni multi-egress come `egress_order` e soglie di failover.
- I metadati attuali delle funzionalità di Poseidon pubblicizzano anche script per il browser, integrazione del browser con file/processi, tasking interattivo, keylogging, screenshot, Push C2, SOCKS, rpfwd e P2P: può quindi funzionare come un vero nodo pivot Linux/macOS, non solo come una semplice shell remota.
- Vale la pena verificare le opzioni in fase di build, come `proxy_bypass` e `garble`, quando servono un comportamento di rete più pulito o un'ulteriore offuscazione dei binari Go.
- `pty` è uno dei comandi più utili introdotti di recente per migliorare la qualità d'uso nelle operazioni
  Linux/macOS, perché apre una PTY interattiva e può esporre una porta lato Mythic per un'interazione più completa con il terminale, senza ricorrere al vecchio workaround
  `sleep 0` + SOCKS.
- La documentazione attuale di Poseidon è particolarmente interessante per le attività
  tradecraft incentrate su macOS: `jxa` esegue JavaScript for Automation in memoria,
  `screencapture` acquisisce il desktop dell'utente connesso, `clipboard_monitor` trasmette
  le modifiche al pasteboard, `execute_library` carica una dylib locale e ne chiama
  una funzione, e `libinject` forza un processo remoto a caricare una dylib su disco.
- Per i job di lunga durata, ricorda che Poseidon esegue le attività di post-exploitation
  in goroutine/thread cooperative, che non possono essere terminate forzatamente. La
  documentazione specifica inoltre che al momento non è disponibile un'offuscazione
  integrata dell'agent; quindi il tradecraft a livello di build/profilo è più importante rispetto agli implant commerciali fortemente
  offuscati.

Per il tradecraft specifico per macOS relativo alle operazioni basate su Mythic, all'abuso di JAMF o alle idee di MDM-as-C2, consulta [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

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

- `triagedirectory`: Trova file interessanti all'interno di una directory su un host, ad esempio file sensibili o credenziali.
- `getenv`: Recupera tutte le variabili d'ambiente attuali.

### Tradecraft specifico per macOS

- `jxa`: Esegue JavaScript for Automation in memoria tramite `OSAScript`, una funzione
  utile per la post-exploitation nativa su macOS senza depositare file di script
  separati.
- `clipboard_monitor`: Interroga il pasteboard e segnala le modifiche a Mythic;
  è utile nei workflow di furto di credenziali/token che si basano su copia/incolla.
- `screencapture`: Acquisisce il desktop dell'utente su macOS.
- `execute_library`: Carica una dylib dal disco e chiama una specifica funzione esportata.
- `libinject`: Inietta uno stub shellcode che forza un altro processo macOS a caricare una dylib dal disco.
- `persist_launchd`: Crea persistenza tramite LaunchAgent / LaunchDaemon direttamente dall'agent.

### Movimento laterale

- `ssh`: Si connette via SSH all'host usando le credenziali designate e apre una PTY senza avviare ssh.
- `sshauth`: Si connette via SSH agli host specificati usando le credenziali designate. Puoi anche usarlo per eseguire un comando specifico sugli host remoti via SSH o per trasferire file tramite SCP.
- `link_tcp`: Stabilisce un collegamento TCP con un altro agent, consentendo la comunicazione diretta tra agent.
- `link_webshell`: Stabilisce un collegamento con un agent usando il profilo P2P webshell, consentendo l'accesso remoto alla sua interfaccia web.
- `rpfwd`: Avvia o arresta un Reverse Port Forward, consentendo l'accesso remoto ai servizi sulla rete target.
- `socks`: Avvia o arresta un proxy SOCKS5 sulla rete target, consentendo il tunneling del traffico attraverso l'host compromesso. Compatibile con strumenti come proxychains.
- `portscan`: Esegue la scansione di host alla ricerca di porte aperte, utile per individuare potenziali target per il movimento laterale o ulteriori attacchi.

### Esecuzione dei processi

- `shell`: Esegue un singolo comando shell tramite /bin/sh, consentendo l'esecuzione diretta di comandi sul sistema target.
- `run`: Esegue un comando da disco con argomenti, consentendo l'esecuzione di binari o script sul sistema target.
- `pty`: Apre una PTY interattiva, consentendo l'interazione diretta con la shell sul sistema target.

## References

- [1] [Matrice delle funzionalità degli agent della community Mythic](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [README di Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2: novità principali: tasking interattivo, Push C2 e browser di file dinamico](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Script per il browser - Documentazione di Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Aggiornamenti da Mythic 3.3 a 3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Trasformare le operazioni Red Team con le gemme nascoste di Mythic: scripting del browser](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: regole YARA Multi_Trojan_Mythic](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Da fork a framework: cosa ci ha insegnato modificare Apollo sull'infiltrazione degli agent](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
