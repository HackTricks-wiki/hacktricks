# Metodologia di sicurezza degli AI Agent

{{#include ../banners/hacktricks-training.md}}

Una valutazione di un agent dovrebbe seguire il percorso **dall’input controllato dall’attaccante a un effetto osservabile esternamente**. Jailbreaking, modifiche del carattere e divulgazione del system prompt dimostrano che un canale di ragionamento può essere influenzato, ma il finding ad alto impatto è la catena che porta all’accesso ai dati, a un’azione non autorizzata tramite un tool, a un sink di injection downstream, alla persistenza o a un altro agent.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) è utile per classificare la copertura (dirottamento dell’obiettivo, uso improprio dei tool, abuso dei privilegi, supply chain, esecuzione di codice, avvelenamento della memoria, fiducia tra agent, errori a cascata, fiducia umana e agent rogue). Usa queste etichette dopo aver costruito un percorso di attacco end-to-end, invece di considerare il testo inatteso generato dal modello come il termine del test.<sup>[[1]](#references)[[2]](#references)</sup>

## Costruire la mappa del target

Prima di scrivere payload, registra queste cinque dimensioni per ogni workflow dell’agent:<sup>[[2]](#references)</sup>

| Dimensione | Cosa enumerare | Domanda di sicurezza |
|---|---|---|
| **Input non attendibile** | Parametri di chat/API, URL, documenti, email, ticket, voci di calendario, chunk recuperati, memoria, risultati dei tool e messaggi di agent peer | Dove può inserire contenuti un attaccante affinché in seguito entrino nel contesto del modello? |
| **Tool** | Nomi e schemi dei tool, effetti collaterali, esecuzione automatica, comportamento di conferma e tool caricati dinamicamente | Quali chiamate leggono segreti, modificano lo stato, inviano messaggi, eliminano dati, eseguono codice o trasferiscono valore? |
| **Autorità** | Delega utente, service account, token API, durata delle credenziali, ambito di tenant/risorsa e accesso alla rete | Con quale identità viene eseguita ogni chiamata e l’autorizzazione viene verificata di nuovo al confine del tool? |
| **Elaborazione** | Query builder, shell, URL fetcher, motori di template, interpreti, parser, operazioni sui file e deserializer | Dove i dati generati dal modello diventano sintassi per un altro interprete? |
| **Output** | Risposte, Markdown/HTML renderizzato, link, recupero di immagini, webhook, email, file, log, report, metriche e traffico tra agent peer | Quale canale osservabile può trasportare un segreto o attivare una richiesta secondaria? |

Non ridurre tutto a un elenco delle integrazioni pubblicizzate. Un artefatto utile collega ogni sorgente all’esatta posizione del contesto che raggiunge, ai tool disponibili in quel punto, alle credenziali usate da ciascun tool, all’interprete downstream e a ogni percorso di egress. Lo stesso tool può avere un impatto basso con un token di lettura per utente e un impatto critico con credenziali condivise da amministratore.<sup>[[2]](#references)</sup>

## Ricognizione

### Mappare ogni percorso di consegna e acquisizione

Inizia dalla superficie di consegna (web, mobile, API, email, piattaforma di chat, estensione del browser) e intercetta il traffico dal client al backend con un proxy. Esamina i campi nascosti dall’interfaccia, i parametri di ricerca/autocompletamento/filtro, gli oggetti che rappresentano lo stato della conversazione, i processi di upload e indicizzazione, le risposte dei tool e il traffico dei sub-agent. Per i client solo mobile potrebbe essere necessario un emulatore e strumentazione per aggirare il certificate pinning prima che diventi visibile il vero schema della richiesta.<sup>[[2]](#references)</sup>

Mappa poi lo stack sottostante al modello: framework di orchestrazione, composizione dei prompt, sistemi di retrieval e memoria, runtime (per esempio Python, container o WASM), volumi montati, servizi host, API interne, raggiungibilità dei metadati cloud e reti adiacenti. Le impostazioni predefinite del framework sono importanti perché alcune “chiamate ai tool” vengono implementate generando o valutando codice; il confine del runtime/sandbox determina se il risultato resta contenuto.<sup>[[2]](#references)</sup>

### Identificare il routing con probe non distruttive

Confronta una richiesta in scope con diverse richieste non correlate, conservando la risposta completa, il codice di stato, la latenza e il comportamento dello streaming. Un rifiuto stabile prima di qualsiasi ragionamento specifico sul task può indicare un gateway/classificatore separato; un rifiuto contestuale suggerisce che la richiesta ha raggiunto il modello; una risposta vuota o puramente estrattiva può indicare una ricerca per parole chiave o un retrieval limitato. Considerale ipotesi e confermale ripetendo lo stesso probe tramite campi API e percorsi di acquisizione alternativi.<sup>[[2]](#references)</sup>

La ricognizione è completa quando la valutazione è in grado di identificare la prima sorgente controllata dall’attaccante che modifica il comportamento dell’agent **e** i tool, le identità, gli interpreti e gli output raggiungibili da quella sorgente.<sup>[[2]](#references)</sup>

## Exploitation: superare un confine di fiducia

Testa i canali, non solo la formulazione del prompt. Inizia con un’injection diretta per stabilire cosa blocca il punto di accesso visibile, quindi ripeti l’intento equivalente tramite i percorsi meno visibili qui sotto:<sup>[[2]](#references)</sup>

- **Contenuti indiretti:** pagine, file, email, ticket, metadati, alt text, commenti HTML, testo fuori schermo o caratteri zero-width. Consulta [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) per le tecniche di consegna dei payload.
- **Retrieval e memoria:** avvelena contenuti che verranno recuperati in seguito o stati che saranno ricaricati nelle sessioni successive. Registra se l’eliminazione della sorgente originale rimuove il comportamento.
- **Output dei tool e agent peer:** inserisci il marker in una risposta di un tool o in un messaggio tra agent per verificare se il traffico interno aggira i filtri applicati solo all’input dell’utente e all’output finale.
- **Supply chain:** esamina descrittori dei tool, plugin, server connessi, skills, modelli e dipendenze come sorgenti di istruzioni attendibili. Per test specifici di MCP, consulta [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Approvazione umana:** confronta la chiamata strutturata effettiva al tool con il testo di approvazione generato dal modello. Verifica se l’influenza dell’attaccante può omettere la destinazione, l’ambito, gli oggetti coinvolti o gli effetti collaterali irreversibili.

Usa prima un marker univoco e innocuo. Conserva l’artefatto sorgente, il contesto assemblato se osservabile, la chiamata al tool selezionata, i dati di approvazione, la richiesta/risposta del backend e lo stato finale. In questo modo distingui l’influenza da una dichiarazione allucinata secondo cui un’azione sarebbe avvenuta.<sup>[[2]](#references)</sup>

### Testo formulato come policy in un tool-risk judge

Un tool gate basato su un modello può ricevere testo controllato dall’attaccante all’interno di un contesto di classificazione altrimenti utile. Per esempio, l’`AutoModeMiddleware` sperimentale di LangChain invia a un judge TypeSafe `is_risky` una chiamata al tool proposta, i suoi argomenti, una descrizione opzionale del tool e fino a 30 messaggi recenti. Blocca i tool configurati quando la probabilità Noul restituita è almeno `0.5`; i tool non elencati non vengono classificati da questo middleware.<sup>[[5]](#references)</sup> TypeSafe avverte inoltre che il testo avversario nello stato può influenzare una classificazione anche quando lo stato dovrebbe essere trattato come dati.<sup>[[6]](#references)</sup>

Una **policy contraffatta** è diversa dal semplice dichiarare di essere un system message. Inserisce etichette alternative o definizioni del rischio all’interno di uno stato con un livello di fiducia inferiore e invita il judge a usare tali definizioni al posto dei criteri definiti dallo sviluppatore. Nel test di Datadog, un `profile_description` modificabile dall’utente veniva copiato negli argomenti del tool insieme a `can_edit:false`. Il testo in stile policy sosteneva che un tentativo di scrittura fosse a basso rischio perché un controllo separato dei permessi lo avrebbe respinto prima di qualsiasi modifica. In 40 esecuzioni, il punteggio medio di `is_risky` è sceso da `0.893` a `0.290`, mentre una comparazione diretta con spoofing del ruolo ha registrato una media di `0.905`. Il fatto che la media sia scesa sotto `0.5` non dimostra che ogni singola chiamata abbia superato il gate, e l’esperimento **non** ha dimostrato una scrittura non autorizzata completata.<sup>[[7]](#references)</sup>

Quando testi questo confine, distingui il verdetto del classificatore dal risultato effettivo dell’autorizzazione del tool. Verifica quali campi modificabili raggiungono il judge, confronta la stessa azione proposta con e senza testo in stile policy e verifica lo stato finale in modo indipendente. Un controllo separato dei permessi deve comunque usare l’autorità del richiedente autenticato, non i diritti del service account del connector.<sup>[[7]](#references)</sup> Consulta [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) per altre modalità di errore dei classificatori; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) riguarda un diverso confine di routing e credenziali.

### Isolamento del contesto dei subagent

Un subagent non-fork del Claude Agent SDK riceve il proprio `AgentDefinition.prompt`, il prompt di delega e i tool disponibili, ma non il system prompt né la conversazione del parent. Se dalla sua definizione viene omesso `tools`, eredita i tool disponibili ai subagent; il file `CLAUDE.md` del progetto potrebbe comunque essere caricato. Di conseguenza, una restrizione del prompt presente solo nel parent è un confine inaffidabile quando il child può usare gli stessi tool di filesystem o esecuzione.<sup>[[4]](#references)</sup>

Testa il confine confrontando una richiesta diretta che il parent rifiuta con lo stesso task delegato a un subagent nominato. NCC Group riferisce che un’enumerazione di file del sistema operativo rifiutata è riuscita quando è stata riformulata per un child come innocua “mappa del layout”.<sup>[[3]](#references)</sup>

Esamina le effettive chiamate ai tool del child e la sua allowlist effettiva di tool, non solo la risposta finale del parent; verifica se il child ha avuto accesso a file a cui il parent non avrebbe acceduto.<sup>[[4]](#references)</sup> Si tratta di un errore nell’ereditarietà dei guardrail, non della prova di un [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) o di un container escape.<sup>[[3]](#references)[[4]](#references)</sup>

### Agent GUI mobile: istruzioni sullo schermo e riassegnazione delle azioni

Un agent GUI su telefono può inviare ogni screenshot a un modello cloud prima di scegliere la successiva azione tra app. Per testare l’**injection visiva indiretta**, inserisci testo controllato dall’attaccante in un SMS, un’email o una pagina che l’agent esaminerà durante un task autorizzato. Confronta un prompt diretto per il task con la stessa istruzione visibile solo nello screenshot, quindi esamina l’azione successiva e l’eventuale decisione relativa a un’operazione ad alto rischio. Nell’assistente valutato, `checkPrompt` lato client filtrava il testo diretto del task, ma non applicava un filtraggio equivalente ai contenuti degli screenshot. Questa variante mobile cross-app dell’[injection tramite screenshot degli agentic browser](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md) non è un modo per aggirare l’autenticazione dei componenti Android.<sup>[[9]](#references)</sup>

Un test illustrativo degli effetti collaterali usa un form controllato dall’attaccante che chiede all’agent di compilare campi sensibili e poi richiede a una persona di cliccare su “upload”, mentre la pagina invia i campi compilati non appena cambiano. Il passaggio del controllo a una persona non può proteggere i dati già inviati dal codice della pagina; verifica l’invio effettivo, invece di considerare la narrazione dell’agent come prova. La fonte presenta questo come un possibile pattern, non come una compromissione dimostrata di ogni assistente.<sup>[[9]](#references)</sup>

**GUI TOCTOU / riassegnazione delle azioni** è una modalità di errore distinta: l’agent pianifica un input sulla base di una schermata osservata a `t0`, ma l’interfaccia in primo piano cambia prima che l’input venga iniettato a `t1`.<sup>[[8]](#references)</sup> Uno screenshot successivo a `t2` non può annullare un’azione già eseguita.<sup>[[9]](#references)</sup> In un test Android autorizzato, il workflow riutilizzabile è:<sup>[[8]](#references)</sup>

1. Rileva le coordinate sullo schermo del controllo target e visualizza un controllo innocuo nella stessa posizione in un’app controllata.
2. Mantieni visibile questo carrier finché l’agent non lo osserva, quindi attiva una normale transizione in primo piano durante l’intervallo tra osservazione e azione.
3. Verifica se il tap pianificato raggiunge il controllo della nuova app e controlla lo stato risultante nell’app target, invece di basarti sulla narrazione dell’agent.

Lo studio originale sulla riassegnazione delle azioni lo dimostra con un’app priva di permessi pericolosi; descrive inoltre come ripetere la transizione tramite il ciclo di recupero del task dell’agent nei flussi multi-step.<sup>[[8]](#references)</sup>

**Non** presumere che il primitivo funzioni allo stesso modo con ogni assistente. Nella valutazione di Doubao, `OpClickUI` ignorava i tap se l’Activity di primo livello era cambiata e confrontava gli screenshot quando `OpOpenApp` compariva nei tre passaggi precedenti. Tap singoli, pressioni prolungate e doppi tap offrivano quindi poche opportunità affidabili di temporizzazione controllata dall’attaccante. `OpTypeText`, `OpSwipeUI` e `OpScrollWheelAction` non disponevano di protezioni equivalenti, ma il report ne valutava l’impatto pratico come più limitato.<sup>[[9]](#references)</sup>

## Esecuzione: dimostrare l’impatto reale

Esistono due percorsi distinti dall’influenza all’impatto:<sup>[[2]](#references)</sup>

1. **Abuso delle capacità:** il tool autorizzato esegue già l’obiettivo. Alcuni esempi sono leggere il record di un tenant e scriverlo in un report visibile all’attaccante, inviare email, modificare record, eliminare un file o avviare un pagamento. Non è necessario alcun bug software secondario.
2. **Sfruttamento di un sink downstream:** l’output del modello guidato dall’attaccante diventa sintassi per un altro componente. Esamina le query database per [SQL injection](../pentesting-web/sql-injection/README.md) o [NoSQL injection](../pentesting-web/nosql-injection.md), i wrapper di shell per [command injection](../pentesting-web/command-injection.md), gli URL scelti per [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), le operazioni sui file per path traversal, gli evaluator di template/codice per RCE e i parser di oggetti per [unsafe deserialization](../pentesting-web/deserialization/README.md).

Per ogni caso candidato, dimostra questa catena:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Un'integrazione di sola lettura è comunque sfruttabile se un qualsiasi componente successivo può pubblicare ciò che ha letto. Verifica le risposte ordinarie e i canali di egress meno ovvi, come link controllati dall'attaccante, recupero automatico di immagini, webhook, log, report, contatori, notifiche e messaggi ad altri agent.<sup>[[2]](#references)</sup>

## Azioni sugli obiettivi

Dopo aver confermato un'azione, valuta l'intero raggio d'impatto invece di fermarti al primo effetto visibile:<sup>[[2]](#references)</sup>

- **Esfiltrazione:** segreti, record utente, file interni, dati delle conversazioni o contenuti di prompt/contesto escono attraverso un canale osservabile.
- **Azione non autorizzata:** l'agent usa capacità di scrittura legittime per raggiungere l'obiettivo dell'attaccante.
- **Denial of service:** strumenti distruttivi o operazioni costose ripetute compromettono l'integrità o la disponibilità.
- **Persistenza:** memoria avvelenata, contenuti indicizzati, stato attendibile o modifiche al runtime sopravvivono alla sessione o alla rimozione della fonte che li ha originati.
- **Propagazione:** un peer attendibile consuma il messaggio o lo stato condiviso dell'agent compromesso e ripete l'azione usando i propri strumenti e le proprie credenziali.

La gravità dovrebbe dipendere dai dati raggiungibili, dai privilegi effettivi, dalla sfruttabilità del sink, dall'egress, dalla persistenza e dalla propagazione, non da quanto il testo del modello sembri sorprendente.<sup>[[2]](#references)</sup>

## Controlli da convalidare durante la valutazione

I filtri dei prompt e un system prompt migliore possono aumentare il costo per l'attaccante, ma non dovrebbero essere considerati confini di autorizzazione. Convalida i controlli seguenti ripetendo la stessa catena tramite input diretto, contenuti indiretti, memoria, strumenti e agent peer:<sup>[[2]](#references)</sup>

- Un livello di policy deterministico verifica l'utente autenticato, il tenant, l'oggetto, l'azione e la destinazione a **ogni invocazione di uno strumento**; il modello non può fornire né sovrascrivere l'identità del chiamante.
- Le capacità di lettura e scrittura usano credenziali separate, con privilegi minimi e di breve durata; gli strumenti ad alto impatto sono resi disponibili just in time e non vengono mai eseguiti automaticamente a partire da contenuti acquisiti.
- L'egress di rete e le destinazioni interne sono inseriti in allowlist indipendenti dagli URL selezionati dal modello; l'accesso del runtime agli endpoint di metadati, ai segreti montati e ai servizi adiacenti è bloccato, salvo quando necessario.
- L'interfaccia di approvazione è generata dalla richiesta strutturata canonica e mostra gli argomenti esatti, l'identità, la destinazione, gli oggetti interessati e gli effetti collaterali, non un riepilogo in testo libero del modello.
- Il successo è verificato dal sistema di destinazione o dal sistema di registrazione ufficiale. La narrazione dell'agent, una richiesta di chiamata a uno strumento o un redirect HTTP non dimostrano che lo stato dichiarato sia stato modificato.
- Le voci di memoria e di retrieval conservano la provenienza e le etichette di attendibilità, possono essere invalidate e vengono nuovamente autorizzate quando sono usate per un'azione successiva.
- I messaggi tra agent sono autenticati e autorizzati come richieste non attendibili; la reputazione di un peer o la sua scheda agent non delegano implicitamente gli strumenti del ricevente.

Per le schede agent A2A, i flussi di task e la loro superficie di attacco, consulta [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [Top 10 OWASP per le applicazioni agentiche del 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [La guida degli hacker per attaccare gli agent AI](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Quanto è davvero difficile far uscire un agent AI dalla sua sandbox?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagent nell'SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Codice sorgente del middleware LangChain TypeSafe Auto Mode](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Jev model jaggedness di TypeSafe AI: contenuti avversari](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev come giudice: come le policy contraffatte condizionano Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [Manipolazione senza permessi: possiamo fidarci degli agent GUI basati su modelli multimodali di grandi dimensioni?](https://arxiv.org/html/2601.12349v1)
- [9] [Quando un assistente AI diventa parte della catena di attacco di un hacker | Analisi della sicurezza di Doubao Phone](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
