# Metodologia di sicurezza degli AI Agent

{{#include ../banners/hacktricks-training.md}}

Una valutazione di un agente dovrebbe seguire il percorso **dall’input controllato dall’attaccante a un effetto osservabile esternamente**. Jailbreaking, modifiche del carattere e divulgazione del system prompt dimostrano che è possibile influenzare un canale di ragionamento, ma il finding ad alto impatto è la catena che porta all’accesso ai dati, a un’azione non autorizzata tramite tool, a un sink di injection a valle, alla persistenza o a un altro agente.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) è utile per classificare la copertura (dirottamento degli obiettivi, uso improprio dei tool, abuso dei privilegi, supply chain, esecuzione di codice, avvelenamento della memoria, fiducia tra agenti, guasti a cascata, fiducia umana e agenti rogue). Usa queste categorie dopo aver costruito un percorso di attacco end-to-end, invece di considerare il testo inatteso generato dal modello come il termine del test.<sup>[[1]](#references)[[2]](#references)</sup>

## Costruire la mappa del target

Prima di scrivere i payload, registra queste cinque dimensioni per ogni workflow dell’agente:<sup>[[2]](#references)</sup>

| Dimensione | Cosa enumerare | Domanda di sicurezza |
|---|---|---|
| **Input non attendibile** | Parametri di chat/API, URL, documenti, email, ticket, voci di calendario, chunk recuperati, memoria, risultati dei tool e messaggi di agenti peer | Dove può inserire contenuti un attaccante affinché entrino successivamente nel contesto del modello? |
| **Tool** | Nomi e schemi dei tool, effetti collaterali, esecuzione automatica, comportamento di conferma e tool caricati dinamicamente | Quali chiamate leggono segreti, scrivono dati, inviano messaggi, eliminano dati, eseguono codice o trasferiscono valore? |
| **Autorità** | Delega dell’utente, account di servizio, token API, durata delle credenziali, ambito del tenant/risorsa e portata di rete | Con quale identità viene eseguita ogni chiamata e l’autorizzazione viene verificata di nuovo al confine del tool? |
| **Elaborazione** | Query builder, shell, strumenti di fetch degli URL, template engine, interpreti, parser, operazioni sui file e deserializzatori | Dove i dati generati dal modello diventano sintassi per un altro interprete? |
| **Output** | Risposte, Markdown/HTML renderizzato, link, fetch di immagini, webhook, email, file, log, report, metriche e traffico tra agenti peer | Quale canale osservabile può trasportare un segreto o attivare una richiesta secondaria? |

Non ridurre tutto a un elenco di integrazioni pubblicizzate. Un artefatto utile collega ogni sorgente alla posizione precisa del contesto che raggiunge, ai tool disponibili in quel punto, alle credenziali usate da ciascun tool, all’interprete a valle e a ogni percorso di egress. Lo stesso tool può avere un impatto ridotto con un token di lettura per utente e un impatto critico con credenziali condivise di amministratore.<sup>[[2]](#references)</sup>

## Ricognizione

### Mappare ogni percorso di distribuzione e acquisizione

Inizia dalla superficie di distribuzione (web, mobile, API, email, piattaforma di chat, estensione del browser) e intercetta il traffico dal client al backend tramite un proxy. Esamina i campi nascosti dall’interfaccia, i parametri di ricerca/autocompletamento/filtro, gli oggetti dello stato della conversazione, i job di caricamento e indicizzazione, le risposte dei tool e il traffico dei sub-agent. I client disponibili solo su mobile potrebbero richiedere un emulatore e strumenti di instrumentation per aggirare il certificate pinning prima che diventi visibile lo schema reale delle richieste.<sup>[[2]](#references)</sup>

Mappa poi lo stack sottostante al modello: framework di orchestrazione, assemblaggio dei prompt, archivi di retrieval e memoria, runtime (ad esempio Python, container o WASM), volumi montati, servizi host, API interne, raggiungibilità dei metadati cloud e reti adiacenti. Le impostazioni predefinite del framework sono importanti perché alcune “tool call” vengono implementate generando o valutando codice; il confine del runtime/sandbox determina se il risultato resta contenuto.<sup>[[2]](#references)</sup>

### Rilevare il routing con probe non distruttive

Confronta una richiesta in scope con diverse richieste non correlate, conservando la risposta completa, il codice di stato, la latenza e il comportamento dello streaming. Un rifiuto stabile prima di qualsiasi ragionamento specifico sul task può indicare un gateway/classificatore separato; un rifiuto contestuale suggerisce che la richiesta ha raggiunto il modello; una risposta vuota o puramente estrattiva può indicare una ricerca per parole chiave o un retrieval limitato. Considerale ipotesi e confermale riproducendo lo stesso probe tramite campi API e percorsi di acquisizione alternativi.<sup>[[2]](#references)</sup>

La ricognizione è completa quando la valutazione sa identificare la prima sorgente controllata dall’attaccante che modifica il comportamento dell’agente **e** i tool, le identità, gli interpreti e gli output raggiungibili da tale sorgente.<sup>[[2]](#references)</sup>

## Sfruttamento: attraversare un confine di fiducia

Testa i canali, non solo la formulazione dei prompt. Inizia con l’injection diretta per stabilire cosa blocca il front door visibile, poi ripeti intenti equivalenti attraverso i percorsi meno visibili qui sotto:<sup>[[2]](#references)</sup>

- **Contenuti indiretti:** pagine, file, email, ticket, metadati, alt text, commenti HTML, testo fuori schermo o caratteri a larghezza zero. Vedi [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) per le tecniche di distribuzione dei payload.
- **Retrieval e memoria:** avvelena contenuti che verranno recuperati in seguito o stato che verrà ricaricato in sessioni successive. Registra se l’eliminazione della sorgente originale rimuove il comportamento.
- **Output dei tool e agenti peer:** inserisci il marker nella risposta di un tool o in un messaggio tra agenti per verificare se il traffico interno aggira i filtri applicati solo all’input utente e all’output finale.
- **Supply chain:** esamina descrittori dei tool, plugin, server connessi, skill, modelli e dipendenze come fonti di istruzioni attendibili. Per i test specifici di MCP, vedi [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Approvazione umana:** confronta la tool call strutturata effettiva con il testo di approvazione generato dal modello. Verifica se l’influenza dell’attaccante può omettere la destinazione, l’ambito, gli oggetti interessati o gli effetti collaterali irreversibili.

Usa prima un marker univoco e innocuo. Conserva l’artefatto sorgente, il contesto assemblato se osservabile, la tool call selezionata, i dati di approvazione, la richiesta/risposta del backend e lo stato finale. In questo modo distingui l’influenza da un’affermazione allucinata secondo cui un’azione sarebbe avvenuta.<sup>[[2]](#references)</sup>

### Testo che imita una policy in un tool-risk judge

Un tool gate basato su un modello può ricevere testo controllato dall’attaccante all’interno di un contesto di classificazione altrimenti utile. Ad esempio, `AutoModeMiddleware` sperimentale di LangChain invia a un judge `is_risky` di TypeSafe una tool call proposta, i relativi argomenti, una descrizione opzionale del tool e fino a 30 messaggi recenti. Blocca i tool configurati quando la probabilità Noul restituita è almeno `0.5`; i tool non elencati non vengono classificati da questo middleware.<sup>[[5]](#references)</sup> TypeSafe avverte inoltre che il testo avversario nello stato può influenzare una classificazione anche quando lo stato dovrebbe essere usato come dato.<sup>[[6]](#references)</sup>

Una **policy contraffatta** è diversa dal semplice dichiarare di essere un system message. Inserisce etichette alternative o definizioni del rischio in uno stato con un livello di fiducia inferiore e invita il judge a usare tali definizioni al posto dei criteri stabiliti dallo sviluppatore. Nel test di Datadog, un `profile_description` modificabile dall’utente veniva copiato negli argomenti del tool insieme a `can_edit:false`. Il testo in stile policy sosteneva che un tentativo di scrittura fosse a basso rischio perché un controllo separato dei permessi lo avrebbe rifiutato prima di qualsiasi modifica. Su 40 esecuzioni, il punteggio medio di `is_risky` è sceso da `0.893` a `0.290`, mentre una comparazione diretta con falsificazione del ruolo ha registrato una media di `0.905`. Il fatto che la media scenda sotto `0.5` non dimostra che ogni singola chiamata abbia superato il gate, e l’esperimento **non** ha dimostrato il completamento di una scrittura non autorizzata.<sup>[[7]](#references)</sup>

Quando testi questo confine, distingui il verdetto del classificatore dall’effettivo risultato dell’autorizzazione del tool. Verifica quali campi modificabili raggiungono il judge, confronta la stessa azione proposta con e senza testo in stile policy e verifica in modo indipendente lo stato finale. Un controllo separato dei permessi deve comunque usare l’autorità del richiedente autenticato, non i diritti dell’account di servizio del connettore.<sup>[[7]](#references)</sup> Vedi [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) per altre modalità di errore dei classificatori; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) riguarda un diverso confine di routing e delle credenziali.

### Isolamento del contesto dei subagent

Un subagent non-fork del Claude Agent SDK riceve il proprio `AgentDefinition.prompt`, il prompt di delega e i tool disponibili, ma non il system prompt o la conversazione del parent. Se `tools` viene omesso dalla sua definizione, il subagent eredita i tool disponibili ai subagent; il file `CLAUDE.md` del progetto può comunque essere caricato. Perciò una restrizione nel prompt del solo parent non è un confine affidabile quando il child può usare gli stessi tool di filesystem o esecuzione.<sup>[[4]](#references)</sup>

Testa il confine confrontando una richiesta diretta che il parent rifiuta con lo stesso task delegato a un subagent con nome. NCC Group riferisce che un’enumerazione di file del sistema operativo rifiutata è riuscita quando è stata riformulata per un child come innocua “mappa della struttura”.<sup>[[3]](#references)</sup>

Esamina le effettive tool call del child e la relativa allowlist effettiva dei tool, non solo la risposta finale del parent; conferma se il child ha avuto accesso a file a cui il parent non avrebbe acceduto.<sup>[[4]](#references)</sup> Si tratta di un errore nell’ereditarietà delle guardrail, non della prova di un [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) o di un container escape.<sup>[[3]](#references)[[4]](#references)</sup>

## Esecuzione: dimostrare l’impatto reale

Esistono due percorsi distinti dall’influenza all’impatto:<sup>[[2]](#references)</sup>

1. **Abuso delle capacità:** il tool autorizzato svolge già l’obiettivo. Gli esempi includono leggere il record di un tenant e scriverlo in un report visibile all’attaccante, inviare email, modificare record, eliminare un file o avviare un pagamento. Non è necessario alcun bug software secondario.
2. **Sfruttamento di un sink a valle:** l’output del modello guidato dall’attaccante diventa sintassi per un altro componente. Esamina le query al database per [SQL injection](../pentesting-web/sql-injection/README.md) o [NoSQL injection](../pentesting-web/nosql-injection.md), i wrapper della shell per [command injection](../pentesting-web/command-injection.md), gli URL scelti per [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), le operazioni sui file per path traversal, i template/code evaluator per RCE e gli object parser per [unsafe deserialization](../pentesting-web/deserialization/README.md).

Per ogni caso candidato, dimostra questa catena:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Un'integrazione in sola lettura è comunque sfruttabile se un componente successivo può pubblicare ciò che ha letto. Verifica le risposte ordinarie e i canali di egress meno evidenti, come link controllati dall'attaccante, recupero automatico di immagini, webhook, log, report, contatori, notifiche e messaggi ad altri agenti.<sup>[[2]](#references)</sup>

## Azioni sugli obiettivi

Dopo aver confermato un'azione, valuta l'intero raggio d'impatto invece di fermarti al primo effetto visibile:<sup>[[2]](#references)</sup>

- **Esfiltrazione:** segreti, record utente, file interni, dati delle conversazioni o contenuti del prompt/contesto escono attraverso un canale osservabile.
- **Azione non autorizzata:** l'agente usa capacità di scrittura legittime per perseguire l'obiettivo dell'attaccante.
- **Denial of service:** strumenti distruttivi o operazioni costose ripetute compromettono l'integrità o la disponibilità.
- **Persistenza:** memoria avvelenata, contenuti indicizzati, stato considerato attendibile o modifiche al runtime sopravvivono alla sessione d'origine o alla rimozione della fonte.
- **Propagazione:** un peer attendibile usa il messaggio o lo stato condiviso dell'agente compromesso e ripete l'azione con i propri strumenti e credenziali.

La gravità dovrebbe basarsi sui dati raggiungibili, sui privilegi effettivi, sulla sfruttabilità del sink, sull'egress, sulla persistenza e sulla propagazione, non su quanto il testo del modello possa sembrare sorprendente.<sup>[[2]](#references)</sup>

## Controlli da convalidare durante la valutazione

I filtri per i prompt e un system prompt migliore possono aumentare il costo per l'attaccante, ma non vanno considerati limiti di autorizzazione. Convalida i controlli seguenti ripetendo la stessa catena tramite input diretto, contenuti indiretti, memoria, strumenti e agenti peer:<sup>[[2]](#references)</sup>

- Un livello di policy deterministico verifica l'utente autenticato, il tenant, l'oggetto, l'azione e la destinazione a **ogni invocazione di uno strumento**; il modello non può fornire o sovrascrivere l'identità del chiamante.
- Le capacità di lettura e scrittura usano credenziali separate, con privilegi minimi e di breve durata; gli strumenti ad alto impatto vengono esposti just-in-time e non vengono mai eseguiti automaticamente in base a contenuti acquisiti.
- L'egress di rete e le destinazioni interne sono inseriti in allowlist, indipendentemente dagli URL selezionati dal modello; l'accesso del runtime agli endpoint di metadata, ai segreti montati e ai servizi adiacenti è bloccato, salvo quando necessario.
- L'interfaccia di approvazione viene generata dalla richiesta strutturata canonica e mostra gli argomenti esatti, l'identità, la destinazione, gli oggetti interessati e gli effetti collaterali, non un riepilogo in testo libero prodotto dal modello.
- Il successo viene verificato nel sistema di destinazione o nel sistema di registrazione ufficiale. La narrazione dell'agente, una richiesta di chiamata a uno strumento o un redirect HTTP non dimostrano che lo stato dichiarato sia stato modificato.
- Le voci di memoria e di retrieval conservano provenienza ed etichette di attendibilità, possono essere invalidate e vengono nuovamente autorizzate quando usate per un'azione successiva.
- I messaggi tra agenti sono autenticati e autorizzati come richieste non attendibili; la reputazione o la scheda di un peer non delegano implicitamente gli strumenti del destinatario.

Per le schede degli agenti A2A, i flussi di attività e la relativa superficie di attacco, consulta [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 per le applicazioni agentiche 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [La guida degli hacker per attaccare gli agenti AI](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Quanto è davvero difficile far uscire un agente AI dalla sua sandbox?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagenti nell'SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Codice sorgente del middleware LangChain TypeSafe Auto Mode](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Jev model jaggedness di TypeSafe AI: contenuti avversari](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev come giudice: come una policy contraffatta influenza Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
