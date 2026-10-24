# Metodologia di sicurezza degli AI Agent

{{#include ../banners/hacktricks-training.md}}

Una valutazione di un agent dovrebbe seguire il percorso **dall'input controllato dall'attaccante a un effetto osservabile dall'esterno**. Il jailbreaking, le modifiche al carattere e la divulgazione del system prompt dimostrano che è possibile influenzare un canale di ragionamento, ma il risultato ad alto impatto è la catena che porta all'accesso ai dati, a un'azione non autorizzata tramite tool, a un sink di injection downstream, alla persistenza o a un altro agent.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) è utile per etichettare la copertura (dirottamento degli obiettivi, uso improprio dei tool, abuso dei privilegi, supply chain, esecuzione di codice, avvelenamento della memoria, fiducia tra agent, guasti a cascata, fiducia umana e agent rogue). Usa queste etichette dopo aver costruito un percorso di attacco end-to-end, anziché considerare il testo inatteso generato da un modello come il risultato finale del test.<sup>[[1]](#references)[[2]](#references)</sup>

## Mappare il target

Prima di scrivere i payload, registra queste cinque dimensioni per ogni workflow dell'agent:<sup>[[2]](#references)</sup>

| Dimensione | Cosa enumerare | Domanda di sicurezza |
|---|---|---|
| **Input non attendibile** | Parametri di chat/API, URL, documenti, email, ticket, voci di calendario, chunk recuperati, memoria, risultati dei tool e messaggi di agent peer | Dove può inserire contenuti un attaccante che in seguito entrano nel contesto del modello? |
| **Tool** | Nomi e schemi dei tool, effetti collaterali, esecuzione automatica, comportamento di conferma e tool caricati dinamicamente | Quali chiamate leggono segreti, modificano lo stato, inviano messaggi, eliminano dati, eseguono codice o trasferiscono valore? |
| **Autorità** | Delega dell'utente, account di servizio, token API, durata delle credenziali, ambito di tenant/risorse e raggiungibilità della rete | Con quale identità viene eseguita ogni chiamata e l'autorizzazione viene verificata di nuovo al confine del tool? |
| **Elaborazione** | Query builder, shell, URL fetcher, motori di template, interpreti, parser, operazioni sui file e deserializzatori | Dove i dati generati dal modello diventano sintassi per un altro interprete? |
| **Output** | Risposte, Markdown/HTML renderizzato, link, fetch di immagini, webhook, email, file, log, report, metriche e traffico tra agent peer | Quale canale osservabile può trasportare un segreto o attivare una richiesta secondaria? |

Non ridurre tutto a un elenco delle integrazioni dichiarate. Un artefatto utile mappa ogni sorgente alla posizione esatta del contesto che raggiunge, ai tool disponibili in quel punto, alle credenziali usate da ciascun tool, all'interprete downstream e a ogni percorso di egress. Lo stesso tool può avere un impatto ridotto con un token di lettura per utente e un impatto critico con credenziali di amministratore condivise.<sup>[[2]](#references)</sup>

## Ricognizione

### Mappare ogni percorso di invio e acquisizione

Inizia dalla superficie di invio (web, mobile, API, email, piattaforma di chat, estensione del browser) e intercetta il traffico dal client al backend tramite proxy. Esamina i campi nascosti dall'interfaccia, i parametri di ricerca/autocompletamento/filtro, gli oggetti che rappresentano lo stato della conversazione, i processi di caricamento e indicizzazione, le risposte dei tool e il traffico dei sub-agent. Per i client esclusivamente mobile potrebbe essere necessario un emulatore e l'instrumentazione per aggirare il certificate pinning prima che diventi visibile lo schema effettivo delle richieste.<sup>[[2]](#references)</sup>

Poi mappa lo stack sotto il modello: framework di orchestrazione, assemblaggio dei prompt, archivi di retrieval e memoria, runtime (ad esempio Python, container o WASM), volumi montati, servizi host, API interne, raggiungibilità dei metadati cloud e reti adiacenti. Le impostazioni predefinite dei framework sono importanti, perché alcune “tool call” vengono implementate generando o valutando codice; il confine del runtime/sandbox determina se il risultato resta contenuto.<sup>[[2]](#references)</sup>

### Identificare il routing con probe non distruttive

Confronta una richiesta in-scope con diverse richieste non correlate, conservando la risposta completa, il codice di stato, la latenza e il comportamento dello streaming. Un rifiuto stabile prima di qualsiasi ragionamento specifico sul task può indicare un gateway/classificatore separato; un rifiuto contestuale suggerisce che la richiesta ha raggiunto il modello; una risposta vuota o puramente estrattiva può indicare una ricerca per parole chiave o un retrieval limitato. Considerale ipotesi e confermale ripetendo la stessa probe tramite campi API e percorsi di acquisizione alternativi.<sup>[[2]](#references)</sup>

La ricognizione è completa quando la valutazione può indicare la prima sorgente controllata dall'attaccante che modifica il comportamento dell'agent **e** i tool, le identità, gli interpreti e gli output raggiungibili da quella sorgente.<sup>[[2]](#references)</sup>

## Exploitation: attraversare un confine di fiducia

Testa i canali, non solo la formulazione dei prompt. Inizia con una injection diretta per stabilire cosa blocca il punto di accesso visibile, poi ripeti un intento equivalente attraverso i percorsi meno visibili qui sotto:<sup>[[2]](#references)</sup>

- **Contenuti indiretti:** pagine, file, email, ticket, metadati, testo alternativo, commenti HTML, testo fuori schermo o caratteri a larghezza zero. Consulta [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) per le tecniche di distribuzione dei payload.
- **Retrieval e memoria:** avvelena contenuti che verranno recuperati in seguito o uno stato che verrà ricaricato nelle sessioni successive. Registra se l'eliminazione della sorgente originale rimuove il comportamento.
- **Output dei tool e agent peer:** inserisci il marker in una risposta di un tool o in un messaggio tra agent per verificare se il traffico interno aggira i filtri applicati solo all'input dell'utente e all'output finale.
- **Supply chain:** considera descrittori dei tool, plugin, server connessi, skill, modelli e dipendenze come sorgenti di istruzioni attendibili. Per i test specifici di MCP, consulta [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Approvazione umana:** confronta la tool call strutturata effettiva con il testo di approvazione generato dal modello. Verifica se l'influenza dell'attaccante può omettere la destinazione, l'ambito, gli oggetti interessati o gli effetti collaterali irreversibili.

Usa prima un marker innocuo e univoco. Conserva l'artefatto sorgente, il contesto assemblato se osservabile, la tool call selezionata, i dati di approvazione, la richiesta/risposta del backend e lo stato finale. Questo permette di distinguere l'influenza da un'affermazione allucinata secondo cui un'azione sarebbe avvenuta.<sup>[[2]](#references)</sup>

### Testo che imita una policy in un tool-risk judge

Un tool gate basato su un modello può ricevere testo controllato dall'attaccante all'interno di un contesto di classificazione altrimenti utile. Per esempio, `AutoModeMiddleware` sperimentale di LangChain invia al judge TypeSafe `is_risky` una tool call proposta, i suoi argomenti, una descrizione facoltativa del tool e fino a 30 messaggi recenti. Blocca i tool configurati quando la probabilità Noul restituita è almeno `0.5`; i tool non elencati non vengono classificati da questo middleware.<sup>[[5]](#references)</sup> TypeSafe avverte inoltre che il testo avversario nello stato può influenzare una classificazione anche quando lo stato dovrebbe contenere solo dati.<sup>[[6]](#references)</sup>

Una **policy contraffatta** è diversa dal semplice dichiarare di essere un messaggio di sistema. Inserisce etichette o definizioni alternative del rischio in uno stato meno attendibile e invita il judge a usare tali definizioni anziché i criteri definiti dallo sviluppatore. Nel test di Datadog, un `profile_description` modificabile dall'utente veniva copiato negli argomenti del tool insieme a `can_edit:false`. Il testo, simile a una policy, sosteneva che un tentativo di scrittura fosse a basso rischio perché un controllo dei permessi separato lo avrebbe rifiutato prima di qualsiasi modifica. Su 40 esecuzioni, il punteggio medio di `is_risky` è sceso da `0.893` a `0.290`, mentre il confronto diretto con role-spoofing ha avuto una media di `0.905`. Il fatto che la media sia scesa sotto `0.5` non dimostra che ogni singola chiamata abbia superato il gate e l'esperimento **non** ha dimostrato il completamento di una scrittura non autorizzata.<sup>[[7]](#references)</sup>

Quando testi questo confine, distingui il verdetto del classificatore dall'effettivo risultato dell'autorizzazione del tool. Verifica quali campi modificabili raggiungono il judge, confronta la stessa azione proposta con e senza testo simile a una policy e verifica lo stato finale in modo indipendente. Un controllo dei permessi separato deve basarsi comunque sull'autorità del richiedente autenticato, non sui diritti dell'account di servizio del connettore.<sup>[[7]](#references)</sup> Consulta [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) per altri casi di errore dei classificatori; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) riguarda un diverso confine di routing e credenziali.

### Isolamento del contesto dei subagent

Un subagent non-fork del Claude Agent SDK riceve il proprio `AgentDefinition.prompt`, il prompt di delega e i tool a sua disposizione, ma non il system prompt o la conversazione del parent. Se `tools` viene omesso dalla sua definizione, eredita i tool disponibili ai subagent; il progetto `CLAUDE.md` può comunque essere caricato. Di conseguenza, una restrizione del prompt applicata solo al parent è un confine inaffidabile quando il child può usare gli stessi tool per filesystem o esecuzione.<sup>[[4]](#references)</sup>

Testa il confine confrontando una richiesta diretta che il parent rifiuta con la stessa attività delegata a un subagent con nome. NCC Group riporta che un'enumerazione di file del sistema operativo rifiutata è riuscita quando è stata riformulata per un child come innocua "mappa del layout".<sup>[[3]](#references)</sup>

Esamina le effettive tool call del child e la sua allowlist effettiva dei tool, non solo la risposta finale del parent; conferma se il child ha avuto accesso a file a cui il parent non avrebbe potuto accedere.<sup>[[4]](#references)</sup> Si tratta di un errore nell'ereditarietà dei guardrail, non della prova di un [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) o di un'evasione dal container.<sup>[[3]](#references)[[4]](#references)</sup>

## Esecuzione: dimostrare l'impatto reale

Esistono due percorsi distinti dall'influenza all'impatto:<sup>[[2]](#references)</sup>

1. **Abuso delle capacità:** il tool autorizzato esegue già l'obiettivo. Gli esempi includono leggere il record di un tenant e scriverlo in un report visibile all'attaccante, inviare email, modificare record, eliminare un file o avviare un pagamento. Non è necessario alcun bug software secondario.
2. **Exploitation di sink downstream:** l'output del modello guidato dall'attaccante diventa sintassi per un altro componente. Esamina le query al database per individuare [SQL injection](../pentesting-web/sql-injection/README.md) o [NoSQL injection](../pentesting-web/nosql-injection.md), i wrapper della shell per [command injection](../pentesting-web/command-injection.md), gli URL scelti per [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), le operazioni sui file per il path traversal, i valutatori di template/codice per RCE e i parser di oggetti per [unsafe deserialization](../pentesting-web/deserialization/README.md).

Per ogni caso candidato, dimostra questa catena:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Un'integrazione di sola lettura è comunque sfruttabile quando qualsiasi componente successivo può pubblicare ciò che ha letto. Verifica le risposte ordinarie e i canali di egress meno evidenti, come link controllati dall'attaccante, recupero automatico di immagini, webhook, log, report, contatori, notifiche e messaggi ad altri agenti.<sup>[[2]](#references)</sup>

## Azioni sugli obiettivi

Dopo aver confermato un'azione, valuta l'intero raggio d'impatto invece di fermarti al primo effetto visibile:<sup>[[2]](#references)</sup>

- **Esfiltrazione:** segreti, record degli utenti, file interni, dati delle conversazioni o contenuti del prompt/contesto escono attraverso un canale osservabile.
- **Azione non autorizzata:** l'agente usa le legittime capacità di scrittura per raggiungere l'obiettivo dell'attaccante.
- **Denial of service:** strumenti distruttivi o operazioni costose ripetute compromettono l'integrità o la disponibilità.
- **Persistenza:** memoria avvelenata, contenuti indicizzati, stato considerato attendibile o modifiche al runtime sopravvivono alla sessione d'origine o alla rimozione della fonte.
- **Propagazione:** un peer attendibile consuma il messaggio o lo stato condiviso dell'agente compromesso e ripete l'azione usando i propri strumenti e le proprie credenziali.

La gravità dovrebbe basarsi sui dati raggiungibili, sui privilegi effettivi, sulla sfruttabilità del sink, sull'egress, sulla persistenza e sulla propagazione, non su quanto sembri sorprendente il testo generato dal modello.<sup>[[2]](#references)</sup>

## Controlli da convalidare durante la valutazione

I filtri per i prompt e un system prompt migliore possono aumentare i costi per l'attaccante, ma non dovrebbero essere considerati confini di autorizzazione. Convalida i controlli seguenti ripetendo la stessa catena tramite input diretto, contenuti indiretti, memoria, strumenti e agenti peer:<sup>[[2]](#references)</sup>

- Un livello deterministico di policy verifica l'utente autenticato, il tenant, l'oggetto, l'azione e la destinazione a **ogni invocazione di uno strumento**; il modello non può fornire né sovrascrivere l'identità del chiamante.
- Le capacità di lettura e scrittura usano credenziali separate, con privilegi minimi e a breve durata; gli strumenti ad alto impatto vengono esposti just in time e non vengono mai eseguiti automaticamente a partire da contenuti acquisiti.
- L'egress di rete e le destinazioni interne sono soggetti a allowlist indipendenti dagli URL selezionati dal modello; l'accesso del runtime agli endpoint dei metadati, ai segreti montati e ai servizi adiacenti è bloccato, salvo quando necessario.
- L'interfaccia di approvazione viene generata dalla richiesta strutturata canonica e mostra gli argomenti esatti, l'identità, la destinazione, gli oggetti coinvolti e gli effetti collaterali, non un riepilogo in testo libero del modello.
- L'esito positivo viene verificato nel sistema di destinazione o nel system of record. La narrazione dell'agente, una richiesta di chiamata a uno strumento o un redirect HTTP non dimostrano che la modifica di stato dichiarata sia avvenuta.
- Le voci di memoria e di retrieval mantengono la provenienza e le etichette di attendibilità, possono essere invalidate e vengono nuovamente autorizzate quando vengono usate per un'azione successiva.
- I messaggi tra agenti vengono autenticati e autorizzati come richieste non attendibili; la reputazione di un peer o la sua scheda agente non delegano implicitamente gli strumenti del destinatario.

## References

- [1] [OWASP Top 10 per le applicazioni agentiche del 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [La guida degli hacker per attaccare gli agenti AI](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Quanto è davvero difficile far evadere un agente AI dalla sua sandbox?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagenti nell'SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Codice sorgente del middleware TypeSafe Auto Mode di LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Jaggedness dei modelli TypeSafe AI Jev: contenuti avversari](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev come giudice: come una policy contraffatta influenza Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
