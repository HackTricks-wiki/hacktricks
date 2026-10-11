# Metodologia di sicurezza degli agenti AI

{{#include ../banners/hacktricks-training.md}}

Una valutazione di un agente dovrebbe seguire **l'input controllato dall'attaccante fino a un effetto osservabile esternamente**. Jailbreaking, modifiche al carattere e divulgazione del system prompt dimostrano che è possibile influenzare un canale di ragionamento, ma il risultato di maggiore impatto è la catena che porta all'accesso ai dati, a un'azione non autorizzata tramite uno strumento, a un sink di injection a valle, alla persistenza o a un altro agente.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) è utile per etichettare la copertura (dirottamento dell'obiettivo, uso improprio degli strumenti, abuso dei privilegi, supply chain, esecuzione di codice, avvelenamento della memoria, fiducia tra agenti, guasti a cascata, fiducia umana e agenti malevoli). Usa queste etichette dopo aver costruito un percorso di attacco end-to-end, anziché considerare il testo inatteso di un modello come il termine del test.<sup>[[1]](#references)[[2]](#references)</sup>

## Costruire la mappa del target

Prima di scrivere i payload, registra queste cinque dimensioni per ogni workflow dell'agente:<sup>[[2]](#references)</sup>

| Dimensione | Cosa elencare | Domanda di sicurezza |
|---|---|---|
| **Input non attendibile** | Parametri di chat/API, URL, documenti, email, ticket, voci di calendario, chunk recuperati, memoria, risultati degli strumenti e messaggi di agenti peer | Dove può inserire contenuti un attaccante che in seguito entreranno nel contesto del modello? |
| **Strumenti** | Nomi e schemi degli strumenti, effetti collaterali, esecuzione automatica, comportamento di conferma e strumenti caricati dinamicamente | Quali chiamate leggono segreti, modificano lo stato, inviano messaggi, eliminano dati, eseguono codice o trasferiscono valore? |
| **Autorità** | Delega dell'utente, account di servizio, token API, durata delle credenziali, ambito di tenant/risorse e raggiungibilità della rete | Con quale identità viene eseguita ogni chiamata e l'autorizzazione viene verificata nuovamente al confine dello strumento? |
| **Elaborazione** | Costruttori di query, shell, recuperatori URL, motori di template, interpreti, parser, operazioni sui file e deserializzatori | Dove i dati generati dal modello diventano sintassi per un altro interprete? |
| **Output** | Risposte, Markdown/HTML renderizzato, link, recupero di immagini, webhook, email, file, log, report, metriche e traffico tra agenti peer | Quale canale osservabile può trasportare un segreto o attivare una richiesta secondaria? |

Non ridurre tutto a un elenco delle integrazioni pubblicizzate. Un artefatto utile collega ogni sorgente all'esatta posizione del contesto che raggiunge, agli strumenti disponibili in quel punto, alle credenziali usate da ciascuno strumento, all'interprete a valle e a ogni percorso di uscita. Lo stesso strumento può avere un impatto limitato con un token di lettura per utente e un impatto critico con credenziali condivise di amministratore.<sup>[[2]](#references)</sup>

## Ricognizione

### Mappare ogni percorso di invio e acquisizione

Inizia dalla superficie di invio (web, mobile, API, email, piattaforma di chat, estensione del browser) e intercetta il traffico dal client al backend tramite proxy. Esamina i campi nascosti dall'interfaccia utente, i parametri di ricerca/autocompletamento/filtro, gli oggetti che rappresentano lo stato della conversazione, i processi di caricamento e indicizzazione, le risposte degli strumenti e il traffico dei sub-agenti. I client solo mobile potrebbero richiedere un emulatore e strumentazione per aggirare il certificate pinning prima che lo schema effettivo delle richieste diventi visibile.<sup>[[2]](#references)</sup>

Mappa poi lo stack sottostante al modello: framework di orchestrazione, assemblaggio dei prompt, archivi di retrieval e memoria, runtime (ad esempio Python, container o WASM), volumi montati, servizi host, API interne, raggiungibilità dei metadati cloud e reti adiacenti. Le impostazioni predefinite del framework sono importanti, perché alcune “tool call” vengono implementate generando o valutando codice; il confine del runtime/sandbox determina se il risultato rimane confinato.<sup>[[2]](#references)</sup>

### Identificare il routing con probe non distruttive

Confronta una richiesta in-scope con diverse richieste non correlate, conservando la risposta completa, il codice di stato, la latenza e il comportamento dello streaming. Un rifiuto stabile prima di qualsiasi ragionamento specifico per il task può indicare un gateway/classificatore separato; un rifiuto contestuale suggerisce che la richiesta abbia raggiunto il modello; una risposta vuota o puramente estrattiva può indicare una ricerca per keyword o un retrieval limitato. Considerale ipotesi e confermale ripetendo lo stesso probe tramite campi API e percorsi di acquisizione alternativi.<sup>[[2]](#references)</sup>

La ricognizione è completa quando la valutazione può identificare la prima sorgente controllata dall'attaccante che modifica il comportamento dell'agente **e** gli strumenti, le identità, gli interpreti e gli output raggiungibili da quella sorgente.<sup>[[2]](#references)</sup>

## Sfruttamento: attraversare un confine di fiducia

Metti alla prova i canali, non solo la formulazione del prompt. Inizia con un'injection diretta per determinare cosa blocca la porta d'ingresso visibile, poi ripeti un intento equivalente attraverso i percorsi meno visibili indicati di seguito:<sup>[[2]](#references)</sup>

- **Contenuti indiretti:** pagine, file, email, ticket, metadati, alt text, commenti HTML, testo fuori schermo o caratteri a larghezza zero. Consulta [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) per le tecniche di distribuzione dei payload.
- **Retrieval e memoria:** avvelena contenuti che verranno recuperati in seguito o uno stato che verrà ricaricato nelle sessioni successive. Registra se l'eliminazione della sorgente originale rimuove il comportamento.
- **Output degli strumenti e agenti peer:** inserisci il marker nella risposta di uno strumento o in un messaggio tra agenti per verificare se il traffico interno aggira i filtri applicati solo all'input utente e all'output finale.
- **Supply chain:** esamina descrittori degli strumenti, plugin, server connessi, skill, modelli e dipendenze come sorgenti di istruzioni attendibili. Per i test specifici di MCP, consulta [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Approvazione umana:** confronta la tool call strutturata effettiva con il testo di approvazione generato dal modello. Verifica se l'influenza dell'attaccante può omettere la destinazione, l'ambito, gli oggetti interessati o gli effetti collaterali irreversibili.

Usa prima un marker univoco e innocuo. Conserva l'artefatto sorgente, il contesto assemblato se osservabile, la tool call selezionata, i dati di approvazione, la richiesta/risposta del backend e lo stato finale. In questo modo distingui l'influenza da un'affermazione allucinata secondo cui un'azione sarebbe stata eseguita.<sup>[[2]](#references)</sup>

## Esecuzione: dimostrare l'impatto reale

Esistono due percorsi distinti dall'influenza all'impatto:<sup>[[2]](#references)</sup>

1. **Abuso delle capacità:** lo strumento autorizzato esegue già l'obiettivo. Gli esempi includono leggere il record di un tenant e scriverlo in un report visibile all'attaccante, inviare email, modificare record, eliminare un file o avviare un pagamento. Non è necessario un bug software secondario.
2. **Sfruttamento di un sink a valle:** l'output del modello pilotato dall'attaccante diventa sintassi per un altro componente. Esamina i query database per [SQL injection](../pentesting-web/sql-injection/README.md) o [NoSQL injection](../pentesting-web/nosql-injection.md), i wrapper di shell per [command injection](../pentesting-web/command-injection.md), gli URL scelti per [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), le operazioni sui file per il directory traversal, i valutatori di template/codice per RCE e i parser di oggetti per [unsafe deserialization](../pentesting-web/deserialization/README.md).

Per ogni possibile vulnerabilità, dimostra questa catena:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Un'integrazione di sola lettura è comunque sfruttabile se un componente successivo può pubblicare ciò che ha letto. Verifica le risposte ordinarie e i canali di egress meno ovvi, come link controllati dall'attaccante, recupero automatico di immagini, webhook, log, report, contatori, notifiche e messaggi ad altri agenti.<sup>[[2]](#references)</sup>

## Azioni sugli obiettivi

Dopo aver confermato un'azione, valuta l'intero raggio d'impatto invece di fermarti al primo effetto visibile:<sup>[[2]](#references)</sup>

- **Esfiltrazione:** segreti, record degli utenti, file interni, dati delle conversazioni o contenuti di prompt/contesto escono attraverso un canale osservabile.
- **Azione non autorizzata:** l'agente usa capacità di scrittura legittime per perseguire l'obiettivo dell'attaccante.
- **Denial of service:** strumenti distruttivi o operazioni costose ripetute compromettono l'integrità o la disponibilità.
- **Persistenza:** memoria avvelenata, contenuti indicizzati, stato attendibile o modifiche al runtime persistono oltre la sessione o la rimozione della fonte che li ha originati.
- **Propagazione:** un peer attendibile consuma il messaggio o lo stato condiviso dell'agente compromesso e ripete l'azione con i propri strumenti e credenziali.

La gravità dovrebbe basarsi sui dati raggiungibili, sui privilegi effettivi, sulla sfruttabilità del sink, sull'egress, sulla persistenza e sulla propagazione, non su quanto sembri sorprendente il testo del modello.<sup>[[2]](#references)</sup>

## Controlli da convalidare durante la valutazione

I filtri dei prompt e un system prompt migliore possono aumentare i costi per l'attaccante, ma non devono essere considerati confini di autorizzazione. Convalida i controlli seguenti ripetendo la stessa catena tramite input diretto, contenuti indiretti, memoria, strumenti e agenti peer:<sup>[[2]](#references)</sup>

- Un livello di policy deterministico verifica l'utente autenticato, il tenant, l'oggetto, l'azione e la destinazione a **ogni invocazione di uno strumento**; il modello non può fornire né sovrascrivere l'identità del chiamante.
- Le capacità di lettura e scrittura usano credenziali separate, con privilegi minimi e di breve durata; gli strumenti ad alto impatto vengono esposti just in time e non vengono mai eseguiti automaticamente a partire da contenuti acquisiti.
- L'egress di rete e le destinazioni interne sono inseriti in allowlist indipendentemente dagli URL selezionati dal modello; l'accesso del runtime agli endpoint di metadati, ai segreti montati e ai servizi adiacenti è bloccato, salvo quando necessario.
- L'interfaccia di approvazione viene generata dalla richiesta strutturata canonica e mostra gli argomenti esatti, l'identità, la destinazione, gli oggetti interessati e gli effetti collaterali, non un riepilogo in testo libero del modello.
- Il successo viene verificato dal sistema di destinazione o dal sistema di riferimento. La narrazione dell'agente, una richiesta di invocazione di uno strumento o un redirect HTTP non dimostrano che sia avvenuta la modifica di stato dichiarata.
- Le voci di memoria e retrieval conservano provenienza ed etichette di attendibilità, possono essere invalidate e vengono nuovamente autorizzate quando sono usate per un'azione successiva.
- I messaggi tra agenti sono autenticati e autorizzati come richieste non attendibili; la reputazione di un peer o la sua agent card non delegano implicitamente gli strumenti del destinatario.

## References

- [1] [OWASP Top 10 per le applicazioni agentiche del 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [La guida degli hacker per attaccare gli agenti AI](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
