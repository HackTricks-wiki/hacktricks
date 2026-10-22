# Confini di fiducia dei gateway LLM

{{#include ../banners/hacktricks-training.md}}

Un gateway LLM gestisce l'instradamento dei modelli e spesso custodisce le credenziali dei provider, quindi i normali chiamanti delle sue API non devono ereditare autorità di configurazione o a livello di provider. La valutazione del gateway LiteLLM nella versione 1.77.7 illustra due confini distinti: l'autorizzazione della sessione UI per la configurazione amministrativa e la configurazione di instradamento fornita dal chiamante per l'inferenza. I problemi segnalati sono stati risolti nella versione 1.83.9.<sup>[[1]](#references)</sup>

## La classificazione delle route UI non è un'autorizzazione

Nella versione di LiteLLM valutata, le chiavi di accesso UI appartenevano al team `litellm-dashboard`. L'autorizzazione classificava una chiave come token UI in base all'identificativo del team, indipendentemente dal ruolo dell'utente. Il controllo delle route UI accettava quindi qualsiasi route che iniziasse con un prefisso consentito. Di conseguenza, la voce `/config` corrispondeva anche all'handler amministrativo `/config/update`. Tale handler richiedeva un'autenticazione generica, ma non verificava autonomamente che l'utente avesse il ruolo `PROXY_ADMIN`, consentendo così a una sessione UI con privilegi inferiori di accedere alla scrittura della configurazione.<sup>[[1]](#references)</sup>

Questo è diverso da un'incoerenza nella normalizzazione dei percorsi tra proxy e backend: il codice di autorizzazione e l'handler non concordano sull'autorità associata alla *stessa* route.<sup>[[1]](#references)</sup> Quando esaminate un gateway, confrontate la classificazione dei token, la corrispondenza esatta di route e metodo e il controllo del ruolo eseguito dall'handler stesso.<sup>[[1]](#references)</sup> Per confini correlati ma distinti, consultate [autorizzazione delle API web](../pentesting-web/web-api-pentesting.md), [bypass 401/403](../pentesting-web/403-and-401-bypasses.md) ed [esenzioni dei prefissi del proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys).

## Le scritture della configurazione raggiungono più della sola configurazione

La stessa operazione di aggiornamento della configurazione di LiteLLM accettava valori di variabili d'ambiente e li applicava al processo in esecuzione. Un componente utilizzava `UI_LOGO_PATH` come percorso locale per una `FileResponse`, senza verificare che puntasse a un logo; un altro leggeva `UI_USERNAME` e `UI_PASSWORD` durante l'accesso non-SSO e assegnava il ruolo `PROXY_ADMIN` in caso di corrispondenza. Pertanto, il permesso di scrivere la configurazione poteva consentire sia la divulgazione di file locali sia la modifica di un'identità amministrativa, a seconda del componente a valle. Il tipo MIME della risposta non dimostra che il file servito sia un'immagine.<sup>[[1]](#references)</sup>

Anche la configurazione dell'endpoint pass-through costituiva un sink a valle. L'inizializzazione accettava target di adapter remoti S3/GCS, scaricava moduli Python e li importava tramite `exec_module` di `importlib`. L'importazione esegue il codice di primo livello prima che venga usata un'istanza dell'adapter; limitare soltanto l'invocazione dell'adapter non eliminerebbe questo confine di esecuzione. Consideratelo caricamento di codice controllato dalla configurazione, non deserializzazione di file di modelli.<sup>[[1]](#references)</sup> Per la primitiva distinta di lettura dei file, consultate [inclusione di file e path traversal](../pentesting-web/file-inclusion/).

## L'instradamento dei modelli per richiesta può causare un leak delle credenziali del gateway

La funzionalità di credenziali lato client di LiteLLM accettava un oggetto `user_config` in una richiesta LLM. La route valutata creava un `litellm.Router` temporaneo a partire da tale oggetto, inclusi l'elenco dei modelli e `api_base` del provider. Una destinazione del provider controllata dal chiamante poteva ricevere la richiesta di completamento in uscita del gateway e le intestazioni di autenticazione configurate per il provider. Le restrizioni sui campi `api_base` o `api_key` di primo livello non coprivano questo percorso di configurazione annidato distinto. Si tratta di un confine SSRF che coinvolge credenziali, non di un problema di prompt injection.<sup>[[1]](#references)</sup>

Nell'ambito di una valutazione autorizzata del gateway, confrontate ogni percorso in grado di creare un router o un client provider, inclusa la configurazione per richiesta, con la policy di destinazione e credenziali usata dalla route configurata normalmente.<sup>[[1]](#references)</sup> La [guida SSRF](../pentesting-web/ssrf-server-side-request-forgery/) illustra il controllo generale delle destinazioni lato server; il problema specifico del gateway consiste nel consentire a un oggetto di richiesta meno affidabile di selezionare una destinazione riutilizzando credenziali privilegiate per le richieste in uscita.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — Quando i gateway LLM vanno storto: risultati emersi da LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
