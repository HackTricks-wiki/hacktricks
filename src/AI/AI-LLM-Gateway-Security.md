# Confini di fiducia dei gateway LLM

{{#include ../banners/hacktricks-training.md}}

Un gateway LLM gestisce il routing dei modelli e spesso conserva le credenziali dei provider, quindi i normali chiamanti API non devono ereditare autorità di configurazione o a livello di provider. La valutazione del gateway LiteLLM alla versione 1.77.7 illustra due confini distinti: l'autorizzazione delle sessioni UI per la configurazione amministrativa e la configurazione di routing fornita dal chiamante per l'inference. I problemi segnalati sono stati risolti nella versione 1.83.9.<sup>[[1]](#references)</sup>

## La classificazione delle route UI non è autorizzazione

Nella versione di LiteLLM valutata, le chiavi di login UI appartenevano al team `litellm-dashboard`. L'autorizzazione classificava una chiave come token UI in base all'identificativo del team, indipendentemente dal ruolo dell'utente. Il controllo delle route UI accettava quindi qualsiasi route che iniziasse con un prefisso allowlist. Di conseguenza, anche l'endpoint `/config/update` amministrativo corrispondeva alla voce `/config`. Quel gestore richiedeva un'autenticazione generica, ma non verificava in modo indipendente il ruolo `PROXY_ADMIN`, permettendo così a una sessione UI con privilegi inferiori di ottenere accesso alla scrittura della configurazione.<sup>[[1]](#references)</sup>

Questo è diverso da un disallineamento nella normalizzazione dei path tra proxy e backend: il codice di autorizzazione e il gestore non concordano sull'autorità della *stessa* route.<sup>[[1]](#references)</sup> Quando esamini un gateway, confronta la classificazione dei token, la corrispondenza esatta di route e metodo e il controllo del ruolo eseguito dal gestore.<sup>[[1]](#references)</sup> Per confini correlati ma distinti, consulta [autorizzazione delle API web](../pentesting-web/web-api-pentesting.md), [bypass 401/403](../pentesting-web/403-and-401-bypasses.md) e [esenzioni dei prefissi proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys).

## Le modifiche alla configurazione raggiungono più del solo archivio di configurazione

Lo stesso aggiornamento della configurazione di LiteLLM accettava valori per variabili d'ambiente e li applicava al processo in esecuzione. Un consumer trattava `UI_LOGO_PATH` come un path locale per una `FileResponse`, senza verificare che identificasse un logo; un altro leggeva `UI_USERNAME` e `UI_PASSWORD` durante il login non-SSO e assegnava `PROXY_ADMIN` se corrispondevano. Di conseguenza, il permesso di scrittura della configurazione poteva portare sia alla divulgazione di file locali sia a una modifica dell'identità amministrativa, a seconda del consumer a valle. Il tipo MIME della risposta non dimostra che il file servito sia un'immagine.<sup>[[1]](#references)</sup>

La configurazione dell'endpoint pass-through era un altro sink a valle. L'inizializzazione accettava target di adapter remoti S3/GCS, scaricava moduli Python e li importava usando `exec_module` di `importlib`. L'importazione esegue il codice di primo livello prima che venga usata un'istanza dell'adapter; limitare semplicemente l'invocazione dell'adapter non elimina questo confine di esecuzione. Consideralo un caricamento di codice controllato dalla configurazione, non una deserializzazione di file modello.<sup>[[1]](#references)</sup> Per la primitiva separata di lettura dei file, consulta [inclusione di file e path traversal](../pentesting-web/file-inclusion/).

## Il routing dei modelli per richiesta può far leakare le credenziali del gateway

La funzionalità di credenziali lato client di LiteLLM accettava un oggetto `user_config` in una richiesta LLM. La route valutata creava un `litellm.Router` temporaneo da quell'oggetto, inclusi l'elenco dei modelli e il `api_base` del provider. Una destinazione del provider controllata dal chiamante poteva ricevere la richiesta outbound di completamento del gateway e le intestazioni di autenticazione configurate per il provider. Le restrizioni sui campi `api_base` o `api_key` di primo livello non coprivano questo percorso di configurazione annidato distinto. Si tratta di un confine SSRF con credenziali, non di un problema di prompt injection.<sup>[[1]](#references)</sup>

Per una valutazione autorizzata del gateway, confronta ogni percorso in grado di creare un router o un client provider, inclusa la configurazione per richiesta, con la policy di destinazione e credenziali usata dalla route configurata normalmente.<sup>[[1]](#references)</sup> La [guida SSRF](../pentesting-web/ssrf-server-side-request-forgery/) tratta il controllo generale delle destinazioni lato server; il problema specifico del gateway consiste nel permettere a un oggetto di richiesta meno attendibile di selezionare una destinazione riutilizzando credenziali outbound privilegiate.<sup>[[1]](#references)</sup>

## La registrazione dei guardrail può aggirare una sandbox disponibile solo nella UI

Il percorso di code-test e quello di registrazione del codice di un gateway possono applicare convalide diverse. In LiteLLM prima della v1.82.0, il test UI dei guardrail personalizzati rifiutava la sintassi pericolosa ed eseguiva il codice con `__builtins__ = {}`, ma `POST /guardrails` compilava il `custom_code` inviato con `exec(compile(...), exec_globals)` senza nessuno dei due controlli. Python inserisce i builtin in un dizionario globals privo di `__builtins__`, quindi gli import e i comandi a livello di modulo venivano eseguiti **al momento della registrazione del guardrail**, prima di qualsiasi chiamata di inference. In seguito, il callback `apply_guardrail` poteva esporre un risultato memorizzato tramite la motivazione del blocco.<sup>[[2]](#references)[[3]](#references)</sup>

Per un test autorizzato, confronta i gestori di test e registrazione anziché presumere che un test riuscito della sandbox UI dimostri che la registrazione sia sicura. La forma della richiesta segnalata prima della correzione era:<sup>[[2]](#references)</sup>

```http
POST /guardrails HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{
  "guardrail": {
    "guardrail_name": "probe",
    "litellm_params": {
      "guardrail": "custom_code", "mode": "pre_call", "default_on": true,
      "custom_code": "import os\nresult = os.popen('id').read()\ndef apply_guardrail(inputs, request_data, input_type):\n    return {'action': 'block', 'reason': result}"
    }
  }
}
```

L'endpoint di registrazione accettava anche normali API key perché non verificava il ruolo `PROXY_ADMIN`. Quando non erano configurati una master key o l'autenticazione JWT/OAuth2, il gestore di autenticazione pre-fix assegnava il ruolo `PROXY_ADMIN` anche alle richieste anonime. La correzione ha cambiato il ruolo in assenza di autenticazione in `INTERNAL_USER`, aggiunto controlli amministrativi ai guardrail e convalidato e limitato i built-in durante la registrazione. Questi confini relativi ai ruoli e all'esecuzione del codice sono distinti dal [problema di fallback dei token MCP](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session).<sup>[[2]](#references)[[3]](#references)</sup>

## Le route di pass-through amministrative possono inoltrare richieste ai metadata cloud

La funzionalità di endpoint pass-through di LiteLLM consente a un amministratore di configurare una destinazione HTTP e, facoltativamente, aggiungere sottopercorsi. A differenza del problema di routing `user_config` per richiesta descritto sopra, questa funzionalità richiede **privilegi di scrittura della configurazione**; la funzionalità è pensata per fidarsi degli amministratori. Nel deployment segnalato, la destinazione non veniva verificata rispetto agli indirizzi privati o link-local.<sup>[[2]](#references)[[4]](#references)</sup> Prima della versione v1.83.0, anche le normali chiavi autenticate potevano raggiungere `/config/update`, poiché mancava un controllo del ruolo amministrativo; vedi [Classificazione delle route UI](#ui-route-classification-is-not-authorization) per il confine correlato relativo alla scrittura della configurazione.<sup>[[2]](#references)[[6]](#references)</sup>

Con quei privilegi e la raggiungibilità di rete dal proxy ai metadata EC2, una route come quella seguente espone i metadata tramite il gateway. Il flag `include_subpath` fa sì che `/meta/meta-data/iam/security-credentials/` venga mappato sotto `/latest/`.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

La [guida Cloud SSRF](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) illustra lo scambio di token IMDSv2; questa route deve consentire la richiesta `PUT` e inoltrare entrambi gli header dei metadati.<sup>[[5]](#references)</sup> La gestione generica degli header pass-through di LiteLLM rimuove il prefisso `x-pass-` prima dell'inoltro, quindi `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` e `x-pass-X-aws-ec2-metadata-token: <token>` possono fornire tali header.<sup>[[2]](#references)[[7]](#references)</sup> Il proxy deve poter raggiungere IMDS, la risposta del token deve attraversare l'hop limit configurato e la richiesta del token non deve contenere `X-Forwarded-For`.<sup>[[5]](#references)</sup> La specificità del gateway consiste nella **route persistente controllata dall'amministratore più l'inoltro degli header della richiesta**.

## References

- [1] [Check Point Research — Quando i gateway LLM vanno storto: risultati da LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — Alla sprovvista: violare LiteLLM dal bypass dell'autenticazione alla compromissione del cloud](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — corregge RCE non autenticata e sandbox escape nella guardrail del codice personalizzato](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Creare endpoint Pass Through](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Come funziona Instance Metadata Service Version 2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [advisory LiteLLM — endpoint di configurazione del proxy senza restrizioni](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [implementazione dell'inoltro degli header pass-through di LiteLLM](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
