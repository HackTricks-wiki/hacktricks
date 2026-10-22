# Mipaka ya Uaminifu ya LLM Gateway

{{#include ../banners/hacktricks-training.md}}

LLM gateway hushughulikia uelekezaji wa modeli na mara nyingi huhifadhi credentials za watoa huduma, kwa hivyo wapigaji wake wa kawaida wa API hawapaswi kurithi mamlaka ya usanidi au ya kiwango cha mtoa huduma. Tathmini ya LiteLLM gateway kwenye toleo la 1.77.7 inaonyesha mipaka miwili tofauti: uidhinishaji wa UI session kwa usanidi wa kiutawala na usanidi wa uelekezaji unaotolewa na mpigaji kwa inference. Masuala yaliyoripotiwa yalirekebishwa katika toleo la 1.83.9.<sup>[[1]](#references)</sup>

## Uainishaji wa UI route si uidhinishaji

Katika toleo la LiteLLM lililotathminiwa, funguo za kuingia za UI zilikuwa za team ya `litellm-dashboard`. Uidhinishaji uliainisha ufunguo kuwa UI token kutokana na kitambulisho hicho cha team, bila kujali role ya mtumiaji. Ukaguzi wa UI route ulikubali route yoyote iliyoanza na prefix iliyoruhusiwa. Kwa hiyo, ingizo la `/config` pia lililingana na handler ya kiutawala ya `/config/update`. Handler hiyo ilihitaji uthibitishaji wa jumla lakini haikuhitaji `PROXY_ADMIN` kivyake, hivyo UI session yenye ruhusa za chini iliweza kufikia ruhusa za kuandika usanidi.<sup>[[1]](#references)</sup>

Hii ni tofauti na kutolingana kwa urekebishaji wa path kati ya proxy na backend: code ya uidhinishaji na handler hazikubaliani kuhusu mamlaka ya route *ileile*.<sup>[[1]](#references)</sup> Unapokagua gateway, linganisha uainishaji wa token, ulinganifu kamili wa route na method, na ukaguzi wa role wa handler yenyewe.<sup>[[1]](#references)</sup> Tazama [web API authorization](../pentesting-web/web-api-pentesting.md), [401/403 bypasses](../pentesting-web/403-and-401-bypasses.md), na [proxy prefix exemptions](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) kwa mipaka inayohusiana lakini tofauti.

## Uandishi wa usanidi huathiri zaidi ya hifadhi ya usanidi

Usasishaji huohuo wa usanidi wa LiteLLM ulikubali thamani za environment variables na kuzitumia kwenye mchakato unaoendelea. Consumer mmoja alitumia `UI_LOGO_PATH` kama path ya ndani kwa `FileResponse`, bila kuthibitisha kuwa path hiyo ilielekeza kwenye logo; mwingine alisoma `UI_USERNAME` na `UI_PASSWORD` wakati wa kuingia bila SSO, na kutoa `PROXY_ADMIN` ikiwa zinalingana. Kwa hiyo, ruhusa ya kuandika usanidi ingeweza kusababisha ufichuzi wa faili ya ndani na mabadiliko ya utambulisho wa kiutawala, kutegemea consumer wa chini. Aina ya media ya jibu haithibitishi kuwa faili inayotolewa ni picha.<sup>[[1]](#references)</sup>

Usanidi wa endpoint ya pass-through ulikuwa sink nyingine ya chini. Uanzishaji ulikubali malengo ya remote S3/GCS adapter, ukapakua Python modules, na kuziingiza kwa kutumia `importlib`'s `exec_module`. Import huendesha code ya kiwango cha juu kabla ya instance ya adapter kutumika; kuzuia tu matumizi ya adapter hakuondoi mpaka huo wa utekelezaji. Ichukulie hii kama upakiaji wa code unaodhibitiwa na usanidi, si deserialization ya faili ya modeli.<sup>[[1]](#references)</sup> Kwa primitive tofauti ya kusoma faili, tazama [file inclusion and path traversal](../pentesting-web/file-inclusion/).

## Uelekezaji wa modeli kwa kila ombi unaweza kuvuja credentials za gateway

Kipengele cha credentials cha upande wa mteja cha LiteLLM kilikubali object ya `user_config` kwenye ombi la LLM. Route iliyotathminiwa iliunda `litellm.Router` ya muda kutoka kwa object hiyo, ikiwa na orodha yake ya modeli na `api_base` ya mtoa huduma. Marudio ya mtoa huduma yaliyodhibitiwa na mpigaji yangeweza kupokea ombi la completion linalotumwa nje na gateway pamoja na headers za uthibitishaji za mtoa huduma zilizosanidiwa. Vizuizi kwenye fields za kiwango cha juu za `api_base` au `api_key` havikushughulikia njia hii tofauti ya usanidi uliowekwa ndani. Huu ni mpaka wa SSRF unaobeba credentials, si suala la prompt injection.<sup>[[1]](#references)</sup>

Kwa tathmini iliyoidhinishwa ya gateway, linganisha kila njia inayoweza kuunda router au provider client, ikiwemo usanidi wa kila ombi, na sera ya marudio na credentials inayotumiwa na route ya kawaida iliyosanidiwa.<sup>[[1]](#references)</sup> [SSRF guide](../pentesting-web/ssrf-server-side-request-forgery/) inaeleza udhibiti wa jumla wa marudio ya upande wa seva; hitilafu mahususi ya gateway ni kuruhusu object ya ombi isiyoaminika sana kuchagua marudio huku ikitumia tena credentials za kutoka nje zenye ruhusa za juu.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — Matatizo Yanapotokea kwenye LLM Gateways: Matokeo kutoka LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
