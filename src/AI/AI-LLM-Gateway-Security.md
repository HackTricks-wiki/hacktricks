# Mipaka ya Uaminifu ya LLM Gateway

{{#include ../banners/hacktricks-training.md}}

LLM gateway hushughulikia uelekezaji wa modeli na mara nyingi huhifadhi credentials za watoa huduma, kwa hivyo wapigaji wake wa kawaida wa API hawapaswi kurithi mamlaka ya usanidi au ya kiwango cha mtoa huduma. Tathmini ya LiteLLM gateway kwenye toleo la 1.77.7 inaonyesha mipaka miwili tofauti: uidhinishaji wa session ya UI kwa usanidi wa kiutawala na usanidi wa uelekezaji unaotolewa na mpigaji kwa inference. Masuala yaliyoripotiwa yalirekebishwa kwenye toleo la 1.83.9.<sup>[[1]](#references)</sup>

## Uainishaji wa route ya UI si uidhinishaji

Katika toleo la LiteLLM lililotathminiwa, funguo za kuingia za UI zilikuwa za timu ya `litellm-dashboard`. Uidhinishaji uliainisha ufunguo kama tokeni ya UI kutokana na kitambulisho hicho cha timu, bila kujali jukumu la mtumiaji. Kisha ukaguzi wa route ya UI ulikubali route yoyote inayoanza na kiambishi awali kilichoruhusiwa. Kwa hiyo, ingizo la `/config` pia lililingana na handler ya kiutawala ya `/config/update`. Handler hiyo ilihitaji uthibitishaji wa jumla lakini haikuhitaji `PROXY_ADMIN` kivyake, hivyo session ya UI yenye mamlaka ya chini iliweza kufikia ruhusa ya kuandika usanidi.<sup>[[1]](#references)</sup>

Hii ni tofauti na kutolingana kwa urekebishaji wa njia kati ya proxy/backend: msimbo wa uidhinishaji na handler hawakubaliani kuhusu mamlaka ya *route ileile*.<sup>[[1]](#references)</sup> Unapokagua gateway, linganisha uainishaji wa tokeni, ulinganifu halisi wa route na method, na ukaguzi wa jukumu wa handler yenyewe.<sup>[[1]](#references)</sup> Tazama [uidhinishaji wa web API](../pentesting-web/web-api-pentesting.md), [bypasses za 401/403](../pentesting-web/403-and-401-bypasses.md), na [misamaha ya prefix ya proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) kwa mipaka inayohusiana lakini tofauti.

## Uandishi wa usanidi huathiri zaidi ya hifadhi ya usanidi

Usasishaji uleule wa usanidi wa LiteLLM ulikubali thamani za environment variables na kuzitumia kwenye mchakato unaoendelea. Consumer mmoja alichukulia `UI_LOGO_PATH` kama njia ya ndani ya `FileResponse`, bila kuthibitisha kuwa inaonyesha logo; mwingine alisoma `UI_USERNAME` na `UI_PASSWORD` wakati wa kuingia bila SSO na kuweka `PROXY_ADMIN` zilipolingana. Kwa hiyo, ruhusa ya kuandika usanidi inaweza kusababisha ufichuaji wa faili za ndani na mabadiliko ya utambulisho wa kiutawala, kutegemea consumer wa chini ya mnyororo. Aina ya media ya response haithibitishi kuwa faili inayotolewa ni picha.<sup>[[1]](#references)</sup>

Usanidi wa endpoint ya pass-through ulikuwa sink nyingine ya chini ya mnyororo. Uanzishaji ulikubali malengo ya remote S3/GCS adapter, ukapakua Python modules, na kuziingiza kwa kutumia `exec_module` ya `importlib`. Kuingiza module hutekeleza msimbo wa kiwango cha juu kabla ya instance ya adapter kutumika; kuzuia tu kuitisha adapter hakuondoi mpaka huo wa utekelezaji. Ichukulie hii kama upakiaji wa msimbo unaodhibitiwa na usanidi, si deserialization ya model-file.<sup>[[1]](#references)</sup> Kwa primitive tofauti ya usomaji wa faili, tazama [ujumuishaji wa faili na path traversal](../pentesting-web/file-inclusion/).

## Uelekezaji wa modeli kwa kila ombi unaweza kuvuja credentials za gateway

Kipengele cha credentials za upande wa client cha LiteLLM kilikubali object ya `user_config` ndani ya ombi la LLM. Route iliyotathminiwa iliunda `litellm.Router` ya muda kutoka kwenye object hiyo, ikijumuisha orodha ya modeli na `api_base` ya mtoa huduma. Destination ya mtoa huduma inayodhibitiwa na mpigaji ingeweza kupokea ombi la completion linalotoka kwenye gateway pamoja na headers za uthibitishaji za mtoa huduma zilizosanidiwa. Vizuizi kwenye fields za kiwango cha juu za `api_base` au `api_key` havikuhusu njia hii tofauti ya usanidi ulio ndani ya object. Huu ni mpaka wa SSRF wenye credentials, si suala la prompt injection.<sup>[[1]](#references)</sup>

Kwa tathmini iliyoidhinishwa ya gateway, linganisha kila njia inayoweza kuunda router au provider client, ikijumuisha usanidi wa kila ombi, na sera ya destination na credentials inayotumiwa na route ya kawaida iliyosanidiwa.<sup>[[1]](#references)</sup> [Mwongozo wa SSRF](../pentesting-web/ssrf-server-side-request-forgery/) unaeleza udhibiti wa jumla wa destination upande wa server; hitilafu mahususi ya gateway ni kuruhusu object ya ombi isiyoaminika sana kuchagua destination huku ikitumia tena credentials za kutoka zenye mamlaka ya juu.<sup>[[1]](#references)</sup>

## Usajili wa guardrail unaweza kupita sandbox ya UI pekee

Njia ya kupima code ya gateway na njia ya kusajili code zinaweza kuwa na uthibitishaji tofauti. Katika LiteLLM kabla ya v1.82.0, jaribio la custom-guardrail la UI lilikataa syntax hatari na kutekeleza kwa `__builtins__ = {}`, lakini `POST /guardrails` ilikusanya `custom_code` iliyowasilishwa kwa `exec(compile(...), exec_globals)` bila ukaguzi wowote kati ya hiyo. Python huingiza builtins kwenye globals dictionary isiyo na `__builtins__`, kwa hiyo imports na amri za kiwango cha module ziliendeshwa **wakati guardrail ilisajiliwa**, kabla ya simu yoyote ya inference. Callback ya baadaye ya `apply_guardrail` ingeweza kufichua matokeo yaliyohifadhiwa kupitia sababu yake ya kuzuia.<sup>[[2]](#references)[[3]](#references)</sup>

Kwa jaribio lililoidhinishwa, linganisha handlers za majaribio na usajili badala ya kudhani kuwa jaribio la sandbox ya UI lililofaulu linathibitisha usalama wa usajili. Muundo wa ombi lililoripotiwa kabla ya marekebisho ulikuwa:<sup>[[2]](#references)</sup>

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

Endpoint ya usajili pia ilikubali API keys za kawaida kwa sababu haikuwa na ukaguzi wa `PROXY_ADMIN`. Pale ambapo master key au uthibitishaji wa JWT/OAuth2 haukuwa umesanidiwa, auth handler ya kabla ya marekebisho ilikabidhi `PROXY_ADMIN` hata kwa maombi yasiyojulikana. Marekebisho yalibadilisha role ya kutokuwa na auth kuwa `INTERNAL_USER`, yakaongeza ukaguzi wa admin wa guardrail, na kuthibitisha na kuweka vizuizi kwa builtins wakati wa usajili. Mipaka hii ya role na utekelezaji wa code ni tofauti na [tatizo la MCP token-fallback](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session).<sup>[[2]](#references)[[3]](#references)</sup>

## Njia za admin pass-through zinaweza kufikia cloud metadata

Kipengele cha pass-through endpoint cha LiteLLM humruhusu msimamizi kusanidi HTTP target na kwa hiari kuongeza subpaths. Tofauti na tatizo la routing la `user_config` kwa kila ombi lililoelezwa hapo juu, hili linahitaji **mamlaka ya kuandika usanidi**; kipengele chenyewe kimekusudiwa kuamini wasimamizi. Katika deployment iliyoripotiwa, target haikukaguliwa ili kubaini kama inaelekeza kwenye private au link-local addresses.<sup>[[2]](#references)[[4]](#references)</sup> Kabla ya v1.83.0, keys za kawaida zilizothibitishwa pia ziliweza kufikia `/config/update` kwa sababu haikuwa na ukaguzi wa role ya msimamizi; tazama [uainishaji wa UI route](#ui-route-classification-is-not-authorization) kwa maelezo kuhusu mpaka unaohusiana na uandishi wa usanidi.<sup>[[2]](#references)[[6]](#references)</sup>

Kwa mamlaka hiyo na ufikikaji wa mtandao kutoka kwa proxy hadi EC2 metadata, route kama ifuatayo hufichua metadata kupitia gateway. Bendera ya `include_subpath` hufanya `/meta/meta-data/iam/security-credentials/` ielekezwe chini ya `/latest/`.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

Mwongozo wa [Cloud SSRF](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) unaeleza ubadilishanaji wa tokeni wa IMDSv2; route hii lazima iruhusu ombi lake la `PUT` na kupeleka headers zote mbili za metadata.<sup>[[5]](#references)</sup> Ushughulikiaji wa jumla wa headers za pass-through katika LiteLLM huondoa kiambishi awali cha `x-pass-` kabla ya kuzisambaza, kwa hivyo `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` na `x-pass-X-aws-ec2-metadata-token: <token>` zinaweza kutoa headers hizo.<sup>[[2]](#references)[[7]](#references)</sup> Proxy lazima iweze kufikia IMDS, jibu la tokeni lazima lipitie kikomo cha hop kilichosanidiwa, na ombi la tokeni lazima lisiwe na `X-Forwarded-For`.<sup>[[5]](#references)</sup> Tofauti maalum ya gateway ni **route endelevu inayodhibitiwa na admin pamoja na uwasilishaji wa headers za ombi**.

## References

- [1] [Check Point Research — LLM Gateways Zinapokosea: Matokeo kutoka LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — Bila Tahadhari: Kuvunja LiteLLM kutoka Kukwepa Uthibitishaji hadi Kuhatarisha Cloud](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — rekebisha RCE isiyohitaji uthibitishaji na kukwepa sandbox kwenye custom code guardrail](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Kuunda Pass Through Endpoints](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Jinsi Toleo la 2 la Instance Metadata Service linavyofanya kazi](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [Ushauri wa LiteLLM — endpoint ya usanidi wa proxy isiyo na vizuizi](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [Utekelezaji wa usambazaji wa headers za pass-through katika LiteLLM](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
