# LLM Gateway-vertrouensgrense

{{#include ../banners/hacktricks-training.md}}

’n LLM gateway hanteer modelroetering en bevat dikwels provider-geloofsbriewe, dus moet gewone API-oproepe dit nie toegang tot konfigurasie- of provider-vlak-gesag gee nie. Die LiteLLM gateway-assessering op weergawe 1.77.7 illustreer twee afsonderlike grense: UI-sessiemagtiging vir administratiewe konfigurasie en roeteringskonfigurasie wat deur die oproeper verskaf word vir inferensie. Die gerapporteerde kwessies is in weergawe 1.83.9 reggestel.<sup>[[1]](#references)</sup>

## UI-roeteklassifikasie is nie magtiging nie

In die geassesseerde LiteLLM-weergawe het UI-aanmeldsleutels aan die `litellm-dashboard`-span behoort. Magtiging het ’n sleutel as ’n UI-token geklassifiseer op grond van daardie spanidentifiseerder, ongeag die gebruiker se rol. Die UI-roetekontrole het vervolgens enige roete aanvaar wat met ’n toegelate voorvoegsel begin. Gevolglik het die `/config`-inskrywing ook met die administratiewe `/config/update`-handler ooreengestem. Daardie handler het algemene verifikasie vereis, maar nie onafhanklik `PROXY_ADMIN` afgedwing nie, en daarom het ’n UI-sessie met laer voorregte toegang tot konfigurasieskryftoegang verkry.<sup>[[1]](#references)</sup>

Dit verskil van ’n wanpassing in proxy/backend-padnormalisering: die magtigingskode en handler stem nie saam oor die gesag van dieselfde roete nie.<sup>[[1]](#references)</sup> Wanneer jy ’n gateway hersien, vergelyk tokenklassifikasie, presiese roete- en metodepassing, en die handler se eie rolkontrole.<sup>[[1]](#references)</sup> Sien [web API-magtiging](../pentesting-web/web-api-pentesting.md), [401/403-omseilings](../pentesting-web/403-and-401-bypasses.md), en [proxy-voorvoegselvrystellings](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) vir verwante maar afsonderlike grense.

## Konfigurasieskryfbewerkings bereik meer as die konfigurasiewinkel

Dieselfde LiteLLM-konfigurasieopdatering het omgewingsveranderlikewaardes aanvaar en dit op die lopende proses toegepas. Een verbruiker het `UI_LOGO_PATH` as ’n plaaslike pad vir ’n `FileResponse` gebruik, sonder om te bevestig dat dit na ’n logo verwys; ’n ander het `UI_USERNAME` en `UI_PASSWORD` tydens nie-SSO-aanmelding gelees en `PROXY_ADMIN` toegeken wanneer hulle ooreengestem het. ’n Toestemming om konfigurasie te wysig kon dus, afhangend van die stroomaf-verbruiker, lei tot sowel plaaslike lêeropenbaarmaking as ’n administratiewe identiteitsverandering. Die mediatik in die antwoord bevestig nie dat ’n bediende lêer ’n beeld is nie.<sup>[[1]](#references)</sup>

Die konfigurasie van die deurvoer-eindpunt was nog ’n stroomaf-sink. Tydens inisialisering het dit afgeleë S3/GCS-adapterteikens aanvaar, Python-modules afgelaai en hulle met `importlib` se `exec_module` ingevoer. Invoer voer topvlak-kode uit voordat ’n adapterinstansie gebruik word; die blote beperking van adapteraanroepe verwyder nie daardie uitvoeringsgrens nie. Behandel dit as konfigurasiebeheerde kodelaai, nie as deserialisering van modellêers nie.<sup>[[1]](#references)</sup> Sien [lêerinsluiting en paddeurkruising](../pentesting-web/file-inclusion/) vir die afsonderlike lêerlees-primitief.

## Modelroetering per versoek kan gateway-geloofsbriewe lek

LiteLLM se kliëntkant-geloofsbrieffunksie het ’n `user_config`-objek in ’n LLM-versoek aanvaar. Die geassesseerde roete het ’n tydelike `litellm.Router` uit daardie objek geskep, met inbegrip van sy modell lys en provider-`api_base`. ’n Providerbestemming wat deur die oproeper beheer is, kon die gateway se uitgaande completion-versoek en gekonfigureerde provider-verifikasie-opskrifte ontvang. Beperkings op topvlak-`api_base`- of `api_key`-velde het nie hierdie afsonderlike geneste konfigurasiepad gedek nie. Dit is ’n SSRF-grens wat geloofsbriewe dra, nie ’n prompt-injection-kwessie nie.<sup>[[1]](#references)</sup>

Vergelyk vir ’n gemagtigde gateway-assessering elke pad wat ’n router of provider-kliënt kan skep, insluitend konfigurasie per versoek, met die bestemmings- en geloofsbriewebeleid wat deur die gewone gekonfigureerde roete gebruik word.<sup>[[1]](#references)</sup> Die [SSRF-gids](../pentesting-web/ssrf-server-side-request-forgery/) behandel algemene beheer oor bedienerkantbestemmings; die gateway-spesifieke fout is dat ’n minder vertroude versoekobjek ’n bestemming kan kies terwyl dit bevoorregte uitgaande geloofsbriewe hergebruik.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — Wanneer LLM-gateways verkeerd loop: Bevindings uit LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
