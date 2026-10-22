# LLM Gateway की Trust Boundaries

{{#include ../banners/hacktricks-training.md}}

LLM gateway model routing संभालता है और अक्सर provider credentials रखता है, इसलिए उसके सामान्य API callers को configuration या provider-स्तर का अधिकार नहीं मिलना चाहिए। LiteLLM gateway के version 1.77.7 पर किए गए assessment में दो अलग boundaries सामने आईं: administrative configuration के लिए UI-session authorization और inference के लिए caller द्वारा दी गई routing configuration। बताई गई समस्याएँ version 1.83.9 में ठीक की गईं।<sup>[[1]](#references)</sup>

## UI route का वर्गीकरण authorization नहीं है

जाँचे गए LiteLLM version में, UI login keys `litellm-dashboard` team से जुड़ी थीं। Authorization ने user की role की परवाह किए बिना, team identifier के आधार पर key को UI token के रूप में वर्गीकृत किया। इसके बाद UI route check ने allowlisted prefix से शुरू होने वाले किसी भी route को स्वीकार कर लिया। नतीजतन, `/config` entry, administrative `/config/update` handler से भी match हो गई। उस handler को सामान्य authentication की आवश्यकता थी, लेकिन वह अलग से `PROXY_ADMIN` की जाँच नहीं करता था, इसलिए कम अधिकार वाला UI session configuration write access तक पहुँच गया।<sup>[[1]](#references)</sup>

यह proxy/backend path-normalization mismatch से अलग है: authorization code और handler *उसी* route के अधिकार को लेकर असहमत होते हैं।<sup>[[1]](#references)</sup> Gateway की समीक्षा करते समय token classification, route और method का exact matching, और handler की अपनी role जाँच की तुलना करें।<sup>[[1]](#references)</sup> इससे जुड़ी, लेकिन अलग boundaries के लिए [web API authorization](../pentesting-web/web-api-pentesting.md), [401/403 bypasses](../pentesting-web/403-and-401-bypasses.md), और [proxy prefix exemptions](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) देखें।

## Configuration writes, configuration store से आगे तक पहुँच सकते हैं

LiteLLM के उसी configuration update में environment-variable values स्वीकार की गईं और उन्हें चल रही process पर लागू किया गया। एक consumer ने `UI_LOGO_PATH` को `FileResponse` के लिए local path की तरह इस्तेमाल किया, बिना यह जाँचे कि वह किसी logo को दर्शाता है या नहीं; दूसरे ने non-SSO login के दौरान `UI_USERNAME` और `UI_PASSWORD` पढ़े और उनके match होने पर `PROXY_ADMIN` assign किया। इस तरह, configuration-write permission downstream consumer के आधार पर local-file disclosure और administrative identity change, दोनों का कारण बन सकती थी। Response का media type यह साबित नहीं करता कि serve की गई file कोई image है।<sup>[[1]](#references)</sup>

Pass-through endpoint configuration एक और downstream sink था। Initialization ने remote S3/GCS adapter targets स्वीकार किए, Python modules download किए, और `importlib` के `exec_module` का इस्तेमाल करके उन्हें import किया। Import, adapter instance का इस्तेमाल होने से पहले ही top-level code execute करता है; केवल adapter के invocation को सीमित करने से यह execution boundary नहीं हटती। इसे configuration-controlled code loading मानें, model-file deserialization नहीं।<sup>[[1]](#references)</sup> अलग file-read primitive के लिए [file inclusion and path traversal](../pentesting-web/file-inclusion/) देखें।

## Per-request model routing से gateway credentials leak हो सकते हैं

LiteLLM के client-side credential feature ने LLM request में `user_config` object स्वीकार किया। जाँचे गए route ने इस object से एक temporary `litellm.Router` बनाया, जिसमें उसकी model list और provider `api_base` शामिल थे। Caller द्वारा नियंत्रित provider destination पर gateway की outbound completion request और configured provider authentication headers भेजे जा सकते थे। Top-level `api_base` या `api_key` fields पर लगी पाबंदियाँ इस अलग nested configuration path पर लागू नहीं थीं। यह prompt-injection समस्या के बजाय credentials वाला SSRF boundary है।<sup>[[1]](#references)</sup>

अनुमति-प्राप्त gateway assessment के दौरान, router या provider client बनाने वाले हर path—जिसमें per-request configuration भी शामिल है—की तुलना normal configured route की destination और credential policy से करें।<sup>[[1]](#references)</sup> [SSRF guide](../pentesting-web/ssrf-server-side-request-forgery/) में सामान्य server-side destination control बताया गया है; gateway-विशिष्ट विफलता यह है कि कम भरोसेमंद request object को destination चुनने की अनुमति दी जाती है, जबकि privileged outbound credentials का फिर से इस्तेमाल होता है।<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — जब LLM Gateways में गड़बड़ी होती है: LiteLLM से मिली जानकारियाँ](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
