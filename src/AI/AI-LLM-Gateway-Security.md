# LLM Gateway Trust Boundaries

{{#include ../banners/hacktricks-training.md}}

एक LLM gateway model routing संभालता है और अक्सर provider credentials रखता है, इसलिए इसके सामान्य API callers को configuration या provider-level authority नहीं मिलनी चाहिए। LiteLLM version 1.77.7 का assessment दो अलग boundaries दिखाता है: administrative configuration के लिए UI-session authorization और inference के लिए caller-supplied routing configuration। रिपोर्ट की गई समस्याएँ version 1.83.9 में ठीक की गईं।<sup>[[1]](#references)</sup>

## UI route classification is not authorization

जाँचे गए LiteLLM version में UI login keys `litellm-dashboard` team से संबंधित थीं। Authorization में key को UI token माना जाता था, यदि उसका team identifier उस team का हो—user की role कुछ भी हो। UI route check इसके बाद allowlisted prefix से शुरू होने वाला कोई भी route स्वीकार करता था। नतीजतन, `/config` entry, administrative `/config/update` handler से भी match हो जाती थी। उस handler को सामान्य authentication की आवश्यकता थी, लेकिन वह स्वतंत्र रूप से `PROXY_ADMIN` की आवश्यकता लागू नहीं करता था। इसलिए कम अधिकार वाली UI session के ज़रिए configuration लिखने की पहुँच मिल जाती थी।<sup>[[1]](#references)</sup>

यह proxy/backend path-normalization mismatch से अलग है: authorization code और handler, *उसी* route के अधिकार को लेकर असहमत होते हैं।<sup>[[1]](#references)</sup> Gateway की समीक्षा करते समय token classification, route और method की exact matching, तथा handler के अपने role check की तुलना करें।<sup>[[1]](#references)</sup> इससे संबंधित, लेकिन अलग boundaries के लिए [web API authorization](../pentesting-web/web-api-pentesting.md), [401/403 bypasses](../pentesting-web/403-and-401-bypasses.md), और [proxy prefix exemptions](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) देखें।

## Configuration writes reach more than the configuration store

LiteLLM का वही configuration update environment-variable values स्वीकार करता था और उन्हें running process पर लागू करता था। एक consumer `UI_LOGO_PATH` को `FileResponse` के लिए local path मानता था, बिना यह जाँचे कि वह logo को दर्शाता है या नहीं; दूसरा, non-SSO login के दौरान `UI_USERNAME` और `UI_PASSWORD` पढ़ता था और उनके match होने पर `PROXY_ADMIN` assign करता था। इसलिए configuration लिखने की permission, downstream consumer के आधार पर, local-file disclosure और administrative identity में बदलाव—दोनों का कारण बन सकती थी। Response media type से यह साबित नहीं होता कि serve की गई file image है।<sup>[[1]](#references)</sup>

Pass-through endpoint configuration एक और downstream sink था। Initialization remote S3/GCS adapter targets स्वीकार करता था, Python modules download करता था और उन्हें `importlib` के `exec_module` से import करता था। Adapter instance का उपयोग होने से पहले ही import, top-level code execute करता है; केवल adapter के invocation को सीमित करने से यह execution boundary नहीं हटती। इसे configuration-controlled code loading मानें, model-file deserialization नहीं।<sup>[[1]](#references)</sup> अलग file-read primitive के लिए [file inclusion and path traversal](../pentesting-web/file-inclusion/) देखें।

## Per-request model routing can leak gateway credentials

LiteLLM का client-side credential feature, LLM request में `user_config` object स्वीकार करता था। जाँचा गया route उस object—जिसमें model list और provider `api_base` शामिल थे—से एक temporary `litellm.Router` बनाता था। Caller द्वारा नियंत्रित provider destination तक gateway की outbound completion request और configured provider authentication headers पहुँच सकते थे। Top-level `api_base` या `api_key` fields पर लगाए गए restrictions, इस अलग nested configuration path पर लागू नहीं होते थे। यह credential-bearing SSRF boundary है, prompt-injection issue नहीं।<sup>[[1]](#references)</sup>

अधिकृत gateway assessment में router या provider client बनाने वाले हर path की तुलना करें—जिसमें per-request configuration भी शामिल है—और उसे सामान्य configured route की destination तथा credential policy के विरुद्ध जाँचें।<sup>[[1]](#references)</sup> [SSRF guide](../pentesting-web/ssrf-server-side-request-forgery/) में सामान्य server-side destination control शामिल है; gateway की विशिष्ट विफलता यह है कि कम भरोसे वाले request object को destination चुनने दिया जाता है, जबकि privileged outbound credentials दोबारा इस्तेमाल होते हैं।<sup>[[1]](#references)</sup>

## Guardrail registration can bypass a UI-only sandbox

Gateway के code-test path और code-registration path में validation अलग-अलग हो सकती है। LiteLLM v1.82.0 से पहले, UI custom-guardrail test खतरनाक syntax को अस्वीकार करता था और `__builtins__ = {}` के साथ execute करता था, लेकिन `POST /guardrails` बिना इनमें से किसी भी जाँच के `exec(compile(...), exec_globals)` से दिए गए `custom_code` को compile करता था। जिस globals dictionary में `__builtins__` न हो, उसमें Python builtins जोड़ देता है। इसलिए module-level imports और commands **guardrail register होते समय**, किसी भी inference call से पहले execute हो जाते थे। बाद का `apply_guardrail` callback, block reason के ज़रिए संग्रहीत परिणाम उजागर कर सकता था।<sup>[[2]](#references)[[3]](#references)</sup>

अधिकृत test के दौरान, test और registration handlers की तुलना करें; यह न मानें कि UI sandbox test सफल होने से registration सुरक्षित साबित हो जाता है। रिपोर्ट की गई pre-fix request का रूप यह था:<sup>[[2]](#references)</sup>

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

रजिस्ट्रेशन endpoint सामान्य API keys भी स्वीकार करता था, क्योंकि उसमें `PROXY_ADMIN` check नहीं था। जहाँ कोई master key या JWT/OAuth2 authentication कॉन्फ़िगर नहीं था, वहाँ pre-fix auth handler anonymous requests को भी `PROXY_ADMIN` role देता था। Fix ने no-auth role को `INTERNAL_USER` में बदला, guardrail admin checks जोड़े और रजिस्ट्रेशन के दौरान builtins को validate और restrict किया। ये role और code-execution boundaries [MCP token-fallback issue](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session) से अलग हैं।<sup>[[2]](#references)[[3]](#references)</sup>

## Admin pass-through routes cloud metadata को proxy कर सकते हैं

LiteLLM का pass-through endpoint feature किसी administrator को HTTP target कॉन्फ़िगर करने और वैकल्पिक रूप से subpaths जोड़ने देता है। ऊपर बताए गए प्रति-request `user_config` routing issue के विपरीत, इसके लिए **configuration-write authority** आवश्यक है; इस feature का उद्देश्य administrators पर भरोसा करना है। रिपोर्ट किए गए deployment में target को private या link-local addresses के विरुद्ध जाँचा नहीं गया था।<sup>[[2]](#references)[[4]](#references)</sup> v1.83.0 से पहले, सामान्य authenticated keys भी `/config/update` तक पहुँच सकती थीं, क्योंकि उसमें administrator role check नहीं था; संबंधित configuration-write boundary के लिए [UI route classification](#ui-route-classification-is-not-authorization) देखें।<sup>[[2]](#references)[[6]](#references)</sup>

उस authority और proxy से EC2 metadata तक network reachability होने पर, इस तरह का route gateway के ज़रिए metadata उजागर करता है। `include_subpath` flag `/meta/meta-data/iam/security-credentials/` को `/latest/` के अंतर्गत map करता है।<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

[Cloud SSRF गाइड](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) में IMDSv2 token exchange बताया गया है; इस route को इसके `PUT` request की अनुमति देनी होगी और दोनों metadata headers को relay करना होगा।<sup>[[5]](#references)</sup> LiteLLM का generic pass-through header handling, forward करने से पहले `x-pass-` prefix हटा देता है, इसलिए `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` और `x-pass-X-aws-ec2-metadata-token: <token>` उन headers को उपलब्ध करा सकते हैं।<sup>[[2]](#references)[[7]](#references)</sup> Proxy को IMDS तक पहुंचना होगा, token response को configured hop limit से होकर गुजरना होगा, और token request में `X-Forwarded-For` नहीं होना चाहिए।<sup>[[5]](#references)</sup> Gateway-विशिष्ट रूपांतर **admin-controlled persistent route plus request-header relay** है।

## References

- [1] [Check Point Research — जब LLM Gateways में गड़बड़ी होती है: LiteLLM से मिली जानकारियां](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — सतर्क रहें: Authentication Bypass से Cloud Compromise तक LiteLLM को तोड़ना](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — custom code guardrail में unauthenticated RCE और sandbox escape ठीक करना](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Pass Through Endpoints बनाएं](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Instance Metadata Service Version 2 कैसे काम करता है](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [LiteLLM सलाह — unrestricted proxy configuration endpoint](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [LiteLLM pass-through header forwarding implementation](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
