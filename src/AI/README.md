# साइबर सुरक्षा में AI

{{#include ../banners/hacktricks-training.md}}

## मुख्य मशीन लर्निंग एल्गोरिदम

AI के बारे में सीखने की सबसे अच्छी शुरुआत यह समझना है कि मुख्य मशीन लर्निंग एल्गोरिदम कैसे काम करते हैं। इससे आपको यह समझने में मदद मिलेगी कि AI कैसे काम करता है, इसका उपयोग कैसे करें और इस पर हमला कैसे करें:


{{#ref}}
./AI-Supervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Unsupervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Reinforcement-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Deep-Learning.md
{{#endref}}

### LLMs की आर्किटेक्चर

अगले पेज पर आपको transformers का उपयोग करके एक बुनियादी LLM बनाने के लिए हर घटक की मूल बातें मिलेंगी:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## मॉडल टूल और प्लेटफ़ॉर्म

मॉडल चलाने, fine-tune करने, serve करने या आज़माने के लिए [AI मॉडल टूल और प्लेटफ़ॉर्म गाइड](AI-Model-Tools-and-Platforms.md) देखें।

## AI सुरक्षा

### LLM Gateway की Trust Boundaries

Gateway सुरक्षा के लिए देखें:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agent सुरक्षा कार्यप्रणाली

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI जोखिम फ्रेमवर्क

AI-सिस्टम के जोखिम का आकलन करने के लिए दो उपयोगी शुरुआती फ्रेमवर्क हैं: OWASP Machine Learning Security Top 10 और Google का Secure AI Framework (SAIF)। ये एक-दूसरे के पूरक हैं, AI जोखिम फ्रेमवर्क की संपूर्ण सूची नहीं।<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic-Interpretability-Guided Adversarial Attacks

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI Prompts की सुरक्षा

पिछले कुछ वर्षों में LLMs ने AI के उपयोग को तेज़ी से बढ़ाया है, लेकिन वे परिपूर्ण नहीं हैं और adversarial prompts से उन्हें धोखा दिया जा सकता है। AI का सुरक्षित उपयोग करने और उस पर हमला करने का तरीका समझने के लिए यह एक बहुत महत्वपूर्ण विषय है:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

डेवलपर्स और कंपनियों के लिए इंटरनेट से डाउनलोड किए गए मॉडल चलाना बहुत आम है, लेकिन सिर्फ़ मॉडल लोड करने से सिस्टम पर arbitrary code execute हो सकता है। AI का सुरक्षित उपयोग करने और उस पर हमला करने का तरीका समझने के लिए यह एक बहुत महत्वपूर्ण विषय है:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-सहायता प्राप्त KYC Bypass

Generative video को virtual-camera injection और camera API manipulation के साथ जोड़कर कमज़ोर KYC, age-verification और biometric liveness workflows को bypass किया जा सकता है:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI applications को tools और data sources से जोड़ने के लिए एक open protocol है। चूँकि MCP servers डेटा और actions उपलब्ध करा सकते हैं, इसलिए आकलन में authorization, consent, tool-input validation और trust-boundary की समीक्षा शामिल होनी चाहिए।<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent-to-Agent (A2A) Protocol

A2A, agents को agent card के ज़रिए एक-दूसरे को खोजने और HTTP पर tasks भेजने की सुविधा देता है। Agent cards, task authorization, push-notification webhooks और extended cards की जाँच करें:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### उजागर Self-Hosted AI Services

ऐसे उजागर model runners, agent builders, ML demo UIs, compute clusters और vector databases की fingerprinting और जाँच करें, जो authentication के बिना चलते हैं:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AI-सहायता प्राप्त Fuzzing और स्वचालित Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-सहायता प्राप्त Source Review और Vulnerability Validation

Source/sink review, mobile entry-point taskflows, kernel pattern audits और साक्ष्य-आधारित validation के लिए:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI-सहायता प्राप्त Reverse Engineering

[Partial lifting, invariant MBA detection, environment-bound decoding और automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLM-आधारित agents, observability, orchestration, authenticated session handling और adversarial validation से समर्थित होने पर लंबे समय तक चलने वाले black-box web pentesting workflows को स्वचालित कर सकते हैं:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP मशीन लर्निंग सुरक्षा के शीर्ष 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — सुरक्षित AI फ्रेमवर्क (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — परिचय](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
