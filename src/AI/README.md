# Cybersecurity में AI

{{#include ../banners/hacktricks-training.md}}

## मुख्य Machine Learning Algorithms

AI के बारे में सीखने की सबसे अच्छी शुरुआत यह समझना है कि मुख्य machine learning algorithms कैसे काम करते हैं। इससे आपको यह समझने में मदद मिलेगी कि AI कैसे काम करता है, इसका उपयोग कैसे करना है और इस पर attack कैसे करना है:


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

### LLMs Architecture

निम्नलिखित page पर आपको transformers का उपयोग करके basic LLM बनाने के लिए प्रत्येक component की मूल बातें मिलेंगी:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Security

### AI Risk Frameworks

AI-system risk का आकलन करने के लिए दो उपयोगी शुरुआती frameworks हैं: OWASP Machine Learning Security Top 10 और Google का Secure AI Framework (SAIF)। ये एक-दूसरे के पूरक हैं, न कि AI risk frameworks की पूरी सूची।<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLMs ने पिछले कुछ वर्षों में AI के उपयोग को बहुत बढ़ा दिया है, लेकिन वे perfect नहीं हैं और adversarial prompts से trick किए जा सकते हैं। AI का सुरक्षित रूप से उपयोग करने और इस पर attack करने का तरीका समझने के लिए यह एक बहुत महत्वपूर्ण topic है:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

Developers और companies द्वारा Internet से download किए गए models को run करना बहुत common है, लेकिन केवल model load करना ही system पर arbitrary code execute करने के लिए पर्याप्त हो सकता है। AI का सुरक्षित रूप से उपयोग करने और इस पर attack करने का तरीका समझने के लिए यह एक बहुत महत्वपूर्ण topic है:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-Assisted KYC Bypass

Generative video को virtual-camera injection और camera API manipulation के साथ combine करके कमजोर KYC, age-verification और biometric liveness workflows को bypass किया जा सकता है:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI applications को tools और data sources से connect करने के लिए एक open protocol है। क्योंकि MCP servers data और actions expose कर सकते हैं, इसलिए assessments में authorization, consent, tool-input validation और trust-boundary review शामिल होने चाहिए।<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-Assisted Reverse Engineering

[Partial lifting, invariant MBA detection, environment-bound decoding, और automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLM-powered agents observability, orchestration, authenticated session handling और adversarial validation द्वारा supported होने पर लंबे समय तक चलने वाले black-box web pentesting workflows को automate कर सकते हैं:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
