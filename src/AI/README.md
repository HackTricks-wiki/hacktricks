# साइबर सुरक्षा में AI

{{#include ../banners/hacktricks-training.md}}

## मुख्य Machine Learning Algorithms

AI के बारे में सीखने की सबसे अच्छी शुरुआत यह समझने से होती है कि मुख्य machine learning algorithms कैसे काम करते हैं। इससे आपको समझने में मदद मिलेगी कि AI कैसे काम करता है, इसका उपयोग कैसे करें और इस पर हमला कैसे करें:


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

### LLM Architecture

अगले पेज पर आपको transformers का उपयोग करके एक बुनियादी LLM बनाने के लिए हर component की बुनियादी जानकारी मिलेगी:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Model tools और platforms

Models को चलाने, fine-tune करने, serve करने या आज़माने के लिए [AI model tools और platforms guide](AI-Model-Tools-and-Platforms.md) देखें।

## AI Security

### LLM Gateway Trust Boundaries

Gateway security के लिए देखें:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agent Security Methodology

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI Risk Frameworks

AI-system के जोखिम का आकलन करने के लिए दो उपयोगी शुरुआती frameworks हैं OWASP Machine Learning Security Top 10 और Google's Secure AI Framework (SAIF)। ये एक-दूसरे के पूरक हैं, न कि AI risk frameworks की पूरी सूची।<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic-Interpretability-Guided Adversarial Attacks

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI Prompts Security

पिछले कुछ वर्षों में LLMs के कारण AI का उपयोग तेज़ी से बढ़ा है, लेकिन वे परिपूर्ण नहीं हैं और adversarial prompts से उन्हें धोखा दिया जा सकता है। AI का सुरक्षित उपयोग करने और उस पर हमला करने का तरीका समझने के लिए यह एक बहुत महत्वपूर्ण विषय है:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

Developers और कंपनियों द्वारा Internet से डाउनलोड किए गए models चलाना बहुत आम है। हालांकि, सिर्फ़ model load करने से ही system पर arbitrary code execute हो सकता है। AI का सुरक्षित उपयोग करने और उस पर हमला करने का तरीका समझने के लिए यह एक बहुत महत्वपूर्ण विषय है:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-Assisted KYC Bypass

Generative video को virtual-camera injection और camera API manipulation के साथ मिलाकर कमज़ोर KYC, age-verification और biometric liveness workflows को bypass किया जा सकता है:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI applications को tools और data sources से जोड़ने के लिए एक open protocol है। चूंकि MCP servers data और actions उपलब्ध करा सकते हैं, इसलिए assessments में authorization, consent, tool-input validation और trust-boundary review शामिल होने चाहिए।<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-Assisted Source Review और Vulnerability Validation

Source/sink review, mobile entry-point taskflows, kernel pattern audits और evidence-gated validation के लिए:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI-Assisted Reverse Engineering

[Partial lifting, invariant MBA detection, environment-bound decoding और automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLM-powered agents लंबे समय तक चलने वाले black-box web pentesting workflows को automate कर सकते हैं, बशर्ते उन्हें observability, orchestration, authenticated session handling और adversarial validation का समर्थन मिले:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security के शीर्ष 10 जोखिम](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — परिचय](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
