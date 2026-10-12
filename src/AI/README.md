# साइबर सुरक्षा में AI

{{#include ../banners/hacktricks-training.md}}

## मुख्य मशीन लर्निंग एल्गोरिदम

AI के बारे में सीखने की शुरुआत के लिए यह समझना सबसे अच्छा है कि मुख्य मशीन लर्निंग एल्गोरिदम कैसे काम करते हैं। इससे आपको समझने में मदद मिलेगी कि AI कैसे काम करता है, इसका उपयोग कैसे करें और इस पर हमला कैसे करें:


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

### LLMs की संरचना

अगले पेज पर आपको transformers का उपयोग करके एक बुनियादी LLM बनाने के लिए हर घटक की बुनियादी जानकारी मिलेगी:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI सुरक्षा

### AI Agent सुरक्षा कार्यप्रणाली

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI जोखिम Frameworks

AI-सिस्टम के जोखिम का आकलन करने के लिए OWASP Machine Learning Security Top 10 और Google का Secure AI Framework (SAIF), शुरुआत के दो उपयोगी Frameworks हैं। ये एक-दूसरे के पूरक हैं, न कि AI जोखिम Frameworks की संपूर्ण सूची।<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic-Interpretability-Guided Adversarial Attacks

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI Prompts की सुरक्षा

पिछले कुछ वर्षों में LLMs ने AI के उपयोग को बहुत बढ़ा दिया है, लेकिन वे परिपूर्ण नहीं हैं और adversarial prompts से उन्हें धोखा दिया जा सकता है। AI का सुरक्षित रूप से उपयोग करने और उस पर हमला करने का तरीका समझने के लिए यह एक बहुत महत्वपूर्ण विषय है:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

डेवलपर्स और कंपनियों के लिए इंटरनेट से डाउनलोड किए गए models चलाना बहुत आम है, लेकिन सिर्फ़ किसी model को लोड करना ही सिस्टम पर arbitrary code चलाने के लिए काफ़ी हो सकता है। AI का सुरक्षित रूप से उपयोग करने और उस पर हमला करने का तरीका समझने के लिए यह एक बहुत महत्वपूर्ण विषय है:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-सहायता प्राप्त KYC Bypass

Generative video को virtual-camera injection और camera API manipulation के साथ मिलाकर कमज़ोर KYC, आयु-सत्यापन और biometric liveness workflows को bypass किया जा सकता है:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI applications को tools और data sources से जोड़ने के लिए एक खुला protocol है। चूँकि MCP servers डेटा और कार्रवाइयों तक पहुँच दे सकते हैं, इसलिए आकलन में authorization, consent, tool-input validation और trust-boundary review शामिल होने चाहिए।<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-सहायता प्राप्त Fuzzing और स्वचालित Vulnerability खोज


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-सहायता प्राप्त Reverse Engineering

[Partial lifting, invariant MBA detection, environment-bound decoding, and automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLM-संचालित agents, observability, orchestration, authenticated session handling और adversarial validation के साथ समर्थित होने पर, लंबे समय तक चलने वाले black-box web pentesting workflows को स्वचालित कर सकते हैं:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP मशीन लर्निंग सुरक्षा के शीर्ष 10 जोखिम](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — सुरक्षित AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — परिचय](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
