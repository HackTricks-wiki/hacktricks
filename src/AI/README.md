# साइबर सुरक्षा में AI

{{#include ../banners/hacktricks-training.md}}

## मुख्य मशीन लर्निंग एल्गोरिदम

AI के बारे में सीखने की सबसे अच्छी शुरुआत यह समझने से होती है कि मुख्य मशीन लर्निंग एल्गोरिदम कैसे काम करते हैं। इससे आपको समझने में मदद मिलेगी कि AI कैसे काम करता है, इसका उपयोग कैसे करें और इस पर हमला कैसे करें:


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

अगले पेज पर आपको transformers का उपयोग करके एक बुनियादी LLM बनाने के लिए प्रत्येक घटक की मूल बातें मिलेंगी:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Model टूल और प्लेटफ़ॉर्म

Models को चलाने, fine-tune करने, serve करने या आज़माने के लिए [AI model tools and platforms guide](AI-Model-Tools-and-Platforms.md) का उपयोग करें।

## AI सुरक्षा

### AI Agent सुरक्षा कार्यप्रणाली

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI जोखिम फ्रेमवर्क

AI-सिस्टम जोखिम का आकलन करने के लिए दो उपयोगी शुरुआती फ्रेमवर्क हैं: OWASP Machine Learning Security Top 10 और Google का Secure AI Framework (SAIF)। ये एक-दूसरे के पूरक हैं, AI जोखिम फ्रेमवर्क की पूरी सूची नहीं।<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic Interpretability द्वारा निर्देशित Adversarial Attacks

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI Prompts की सुरक्षा

पिछले कुछ वर्षों में LLMs के कारण AI का उपयोग बहुत बढ़ा है, लेकिन वे परिपूर्ण नहीं हैं और adversarial prompts से उन्हें धोखा दिया जा सकता है। यह समझना बहुत ज़रूरी है कि AI का सुरक्षित रूप से उपयोग कैसे करें और इस पर हमला कैसे करें:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

डेवलपर्स और कंपनियों के लिए Internet से डाउनलोड किए गए models चलाना आम है। हालाँकि, केवल model लोड करना ही सिस्टम पर arbitrary code चलाने के लिए पर्याप्त हो सकता है। यह समझना बहुत ज़रूरी है कि AI का सुरक्षित रूप से उपयोग कैसे करें और इस पर हमला कैसे करें:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-सहायता प्राप्त KYC बाईपास

Generative video को virtual-camera injection और camera API manipulation के साथ मिलाकर कमज़ोर KYC, age-verification और biometric liveness workflows को बाईपास किया जा सकता है:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI applications को tools और data sources से जोड़ने के लिए एक open protocol है। चूँकि MCP servers data और actions उपलब्ध करा सकते हैं, इसलिए आकलन में authorization, consent, tool-input validation और trust-boundary review शामिल होना चाहिए।<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-सहायता प्राप्त Fuzzing और स्वचालित Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-सहायता प्राप्त Reverse Engineering

[आंशिक lifting, invariant MBA detection, environment-bound decoding और automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLM-आधारित agents लंबे समय तक चलने वाले black-box web pentesting workflows को स्वचालित कर सकते हैं, बशर्ते उन्हें observability, orchestration, authenticated session handling और adversarial validation का समर्थन मिले:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP मशीन लर्निंग सुरक्षा के शीर्ष 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — सुरक्षित AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — परिचय](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
