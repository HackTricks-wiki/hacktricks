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

निम्नलिखित पेज पर आपको transformers का उपयोग करके एक basic LLM बनाने के लिए प्रत्येक component की मूल बातें मिलेंगी:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Security

### AI Risk Frameworks

इस समय, AI systems के risks का assessment करने के लिए मुख्य 2 frameworks OWASP ML Top 10 और Google SAIF हैं:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLMs के कारण पिछले कुछ वर्षों में AI का उपयोग बहुत बढ़ गया है, लेकिन वे perfect नहीं हैं और adversarial prompts से trick किए जा सकते हैं। AI का सुरक्षित रूप से उपयोग करने और इस पर attack करने का तरीका समझने के लिए यह एक बहुत महत्वपूर्ण विषय है:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

Developers और companies द्वारा Internet से download किए गए models को run करना बहुत common है, लेकिन केवल model को load करना ही system पर arbitrary code execute करने के लिए पर्याप्त हो सकता है। AI का सुरक्षित रूप से उपयोग करने और इस पर attack करने का तरीका समझने के लिए यह एक बहुत महत्वपूर्ण विषय है:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-Assisted KYC Bypass

Generative video को virtual-camera injection और camera API manipulation के साथ combine करके कमजोर KYC, age-verification और biometric liveness workflows को bypass किया जा सकता है:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) एक ऐसा protocol है जो AI agent clients को external tools और data sources से plug-and-play तरीके से connect करने की अनुमति देता है। इससे AI models और external systems के बीच complex workflows और interactions संभव होते हैं:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

LLM-powered agents लंबे समय तक चलने वाले black-box web pentesting workflows को automate कर सकते हैं, जब उन्हें observability, orchestration, authenticated session handling और adversarial validation का support प्राप्त हो:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
