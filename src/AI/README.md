# साइबर सुरक्षा में AI

{{#include ../banners/hacktricks-training.md}}

## मुख्य Machine Learning Algorithms

AI के बारे में सीखने की शुरुआत करने का सबसे अच्छा तरीका यह समझना है कि मुख्य machine learning algorithms कैसे काम करते हैं। इससे आपको यह समझने में मदद मिलेगी कि AI कैसे काम करता है, इसका उपयोग कैसे करें और इस पर हमला कैसे करें:


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

### Model डेटा की तैयारी और मूल्यांकन

Dataset splits, classical metrics और LLM-आधारित grading पर answer-side attacks के लिए, [model डेटा की तैयारी और मूल्यांकन](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection) देखें।

### LLMs का आर्किटेक्चर

अगले पेज पर आपको transformers का उपयोग करके एक basic LLM बनाने के लिए प्रत्येक component की मूल बातें मिलेंगी:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Model tools और platforms

Models चलाने, fine-tune करने, serve करने या आज़माने के लिए, [AI model tools और platforms गाइड](AI-Model-Tools-and-Platforms.md) का उपयोग करें।

## AI सुरक्षा

### LLM Gateway की Trust Boundaries

Gateway सुरक्षा के लिए, देखें:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agent सुरक्षा कार्यप्रणाली

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI जोखिम ढाँचे

AI-system जोखिम का आकलन करने के लिए दो उपयोगी शुरुआती ढाँचे हैं OWASP Machine Learning Security Top 10 और Google का Secure AI Framework (SAIF)। ये एक-दूसरे के पूरक हैं, न कि AI जोखिम ढाँचों की संपूर्ण सूची।<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic Interpretability-निर्देशित Adversarial Attacks

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### एम्बेडेड ब्राउज़र की Trust Boundaries

Desktop-assistant browser bridges, tab-address spoofing और worker-context में local-file पढ़ने के लिए, [AI assistant की एम्बेडेड ब्राउज़र trust boundaries](AI-Embedded-Browser-Trust-Boundaries.md) देखें।

### AI Prompts की सुरक्षा

पिछले कुछ वर्षों में LLMs ने AI के उपयोग को तेज़ी से बढ़ाया है, लेकिन वे परिपूर्ण नहीं हैं और adversarial prompts से उन्हें धोखा दिया जा सकता है। AI का सुरक्षित उपयोग कैसे करें और इस पर हमला कैसे करें, यह समझने के लिए यह एक बहुत महत्वपूर्ण विषय है:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

डेवलपर्स और कंपनियों के लिए Internet से डाउनलोड किए गए models चलाना बहुत आम है, लेकिन केवल model लोड करना ही सिस्टम पर arbitrary code execute करने के लिए पर्याप्त हो सकता है। AI का सुरक्षित उपयोग कैसे करें और इस पर हमला कैसे करें, यह समझने के लिए यह एक बहुत महत्वपूर्ण विषय है:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-सहायता से KYC Bypass

Generative video को virtual-camera injection और camera API manipulation के साथ मिलाकर कमजोर KYC, age-verification और biometric liveness workflows को bypass किया जा सकता है:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) AI applications को tools और data sources से जोड़ने के लिए एक open protocol है। चूँकि MCP servers डेटा और कार्रवाइयाँ उपलब्ध करा सकते हैं, इसलिए assessments में authorization, consent, tool-input validation और trust-boundary review शामिल होने चाहिए।<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent-to-Agent (A2A) Protocol

A2A agents को agent card के ज़रिए एक-दूसरे को खोजने और HTTP पर tasks भेजने देता है। Agent cards, task authorization, push-notification webhooks और extended cards की जाँच करें:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### उजागर Self-Hosted AI Services

बिना authentication के चलने वाले उजागर model runners, agent builders, ML demo UIs, compute clusters और vector databases की fingerprinting और testing:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AI-सहायता से Fuzzing और स्वचालित Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-सहायता से Source Review और Vulnerability Validation

Source/sink review, mobile entry-point taskflows, kernel pattern audits और evidence-gated validation के लिए:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI-सहायता से Reverse Engineering

[Partial lifting, invariant MBA detection, environment-bound decoding और automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLM-संचालित agents लंबे समय तक चलने वाले black-box web pentesting workflows को automate कर सकते हैं, जब उन्हें observability, orchestration, authenticated session handling और adversarial validation का समर्थन मिले:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — परिचय](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
