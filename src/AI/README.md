# Siber Güvenlikte AI

{{#include ../banners/hacktricks-training.md}}

## Temel Machine Learning Algoritmaları

AI hakkında bilgi edinmek için en iyi başlangıç, temel machine learning algoritmalarının nasıl çalıştığını anlamaktır. Bu, AI'ın nasıl çalıştığını, nasıl kullanılacağını ve ona nasıl saldırılacağını anlamanıza yardımcı olur:


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

### Model verilerini hazırlama ve değerlendirme

Dataset bölme, klasik metrikler ve LLM tabanlı notlandırmaya yönelik yanıt tarafı saldırıları için bkz. [model verilerini hazırlama ve değerlendirme](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### LLM Mimarisi

Aşağıdaki sayfada, transformers kullanarak temel bir LLM oluşturmak için gereken her bileşenin temel bilgilerini bulabilirsiniz:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Model araçları ve platformları

Modelleri çalıştırmak, fine-tune etmek, sunmak veya denemek için [AI model araçları ve platformları kılavuzunu](AI-Model-Tools-and-Platforms.md) kullanın.

## AI Güvenliği

### LLM Gateway Güven Sınırları

Gateway güvenliği hakkında bilgi için bkz.:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agent Güvenlik Metodolojisi

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI Risk Çerçeveleri

AI sistemlerindeki riskleri değerlendirmek için yararlı iki başlangıç çerçevesi, OWASP Machine Learning Security Top 10 ve Google Secure AI Framework (SAIF)'tir. Bunlar birbirini tamamlar; AI risk çerçevelerinin kapsamlı bir listesi değildir.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mekanistik Yorumlanabilirlik Rehberliğinde Adversarial Saldırılar

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Gömülü tarayıcı güven sınırları

Masaüstü asistanlarının tarayıcı köprüleri, sekme adresi sahteciliği ve worker bağlamından yerel dosya okumaları hakkında bilgi için bkz. [AI asistanlarının gömülü tarayıcı güven sınırları](AI-Embedded-Browser-Trust-Boundaries.md).

### AI Prompt Güvenliği

LLM'ler son yıllarda AI kullanımının hızla artmasını sağladı, ancak kusursuz değiller ve adversarial prompt'larla kandırılabilirler. Bu, AI'ı güvenli bir şekilde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak için çok önemli bir konudur:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Modellerinde RCE

Geliştiricilerin ve şirketlerin Internet'ten indirilen modelleri çalıştırması oldukça yaygındır; ancak yalnızca bir modeli yüklemek, sistemde rastgele kod çalıştırmak için yeterli olabilir. Bu, AI'ı güvenli bir şekilde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak için çok önemli bir konudur:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Keras `.keras`/HDF5 model yükleme riskleri, Lambda katmanları ve düzeltme sonrası gadget analizleri için bkz. [Keras model deserialization ve gadget avı](keras-model-deserialization-rce-and-gadget-hunting.md).

### AI Destekli KYC Bypass

Generative video; zayıf KYC, yaş doğrulama ve biyometrik canlılık kontrollerini atlatmak için sanal kamera enjeksiyonu ve kamera API manipülasyonuyla birleştirilebilir:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI uygulamalarını araçlara ve veri kaynaklarına bağlamak için kullanılan açık bir protokoldür. MCP sunucuları verileri ve eylemleri açığa çıkarabildiğinden, değerlendirmeler yetkilendirme, rıza, araç girdisi doğrulaması ve güven sınırlarının incelenmesini kapsamalıdır.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent-to-Agent (A2A) Protokolü

A2A, agent'ların bir agent card aracılığıyla birbirlerini keşfetmelerini ve HTTP üzerinden birbirlerine görev göndermelerini sağlar. Agent card'ları, görev yetkilendirmesini, push-notification webhook'larını ve genişletilmiş card'ları test edin:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### İnternete Açık, Self-Hosted AI Hizmetleri

Kimlik doğrulaması olmadan çalışan ve internete açık model runner'larını, agent builder'larını, ML demo arayüzlerini, compute cluster'larını ve vector database'lerini parmak izleyip test etme:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AI Destekli Fuzzing ve Otomatik Zafiyet Keşfi


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI Destekli Kaynak Kodu İncelemesi ve Zafiyet Doğrulaması

Source/sink incelemesi, mobil giriş noktası taskflow'ları, kernel pattern denetimleri ve kanıt koşullu doğrulama için:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI Destekli Tersine Mühendislik

[Partial lifting, invariant MBA tespiti, ortama bağlı decoding ve otomatik extractor doğrulaması](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Botları

LLM destekli agent'lar; gözlemlenebilirlik, orkestrasyon, kimliği doğrulanmış oturum yönetimi ve adversarial doğrulama desteğiyle uzun süre çalışan black-box web pentesting iş akışlarını otomatikleştirebilir:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
