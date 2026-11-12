# Siber Güvenlikte AI

{{#include ../banners/hacktricks-training.md}}

## Temel Makine Öğrenimi Algoritmaları

AI hakkında bilgi edinmek için en iyi başlangıç, temel makine öğrenimi algoritmalarının nasıl çalıştığını anlamaktır. Bu, AI'nin nasıl çalıştığını, nasıl kullanılacağını ve nasıl saldırıya uğratılacağını anlamanıza yardımcı olur:


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

### Model verilerinin hazırlanması ve değerlendirilmesi

Veri kümesi bölümleri, klasik metrikler ve LLM tabanlı değerlendirmeye yönelik yanıt tarafı saldırıları için bkz. [model verilerinin hazırlanması ve değerlendirilmesi](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### LLM mimarisi

Aşağıdaki sayfada, transformers kullanarak temel bir LLM oluşturmak için her bileşenin temellerini bulabilirsiniz:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Model araçları ve platformları

Modelleri çalıştırmak, fine-tune etmek, sunmak veya denemek için [AI model araçları ve platformları kılavuzunu](AI-Model-Tools-and-Platforms.md) kullanın.

## AI Güvenliği

### LLM Gateway Güven sınırları

Gateway güvenliği için bkz.:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agent Güvenliği Metodolojisi

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI Risk Çerçeveleri

AI sistemlerinin risklerini değerlendirmek için yararlı iki başlangıç çerçevesi, OWASP Machine Learning Security Top 10 ve Google'ın Secure AI Framework (SAIF) çerçevesidir. Bunlar, AI risk çerçevelerinin kapsamlı bir listesi olmaktan ziyade birbirini tamamlar.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mekanistik Yorumlanabilirlik Rehberliğinde Adversarial Saldırılar

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI Prompt Güvenliği

LLM'ler son yıllarda AI kullanımını büyük ölçüde artırdı, ancak kusursuz değiller ve adversarial prompt'larla kandırılabilirler. Bu konu, AI'yi güvenli şekilde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak açısından çok önemlidir:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Modellerinde RCE

Geliştiricilerin ve şirketlerin internetten indirilen modelleri çalıştırması oldukça yaygındır; ancak yalnızca bir modeli yüklemek, sistemde keyfi kod çalıştırmak için yeterli olabilir. Bu konu, AI'yi güvenli şekilde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak açısından çok önemlidir:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Destekli KYC Atlatma

Üretken video; sanal kamera enjeksiyonu ve kamera API manipülasyonuyla birleştirilerek zayıf KYC, yaş doğrulama ve biyometrik canlılık kontrolleri atlatılabilir:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI uygulamalarını araçlara ve veri kaynaklarına bağlamak için kullanılan açık bir protokoldür. MCP sunucuları verileri ve eylemleri açığa çıkarabileceğinden, değerlendirmeler yetkilendirme, rıza, araç girdilerinin doğrulanması ve güven sınırlarının incelenmesini kapsamalıdır.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent'lar Arası (A2A) Protokolü

A2A, agent'ların bir agent card aracılığıyla birbirlerini keşfetmesine ve HTTP üzerinden birbirlerine görev göndermesine olanak tanır. Agent card'ları, görev yetkilendirmesini, push-notification webhook'larını ve genişletilmiş card'ları test edin:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### İnternete Açık, Self-Hosted AI Hizmetleri

Kimlik doğrulaması olmadan çalışan ve internete açık model çalıştırıcılarını, agent oluşturucularını, ML demo arayüzlerini, hesaplama kümelerini ve vektör veritabanlarını parmak izine tabi tutma ve test etme:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AI Destekli Fuzzing ve Otomatik Zafiyet Keşfi


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI Destekli Kaynak Kodu İncelemesi ve Zafiyet Doğrulaması

Kaynak/hedef incelemesi, mobil giriş noktası görev akışları, kernel örüntü denetimleri ve kanıta dayalı doğrulama için:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI Destekli Tersine Mühendislik

[Kısmi lifting, invariant MBA tespiti, ortama bağlı kod çözme ve otomatik çıkarıcı doğrulaması](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Botları

LLM destekli agent'lar; gözlemlenebilirlik, orkestrasyon, kimliği doğrulanmış oturum yönetimi ve adversarial doğrulamayla desteklendiklerinde uzun süreli black-box web pentesting iş akışlarını otomatikleştirebilir:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Makine Öğrenimi Güvenliği İlk 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Güvenli AI Çerçevesi (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Giriş](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
