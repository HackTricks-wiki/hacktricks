# Siber Güvenlikte AI

{{#include ../banners/hacktricks-training.md}}

## Ana Makine Öğrenimi Algoritmaları

AI hakkında bilgi edinmeye başlamak için en iyi yol, temel makine öğrenimi algoritmalarının nasıl çalıştığını anlamaktır. Bu, AI'ın nasıl çalıştığını, nasıl kullanılacağını ve ona nasıl saldırılacağını anlamanıza yardımcı olur:


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

### LLM Mimarisi

Aşağıdaki sayfada, transformers kullanarak temel bir LLM oluşturmak için her bileşenin temellerini bulabilirsiniz:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Model araçları ve platformları

Modelleri çalıştırmak, fine-tuning yapmak, sunmak veya denemek için [AI model araçları ve platformları kılavuzunu](AI-Model-Tools-and-Platforms.md) kullanın.

## AI Güvenliği

### AI Agent Güvenlik Metodolojisi

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI Risk Çerçeveleri

AI sistemi riskini değerlendirmek için kullanılabilecek iki faydalı başlangıç çerçevesi, OWASP Machine Learning Security Top 10 ve Google Secure AI Framework (SAIF)'tir. Bunlar, AI risk çerçevelerinin kapsamlı bir listesi olmaktan ziyade birbirini tamamlar.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mekanistik Yorumlanabilirlik Kılavuzluğunda Adversarial Saldırılar

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI Prompt Güvenliği

LLM'ler son yıllarda AI kullanımının hızla yaygınlaşmasını sağladı; ancak kusursuz değiller ve adversarial promptlarla kandırılabilirler. Bu, AI'ı güvenli şekilde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak için çok önemli bir konudur:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Modellerinde RCE

Geliştiricilerin ve şirketlerin İnternet'ten indirdikleri modelleri çalıştırması oldukça yaygındır; ancak yalnızca bir modeli yüklemek bile sistemde rastgele kod çalıştırmak için yeterli olabilir. Bu, AI'ı güvenli şekilde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak için çok önemli bir konudur:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Destekli KYC Atlama

Üretken video; zayıf KYC, yaş doğrulama ve biyometrik canlılık denetimi süreçlerini atlatmak için sanal kamera enjeksiyonu ve kamera API manipülasyonuyla birleştirilebilir:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI uygulamalarını araçlara ve veri kaynaklarına bağlamak için kullanılan açık bir protokoldür. MCP sunucuları veri ve eylemlere erişim sağlayabildiğinden, güvenlik değerlendirmeleri yetkilendirme, rıza, araç girdisi doğrulaması ve güven sınırlarının incelenmesini kapsamalıdır.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Destekli Fuzzing ve Otomatik Güvenlik Açığı Keşfi


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI Destekli Tersine Mühendislik

[Partial lifting, invariant MBA tespiti, ortama bağlı kod çözme ve otomatik çıkarıcı doğrulaması](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

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
