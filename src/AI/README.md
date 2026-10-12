# Siber Güvenlikte AI

{{#include ../banners/hacktricks-training.md}}

## Temel Machine Learning Algoritmaları

AI hakkında bilgi edinmeye başlamak için en iyi yol, temel machine learning algoritmalarının nasıl çalıştığını anlamaktır. Bu, AI'ın nasıl çalıştığını, nasıl kullanılacağını ve ona nasıl saldırılacağını anlamanıza yardımcı olur:


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

Aşağıdaki sayfada, transformers kullanarak temel bir LLM oluşturmak için gereken her bileşenin temellerini bulabilirsiniz:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Güvenliği

### AI Agent Güvenliği Metodolojisi

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI Risk Framework'leri

AI sistemi risklerini değerlendirmek için yararlı iki başlangıç framework'ü, OWASP Machine Learning Security Top 10 ve Google'ın Secure AI Framework'üdür (SAIF). Bunlar, AI risk framework'lerinin kapsamlı bir listesi olmaktan ziyade birbirini tamamlar.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mekanistik Yorumlanabilirlik Rehberliğinde Adversarial Saldırılar

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI Prompt Güvenliği

LLM'ler son yıllarda AI kullanımını büyük ölçüde artırdı; ancak kusursuz değiller ve adversarial prompt'larla kandırılabilirler. Bu, AI'ı güvenli biçimde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak için çok önemli bir konudur:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Modellerinde RCE

Geliştiricilerin ve şirketlerin internetten indirdikleri modelleri çalıştırması oldukça yaygındır. Ancak yalnızca bir modeli yüklemek bile sistemde rastgele kod çalıştırmak için yeterli olabilir. Bu, AI'ı güvenli biçimde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak için çok önemli bir konudur:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Destekli KYC Bypass

Generative video; sanal kamera enjeksiyonu ve kamera API manipülasyonuyla birleştirilerek zayıf KYC, yaş doğrulama ve biyometrik canlılık kontrolleri atlatılabilir:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI uygulamalarını araçlara ve veri kaynaklarına bağlamaya yönelik açık bir protokoldür. MCP sunucuları veri ve eylemlere erişim sağlayabildiğinden, değerlendirmelerde yetkilendirme, onay, araç girdisi doğrulaması ve güven sınırlarının incelenmesi ele alınmalıdır.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Destekli Fuzzing ve Otomatik Zafiyet Keşfi


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI Destekli Reverse Engineering

[Partial lifting, invariant MBA detection, environment-bound decoding, and automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Botları

LLM destekli agent'lar; gözlemlenebilirlik, orkestrasyon, kimliği doğrulanmış oturum yönetimi ve adversarial doğrulamayla desteklendiklerinde uzun süreli black-box web pentesting iş akışlarını otomatikleştirebilir:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security İlk 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Güvenli AI Framework'ü (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Giriş](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
