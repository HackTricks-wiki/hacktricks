# Siber Güvenlikte AI

{{#include ../banners/hacktricks-training.md}}

## Başlıca Makine Öğrenimi Algoritmaları

AI hakkında bilgi edinmeye başlamak için en iyi yol, başlıca makine öğrenimi algoritmalarının nasıl çalıştığını anlamaktır. Bu, AI'ın nasıl çalıştığını, nasıl kullanılacağını ve ona nasıl saldırılacağını anlamanıza yardımcı olur:


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

### AI Risk Çerçeveleri

AI sistemi riskini değerlendirmeye başlamak için yararlı iki çerçeve, OWASP Machine Learning Security Top 10 ve Google'ın Secure AI Framework (SAIF) çerçevesidir. Bunlar, AI risk çerçevelerinin kapsamlı bir listesini sunmak yerine birbirini tamamlar.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompt Güvenliği

LLM'ler son yıllarda AI kullanımının hızla yaygınlaşmasını sağladı; ancak kusursuz değiller ve adversarial prompt'larla kandırılabilirler. Bu konu, AI'ı güvenli şekilde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak açısından çok önemlidir:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Modellerinde RCE

Geliştiricilerin ve şirketlerin internetten indirdikleri modelleri çalıştırması oldukça yaygındır; ancak yalnızca bir modeli yüklemek, sistemde rastgele kod çalıştırmak için yeterli olabilir. Bu konu, AI'ı güvenli şekilde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak açısından çok önemlidir:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Destekli KYC Atlatma

Üretken video; sanal kamera enjeksiyonu ve kamera API'si manipülasyonuyla birleştirilerek zayıf KYC, yaş doğrulama ve biyometrik canlılık kontrolleri atlatılabilir:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI uygulamalarını araçlara ve veri kaynaklarına bağlamaya yönelik açık bir protokoldür. MCP sunucuları veri ve eylemlere erişim sağlayabildiğinden, değerlendirmelerde yetkilendirme, izin, araç girdilerinin doğrulanması ve güven sınırlarının incelenmesi yer almalıdır.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Destekli Fuzzing ve Otomatik Güvenlik Açığı Keşfi


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI Destekli Tersine Mühendislik

[Kısmi lifting, invariant MBA tespiti, ortama bağlı kod çözme ve otomatik çıkarıcıların doğrulanması](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Botları

LLM destekli agent'lar; gözlemlenebilirlik, orkestrasyon, kimliği doğrulanmış oturum yönetimi ve adversarial doğrulama ile desteklendiklerinde uzun süren black-box web pentesting iş akışlarını otomatikleştirebilir:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Makine Öğrenimi Güvenliği İlk 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Güvenli AI Çerçevesi (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Giriş](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
