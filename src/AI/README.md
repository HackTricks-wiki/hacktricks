# Siber Güvenlikte Yapay Zeka

{{#include ../banners/hacktricks-training.md}}

## Başlıca Makine Öğrenimi Algoritmaları

Yapay zekayı öğrenmeye başlamak için en iyi yol, başlıca makine öğrenimi algoritmalarının nasıl çalıştığını anlamaktır. Bu, yapay zekanın nasıl çalıştığını, nasıl kullanılacağını ve ona nasıl saldırılacağını anlamanıza yardımcı olur:


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

### LLM Gateway Güven Sınırları

Gateway güvenliği için bkz.:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agent Güvenliği Metodolojisi

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI Risk Çerçeveleri

AI sistemi risklerini değerlendirmek için kullanılabilecek iki yararlı başlangıç çerçevesi, OWASP Machine Learning Security Top 10 ve Google Secure AI Framework'tür (SAIF). Bunlar birbirini tamamlar; AI risk çerçevelerinin kapsamlı bir listesi değildir.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mekanistik Yorumlanabilirlik Rehberliğinde Adversarial Saldırılar

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI Prompt Güvenliği

LLM'ler son yıllarda AI kullanımını büyük ölçüde yaygınlaştırdı; ancak kusursuz değiller ve adversarial promptlarla kandırılabilirler. Bu konu, AI'ı güvenli biçimde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak açısından çok önemlidir:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Modellerinde RCE

Geliştiricilerin ve şirketlerin internetten indirdikleri modelleri çalıştırması çok yaygındır; ancak yalnızca bir modeli yüklemek sistemde rastgele kod çalıştırmak için yeterli olabilir. Bu konu, AI'ı güvenli biçimde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak açısından çok önemlidir:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Destekli KYC Bypass

Üretken video, zayıf KYC, yaş doğrulama ve biyometrik canlılık iş akışlarını bypass etmek için sanal kamera enjeksiyonu ve kamera API manipülasyonuyla birleştirilebilir:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI uygulamalarını araçlara ve veri kaynaklarına bağlamak için kullanılan açık bir protokoldür. MCP sunucuları verileri ve işlemleri açığa çıkarabildiğinden, değerlendirmeler yetkilendirme, rıza, araç girdilerinin doğrulanması ve güven sınırlarının incelenmesini kapsamalıdır.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Destekli Fuzzing ve Otomatik Zafiyet Keşfi


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI Destekli Kaynak İncelemesi ve Zafiyet Doğrulaması

Kaynak/hedef incelemesi, mobil giriş noktası görev akışları, kernel örüntü denetimleri ve kanıta dayalı doğrulama için:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI Destekli Tersine Mühendislik

[Partial lifting, invariant MBA tespiti, ortama bağlı çözümleme ve otomatik çıkarıcı doğrulaması](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Botları

LLM destekli agent'lar; gözlemlenebilirlik, orkestrasyon, kimliği doğrulanmış oturum yönetimi ve adversarial doğrulama ile desteklendiklerinde, uzun süreli black-box web pentesting iş akışlarını otomatikleştirebilir:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
