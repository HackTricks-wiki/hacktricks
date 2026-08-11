# Siber Güvenlikte AI

{{#include ../banners/hacktricks-training.md}}

## Temel Machine Learning Algoritmaları

AI hakkında bilgi edinmek için en iyi başlangıç noktası, temel machine learning algoritmalarının nasıl çalıştığını anlamaktır. Bu, AI'ın nasıl çalıştığını, nasıl kullanılacağını ve nasıl saldırıya uğratılabileceğini anlamanıza yardımcı olur:


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

### LLMs Mimarisi

Aşağıdaki sayfada, transformers kullanarak temel bir LLM oluşturmak için her bileşenin temellerini bulabilirsiniz:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Güvenliği

### AI Risk Frameworks

AI-system riskini değerlendirmek için yararlı iki başlangıç framework'ü, OWASP Machine Learning Security Top 10 ve Google's Secure AI Framework (SAIF)'tir. Bunlar kapsamlı bir AI risk framework'leri listesi olmaktan ziyade birbirlerini tamamlar.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLM'ler son yıllarda AI kullanımını büyük ölçüde artırdı, ancak kusursuz değiller ve adversarial prompt'larla kandırılabilirler. Bu, AI'ı güvenli bir şekilde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak için çok önemli bir konudur:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

Geliştiricilerin ve şirketlerin Internet'ten indirilen modelleri çalıştırması oldukça yaygındır; ancak yalnızca bir modeli yüklemek bile sistemde arbitrary code çalıştırmak için yeterli olabilir. Bu, AI'ı güvenli bir şekilde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak için çok önemli bir konudur:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-Assisted KYC Bypass

Generative video; zayıf KYC, age-verification ve biometric liveness iş akışlarını bypass etmek için virtual-camera injection ve camera API manipulation ile birleştirilebilir:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI uygulamalarını tools ve data sources'a bağlamak için kullanılan açık bir protokoldür. MCP server'ları data ve action'ları açığa çıkarabildiğinden, değerlendirmeler authorization, consent, tool-input validation ve trust-boundary review süreçlerini içermelidir.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

LLM destekli agent'lar, observability, orchestration, authenticated session handling ve adversarial validation ile desteklendiklerinde uzun süren black-box web pentesting iş akışlarını otomatikleştirebilir:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
