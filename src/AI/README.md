# Siber Güvenlikte AI

{{#include ../banners/hacktricks-training.md}}

## Ana Makine Öğrenmesi Algoritmaları

AI hakkında bilgi edinmek için en iyi başlangıç, ana makine öğrenmesi algoritmalarının nasıl çalıştığını anlamaktır. Bu, AI'ın nasıl çalıştığını, nasıl kullanılacağını ve nasıl saldırıya uğratılacağını anlamanıza yardımcı olacaktır:


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

Aşağıdaki sayfada, transformers kullanarak temel bir LLM oluşturmak için her bileşenin temellerini bulacaksınız:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Güvenliği

### AI Risk Framework'leri

Şu anda AI sistemlerinin risklerini değerlendirmek için kullanılan 2 ana framework OWASP ML Top 10 ve Google SAIF'tir:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Güvenliği

LLM'ler son yıllarda AI kullanımını büyük ölçüde yaygınlaştırdı, ancak kusursuz değiller ve adversarial prompt'larla kandırılabilirler. Bu, AI'ı güvenli bir şekilde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak için çok önemli bir konudur:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Modellerinde RCE

Geliştiricilerin ve şirketlerin Internet'ten indirilen modelleri çalıştırması oldukça yaygındır; ancak yalnızca bir modeli yüklemek bile sistemde arbitrary code çalıştırmak için yeterli olabilir. Bu, AI'ı güvenli bir şekilde nasıl kullanacağınızı ve ona nasıl saldıracağınızı anlamak için çok önemli bir konudur:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Destekli KYC Bypass

Generative video, virtual-camera injection ve camera API manipulation ile birleştirilerek zayıf KYC, yaş doğrulama ve biometric liveness iş akışlarını bypass etmek için kullanılabilir:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI agent client'larının external tool'lara ve data source'lara plug-and-play yöntemiyle bağlanmasını sağlayan bir protokoldür. Bu, AI modelleri ile external system'ler arasında karmaşık iş akışlarını ve etkileşimleri mümkün kılar:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Destekli Fuzzing ve Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bot'ları

LLM destekli agent'lar, observability, orchestration, authenticated session handling ve adversarial validation ile desteklendiklerinde uzun süren black-box web pentesting iş akışlarını otomatikleştirebilir:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
