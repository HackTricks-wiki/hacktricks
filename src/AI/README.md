# Cybersecurity'de AI

{{#include ../banners/hacktricks-training.md}}

## Ana Machine Learning Algoritmaları

AI hakkında bilgi edinmek için en iyi başlangıç, ana machine learning algoritmalarının nasıl çalıştığını anlamaktır. Bu, AI'ın nasıl çalıştığını, nasıl kullanılacağını ve nasıl attack edileceğini anlamanıza yardımcı olacaktır:


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

Aşağıdaki sayfada, transformers kullanarak temel bir LLM oluşturmak için her bir bileşenin temellerini bulabilirsiniz:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Security

### AI Risk Framework'leri

Şu anda AI sistemlerinin risklerini değerlendirmek için kullanılan 2 ana framework OWASP ML Top 10 ve Google SAIF'tir:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompt Security

LLM'ler son yıllarda AI kullanımını büyük ölçüde artırdı, ancak kusursuz değiller ve adversarial prompt'larla kandırılabilirler. Bu, AI'ı güvenli bir şekilde nasıl kullanacağınızı ve nasıl attack edeceğinizi anlamak için çok önemli bir konudur:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

Geliştiricilerin ve şirketlerin Internet'ten indirilen modelleri çalıştırması çok yaygındır; ancak yalnızca bir model yüklemek bile sistemde arbitrary code çalıştırmak için yeterli olabilir. Bu, AI'ı güvenli bir şekilde nasıl kullanacağınızı ve nasıl attack edeceğinizi anlamak için çok önemli bir konudur:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol), AI agent client'larının harici araçlara ve veri kaynaklarına plug-and-play yöntemiyle bağlanmasını sağlayan bir protocol'dür. Bu, AI modelleri ile harici sistemler arasında karmaşık workflow'ları ve etkileşimleri mümkün kılar:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bot'ları

LLM destekli agent'lar; observability, orchestration, authenticated session handling ve adversarial validation ile desteklendiklerinde uzun süren black-box web pentesting workflow'larını otomatikleştirebilir:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
