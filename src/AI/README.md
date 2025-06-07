# Siber Güvenlikte AI

{{#include ../banners/hacktricks-training.md}}

## Ana Makine Öğrenimi Algoritmaları

AI hakkında öğrenmeye başlamak için en iyi nokta, ana makine öğrenimi algoritmalarının nasıl çalıştığını anlamaktır. Bu, AI'nın nasıl çalıştığını, nasıl kullanılacağını ve nasıl saldırılacağını anlamanıza yardımcı olacaktır:

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

### LLM'lerin Mimarisi

Aşağıdaki sayfada, transformer'lar kullanarak temel bir LLM oluşturmak için her bileşenin temellerini bulacaksınız:

{{#ref}}
llm-architecture/README.md
{{#endref}}

## AI Güvenliği

### AI Risk Çerçeveleri

Bu anda, AI sistemlerinin risklerini değerlendirmek için ana 2 çerçeve OWASP ML Top 10 ve Google SAIF'tir:

{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI İstemleri Güvenliği

LLM'ler son yıllarda AI kullanımını patlattı, ancak mükemmel değiller ve düşmanca istemlerle kandırılabilirler. Bu, AI'yı güvenli bir şekilde kullanmayı ve ona nasıl saldırılacağını anlamak için çok önemli bir konudur:

{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Modelleri RCE

Geliştiricilerin ve şirketlerin İnternetten indirilen modelleri çalıştırması oldukça yaygındır, ancak sadece bir modeli yüklemek, sistemde rastgele kod çalıştırmak için yeterli olabilir. Bu, AI'yı güvenli bir şekilde kullanmayı ve ona nasıl saldırılacağını anlamak için çok önemli bir konudur:

{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Modeli Bağlam Protokolü

MCP (Model Bağlam Protokolü), AI ajanı istemcilerinin harici araçlar ve veri kaynaklarıyla tak-çalıştır tarzında bağlantı kurmasına olanak tanıyan bir protokoldür. Bu, AI modelleri ile harici sistemler arasında karmaşık iş akışları ve etkileşimler sağlar:

{{#ref}}
AI-MCP-Servers.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
