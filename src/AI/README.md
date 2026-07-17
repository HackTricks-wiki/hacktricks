# IA em Cibersegurança

{{#include ../banners/hacktricks-training.md}}

## Principais Algoritmos de Machine Learning

O melhor ponto de partida para aprender sobre IA é entender como funcionam os principais algoritmos de Machine Learning. Isso ajudará você a entender como a IA funciona, como utilizá-la e como atacá-la:


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

### Arquitetura de LLMs

Na página a seguir, você encontrará os conceitos básicos de cada componente para construir um LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Segurança de IA

### Frameworks de Risco de IA

Atualmente, os 2 principais frameworks para avaliar os riscos de sistemas de IA são o OWASP ML Top 10 e o Google SAIF:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Segurança de Prompts de IA

Os LLMs fizeram o uso de IA explodir nos últimos anos, mas não são perfeitos e podem ser enganados por prompts adversariais. Este é um tópico muito importante para entender como usar a IA com segurança e como atacá-la:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE em Modelos de IA

É muito comum que desenvolvedores e empresas executem modelos baixados da Internet; no entanto, apenas carregar um modelo pode ser suficiente para executar código arbitrário no sistema. Este é um tópico muito importante para entender como usar a IA com segurança e como atacá-la:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Model Context Protocol de IA

MCP (Model Context Protocol) é um protocolo que permite que clientes de agentes de IA se conectem a ferramentas externas e fontes de dados de maneira plug-and-play. Isso possibilita workflows complexos e interações entre modelos de IA e sistemas externos:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing Assistido por IA e Descoberta Automatizada de Vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Bots de Pentesting Web Black-Box com IA

Agentes baseados em LLM podem automatizar workflows prolongados de pentesting web black-box quando contam com observabilidade, orquestração, gerenciamento de sessões autenticadas e validação adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
