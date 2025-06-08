# AI em Cibersegurança

{{#include ../banners/hacktricks-training.md}}

## Principais Algoritmos de Aprendizado de Máquina

O melhor ponto de partida para aprender sobre IA é entender como funcionam os principais algoritmos de aprendizado de máquina. Isso ajudará você a entender como a IA funciona, como usá-la e como atacá-la:

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

Na página a seguir, você encontrará o básico de cada componente para construir um LLM básico usando transformers:

{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Segurança da IA

### Estruturas de Risco da IA

Neste momento, as principais 2 estruturas para avaliar os riscos dos sistemas de IA são o OWASP ML Top 10 e o Google SAIF:

{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Segurança de Prompts de IA

LLMs fizeram o uso de IA explodir nos últimos anos, mas não são perfeitos e podem ser enganados por prompts adversariais. Este é um tópico muito importante para entender como usar a IA com segurança e como atacá-la:

{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE de Modelos de IA

É muito comum que desenvolvedores e empresas executem modelos baixados da Internet, no entanto, apenas carregar um modelo pode ser suficiente para executar código arbitrário no sistema. Este é um tópico muito importante para entender como usar a IA com segurança e como atacá-la:

{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Protocolo de Contexto de Modelos de IA

MCP (Protocolo de Contexto de Modelos) é um protocolo que permite que clientes de agentes de IA se conectem a ferramentas externas e fontes de dados de forma plug-and-play. Isso possibilita fluxos de trabalho complexos e interações entre modelos de IA e sistemas externos:

{{#ref}}
AI-MCP-Servers.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
