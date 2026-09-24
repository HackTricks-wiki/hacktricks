# IA em Cibersegurança

{{#include ../banners/hacktricks-training.md}}

## Principais Algoritmos de Machine Learning

O melhor ponto de partida para aprender sobre IA é entender como funcionam os principais algoritmos de machine learning. Isso ajudará você a entender como a IA funciona, como usá-la e como atacá-la:


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

Na página a seguir, você encontrará os conceitos básicos de cada componente para criar um LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Segurança de IA

### Frameworks de Risco de IA

Dois frameworks iniciais úteis para avaliar riscos de sistemas de IA são o OWASP Machine Learning Security Top 10 e o Secure AI Framework (SAIF) do Google. Eles são complementares, e não uma lista exaustiva de frameworks de risco de IA.<sup>[[1]](#references)[[2]](#references)</sup>


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

### Bypass de KYC Assistido por IA

Vídeos generativos podem ser combinados com injeção de câmera virtual e manipulação da API da câmera para realizar bypass de KYC fraco, verificação de idade e workflows de detecção de presença biométrica:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de IA

MCP (Model Context Protocol) é um protocolo aberto para conectar aplicações de IA a ferramentas e fontes de dados. Como os servidores MCP podem expor dados e ações, as avaliações devem incluir autorização, consentimento, validação de entradas de ferramentas e revisão dos limites de confiança.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing Assistido por IA e Descoberta Automatizada de Vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Reverse Engineering Assistida por IA

[Partial lifting, invariant MBA detection, environment-bound decoding, and automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de Pentesting Web Black-Box com IA

Agentes baseados em LLM podem automatizar workflows prolongados de pentesting web black-box quando contam com observabilidade, orquestração, gerenciamento de sessões autenticadas e validação adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introdução](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
