# IA em Cibersegurança

{{#include ../banners/hacktricks-training.md}}

## Principais algoritmos de Machine Learning

O melhor ponto de partida para aprender sobre IA é entender como funcionam os principais algoritmos de Machine Learning. Isso ajudará você a entender como a IA funciona, como usá-la e como atacá-la:


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

Na página a seguir, você encontrará os conceitos básicos de cada componente necessário para criar um LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Segurança de IA

### Metodologia de segurança de agentes de IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Frameworks de risco de IA

Dois frameworks úteis para começar a avaliar os riscos de sistemas de IA são o OWASP Machine Learning Security Top 10 e o Secure AI Framework (SAIF) do Google. Eles são complementares, não uma lista exaustiva de frameworks de risco de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataques adversariais guiados por interpretabilidade mecanística

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Segurança de prompts de IA

O uso de IA cresceu bastante nos últimos anos com o surgimento dos LLMs, mas eles não são perfeitos e podem ser enganados por prompts adversariais. Este é um tópico muito importante para entender como usar a IA com segurança e como atacá-la:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE em modelos de IA

É muito comum desenvolvedores e empresas executarem modelos baixados da Internet. No entanto, apenas carregar um modelo pode ser suficiente para executar código arbitrário no sistema. Este é um tópico muito importante para entender como usar a IA com segurança e como atacá-la:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass de KYC assistido por IA

Vídeos generativos podem ser combinados com injeção de câmera virtual e manipulação da API da câmera para contornar fluxos fracos de KYC, verificação de idade e prova de vida biométrica:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de IA

MCP (Model Context Protocol) é um protocolo aberto para conectar aplicações de IA a ferramentas e fontes de dados. Como os servidores MCP podem expor dados e ações, as avaliações devem incluir autorização, consentimento, validação de entradas das ferramentas e análise dos limites de confiança.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing e descoberta automatizada de vulnerabilidades assistidos por IA


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Engenharia reversa assistida por IA

[Elevação parcial, detecção de MBA invariantes, decodificação vinculada ao ambiente e validação de extratores automatizados](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de Pentester de IA para Web Black-Box

Agentes baseados em LLM podem automatizar fluxos de trabalho de pentesting web black-box de longa duração quando contam com observabilidade, orquestração, gerenciamento de sessões autenticadas e validação adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 de segurança de Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introdução](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
