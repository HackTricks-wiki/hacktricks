# IA na Cibersegurança

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

Na página a seguir, você encontrará o básico de cada componente necessário para construir um LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Ferramentas e plataformas de modelos

Para executar, fazer fine-tuning, disponibilizar ou experimentar modelos, use o [guia de ferramentas e plataformas de modelos de IA](AI-Model-Tools-and-Platforms.md).

## Segurança de IA

### Limites de confiança de gateways de LLM

Para segurança de gateways, consulte:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologia de segurança de agentes de IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Frameworks de risco de IA

Dois frameworks úteis para começar a avaliar o risco de sistemas de IA são o OWASP Machine Learning Security Top 10 e o Secure AI Framework (SAIF) do Google. Eles são complementares e não constituem uma lista exaustiva de frameworks de risco de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataques adversariais guiados por interpretabilidade mecanística

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Segurança de prompts de IA

O uso de IA explodiu nos últimos anos graças aos LLMs, mas eles não são perfeitos e podem ser enganados por prompts adversariais. Este é um tema muito importante para entender como usar a IA com segurança e como atacá-la:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE em modelos de IA

É muito comum desenvolvedores e empresas executarem modelos baixados da Internet; no entanto, apenas carregar um modelo pode ser suficiente para executar código arbitrário no sistema. Este é um tema muito importante para entender como usar a IA com segurança e como atacá-la:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass de KYC com auxílio de IA

Vídeos generativos podem ser combinados com injeção de câmera virtual e manipulação da API da câmera para contornar fluxos vulneráveis de KYC, verificação de idade e prova de vida biométrica:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de IA

MCP (Model Context Protocol) é um protocolo aberto para conectar aplicações de IA a ferramentas e fontes de dados. Como os servidores MCP podem expor dados e ações, as avaliações devem incluir autorização, consentimento, validação de entradas das ferramentas e análise dos limites de confiança.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing com auxílio de IA e descoberta automatizada de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Revisão de código-fonte e validação de vulnerabilidades com auxílio de IA

Para revisão de source/sink, fluxos de tarefas de pontos de entrada mobile, auditorias de padrões de kernel e validação condicionada a evidências:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Engenharia reversa com auxílio de IA

[Elevação parcial, detecção de MBA invariável, decodificação vinculada ao ambiente e validação de extratores automatizados](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots pentester de IA para Web Black-Box

Agentes com tecnologia LLM podem automatizar fluxos de pentesting web black-box de longa duração quando contam com observabilidade, orquestração, gerenciamento de sessões autenticadas e validação adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 de Segurança de Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework de IA Segura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introdução](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
