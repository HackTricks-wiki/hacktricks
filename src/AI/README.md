# IA em Cibersegurança

{{#include ../banners/hacktricks-training.md}}

## Principais algoritmos de aprendizado de máquina

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

Na página a seguir, você encontrará os fundamentos de cada componente para criar um LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Ferramentas e plataformas de modelos

Para executar, fazer fine-tuning, disponibilizar ou experimentar modelos, use o [guia de ferramentas e plataformas de modelos de IA](AI-Model-Tools-and-Platforms.md).

## Segurança de IA

### Limites de confiança de gateways de LLM

Para saber mais sobre a segurança de gateways, consulte:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologia de segurança de agentes de IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Frameworks de risco de IA

Dois frameworks úteis para começar a avaliar os riscos de sistemas de IA são o OWASP Machine Learning Security Top 10 e o Secure AI Framework (SAIF) do Google. Eles são complementares, mas não constituem uma lista exaustiva de frameworks de risco de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataques adversariais guiados por interpretabilidade mecanística

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Segurança de prompts de IA

O uso de IA explodiu nos últimos anos com os LLMs, mas eles não são perfeitos e podem ser enganados por prompts adversariais. Este é um tópico muito importante para entender como usar a IA com segurança e como atacá-la:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE em modelos de IA

É muito comum que desenvolvedores e empresas executem modelos baixados da Internet. No entanto, apenas carregar um modelo pode ser suficiente para executar código arbitrário no sistema. Este é um tópico muito importante para entender como usar a IA com segurança e como atacá-la:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass de KYC assistido por IA

Vídeos generativos podem ser combinados com injection de câmera virtual e manipulação da API da câmera para contornar processos fracos de KYC, verificação de idade e prova de vivacidade biométrica:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de IA

O MCP (Model Context Protocol) é um protocolo aberto para conectar aplicações de IA a ferramentas e fontes de dados. Como servidores MCP podem expor dados e ações, as avaliações devem incluir autorização, consentimento, validação de entradas de ferramentas e análise dos limites de confiança.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocolo de agente para agente (A2A) de IA

O A2A permite que agentes descubram uns aos outros por meio de um cartão de agente e enviem tarefas entre si por HTTP. Teste cartões de agente, autorização de tarefas, webhooks de notificações push e cartões estendidos:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Serviços de IA auto-hospedados expostos

Identificação e teste de executores de modelos, criadores de agentes, interfaces de demonstração de ML, clusters de computação e bancos de dados vetoriais expostos e sem autenticação:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing assistido por IA e descoberta automatizada de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Análise de código-fonte e validação de vulnerabilidades assistidas por IA

Para análise de source/sink, fluxos de tarefas de pontos de entrada mobile, auditorias de padrões do kernel e validação condicionada a evidências:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Engenharia reversa assistida por IA

[Elevação parcial, detecção de MBA invariante, decodificação vinculada ao ambiente e validação de extratores automatizados](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web black-box com IA

Agentes com tecnologia de LLM podem automatizar fluxos de trabalho de pentesting web black-box de longa duração quando contam com observabilidade, orquestração, tratamento de sessões autenticadas e validação adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 de segurança de aprendizado de máquina](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework de IA segura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introdução](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
