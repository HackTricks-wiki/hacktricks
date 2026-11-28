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

### Preparação e avaliação de dados de modelos

Para divisão de datasets, métricas clássicas e ataques do lado das respostas em avaliações baseadas em LLMs, consulte [preparação e avaliação de dados de modelos](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Arquitetura de LLMs

Na página a seguir, você encontrará os conceitos básicos de cada componente para criar um LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Ferramentas e plataformas de modelos de IA

Para executar, fazer fine-tuning, disponibilizar ou experimentar modelos, consulte o [guia de ferramentas e plataformas de modelos de IA](AI-Model-Tools-and-Platforms.md).

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

Dois frameworks úteis para começar a avaliar riscos de sistemas de IA são o OWASP Machine Learning Security Top 10 e o Secure AI Framework (SAIF) do Google. Eles são complementares, mas não constituem uma lista exaustiva de frameworks de risco de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataques adversariais guiados por interpretabilidade mecanística

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Limites de confiança de navegadores incorporados

Para pontes de navegador de assistentes desktop, falsificação de endereços de abas e leitura de arquivos locais no contexto de workers, consulte [limites de confiança de navegadores incorporados em assistentes de IA](AI-Embedded-Browser-Trust-Boundaries.md).

### Segurança de prompts de IA

Os LLMs fizeram o uso de IA explodir nos últimos anos, mas não são perfeitos e podem ser enganados por prompts adversariais. Este é um tópico muito importante para entender como usar IA com segurança e como atacá-la:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE em modelos de IA

É muito comum desenvolvedores e empresas executarem modelos baixados da Internet; no entanto, simplesmente carregar um modelo pode ser suficiente para executar código arbitrário no sistema. Este é um tópico muito importante para entender como usar IA com segurança e como atacá-la:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Para riscos ao carregar modelos Keras `.keras`/HDF5, camadas Lambda e análise de gadgets após correções, consulte [desserialização de modelos Keras e busca por gadgets](keras-model-deserialization-rce-and-gadget-hunting.md).

### Bypass de KYC com assistência de IA

Vídeos generativos podem ser combinados com injeção de câmera virtual e manipulação da API de câmera para contornar fluxos fracos de KYC, verificação de idade e prova de vida biométrica:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol para IA

MCP (Model Context Protocol) é um protocolo aberto para conectar aplicações de IA a ferramentas e fontes de dados. Como servidores MCP podem expor dados e ações, as avaliações devem incluir autorização, consentimento, validação de entradas de ferramentas e análise dos limites de confiança.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocolo Agent-to-Agent (A2A) de IA

O A2A permite que agentes descubram uns aos outros por meio de um cartão de agente e enviem tarefas uns aos outros por HTTP. Teste cartões de agente, autorização de tarefas, webhooks de notificações push e cartões estendidos:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Serviços de IA self-hosted expostos

Identificação e teste de executores de modelos, construtores de agentes, interfaces de demonstração de ML, clusters de computação e bancos de dados vetoriais expostos que funcionam sem autenticação:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing com assistência de IA e descoberta automatizada de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Revisão de código-fonte e validação de vulnerabilidades com assistência de IA

Para análise de source/sink, fluxos de tarefas de pontos de entrada mobile, auditorias de padrões de kernel e validação baseada em evidências:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Engenharia reversa com assistência de IA

[Elevação parcial, detecção de MBA invariante, decodificação vinculada ao ambiente e validação de extratores automatizados](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web black-box com IA

Agentes baseados em LLM podem automatizar fluxos de trabalho de pentesting web black-box de longa duração quando contam com observabilidade, orquestração, gerenciamento de sessões autenticadas e validação adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Top 10 de segurança de Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework de IA segura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introdução](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
