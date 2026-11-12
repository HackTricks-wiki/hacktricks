# AI em Cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Principais algoritmos de Machine Learning

O melhor ponto de partida para aprender sobre AI é entender como funcionam os principais algoritmos de Machine Learning. Isso ajudará você a entender como AI funciona, como usá-la e como atacá-la:


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

Para divisões de datasets, métricas clássicas e ataques no lado da resposta contra avaliações baseadas em LLM, consulte [preparação e avaliação de dados de modelos](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Arquitetura de LLMs

Na página a seguir, você encontrará os conceitos básicos de cada componente para construir um LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Ferramentas e plataformas de modelos

Para executar, fazer fine-tuning, disponibilizar ou testar modelos, consulte o [guia de ferramentas e plataformas de modelos de AI](AI-Model-Tools-and-Platforms.md).

## Segurança de AI

### Limites de confiança de LLM Gateway

Para segurança de gateway, consulte:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologia de segurança de AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Frameworks de risco de AI

Dois frameworks úteis para começar a avaliar os riscos de sistemas de AI são o OWASP Machine Learning Security Top 10 e o Secure AI Framework (SAIF), do Google. Eles se complementam, mas não constituem uma lista exaustiva de frameworks de risco de AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataques adversariais guiados por Mechanistic Interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Segurança de prompts de AI

Nos últimos anos, os LLMs fizeram o uso de AI explodir, mas não são perfeitos e podem ser enganados por prompts adversariais. Este é um tópico muito importante para entender como usar AI com segurança e como atacá-la:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE em modelos de AI

É muito comum que desenvolvedores e empresas executem modelos baixados da Internet. No entanto, apenas carregar um modelo pode ser suficiente para executar código arbitrário no sistema. Este é um tópico muito importante para entender como usar AI com segurança e como atacá-la:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass de KYC assistido por AI

Vídeos generativos podem ser combinados com injeção de câmera virtual e manipulação da API da câmera para contornar fluxos de KYC, verificação de idade e detecção de vivacidade biométrica mal protegidos:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de AI

MCP (Model Context Protocol) é um protocolo aberto para conectar aplicações de AI a ferramentas e fontes de dados. Como os servidores MCP podem expor dados e ações, as avaliações devem incluir autorização, consentimento, validação de entradas de ferramentas e análise dos limites de confiança.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocolo AI Agent-to-Agent (A2A)

O A2A permite que agents descubram uns aos outros por meio de um agent card e enviem tarefas entre si por HTTP. Teste os agent cards, a autorização de tarefas, os webhooks de notificações push e os cards estendidos:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Serviços de AI self-hosted expostos

Identificação e teste de runners de modelos, criadores de agents, interfaces de demonstração de ML, clusters de computação e bancos de dados vetoriais expostos e sem autenticação:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing assistido por AI e descoberta automatizada de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Análise de código-fonte e validação de vulnerabilidades assistidas por AI

Para análise de source/sink, fluxos de tarefas de pontos de entrada mobile, auditorias de padrões de kernel e validação baseada em evidências:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Engenharia reversa assistida por AI

[Levantamento parcial, detecção de MBA de invariantes, decodificação vinculada ao ambiente e validação de extratores automatizados](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web black-box com AI

Agents baseados em LLM podem automatizar fluxos de trabalho prolongados de pentesting web black-box quando contam com observabilidade, orquestração, gerenciamento de sessões autenticadas e validação adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Top 10 de segurança de Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introdução](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
