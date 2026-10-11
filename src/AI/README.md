# AI em Cibersegurança

{{#include ../banners/hacktricks-training.md}}

## Principais algoritmos de Machine Learning

O melhor ponto de partida para aprender sobre AI é entender como funcionam os principais algoritmos de machine learning. Isso ajudará você a entender como a AI funciona, como usá-la e como atacá-la:


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

## Segurança de AI

### Metodologia de Segurança de Agentes de AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Frameworks de Risco de AI

Dois frameworks úteis para começar a avaliar os riscos de sistemas de AI são o OWASP Machine Learning Security Top 10 e o Secure AI Framework (SAIF) do Google. Eles são complementares, não uma lista exaustiva de frameworks de risco de AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Segurança de prompts de AI

Os LLMs fizeram o uso de AI explodir nos últimos anos, mas não são perfeitos e podem ser enganados por prompts adversariais. Este é um tópico muito importante para entender como usar AI com segurança e como atacá-la:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE em modelos de AI

É muito comum que desenvolvedores e empresas executem modelos baixados da Internet. No entanto, apenas carregar um modelo pode ser suficiente para executar código arbitrário no sistema. Este é um tópico muito importante para entender como usar AI com segurança e como atacá-la:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass de KYC com auxílio de AI

Vídeos generativos podem ser combinados com injeção de câmera virtual e manipulação da API da câmera para contornar fluxos fracos de KYC, verificação de idade e prova de vida biométrica:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de AI

MCP (Model Context Protocol) é um protocolo aberto para conectar aplicações de AI a ferramentas e fontes de dados. Como os servidores MCP podem expor dados e ações, as avaliações devem incluir autorização, consentimento, validação das entradas das ferramentas e análise dos limites de confiança.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing e descoberta automatizada de vulnerabilidades com auxílio de AI


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Engenharia reversa com auxílio de AI

[Elevação parcial, detecção de invariantes MBA, decodificação vinculada ao ambiente e validação de extratores automatizados](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots pentesters de Web black-box

Agentes com tecnologia de LLM podem automatizar fluxos de pentesting web black-box de longa duração quando contam com observabilidade, orquestração, gerenciamento de sessões autenticadas e validação adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 de Segurança de Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework de AI Seguro (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introdução](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
