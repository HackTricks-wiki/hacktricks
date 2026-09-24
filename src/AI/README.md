# IA en Ciberseguridad

{{#include ../banners/hacktricks-training.md}}

## Principales algoritmos de Machine Learning

El mejor punto de partida para aprender sobre IA es comprender cómo funcionan los principales algoritmos de Machine Learning. Esto te ayudará a entender cómo funciona la IA, cómo usarla y cómo atacarla:


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

### Arquitectura de LLMs

En la siguiente página encontrarás los conceptos básicos de cada componente para construir un LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Seguridad de la IA

### Frameworks de riesgos de IA

Dos frameworks iniciales útiles para evaluar el riesgo de los sistemas de IA son OWASP Machine Learning Security Top 10 y Secure AI Framework (SAIF) de Google. Son complementarios, no una lista exhaustiva de frameworks de riesgos de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Seguridad de los prompts de IA

Los LLMs han hecho que el uso de la IA se dispare en los últimos años, pero no son perfectos y pueden ser engañados mediante prompts adversarios. Este es un tema muy importante para comprender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE en modelos de IA

Es muy común que los developers y las empresas ejecuten modelos descargados de Internet; sin embargo, simplemente cargar un modelo podría ser suficiente para ejecutar código arbitrario en el sistema. Este es un tema muy importante para comprender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass de KYC asistido por IA

El vídeo generativo puede combinarse con la inyección de cámaras virtuales y la manipulación de APIs de cámara para realizar un bypass de KYC débil, de la verificación de edad y de los flujos de trabajo de liveness biométrico:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de IA

MCP (Model Context Protocol) es un protocolo abierto para conectar aplicaciones de IA con herramientas y fuentes de datos. Dado que los servidores MCP pueden exponer datos y acciones, las evaluaciones deben incluir autorización, consentimiento, validación de entradas de herramientas y revisión de los límites de confianza.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing y descubrimiento automatizado de vulnerabilidades asistidos por IA


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Ingeniería inversa asistida por IA

[Partial lifting, invariant MBA detection, environment-bound decoding, and automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots pentesters de Web Black-Box con IA

Los agentes basados en LLM pueden automatizar workflows prolongados de pentesting Web Black-Box cuando cuentan con observabilidad, orquestación, gestión de sesiones autenticadas y validación adversaria:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
