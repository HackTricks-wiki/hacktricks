# IA en ciberseguridad

{{#include ../banners/hacktricks-training.md}}

## Principales algoritmos de machine learning

El mejor punto de partida para aprender sobre IA es entender cómo funcionan los principales algoritmos de machine learning. Esto te ayudará a comprender cómo funciona la IA, cómo usarla y cómo atacarla:


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

### Arquitectura de los LLMs

En la siguiente página encontrarás los conceptos básicos de cada componente necesario para crear un LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Seguridad de la IA

### Metodología de seguridad de agentes de IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Marcos de riesgo de IA

Dos marcos útiles para empezar a evaluar los riesgos de los sistemas de IA son OWASP Machine Learning Security Top 10 y Secure AI Framework (SAIF) de Google. Son complementarios y no constituyen una lista exhaustiva de marcos de riesgo de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataques adversariales guiados por interpretabilidad mecanicista

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Seguridad de los prompts de IA

El uso de la IA se ha disparado en los últimos años gracias a los LLMs, pero no son perfectos y pueden ser engañados mediante prompts adversariales. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE en modelos de IA

Es muy común que desarrolladores y empresas ejecuten modelos descargados de Internet; sin embargo, con solo cargar un modelo podría bastar para ejecutar código arbitrario en el sistema. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Evasión de KYC asistida por IA

El video generativo puede combinarse con la inyección de cámaras virtuales y la manipulación de la API de la cámara para evadir flujos de trabajo débiles de KYC, verificación de edad y comprobación biométrica de presencia:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de IA

MCP (Model Context Protocol) es un protocolo abierto para conectar aplicaciones de IA con herramientas y fuentes de datos. Como los servidores MCP pueden exponer datos y acciones, las evaluaciones deben incluir la autorización, el consentimiento, la validación de las entradas de las herramientas y la revisión de los límites de confianza.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing asistido por IA y descubrimiento automatizado de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Ingeniería inversa asistida por IA

[Elevación parcial, detección de invariantes MBA, decodificación vinculada al entorno y validación automatizada de extractores](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web black-box con IA

Los agentes basados en LLMs pueden automatizar flujos de trabajo prolongados de pentesting web black-box si cuentan con observabilidad, orquestación, gestión de sesiones autenticadas y validación adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 de seguridad de machine learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Marco de IA segura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introducción](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
