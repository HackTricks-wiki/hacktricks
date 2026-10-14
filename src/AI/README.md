# IA en ciberseguridad

{{#include ../banners/hacktricks-training.md}}

## Principales algoritmos de Machine Learning

El mejor punto de partida para aprender sobre IA es entender cómo funcionan los principales algoritmos de Machine Learning. Esto te ayudará a entender cómo funciona la IA, cómo usarla y cómo atacarla:


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

### Arquitectura de los LLM

En la siguiente página encontrarás los conceptos básicos de cada componente necesario para crear un LLM básico con transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Herramientas y plataformas de modelos

Para ejecutar, ajustar, servir o probar modelos, consulta la [guía de herramientas y plataformas de modelos de IA](AI-Model-Tools-and-Platforms.md).

## Seguridad de la IA

### Metodología de seguridad para agentes de IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Marcos de riesgo de la IA

Dos marcos útiles para comenzar a evaluar los riesgos de los sistemas de IA son OWASP Machine Learning Security Top 10 y Secure AI Framework (SAIF) de Google. Son complementarios y no constituyen una lista exhaustiva de marcos de riesgo de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataques adversariales guiados por la interpretabilidad mecanicista

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Seguridad de prompts de IA

El uso de la IA se ha disparado en los últimos años gracias a los LLM, pero no son perfectos y pueden ser engañados mediante prompts adversariales. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE en modelos de IA

Es muy común que los desarrolladores y las empresas ejecuten modelos descargados de Internet. Sin embargo, cargar un modelo podría bastar para ejecutar código arbitrario en el sistema. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Evasión de KYC asistida por IA

El video generativo puede combinarse con la inyección de cámaras virtuales y la manipulación de las API de cámara para evadir flujos débiles de KYC, verificación de edad y comprobación biométrica de vida:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de IA

MCP (Model Context Protocol) es un protocolo abierto para conectar aplicaciones de IA con herramientas y fuentes de datos. Como los servidores MCP pueden exponer datos y acciones, las evaluaciones deben incluir la autorización, el consentimiento, la validación de las entradas de las herramientas y la revisión de los límites de confianza.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing asistido por IA y detección automatizada de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Ingeniería inversa asistida por IA

[Elevación parcial a código, detección de invariantes MBA, decodificación vinculada al entorno y validación de extractores automatizados](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web de caja negra con IA

Los agentes basados en LLM pueden automatizar flujos de trabajo prolongados de pentesting web de caja negra cuando cuentan con observabilidad, orquestación, gestión de sesiones autenticadas y validación adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP: Los 10 principales riesgos de seguridad de Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Marco de IA segura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introducción](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
