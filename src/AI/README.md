# IA en Ciberseguridad

{{#include ../banners/hacktricks-training.md}}

## Principales algoritmos de aprendizaje automático

El mejor punto de partida para aprender sobre IA es comprender cómo funcionan los principales algoritmos de aprendizaje automático. Esto te ayudará a entender cómo funciona la IA, cómo usarla y cómo atacarla:


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

En la siguiente página encontrarás los fundamentos de cada componente para crear un LLM básico con transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Seguridad de la IA

### Metodología de seguridad de agentes de IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Marcos de riesgo de IA

Dos marcos útiles para empezar a evaluar el riesgo de los sistemas de IA son OWASP Machine Learning Security Top 10 y Google's Secure AI Framework (SAIF). Son complementarios, no una lista exhaustiva de marcos de riesgo de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Seguridad de prompts de IA

El uso de la IA se ha disparado en los últimos años gracias a los LLMs, pero no son perfectos y los prompts adversariales pueden engañarlos. Este es un tema muy importante para comprender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE de modelos de IA

Es muy común que los desarrolladores y las empresas ejecuten modelos descargados de Internet; sin embargo, cargar un modelo podría bastar para ejecutar código arbitrario en el sistema. Este es un tema muy importante para comprender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass de KYC asistido por IA

El video generativo puede combinarse con la inyección de cámara virtual y la manipulación de la API de cámara para evadir flujos de trabajo débiles de KYC, verificación de edad y comprobación biométrica de actividad:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Protocolo de contexto de modelos de IA

MCP (Model Context Protocol) es un protocolo abierto para conectar aplicaciones de IA con herramientas y fuentes de datos. Como los servidores MCP pueden exponer datos y acciones, las evaluaciones deben incluir la autorización, el consentimiento, la validación de entradas de herramientas y la revisión de los límites de confianza.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing asistido por IA y descubrimiento automatizado de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Ingeniería inversa asistida por IA

[Elevación parcial, detección de invariantes MBA, decodificación vinculada al entorno y validación de extractores automatizados](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web black-box con IA

Los agentes basados en LLM pueden automatizar flujos de trabajo de pentesting web black-box de larga duración cuando cuentan con observabilidad, orquestación, gestión de sesiones autenticadas y validación adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 de seguridad de aprendizaje automático](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Marco de IA segura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introducción](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
