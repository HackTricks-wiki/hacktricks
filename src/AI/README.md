# IA en ciberseguridad

{{#include ../banners/hacktricks-training.md}}

## Principales algoritmos de machine learning

La mejor forma de empezar a aprender sobre IA es entender cómo funcionan los principales algoritmos de machine learning. Esto te ayudará a entender cómo funciona la IA, cómo usarla y cómo atacarla:


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

En la siguiente página encontrarás los conceptos básicos de cada componente para construir un LLM básico con transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Herramientas y plataformas para modelos

Para ejecutar, ajustar, servir o probar modelos, consulta la [guía de herramientas y plataformas para modelos de IA](AI-Model-Tools-and-Platforms.md).

## Seguridad de la IA

### Límites de confianza de los LLM Gateway

Para la seguridad de los gateway, consulta:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodología de seguridad de agentes de IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Marcos de riesgo de IA

Dos marcos útiles para empezar a evaluar los riesgos de los sistemas de IA son OWASP Machine Learning Security Top 10 y Secure AI Framework (SAIF) de Google. Son complementarios, no una lista exhaustiva de marcos de riesgo de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataques adversarios guiados por interpretabilidad mecanicista

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Seguridad de prompts de IA

El uso de la IA ha aumentado enormemente en los últimos años gracias a los LLM, pero no son perfectos y pueden ser engañados con prompts adversarios. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE en modelos de IA

Es muy común que los desarrolladores y las empresas ejecuten modelos descargados de Internet; sin embargo, cargar un modelo podría bastar para ejecutar código arbitrario en el sistema. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Evasión de KYC asistida por IA

El vídeo generativo puede combinarse con la inyección de cámaras virtuales y la manipulación de APIs de cámara para evadir procesos débiles de KYC, verificación de edad y comprobación de actividad biométrica:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol para IA

MCP (Model Context Protocol) es un protocolo abierto para conectar aplicaciones de IA con herramientas y fuentes de datos. Como los servidores MCP pueden exponer datos y acciones, las evaluaciones deben incluir autorización, consentimiento, validación de entradas de herramientas y revisión de límites de confianza.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocolo de agente a agente (A2A) de IA

A2A permite que los agentes se descubran entre sí mediante una tarjeta de agente y se envíen tareas por HTTP. Prueba las tarjetas de agente, la autorización de tareas, los webhooks de notificaciones push y las tarjetas ampliadas:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Servicios de IA autoalojados expuestos

Identifica y prueba ejecutores de modelos, creadores de agentes, interfaces de demostración de ML, clústeres de computación y bases de datos vectoriales expuestos que funcionan sin autenticación:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing y detección automatizada de vulnerabilidades asistidos por IA


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Revisión de código fuente y validación de vulnerabilidades asistidas por IA

Para revisar fuentes y sinks, flujos de tareas de puntos de entrada móviles, auditar patrones del kernel y realizar validaciones condicionadas por evidencias:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Ingeniería inversa asistida por IA

[Elevación parcial, detección de MBA invariantes, decodificación ligada al entorno y validación automatizada de extractores](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web black-box con IA

Los agentes basados en LLM pueden automatizar flujos de trabajo prolongados de pentesting web black-box cuando cuentan con observabilidad, orquestación, gestión de sesiones autenticadas y validación adversaria:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Marco de IA segura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introducción](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
