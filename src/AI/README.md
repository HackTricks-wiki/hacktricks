# IA en ciberseguridad

{{#include ../banners/hacktricks-training.md}}

## Principales algoritmos de Machine Learning

El mejor punto de partida para aprender sobre IA es entender cómo funcionan los principales algoritmos de Machine Learning. Esto te ayudará a comprender cómo funciona la IA, cómo usarla y cómo atacarla:


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

### Preparación y evaluación de datos de modelos

Para conocer las divisiones de datasets, las métricas clásicas y los ataques del lado de las respuestas contra la evaluación basada en LLM, consulta [preparación y evaluación de datos de modelos](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Arquitectura de los LLM

En la siguiente página encontrarás los conceptos básicos de cada componente necesario para crear un LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Herramientas y plataformas de modelos

Para ejecutar, ajustar, servir o probar modelos, consulta la [guía de herramientas y plataformas de modelos de IA](AI-Model-Tools-and-Platforms.md).

## Seguridad de la IA

### Límites de confianza de los gateways de LLM

Para conocer la seguridad de los gateways, consulta:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodología de seguridad de agentes de IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Frameworks de riesgo de IA

Dos frameworks útiles para empezar a evaluar los riesgos de los sistemas de IA son OWASP Machine Learning Security Top 10 y Secure AI Framework (SAIF) de Google. Son complementarios, no una lista exhaustiva de frameworks de riesgo de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataques adversariales guiados por interpretabilidad mecanicista

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Seguridad de prompts de IA

Los LLM han hecho que el uso de la IA se dispare en los últimos años, pero no son perfectos y pueden ser engañados con prompts adversariales. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE en modelos de IA

Es muy común que desarrolladores y empresas ejecuten modelos descargados de Internet; sin embargo, cargar un modelo podría bastar para ejecutar código arbitrario en el sistema. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Evasión de KYC asistida por IA

El video generativo puede combinarse con la inyección de cámaras virtuales y la manipulación de la API de cámara para evadir flujos débiles de KYC, verificación de edad y comprobación de vida biométrica:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Protocolo de contexto de modelos de IA

MCP (Model Context Protocol) es un protocolo abierto para conectar aplicaciones de IA con herramientas y fuentes de datos. Como los servidores MCP pueden exponer datos y acciones, las evaluaciones deben incluir autorización, consentimiento, validación de entradas de herramientas y revisión de límites de confianza.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocolo de agente a agente (A2A) de IA

A2A permite que los agentes se descubran entre sí mediante una tarjeta de agente y se envíen tareas por HTTP. Prueba las tarjetas de agente, la autorización de tareas, los webhooks de notificaciones push y las tarjetas extendidas:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Servicios de IA autoalojados expuestos

Identificación de huellas y pruebas de ejecutores de modelos, creadores de agentes, interfaces de demostración de ML, clústeres de cómputo y bases de datos vectoriales expuestos que se ejecutan sin autenticación:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing asistido por IA y descubrimiento automatizado de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Revisión de código fuente y validación de vulnerabilidades asistidas por IA

Para revisar fuentes y sinks, flujos de tareas de puntos de entrada móviles, auditorías de patrones del kernel y validación basada en evidencias:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Ingeniería inversa asistida por IA

[Elevación parcial, detección de MBA de invariantes, decodificación ligada al entorno y validación de extractores automatizados](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web de caja negra con IA

Los agentes basados en LLM pueden automatizar flujos de pentesting web de caja negra de larga duración cuando cuentan con observabilidad, orquestación, gestión de sesiones autenticadas y validación adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introducción](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
