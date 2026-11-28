# IA en ciberseguridad

{{#include ../banners/hacktricks-training.md}}

## Principales algoritmos de machine learning

El mejor punto de partida para aprender sobre IA es comprender cómo funcionan los principales algoritmos de machine learning. Esto te ayudará a entender cómo funciona la IA, cómo usarla y cómo atacarla:


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

Para las divisiones de datasets, las métricas clásicas y los ataques del lado de las respuestas contra la evaluación basada en LLM, consulta [preparación y evaluación de datos de modelos](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Arquitectura de LLM

En la siguiente página encontrarás los fundamentos de cada componente para construir un LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Herramientas y plataformas de modelos

Para ejecutar, ajustar, servir o probar modelos, consulta la [guía de herramientas y plataformas de modelos de IA](AI-Model-Tools-and-Platforms.md).

## Seguridad de IA

### Límites de confianza del gateway de LLM

Para consultar la seguridad de los gateways, visita:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodología de seguridad de agentes de IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Marcos de riesgo de IA

Dos marcos útiles para empezar a evaluar el riesgo de los sistemas de IA son OWASP Machine Learning Security Top 10 y Google's Secure AI Framework (SAIF). Son complementarios, no una lista exhaustiva de marcos de riesgo de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataques adversariales guiados por la interpretabilidad mecanicista

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Límites de confianza del navegador integrado

Para consultar los puentes de navegador de asistentes de escritorio, la suplantación de direcciones de pestañas y la lectura de archivos locales desde el contexto de workers, visita [límites de confianza del navegador integrado en asistentes de IA](AI-Embedded-Browser-Trust-Boundaries.md).

### Seguridad de prompts de IA

Los LLM han hecho que el uso de la IA se dispare en los últimos años, pero no son perfectos y pueden ser engañados mediante prompts adversariales. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE en modelos de IA

Es muy común que desarrolladores y empresas ejecuten modelos descargados de Internet. Sin embargo, cargar un modelo podría bastar para ejecutar código arbitrario en el sistema. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Para consultar los riesgos de carga de modelos Keras `.keras`/HDF5, las capas Lambda y el análisis de gadgets después de una corrección, visita [deserialización de modelos Keras y búsqueda de gadgets](keras-model-deserialization-rce-and-gadget-hunting.md).

### Evasión de KYC asistida por IA

El video generativo se puede combinar con la inyección de cámaras virtuales y la manipulación de la API de la cámara para evadir procesos débiles de KYC, verificación de edad y prueba de vida biométrica:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Protocolo de contexto de modelos de IA

MCP (Model Context Protocol) es un protocolo abierto para conectar aplicaciones de IA con herramientas y fuentes de datos. Como los servidores MCP pueden exponer datos y acciones, las evaluaciones deben incluir autorización, consentimiento, validación de entradas de herramientas y revisión de límites de confianza.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocolo de agente a agente (A2A) de IA

A2A permite que los agentes se descubran entre sí mediante una tarjeta de agente y se envíen tareas a través de HTTP. Prueba las tarjetas de agente, la autorización de tareas, los webhooks de notificaciones push y las tarjetas ampliadas:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Servicios de IA autoalojados expuestos

Identificación y pruebas de ejecutores de modelos, creadores de agentes, interfaces de demostración de ML, clústeres de cómputo y bases de datos vectoriales expuestos que se ejecutan sin autenticación:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing asistido por IA y descubrimiento automatizado de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Revisión de código fuente y validación de vulnerabilidades asistidas por IA

Para consultar la revisión de fuentes y sumideros, los flujos de tareas de puntos de entrada móviles, las auditorías de patrones del kernel y la validación condicionada a evidencias:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Ingeniería inversa asistida por IA

[Elevación parcial, detección de MBA invariantes, decodificación vinculada al entorno y validación de extractores automatizados](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots pentester de IA web black-box

Los agentes basados en LLM pueden automatizar flujos de trabajo prolongados de pentesting web black-box cuando cuentan con observabilidad, orquestación, gestión de sesiones autenticadas y validación adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Marco de IA segura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introducción](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
