# IA en ciberseguridad

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

### Preparación y evaluación de datos del modelo

Para consultar las divisiones de conjuntos de datos, las métricas clásicas y los ataques del lado de la respuesta contra la evaluación basada en LLM, consulta [preparación y evaluación de datos del modelo](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Arquitectura de LLM

En la siguiente página encontrarás los conceptos básicos de cada componente para crear un LLM básico con transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Herramientas y plataformas de modelos de IA

Para ejecutar, ajustar, servir o probar modelos, consulta la [guía de herramientas y plataformas de modelos de IA](AI-Model-Tools-and-Platforms.md).

## Seguridad de IA

### Límites de confianza de LLM Gateway

Para consultar la seguridad de Gateway, visita:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodología de seguridad de agentes de IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Marcos de riesgo de IA

Dos marcos útiles para comenzar a evaluar los riesgos de los sistemas de IA son OWASP Machine Learning Security Top 10 y Secure AI Framework (SAIF) de Google. Son complementarios y no constituyen una lista exhaustiva de marcos de riesgo de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataques adversariales guiados por interpretabilidad mecanicista

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Límites de confianza del navegador integrado

Para consultar los puentes del navegador de asistentes de escritorio, la suplantación de direcciones de pestañas y la lectura de archivos locales desde el contexto de workers, visita [límites de confianza del navegador integrado en asistentes de IA](AI-Embedded-Browser-Trust-Boundaries.md).

### Seguridad de prompts de IA

Los LLM han hecho que el uso de la IA se dispare en los últimos años, pero no son perfectos y pueden ser engañados con prompts adversariales. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE en modelos de IA

Es muy común que los desarrolladores y las empresas ejecuten modelos descargados de Internet; sin embargo, con solo cargar un modelo podría bastar para ejecutar código arbitrario en el sistema. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass de KYC asistido por IA

El video generativo puede combinarse con la inyección de cámaras virtuales y la manipulación de API de cámaras para eludir flujos KYC, de verificación de edad y de detección biométrica de actividad que sean débiles:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Protocolo Model Context de IA

MCP (Model Context Protocol) es un protocolo abierto para conectar aplicaciones de IA con herramientas y fuentes de datos. Como los servidores MCP pueden exponer datos y acciones, las evaluaciones deben incluir la autorización, el consentimiento, la validación de entradas de herramientas y la revisión de los límites de confianza.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocolo de agente a agente (A2A) de IA

A2A permite que los agentes se descubran entre sí mediante una tarjeta de agente y se envíen tareas por HTTP. Prueba las tarjetas de agente, la autorización de tareas, los webhooks de notificaciones push y las tarjetas extendidas:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Servicios de IA autoalojados expuestos

Identificación y prueba de ejecutores de modelos, constructores de agentes, interfaces de demostración de ML, clústeres de cómputo y bases de datos vectoriales expuestos que se ejecutan sin autenticación:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing asistido por IA y descubrimiento automatizado de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Revisión de código fuente y validación de vulnerabilidades asistidas por IA

Para revisar fuentes y sumideros, flujos de tareas de puntos de entrada móviles, auditorías de patrones del kernel y validaciones sujetas a requisitos de evidencia:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Ingeniería inversa asistida por IA

[Elevación parcial, detección de MBA invariantes, decodificación vinculada al entorno y validación de extractores automatizados](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web de caja negra con IA

Los agentes impulsados por LLM pueden automatizar flujos de trabajo prolongados de pentesting web de caja negra cuando cuentan con observabilidad, orquestación, gestión de sesiones autenticadas y validación adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Marco de IA segura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introducción](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
