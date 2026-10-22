# IA en ciberseguridad

{{#include ../banners/hacktricks-training.md}}

## Principales algoritmos de aprendizaje automático

La mejor manera de empezar a aprender sobre IA es entender cómo funcionan los principales algoritmos de aprendizaje automático. Esto te ayudará a comprender cómo funciona la IA, cómo usarla y cómo atacarla:


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

En la siguiente página encontrarás los conceptos básicos de cada componente necesario para crear un LLM básico con transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Herramientas y plataformas para modelos

Para ejecutar, ajustar, servir o probar modelos, consulta la [guía de herramientas y plataformas para modelos de IA](AI-Model-Tools-and-Platforms.md).

## Seguridad de IA

### Límites de confianza de LLM Gateway

Para la seguridad de gateways, consulta:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodología de seguridad para agentes de IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Marcos de riesgo de IA

Dos marcos útiles para empezar a evaluar el riesgo de los sistemas de IA son OWASP Machine Learning Security Top 10 y Secure AI Framework (SAIF) de Google. Son complementarios y no constituyen una lista exhaustiva de marcos de riesgo de IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataques adversariales guiados por interpretabilidad mecanicista

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Seguridad de prompts de IA

Los LLM han hecho que el uso de la IA se dispare en los últimos años, pero no son perfectos y pueden ser engañados mediante prompts adversariales. Este tema es muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE en modelos de IA

Es muy común que desarrolladores y empresas ejecuten modelos descargados de Internet; sin embargo, cargar un modelo podría bastar para ejecutar código arbitrario en el sistema. Este tema es muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Evasión de KYC asistida por IA

El video generativo puede combinarse con la inyección de una cámara virtual y la manipulación de la API de la cámara para evadir flujos de trabajo vulnerables de KYC, verificación de edad y detección biométrica de presencia real:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de IA

MCP (Model Context Protocol) es un protocolo abierto que conecta aplicaciones de IA con herramientas y fuentes de datos. Como los servidores MCP pueden exponer datos y acciones, las evaluaciones deben incluir la autorización, el consentimiento, la validación de entradas de herramientas y la revisión de los límites de confianza.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing asistido por IA y descubrimiento automatizado de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Revisión de código fuente y validación de vulnerabilidades asistidas por IA

Para revisar fuentes y sumideros, flujos de tareas de puntos de entrada móviles, auditorías de patrones del kernel y validaciones basadas en evidencias:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Ingeniería inversa asistida por IA

[Elevación parcial, detección de MBA invariantes, decodificación ligada al entorno y validación de extractores automatizados](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web de caja negra con IA

Los agentes basados en LLM pueden automatizar flujos de trabajo de pentesting web de caja negra de larga duración cuando cuentan con observabilidad, orquestación, gestión de sesiones autenticadas y validación adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 de seguridad del aprendizaje automático](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Marco de IA segura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introducción](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
