# AI en Ciberseguridad

{{#include ../banners/hacktricks-training.md}}

## Principales Algoritmos de Aprendizaje Automático

El mejor punto de partida para aprender sobre IA es entender cómo funcionan los principales algoritmos de aprendizaje automático. Esto te ayudará a entender cómo funciona la IA, cómo usarla y cómo atacarla:


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

En la siguiente página encontrarás los conceptos básicos de cada componente para construir un LLM básico utilizando transformadores:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Seguridad de IA

### Marcos de Riesgo de IA

En este momento, los 2 principales marcos para evaluar los riesgos de los sistemas de IA son el OWASP ML Top 10 y el Google SAIF:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Seguridad de Prompts de IA

Los LLMs han hecho que el uso de IA explote en los últimos años, pero no son perfectos y pueden ser engañados por prompts adversariales. Este es un tema muy importante para entender cómo usar la IA de manera segura y cómo atacarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE de Modelos de IA

Es muy común que desarrolladores y empresas ejecuten modelos descargados de Internet, sin embargo, solo cargar un modelo podría ser suficiente para ejecutar código arbitrario en el sistema. Este es un tema muy importante para entender cómo usar la IA de manera segura y cómo atacarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Protocolo de Contexto de Modelos de IA

MCP (Protocolo de Contexto de Modelos) es un protocolo que permite a los clientes de agentes de IA conectarse con herramientas externas y fuentes de datos de manera plug-and-play. Esto habilita flujos de trabajo complejos e interacciones entre modelos de IA y sistemas externos:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing Asistido por IA y Descubrimiento Automatizado de Vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
