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

En la siguiente página encontrarás los conceptos básicos de cada componente para crear un LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Seguridad de la IA

### Frameworks de riesgos de IA

En este momento, los 2 principales frameworks para evaluar los riesgos de los sistemas de IA son OWASP ML Top 10 y Google SAIF:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Seguridad de los prompts de IA

Los LLMs han hecho que el uso de la IA se dispare en los últimos años, pero no son perfectos y pueden ser engañados mediante prompts adversariales. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE en modelos de IA

Es muy habitual que los desarrolladores y las empresas ejecuten modelos descargados de Internet; sin embargo, simplemente cargar un modelo podría ser suficiente para ejecutar código arbitrario en el sistema. Este es un tema muy importante para entender cómo usar la IA de forma segura y cómo atacarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Model Context Protocol de IA

MCP (Model Context Protocol) es un protocolo que permite a los clientes de agentes de IA conectarse con herramientas y fuentes de datos externas de forma plug-and-play. Esto permite flujos de trabajo complejos e interacciones entre modelos de IA y sistemas externos:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing asistido por IA y descubrimiento automatizado de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Bots pentester de IA Web Black-Box

Los agentes potenciados por LLM pueden automatizar flujos de trabajo prolongados de pentesting web black-box cuando cuentan con observabilidad, orquestación, gestión de sesiones autenticadas y validación adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
