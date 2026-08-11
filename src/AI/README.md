# AI en Ciberseguridad

{{#include ../banners/hacktricks-training.md}}

## Principales algoritmos de Machine Learning

El mejor punto de partida para aprender sobre AI es comprender cómo funcionan los principales algoritmos de Machine Learning. Esto te ayudará a entender cómo funciona la AI, cómo usarla y cómo atacarla:


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

En la siguiente página encontrarás los conceptos básicos de cada componente necesario para construir un LLM básico usando transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Seguridad de AI

### Frameworks de riesgos de AI

Dos frameworks útiles para empezar a evaluar los riesgos de los sistemas de AI son OWASP Machine Learning Security Top 10 y Google's Secure AI Framework (SAIF). Son complementarios, no una lista exhaustiva de frameworks de riesgos de AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Seguridad de los prompts de AI

Los LLMs han hecho que el uso de AI se dispare en los últimos años, pero no son perfectos y pueden ser engañados mediante prompts adversariales. Este es un tema muy importante para entender cómo usar AI de forma segura y cómo atacarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE en modelos de AI

Es muy común que los desarrolladores y las empresas ejecuten modelos descargados de Internet; sin embargo, simplemente cargar un modelo podría ser suficiente para ejecutar código arbitrario en el sistema. Este es un tema muy importante para entender cómo usar AI de forma segura y cómo atacarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass de KYC asistido por AI

El vídeo generativo puede combinarse con la inyección de cámaras virtuales y la manipulación de APIs de cámara para evadir flujos débiles de KYC, verificación de edad y validación biométrica de presencia real:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de AI

MCP (Model Context Protocol) es un protocolo abierto para conectar aplicaciones de AI con herramientas y fuentes de datos. Debido a que los servidores MCP pueden exponer datos y acciones, las evaluaciones deben incluir autorización, consentimiento, validación de entradas de herramientas y revisión de los límites de confianza.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing asistido por AI y descubrimiento automatizado de vulnerabilidades


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Bots de Pentesting web black-box con AI

Los agentes basados en LLM pueden automatizar flujos prolongados de pentesting web black-box cuando cuentan con observabilidad, orquestación, gestión de sesiones autenticadas y validación adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introducción](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
