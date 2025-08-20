# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ha identificado las 10 principales vulnerabilidades de aprendizaje automático que pueden afectar a los sistemas de IA. Estas vulnerabilidades pueden llevar a varios problemas de seguridad, incluyendo envenenamiento de datos, inversión de modelos y ataques adversariales. Comprender estas vulnerabilidades es crucial para construir sistemas de IA seguros.

Para una lista actualizada y detallada de las 10 principales vulnerabilidades de aprendizaje automático, consulte el proyecto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un atacante agrega pequeños cambios, a menudo invisibles, a los **datos entrantes** para que el modelo tome la decisión incorrecta.\
*Ejemplo*: Unas pocas manchas de pintura en una señal de alto engañan a un coche autónomo haciéndolo "ver" una señal de límite de velocidad.

- **Data Poisoning Attack**: El **conjunto de entrenamiento** se contamina deliberadamente con muestras malas, enseñando al modelo reglas dañinas.\
*Ejemplo*: Los binarios de malware se etiquetan incorrectamente como "benignos" en un corpus de entrenamiento de antivirus, permitiendo que malware similar pase desapercibido más tarde.

- **Model Inversion Attack**: Al sondear salidas, un atacante construye un **modelo inverso** que reconstruye características sensibles de las entradas originales.\
*Ejemplo*: Recrear la imagen de MRI de un paciente a partir de las predicciones de un modelo de detección de cáncer.

- **Membership Inference Attack**: El adversario prueba si un **registro específico** fue utilizado durante el entrenamiento al detectar diferencias de confianza.\
*Ejemplo*: Confirmar que la transacción bancaria de una persona aparece en los datos de entrenamiento de un modelo de detección de fraude.

- **Model Theft**: Consultas repetidas permiten a un atacante aprender los límites de decisión y **clonar el comportamiento del modelo** (y la propiedad intelectual).\
*Ejemplo*: Recopilar suficientes pares de preguntas y respuestas de una API de ML‑as‑a‑Service para construir un modelo local casi equivalente.

- **AI Supply‑Chain Attack**: Comprometer cualquier componente (datos, bibliotecas, pesos preentrenados, CI/CD) en la **tubería de ML** para corromper modelos posteriores.\
*Ejemplo*: Una dependencia envenenada en un modelo‑hub instala un modelo de análisis de sentimientos con puerta trasera en muchas aplicaciones.

- **Transfer Learning Attack**: Lógica maliciosa se planta en un **modelo preentrenado** y sobrevive al ajuste fino en la tarea de la víctima.\
*Ejemplo*: Un backbone de visión con un disparador oculto aún cambia etiquetas después de ser adaptado para imágenes médicas.

- **Model Skewing**: Datos sutilmente sesgados o etiquetados incorrectamente **desplazan las salidas del modelo** para favorecer la agenda del atacante.\
*Ejemplo*: Inyectar correos electrónicos de spam "limpios" etiquetados como ham para que un filtro de spam permita pasar correos similares en el futuro.

- **Output Integrity Attack**: El atacante **altera las predicciones del modelo en tránsito**, no el modelo en sí, engañando a los sistemas posteriores.\
*Ejemplo*: Cambiar el veredicto "malicioso" de un clasificador de malware a "benigno" antes de que la etapa de cuarentena del archivo lo vea.

- **Model Poisoning** --- Cambios directos y específicos en los **parámetros del modelo** mismos, a menudo después de obtener acceso de escritura, para alterar el comportamiento.\
*Ejemplo*: Ajustar pesos en un modelo de detección de fraude en producción para que las transacciones de ciertas tarjetas sean siempre aprobadas.

## Google SAIF Risks

Los [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google describen varios riesgos asociados con los sistemas de IA:

- **Data Poisoning**: Actores maliciosos alteran o inyectan datos de entrenamiento/ajuste para degradar la precisión, implantar puertas traseras o sesgar resultados, socavando la integridad del modelo a lo largo de todo el ciclo de vida de los datos.

- **Unauthorized Training Data**: Ingerir conjuntos de datos con derechos de autor, sensibles o no permitidos crea responsabilidades legales, éticas y de rendimiento porque el modelo aprende de datos que nunca se le permitió usar.

- **Model Source Tampering**: La manipulación de la cadena de suministro o de insiders del código del modelo, dependencias o pesos antes o durante el entrenamiento puede incrustar lógica oculta que persiste incluso después del reentrenamiento.

- **Excessive Data Handling**: Controles débiles de retención y gobernanza de datos llevan a los sistemas a almacenar o procesar más datos personales de los necesarios, aumentando la exposición y el riesgo de cumplimiento.

- **Model Exfiltration**: Los atacantes roban archivos/pesos del modelo, causando pérdida de propiedad intelectual y habilitando servicios imitadores o ataques posteriores.

- **Model Deployment Tampering**: Los adversarios modifican artefactos del modelo o infraestructura de servicio para que el modelo en ejecución difiera de la versión verificada, potencialmente cambiando el comportamiento.

- **Denial of ML Service**: Inundar APIs o enviar entradas "esponja" puede agotar recursos computacionales/energía y dejar el modelo fuera de línea, reflejando ataques clásicos de DoS.

- **Model Reverse Engineering**: Al cosechar grandes cantidades de pares de entrada-salida, los atacantes pueden clonar o destilar el modelo, alimentando productos de imitación y ataques adversariales personalizados.

- **Insecure Integrated Component**: Plugins, agentes o servicios ascendentes vulnerables permiten a los atacantes inyectar código o escalar privilegios dentro de la tubería de IA.

- **Prompt Injection**: Elaborar prompts (directa o indirectamente) para contrabandear instrucciones que anulan la intención del sistema, haciendo que el modelo ejecute comandos no deseados.

- **Model Evasion**: Entradas cuidadosamente diseñadas provocan que el modelo clasifique incorrectamente, alucine o produzca contenido no permitido, erosionando la seguridad y la confianza.

- **Sensitive Data Disclosure**: El modelo revela información privada o confidencial de sus datos de entrenamiento o contexto del usuario, violando la privacidad y regulaciones.

- **Inferred Sensitive Data**: El modelo deduce atributos personales que nunca se proporcionaron, creando nuevos daños a la privacidad a través de inferencias.

- **Insecure Model Output**: Respuestas no sanitizadas transmiten código dañino, desinformación o contenido inapropiado a los usuarios o sistemas posteriores.

- **Rogue Actions**: Agentes integrados de forma autónoma ejecutan operaciones del mundo real no intencionadas (escrituras de archivos, llamadas a API, compras, etc.) sin la supervisión adecuada del usuario.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) proporciona un marco integral para comprender y mitigar los riesgos asociados con los sistemas de IA. Categoriza varias técnicas y tácticas de ataque que los adversarios pueden usar contra modelos de IA y también cómo usar sistemas de IA para realizar diferentes ataques.

{{#include ../banners/hacktricks-training.md}}
