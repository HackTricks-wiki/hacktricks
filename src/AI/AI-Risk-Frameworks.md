# Riesgos de IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ha identificado las top 10 vulnerabilidades de machine learning que pueden afectar a los sistemas de AI. Estas vulnerabilidades pueden generar diversos problemas de seguridad, incluyendo data poisoning, model inversion y adversarial attacks. Entenderlas es crucial para construir sistemas de AI seguros.

Para una lista actualizada y detallada, consulte el proyecto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un atacante añade cambios mínimos, a menudo invisibles, a los **datos entrantes** para que el modelo tome la decisión equivocada.\
*Ejemplo*: Unos pocos puntos de pintura en un stop‑sign hacen que un self‑driving car "vea" una señal de límite de velocidad.

- **Data Poisoning Attack**: El **conjunto de entrenamiento** se contamina deliberadamente con muestras maliciosas, enseñando al modelo reglas dañinas.\
*Ejemplo*: Binaries de malware etiquetados erróneamente como "benign" en un corpus de entrenamiento de un antivirus, permitiendo que malware similar pase desapercibido después.

- **Model Inversion Attack**: Mediante sondeos de salidas, un atacante construye un **modelo inverso** que reconstruye características sensibles de las entradas originales.\
*Ejemplo*: Recrear la imagen MRI de un paciente a partir de las predicciones de un modelo de detección de cáncer.

- **Membership Inference Attack**: El adversario prueba si un **registro específico** fue usado durante el entrenamiento detectando diferencias en la confianza.\
*Ejemplo*: Confirmar que la transacción bancaria de una persona aparece en los datos de entrenamiento de un modelo de detección de fraude.

- **Model Theft**: Consultas repetidas permiten a un atacante aprender los límites de decisión y **clonar el comportamiento del modelo** (y la IP).\
*Ejemplo*: Extraer suficientes pares Q&A de un ML‑as‑a‑Service API para construir un modelo local casi equivalente.

- **AI Supply‑Chain Attack**: Comprometer cualquier componente (datos, libraries, pre‑trained weights, CI/CD) en la **pipeline de ML** para corromper modelos downstream.\
*Ejemplo*: Una dependencia envenenada en un model‑hub instala un modelo de sentiment‑analysis con backdoor en muchas apps.

- **Transfer Learning Attack**: Lógica maliciosa se planta en un **pre‑trained model** y sobrevive al fine‑tuning en la tarea de la víctima.\
*Ejemplo*: Un vision backbone con un trigger oculto sigue invirtiendo etiquetas después de ser adaptado para imágenes médicas.

- **Model Skewing**: Datos sutilmente sesgados o mal etiquetados **desvían las salidas del modelo** para favorecer la agenda del atacante.\
*Ejemplo*: Inyectar correos spam "limpios" etiquetados como ham para que un filtro de spam permita correos similares en el futuro.

- **Output Integrity Attack**: El atacante **altera las predicciones del modelo en tránsito**, no el modelo en sí, engañando a sistemas downstream.\
*Ejemplo*: Cambiar el veredicto "malicious" de un malware classifier a "benign" antes de que la etapa de cuarentena de archivos lo vea.

- **Model Poisoning** --- Cambios directos y dirigidos a los **parámetros del modelo** mismos, a menudo tras obtener acceso de escritura, para alterar el comportamiento.\
*Ejemplo*: Ajustar pesos en un modelo de detección de fraude en producción para que las transacciones de ciertas tarjetas siempre sean aprobadas.


## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) describe varios riesgos asociados con los sistemas de AI:

- **Data Poisoning**: Actores maliciosos alteran o inyectan datos de entrenamiento/tuning para degradar la precisión, implantar backdoors o sesgar resultados, minando la integridad del modelo a lo largo del ciclo de vida de los datos.

- **Unauthorized Training Data**: Ingerir datasets con copyright, sensibles o no autorizados crea responsabilidades legales, éticas y de rendimiento porque el modelo aprende de datos que nunca debió usar.

- **Model Source Tampering**: Manipulación en la supply‑chain o por insiders del código del modelo, dependencias o weights antes o durante el entrenamiento puede incrustar lógica oculta que persiste incluso tras el retraining.

- **Excessive Data Handling**: Controles débiles de retención y gobernanza de datos llevan a que los sistemas almacenen o procesen más datos personales de los necesarios, aumentando la exposición y el riesgo de cumplimiento.

- **Model Exfiltration**: Los atacantes roban archivos/weights del modelo, causando pérdida de propiedad intelectual y posibilitando servicios clonados o ataques posteriores.

- **Model Deployment Tampering**: Adversarios modifican artefactos del modelo o la infraestructura de serving para que el modelo en ejecución difiera de la versión verificada, cambiando potencialmente su comportamiento.

- **Denial of ML Service**: Saturar APIs o enviar entradas “sponge” puede agotar compute/energía y dejar al modelo offline, replicando ataques DoS clásicos.

- **Model Reverse Engineering**: Al cosechar un gran número de pares input‑output, los atacantes pueden clonar o destilar el modelo, alimentando productos de imitación y ataques adversariales personalizados.

- **Insecure Integrated Component**: Plugins, agents o servicios upstream vulnerables permiten a atacantes inyectar código o escalar privilegios dentro de la pipeline de AI.

- **Prompt Injection**: Diseñar prompts (directa o indirectamente) para introducir instrucciones que sobreescriben la intención del sistema, forzando al modelo a ejecutar comandos no deseados.

- **Model Evasion**: Entradas cuidadosamente diseñadas provocan que el modelo mis‑clasifique, hallucinate o genere contenido no permitido, erosionando seguridad y confianza.

- **Sensitive Data Disclosure**: El modelo revela información privada o confidencial de sus datos de entrenamiento o del contexto del usuario, violando privacidad y regulaciones.

- **Inferred Sensitive Data**: El modelo deduce atributos personales que nunca fueron proporcionados, creando nuevos daños de privacidad por inferencia.

- **Insecure Model Output**: Respuestas no saneadas transmiten código dañino, misinformation o contenido inapropiado a usuarios o sistemas downstream.

- **Rogue Actions**: Agentes integrados autónomamente ejecutan operaciones del mundo real no deseadas (escritura de archivos, llamadas a APIs, compras, etc.) sin la supervisión adecuada del usuario.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) proporciona un marco completo para entender y mitigar riesgos asociados con sistemas de AI. Categoriza varias técnicas y tácticas de ataque que los adversarios pueden usar contra modelos de AI y también cómo usar sistemas de AI para realizar distintos ataques.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers steal active session tokens or cloud API credentials and invoke paid, cloud-hosted LLMs without authorization. Access is often resold via reverse proxies that front the victim’s account, e.g. "oai-reverse-proxy" deployments. Consequences include financial loss, model misuse outside policy, and attribution to the victim tenant.

TTPs:
- Harvest tokens from infected developer machines or browsers; steal CI/CD secrets; buy leaked cookies.
- Stand up a reverse proxy that forwards requests to the genuine provider, hiding the upstream key and multiplexing many customers.
- Abuse direct base-model endpoints to bypass enterprise guardrails and rate limits.

Mitigations:
- Bind tokens to device fingerprint, IP ranges, and client attestation; enforce short expirations and refresh with MFA.
- Scope keys minimally (no tool access, read‑only where applicable); rotate on anomaly.
- Terminate all traffic server-side behind a policy gateway that enforces safety filters, per-route quotas, and tenant isolation.
- Monitor for unusual usage patterns (sudden spend spikes, atypical regions, UA strings) and auto-revoke suspicious sessions.
- Prefer mTLS or signed JWTs issued by your IdP over long-lived static API keys.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
