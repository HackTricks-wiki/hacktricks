# Riesgos de IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP ha identificado las principales 10 vulnerabilidades de machine learning que pueden afectar a los sistemas de IA. Estas vulnerabilidades pueden llevar a distintos problemas de seguridad, incluyendo data poisoning, model inversion y adversarial attacks. Comprenderlas es crucial para construir sistemas de IA seguros.

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: Un atacante añade cambios diminutos, a menudo invisibles, a **datos entrantes** para que el modelo tome la decisión equivocada.\
*Example*: Unos pocos puntos de pintura en una señal de stop engañan a un coche self‑driving para que "vea" una señal de límite de velocidad.

- **Data Poisoning Attack**: El **conjunto de entrenamiento** se contamina deliberadamente con muestras maliciosas, enseñando al modelo reglas dañinas.\
*Example*: Binaries de malware etiquetados incorrectamente como "benign" en un corpus de entrenamiento de un antivirus, permitiendo que malware similar pase desapercibido después.

- **Model Inversion Attack**: Al sondear las salidas, un atacante construye un **reverse model** que reconstruye características sensibles de las entradas originales.\
*Example*: Recrear la imagen de una resonancia magnética de un paciente a partir de las predicciones de un modelo de detección de cáncer.

- **Membership Inference Attack**: El adversario prueba si un **registro específico** fue usado durante el entrenamiento detectando diferencias de confianza.\
*Example*: Confirmar que la transacción bancaria de una persona aparece en los datos de entrenamiento de un modelo de detección de fraude.

- **Model Theft**: Consultas repetidas permiten a un atacante aprender los límites de decisión y **clonar el comportamiento del modelo** (y la IP).\
*Example*: Recolectar suficientes pares Q&A de una ML‑as‑a‑Service API para construir un modelo local casi equivalente.

- **AI Supply‑Chain Attack**: Comprometer cualquier componente (datos, librerías, pesos pre‑entrenados, CI/CD) en la **ML pipeline** para corromper modelos downstream.\
*Example*: Una dependencia envenenada en un model‑hub instala un modelo backdoored de análisis de sentimiento en muchas apps.

- **Transfer Learning Attack**: Se planta lógica maliciosa en un **pre‑trained model** que sobrevive al fine‑tuning en la tarea de la víctima.\
*Example*: Un backbone de visión con un trigger oculto aún invierte etiquetas tras adaptarse para imágenes médicas.

- **Model Skewing**: Datos sutilmente sesgados o mal etiquetados **desplazan las salidas del modelo** para favorecer la agenda del atacante.\
*Example*: Inyectar correos spam "limpios" etiquetados como ham para que un filtro de spam permita mensajes similares en el futuro.

- **Output Integrity Attack**: El atacante **altera las predicciones del modelo en tránsito**, no el modelo en sí, engañando sistemas downstream.\
*Example*: Cambiar el veredicto "malicious" de un clasificador de malware a "benign" antes de que la etapa de cuarentena vea el archivo.

- **Model Poisoning** --- Cambios directos y dirigidos a los **parámetros del modelo** mismos, a menudo tras obtener acceso de escritura, para alterar su comportamiento.\
*Example*: Ajustar pesos en un modelo de detección de fraude en producción para que las transacciones de ciertas tarjetas siempre sean aprobadas.


## Google SAIF Risks

El [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google describe varios riesgos asociados con los sistemas de IA:

- **Data Poisoning**: Actores maliciosos alteran o inyectan datos de entrenamiento/afinado para degradar la precisión, implantar backdoors o sesgar resultados, socavando la integridad del modelo a lo largo de todo el ciclo de vida de los datos.

- **Unauthorized Training Data**: Ingerir datasets con copyright, sensibles o no autorizados crea responsabilidades legales, éticas y de rendimiento porque el modelo aprende de datos que nunca debió usar.

- **Model Source Tampering**: Manipulación en la cadena de suministro o por insiders del código del modelo, dependencias o pesos antes o durante el entrenamiento puede incrustar lógica oculta que persiste incluso tras retraining.

- **Excessive Data Handling**: Controles débiles de retención y gobernanza de datos hacen que los sistemas almacenen o procesen más datos personales de los necesarios, aumentando exposición y riesgo de cumplimiento.

- **Model Exfiltration**: Ataques que roban archivos/pesos del modelo, provocando pérdida de propiedad intelectual y permitiendo servicios clonados o ataques posteriores.

- **Model Deployment Tampering**: Adversarios modifican artefactos del modelo o la infraestructura de serving para que el modelo en ejecución difiera de la versión verificada, cambiando potencialmente su comportamiento.

- **Denial of ML Service**: Saturar APIs o enviar inputs “esponja” puede agotar cómputo/energía y dejar el modelo offline, similar a ataques DoS clásicos.

- **Model Reverse Engineering**: Recolectando grandes números de pares input‑output, atacantes pueden clonar o destilar el modelo, alimentando productos de imitación y ataques adversariales personalizados.

- **Insecure Integrated Component**: Plugins, agentes o servicios upstream vulnerables permiten a atacantes inyectar código o escalar privilegios dentro de la pipeline de IA.

- **Prompt Injection**: Diseñar prompts (directa o indirectamente) para introducir instrucciones que anulen la intención del sistema, obligando al modelo a ejecutar comandos no deseados.

- **Model Evasion**: Inputs cuidadosamente diseñados provocan que el modelo misclasifique, hallucinate o genere contenido no permitido, erosionando seguridad y confianza.

- **Sensitive Data Disclosure**: El modelo revela información privada o confidencial de sus datos de entrenamiento o del contexto del usuario, violando privacidad y regulaciones.

- **Inferred Sensitive Data**: El modelo deduce atributos personales que nunca se proporcionaron, creando nuevos daños de privacidad por inferencia.

- **Insecure Model Output**: Respuestas no saneadas pasan código dañino, desinformación o contenido inapropiado a usuarios o sistemas downstream.

- **Rogue Actions**: Agentes integrados de forma autónoma ejecutan operaciones reales no deseadas (escritura de archivos, llamadas API, compras, etc.) sin supervisión de usuario adecuada.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) proporciona un marco integral para entender y mitigar los riesgos asociados con los sistemas de IA. Categoriza diversas técnicas y tácticas de ataque que los adversarios pueden usar contra modelos de IA y también cómo usar sistemas de IA para realizar diferentes ataques.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Los atacantes roban tokens de sesión activos o credenciales de API cloud y invocan LLMs alojados en la nube y de pago sin autorización. El acceso suele revenderse vía reverse proxies que ponen delante de la cuenta de la víctima, p. ej. despliegues "oai-reverse-proxy". Las consecuencias incluyen pérdida financiera, uso indebido del modelo fuera de la política y atribución al tenant víctima.

TTPs:
- Harvest tokens from infected developer machines or browsers; steal CI/CD secrets; buy leaked cookies.
- Stand up a reverse proxy that forwards requests to the genuine provider, hiding the upstream key and multiplexing many customers.
- Abuse direct base-model endpoints to bypass enterprise guardrails and rate limits.

Mitigations:
- Bind tokens to device fingerprint, IP ranges, and client attestation; enforce short expirations and refresh with MFA.
- Scope keys minimally (no tool access, read-only where applicable); rotate on anomaly.
- Terminate all traffic server-side behind a policy gateway that enforces safety filters, per-route quotas, and tenant isolation.
- Monitor for unusual usage patterns (sudden spend spikes, atypical regions, UA strings) and auto-revoke suspicious sessions.
- Prefer mTLS or signed JWTs issued by your IdP over long-lived static API keys.

## Endurecimiento de la inferencia de LLM autohospedada

Ejecutar un servidor LLM local para datos confidenciales crea una superficie de ataque distinta a la de las APIs alojadas en la nube: inference/debug endpoints may leak prompts, la pila de serving suele exponer un reverse proxy, y los nodos de dispositivo GPU dan acceso a grandes superficies de `ioctl()`. Si estás evaluando o desplegando un servicio de inferencia on‑prem, revisa al menos los puntos siguientes.

### Prompt leakage via debug and monitoring endpoints

Treat the inference API as a **multi-user sensitive service**. Debug or monitoring routes can expose prompt contents, slot state, model metadata, or internal queue information. In `llama.cpp`, the `/slots` endpoint is especially sensitive because it exposes per-slot state and is only meant for slot inspection/management.

- Put a reverse proxy in front of the inference server and **deny by default**.
- Only allowlist the exact HTTP method + path combinations that are needed by the client/UI.
- Disable introspection endpoints in the backend itself whenever possible, for example `llama-server --no-slots`.
- Bind the reverse proxy to `127.0.0.1` and expose it through an authenticated transport such as SSH local port forwarding instead of publishing it on the LAN.

Example allowlist with nginx:
```nginx
map "$request_method:$uri" $llm_whitelist {
default 0;

"GET:/health"              1;
"GET:/v1/models"           1;
"POST:/v1/completions"     1;
"POST:/v1/chat/completions" 1;
}

server {
listen 127.0.0.1:80;

location / {
if ($llm_whitelist = 0) { return 403; }
proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
}
}
```
### Rootless containers sin red y UNIX sockets

Si el daemon de inferencia admite escuchar en un UNIX socket, prefiera eso frente a TCP y ejecute el container con **sin pila de red**:
```bash
podman run --rm -d \
--network none \
--user 1000:1000 \
--userns=keep-id \
--umask=007 \
--volume /var/lib/models:/models:ro \
--volume /srv/llm/socks:/run/llama-cpp \
ghcr.io/ggml-org/llama.cpp:server-cuda13 \
--host /run/llama-cpp/llama-cpp.sock \
--model /models/model.gguf \
--parallel 4 \
--no-slots
```
Beneficios:
- `--network none` elimina la exposición TCP/IP entrante/saliente y evita los helpers en modo usuario que los contenedores rootless necesitarían de otro modo.
- Un socket UNIX te permite usar permisos POSIX/ACLs en la ruta del socket como la primera capa de control de acceso.
- `--userns=keep-id` y rootless Podman reducen el impacto de un breakout de contenedor porque el root del contenedor no es el root del host.
- Los mounts de modelo en solo lectura reducen la probabilidad de manipulación del modelo desde dentro del contenedor.

### Minimización de device-nodes de GPU

Para la inferencia respaldada por GPU, los archivos `/dev/nvidia*` son superficies de ataque locales de alto valor porque exponen grandes handlers `ioctl()` del driver y potencialmente rutas compartidas de gestión de memoria de la GPU.

- No dejes `/dev/nvidia*` world writable.
- Restringe `nvidia`, `nvidiactl` y `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, reglas udev y ACLs para que solo el UID mapeado del contenedor pueda abrirlos.
- Pon en blacklist módulos innecesarios como `nvidia_drm`, `nvidia_modeset` y `nvidia_peermem` en hosts de inferencia headless.
- Precarga solo los módulos requeridos al boot en lugar de permitir que el runtime los `modprobe` de forma oportunista durante el startup de la inferencia.

Ejemplo:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un punto importante de revisión es **`/dev/nvidia-uvm`**. Incluso si la carga de trabajo no usa explícitamente `cudaMallocManaged()`, los runtimes de CUDA recientes aún pueden requerir `nvidia-uvm`. Dado que este dispositivo es compartido y gestiona la administración de memoria virtual de la GPU, trátalo como una superficie de exposición de datos entre tenants. Si el inference backend lo soporta, un backend Vulkan puede ser un trade-off interesante porque podría evitar exponer `nvidia-uvm` al container por completo.

### Confinamiento LSM para trabajadores de inferencia

AppArmor/SELinux/seccomp deberían usarse como defensa en profundidad alrededor del proceso de inferencia:

- Permitir únicamente las bibliotecas compartidas, rutas del modelo, el directorio de sockets y los nodos de dispositivo GPU que realmente se requieran.
- Denegar explícitamente capacidades de alto riesgo como `sys_admin`, `sys_module`, `sys_rawio` y `sys_ptrace`.
- Mantener el directorio del modelo en solo lectura y limitar las rutas escribibles solo a los directorios de sockets/cache del runtime.
- Supervisar los logs de denegación, ya que proporcionan telemetría de detección útil cuando el servidor de modelos o un payload de post-exploitation intentan escapar de su comportamiento esperado.

Example AppArmor rules for a GPU-backed worker:
```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```
## Referencias
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
