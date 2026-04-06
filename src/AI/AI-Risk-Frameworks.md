# Riesgos de IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Vulnerabilidades de Machine Learning

OWASP ha identificado las 10 principales vulnerabilidades de machine learning que pueden afectar a los sistemas de IA. Estas vulnerabilidades pueden provocar diversos problemas de seguridad, incluyendo data poisoning, model inversion y ataques adversariales. Entender estas vulnerabilidades es crucial para construir sistemas de IA seguros.

Para una lista actualizada y detallada de las top 10 vulnerabilidades de machine learning, consulta el proyecto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un atacante añade cambios diminutos, a menudo invisibles, a los **datos entrantes** para que el modelo tome la decisión equivocada.\
*Ejemplo*: Unos pocos toques de pintura en una señal de stop engañan a un coche autónomo para que "vea" una señal de límite de velocidad.

- **Data Poisoning Attack**: El **conjunto de entrenamiento** es deliberadamente contaminado con muestras malas, enseñando al modelo reglas dañinas.\
*Ejemplo*: Binaries de malware son etiquetados erróneamente como "benign" en un corpus de entrenamiento de un antivirus, permitiendo que malware similar pase desapercibido después.

- **Model Inversion Attack**: Al sondear salidas, un atacante construye un **modelo inverso** que reconstruye características sensibles de las entradas originales.\
*Ejemplo*: Recrear la imagen de una resonancia magnética de un paciente a partir de las predicciones de un modelo de detección de cáncer.

- **Membership Inference Attack**: El adversario prueba si un **registro específico** fue usado durante el entrenamiento detectando diferencias de confianza.\
*Ejemplo*: Confirmar que la transacción bancaria de una persona aparece en los datos de entrenamiento de un modelo de detección de fraude.

- **Model Theft**: Consultas repetidas permiten a un atacante aprender los límites de decisión y **clonar el comportamiento del modelo** (y la IP).\
*Ejemplo*: Extraer suficientes pares Q&A de una API de ML‑as‑a‑Service para construir un modelo local casi equivalente.

- **AI Supply‑Chain Attack**: Comprometer cualquier componente (datos, librerías, pre‑trained weights, CI/CD) en la **pipeline de ML** para corromper modelos downstream.\
*Ejemplo*: Una dependencia envenenada en un model‑hub instala un modelo de análisis de sentimiento backdoored en muchas aplicaciones.

- **Transfer Learning Attack**: Lógica maliciosa es plantada en un **pre‑trained model** y sobrevive al fine‑tuning para la tarea de la víctima.\
*Ejemplo*: Un backbone de visión con un trigger oculto sigue invirtiendo etiquetas después de ser adaptado para imagen médica.

- **Model Skewing**: Datos sutilmente sesgados o mal etiquetados **desplazan las salidas del modelo** para favorecer la agenda del atacante.\
*Ejemplo*: Inyectar correos spam "limpios" etiquetados como ham para que un filtro de spam permita correos similares en el futuro.

- **Output Integrity Attack**: El atacante **altera las predicciones del modelo en tránsito**, no el modelo en sí, engañando a sistemas downstream.\
*Ejemplo*: Cambiar el veredicto "malicious" de un clasificador de malware a "benign" antes de que la etapa de cuarentena del archivo lo vea.

- **Model Poisoning** --- Cambios directos y dirigidos a los **parámetros del modelo** mismos, a menudo tras obtener acceso de escritura, para alterar el comportamiento.\
*Ejemplo*: Ajustar pesos en un modelo de detección de fraude en producción para que las transacciones de ciertas tarjetas siempre sean aprobadas.


## Google SAIF Risks

El [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google describe varios riesgos asociados con los sistemas de IA:

- **Data Poisoning**: Actores maliciosos alteran o inyectan datos de entrenamiento/ajuste para degradar la precisión, implantar backdoors o sesgar resultados, socavando la integridad del modelo a lo largo de todo el ciclo de vida de los datos.

- **Unauthorized Training Data**: Ingerir datasets con copyright, sensibles o no permitidos crea responsabilidades legales, éticas y de rendimiento porque el modelo aprende de datos que nunca debió usar.

- **Model Source Tampering**: Manipulación en la supply‑chain o por insiders del código del modelo, dependencias o weights antes o durante el entrenamiento puede incrustar lógica oculta que persiste incluso tras retrainings.

- **Excessive Data Handling**: Controles débiles de retención y gobernanza de datos hacen que los sistemas almacenen o procesen más datos personales de los necesarios, aumentando la exposición y el riesgo de cumplimiento.

- **Model Exfiltration**: Atacantes roban archivos/weights del modelo, causando pérdida de propiedad intelectual y permitiendo servicios imitadores o ataques sucesivos.

- **Model Deployment Tampering**: Adversarios modifican artefactos del modelo o la infraestructura de serving para que el modelo en ejecución difiera de la versión auditada, cambiando potencialmente el comportamiento.

- **Denial of ML Service**: Saturar APIs o enviar inputs “sponge” puede agotar cómputo/energía y dejar el modelo offline, reflejando ataques DoS clásicos.

- **Model Reverse Engineering**: Cosechando grandes cantidades de pares input-output, los atacantes pueden clonar o destilar el modelo, alimentando productos de imitación y ataques adversariales personalizados.

- **Insecure Integrated Component**: Plugins vulnerables, agents o servicios upstream permiten a atacantes inyectar código o escalar privilegios dentro de la pipeline de IA.

- **Prompt Injection**: Diseñar prompts (directa o indirectamente) para contrabandear instrucciones que anulan la intención del sistema, haciendo que el modelo ejecute comandos no deseados.

- **Model Evasion**: Inputs cuidadosamente diseñados hacen que el modelo mis‑clasifique, hallucinate o devuelva contenido prohibido, erosionando la seguridad y la confianza.

- **Sensitive Data Disclosure**: El modelo revela información privada o confidencial de sus datos de entrenamiento o del contexto del usuario, violando privacidad y regulaciones.

- **Inferred Sensitive Data**: El modelo deduce atributos personales que nunca fueron proporcionados, creando nuevos daños de privacidad mediante inferencia.

- **Insecure Model Output**: Respuestas no sanitizadas pasan código dañino, misinformation o contenido inapropiado a usuarios o sistemas downstream.

- **Rogue Actions**: Agentes integrados autónomamente ejecutan operaciones reales no deseadas (escritura de archivos, llamadas a APIs, compras, etc.) sin supervisión de usuario adecuada.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) proporciona un marco comprensivo para entender y mitigar riesgos asociados con sistemas de IA. Categoriza varias técnicas y tácticas de ataque que los adversarios pueden usar contra modelos de IA y también cómo usar sistemas de IA para realizar diferentes ataques.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Los atacantes roban tokens de sesión activos o credenciales de API cloud y llaman a LLMs alojados en la nube de pago sin autorización. El acceso a menudo se revende vía reverse proxies que delantean la cuenta de la víctima, p. ej. despliegues "oai-reverse-proxy". Las consecuencias incluyen pérdida financiera, uso indebido del modelo fuera de la política y atribución al tenant víctima.

TTPs:
- Harvest tokens desde máquinas de desarrolladores o navegadores infectados; robar secretos de CI/CD; buy leaked cookies.
- Levantar un reverse proxy que reenvíe requests al proveedor genuino, ocultando la upstream key y multiplexando muchos clientes.
- Abusar de endpoints directos de base‑model para eludir enterprise guardrails y rate limits.

Mitigations:
- Bind tokens a device fingerprint, rangos IP y client attestation; exigir expiraciones cortas y refresh con MFA.
- Scope keys de forma mínima (sin acceso a herramientas, read‑only cuando aplique); rotar ante anomalías.
- Terminar todo el tráfico server‑side detrás de una policy gateway que haga cumplir filtros de seguridad, cuotas por ruta e isolation por tenant.
- Monitorizar patrones de uso inusuales (picos de gasto repentinos, regiones atípicas, UA strings) y auto‑revocar sesiones sospechosas.
- Preferir mTLS o JWTs firmados emitidos por tu IdP sobre claves API estáticas de larga duración.

## Endurecimiento de inference LLM autohospedada

Ejecutar un servidor LLM local para datos confidenciales crea una superficie de ataque diferente a las APIs cloud: endpoints de inference/debug pueden leak prompts, la stack de serving suele exponer un reverse proxy, y los nodos de dispositivo GPU dan acceso a grandes superficies de `ioctl()`. Si estás evaluando o desplegando un servicio de inference on‑prem, revisa al menos los siguientes puntos.

### Leak de prompts vía debug y monitoring endpoints

Trata la API de inference como un **servicio sensible multi‑usuario**. Rutas de debug o monitoring pueden exponer contenidos de prompts, estado de slots, metadata del modelo o información de colas internas. En `llama.cpp`, el endpoint `/slots` es especialmente sensible porque expone el estado por‑slot y está pensado solo para inspección/gestión de slots.

- Pon un reverse proxy delante del inference server y **deny by default**.
- Solo allowlistea las combinaciones exactas de método HTTP + path que necesita el cliente/UI.
- Deshabilita endpoints de introspección en el backend siempre que sea posible, por ejemplo `llama-server --no-slots`.
- Bindea el reverse proxy a `127.0.0.1` y exponlo mediante un transporte autenticado como SSH local port forwarding en lugar de publicar en la LAN.

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
### Rootless containers con no network y UNIX sockets

Si el inference daemon admite escuchar en un UNIX socket, prefíérelo sobre TCP y ejecuta el container con **no network stack**:
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
- `--network none` elimina la exposición TCP/IP entrante/saliente y evita los user-mode helpers que los contenedores rootless necesitarían de otro modo.
- A UNIX socket te permite usar POSIX permissions/ACLs en la ruta del socket como la primera capa de control de acceso.
- `--userns=keep-id` y rootless Podman reducen el impacto de un breakout del contenedor porque el root del contenedor no es el root del host.
- Los montajes de modelos de solo lectura reducen la probabilidad de manipulación del modelo desde dentro del contenedor.

### GPU device-node minimization

Para inferencia respaldada por GPU, los archivos `/dev/nvidia*` son superficies de ataque locales de alto valor porque exponen grandes manejadores `ioctl()` del driver y potencialmente rutas compartidas de gestión de memoria de la GPU.

- No dejes `/dev/nvidia*` escribible para todos.
- Restringe `nvidia`, `nvidiactl` y `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, reglas udev y ACLs para que solo el UID mapeado del contenedor pueda abrirlos.
- Bloquea módulos innecesarios como `nvidia_drm`, `nvidia_modeset` y `nvidia_peermem` en headless inference hosts.
- Precarga solo los módulos requeridos al arrancar en lugar de permitir que el runtime los cargue oportunísticamente con `modprobe` durante el inicio de la inferencia.

Ejemplo:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un punto importante de revisión es **`/dev/nvidia-uvm`**. Incluso si la carga de trabajo no utiliza explícitamente `cudaMallocManaged()`, los runtimes recientes de CUDA pueden seguir requiriendo `nvidia-uvm`. Dado que este dispositivo es compartido y maneja la gestión de memoria virtual de la GPU, trátalo como una superficie de exposición de datos entre inquilinos. Si el backend de inferencia lo soporta, un backend Vulkan puede ser una compensación interesante porque podría evitar exponer `nvidia-uvm` al contenedor por completo.

### Confinamiento LSM para trabajadores de inferencia

AppArmor/SELinux/seccomp deben usarse como defensa en profundidad alrededor del proceso de inferencia:

- Permitir solo las librerías compartidas, las rutas del modelo, el directorio de sockets y los nodos de dispositivo GPU que realmente sean necesarios.
- Denegar explícitamente capacidades de alto riesgo como `sys_admin`, `sys_module`, `sys_rawio` y `sys_ptrace`.
- Mantener el directorio del modelo en solo lectura y limitar las rutas grabables a los directorios de socket/cache en tiempo de ejecución únicamente.
- Monitorizar los registros de denegación porque proporcionan telemetría útil para la detección cuando el model server o un post-exploitation payload intenta escapar de su comportamiento esperado.

Ejemplo de reglas AppArmor para un worker con GPU:
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
- [Unit 42 – Los riesgos de Code Assistant LLMs: contenido dañino, uso indebido y engaño](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Descripción general del esquema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reventa de acceso LLM robado)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Análisis profundo del despliegue de un servidor LLM on-premise de privilegios bajos](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
