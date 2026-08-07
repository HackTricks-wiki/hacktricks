# Riesgos de AI

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP ha identificado las 10 principales vulnerabilidades de machine learning que pueden afectar a los sistemas de AI. Estas vulnerabilidades pueden provocar diversos problemas de seguridad, incluidos data poisoning, model inversion y adversarial attacks. Comprender estas vulnerabilidades es fundamental para crear sistemas de AI seguros.

Para consultar una lista actualizada y detallada de las 10 principales vulnerabilidades de machine learning, consulta el proyecto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Un atacante añade pequeños cambios, a menudo invisibles, a los **datos entrantes** para que el modelo tome una decisión incorrecta.\
*Ejemplo*: Unas pocas manchas de pintura en una señal de stop engañan a un coche autónomo para que "vea" una señal de límite de velocidad.

- **Data Poisoning Attack**: El **training set** se contamina deliberadamente con muestras maliciosas, enseñando al modelo reglas dañinas.\
*Ejemplo*: Los binarios de malware se etiquetan incorrectamente como "benign" en un corpus de entrenamiento de antivirus, permitiendo que malware similar pase desapercibido posteriormente.

- **Model Inversion Attack**: Mediante el análisis de las salidas, un atacante crea un **reverse model** que reconstruye características sensibles de las entradas originales.\
*Ejemplo*: Recrear la imagen de MRI de un paciente a partir de las predicciones de un modelo de detección de cáncer.

- **Membership Inference Attack**: El adversario comprueba si un **registro específico** se utilizó durante el entrenamiento observando diferencias en el nivel de confianza.\
*Ejemplo*: Confirmar que la transacción bancaria de una persona aparece en los datos de entrenamiento de un modelo de detección de fraude.

- **Model Theft**: Las consultas repetidas permiten a un atacante aprender los límites de decisión y **clonar el comportamiento del modelo** (y su IP).\
*Ejemplo*: Recopilar suficientes pares de preguntas y respuestas de una API de ML-as-a-Service para crear un modelo local casi equivalente.

- **AI Supply-Chain Attack**: Comprometer cualquier componente (datos, libraries, pre-trained weights, CI/CD) del **ML pipeline** para corromper los modelos posteriores.\
*Ejemplo*: Una dependencia envenenada de un model-hub instala un modelo de análisis de sentimiento con backdoor en muchas aplicaciones.

- **Transfer Learning Attack**: Se introduce lógica maliciosa en un **pre-trained model** que sobrevive al fine-tuning para la tarea de la víctima.\
*Ejemplo*: Un backbone de visión con un trigger oculto sigue cambiando las etiquetas después de adaptarse a imágenes médicas.

- **Model Skewing**: Los datos sutilmente sesgados o etiquetados incorrectamente **desplazan las salidas del modelo** para favorecer la agenda del atacante.\
*Ejemplo*: Inyectar correos de spam "limpios" etiquetados como ham para que un filtro de spam permita el paso de correos futuros similares.

- **Output Integrity Attack**: El atacante **altera las predicciones del modelo durante el tránsito**, no el modelo en sí, engañando a los sistemas posteriores.\
*Ejemplo*: Cambiar el veredicto "malicious" de un clasificador de malware a "benign" antes de que la fase de cuarentena del archivo lo procese.

- **Model Poisoning** --- Cambios directos y dirigidos en los **parámetros del modelo**, normalmente después de obtener acceso de escritura, para alterar su comportamiento.\
*Ejemplo*: Modificar los weights de un modelo de detección de fraude en producción para que las transacciones de determinadas tarjetas siempre se aprueben.


## Riesgos de Google SAIF

La [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google describe diversos riesgos asociados a los sistemas de AI:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Los actores maliciosos alteran o inyectan datos de training/tuning para degradar la precisión, implantar backdoors o sesgar los resultados, comprometiendo la integridad del modelo durante todo el ciclo de vida de los datos.

- **Unauthorized Training Data**: Ingerir datasets con copyright, sensibles o no autorizados crea responsabilidades legales, éticas y de rendimiento, porque el modelo aprende de datos que nunca tuvo permiso para utilizar.

- **Model Source Tampering**: La manipulación por parte de la supply chain o de personal interno del código del modelo, sus dependencias o weights, antes o durante el entrenamiento, puede incorporar lógica oculta que persiste incluso después del retraining.

- **Excessive Data Handling**: Los controles débiles de retención y gobernanza de datos hacen que los sistemas almacenen o procesen más datos personales de los necesarios, aumentando la exposición y el riesgo de incumplimiento.

- **Model Exfiltration**: Los atacantes roban archivos o weights del modelo, provocando la pérdida de propiedad intelectual y permitiendo servicios clonados o ataques posteriores.

- **Model Deployment Tampering**: Los adversarios modifican los artefactos del modelo o la infraestructura de serving para que el modelo en ejecución difiera de la versión validada, cambiando potencialmente su comportamiento.

- **Denial of ML Service**: Inundar las APIs o enviar inputs “sponge” puede agotar la capacidad de cómputo o energía y dejar el modelo offline, imitando los ataques DoS clásicos.

- **Model Reverse Engineering**: Al recopilar grandes cantidades de pares input-output, los atacantes pueden clonar o destilar el modelo, impulsando productos imitadores y ataques adversariales personalizados.

- **Insecure Integrated Component**: Los plugins, agentes o servicios upstream vulnerables permiten a los atacantes inyectar código o escalar privilegios dentro del AI pipeline.

- **Prompt Injection**: Crear prompts, directa o indirectamente, para introducir instrucciones que anulen la intención del sistema, haciendo que el modelo ejecute comandos no deseados.

- **Model Evasion**: Los inputs cuidadosamente diseñados hacen que el modelo clasifique incorrectamente, alucine o genere contenido no permitido, erosionando la seguridad y la confianza.

- **Sensitive Data Disclosure**: El modelo revela información privada o confidencial de sus datos de entrenamiento o del contexto del usuario, infringiendo la privacidad y la normativa.

- **Inferred Sensitive Data**: El modelo deduce atributos personales que nunca se proporcionaron, creando nuevos perjuicios para la privacidad mediante inferencias.

- **Insecure Model Output**: Las respuestas no sanitizadas transmiten código dañino, desinformación o contenido inapropiado a los usuarios o a los sistemas posteriores.

- **Rogue Actions**: Los agentes integrados de forma autónoma ejecutan operaciones no deseadas en el mundo real (escrituras de archivos, llamadas a APIs, compras, etc.) sin una supervisión adecuada del usuario.

## MITRE AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) proporciona un marco integral para comprender y mitigar los riesgos asociados a los sistemas de AI. Clasifica diversas técnicas y tácticas de ataque que los adversarios pueden utilizar contra los modelos de AI, así como las formas de utilizar sistemas de AI para realizar distintos ataques.<sup>[[3]](#references)</sup>

## LLMJacking (Robo y reventa de tokens de acceso a LLM alojados en la cloud)

Los atacantes roban tokens de sesión activos o credenciales de API de la cloud y utilizan LLM de pago alojados en la cloud sin autorización. El acceso suele revenderse mediante reverse proxies que se sitúan delante de la cuenta de la víctima, por ejemplo, mediante despliegues de "oai-reverse-proxy". Las consecuencias incluyen pérdidas económicas, uso indebido del modelo fuera de la policy y atribución al tenant de la víctima.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- Recopilar tokens de máquinas de desarrolladores o browsers infectados; robar secretos de CI/CD; comprar cookies filtradas.<sup>[[5]](#references)</sup>
- Configurar un reverse proxy que reenvíe las solicitudes al proveedor legítimo, ocultando la key upstream y multiplexando a muchos clientes.<sup>[[5]](#references)[[7]](#references)</sup>
- Abusar de endpoints directos del base-model para eludir las medidas de seguridad y los rate limits empresariales.<sup>[[4]](#references)</sup>

Mitigations:
- Vincular los tokens a la huella del dispositivo, rangos de IP y client attestation; aplicar expiraciones breves y renovar mediante MFA.
- Limitar las keys al mínimo necesario (sin acceso a tools y con permisos de solo lectura cuando corresponda); rotarlas ante anomalías.
- Terminar todo el tráfico en el lado del servidor detrás de un policy gateway que aplique filtros de seguridad, cuotas por ruta y aislamiento de tenants.
- Supervisar patrones de uso inusuales (picos repentinos de gasto, regiones atípicas, cadenas UA) y revocar automáticamente las sesiones sospechosas.
- Preferir mTLS o JWTs firmados emitidos por el IdP frente a API keys estáticas de larga duración.

## Refuerzo de la seguridad de la inferencia de LLM self-hosted

Ejecutar un servidor local de LLM para datos confidenciales crea una attack surface diferente a la de las APIs alojadas en la cloud: los endpoints de inference/debug pueden filtrar prompts, el serving stack suele exponer un reverse proxy y los nodos de dispositivo GPU proporcionan acceso a grandes superficies `ioctl()`. Si estás evaluando o desplegando un servicio de inference on-prem, revisa al menos los siguientes puntos.<sup>[[8]](#references)</sup>

### Fuga de prompts mediante endpoints de debug y monitoring

Trata la API de inference como un **servicio sensible multiusuario**. Las rutas de debug o monitoring pueden exponer el contenido de los prompts, el estado de los slots, los metadatos del modelo o información sobre las colas internas. En `llama.cpp`, el endpoint `/slots` es especialmente sensible porque expone el estado de cada slot y solo está destinado a la inspección o gestión de slots.<sup>[[8]](#references)</sup>

- Coloca un reverse proxy delante del servidor de inference y **deniega por defecto**.
- Permite únicamente las combinaciones exactas de método HTTP + path que necesiten el cliente o la UI.
- Desactiva los endpoints de introspection en el propio backend siempre que sea posible, por ejemplo, `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Vincula el reverse proxy a `127.0.0.1` y expónlo mediante un transporte autenticado, como el local port forwarding de SSH, en lugar de publicarlo en la LAN.

Ejemplo de allowlist con nginx:
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
### Contenedores sin root, sin red y sockets UNIX

Si el daemon de inferencia admite escuchar en un socket UNIX, prefiera esa opción en lugar de TCP y ejecute el contenedor sin pila de red:<sup>[[8]](#references)</sup>
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
- `--network none` elimina la exposición TCP/IP entrante/saliente y evita los helpers de user-mode que, de otro modo, necesitarían los contenedores rootless.
- Un socket UNIX permite usar permisos/ACLs POSIX en la ruta del socket como primera capa de control de acceso.
- `--userns=keep-id` y Podman rootless reducen el impacto de un breakout del contenedor porque el root del contenedor no es el root del host.
- Los mounts de modelos de solo lectura reducen la posibilidad de manipulación del modelo desde dentro del contenedor.

### Minimización de device-nodes de GPU

Para inference respaldada por GPU, los archivos `/dev/nvidia*` son superficies de ataque locales de alto valor porque exponen grandes handlers de `ioctl()` del driver y posibles rutas compartidas de gestión de memoria de la GPU.<sup>[[8]](#references)</sup>

- No dejes `/dev/nvidia*` con permisos de escritura para todo el mundo.
- Restringe `nvidia`, `nvidiactl` y `nvidia-uvm` mediante `NVreg_DeviceFileUID/GID/Mode`, reglas de udev y ACLs, de modo que solo el UID mapeado del contenedor pueda abrirlos.
- Incluye en la blacklist módulos innecesarios como `nvidia_drm`, `nvidia_modeset` y `nvidia_peermem` en hosts de inference headless.
- Precarga únicamente los módulos necesarios durante el arranque, en lugar de permitir que el runtime ejecute `modprobe` oportunistamente durante el inicio de la inference.

Ejemplo:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un punto de revisión importante es **`/dev/nvidia-uvm`**. Incluso si la workload no utiliza explícitamente `cudaMallocManaged()`, los runtimes de CUDA recientes pueden seguir requiriendo `nvidia-uvm`. Dado que este dispositivo se comparte y gestiona la memoria virtual de la GPU, trátalo como una superficie de exposición de datos entre tenants. Si el backend de inference lo admite, un backend de Vulkan puede ser una alternativa interesante, ya que podría evitar exponer `nvidia-uvm` al container por completo.<sup>[[8]](#references)</sup>

### Confinamiento LSM para los workers de inference

AppArmor/SELinux/seccomp deberían utilizarse como defensa en profundidad alrededor del proceso de inference:<sup>[[8]](#references)</sup>

- Permite únicamente las shared libraries, las rutas de los modelos, el directorio de sockets y los device nodes de la GPU que sean realmente necesarios.
- Deniega explícitamente capabilities de alto riesgo como `sys_admin`, `sys_module`, `sys_rawio` y `sys_ptrace`.
- Mantén el directorio del modelo en solo lectura y limita las rutas escribibles únicamente a los directorios de sockets/cache del runtime.
- Monitoriza los logs de denegaciones, ya que proporcionan telemetría de detección útil cuando el model server o un payload de post-exploitation intenta escapar de su comportamiento esperado.

Reglas de AppArmor de ejemplo para un worker respaldado por GPU:
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
## Phantom Squatting: dominios alucinados por LLM como vector de la cadena de suministro de IA

Phantom squatting es el **equivalente de dominio/URL de slopsquatting**. En lugar de alucinar un nombre de paquete inexistente, el LLM alucina un **dominio plausible de portal, API, webhook, facturación, SSO, descarga o soporte** para una marca real, y un atacante registra ese namespace antes de que una persona o un agente lo utilice.<sup>[[12]](#references)[[13]](#references)</sup>

Esto es importante porque, en muchos flujos de trabajo asistidos por IA, la salida del modelo se trata como una **dependencia de confianza**:
- Los desarrolladores pegan el endpoint sugerido en el código o en integraciones CI/CD.
- Los agentes de IA obtienen automáticamente documentación, schemas, APKs, ZIPs o destinos de webhook.
- Los runbooks o documentos generados pueden incluir la URL falsa como si fuera autoritativa.

### Flujo de trabajo ofensivo

1. **Sondear la superficie de alucinación**: hacer preguntas específicas sobre una marca y relacionadas con flujos de trabajo realistas, como portales `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizar candidatos**: resolver las URLs generadas, reducir las respuestas NXDOMAIN al dominio principal registrable y eliminar duplicados entre familias de prompts. Los corpus de prompts deben mantenerse diversos, por ejemplo, eliminando casi duplicados mediante **similitud de Jaccard**.
3. **Priorizar las alucinaciones predecibles**:
- **Thermal Hallucination Persistence (THP)**: el mismo dominio falso aparece con distintas temperaturas, incluida una temperatura baja como `T=0.1`.
- **Consenso entre modelos**: varias familias de LLM generan el mismo dominio falso.
4. **Registrar y weaponize** el dominio principal; después, alojar phishing, descargas falsas de APK/ZIP, credential harvesters, documentos maliciosos o endpoints de API que recopilen secretos o payloads de webhook. Las **alucinaciones puras a nivel de dominio** son las más fáciles de monetizar porque el atacante controla todo el namespace; las alucinaciones de subdominio/ruta también pueden abusarse cuando el dominio principal normalizado no está registrado.
5. **Explotar la ventana de reputación cero**: los dominios recién registrados suelen carecer de historial en blocklists, reputación de URL y telemetría madura, por lo que pueden evadir los controles hasta que las detecciones se pongan al día. Los atacantes pueden ampliar esta ventana mediante respuestas benignas solo para crawlers, redirect cloaking, CAPTCHA gates o staging retardado del payload.

### Por qué es peligroso para los agentes

Para una víctima humana, el dominio falso normalmente todavía requiere un clic y otra acción. En un **flujo de trabajo agentic**, el LLM puede ser tanto el **señuelo** como el **ejecutor**: el agente recibe la URL alucinada, la obtiene, analiza la respuesta y después puede hacer leak de tokens, ejecutar instrucciones, descargar una dependencia o introducir datos envenenados en CI/CD sin ninguna revisión humana.<sup>[[12]](#references)</sup>

### Prompts prácticos para atacantes

Los prompts de alto rendimiento suelen parecer tareas empresariales normales en lugar de señuelos de phishing explícitos:<sup>[[12]](#references)</sup>
- “¿Cuál es la URL del payment sandbox para las integraciones de `<brand>`?”
- “¿Qué endpoint de webhook debería usar para las notificaciones de compilación de `<brand>`?”
- “¿Dónde está el portal de beneficios para empleados / facturación / SSO de `<brand>`?”
- “Dame la descarga directa del APK de Android o del cliente de escritorio de `<brand>`.”

### Inversión defensiva

Trata esto como un problema proactivo de monitorización de dominios, no solo como un problema de prompt injection:<sup>[[12]](#references)</sup>
- Crear un **corpus de prompts de marcas** y sondear periódicamente los LLM de los que dependen los usuarios/agentes.
- Almacenar las URLs alucinadas y realizar un seguimiento de cuáles son estables entre temperaturas/modelos.
- Seguir la **Adversarial Exploitation Window (AEW)**: el tiempo entre la primera alucinación y el registro por parte del atacante. Un AEW positivo significa que los defensores pueden registrar preventivamente, hacer sinkhole o bloquear preventivamente antes de la weaponization.
- Monitorizar las transiciones de **NXDOMAIN → registrado** para los dominios principales.
- Tras el registro, analizar el registrar, la fecha de creación, los nameservers, el privacy shielding, el contenido de la página, las capturas de pantalla, el estado de página aparcada y la similitud con los activos de la marca.
- Añadir policy gates para que los agentes/desarrolladores **no confíen por defecto en dominios generados por LLM**: exigir allowlists, validación de propiedad, comprobaciones CT/RDAP o aprobación humana antes del primer uso.

Esto encaja simultáneamente en varias categorías de riesgo de IA: **ataque a la cadena de suministro de IA**, **salida insegura del modelo** y **acciones rogue** cuando los agentes consumen autónomamente la URL alucinada.

## Referencias

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Stolen Cloud Credentials Used in New AI Attack](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
