# Riesgos de la IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 de vulnerabilidades de Machine Learning

Owasp ha identificado las 10 principales vulnerabilidades de machine learning que pueden afectar a los sistemas de IA. Estas vulnerabilidades pueden provocar diversos problemas de seguridad, incluyendo data poisoning, model inversion y adversarial attacks. Comprender estas vulnerabilidades es crucial para crear sistemas de IA seguros.

Para consultar una lista actualizada y detallada de las 10 principales vulnerabilidades de machine learning, consulta el proyecto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[10]](#references)</sup>

- **Input Manipulation Attack**: Un atacante añade pequeños cambios, a menudo invisibles, a los **datos entrantes** para que el modelo tome una decisión incorrecta.\
*Ejemplo*: Unas pocas manchas de pintura en una señal de stop engañan a un coche autónomo para que "vea" una señal de límite de velocidad.

- **Data Poisoning Attack**: El **conjunto de entrenamiento** se contamina deliberadamente con muestras maliciosas, enseñando al modelo reglas perjudiciales.\
*Ejemplo*: Los binarios de malware se etiquetan incorrectamente como "benignos" en un corpus de entrenamiento de antivirus, permitiendo que malware similar pase desapercibido posteriormente.

- **Model Inversion Attack**: Mediante el análisis de las salidas, un atacante crea un **modelo inverso** que reconstruye características sensibles de las entradas originales.\
*Ejemplo*: Recrear la imagen de la MRI de un paciente a partir de las predicciones de un modelo de detección de cáncer.

- **Membership Inference Attack**: El adversario comprueba si un **registro específico** se utilizó durante el entrenamiento observando diferencias en el nivel de confianza.\
*Ejemplo*: Confirmar que la transacción bancaria de una persona aparece en los datos de entrenamiento de un modelo de detección de fraude.

- **Model Theft**: Las consultas repetidas permiten a un atacante aprender los límites de decisión y **clonar el comportamiento del modelo** (y su IP).\
*Ejemplo*: Recopilar suficientes pares de preguntas y respuestas de una API de ML-as-a-Service para crear un modelo local casi equivalente.

- **AI Supply-Chain Attack**: Comprometer cualquier componente (datos, librerías, pesos pre-entrenados, CI/CD) del **pipeline de ML** para corromper los modelos posteriores.\
*Ejemplo*: Una dependencia envenenada de un model-hub instala un modelo de análisis de sentimiento con una backdoor en muchas aplicaciones.

- **Transfer Learning Attack**: Se inserta lógica maliciosa en un **modelo pre-entrenado** que sobrevive al fine-tuning de la tarea de la víctima.\
*Ejemplo*: Un backbone de visión con un trigger oculto sigue cambiando las etiquetas después de adaptarse para imágenes médicas.

- **Model Skewing**: Los datos sutilmente sesgados o etiquetados incorrectamente **desplazan las salidas del modelo** para favorecer la agenda del atacante.\
*Ejemplo*: Inyectar correos de spam "limpios" etiquetados como ham para que un filtro antispam deje pasar correos similares en el futuro.

- **Output Integrity Attack**: El atacante **modifica las predicciones del modelo durante el tránsito**, no el modelo en sí, engañando a los sistemas posteriores.\
*Ejemplo*: Cambiar el veredicto "malicioso" de un clasificador de malware a "benigno" antes de que la fase de cuarentena del archivo lo reciba.

- **Model Poisoning** --- Cambios directos y dirigidos en los **parámetros del modelo**, normalmente después de obtener acceso de escritura, para alterar su comportamiento.\
*Ejemplo*: Ajustar los pesos de un modelo de detección de fraude en producción para que las transacciones de determinadas tarjetas siempre sean aprobadas.


## Riesgos de Google SAIF

El [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google describe diversos riesgos asociados a los sistemas de IA:<sup>[[11]](#references)</sup>

- **Data Poisoning**: Los actores maliciosos alteran o inyectan datos de entrenamiento o ajuste para degradar la precisión, implantar backdoors o sesgar los resultados, debilitando la integridad del modelo durante todo el ciclo de vida de los datos.

- **Unauthorized Training Data**: La incorporación de datasets con copyright, sensibles o no autorizados crea responsabilidades legales, éticas y de rendimiento, porque el modelo aprende de datos que nunca tuvo permiso para utilizar.

- **Model Source Tampering**: La manipulación de la cadena de suministro o por parte de insiders del código del modelo, sus dependencias o pesos, antes o durante el entrenamiento, puede insertar lógica oculta que persiste incluso después del reentrenamiento.

- **Excessive Data Handling**: Los controles débiles de retención y gobernanza de datos hacen que los sistemas almacenen o procesen más datos personales de los necesarios, aumentando la exposición y el riesgo de incumplimiento.

- **Model Exfiltration**: Los atacantes roban archivos o pesos del modelo, provocando la pérdida de propiedad intelectual y permitiendo servicios imitadores o ataques posteriores.

- **Model Deployment Tampering**: Los adversarios modifican los artefactos del modelo o la infraestructura de serving para que el modelo en ejecución difiera de la versión validada, cambiando potencialmente su comportamiento.

- **Denial of ML Service**: Inundar las APIs o enviar entradas tipo “sponge” puede agotar la capacidad de cómputo o energía y dejar el modelo fuera de servicio, imitando los ataques DoS clásicos.

- **Model Reverse Engineering**: Al recopilar grandes cantidades de pares de entrada y salida, los atacantes pueden clonar o destilar el modelo, impulsando productos imitadores y adversarial attacks personalizados.

- **Insecure Integrated Component**: Los plugins, agentes o servicios upstream vulnerables permiten a los atacantes inyectar código o escalar privilegios dentro del pipeline de IA.

- **Prompt Injection**: Crear prompts, directa o indirectamente, para introducir instrucciones que anulen la intención del sistema, haciendo que el modelo ejecute comandos no deseados.

- **Model Evasion**: Las entradas cuidadosamente diseñadas provocan que el modelo clasifique incorrectamente, alucine o genere contenido no permitido, erosionando la seguridad y la confianza.

- **Sensitive Data Disclosure**: El modelo revela información privada o confidencial de sus datos de entrenamiento o del contexto del usuario, infringiendo la privacidad y las normativas.

- **Inferred Sensitive Data**: El modelo deduce atributos personales que nunca se proporcionaron, creando nuevos daños a la privacidad mediante inferencias.

- **Insecure Model Output**: Las respuestas no sanitizadas transmiten código dañino, desinformación o contenido inapropiado a los usuarios o sistemas posteriores.

- **Rogue Actions**: Los agentes integrados de forma autónoma ejecutan operaciones no deseadas en el mundo real (escrituras de archivos, llamadas a APIs, compras, etc.) sin una supervisión adecuada del usuario.

## Matriz MITRE AI ATLAS

La [Matriz MITRE AI ATLAS](https://atlas.mitre.org/matrices/ATLAS) proporciona un marco integral para comprender y mitigar los riesgos asociados a los sistemas de IA. Clasifica diversas técnicas y tácticas de ataque que los adversarios pueden utilizar contra modelos de IA, así como las formas de utilizar sistemas de IA para realizar distintos ataques.<sup>[[12]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Los atacantes roban tokens de sesión activos o credenciales de API cloud e invocan LLM alojados en la cloud y de pago sin autorización. El acceso suele revenderse mediante reverse proxies que actúan como interfaz de la cuenta de la víctima, por ejemplo, despliegues de "oai-reverse-proxy". Las consecuencias incluyen pérdidas económicas, uso indebido del modelo fuera de la política y atribución al tenant de la víctima.<sup>[[2]](#references)[[3]](#references)</sup>

TTPs:
- Recopilar tokens de máquinas de desarrolladores o navegadores infectados; robar secretos de CI/CD; comprar cookies filtradas.
- Configurar un reverse proxy que reenvíe las solicitudes al proveedor legítimo, ocultando la clave upstream y multiplexando a muchos clientes.
- Abusar de los endpoints directos del modelo base para eludir las medidas de seguridad empresariales y los límites de tasa.

Mitigaciones:
- Vincular los tokens a la huella del dispositivo, rangos de IP y attestation del cliente; aplicar expiraciones cortas y renovar con MFA.
- Limitar las claves al mínimo necesario (sin acceso a herramientas y en modo solo lectura cuando corresponda); rotarlas ante anomalías.
- Terminar todo el tráfico en el servidor detrás de un gateway de políticas que aplique filtros de seguridad, cuotas por ruta y aislamiento de tenants.
- Supervisar patrones de uso inusuales (picos repentinos de gasto, regiones atípicas, cadenas UA) y revocar automáticamente las sesiones sospechosas.
- Preferir mTLS o JWTs firmados emitidos por tu IdP frente a API keys estáticas de larga duración.

## Refuerzo de la seguridad de la inferencia de LLM self-hosted

Ejecutar un servidor LLM local para datos confidenciales crea una superficie de ataque distinta a la de las APIs alojadas en la cloud: los endpoints de inferencia o debug pueden filtrar prompts, el stack de serving normalmente expone un reverse proxy y los nodos de dispositivo GPU proporcionan acceso a grandes superficies `ioctl()`. Si estás evaluando o desplegando un servicio de inferencia on-prem, revisa como mínimo los siguientes puntos.<sup>[[4]](#references)</sup>

### Filtración de prompts mediante endpoints de debug y monitorización

Trata la API de inferencia como un **servicio sensible multiusuario**. Las rutas de debug o monitorización pueden exponer el contenido de los prompts, el estado de los slots, los metadatos del modelo o información sobre las colas internas. En `llama.cpp`, el endpoint `/slots` es especialmente sensible porque expone el estado de cada slot y solo está destinado a la inspección o gestión de slots.<sup>[[4]](#references)[[5]](#references)</sup>

- Coloca un reverse proxy delante del servidor de inferencia y **deniega por defecto**.
- Permite únicamente las combinaciones exactas de método HTTP + ruta que necesiten el cliente o la UI.
- Desactiva los endpoints de introspección en el propio backend siempre que sea posible, por ejemplo `llama-server --no-slots`.
- Vincula el reverse proxy a `127.0.0.1` y expónlo mediante un transporte autenticado, como el reenvío de puertos local de SSH, en lugar de publicarlo en la LAN.

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
### Contenedores rootless sin red y sockets UNIX

Si el daemon de inferencia admite escuchar en un socket UNIX, prefiera esta opción en lugar de TCP y ejecute el contenedor con **sin pila de red**:
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
- `--network none` elimina la exposición TCP/IP entrante/saliente y evita los user-mode helpers que, de otro modo, necesitarían los contenedores rootless.
- Un UNIX socket permite usar permisos/ACL de POSIX en la ruta del socket como primera capa de control de acceso.
- `--userns=keep-id` y Podman rootless reducen el impacto de un container breakout porque el root del contenedor no es el root del host.
- Los montajes de modelos de solo lectura reducen la posibilidad de manipulación del modelo desde dentro del contenedor.

### Minimización de nodos de dispositivo GPU

Para la inferencia respaldada por GPU, los archivos `/dev/nvidia*` son superficies de ataque locales de alto valor porque exponen grandes controladores `ioctl()` y posibles rutas compartidas de gestión de memoria de la GPU.<sup>[[4]](#references)</sup>

- No dejes `/dev/nvidia*` con permisos de escritura para todo el mundo.
- Restringe `nvidia`, `nvidiactl` y `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, reglas de udev y ACLs para que solo el UID asignado al contenedor pueda abrirlos.
- Incluye en la blacklist los módulos innecesarios, como `nvidia_drm`, `nvidia_modeset` y `nvidia_peermem`, en hosts de inferencia headless.
- Precarga únicamente los módulos necesarios durante el arranque, en lugar de permitir que el runtime haga `modprobe` de forma oportunista durante el inicio de la inferencia.

Ejemplo:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un punto importante de la revisión es **`/dev/nvidia-uvm`**. Aunque la workload no utilice explícitamente `cudaMallocManaged()`, los runtimes recientes de CUDA aún pueden requerir `nvidia-uvm`. Dado que este dispositivo es compartido y gestiona la memoria virtual de la GPU, debe tratarse como una superficie de exposición de datos entre tenants. Si el backend de inference lo admite, un backend de Vulkan puede ser una alternativa interesante, ya que podría evitar exponer `nvidia-uvm` al container por completo.

### Confinamiento LSM para inference workers

AppArmor/SELinux/seccomp deben utilizarse como defense in depth alrededor del proceso de inference:<sup>[[4]](#references)</sup>

- Permitir únicamente las shared libraries, rutas de los modelos, directorio de sockets y nodos de dispositivos de la GPU que sean realmente necesarios.
- Denegar explícitamente capabilities de alto riesgo como `sys_admin`, `sys_module`, `sys_rawio` y `sys_ptrace`.
- Mantener el directorio de los modelos en modo read-only y limitar las rutas con permisos de escritura únicamente a los directorios de sockets/cache del runtime.
- Monitorizar los logs de denegaciones, ya que proporcionan telemetría de detección útil cuando el model server o un payload de post-exploitation intenta escapar de su comportamiento esperado.

Ejemplo de reglas de AppArmor para un worker respaldado por GPU:
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
## Phantom Squatting: Dominios alucinados por LLM como vector de la cadena de suministro de IA

Phantom squatting es el **equivalente de dominio/URL de slopsquatting**. En lugar de alucinar el nombre de un paquete inexistente, el LLM alucina un **dominio plausible de portal, API, webhook, facturación, SSO, descarga o soporte** para una marca real, y un atacante registra ese namespace antes de que una persona o un agente lo utilice.<sup>[[8]](#references)[[9]](#references)</sup>

Esto es importante porque, en muchos flujos de trabajo asistidos por IA, la salida del modelo se trata como una **dependencia de confianza**:
- Los desarrolladores pegan el endpoint sugerido en el código o en integraciones de CI/CD.
- Los agentes de IA obtienen automáticamente documentación, esquemas, APKs, ZIPs o destinos de webhook.
- Los runbooks o documentos generados pueden incluir la URL falsa como si fuera autoritativa.

### Flujo de trabajo ofensivo

1. **Sondear la superficie de alucinación**: hacer preguntas específicas sobre marcas acerca de flujos de trabajo realistas, como portales de `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.
2. **Normalizar candidatos**: resolver las URL generadas, reducir las respuestas NXDOMAIN al dominio principal registrable y eliminar duplicados entre familias de prompts. Los corpus de prompts deben mantenerse diversos, por ejemplo, descartando casi duplicados mediante **similitud de Jaccard**.
3. **Priorizar las alucinaciones predecibles**:
- **Thermal Hallucination Persistence (THP)**: el mismo dominio falso aparece con distintas temperaturas, incluida una temperatura baja como `T=0.1`.
- **Consenso entre modelos**: varias familias de LLM generan el mismo dominio falso.
4. **Registrar y weaponize** el dominio principal; después, alojar phishing, descargas falsas de APK/ZIP, credential harvesters, documentos maliciosos o endpoints de API que recopilen secretos/payloads de webhook. Las **alucinaciones puras a nivel de dominio** son las más fáciles de monetizar porque el atacante controla todo el namespace; las alucinaciones de subdominio/ruta aún pueden abusarse cuando el dominio principal normalizado no está registrado.
5. **Explotar la ventana de reputación cero**: los dominios recién registrados suelen carecer de historial en blocklists, reputación de URL y telemetría madura, por lo que pueden eludir los controles hasta que las detecciones se pongan al día. Los atacantes pueden prolongar esta ventana mediante respuestas benignas solo para crawlers, redirect cloaking, CAPTCHA gates o staging retrasado de payloads.

### Por qué es peligroso para los agentes

Para una víctima humana, el dominio falso normalmente aún requiere un clic y otra acción. En un **flujo de trabajo agéntico**, el LLM puede ser tanto el **cebo** como el **ejecutor**: el agente recibe la URL alucinada, la obtiene, analiza la respuesta y después puede filtrar tokens, ejecutar instrucciones, descargar una dependencia o introducir datos envenenados en CI/CD sin ninguna revisión humana.<sup>[[8]](#references)</sup>

### Prompts prácticos para atacantes

Los prompts de mayor rendimiento suelen parecer tareas empresariales normales en lugar de cebos de phishing explícitos:
- “¿Cuál es la URL del sandbox de pagos para las integraciones de `<brand>`?”
- “¿Qué endpoint de webhook debo utilizar para las notificaciones de compilación de `<brand>`?”
- “¿Dónde está el portal de beneficios para empleados / facturación / SSO de `<brand>`?”
- “Dame la descarga directa del APK de Android o del cliente de escritorio de `<brand>`.”

### Inversión defensiva

Trátalo como un problema de monitorización proactiva de dominios, no solo como un problema de prompt injection:
- Crea un **corpus de prompts de marcas** y sondea periódicamente los LLM de los que dependen tus usuarios/agentes.
- Almacena las URL alucinadas y registra cuáles son estables entre temperaturas/modelos.
- Registra la **Adversarial Exploitation Window (AEW)**: el tiempo entre la primera alucinación y el registro por parte del atacante. Un AEW positivo significa que los defensores pueden registrar previamente, hacer sinkhole o bloquear previamente el dominio antes de su weaponization.
- Monitoriza las transiciones de **NXDOMAIN → registrado** para los dominios principales.
- Tras el registro, clasifica el registrar, la fecha de creación, los nameservers, el privacy shielding, el contenido de la página, las capturas de pantalla, el estado de página aparcada y la similitud con los recursos de la marca.
- Añade policy gates para que los agentes/desarrolladores **no confíen por defecto en dominios generados por LLM**: exige allowlists, validación de propiedad, comprobaciones CT/RDAP o aprobación humana antes del primer uso.

Esto encaja simultáneamente en varias categorías de riesgo de IA: **ataque a la cadena de suministro de IA**, **salida insegura del modelo** y **acciones rogue** cuando los agentes consumen de forma autónoma la URL alucinada.

## References
- [1] [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [2] [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [3] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [4] [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [5] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [6] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [7] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [8] [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [9] [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [10] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [11] [Google SAIF (Security AI Framework) Risks](https://saif.google/secure-ai-framework/risks)
- [12] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)

{{#include ../banners/hacktricks-training.md}}
