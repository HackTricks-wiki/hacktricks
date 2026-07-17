# Riesgos de la IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP ha identificado las 10 principales vulnerabilidades de machine learning que pueden afectar a los sistemas de IA. Estas vulnerabilidades pueden provocar diversos problemas de seguridad, incluidos data poisoning, model inversion y adversarial attacks. Comprender estas vulnerabilidades es fundamental para crear sistemas de IA seguros.

Para consultar una lista actualizada y detallada de las 10 principales vulnerabilidades de machine learning, consulta el proyecto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un atacante añade pequeños cambios, a menudo invisibles, a los **datos entrantes** para que el modelo tome una decisión incorrecta.\
*Ejemplo*: Unas pocas manchas de pintura en una señal de stop engañan a un coche autónomo para que "vea" una señal de límite de velocidad.

- **Data Poisoning Attack**: El **conjunto de entrenamiento** se contamina deliberadamente con muestras maliciosas, enseñando al modelo reglas perjudiciales.\
*Ejemplo*: Los binarios de malware se etiquetan incorrectamente como "benignos" en un corpus de entrenamiento de antivirus, permitiendo que malware similar pase desapercibido posteriormente.

- **Model Inversion Attack**: Mediante el análisis de las salidas, un atacante construye un **modelo inverso** que reconstruye características sensibles de las entradas originales.\
*Ejemplo*: Recrear la imagen de resonancia magnética de un paciente a partir de las predicciones de un modelo de detección de cáncer.

- **Membership Inference Attack**: El adversario comprueba si un **registro específico** se utilizó durante el entrenamiento observando diferencias en los niveles de confianza.\
*Ejemplo*: Confirmar que la transacción bancaria de una persona aparece en los datos de entrenamiento de un modelo de detección de fraude.

- **Model Theft**: Las consultas repetidas permiten a un atacante aprender los límites de decisión y **clonar el comportamiento del modelo** (y su IP).\
*Ejemplo*: Recopilar suficientes pares de preguntas y respuestas de una API de ML-as-a-Service para crear un modelo local casi equivalente.

- **AI Supply-Chain Attack**: Comprometer cualquier componente (datos, librerías, pesos preentrenados, CI/CD) del **pipeline de ML** para corromper los modelos posteriores.\
*Ejemplo*: Una dependencia envenenada de un model-hub instala un modelo de análisis de sentimiento con una backdoor en numerosas aplicaciones.

- **Transfer Learning Attack**: Se introduce lógica maliciosa en un **modelo preentrenado** que sobrevive al fine-tuning para la tarea de la víctima.\
*Ejemplo*: Un backbone de visión con un trigger oculto sigue cambiando las etiquetas después de adaptarse a imágenes médicas.

- **Model Skewing**: Los datos sutilmente sesgados o etiquetados incorrectamente **desplazan las salidas del modelo** para favorecer los objetivos del atacante.\
*Ejemplo*: Inyectar correos spam "limpios" etiquetados como ham para que un filtro de spam permita pasar correos futuros similares.

- **Output Integrity Attack**: El atacante **altera las predicciones del modelo durante el tránsito**, no el modelo en sí, engañando a los sistemas posteriores.\
*Ejemplo*: Cambiar el veredicto "malicioso" de un clasificador de malware a "benigno" antes de que la fase de cuarentena del archivo lo reciba.

- **Model Poisoning** --- Cambios directos y dirigidos en los **parámetros del modelo**, normalmente después de obtener acceso de escritura, para alterar su comportamiento.\
*Ejemplo*: Ajustar los pesos de un modelo de detección de fraude en producción para que las transacciones de determinadas tarjetas siempre se aprueben.


## Google SAIF Risks

El [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google describe diversos riesgos asociados a los sistemas de IA:

- **Data Poisoning**: Actores maliciosos alteran o inyectan datos de entrenamiento o tuning para degradar la precisión, implantar backdoors o sesgar los resultados, debilitando la integridad del modelo durante todo el ciclo de vida de los datos.

- **Unauthorized Training Data**: La incorporación de datasets con copyright, sensibles o no autorizados genera responsabilidades legales, éticas y de rendimiento, porque el modelo aprende de datos cuyo uso nunca estuvo permitido.

- **Model Source Tampering**: La manipulación de la cadena de suministro o por parte de insiders del código del modelo, sus dependencias o pesos antes o durante el entrenamiento puede introducir lógica oculta que persiste incluso después del reentrenamiento.

- **Excessive Data Handling**: Unos controles débiles de retención y gobierno de datos hacen que los sistemas almacenen o procesen más datos personales de los necesarios, aumentando la exposición y el riesgo de incumplimiento.

- **Model Exfiltration**: Los atacantes roban archivos o pesos del modelo, provocando la pérdida de propiedad intelectual y permitiendo crear servicios imitadores o realizar ataques posteriores.

- **Model Deployment Tampering**: Los adversarios modifican los artefactos del modelo o la infraestructura que lo sirve, de modo que el modelo en ejecución difiere de la versión validada, pudiendo cambiar su comportamiento.

- **Denial of ML Service**: Inundar las APIs o enviar entradas "sponge" puede agotar la capacidad de cómputo o la energía y dejar el modelo fuera de servicio, imitando los ataques DoS clásicos.

- **Model Reverse Engineering**: Al recopilar grandes cantidades de pares de entrada y salida, los atacantes pueden clonar o destilar el modelo, impulsando productos imitadores y ataques adversariales personalizados.

- **Insecure Integrated Component**: Los plugins, agentes o servicios upstream vulnerables permiten a los atacantes inyectar código o escalar privilegios dentro del pipeline de IA.

- **Prompt Injection**: Crear prompts, directa o indirectamente, para introducir instrucciones que anulen la intención del sistema y hagan que el modelo ejecute comandos no deseados.

- **Model Evasion**: Las entradas cuidadosamente diseñadas hacen que el modelo clasifique incorrectamente, alucine o genere contenido no permitido, erosionando la seguridad y la confianza.

- **Sensitive Data Disclosure**: El modelo revela información privada o confidencial de sus datos de entrenamiento o del contexto del usuario, infringiendo la privacidad y las normativas.

- **Inferred Sensitive Data**: El modelo deduce atributos personales que nunca se proporcionaron, creando nuevos daños a la privacidad mediante inferencias.

- **Insecure Model Output**: Las respuestas no saneadas transmiten código dañino, desinformación o contenido inapropiado a los usuarios o a los sistemas posteriores.

- **Rogue Actions**: Los agentes integrados de forma autónoma ejecutan operaciones no deseadas en el mundo real (escritura de archivos, llamadas a APIs, compras, etc.) sin una supervisión adecuada del usuario.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) proporciona un marco completo para comprender y mitigar los riesgos asociados a los sistemas de IA. Clasifica diversas técnicas y tácticas de ataque que los adversarios pueden utilizar contra modelos de IA, así como las formas de utilizar sistemas de IA para realizar distintos ataques.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Los atacantes roban tokens de sesión activos o credenciales de API cloud e invocan LLM alojados en la cloud y de pago sin autorización. A menudo, el acceso se revende mediante reverse proxies que se sitúan delante de la cuenta de la víctima, por ejemplo, despliegues de "oai-reverse-proxy". Las consecuencias incluyen pérdidas económicas, uso indebido del modelo fuera de la política y atribución al tenant de la víctima.

TTPs:
- Recopilar tokens de máquinas de desarrolladores o navegadores infectados; robar secretos de CI/CD; comprar cookies filtradas.
- Montar un reverse proxy que reenvíe las solicitudes al proveedor legítimo, oculte la clave upstream y multiplexe a muchos clientes.
- Abusar de endpoints de modelos base directos para eludir las medidas de seguridad empresariales y los límites de velocidad.

Mitigaciones:
- Vincular los tokens a la huella del dispositivo, rangos de IP y attestation del cliente; aplicar expiraciones cortas y renovar con MFA.
- Limitar las claves al mínimo (sin acceso a herramientas y en solo lectura cuando corresponda); rotarlas ante anomalías.
- Terminar todo el tráfico en el servidor detrás de un policy gateway que aplique filtros de seguridad, cuotas por ruta y aislamiento de tenants.
- Supervisar patrones de uso inusuales (picos repentinos de gasto, regiones atípicas, cadenas UA) y revocar automáticamente las sesiones sospechosas.
- Preferir mTLS o JWTs firmados emitidos por el IdP frente a claves de API estáticas de larga duración.

## Self-hosted LLM inference hardening

Ejecutar un servidor LLM local para datos confidenciales crea una superficie de ataque diferente a la de las APIs alojadas en la cloud: los endpoints de inference/debug pueden filtrar prompts, el serving stack suele exponer un reverse proxy y los nodos de dispositivo GPU proporcionan acceso a grandes superficies `ioctl()`. Si estás evaluando o desplegando un servicio de inference on-prem, revisa al menos los siguientes puntos.

### Prompt leakage via debug and monitoring endpoints

Trata la API de inference como un **servicio sensible multiusuario**. Las rutas de debug o monitorización pueden exponer el contenido de los prompts, el estado de los slots, los metadatos del modelo o información sobre las colas internas. En `llama.cpp`, el endpoint `/slots` es especialmente sensible porque expone el estado de cada slot y solo está destinado a la inspección o gestión de slots.

- Coloca un reverse proxy delante del servidor de inference y **deniega por defecto**.
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

Si el daemon de inferencia admite escuchar en un socket UNIX, prefiera esa opción en lugar de TCP y ejecute el contenedor **sin pila de red**:
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
- `--network none` elimina la exposición TCP/IP entrante/saliente y evita los helpers en espacio de usuario que, de otro modo, necesitarían los contenedores rootless.
- Un UNIX socket permite usar permisos/ACLs POSIX en la ruta del socket como primera capa de control de acceso.
- `--userns=keep-id` y rootless Podman reducen el impacto de un breakout del contenedor porque el root del contenedor no es el root del host.
- Los mounts de modelos de solo lectura reducen la posibilidad de manipulación del modelo desde dentro del contenedor.

### Minimización de device-nodes de GPU

Para la inferencia respaldada por GPU, los archivos `/dev/nvidia*` son superficies de ataque locales de alto valor porque exponen grandes handlers `ioctl()` del driver y posibles rutas compartidas de gestión de memoria de la GPU.

- No dejes `/dev/nvidia*` con permisos de escritura para todo el mundo.
- Restringe `nvidia`, `nvidiactl` y `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, reglas de udev y ACLs para que solo el UID mapeado del contenedor pueda abrirlos.
- Haz blacklist de módulos innecesarios como `nvidia_drm`, `nvidia_modeset` y `nvidia_peermem` en hosts de inferencia headless.
- Precarga únicamente los módulos necesarios durante el arranque, en lugar de permitir que el runtime ejecute `modprobe` oportunistamente durante el inicio de la inferencia.

Ejemplo:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un punto importante de la revisión es **`/dev/nvidia-uvm`**. Aunque el workload no use explícitamente `cudaMallocManaged()`, los runtimes recientes de CUDA todavía pueden requerir `nvidia-uvm`. Debido a que este dispositivo se comparte y gestiona la memoria virtual de la GPU, trátalo como una superficie de exposición de datos entre tenants. Si el inference backend lo admite, un backend de Vulkan puede ser una alternativa interesante, ya que podría evitar exponer `nvidia-uvm` al contenedor por completo.

### Confinamiento LSM para inference workers

AppArmor/SELinux/seccomp deben utilizarse como defensa en profundidad alrededor del proceso de inferencia:

- Permite únicamente las shared libraries, las rutas de los modelos, el directorio de sockets y los nodos de dispositivos GPU que realmente sean necesarios.
- Deniega explícitamente capacidades de alto riesgo como `sys_admin`, `sys_module`, `sys_rawio` y `sys_ptrace`.
- Mantén el directorio del modelo en solo lectura y limita las rutas escribibles exclusivamente a los directorios de sockets/cache del runtime.
- Monitoriza los logs de denegaciones, ya que proporcionan telemetría de detección útil cuando el model server o un payload de post-exploitation intenta escapar de su comportamiento esperado.

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

Phantom squatting es el **equivalente de dominio/URL de slopsquatting**. En lugar de alucinar el nombre de un paquete inexistente, el LLM alucina un **dominio plausible de portal, API, webhook, facturación, SSO, descarga o soporte** para una marca real, y un atacante registra ese namespace antes de que un humano o agente lo utilice.

Esto es importante porque, en muchos flujos de trabajo asistidos por IA, la salida del modelo se trata como una **dependencia confiable**:
- Los desarrolladores pegan el endpoint sugerido en el código o en integraciones de CI/CD.
- Los agentes de IA obtienen automáticamente documentación, schemas, APKs, ZIPs o destinos de webhook.
- Los runbooks o documentos generados pueden incluir la URL falsa como si fuera autoritativa.

### Flujo de trabajo ofensivo

1. **Sondear la superficie de alucinación**: hacer preguntas específicas sobre marcas relacionadas con flujos de trabajo realistas, como portales de `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.
2. **Normalizar candidatos**: resolver las URLs generadas, convertir las respuestas NXDOMAIN al dominio registrable principal y eliminar duplicados entre familias de prompts. Los corpus de prompts deben mantenerse diversos, por ejemplo, descartando casi duplicados mediante la **similitud de Jaccard**.
3. **Priorizar las alucinaciones predecibles**:
- **Thermal Hallucination Persistence (THP)**: el mismo dominio falso aparece con distintas temperaturas, incluida una temperatura baja como `T=0.1`.
- **Consenso entre modelos**: varias familias de LLM generan el mismo dominio falso.
4. **Registrar y weaponize** el dominio principal; después alojar phishing, descargas de APK/ZIP falsos, credential harvesters, documentos maliciosos o endpoints de API que recopilen secretos/payloads de webhook. Las **alucinaciones puras a nivel de dominio** son las más fáciles de monetizar porque el atacante controla todo el namespace; las alucinaciones de subdominio/ruta todavía pueden abusarse cuando el dominio principal normalizado no está registrado.
5. **Explotar la ventana de reputación cero**: los dominios recién registrados suelen carecer de historial en blocklists, reputación de URL y telemetría madura, por lo que pueden evadir los controles hasta que las detecciones se actualicen. Los atacantes pueden ampliar esta ventana usando respuestas benignas solo para crawlers, redirect cloaking, CAPTCHA gates o staging retardado del payload.

### Por qué es peligroso para los agentes

Para una víctima humana, el dominio falso normalmente todavía requiere un clic y otra acción. En un **flujo de trabajo agéntico**, el LLM puede ser tanto el **señuelo** como el **ejecutor**: el agente recibe la URL alucinada, la obtiene, analiza la respuesta y después puede filtrar tokens, ejecutar instrucciones, descargar una dependencia o introducir datos envenenados en CI/CD sin ninguna revisión humana.

### Prompts prácticos para atacantes

Los prompts de mayor rendimiento suelen parecer tareas empresariales normales en lugar de señuelos de phishing explícitos:
- “¿Cuál es la URL del sandbox de pagos para las integraciones de `<brand>`?”
- “¿Qué endpoint de webhook debo usar para las notificaciones de build de `<brand>`?”
- “¿Dónde está el portal de beneficios para empleados / facturación / SSO de `<brand>`?”
- “Dame la descarga directa del APK de Android o del cliente de escritorio de `<brand>`.”

### Inversión defensiva

Trata esto como un problema de monitorización proactiva de dominios, no solo como un problema de prompt injection:
- Construye un **corpus de prompts de marcas** y sondea periódicamente los LLM de los que dependen tus usuarios/agentes.
- Almacena las URLs alucinadas y registra cuáles permanecen estables entre temperaturas/modelos.
- Registra la **Adversarial Exploitation Window (AEW)**: el tiempo entre la primera alucinación y el registro por parte del atacante. Una AEW positiva significa que los defensores pueden registrar previamente, hacer sinkhole o bloquear previamente el dominio antes de su weaponization.
- Monitoriza las transiciones **NXDOMAIN → registrado** de los dominios principales.
- Tras el registro, analiza el registrar, la fecha de creación, los nameservers, el privacy shielding, el contenido de la página, las capturas de pantalla, el estado de página aparcada y la similitud con los activos de la marca.
- Añade policy gates para que los agentes/desarrolladores **no confíen por defecto en dominios generados por LLM**: exige allowlists, validación de propiedad, comprobaciones CT/RDAP o aprobación humana antes del primer uso.

Esto encaja simultáneamente en varias categorías de riesgo de IA: **ataque a la cadena de suministro de IA**, **salida insegura del modelo** y **rogue actions** cuando los agentes consumen autónomamente la URL alucinada.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
