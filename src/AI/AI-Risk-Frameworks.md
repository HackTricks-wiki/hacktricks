# Riesgos de la IA

{{#include ../banners/hacktricks-training.md}}

## Diez principales vulnerabilidades de machine learning según OWASP

OWASP ha identificado las diez principales vulnerabilidades de machine learning que pueden afectar a los sistemas de IA. Estas vulnerabilidades pueden provocar diversos problemas de seguridad, como data poisoning, model inversion y adversarial attacks. Comprenderlas es fundamental para crear sistemas de IA seguros.

Para consultar una lista actualizada y detallada de las diez principales vulnerabilidades de machine learning, visita el proyecto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Un atacante introduce cambios minúsculos, a menudo invisibles, en los **datos entrantes** para que el modelo tome una decisión equivocada.\
    *Ejemplo*: Unas pequeñas manchas de pintura en una señal de stop engañan a un coche autónomo y hacen que «vea» una señal de límite de velocidad.

- **Data Poisoning Attack**: El **conjunto de entrenamiento** se contamina deliberadamente con muestras maliciosas, lo que enseña al modelo reglas dañinas.\
*Ejemplo*: Se etiquetan erróneamente binarios de malware como «benignos» en un corpus de entrenamiento de antivirus, lo que permite que malware similar pase desapercibido más adelante.

- **Model Inversion Attack**: Mediante consultas a las salidas, un atacante crea un **modelo inverso** que reconstruye características sensibles de las entradas originales.\
*Ejemplo*: Recrear la imagen de una resonancia magnética de un paciente a partir de las predicciones de un modelo de detección de cáncer.

- **Membership Inference Attack**: El adversario comprueba si un **registro específico** se usó durante el entrenamiento al detectar diferencias en los niveles de confianza.\
*Ejemplo*: Confirmar que las transacciones bancarias de una persona aparecen en los datos de entrenamiento de un modelo de detección de fraude.

- **Model Theft**: Las consultas repetidas permiten a un atacante conocer los límites de decisión y **clonar el comportamiento del modelo** (y su propiedad intelectual).\
*Ejemplo*: Recopilar suficientes pares de preguntas y respuestas de una API de ML-as-a-Service para crear un modelo local prácticamente equivalente.

- **AI Supply‑Chain Attack**: Se compromete cualquier componente (datos, bibliotecas, pesos preentrenados, CI/CD) del **pipeline de ML** para corromper los modelos posteriores.\
*Ejemplo*: Una dependencia envenenada de un hub de modelos instala un modelo de análisis de sentimiento con una puerta trasera en muchas aplicaciones.

- **Transfer Learning Attack**: Se introduce lógica maliciosa en un **modelo preentrenado** que sobrevive al fine-tuning para la tarea de la víctima.\
*Ejemplo*: Una red troncal de visión con un activador oculto sigue cambiando etiquetas después de adaptarse al procesamiento de imágenes médicas.

- **Model Skewing**: Los datos sesgados o mal etiquetados de forma sutil **desplazan las salidas del modelo** para favorecer los objetivos del atacante.\
*Ejemplo*: Inyectar correos de spam «limpios» etiquetados como correo legítimo para que un filtro antispam deje pasar correos similares en el futuro.

- **Output Integrity Attack**: El atacante **altera las predicciones del modelo durante la transmisión**, no el modelo en sí, para engañar a los sistemas posteriores.\
*Ejemplo*: Cambiar el veredicto «malicioso» de un clasificador de malware a «benigno» antes de que el sistema de cuarentena de archivos lo reciba.

- **Model Poisoning** --- Cambios directos y dirigidos en los **parámetros del modelo**, a menudo tras obtener acceso de escritura, para alterar su comportamiento.\
*Ejemplo*: Modificar los pesos de un modelo de detección de fraude en producción para que siempre apruebe las transacciones de ciertas tarjetas.


## Riesgos de Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google describe diversos riesgos asociados a los sistemas de IA:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Actores maliciosos alteran o inyectan datos de entrenamiento o ajuste para reducir la precisión, implantar puertas traseras o sesgar los resultados, lo que socava la integridad del modelo a lo largo de todo el ciclo de vida de los datos.

- **Unauthorized Training Data**: La ingestión de conjuntos de datos protegidos por derechos de autor, sensibles o no autorizados genera responsabilidades legales, éticas y de rendimiento, porque el modelo aprende de datos que no tenía permiso para usar.

- **Model Source Tampering**: La manipulación de la cadena de suministro o por parte de personal interno del código del modelo, sus dependencias o sus pesos, antes o durante el entrenamiento, puede incorporar lógica oculta que persiste incluso después del reentrenamiento.

- **Excessive Data Handling**: Los controles deficientes de retención y gobernanza de datos llevan a los sistemas a almacenar o procesar más datos personales de los necesarios, lo que aumenta la exposición y los riesgos de incumplimiento normativo.

- **Model Exfiltration**: Los atacantes roban archivos o pesos del modelo, lo que provoca la pérdida de propiedad intelectual y permite crear servicios imitadores o llevar a cabo ataques posteriores.

- **Model Deployment Tampering**: Los adversarios modifican los artefactos del modelo o la infraestructura de servicio para que el modelo en ejecución difiera de la versión verificada, lo que puede cambiar su comportamiento.

- **Denial of ML Service**: Saturar las API o enviar entradas «esponja» puede agotar los recursos de cómputo o energía y dejar el modelo fuera de servicio, de forma similar a los ataques DoS clásicos.

- **Model Reverse Engineering**: Al recopilar grandes cantidades de pares de entrada y salida, los atacantes pueden clonar o destilar el modelo, lo que facilita la creación de productos imitadores y ataques adversariales personalizados.

- **Insecure Integrated Component**: Los plugins, agentes o servicios ascendentes vulnerables permiten a los atacantes inyectar código o elevar privilegios dentro del pipeline de IA.

- **Prompt Injection**: Crear prompts, de forma directa o indirecta, para introducir instrucciones que anulan la intención del sistema y hacen que el modelo ejecute comandos no deseados.

- **Model Evasion**: Las entradas diseñadas cuidadosamente provocan que el modelo clasifique mal, genere alucinaciones o produzca contenido no permitido, lo que reduce la seguridad y la confianza.

- **Sensitive Data Disclosure**: El modelo revela información privada o confidencial de sus datos de entrenamiento o del contexto del usuario, infringiendo la privacidad y la normativa.

- **Inferred Sensitive Data**: El modelo deduce atributos personales que nunca se proporcionaron, lo que genera nuevos daños a la privacidad mediante inferencias.

- **Insecure Model Output**: Las respuestas sin sanitizar transmiten código dañino, información errónea o contenido inapropiado a los usuarios o a los sistemas posteriores.

- **Rogue Actions**: Los agentes integrados de forma autónoma ejecutan operaciones no deseadas en el mundo real (escritura de archivos, llamadas a API, compras, etc.) sin suficiente supervisión del usuario.

## Matriz MITRE AI ATLAS

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) ofrece un marco integral para comprender y mitigar los riesgos asociados a los sistemas de IA. Clasifica diversas técnicas de ataque y tácticas que los adversarios pueden usar contra los modelos de IA, así como formas de utilizar sistemas de IA para llevar a cabo distintos ataques.<sup>[[3]](#references)</sup>

## LLMJacking (robo de tokens y reventa del acceso a LLM alojados en la nube)

Los atacantes roban tokens de sesión activos o credenciales de API de la nube y utilizan LLM de pago alojados en la nube sin autorización. A menudo revenden el acceso mediante proxies inversos que canalizan las solicitudes a través de la cuenta de la víctima, por ejemplo, implementaciones de «oai-reverse-proxy». Las consecuencias incluyen pérdidas económicas, uso del modelo contrario a las políticas y atribución de la actividad al tenant de la víctima.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Recopilar tokens de equipos de desarrolladores infectados o navegadores; robar secretos de CI/CD; comprar cookies filtradas.<sup>[[5]](#references)</sup>
- Configurar un proxy inverso que reenvíe las solicitudes al proveedor legítimo, oculte la clave upstream y permita atender a muchos clientes.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abusar de los endpoints directos de los modelos base para eludir las protecciones empresariales y los límites de velocidad.<sup>[[4]](#references)</sup>

Mitigaciones:
- Vincular los tokens a la huella digital del dispositivo, los rangos de IP y la validación del cliente; imponer vencimientos breves y renovarlos con MFA.
- Limitar las claves a los permisos mínimos (sin acceso a herramientas y de solo lectura cuando corresponda); rotarlas si se detectan anomalías.
- Terminar todo el tráfico en el servidor, detrás de una pasarela de políticas que aplique filtros de seguridad, cuotas por ruta y aislamiento entre tenants.
- Supervisar patrones de uso inusuales (aumentos repentinos del gasto, regiones atípicas, cadenas UA) y revocar automáticamente las sesiones sospechosas.
- Preferir mTLS o JWT firmados emitidos por el IdP en lugar de claves de API estáticas de larga duración.

## Refuerzo de la inferencia de LLM autoalojados

Ejecutar un servidor local de LLM para procesar datos confidenciales crea una superficie de ataque distinta a la de las API alojadas en la nube: los endpoints de inferencia y depuración pueden exponer prompts, la pila de servicio suele exponer un proxy inverso y los nodos de dispositivo GPU permiten acceder a grandes superficies de `ioctl()`. Si estás evaluando o implementando un servicio de inferencia local, revisa al menos los siguientes puntos.<sup>[[8]](#references)</sup>

### Exposición de prompts a través de endpoints de depuración y supervisión

Trata la API de inferencia como un **servicio sensible multiusuario**. Las rutas de depuración o supervisión pueden exponer el contenido de los prompts, el estado de los slots, los metadatos del modelo o información de las colas internas. En `llama.cpp`, el endpoint `/slots` es especialmente sensible porque expone el estado de cada slot y está pensado únicamente para inspeccionar o gestionar slots.<sup>[[8]](#references)</sup>

Para identificar mediante fingerprinting de caja negra y probar runners de modelos expuestos y servicios de IA relacionados, consulta [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Coloca un proxy inverso delante del servidor de inferencia y **deniega el acceso de forma predeterminada**.
- Añade a la lista de permitidos solo las combinaciones exactas de método HTTP y ruta que necesiten el cliente o la interfaz de usuario.
- Desactiva los endpoints de introspección en el propio backend siempre que sea posible; por ejemplo, con `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Vincula el proxy inverso a `127.0.0.1` y expónlo mediante un transporte autenticado, como el reenvío local de puertos SSH, en lugar de publicarlo en la LAN.

Ejemplo de lista de permitidos con nginx:

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

### Contenedores sin privilegios, sin red y con sockets UNIX

Si el daemon de inferencia admite escuchar en un socket UNIX, prefiérelo a TCP y ejecuta el contenedor **sin pila de red**:<sup>[[8]](#references)</sup>

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
- `--network none` elimina la exposición TCP/IP entrante/saliente y evita los helpers en modo usuario que, de otro modo, necesitarían los contenedores rootless.
- Un socket UNIX permite usar permisos/ACLs de POSIX en la ruta del socket como primera capa de control de acceso.
- `--userns=keep-id` y Podman rootless reducen el impacto de un escape del contenedor, porque el root del contenedor no es el root del host.
- Los montajes de modelos de solo lectura reducen la posibilidad de manipular los modelos desde dentro del contenedor.

En despliegues persistentes, las mismas restricciones se pueden expresar como unidades de Podman Quadlet. Si el acceso a la GPU se delega mediante Container Device Interface, mantén la especificación del dispositivo CDI lo más acotada posible, en lugar de exponer todos los nodos de aceleradores.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimización de nodos de dispositivo de GPU

Para la inferencia con GPU, los archivos `/dev/nvidia*` son superficies de ataque locales de alto valor, ya que exponen grandes manejadores `ioctl()` del driver y posiblemente rutas compartidas de gestión de memoria de la GPU.<sup>[[8]](#references)</sup>

- No dejes `/dev/nvidia*` con permisos de escritura para todos.
- Restringe `nvidia`, `nvidiactl` y `nvidia-uvm` con `NVreg_DeviceFileUID/GID/Mode`, reglas de udev y ACLs, de modo que solo el UID del contenedor mapeado pueda abrirlos.
- Incluye en la lista negra módulos innecesarios, como `nvidia_drm`, `nvidia_modeset` y `nvidia_peermem`, en hosts de inferencia sin pantalla.
- Precarga solo los módulos necesarios durante el arranque, en lugar de permitir que el runtime ejecute `modprobe` de forma oportunista durante el inicio de la inferencia.

Ejemplo:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Un punto importante de revisión es **`/dev/nvidia-uvm`**. Aunque la carga de trabajo no use explícitamente `cudaMallocManaged()`, los runtimes recientes de CUDA pueden seguir necesitando `nvidia-uvm`. Como este dispositivo es compartido y gestiona la memoria virtual de la GPU, trátalo como una superficie de exposición de datos entre tenants. Si el backend de inferencia lo admite, un backend Vulkan puede ser una alternativa interesante, ya que podría evitar por completo exponer `nvidia-uvm` al contenedor.<sup>[[8]](#references)</sup>

### Confinamiento LSM para workers de inferencia

AppArmor/SELinux/seccomp deberían usarse como defensa en profundidad alrededor del proceso de inferencia:<sup>[[8]](#references)</sup>

- Permite únicamente las bibliotecas compartidas, las rutas de los modelos, el directorio de sockets y los nodos de dispositivo de GPU que realmente se necesiten.
- Deniega explícitamente capacidades de alto riesgo como `sys_admin`, `sys_module`, `sys_rawio` y `sys_ptrace`.
- Mantén el directorio del modelo en modo de solo lectura y limita las rutas de escritura únicamente a los directorios de sockets/caché del runtime.
- Supervisa los registros de denegaciones, ya que proporcionan telemetría útil para la detección cuando el servidor del modelo o un payload de post-exploitation intenta escapar de su comportamiento previsto.

Ejemplo de reglas de AppArmor para un worker con GPU:

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

Phantom Squatting es el **equivalente de dominio/URL de slopsquatting**. En lugar de alucinar un nombre de paquete inexistente, el LLM alucina un **dominio de portal, API, webhook, facturación, SSO, descarga o soporte** plausible para una marca real, y un atacante registra ese espacio de nombres antes de que una persona o un agente lo use.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Esto importa porque, en muchos flujos de trabajo asistidos por IA, la salida del modelo se trata como una **dependencia de confianza**:
- Los desarrolladores pegan el endpoint sugerido en código o integraciones de CI/CD.
- Los agentes de IA obtienen documentación, esquemas, APK, ZIP o destinos de webhook automáticamente.
- Los runbooks o documentos generados pueden incluir la URL falsa como si fuera oficial.

### Flujo de ataque

1. **Sondear la superficie de alucinación**: hacer preguntas específicas sobre marcas y flujos de trabajo realistas, como portales de `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizar los candidatos**: resolver las URL generadas, reducir las respuestas NXDOMAIN al dominio principal registrable y eliminar duplicados entre familias de prompts. Los corpus de prompts deben ser diversos; por ejemplo, se pueden eliminar los casi duplicados mediante la **similitud de Jaccard**.
3. **Priorizar las alucinaciones predecibles**:
   - **Persistencia de alucinación térmica (THP)**: el mismo dominio falso aparece con distintas temperaturas, incluso con temperaturas bajas como `T=0.1`.
   - **Consenso entre modelos**: varias familias de LLM generan el mismo dominio falso.
4. **Registrar y weaponize** el dominio principal, y luego alojar phishing, descargas falsas de APK/ZIP, recolectores de credenciales, documentos maliciosos o endpoints de API que recopilen secretos o cargas útiles de webhook. Las **alucinaciones puras a nivel de dominio** son las más fáciles de monetizar porque el atacante controla todo el espacio de nombres; también se pueden aprovechar alucinaciones de subdominios/rutas si el dominio principal normalizado no está registrado.
5. **Aprovechar la ventana de reputación cero**: los dominios recién registrados suelen carecer de historial en listas de bloqueo, reputación de URL y telemetría consolidada, por lo que pueden eludir los controles hasta que las detecciones se actualicen. Los atacantes pueden alargar esta ventana ofreciendo respuestas benignas solo a los rastreadores, ocultando redirecciones, usando CAPTCHA o retrasando la activación de la carga útil.

### Por qué es peligroso para los agentes

Para una víctima humana, el dominio falso suele requerir un clic y otra acción. En un **flujo de trabajo agéntico**, el LLM puede ser tanto el **señuelo** como el **ejecutor**: el agente recibe la URL alucinada, la visita, analiza la respuesta y luego puede filtrar tokens, ejecutar instrucciones, descargar una dependencia o introducir datos envenenados en CI/CD sin revisión humana.<sup>[[12]](#references)</sup>

### Prompts prácticos para atacantes

Los prompts de mayor rendimiento suelen parecer tareas empresariales normales, en lugar de señuelos de phishing explícitos:<sup>[[12]](#references)</sup>
- “¿Cuál es la URL del entorno sandbox de pagos para las integraciones de `<brand>`?”
- “¿Qué endpoint de webhook debo usar para las notificaciones de compilación de `<brand>`?”
- “¿Dónde está el portal de beneficios para empleados / facturación / SSO de `<brand>`?”
- “Dame el enlace directo para descargar el APK de Android o el cliente de escritorio de `<brand>`.”

### Inversión defensiva

Aborda esto como un problema proactivo de supervisión de dominios, no solo como un problema de inyección de prompts:<sup>[[12]](#references)</sup>
- Crea un **corpus de prompts de marcas** y prueba periódicamente los LLM de los que dependen tus usuarios/agentes.
- Almacena las URL alucinadas y registra cuáles se mantienen estables entre temperaturas/modelos.
- Registra la **Ventana de explotación adversaria (AEW)**: el tiempo entre la primera alucinación y el registro del dominio por parte del atacante. Una AEW positiva significa que los defensores pueden registrar previamente, redirigir a un sinkhole o bloquear el dominio antes de que se weaponize.
- Supervisa las transiciones de **NXDOMAIN → registrado** para los dominios principales.
- Cuando se registre un dominio, analiza el registrador, la fecha de creación, los servidores de nombres, la protección de privacidad, el contenido de la página, las capturas de pantalla, el estado de la página aparcada y la similitud con los recursos de marca.
- Añade controles de políticas para que los agentes/desarrolladores **no confíen de forma predeterminada en los dominios generados por LLM**: exige listas de permitidos, validación de propiedad, comprobaciones CT/RDAP o aprobación humana antes del primer uso.

Esto encaja en varias categorías de riesgo de IA a la vez: **ataque a la cadena de suministro de IA**, **salida insegura del modelo** y **acciones maliciosas** cuando los agentes consumen autónomamente la URL alucinada.

## References

- [1] [OWASP Top 10 de vulnerabilidades de Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Riesgos](https://saif.google/secure-ai-framework/risks)
- [3] [Matriz de amenazas MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – Los riesgos de los LLM asistentes de código: contenido dañino, uso indebido y engaño](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: credenciales de cloud robadas utilizadas en un nuevo ataque de IA](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Descripción general del esquema LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (reventa de acceso robado a LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Análisis detallado de la implementación de un servidor LLM local con privilegios bajos](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README del servidor llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlets de Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Especificación de la Container Device Interface (CDI) de CNCF](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: dominios alucinados por IA como vector de ataque a la cadena de suministro de software](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: cómo las alucinaciones de IA impulsan una nueva clase de ataques a la cadena de suministro](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
