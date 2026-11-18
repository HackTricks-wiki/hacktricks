# Riesgos de la IA

{{#include ../banners/hacktricks-training.md}}

## Las 10 principales vulnerabilidades de machine learning según OWASP

OWASP ha identificado las 10 principales vulnerabilidades de machine learning que pueden afectar a los sistemas de IA. Estas vulnerabilidades pueden provocar diversos problemas de seguridad, como envenenamiento de datos, inversión del modelo y ataques adversariales. Comprender estas vulnerabilidades es crucial para crear sistemas de IA seguros.

Para consultar una lista actualizada y detallada de las 10 principales vulnerabilidades de machine learning, visita el proyecto [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Ataque de manipulación de entradas**: Un atacante añade cambios diminutos, a menudo invisibles, a los **datos de entrada** para que el modelo tome una decisión equivocada.\
    *Ejemplo*: Unas pocas manchas de pintura en una señal de stop engañan a un coche autónomo para que «vea» una señal de límite de velocidad.

- **Ataque de envenenamiento de datos**: El **conjunto de entrenamiento** se contamina deliberadamente con muestras incorrectas, lo que enseña reglas dañinas al modelo.\
*Ejemplo*: Se etiquetan erróneamente binarios de malware como «benignos» en un corpus de entrenamiento de antivirus, lo que permite que malware similar pase desapercibido más adelante.

- **Ataque de inversión del modelo**: Al sondear las salidas, un atacante crea un **modelo inverso** que reconstruye características sensibles de las entradas originales.\
*Ejemplo*: Recrear la imagen de una resonancia magnética de un paciente a partir de las predicciones de un modelo de detección de cáncer.

- **Ataque de inferencia de pertenencia**: El adversario comprueba si se usó un **registro específico** durante el entrenamiento detectando diferencias en los niveles de confianza.\
*Ejemplo*: Confirmar que la transacción bancaria de una persona aparece en los datos de entrenamiento de un modelo de detección de fraude.

- **Robo de modelo**: Las consultas repetidas permiten a un atacante conocer los límites de decisión y **clonar el comportamiento del modelo** (y la propiedad intelectual).\
*Ejemplo*: Recopilar suficientes pares de preguntas y respuestas de una API de ML-as-a-Service para crear un modelo local casi equivalente.

- **Ataque a la cadena de suministro de IA**: Comprometer cualquier componente (datos, bibliotecas, pesos preentrenados, CI/CD) del **pipeline de ML** para corromper los modelos posteriores.\
*Ejemplo*: Una dependencia envenenada de un model hub instala un modelo de análisis de sentimientos con una puerta trasera en muchas aplicaciones.

- **Ataque de transfer learning**: Se introduce lógica maliciosa en un **modelo preentrenado** que sobrevive al fine-tuning para la tarea de la víctima.\
*Ejemplo*: Un backbone de visión con un disparador oculto sigue alterando las etiquetas después de adaptarse para la obtención de imágenes médicas.

- **Sesgo del modelo**: Los datos sutilmente sesgados o mal etiquetados **desvían las salidas del modelo** para favorecer los objetivos del atacante.\
*Ejemplo*: Inyectar correos de spam «limpios» etiquetados como correo legítimo para que un filtro de spam deje pasar mensajes similares en el futuro.

- **Ataque a la integridad de las salidas**: El atacante **altera las predicciones del modelo durante la transmisión**, no el modelo en sí, y engaña a los sistemas posteriores.\
*Ejemplo*: Cambiar el veredicto «malicioso» de un clasificador de malware a «benigno» antes de que llegue a la fase de cuarentena de archivos.

- **Envenenamiento del modelo** --- Cambios directos y dirigidos a los **parámetros del modelo**, a menudo después de obtener acceso de escritura, para alterar su comportamiento.\
*Ejemplo*: Modificar los pesos de un modelo de detección de fraude en producción para que siempre apruebe las transacciones de determinadas tarjetas.


## Riesgos de Google SAIF

[SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google describe diversos riesgos asociados a los sistemas de IA:<sup>[[2]](#references)</sup>

- **Envenenamiento de datos**: Actores maliciosos alteran o inyectan datos de entrenamiento o ajuste para reducir la precisión, implantar puertas traseras o sesgar los resultados, lo que socava la integridad del modelo durante todo el ciclo de vida de los datos. 

- **Datos de entrenamiento no autorizados**: Ingerir conjuntos de datos protegidos por derechos de autor, sensibles o cuyo uso no está permitido genera responsabilidades legales, éticas y de rendimiento, ya que el modelo aprende de datos que no tenía permiso para usar. 

- **Manipulación del código fuente del modelo**: La manipulación de código, dependencias o pesos del modelo antes o durante el entrenamiento, ya sea mediante ataques a la cadena de suministro o por parte de personas internas, puede incorporar lógica oculta que persiste incluso después de volver a entrenar el modelo. 

- **Gestión excesiva de datos**: Los controles débiles de retención y gobernanza de datos hacen que los sistemas almacenen o procesen más datos personales de los necesarios, lo que aumenta la exposición y los riesgos de incumplimiento normativo. 

- **Exfiltración del modelo**: Los atacantes roban archivos o pesos del modelo, lo que provoca la pérdida de propiedad intelectual y permite crear servicios imitadores o realizar ataques posteriores. 

- **Manipulación del despliegue del modelo**: Los adversarios modifican los artefactos del modelo o la infraestructura que lo sirve, de modo que el modelo en ejecución difiere de la versión verificada y su comportamiento puede cambiar. 

- **Denegación del servicio de ML**: Saturar las API o enviar entradas «sponge» puede agotar la capacidad de cómputo o energía y dejar el modelo fuera de servicio, de forma similar a los ataques DoS clásicos. 

- **Ingeniería inversa del modelo**: Al recopilar grandes cantidades de pares de entrada y salida, los atacantes pueden clonar o destilar el modelo, lo que facilita crear productos imitadores y ataques adversariales personalizados. 

- **Componente integrado inseguro**: Los plugins, agentes o servicios upstream vulnerables permiten que los atacantes inyecten código o eleven privilegios dentro del pipeline de IA. 

- **Prompt injection**: Crear prompts (directa o indirectamente) para introducir instrucciones que anulen la intención del sistema y hagan que el modelo ejecute comandos no deseados. 

- **Evasión del modelo**: Las entradas diseñadas cuidadosamente hacen que el modelo clasifique incorrectamente, alucine o genere contenido no permitido, lo que erosiona la seguridad y la confianza. 

- **Divulgación de datos sensibles**: El modelo revela información privada o confidencial de sus datos de entrenamiento o del contexto del usuario, infringiendo la privacidad y la normativa. 

- **Inferencia de datos sensibles**: El modelo deduce atributos personales que nunca se proporcionaron, lo que genera nuevos daños a la privacidad mediante inferencias. 

- **Salida insegura del modelo**: Las respuestas sin sanear transmiten código dañino, información errónea o contenido inapropiado a los usuarios o a los sistemas posteriores. 

- **Acciones no autorizadas**: Los agentes integrados de forma autónoma ejecutan operaciones no deseadas en el mundo real (escritura de archivos, llamadas a API, compras, etc.) sin una supervisión adecuada del usuario.

## Matriz MITRE AI ATLAS

La [matriz MITRE AI ATLAS](https://atlas.mitre.org/matrices/ATLAS) proporciona un marco integral para comprender y mitigar los riesgos asociados a los sistemas de IA. Clasifica distintas técnicas y tácticas de ataque que los adversarios pueden usar contra los modelos de IA, así como las formas de utilizar sistemas de IA para realizar diferentes ataques.<sup>[[3]](#references)</sup>

## LLMJacking (robo de tokens y reventa de acceso a LLM alojados en la nube)

Los atacantes roban tokens de sesión activos o credenciales de API de cloud e invocan LLM alojados en la nube y de pago sin autorización. A menudo revenden el acceso mediante reverse proxies que se interponen ante la cuenta de la víctima, por ejemplo, implementaciones de «oai-reverse-proxy». Entre las consecuencias se encuentran pérdidas económicas, uso del modelo fuera de las políticas y atribución de la actividad al tenant de la víctima.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Recopilar tokens de equipos de desarrolladores o navegadores infectados; robar secretos de CI/CD; comprar cookies filtradas.<sup>[[5]](#references)</sup>
- Poner en marcha un reverse proxy que reenvíe solicitudes al proveedor legítimo, oculte la clave upstream y permita atender a muchos clientes.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abusar de los endpoints directos del modelo base para eludir las medidas de seguridad empresariales y los límites de frecuencia.<sup>[[4]](#references)</sup>

**Reutilización de la clave de API dentro del host:** Tras comprometer un host, un implante puede enviar solicitudes a la API del modelo directamente desde el host de la víctima y retransmitir las respuestas a través de C2, sin exportar una clave de API de cloud ni iniciar una CLI de IA local. En el controlador observado, una clave proporcionada por C2 tiene prioridad; solo si no está presente, el implante lee `OPENAI_API_KEY` del entorno de su propio proceso. Por tanto, usar la cuenta de la víctima requiere una clave válida visible para ese proceso y acceso a la API del modelo. El prompt del operador se envía a la API de Chat Completions, mientras que la salida del modelo y el uso de tokens se reciben a través de C2. Esto puede consumir el acceso de pago de la víctima al modelo sin ejecutar las herramientas de IA del desarrollador, a diferencia del abuso de la configuración de [CLI de IA local o MCP](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md).<sup>[[14]](#references)</sup>

Mitigaciones:
- Vincular los tokens a la huella digital del dispositivo, rangos de IP y atestación del cliente; aplicar vencimientos cortos y renovar con MFA.
- Limitar el alcance de las claves al mínimo (sin acceso a herramientas y solo lectura cuando corresponda); rotarlas si se detectan anomalías.
- Terminar todo el tráfico en el servidor, detrás de un gateway de políticas que aplique filtros de seguridad, cuotas por ruta y aislamiento entre tenants.
- Supervisar patrones de uso inusuales (aumentos repentinos del gasto, regiones atípicas, cadenas UA) y revocar automáticamente las sesiones sospechosas.
- Preferir mTLS o JWT firmados emitidos por el IdP en lugar de claves de API estáticas de larga duración.

## Refuerzo de la inferencia de LLM autoalojados

Ejecutar un servidor de LLM local para datos confidenciales crea una superficie de ataque distinta a la de las API alojadas en la nube: los endpoints de inferencia y depuración pueden filtrar prompts, la pila que sirve el modelo suele exponer un reverse proxy y los nodos de dispositivo GPU dan acceso a grandes superficies de `ioctl()`. Si estás evaluando o desplegando un servicio de inferencia local, revisa al menos los siguientes puntos.<sup>[[8]](#references)</sup>

### Filtración de prompts a través de endpoints de depuración y monitorización

Trata la API de inferencia como un **servicio sensible multiusuario**. Las rutas de depuración o monitorización pueden exponer el contenido de los prompts, el estado de los slots, los metadatos del modelo o información de las colas internas. En `llama.cpp`, el endpoint `/slots` es especialmente sensible porque expone el estado de cada slot y está pensado únicamente para inspeccionar o gestionar slots.<sup>[[8]](#references)</sup>

Para la toma de huellas y las pruebas de caja negra de los ejecutores de modelos expuestos y los servicios de IA relacionados, consulta [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Coloca un reverse proxy delante del servidor de inferencia y **deniega por defecto**.
- Añade a la lista de permitidos únicamente las combinaciones exactas de método HTTP y ruta que necesite el cliente o la interfaz de usuario.
- Desactiva los endpoints de introspección en el propio backend siempre que sea posible; por ejemplo, con `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Vincula el reverse proxy a `127.0.0.1` y expónlo mediante un transporte autenticado, como el reenvío de puertos locales de SSH, en lugar de publicarlo en la LAN.

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
- `--network none` elimina la exposición TCP/IP entrante/saliente y evita los helpers en modo de usuario que, de otro modo, necesitarían los contenedores rootless.
- Un socket UNIX permite usar permisos/ACL de POSIX en la ruta del socket como primera capa de control de acceso.
- `--userns=keep-id` y Podman rootless reducen el impacto de una salida del contenedor, porque el root del contenedor no es el root del host.
- Los montajes de modelos de solo lectura reducen la posibilidad de manipular modelos desde dentro del contenedor.

En implementaciones persistentes, se pueden expresar las mismas restricciones mediante unidades Podman Quadlet. Si el acceso a la GPU se delega mediante Container Device Interface, limita al máximo la especificación del dispositivo CDI en lugar de exponer todos los nodos de aceleradores.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimización de nodos de dispositivo de GPU

Para la inferencia acelerada por GPU, los archivos `/dev/nvidia*` son superficies de ataque locales de alto valor porque exponen grandes controladores `ioctl()` y, potencialmente, rutas compartidas de gestión de memoria de GPU.<sup>[[8]](#references)</sup>

- No dejes `/dev/nvidia*` con permisos de escritura para todos.
- Restringe `nvidia`, `nvidiactl` y `nvidia-uvm` mediante `NVreg_DeviceFileUID/GID/Mode`, reglas de udev y ACL para que solo el UID asignado al contenedor pueda abrirlos.
- Incluye en la lista negra módulos innecesarios como `nvidia_drm`, `nvidia_modeset` y `nvidia_peermem` en hosts de inferencia sin interfaz gráfica.
- Precarga solo los módulos necesarios al arrancar, en lugar de permitir que el runtime ejecute `modprobe` de forma oportunista durante el inicio de la inferencia.

Ejemplo:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Un punto importante de revisión es **`/dev/nvidia-uvm`**. Aunque la carga de trabajo no use explícitamente `cudaMallocManaged()`, los runtimes recientes de CUDA podrían seguir requiriendo `nvidia-uvm`. Como este dispositivo es compartido y gestiona la memoria virtual de la GPU, trátalo como una superficie de exposición de datos entre tenants. Si el backend de inferencia lo admite, un backend de Vulkan puede ser una alternativa interesante, ya que podría evitar exponer `nvidia-uvm` al contenedor.<sup>[[8]](#references)</sup>

### Confinamiento con LSM para workers de inferencia

AppArmor/SELinux/seccomp deberían usarse como defensa en profundidad alrededor del proceso de inferencia:<sup>[[8]](#references)</sup>

- Permite solo las bibliotecas compartidas, las rutas de modelos, el directorio de sockets y los nodos de dispositivo de GPU que sean realmente necesarios.
- Deniega explícitamente capacidades de alto riesgo como `sys_admin`, `sys_module`, `sys_rawio` y `sys_ptrace`.
- Mantén el directorio de modelos en modo de solo lectura y limita las rutas de escritura únicamente a los directorios de sockets/caché del runtime.
- Supervisa los registros de denegaciones, ya que proporcionan telemetría útil para la detección cuando el servidor de modelos o un payload de post-exploitation intenta escapar de su comportamiento esperado.

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

Phantom squatting es el **equivalente de dominio/URL de slopsquatting**. En lugar de alucinar el nombre de un paquete inexistente, el LLM alucina un **dominio plausible de portal, API, webhook, facturación, SSO, descargas o soporte** para una marca real, y un atacante registra ese espacio de nombres antes de que una persona o un agente lo use.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Esto importa porque en muchos flujos de trabajo asistidos por IA, el resultado del modelo se trata como una **dependencia de confianza**:
- Los desarrolladores pegan el endpoint sugerido en el código o en integraciones de CI/CD.
- Los agentes de IA obtienen automáticamente documentación, esquemas, APK, ZIP o destinos de webhook.
- Los runbooks o documentos generados pueden incluir la URL falsa como si fuera autorizada.

### Flujo de ataque

1. **Sondear la superficie de alucinación**: hacer preguntas específicas sobre la marca en relación con flujos de trabajo realistas, como portales de `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` o `mobile app`.<sup>[[12]](#references)</sup>
2. **Normalizar candidatos**: resolver las URL generadas, reducir las respuestas NXDOMAIN al dominio principal registrable y eliminar duplicados entre familias de prompts. Los corpus de prompts deben ser diversos; por ejemplo, se pueden eliminar casi duplicados mediante la **similitud de Jaccard**.
3. **Dar prioridad a las alucinaciones predecibles**:
   - **Persistencia térmica de la alucinación (THP)**: el mismo dominio falso aparece con distintas temperaturas, incluso con temperaturas bajas como `T=0.1`.
   - **Consenso entre modelos**: varias familias de LLM generan el mismo dominio falso.
4. **Registrar y weaponize** el dominio principal, y luego alojar phishing, descargas falsas de APK/ZIP, recolectores de credenciales, documentos maliciosos o endpoints de API que recopilen secretos o cargas de webhook. Las **alucinaciones puras a nivel de dominio** son las más fáciles de monetizar porque el atacante controla todo el espacio de nombres; las alucinaciones de subdominios/rutas también pueden explotarse si el dominio principal normalizado no está registrado.
5. **Aprovechar la ventana sin reputación**: los dominios recién registrados suelen carecer de historial en listas de bloqueo, reputación de URL y telemetría madura, por lo que pueden eludir los controles hasta que las detecciones se pongan al día. Los atacantes pueden prolongar esta ventana con respuestas benignas solo para rastreadores, encubrimiento mediante redirecciones, pruebas CAPTCHA o preparación diferida de cargas maliciosas.

### Por qué es peligroso para los agentes

Para una víctima humana, el dominio falso suele requerir que haga clic y realice otra acción. En un **flujo de trabajo agéntico**, el LLM puede ser tanto el **anzuelo** como el **ejecutor**: el agente recibe la URL alucinada, la obtiene, analiza la respuesta y luego puede filtrar tokens, ejecutar instrucciones, descargar una dependencia o insertar datos envenenados en CI/CD sin revisión humana.<sup>[[12]](#references)</sup>

### Prompts prácticos para atacantes

Los prompts de alto rendimiento suelen parecer tareas empresariales normales, en vez de cebos de phishing explícitos:<sup>[[12]](#references)</sup>
- “¿Cuál es la URL del sandbox de pagos para las integraciones de `<brand>`?”
- “¿Qué endpoint de webhook debo usar para las notificaciones de compilación de `<brand>`?”
- “¿Dónde está el portal de beneficios para empleados / facturación / SSO de `<brand>`?”
- “Dame el enlace directo para descargar el APK de Android o el cliente de escritorio de `<brand>`.”

### Inversión defensiva

Trata esto como un problema de monitorización proactiva de dominios, no solo como un problema de prompt injection:<sup>[[12]](#references)</sup>
- Crea un **corpus de prompts sobre marcas** y sondea periódicamente los LLM de los que dependen tus usuarios/agentes.
- Guarda las URL alucinadas y registra cuáles se mantienen estables entre temperaturas/modelos.
- Registra la **Ventana de Explotación Adversaria (AEW)**: el tiempo entre la primera alucinación y el registro por parte del atacante. Una AEW positiva significa que los defensores pueden registrar previamente, llevar a un sinkhole o bloquear de antemano antes de que se weaponize.
- Monitoriza las transiciones de **NXDOMAIN → registrado** para los dominios principales.
- Cuando se registre un dominio, analiza el registrador, la fecha de creación, los servidores de nombres, la protección de privacidad, el contenido de la página, las capturas de pantalla, el estado de página aparcada y la similitud con los activos de la marca.
- Añade controles de políticas para que los agentes/desarrolladores **no confíen por defecto en los dominios generados por LLM**: exige listas de permitidos, validación de propiedad, comprobaciones CT/RDAP o aprobación humana antes del primer uso.

Esto encaja en varias categorías de riesgo de IA a la vez: **ataque a la cadena de suministro de IA**, **salida insegura del modelo** y **acciones descontroladas** cuando los agentes consumen de forma autónoma la URL alucinada.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Diez principales vulnerabilidades de machine learning de OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework): riesgos](https://saif.google/secure-ai-framework/risks)
- [3] [Matriz de amenazas MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42: los riesgos de los LLM asistentes de código: contenido dañino, uso indebido y engaño](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig: LLMjacking: credenciales de cloud robadas utilizadas en un nuevo ataque de IA](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Descripción general del esquema LLMJacking: The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (reventa de acceso robado a LLM)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Análisis detallado de la implementación de un servidor LLM local con privilegios limitados](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README del servidor llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlets de Podman: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Especificación de Container Device Interface (CDI) de CNCF](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42: Phantom Squatting: dominios alucinados por IA como vector de la cadena de suministro de software](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket: Slopsquatting: cómo las alucinaciones de IA alimentan una nueva clase de ataques a la cadena de suministro](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos: NIK C2: el nuevo framework de comando y control habilitado por IA](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
