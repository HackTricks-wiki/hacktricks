# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Učitavanje modela za RCE

Modeli mašinskog učenja obično se dele u različitim formatima, kao što su ONNX, TensorFlow, PyTorch, itd. Ovi modeli mogu biti učitani na mašine programera ili proizvodne sisteme za korišćenje. Obično modeli ne bi trebali sadržati zlonamerni kod, ali postoje slučajevi kada se model može koristiti za izvršavanje proizvoljnog koda na sistemu kao nameravana funkcija ili zbog ranjivosti u biblioteci za učitavanje modela.

U vreme pisanja ovo su neki primeri ovog tipa ranjivosti:

| **Okvir / Alat**            | **Ranjivost (CVE ako je dostupno)**                                                                                          | **RCE Vektor**                                                                                                                           | **Reference**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Neosigurana deserializacija u* `torch.load` **(CVE-2025-32434)**                                                          | Zlonameran pickle u model checkpoint-u dovodi do izvršavanja koda (zaobilazeći `weights_only` zaštitu)                                   | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + preuzimanje zlonamernog modela uzrokuje izvršavanje koda; Java deserializacija RCE u upravljačkom API-ju                         | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (nesiguran YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                  | Učitavanje modela iz YAML koristi `yaml.unsafe_load` (izvršavanje koda) <br> Učitavanje modela sa **Lambda** slojem pokreće proizvoljan Python kod | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsiranje)                                                                                        | Prilagođeni `.tflite` model izaziva prelivanje celobrojne vrednosti → oštećenje heap-a (potencijalni RCE)                               | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Učitavanje modela putem `joblib.load` izvršava pickle sa napadačevim `__reduce__` payload-om                                          | |
| **NumPy** (Python)          | **CVE-2019-6446** (nesiguran `np.load`) *sporno*                                                                            | `numpy.load` podrazumevano dozvoljava pickled objekte – zlonameran `.npy/.npz` pokreće izvršavanje koda                                 | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                  | ONNX modelova putanja spoljašnjih težina može pobjeći iz direktorijuma (čitati proizvoljne datoteke) <br> Zlonameran ONNX model tar može prepisati proizvoljne datoteke (što dovodi do RCE) | |
| ONNX Runtime (dizajnerski rizik) | *(Nema CVE)* ONNX prilagođene operacije / kontrolni tok                                                                  | Model sa prilagođenim operatorom zahteva učitavanje napadačeve nativne koda; složeni grafovi modela zloupotrebljavaju logiku za izvršavanje nepredviđenih proračuna | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (putanja prelaz)                                                                                          | Korišćenje API-ja za učitavanje modela sa `--model-control` omogućeno omogućava relativno prelaz putanje za pisanje datoteka (npr., prepisivanje `.bashrc` za RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (više heap prelivanja)                                                                           | Neispravan GGUF model fajl uzrokuje prelivanje bafera u parseru, omogućavajući proizvoljno izvršavanje koda na sistemu žrtve            | |
| **Keras (stariji formati)** | *(Nema novog CVE)* Nasleđeni Keras H5 model                                                                                  | Zlonameran HDF5 (`.h5`) model sa kodom Lambda sloja i dalje se izvršava prilikom učitavanja (Keras safe_mode ne pokriva stari format – “napad s degradacijom”) | |
| **Drugi** (opšti)           | *Dizajnerska greška* – Pickle serijalizacija                                                                                 | Mnogi ML alati (npr., formati modela zasnovani na pickle-u, Python `pickle.load`) će izvršiti proizvoljan kod ugrađen u model fajlove osim ako se ne ublaži | |

Pored toga, postoje modeli zasnovani na Python pickle-u poput onih koje koristi [PyTorch](https://github.com/pytorch/pytorch/security) koji se mogu koristiti za izvršavanje proizvoljnog koda na sistemu ako se ne učitaju sa `weights_only=True`. Dakle, svaki model zasnovan na pickle-u može biti posebno podložan ovim vrstama napada, čak i ako nisu navedeni u tabeli iznad.

{{#include ../banners/hacktricks-training.md}}
