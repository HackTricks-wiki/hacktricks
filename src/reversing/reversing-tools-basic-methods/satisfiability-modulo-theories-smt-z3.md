# Πολύ βασικά, αυτό το εργαλείο θα μας βοηθήσει να βρούμε τιμές για μεταβλητές που πρέπει να ικανοποιούν κάποιες συνθήκες, καθώς ο υπολογισμός τους με το χέρι θα ήταν πολύ ενοχλητικός. Επομένως, μπορείτε να υποδείξετε στο Z3 τις συνθήκες που πρέπει να ικανοποιούν οι μεταβλητές και αυτό θα βρει κάποιες τιμές (αν είναι δυνατό).

{{#include ../../banners/hacktricks-training.md}}

# Βασικές λειτουργίες

## Boolean/And/Or/Not
```python
# pip3 install z3-solver
from z3 import *

s = Solver() # The solver will be given the conditions

x = Bool("x") # Declare the symbols x, y and z
y = Bool("y")
z = Bool("z")

# (x or y or !z) and y
s.add(And(Or(x, y, Not(z)), y))
s.check() # If response is "sat" then the model is satisfiable, if "unsat" something is wrong
print(s.model()) # Print valid values to satisfy the model
```
## Ints/Simplify/Reals
```python
from z3 import *

x = Int('x')
y = Int('y')

# Simplify a "complex" equation
print(simplify(And(x + 1 >= 3, x**2 + x**2 + y**2 + 2 >= 5)))
# And(x >= 2, 2*x**2 + y**2 >= 3)

# Note that Z3 is capable of treating irrational numbers
# (an irrational algebraic number is a root of a polynomial with integer coefficients).
# Internally, Z3 represents all these numbers precisely.
r1 = Real('r1')
r2 = Real('r2')

# Solve the equation
print(solve(r1**2 + r2**2 == 3, r1**3 == 2))

# Solve the equation with 30 decimals
set_option(precision=30)
print(solve(r1**2 + r2**2 == 3, r1**3 == 2))
```
## Μοντέλο Εκτύπωσης
```python
from z3 import *

x, y, z = Reals('x y z')
s = Solver()
s.add(x > 1, y > 1, x + y > 3, z - x < 10)
s.check()

m = s.model()
print("x = %s" % m[x])
for d in m.decls():
print("%s = %s" % (d.name(), m[d]))
```
# Αριθμητική Μηχανής

Οι σύγχρονοι CPU και οι mainstream γλώσσες προγραμματισμού χρησιμοποιούν αριθμητική πάνω σε bit-vectors σταθερού μεγέθους. Η αριθμητική μηχανής είναι διαθέσιμη στο Z3Py ως Bit-Vectors.
```python
from z3 import *

x = BitVec('x', 16) # Bit vector variable "x" of length 16 bits
y = BitVec('y', 16)
e = BitVecVal(10, 16) # Bit vector with value 10 of length 16 bits
a = BitVecVal(-1, 16)
b = BitVecVal(65535, 16)
print(simplify(a == b)) # This is True!

a = BitVecVal(-1, 32)
b = BitVecVal(65535, 32)
print(simplify(a == b)) # This is False
```
## Προσημασμένοι/Μη προσημασμένοι Αριθμοί

Το Z3 παρέχει ειδικές signed εκδόσεις των αριθμητικών πράξεων, στις οποίες έχει σημασία αν το bit-vector αντιμετωπίζεται ως signed ή unsigned. Στο Z3Py, οι τελεστές `<`, `<=`, `>`, `>=`, `/`, `%` και `>>` αντιστοιχούν στις signed εκδόσεις. Οι αντίστοιχοι unsigned τελεστές είναι οι `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` και `LShR`.<sup>[[1]](#references)</sup>
```python
from z3 import *

# Create two bit-vectors of size 32
x, y = BitVecs('x y', 32)
solve(x + y == 2, x > 0, y > 0)

# Bit-wise operators
# & bit-wise and
# | bit-wise or
# ~ bit-wise not
solve(x & y == ~y)
solve(x < 0)

# Using unsigned version of <
solve(ULT(x, 0))
```
## Συναρτήσεις

Οι interpreted συναρτήσεις, όπως οι αριθμητικές, έχουν μια σταθερή τυπική ερμηνεία. Οι uninterpreted συναρτήσεις και σταθερές είναι εξαιρετικά ευέλικτες· επιτρέπουν οποιαδήποτε ερμηνεία που είναι συνεπής με τους περιορισμούς της συνάρτησης ή της σταθεράς.<sup>[[1]](#references)</sup>

Παράδειγμα: η εφαρμογή της `f` δύο φορές στο `x` έχει ξανά ως αποτέλεσμα το `x`, αλλά η εφαρμογή της `f` μία φορά στο `x` διαφέρει από το `x`.
```python
from z3 import *

x = Int('x')
y = Int('y')
f = Function('f', IntSort(), IntSort())
s = Solver()
s.add(f(f(x)) == x, f(x) == y, x != y)
s.check()
m = s.model()
print("f(f(x)) =", m.evaluate(f(f(x))))
print("f(x)    =", m.evaluate(f(x)))

print(m.evaluate(f(2)))
s.add(f(x) == 4) # Find the value that generates 4 as response
s.check()
print(s.model())
```
# Μοτίβα προσανατολισμένα στο Reversing

Αν χρειάζεστε πλήρες symbolic execution σε ένα binary αντί να κάνετε χειροκίνητο lifting μόνο σε μερικούς ελέγχους, δείτε το [Angr - Examples](angr/angr-examples.md). Στην πράξη, μια πολύ συνηθισμένη ροή εργασίας είναι να ανακτήσετε τα σχετικά predicates από τον decompiler/assembly και να αναδημιουργήσετε στο Z3 μόνο τους ενδιαφέροντες αριθμητικούς ή memory constraints.

## Μοντελοποιήστε πρώτα τα δεδομένα που ελέγχει ο χρήστης ως bytes

Για reversing, συνήθως είναι καλύτερο να ξεκινήσετε με `BitVec(..., 8)` για κάθε input byte και στη συνέχεια να αναδημιουργήσετε τα words ακριβώς όπως το κάνει ο στόχος. Αυτό διατηρεί το wrap-around, τα signedness bugs, τα shifts, τα rotates και τα ζητήματα byte-order.<sup>[[2]](#references)</sup>
```python
from z3 import *

b0, b1, b2, b3 = BitVecs('b0 b1 b2 b3', 8)
dword = Concat(b3, b2, b1, b0) # bytes -> little-endian uint32

s = Solver()
s.add(b0 == ord('A'), b1 == ord('B'), b2 == ord('C'), b3 == ord('D'))
s.add(Extract(15, 0, dword) == 0x4241)
s.add(RotateRight(dword, 8) == 0x41444342)

print(s.check())
print(hex(s.model().eval(dword).as_long()))
```
Χρήσιμα helpers κατά τη μετάφραση κώδικα assembly ή decompiler:

- `Concat`: ανακατασκευή τιμών 16/32/64-bit από bytes
- `Extract`: σύγκριση των high/low words ή προσομοίωση masks/shifts
- `ZeroExt` / `SignExt`: σωστή μοντελοποίηση σφαλμάτων zero/sign extension
- `LShR` / `RotateLeft` / `RotateRight`: συνηθισμένα σε crackmes, hashes και obfuscators

## Μοντελοποιήστε πίνακες μνήμης/registers με arrays

Όταν ένας έλεγχος εξαρτάται από το `buf[i]`, lookup tables ή emulated memory, το `Array` μπορεί να είναι πιο καθαρό από τη δημιουργία δεκάδων ξεχωριστών μεταβλητών.<sup>[[3]](#references)</sup>
```python
from z3 import *

mem = Array('mem', BitVecSort(32), BitVecSort(8))
mem = Store(mem, BitVecVal(0x1000, 32), BitVecVal(0x41, 8))
mem = Store(mem, BitVecVal(0x1001, 32), BitVecVal(0x42, 8))

word = Concat(
Select(mem, BitVecVal(0x1001, 32)),
Select(mem, BitVecVal(0x1000, 32))
)

s = Solver()
s.add(word == 0x4241)
print(s.check())
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν το binary αντιγράφει τιμές σε διαφορετικές θέσεις της μνήμης πριν από την επικύρωσή τους ή όταν θέλετε να μοντελοποιήσετε την επίδραση μερικών λειτουργιών `mov`/`xor`/`add` χωρίς να εκτελέσετε ολόκληρο το πρόγραμμα.

## Το incremental solving είναι εξαιρετικό για τη διαλογή διακλαδώσεων

Όταν έχετε ήδη εξαγάγει τους βασικούς περιορισμούς, χρησιμοποιήστε `push()` / `pop()` (ή assumptions) για να δοκιμάσετε εναλλακτικές διακλαδώσεις χωρίς να δημιουργείτε ξανά τον solver κάθε φορά:<sup>[[3]](#references)</sup>
```python
from z3 import *

x = BitVec('x', 32)
s = Solver()
s.add(x & 0xff == 0x41)

s.push()
s.add(x > 0x1000)
print("branch 1:", s.check())
s.pop()

s.push()
s.add(x < 0x100)
print("branch 2:", s.check())
s.pop()
```
Αυτό είναι χρήσιμο όταν επαναλαμβάνετε path conditions που ανακτήθηκαν από έναν decompiler ή όταν θέλετε να εντοπίσετε γρήγορα ποια σύγκριση κάνει το model `unsat`.

## Βελτιστοποίηση για καλύτερα payloads

Μόλις ένα model γίνει satisfiable, το `Optimize()` μπορεί να σας βοηθήσει να λάβετε μια πιο αξιοποιήσιμη λύση: για παράδειγμα, να προτιμά printable bytes, να ελαχιστοποιεί ένα στοιχείο checksum ή να μεγιστοποιεί κάποια δομή που κάνει τον ανακτημένο κωδικό πρόσβασης ευκολότερο στην πληκτρολόγηση ή την αντιγραφή.<sup>[[3]](#references)</sup>
```python
from z3 import *

key = [BitVec(f'k{i}', 8) for i in range(6)]
o = Optimize()
for c in key:
o.add(c != 0)
o.add_soft(And(c >= 0x20, c <= 0x7e))

print(o.check())
print(bytes(o.model()[c].as_long() for c in key))
```
## Strings/sequences για serials με έντονη μορφοποίηση

Αν ο στόχος ελέγχει κυρίως prefixes, suffixes, substrings ή regex-like δομή, οι constraints `String`/`Seq` μπορεί να είναι ευκολότερες από bit-vectors byte-by-byte:<sup>[[3]](#references)</sup>
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
Ωστόσο, μόλις το binary αρχίσει να εκτελεί αριθμητικές πράξεις, περιστροφές, checksums ή casts σε χαρακτήρες, συνήθως είναι προτιμότερο να επιστρέψετε σε 8-bit bit-vectors.

# Παραδείγματα

## Επίλυση Sudoku
```python
# 9x9 matrix of integer variables
X = [[Int("x_%s_%s" % (i+1, j+1)) for j in range(9)]
for i in range(9)]

# each cell contains a value in {1, ..., 9}
cells_c = [And(1 <= X[i][j], X[i][j] <= 9)
for i in range(9) for j in range(9)]

# each row contains a digit at most once
rows_c = [Distinct(X[i]) for i in range(9)]

# each column contains a digit at most once
cols_c = [Distinct([X[i][j] for i in range(9)])
for j in range(9)]

# each 3x3 square contains a digit at most once
sq_c = [Distinct([X[3*i0 + i][3*j0 + j]
for i in range(3) for j in range(3)])
for i0 in range(3) for j0 in range(3)]

sudoku_c = cells_c + rows_c + cols_c + sq_c

# sudoku instance, we use '0' for empty cells
instance = ((0,0,0,0,9,4,0,3,0),
(0,0,0,5,1,0,0,0,7),
(0,8,9,0,0,0,0,4,0),
(0,0,0,0,0,0,2,0,8),
(0,6,0,2,0,1,0,5,0),
(1,0,2,0,0,0,0,0,0),
(0,7,0,0,0,0,5,2,0),
(9,0,0,0,6,5,0,0,0),
(0,4,0,9,7,0,0,0,0))

instance_c = [If(instance[i][j] == 0, True, X[i][j] == instance[i][j])
for i in range(9) for j in range(9)]

s = Solver()
s.add(sudoku_c + instance_c)
if s.check() == sat:
m = s.model()
r = [[m.evaluate(X[i][j]) for j in range(9)]
for i in range(9)]
print_matrix(r)
else:
print("failed to solve")
```
## Αναφορές

- [1] [Οδηγός Z3Py με Παραδείγματα (ericpony z3py-tutorial)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Οδηγός Z3 - Θεωρία Bit-Vectors (Microsoft z3guide)](https://microsoft.github.io/z3guide/)
- [3] [Προγραμματισμός του Z3 (Nikolaj Bjørner, Leonardo de Moura, Lev Nachmanson, Christoph Wintersteiger)](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
