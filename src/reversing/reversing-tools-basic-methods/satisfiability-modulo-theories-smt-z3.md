# Ικανοποιησιμότητα Modulo Θεωριών (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

Σε πολύ βασικό επίπεδο, αυτό το εργαλείο θα μας βοηθήσει να βρούμε τιμές για μεταβλητές που πρέπει να ικανοποιούν κάποιες συνθήκες — και ο υπολογισμός τους στο χέρι θα ήταν εξαιρετικά ενοχλητικός. Συνεπώς, μπορείτε να δηλώσετε στο Z3 τις συνθήκες που πρέπει να ικανοποιούν οι μεταβλητές και αυτό θα βρει κάποιες τιμές (εφόσον είναι δυνατές).

**Ορισμένα κείμενα και παραδείγματα έχουν εξαχθεί από [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## Βασικές Λειτουργίες

### Booleans/And/Or/Not
```python
#pip3 install z3-solver
from z3 import *
s = Solver() #The solver will be given the conditions

x = Bool("x") #Declare the symbos x, y and z
y = Bool("y")
z = Bool("z")

# (x or y or !z) and y
s.add(And(Or(x,y,Not(z)),y))
s.check() #If response is "sat" then the model is satifable, if "unsat" something is wrong
print(s.model()) #Print valid values to satisfy the model
```
### Ints/Simplify/Reals
```python
from z3 import *

x = Int('x')
y = Int('y')
#Simplify a "complex" ecuation
print(simplify(And(x + 1 >= 3, x**2 + x**2 + y**2 + 2 >= 5)))
#And(x >= 2, 2*x**2 + y**2 >= 3)

#Note that Z3 is capable to treat irrational numbers (An irrational algebraic number is a root of a polynomial with integer coefficients. Internally, Z3 represents all these numbers precisely.)
#so you can get the decimals you need from the solution
r1 = Real('r1')
r2 = Real('r2')
#Solve the ecuation
print(solve(r1**2 + r2**2 == 3, r1**3 == 2))
#Solve the ecuation with 30 decimals
set_option(precision=30)
print(solve(r1**2 + r2**2 == 3, r1**3 == 2))
```
### Εκτύπωση Μοντέλου
```python
from z3 import *

x, y, z = Reals('x y z')
s = Solver()
s.add(x > 1, y > 1, x + y > 3, z - x < 10)
s.check()

m = s.model()
print ("x = %s" % m[x])
for d in m.decls():
print("%s = %s" % (d.name(), m[d]))
```
## Αριθμητική της μηχανής

Οι σύγχρονοι επεξεργαστές CPU και οι ευρέως διαδεδομένες γλώσσες προγραμματισμού χρησιμοποιούν αριθμητική πάνω σε **σταθερού μεγέθους bit-vectors**. Η αριθμητική της μηχανής είναι διαθέσιμη στο Z3Py ως **Bit-Vectors**.
```python
from z3 import *

x = BitVec('x', 16) #Bit vector variable "x" of length 16 bit
y = BitVec('y', 16)

e = BitVecVal(10, 16) #Bit vector with value 10 of length 16bits
a = BitVecVal(-1, 16)
b = BitVecVal(65535, 16)
print(simplify(a == b)) #This is True!
a = BitVecVal(-1, 32)
b = BitVecVal(65535, 32)
print(simplify(a == b)) #This is False
```
### Αριθμοί με πρόσημο/χωρίς πρόσημο

Το Z3 παρέχει ειδικές εκδόσεις αριθμητικών πράξεων όπου έχει σημασία αν το **bit-vector αντιμετωπίζεται ως με πρόσημο ή χωρίς πρόσημο**. Στο Z3Py, οι τελεστές **<, <=, >, >=, /, % και >>** αντιστοιχούν στις εκδόσεις **με πρόσημο**. Οι αντίστοιχοι τελεστές **χωρίς πρόσημο** είναι **ULT, ULE, UGT, UGE, UDiv, URem και LShR.**
```python
from z3 import *

# Create to bit-vectors of size 32
x, y = BitVecs('x y', 32)
solve(x + y == 2, x > 0, y > 0)

# Bit-wise operators
# & bit-wise and
# | bit-wise or
# ~ bit-wise not
solve(x & y == ~y)
solve(x < 0)

# using unsigned version of <
solve(ULT(x, 0))
```
### Bit-vector helpers που συχνά χρειάζονται στο reversing

Όταν κάνετε **lifting checks from assembly or decompiler output**, συνήθως είναι καλύτερο να μοντελοποιείτε κάθε input byte ως `BitVec(..., 8)` και στη συνέχεια να επανασυνθέτετε τις λέξεις ακριβώς όπως το κάνει ο κώδικας-στόχος. Αυτό αποφεύγει σφάλματα που προκαλούνται από τη μίξη μαθηματικών ακεραίων με αριθμητική μηχανής.
```python
from z3 import *

b0, b1, b2, b3 = BitVecs('b0 b1 b2 b3', 8)
eax = Concat(b3, b2, b1, b0)        # little-endian bytes -> 32-bit register value
low_byte = Extract(7, 0, eax)        # AL
high_word = Extract(31, 16, eax)     # upper 16 bits
signed_b0 = SignExt(24, b0)          # movsx eax, byte ptr [...]
unsigned_b0 = ZeroExt(24, b0)        # movzx eax, byte ptr [...]
rot = RotateLeft(eax, 13)            # rol eax, 13
logical = LShR(eax, 3)               # shr eax, 3
arith = eax >> 3                     # sar eax, 3 (signed shift)
```
Κάποιες κοινές παγίδες κατά τη μετάφραση κώδικα σε περιορισμούς:

- `>>` είναι μια **arithmetic** δεξιά μετατόπιση για bit-vectors. Χρησιμοποιήστε `LShR` για την λογική εντολή `shr`.
- Χρησιμοποιήστε `UDiv`, `URem`, `ULT`, `ULE`, `UGT` και `UGE` όταν η αρχική σύγκριση/διαίρεση ήταν **unsigned**.
- Κρατήστε ρητό το πλάτος. Αν το binary περικόπτει σε 8 ή 16 bits, προσθέστε `Extract` ή επανασυνθέστε την τιμή με `Concat` αντί να προωθείτε σιωπηρά τα πάντα σε Python integers.

### Συναρτήσεις

**Ερμηνευμένες συναρτήσεις** όπως οι αριθμητικές όπου η **function +** έχει μια **σταθερή τυπική ερμηνεία** (προσθέτει δύο αριθμούς). **Μη-ερμηνευμένες συναρτήσεις** και σταθερές είναι **απολύτως ευέλικτες**· επιτρέπουν **οποιαδήποτε ερμηνεία** που είναι **συμβατή** με τους **περιορισμούς** πάνω στη συνάρτηση ή τη σταθερά.

Παράδειγμα: f εφαρμοσμένη δύο φορές στο x επιστρέφει ξανά το x, αλλά f εφαρμοσμένη μία φορά στο x είναι διαφορετική από το x.
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
s.add(f(x) == 4) #Find the value that generates 4 as response
s.check()
print(m.model())
```
## Παραδείγματα

### Επίλυση Sudoku
```python
# 9x9 matrix of integer variables
X = [ [ Int("x_%s_%s" % (i+1, j+1)) for j in range(9) ]
for i in range(9) ]

# each cell contains a value in {1, ..., 9}
cells_c  = [ And(1 <= X[i][j], X[i][j] <= 9)
for i in range(9) for j in range(9) ]

# each row contains a digit at most once
rows_c   = [ Distinct(X[i]) for i in range(9) ]

# each column contains a digit at most once
cols_c   = [ Distinct([ X[i][j] for i in range(9) ])
for j in range(9) ]

# each 3x3 square contains a digit at most once
sq_c     = [ Distinct([ X[3*i0 + i][3*j0 + j]
for i in range(3) for j in range(3) ])
for i0 in range(3) for j0 in range(3) ]

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

instance_c = [ If(instance[i][j] == 0,
True,
X[i][j] == instance[i][j])
for i in range(9) for j in range(9) ]

s = Solver()
s.add(sudoku_c + instance_c)
if s.check() == sat:
m = s.model()
r = [ [ m.evaluate(X[i][j]) for j in range(9) ]
for i in range(9) ]
print_matrix(r)
else:
print "failed to solve"
```
### Reversing workflows

Αν χρειάζεστε να **εκτελέσετε συμβολικά το binary και να συλλέξετε περιορισμούς αυτόματα**, δείτε τις σημειώσεις του angr εδώ:

{{#ref}}
angr/README.md
{{#endref}}

Αν ήδη κοιτάτε τα decompiled checks και χρειάζεται μόνο να τα λύσετε, το raw Z3 είναι συνήθως πιο γρήγορο και ευκολότερο στον έλεγχο.

#### Lifting byte-based checks από ένα crackme

Ένα πολύ κοινό pattern σε crackmes και packed loaders είναι μια μεγάλη λίστα από byte equations πάνω σε έναν υποψήφιο password. Μοντελοποιήστε τα bytes ως 8-bit vectors, περιορίστε το alphabet, και διευρύνετέ τα μόνο όταν ο original code τα διευρύνει.

<details>
<summary>Παράδειγμα: rebuild a serial check from decompiled arithmetic</summary>
```python
from z3 import *

flag = [BitVec(f'flag_{i}', 8) for i in range(8)]
s = Solver()

for c in flag:
s.add(c >= 0x20, c <= 0x7e)

w0 = Concat(flag[3], flag[2], flag[1], flag[0])
w1 = Concat(flag[7], flag[6], flag[5], flag[4])

s.add((ZeroExt(24, flag[0]) + ZeroExt(24, flag[5])) == 0x90)
s.add((flag[1] ^ flag[2] ^ flag[3]) == 0x5a)
s.add(RotateLeft(w0, 7) ^ w1 == BitVecVal(0x4f625a13, 32))
s.add(ULE(flag[6], flag[7]))
s.add(LShR(w1, 5) == BitVecVal(0x03a1f21, 32))

if s.check() == sat:
m = s.model()
print(bytes(m[c].as_long() for c in flag))
```
</details>

Αυτό το στυλ ταιριάζει καλά με την πραγματική αντίστροφη ανάλυση, επειδή αντιστοιχεί σε αυτό που κάνουν στην πράξη οι σύγχρονες αναφορές: ανακτούν τις αριθμητικές/σε επίπεδο bit σχέσεις, μετατρέπουν κάθε σύγκριση σε έναν περιορισμό και επιλύουν ολόκληρο το σύστημα ταυτόχρονα.

#### Σταδιακή επίλυση με `push()` / `pop()`

Κατά την αντίστροφη ανάλυση, συχνά θέλετε να δοκιμάσετε αρκετές υποθέσεις χωρίς να αναδημιουργήσετε ολόκληρο τον solver. `push()` δημιουργεί ένα σημείο ελέγχου και `pop()` απορρίπτει τους περιορισμούς που προστέθηκαν μετά από αυτό το σημείο. Αυτό είναι χρήσιμο όταν δεν είστε σίγουροι αν ένα branch είναι υπογεγραμμένο ή μη-υπογεγραμμένο, αν ένας καταχωρητής έχει επέκταση με μηδενικά ή επέκταση με προσημασία, ή όταν δοκιμάζετε διάφορες υποψήφιες σταθερές εξαγόμενες από την αποσυναρμολόγηση.
```python
from z3 import *

x = BitVec('x', 32)
s = Solver()
s.add((x & 0xff) == 0x41)

s.push()
s.add(UGT(x, 0x1000))
print(s.check())
s.pop()

s.push()
s.add(x == 0x41)
print(s.check())
print(s.model())
s.pop()
```
#### Βρίσκοντας περισσότερες από μία έγκυρες εισόδους

Ορισμένα keygens, license checks και CTF challenges σκοπίμως δέχονται **πολλές** έγκυρες εισόδους. Το Z3 δεν τις απαριθμεί αυτόματα, αλλά μπορείτε να προσθέσετε ένα **blocking clause** μετά από κάθε model για να αναγκάσετε το επόμενο αποτέλεσμα να διαφέρει σε τουλάχιστον μία θέση.
```python
from z3 import *

xs = [BitVec(f'x{i}', 8) for i in range(4)]
s = Solver()
for x in xs:
s.add(And(x >= 0x30, x <= 0x39))
s.add(xs[0] + xs[1] == xs[2] + 1)
s.add(xs[3] == xs[0] ^ 3)

while s.check() == sat:
m = s.model()
print(''.join(chr(m[x].as_long()) for x in xs))
s.add(Or([x != m.eval(x, model_completion=True) for x in xs]))
```
#### Τακτικές για άσχημες φόρμουλες bit-vector

Ο προεπιλεγμένος solver του Z3 είναι συνήθως αρκετός, αλλά οι φόρμουλες που δημιουργούνται από decompiler με πολλές εξισώσεις και επαναγραφές σε bit-vector συχνά γίνονται ευκολότερες μετά από ένα πρώτο πέρασμα κανονικοποίησης. Σε αυτές τις περιπτώσεις μπορεί να είναι χρήσιμο να κατασκευάσετε έναν solver από tactics:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν το πρόβλημα είναι σχεδόν εξολοκλήρου **bit-vector + Boolean logic** και θέλετε το Z3 να απλοποιήσει και να εξαλείψει προφανείς ισότητες πριν παραδώσει τον τύπο στο SAT backend.

#### CRCs και άλλοι προσαρμοσμένοι ελεγκτές

Πρόσφατες reversing προκλήσεις εξακολουθούν να χρησιμοποιούν το Z3 για περιορισμούς που είναι ενοχλητικοί στο brute-force αλλά απλοί στο μοντέλο, όπως έλεγχοι CRC32 σε ASCII-only είσοδο, μικτά pipelines rotate/xor/add, ή πολλοί αλυσιδωτοί αριθμητικοί περιορισμοί που εξάγονται από έναν JITed/obfuscated checker. Για προβλήματα τύπου CRC, διατηρήστε την κατάσταση ως bit-vectors και εφαρμόστε περιορισμούς per-byte ASCII νωρίς για να συρρικνώσετε τον χώρο αναζήτησης.

## Αναφορές

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
