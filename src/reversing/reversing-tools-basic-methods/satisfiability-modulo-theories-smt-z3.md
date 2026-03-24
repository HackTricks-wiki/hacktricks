# Satisfiability Modulo Theories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

Sehr vereinfacht: Dieses Tool hilft uns, Werte für Variablen zu finden, die bestimmte Bedingungen erfüllen müssen — das manuell zu berechnen wäre sehr mühselig. Du kannst Z3 die Bedingungen angeben, die die Variablen erfüllen sollen, und es wird (falls möglich) geeignete Werte finden.

**Einige Texte und Beispiele stammen aus [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## Grundlegende Operationen

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
### Modell ausgeben
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
## Maschinenarithmetik

Moderne CPUs und gängige Programmiersprachen verwenden Arithmetik über **fixed-size bit-vectors**. Maschinenarithmetik ist in Z3Py als **Bit-Vectors** verfügbar.
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
### Vorzeichenbehaftete/vorzeichenlose Zahlen

Z3 stellt spezielle vorzeichenbehaftete Versionen arithmetischer Operationen bereit, bei denen es einen Unterschied macht, ob der **Bit-Vektor als vorzeichenbehaftet oder vorzeichenlos behandelt wird**. In Z3Py entsprechen die Operatoren **<, <=, >, >=, /, % und >>** den **vorzeichenbehafteten** Versionen. Die entsprechenden **vorzeichenlosen** Operatoren sind **ULT, ULE, UGT, UGE, UDiv, URem und LShR.**
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
### Bit-Vektor-Hilfen, die beim reversing häufig benötigt werden

Wenn du **lifting checks from assembly or decompiler output** durchführst, ist es in der Regel besser, jedes Eingabe-Byte als `BitVec(..., 8)` zu modellieren und dann die Wörter genau so wieder aufzubauen, wie es der Zielcode tut. Das vermeidet Fehler, die durch das Mischen mathematischer Ganzzahlen mit Maschinenarithmetik entstehen.
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
Einige häufige Fallstricke beim Übersetzen von Code in Constraints:

- `>>` ist ein **arithmetischer** Rechts-Shift für Bit-Vektoren. Verwende `LShR` für die logische `shr` Anweisung.
- Verwende `UDiv`, `URem`, `ULT`, `ULE`, `UGT` und `UGE`, wenn der ursprüngliche Vergleich/die Division **vorzeichenlos** war.
- Mache die Breiten explizit. Wenn das Binary auf 8 oder 16 Bit kürzt, füge `Extract` hinzu oder baue den Wert mit `Concat` wieder auf, anstatt stillschweigend alles zu Python integers zu konvertieren.

### Funktionen

**Interpretierte Funktionen** wie arithmetische Operatoren, bei denen die **Funktion +** eine **feste Standardinterpretation** hat (sie addiert zwei Zahlen). **Nichtinterpretierte Funktionen** und Konstanten sind **maximal flexibel**; sie erlauben **jede Interpretation**, die mit den **Constraints** über die Funktion oder Konstante **konsistent** ist.

Beispiel: Wenn f zweimal auf x angewendet wird, ergibt das wieder x; wenn f einmal auf x angewendet wird, ist das Ergebnis ungleich x.
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
## Beispiele

### Sudoku-Löser
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

Wenn du die **symbolically execute the binary and collect constraints automatically** musst, sieh dir die angr-Notizen hier an:

{{#ref}}
angr/README.md
{{#endref}}

Wenn du dir bereits die decompiled checks ansiehst und sie nur lösen musst, ist raw Z3 normalerweise schneller und einfacher zu kontrollieren.

#### Lifting byte-based checks from a crackme

Ein sehr verbreitetes Muster in crackmes und packed loaders ist eine lange Liste von byte-Gleichungen über ein candidate password. Modellier die bytes als 8-bit vectors, schränke das Alphabet ein und weite sie nur, wenn der ursprüngliche Code sie weitet.

<details>
<summary>Beispiel: rebuild a serial check from decompiled arithmetic</summary>
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

Dieser Stil passt gut zum real-world reversing, weil er dem entspricht, was moderne writeups in der Praxis tun: die arithmetischen/bitweisen Relationen rekonstruieren, jeden Vergleich in eine Bedingung umwandeln und das gesamte System auf einmal lösen.

#### Inkrementelles Lösen mit `push()` / `pop()`

Beim reversing willst du häufig mehrere Hypothesen testen, ohne den gesamten Solver neu aufzubauen. `push()` erzeugt einen Checkpoint und `pop()` verwirft die nach diesem Checkpoint hinzugefügten Constraints. Das ist nützlich, wenn du dir nicht sicher bist, ob ein branch signed oder unsigned ist, ob ein register zero-extended oder sign-extended ist, oder wenn du mehrere candidate constants aus der disassembly ausprobierst.
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
#### Mehrere gültige Eingaben aufzählen

Einige keygens, license checks und CTF challenges erlauben absichtlich **viele** gültige Eingaben. Z3 enumeriert diese nicht automatisch, aber du kannst nach jedem Modell eine **Ausschlussklausel** hinzufügen, um zu erzwingen, dass sich das nächste Ergebnis in mindestens einer Position unterscheidet.
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
#### Taktiken für unordentliche bit-vector-Formeln

Der Standard-Solver von Z3 ist normalerweise ausreichend, aber decompiler-generated Formeln mit vielen Gleichungen und bit-vector-Rewrites werden nach einem ersten Normalisierungsdurchlauf oft einfacher. In solchen Fällen kann es nützlich sein, einen Solver aus Taktiken zu bauen:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
Das ist besonders hilfreich, wenn das Problem nahezu vollständig aus **bit-vector + Boolean logic** besteht und man möchte, dass Z3 offensichtliche Gleichheiten vereinfacht und eliminiert, bevor die Formel an das SAT backend übergeben wird.

#### CRCs und andere benutzerdefinierte Checker

Aktuelle reversing challenges verwenden Z3 weiterhin für constraints, die sich zwar mühselig brute-force lösen lassen, aber sich einfach modellieren lassen, wie z. B. CRC32-Checks über ASCII-only Input, gemischte rotate/xor/add-Pipelines oder viele verkettete arithmetische Prädikate, die aus einem JITed/obfuscated Checker extrahiert wurden. Bei CRC-ähnlichen Problemen sollte der Zustand als bit-vectors belassen und früh per-byte ASCII-Constraints angewendet werden, um den Suchraum zu verkleinern.

## Referenzen

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
