# Baie basies, hierdie tool sal ons help om waardes te vind vir variables wat sekere conditions moet satisfy, en om dit met die hand te bereken sal baie irriterend wees. Daarom kan jy vir Z3 die conditions aandui wat die variables moet satisfy, en dit sal some values vind (indien moontlik).

{{#include ../../banners/hacktricks-training.md}}

# Basic Operations

## Booleans/And/Or/Not
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
## Druk Model
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
# Masjienrekenkunde

Moderne CPUs en hoofstroom-programmeertale gebruik rekenkunde oor vaste-grootte bit-vektore. Masjienrekenkunde is beskikbaar in Z3Py as Bit-Vectors.
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
## Signed/Unsigned Numbers

Z3 verskaf spesiale signed weergawes van rekenkundige bewerkings waar dit ’n verskil maak of die bit-vector as signed of unsigned behandel word. In Z3Py stem die operateurs `<`, `<=`, `>`, `>=`, `/`, `%` en `>>` ooreen met die signed weergawes. Die ooreenstemmende unsigned operateurs is `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` en `LShR`.
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
## Funksies

Geïnterpreteerde funksies soos rekenkundige funksies het ’n vaste standaardinterpretasie. Ongeïnterpreteerde funksies en konstantes is maksimum buigsaam; hulle laat enige interpretasie toe wat konsekwent is met die beperkings oor die funksie of konstante.

Voorbeeld: `f` wat twee keer op `x` toegepas word, lewer weer `x`, maar `f` wat een keer op `x` toegepas word, is anders as `x`.
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
# Reversing-Oriented Patterns

As jy volle simboliese uitvoering oor ’n binary nodig het in plaas van om net ’n paar kontroles handmatig op te lig, kyk na [Angr - Examples](angr/angr-examples.md). In die praktyk is ’n baie algemene werkvloei om die relevante predikate uit die decompiler/assembly te herstel en net die interessante rekenkundige of memory constraints in Z3 te herbou.

## Model user-controlled data as bytes first

Vir reversing is dit gewoonlik beter om te begin met `BitVec(..., 8)` vir elke input-byte en dan words presies te herbou soos die target dit doen. Dit behou wrap-around, signedness bugs, shifts, rotates, en byte-order issues.
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
Nuttige helpers wanneer assembly of decompiler code vertaal word:

- `Concat`: herbou 16/32/64-bit waardes vanaf bytes
- `Extract`: vergelyk hoë/lae woorde of emuleer masks/shifts
- `ZeroExt` / `SignExt`: modelleer zero/sign extension-bugs korrek
- `LShR` / `RotateLeft` / `RotateRight`: algemeen in crackmes, hashes, en obfuscators

## Modelleer memory/register tables met arrays

Wanneer 'n check afhanklik is van `buf[i]`, lookup tables, of geëmuleerde memory, kan `Array` skoner wees as om dosyne aparte variables te skep.
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
Dit is veral handig wanneer die binary waardes rond skuif in memory voordat dit hulle valideer, of wanneer jy die effek van ’n paar `mov`/`xor`/`add`-operasies wil modelleer sonder om die hele program te laat loop.

## Incremental solving is great for branch triage

Wanneer jy reeds die basis-beperkings onttrek het, gebruik `push()` / `pop()` (of assumptions) om alternatiewe branches te toets sonder om die solver elke keer van nuuts af te bou:
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
Dit is nuttig wanneer jy path conditions herhaal wat uit ’n decompiler herstel is, of wanneer jy vinnig wil identifiseer watter comparison die model `unsat` maak.

## Optimize vir mooier payloads

Sodra ’n model satisfiable is, kan `Optimize()` jou help om ’n meer bruikbare solution te kry: byvoorbeeld, verkies printable bytes, minimaliseer ’n checksum component, of maksimaliseer ’n struktuur wat die recovered password makliker maak om te tik of te copy.
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
## Strings/sequences vir format-swaar serials

As die teiken hoofsaaklik prefixes, suffixes, substrings, of regex-agtige struktuur kontroleer, kan `String`/`Seq`-beperkings makliker wees as byte-vir-byte bit-vectors:
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
Maar, sodra die binary begin om rekenkunde, rotasies, checksums, of casts oor karakters te doen, is dit gewoonlik beter om terug te gaan na 8-bis bit-vectors.

# Examples

## Sudoku solver
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
## Verwysings

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
* [https://microsoft.github.io/z3guide/](https://microsoft.github.io/z3guide/)
* [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
