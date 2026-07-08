# Veoma ukratko, ovaj alat će nam pomoći da pronađemo vrednosti za promenljive koje moraju da zadovolje neke uslove, a njihovo ručno računanje bi bilo veoma naporno. Zato možete Z3 da navedete uslove koje promenljive treba da zadovolje i on će pronaći neke vrednosti (ako je moguće).

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
## Ispisivanje modela
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
# Arithmetika mašina

Moderni CPU-i i glavne programske jezike koriste aritmetiku nad bit-vektorima fiksne veličine. Arithmetika mašina je dostupna u Z3Py kao Bit-Vectors.
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
## Potpisani/nepotpisani brojevi

Z3 pruža posebne signed verzije aritmetičkih operacija gde je bitno da li se bit-vector tretira kao signed ili unsigned. U Z3Py, operatori `<`, `<=`, `>`, `>=`, `/`, `%` i `>>` odgovaraju signed verzijama. Odgovarajući unsigned operatori su `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` i `LShR`.
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
## Funkcije

Interpretirane funkcije kao što je aritmetika imaju fiksnu standardnu interpretaciju. Neinterpretirane funkcije i konstante su maksimalno fleksibilne; one dozvoljavaju bilo koju interpretaciju koja je usklađena sa ograničenjima nad funkcijom ili konstantom.

Primer: `f` primenjena dva puta na `x` daje opet `x`, ali `f` primenjena jednom na `x` je različita od `x`.
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
# Obrasci orijentisani na reversing

Ako vam je potrebno potpuno simboličko izvršavanje nad binarnim fajlom umesto da ručno podižete samo nekoliko provera, pogledajte [Angr - Examples](angr/angr-examples.md). U praksi, veoma čest workflow je da se povrate relevantni predikati iz dekompajlera/assembly-ja i da se ponovo izgrade samo zanimljiva aritmetička ili memorijska ograničenja u Z3.

## Modelujte podatke pod kontrolom korisnika prvo kao bajtove

Za reversing, obično je bolje da počnete sa `BitVec(..., 8)` za svaki ulazni bajt i zatim ponovo izgradite reči tačno onako kako to radi cilj. Ovo čuva wrap-around, signedness bagove, shiftove, rotateove i probleme sa redosledom bajtova.
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
Korisni pomagači pri prevođenju assembly ili decompiler koda:

- `Concat`: rekonstruiši 16/32/64-bitne vrednosti iz bajtova
- `Extract`: poredi visoke/niske reči ili emuliraj maske/pomeraje
- `ZeroExt` / `SignExt`: pravilno modeluj bugove sa zero/sign ekstenzijom
- `LShR` / `RotateLeft` / `RotateRight`: često u crackmes, hash-evima i obfuscatorima

## Modeluj tabele memorije/registera pomoću nizova

Kada provera zavisi od `buf[i]`, lookup tabela ili emulirane memorije, `Array` može biti čistije rešenje nego pravljenje desetina odvojenih promenljivih.
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
Ovo je posebno korisno kada binary kopira vrednosti kroz memoriju pre nego što ih validira, ili kada želiš da modeluješ efekat nekoliko `mov`/`xor`/`add` operacija bez pokretanja celog programa.

## Incremental solving je odličan za branch triage

Kada si već izdvojio osnovne constraints, koristi `push()` / `pop()` (ili assumptions) da testiraš alternativne branches bez ponovnog izgrađivanja solvera svaki put:
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
Ovo je korisno kada se ponovo izvršavaju path conditions dobijeni iz decompiler-a, ili kada želite brzo da identifikujete koja comparison čini model `unsat`.

## Optimize za lepše payloads

Kada je model satisfiable, `Optimize()` može pomoći da dobijete praktičnije rešenje: na primer, da preferira printable bytes, minimizuje checksum komponentu, ili maksimizuje neku strukturu koja čini recovered password lakšom za kucanje ili kopiranje.
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
## Stringovi/sekvence za serijske brojeve sa mnogo formata

Ako target uglavnom proverava prefikse, sufikse, podstringove ili strukturu nalik regex-u, `String`/`Seq` constraint-i mogu biti lakši od bit-vectors po bajtovima:
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
Međutim, kada binarni fajl počne da radi aritmetiku, rotacije, checksum-ove ili kastovanje nad karakterima, obično je bolje vratiti se na 8-bit bit-vectors.

# Primeri

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
## Reference

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
* [https://microsoft.github.io/z3guide/](https://microsoft.github.io/z3guide/)
* [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
