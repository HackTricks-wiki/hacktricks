# Kwa msingi kabisa, tool hii itatusaidia kupata values za variables zinazohitaji kutimiza conditions fulani, kwa kuwa kuzikokotoa kwa mkono kutakuwa kero sana. Kwa hiyo, unaweza kuonyesha Z3 conditions ambazo variables zinahitaji kutimiza, nayo itapata values fulani (ikiwezekana).

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
## Kuchapisha Modelu
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
# Arithmetiki ya Mashine

CPU za kisasa na lugha maarufu za programming hutumia arithmetiki juu ya bit-vectors zenye ukubwa maalum. Arithmetiki ya mashine inapatikana katika Z3Py kama Bit-Vectors.<sup>[[1]](#references)</sup>
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
## Nambari za Signed/Unsigned

Z3 hutoa matoleo maalum ya signed ya shughuli za kihesabu ambapo ni muhimu kujua ikiwa bit-vector inachukuliwa kuwa signed au unsigned. Katika Z3Py, waendeshaji `<`, `<=`, `>`, `>=`, `/`, `%` na `>>` hulingana na matoleo ya signed. Waendeshaji wa unsigned wanaolingana ni `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` na `LShR`.<sup>[[1]](#references)</sup>
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
## Functions

Functions zilizotafsiriwa kama arithmetic zina tafsiri ya kawaida isiyobadilika. Functions na constants ambazo hazijatafsiriwa zina unyumbufu wa kiwango cha juu; zinaruhusu tafsiri yoyote inayolingana na constraints zinazohusu function au constant.<sup>[[1]](#references)</sup>

Mfano: `f` ikitumika mara mbili kwa `x`, matokeo huwa `x` tena, lakini `f` ikitumika mara moja kwa `x`, matokeo huwa tofauti na `x`.
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
# Mifumo Inayolenga Reversing

Ikiwa unahitaji symbolic execution kamili kwenye binary badala ya kuinua manually checks chache tu, angalia [Angr - Examples](angr/angr-examples.md). Kwa kawaida, workflow inayotumika sana ni kurejesha predicates zinazohusika kutoka kwenye decompiler/assembly na kujenga upya arithmetic au memory constraints zinazovutia pekee katika Z3.

## Model data inayodhibitiwa na user kama bytes kwanza

Kwa reversing, kwa kawaida ni bora kuanza na `BitVec(..., 8)` kwa kila input byte, kisha kujenga upya words hasa jinsi target inavyofanya. Hii huhifadhi wrap-around, signedness bugs, shifts, rotates, na masuala ya byte-order.
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
Vihisishi muhimu unapotafsiri assembly au decompiler code:

- `Concat`: jenga upya values za biti 16/32/64 kutoka kwa bytes
- `Extract`: linganisha words za juu/chini au iga masks/shifts
- `ZeroExt` / `SignExt`: model bugs za zero/sign extension kwa usahihi
- `LShR` / `RotateLeft` / `RotateRight`: hutumika sana katika crackmes, hashes, na obfuscators

## Model memory/register tables with arrays

Wakati check inategemea `buf[i]`, lookup tables, au emulated memory, `Array` inaweza kuwa safi zaidi kuliko kuunda variables nyingi tofauti.
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
Hii ni muhimu hasa wakati binary inakopi values kwenye memory kabla ya kuzivalidate, au unapotaka ku-model athari ya operations chache za `mov`/`xor`/`add` bila ku-run program nzima.

## Incremental solving ni nzuri kwa branch triage

Baada ya kutoa constraints za msingi, tumia `push()` / `pop()` (au assumptions) ku-test branches mbadala bila kuunda upya solver kila wakati:
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
Hii ni muhimu unapocheza tena path conditions zilizorejeshwa kutoka kwa decompiler, au unapotaka kutambua haraka ni comparison gani inayofanya model kuwa `unsat`.

## Optimize kwa payloads zinazofaa zaidi

Mara tu model inapokuwa satisfiable, `Optimize()` inaweza kukusaidia kupata solution inayotumika zaidi: kwa mfano, kupendelea bytes zinazoweza kuchapishwa, kupunguza checksum component, au kuongeza muundo unaorahisisha password iliyorejeshwa kuandika au kunakili.
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
## Strings/sequences kwa serials zenye format nyingi

Ikiwa target hukagua hasa prefixes, suffixes, substrings, au muundo unaofanana na regex, constraints za `String`/`Seq` zinaweza kuwa rahisi kuliko bit-vectors zinazochakata byte moja baada ya nyingine:
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
Hata hivyo, binary inapoanza kufanya arithmetic, rotations, checksums, au casts kwenye characters, kwa kawaida ni bora kurudi kwenye 8-bit bit-vectors.

# Mifano

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
## References

- [1] [Z3Py Guide - Examples (ericpony)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Z3 Guide (Microsoft)](https://microsoft.github.io/z3guide/)
- [3] [Programming Z3 (Stanford)](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
