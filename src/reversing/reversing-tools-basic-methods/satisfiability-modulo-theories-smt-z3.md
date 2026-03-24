# Bevredigbaarheid Modulo-teorieë (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

In eenvoudige terme help hierdie hulpmiddel ons om waardes vir veranderlikes te vind wat aan sekere voorwaardes moet voldoen — dit met die hand uitwerk sou baie vervelig wees. Jy kan dus aan Z3 die voorwaardes spesifiseer en dit sal (indien moontlik) geskikte waardes vind.

**Sommige teks en voorbeelde is ontleën aan [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## Basiese Operasies

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
### Model afdruk
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
## Masjienaritmetika

Moderne CPUs en hoofstroom-programmeertale gebruik aritmetika oor **vasgrootte bit-vectors**. Masjienaritmetika is beskikbaar in Z3Py as **Bit-Vectors**.
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
### Gesigneerde/Ongetekende getalle

Z3 verskaf spesiale gesigneerde weergawes van aritmetiese bewerkings waar dit 'n verskil maak of die **bit-vector as gesigneerd of ongetekend behandel word**. In Z3Py, die operateurs **<, <=, >, >=, /, % and >>** kom ooreen met die **gesigneerde** weergawes. Die ooreenstemmende **ongetekende** operateurs is **ULT, ULE, UGT, UGE, UDiv, URem and LShR.**
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
### Bit-vektor hulpfunksies wat algemeen in reversing benodig word

Wanneer jy **lifting checks from assembly or decompiler output**, is dit gewoonlik beter om elke input byte as `BitVec(..., 8)` te modelleer en dan woorde presies soos die target code dit doen weer op te bou. Dit vermy bugs wat veroorsaak word deur die meng van wiskundige heelgetalle met masjienaritmetika.
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
Gereelde struikelblokke wanneer kode na beperkings vertaal word:

- `>>` is 'n **aritmetiese** regterskuif vir bit-vektore. Gebruik `LShR` vir die logiese `shr` instruksie.
- Gebruik `UDiv`, `URem`, `ULT`, `ULE`, `UGT` en `UGE` wanneer die oorspronklike vergelyking/deling **ongeteken** was.
- Hou breedtes eksplisiet. As die binêre na 8 of 16 bits afkap, voeg `Extract` by of bou die waarde weer op met `Concat` in plaas daarvan om alles stilweg na Python integers te bevorder.

### Funksies

**Geïnterpreteerde funksies** soos rekenkunde waar die **funksie +** 'n **vaste standaardinterpretasie** het (dit tel twee getalle op). **Ongeïnterpreteerde funksies** en konstantes is **uiterst buigsaam**; hulle laat **enige interpretasie** toe wat **konsekwent** is met die **beperkings** oor die funksie of konstante.

Voorbeeld: f wat twee keer op x toegepas word, gee weer x, maar f wat een keer op x toegepas word is anders as x.
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
## Voorbeelde

### Sudoku-oploser
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

As jy nodig het om **symbolically execute the binary and collect constraints automatically**, kyk na die angr-notas hier:

{{#ref}}
angr/README.md
{{#endref}}

If you are already looking at the decompiled checks and only need to solve them, raw Z3 is usually faster and easier to control.

#### Lifting byte-based checks from a crackme

'n Baie algemene patroon in crackmes en packed loaders is 'n lang lys van byte-vergelykings oor 'n kandidaat-wagwoord. Modelleer bytes as 8-bit vektore, beperk die alfabet, en verbreed hulle slegs wanneer die oorspronklike kode dit verbreed.

<details>
<summary>Example: rebuild a serial check from decompiled arithmetic</summary>
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

Hierdie styl pas goed by real-world reversing omdat dit ooreenstem met wat moderne writeups in die praktyk doen: herkry die arithmetic/bitwise relations, draai elke comparison om in 'n constraint, en los die hele stelsel in een keer op.

#### Incremental solving with `push()` / `pop()`

Terwyl jy reversing doen, wil jy dikwels verskeie hipoteses toets sonder om die hele solver te herbou. `push()` skep 'n checkpoint en `pop()` verwyder die constraints wat ná daardie checkpoint bygevoeg is. Dit is nuttig wanneer jy nie seker is of 'n branch signed of unsigned is nie, of 'n register zero-extended of sign-extended is, of wanneer jy verskeie kandidaat constants uit disassembly probeer.
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
#### Opsomming van meer as een geldige invoer

Sommige keygens, license checks, en CTF-uitdagings laat opsetlik **baie** geldige invoere toe. Z3 som dit nie outomaties op nie, maar jy kan na elke model 'n **blocking clause** byvoeg om die volgende resultaat te dwing om in minstens een posisie te verskil.
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
#### Taktieke vir lelike bit-vector-formules

Z3 se default solver is gewoonlik genoeg, maar decompiler-generated formules met baie gelykhede en bit-vector rewrites raak dikwels eenvoudiger ná 'n eerste normaliseringspas. In daardie gevalle kan dit nuttig wees om 'n solver uit taktieke op te bou:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
Dit is veral nuttig wanneer die probleem byna uitsluitlik **bit-vector + Boolean logic** is en jy wil hê Z3 moet voor die oorhandiging van die formule aan die SAT backend voor de hand liggende gelykhede vereenvoudig en uitskakel.

#### CRCs en ander aangepaste checkers

Onlangse reversing-uitdagings gebruik steeds Z3 vir constraints wat lastig is om met brute-force op te los maar eenvoudig is om te modelleer, soos CRC32 checks oor ASCII-only input, gemengde rotate/xor/add pipelines, of baie geketende aritmetiese predikate wat uit 'n JITed/obfuscated checker onttrek is. Vir CRC-agtige probleme, hou die staat as bit-vectors en pas per-byte ASCII-constraints vroeg toe om die soekruimte te verklein.

## References

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
