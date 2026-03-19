# Satisfiability Modulo Theories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

Kwa msingi tu, zana hii itatusaidia kupata thamani za vigezo ambazo zinahitaji kutimiza masharti fulani, na kuzihesabu kwa mkono kutakuwa kuchosha sana. Kwa hivyo, unaweza kueleza kwa Z3 masharti ambayo vigezo vinapaswa kuyatimiza na itatafuta baadhi ya thamani (ikiwa inawezekana).

**Baadhi ya maandishi na mifano imetolewa kutoka [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## Operesheni za Msingi

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
### Kuchapisha Mfano
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
## Hisabati ya Mashine

CPU za kisasa na lugha maarufu za programu zinatumia hesabu inayofanywa kwenye **fixed-size bit-vectors**. Hesabu ya mashine inapatikana katika Z3Py kama **Bit-Vectors**.
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
### Nambari Zenye Saini/Isiyo na Saini

Z3 inatoa matoleo maalum za operesheni za hisabati ambapo kuna tofauti ikiwa **bit-vector inachukuliwa kuwa yenye saini au isiyo na saini**. Katika Z3Py, operators **<, <=, >, >=, /, % and >>** zinawakilisha matoleo ya **yaliyosainiwa**. Operators zinazolingana za **zisizo na saini** ni **ULT, ULE, UGT, UGE, UDiv, URem and LShR.**
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
### Bit-vector helpers zinazohitajika mara kwa mara katika reversing

Unapokuwa **lifting checks from assembly or decompiler output**, kawaida ni bora kuiga kila baiti la ingizo kama `BitVec(..., 8)` kisha kujenga tena maneno hasa kama vile target code inavyofanya. Hii inazuia mende zinazotokana na kuchanganya nambari kamili za kihisabati na aritmetiki ya mashine.
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
Baadhi ya makosa ya kawaida wakati wa kutafsiri code kuwa vizingiti:

- `>>` ni shift ya kulia ya **arithmetic** kwa bit-vectors. Tumia `LShR` kwa instruction ya `shr` ya logical.
- Tumia `UDiv`, `URem`, `ULT`, `ULE`, `UGT` na `UGE` wakati comparison/division ya asili ilikuwa **unsigned**.
- Weka widths wazi. Ikiwa binary inakata hadi 8 au 16 bits, ongeza `Extract` au jenga tena thamani na `Concat` badala ya kuinua kila kitu kimya kimya kuwa Python integers.

### Functions

**Interpreted functio**ns kama arithmetic ambapo **function +** ina **fixed standard interpretation** (inaongeza nambari mbili). **Uninterpreted functions** na constants ni **maximally flexible**; zinaruhusu **any interpretation** inayokuwa **consistent** na **constraints** juu ya function au constant.

Mfano: f applied twice to x results in x again, but f applied once to x is different from x.
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
## Mifano

### Mtatuzi wa Sudoku
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

Ikiwa unahitaji **symbolically execute the binary and collect constraints automatically**, angalia noti za angr hapa:

{{#ref}}
angr/README.md
{{#endref}}

Ikiwa tayari unatazama the decompiled checks na unahitaji tu kuzitatua, raw Z3 kwa kawaida ni haraka zaidi na rahisi kudhibiti.

#### Kuinua ukaguzi unaotegemea byte kutoka crackme

Muundo unaojirudia sana katika crackmes na packed loaders ni orodha ndefu ya byte equations zinazohusu candidate password. Model bytes as 8-bit vectors, weka vikwazo kwa alphabet, na uzipanue (widen) tu wakati original code inaziwiden.

<details>
<summary>Mfano: rebuild a serial check from decompiled arithmetic</summary>
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

Mtindo huu unaendana vizuri na real-world reversing kwa sababu unalingana na kile modern writeups hufanya kwa vitendo: kuvumbua uhusiano wa arithmetic/bitwise, kugeuza kila comparison kuwa kizuizi, na kutatua mfumo mzima mara moja.

#### Kutatua kwa hatua kwa kutumia `push()` / `pop()`

Wakati wa reversing, mara nyingi unataka kujaribu nadharia kadhaa bila kujenga tena solver yote. `push()` huunda checkpoint na `pop()` hutupa vikwazo vilivyoongezwa baada ya checkpoint hiyo. Hii ni muhimu ikiwa huna uhakika kama tawi ni signed au unsigned, ikiwa register ime-zero-extended au sign-extended, au unapojaribu konstanti kadhaa zilizochukuliwa kutoka kwenye disassembly.
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
#### Kuhesabu ingizo zaidi ya moja linalokubalika

Baadhi ya keygens, license checks, na CTF challenges kwa makusudi huruhusu **mengi** ya ingizo halali. Z3 haiziorodheshi hizi moja kwa moja, lakini unaweza kuongeza **blocking clause** baada ya kila model ili kulazimisha matokeo yanayofuata yatofautiane angalau katika nafasi moja.
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
#### Taktiki kwa fomula za bit-vector zisizopendeza

Default solver ya Z3 kwa kawaida inatosha, lakini decompiler-generated formulas zenye equalities nyingi na bit-vector rewrites mara nyingi zinakuwa rahisi zaidi baada ya first normalization pass. Katika kesi hizo, inaweza kuwa ya msaada kujenga solver kwa kutumia tactics:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
Hii inasaidia hasa wakati tatizo ni karibu kabisa **bit-vector + Boolean logic** na unataka Z3 ipunguze na kuondoa usawa zilizo wazi kabla ya kukabidhi fomula kwa SAT backend.

#### CRCs na checkers za desturi

Changamoto za hivi karibuni za reversing bado zinatumia Z3 kwa constraints ambazo zinaweza kuchosha kujaribu kwa brute-force lakini ni rahisi ku-model, kama CRC32 checks juu ya ASCII-only input, mixed rotate/xor/add pipelines, au predicates nyingi za arithmetic zilizochained zilizotolewa kutoka kwa JITed/obfuscated checker. Kwa matatizo yanayofanana na CRC, wahifadhi state kama bit-vectors na apply per-byte ASCII constraints mapema ili kupunguza search space.

## Marejeo

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
