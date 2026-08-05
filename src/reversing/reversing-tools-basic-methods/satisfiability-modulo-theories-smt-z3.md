# बहुत सामान्य रूप से, यह tool हमें उन variables के values खोजने में मदद करेगा जिन्हें कुछ conditions को satisfy करना आवश्यक है, और जिन्हें हाथ से calculate करना बहुत परेशान करने वाला होगा। इसलिए, आप Z3 को वे conditions बता सकते हैं जिन्हें variables को satisfy करना आवश्यक है, और यह कुछ values खोज लेगा (यदि संभव हो)।

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
## प्रिंटिंग मॉडल
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
# Machine Arithmetic

Modern CPUs और main-stream programming languages fixed-size bit-vectors पर arithmetic का उपयोग करते हैं। Machine arithmetic Z3Py में Bit-Vectors के रूप में उपलब्ध है।<sup>[[1]](#references)</sup>
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

Z3 arithmetical operations के विशेष signed versions प्रदान करता है, जहाँ bit-vector को signed या unsigned मानने पर अंतर पड़ता है। Z3Py में operators `<`, `<=`, `>`, `>=`, `/`, `%` और `>>` signed versions के अनुरूप होते हैं। इनके संबंधित unsigned operators `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` और `LShR` हैं।<sup>[[1]](#references)</sup>
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

Arithmetic जैसे interpreted functions की एक fixed standard interpretation होती है। Uninterpreted functions और constants अधिकतम flexible होते हैं; वे किसी भी ऐसी interpretation की अनुमति देते हैं जो function या constant पर लागू constraints के अनुरूप हो।<sup>[[1]](#references)</sup>

Example: `f` को `x` पर दो बार apply करने पर फिर से `x` प्राप्त होता है, लेकिन `f` को `x` पर एक बार apply करने पर परिणाम `x` से अलग होता है।
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
# Reversing-केंद्रित Patterns

यदि आपको केवल कुछ checks को manually lifting करने के बजाय किसी binary पर full symbolic execution चाहिए, तो [Angr - Examples](angr/angr-examples.md) देखें। व्यवहार में, एक बहुत common workflow decompiler/assembly से relevant predicates को recover करना और Z3 में केवल interesting arithmetic या memory constraints को rebuild करना है।

## user-controlled data को पहले bytes के रूप में Model करें

Reversing के लिए, आमतौर पर प्रत्येक input byte के लिए `BitVec(..., 8)` से शुरुआत करना और फिर target के अनुसार words को exactly rebuild करना बेहतर होता है। इससे wrap-around, signedness bugs, shifts, rotates और byte-order issues सुरक्षित रहते हैं।
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
Assembly या decompiler code का अनुवाद करते समय उपयोगी helpers:

- `Concat`: bytes से 16/32/64-bit values को फिर से बनाएं
- `Extract`: high/low words की तुलना करें या masks/shifts का अनुकरण करें
- `ZeroExt` / `SignExt`: zero/sign extension bugs को सही तरीके से model करें
- `LShR` / `RotateLeft` / `RotateRight`: crackmes, hashes और obfuscators में सामान्य रूप से उपयोग किए जाते हैं

## Arrays के साथ memory/register tables को model करें

जब कोई check `buf[i]`, lookup tables या emulated memory पर निर्भर करता है, तो दर्जनों अलग-अलग variables बनाने के बजाय `Array` अधिक साफ-सुथरा हो सकता है।
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
यह विशेष रूप से तब उपयोगी होता है जब binary values को validate करने से पहले memory में इधर-उधर copy करता है, या जब आप पूरे program को चलाए बिना कुछ `mov`/`xor`/`add` operations के प्रभाव को model करना चाहते हैं।

## Branch triage के लिए incremental solving उपयोगी है

जब आप base constraints पहले ही extract कर चुके हों, तो हर बार solver को फिर से बनाए बिना alternative branches को test करने के लिए `push()` / `pop()` (या assumptions) का उपयोग करें:
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
यह तब उपयोगी होता है जब आप decompiler से recovered path conditions को replay कर रहे हों, या जब आप जल्दी से यह पहचानना चाहते हों कि कौन-सी comparison model को `unsat` बना रही है।

## अधिक सुविधाजनक payloads के लिए Optimize करें

जब कोई model satisfiable हो, तो `Optimize()` आपको अधिक उपयोगी solution प्राप्त करने में मदद कर सकता है: उदाहरण के लिए, printable bytes को प्राथमिकता देना, checksum component को minimize करना, या किसी ऐसी structure को maximize करना जिससे recovered password को type या copy करना आसान हो।
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
## Format-heavy serials के लिए Strings/sequences

यदि target मुख्य रूप से prefixes, suffixes, substrings या regex-जैसी structure को check करता है, तो byte-by-byte bit-vectors की तुलना में `String`/`Seq` constraints अधिक आसान हो सकती हैं:
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
हालाँकि, जब binary characters पर arithmetic, rotations, checksums या casts करने लगती है, तो आमतौर पर 8-bit bit-vectors पर वापस जाना बेहतर होता है।

# उदाहरण

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
## संदर्भ

- [1] [Z3Py Guide - Examples (ericpony)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Z3 Guide (Microsoft)](https://microsoft.github.io/z3guide/)
- [3] [Programming Z3 (Stanford)](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
