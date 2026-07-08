# बहुत ही बुनियादी रूप से, यह tool हमें ऐसे variables के लिए values ढूंढने में मदद करेगा जिन्हें कुछ conditions satisfy करनी हों, और इन्हें manually calculate करना बहुत annoying होगा। इसलिए, आप Z3 को वे conditions बता सकते हैं जिन्हें variables को satisfy करना है और यह कुछ values ढूंढ देगा (अगर possible हो)।

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
# मशीन Arithmetic

Modern CPUs और main-stream programming languages fixed-size bit-vectors पर arithmetic use करते हैं। Machine arithmetic Z3Py में Bit-Vectors के रूप में available है।
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

Z3 arithmetical operations के special signed versions प्रदान करता है, जहाँ यह फर्क पड़ता है कि bit-vector को signed या unsigned के रूप में treat किया जा रहा है। Z3Py में, operators `<`, `<=`, `>`, `>=`, `/`, `%` और `>>` signed versions के correspond करते हैं। Corresponding unsigned operators `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` और `LShR` हैं।
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
## फ़ंक्शन्स

Interpreted functions जैसे arithmetic का एक fixed standard interpretation होता है। Uninterpreted functions और constants अधिकतम लचीले होते हैं; वे ऐसा कोई भी interpretation allow करते हैं जो function या constant पर लगाए गए constraints के साथ consistent हो।

उदाहरण: `x` पर `f` को दो बार लागू करने पर फिर से `x` मिलता है, लेकिन `x` पर `f` को एक बार लागू करने पर वह `x` से अलग है।
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

यदि आपको किसी binary पर manually कुछ checks को ही lift करने के बजाय full symbolic execution चाहिए, तो [Angr - Examples](angr/angr-examples.md) देखें। व्यवहार में, एक बहुत common workflow यह है कि decompiler/assembly से relevant predicates को recover किया जाए और केवल interesting arithmetic या memory constraints को Z3 में rebuild किया जाए।

## Model user-controlled data as bytes first

Reversing के लिए, आमतौर पर `BitVec(..., 8)` से हर input byte के लिए start करना बेहतर होता है और फिर words को exactly वैसे ही rebuild करना चाहिए जैसे target करता है। इससे wrap-around, signedness bugs, shifts, rotates, और byte-order issues preserve रहते हैं।
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
उपयोगी helpers जब assembly या decompiler code का अनुवाद कर रहे हों:

- `Concat`: bytes से 16/32/64-bit values को फिर से बनाना
- `Extract`: high/low words की तुलना करना या masks/shifts को emulate करना
- `ZeroExt` / `SignExt`: zero/sign extension bugs को सही तरीके से model करना
- `LShR` / `RotateLeft` / `RotateRight`: crackmes, hashes, और obfuscators में common

## Model memory/register tables with arrays

जब कोई check `buf[i]`, lookup tables, या emulated memory पर depend करता है, तो `Array` dozens अलग-अलग variables बनाने से ज्यादा clean हो सकता है।
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
यह विशेष रूप से तब उपयोगी है जब binary वैलिडेट करने से पहले memory में values कॉपी करता है, या जब आप पूरे program को चलाए बिना कुछ `mov`/`xor`/`add` operations के effect को model करना चाहते हैं।

## Incremental solving branch triage के लिए बहुत अच्छा है

जब आप base constraints पहले ही extract कर चुके हों, तो `push()` / `pop()` (या assumptions) का use करके alternative branches test करें, बिना हर बार solver को दोबारा build किए:
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
यह decompiler से recovered path conditions को replay करते समय उपयोगी है, या जब आप जल्दी से identify करना चाहते हैं कि कौन-सा comparison model को `unsat` बना रहा है।

## Optimize for nicer payloads

एक बार model satisfiable हो जाने पर, `Optimize()` आपको एक अधिक usable solution पाने में मदद कर सकता है: उदाहरण के लिए, printable bytes को prefer करना, checksum component को minimize करना, या किसी structure को maximize करना जो recovered password को type या copy करना आसान बनाता है।
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
## format-heavy serials के लिए Strings/sequences

अगर target मुख्य रूप से prefixes, suffixes, substrings, या regex-like structure चेक करता है, तो `String`/`Seq` constraints byte-by-byte bit-vectors से आसान हो सकते हैं:
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
हालाँकि, एक बार binary जब arithmetic, rotations, checksums, या characters पर casts करना शुरू करती है, तो आमतौर पर 8-bit bit-vectors पर वापस जाना बेहतर होता है।

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
## संदर्भ

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
* [https://microsoft.github.io/z3guide/](https://microsoft.github.io/z3guide/)
* [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
