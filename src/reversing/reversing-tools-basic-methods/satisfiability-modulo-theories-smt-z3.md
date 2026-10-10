# बहुत ही बुनियादी तौर पर, यह टूल हमें उन वैल्यूज़ को खोजने में मदद करेगा जिन्हें वेरिएबल्स को कुछ शर्तें पूरी करने के लिए लेना होगा। उन्हें हाथ से निकालना बहुत झंझटभरा होगा। इसलिए, आप Z3 को बता सकते हैं कि वेरिएबल्स को कौन-सी शर्तें पूरी करनी हैं, और यह कुछ वैल्यूज़ ढूँढ़ लेगा (यदि संभव हो)।

{{#include ../../banners/hacktricks-training.md}}

# बुनियादी ऑपरेशन्स

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

## पूर्णांक/सरलीकरण/वास्तविक संख्याएँ

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

# मशीन अंकगणित

आधुनिक CPUs और मुख्यधारा की programming languages, निश्चित आकार के bit-vectors पर अंकगणित का उपयोग करती हैं। Z3Py में मशीन अंकगणित Bit-Vectors के रूप में उपलब्ध है।

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

## चिह्नित/अचिह्नित संख्याएँ

Z3 अंकगणितीय ऑपरेशनों के विशेष चिह्नित संस्करण प्रदान करता है, जहाँ यह मायने रखता है कि bit-vector को चिह्नित माना गया है या अचिह्नित। Z3Py में, ऑपरेटर `<`, `<=`, `>`, `>=`, `/`, `%` और `>>` चिह्नित संस्करणों के अनुरूप हैं। इनके संगत अचिह्नित ऑपरेटर `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` और `LShR` हैं।<sup>[[1]](#references)</sup>

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

अंकगणित जैसे interpreted functions की एक निश्चित standard interpretation होती है। Uninterpreted functions और constants अधिकतम लचीले होते हैं; वे function या constant पर लागू constraints के अनुरूप कोई भी interpretation स्वीकार करते हैं।<sup>[[1]](#references)</sup>

उदाहरण: `x` पर `f` को दो बार लागू करने से फिर `x` मिलता है, लेकिन `x` पर `f` को एक बार लागू करने से `x` नहीं मिलता।

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

# Reversing-केंद्रित पैटर्न

अगर आपको केवल कुछ checks को manually lift करने के बजाय किसी binary पर पूरा symbolic execution करना है, तो [Angr - Examples](angr/angr-examples.md) देखें। व्यवहार में, एक बहुत आम workflow यह है कि decompiler/assembly से संबंधित predicates निकालें और Z3 में केवल दिलचस्प arithmetic या memory constraints को फिर से बनाएँ।

## User-controlled data को पहले bytes के रूप में मॉडल करें

Reversing के लिए, आमतौर पर हर input byte के लिए `BitVec(..., 8)` से शुरुआत करना और फिर target के अनुसार words को हूबहू फिर से बनाना बेहतर होता है। इससे wrap-around, signedness bugs, shifts, rotates और byte-order संबंधी समस्याएँ बनी रहती हैं।<sup>[[2]](#references)</sup>

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

- `Concat`: bytes से 16/32/64-bit values फिर से बनाएं
- `Extract`: high/low words की तुलना करें या masks/shifts emulate करें
- `ZeroExt` / `SignExt`: zero/sign extension bugs को सही ढंग से model करें
- `LShR` / `RotateLeft` / `RotateRight`: crackmes, hashes और obfuscators में आम

## Arrays से memory/register tables model करें

जब कोई check `buf[i]`, lookup tables या emulated memory पर निर्भर हो, तो दर्जनों अलग-अलग variables बनाने के बजाय `Array` का इस्तेमाल अधिक साफ़ हो सकता है।<sup>[[3]](#references)</sup>

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

यह तब विशेष रूप से उपयोगी है जब binary मानों को validate करने से पहले memory में इधर-उधर कॉपी करता है, या जब आप पूरा program चलाए बिना कुछ `mov`/`xor`/`add` operations के प्रभाव का मॉडल बनाना चाहते हैं।

## शाखाओं की छँटाई के लिए incremental solving बहुत उपयोगी है

जब आप base constraints पहले ही निकाल चुके हों, तो हर बार solver को दोबारा बनाए बिना वैकल्पिक शाखाओं को जाँचने के लिए `push()` / `pop()` (या assumptions) का उपयोग करें:<sup>[[3]](#references)</sup>

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

यह तब उपयोगी होता है जब decompiler से प्राप्त path conditions को फिर से चलाया जा रहा हो, या आप जल्दी से पहचानना चाहते हों कि कौन-सी comparison model को `unsat` बना रही है।

## बेहतर payloads के लिए Optimize करें

जब कोई model satisfiable हो जाए, तो `Optimize()` आपको अधिक उपयोगी solution पाने में मदद कर सकता है: उदाहरण के लिए, printable bytes को प्राथमिकता देना, checksum component को न्यूनतम करना, या ऐसी structure को अधिकतम करना जिससे प्राप्त password को टाइप या कॉपी करना आसान हो।<sup>[[3]](#references)</sup>

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

## फ़ॉर्मैट-प्रधान सीरियल के लिए Strings/sequences

अगर target मुख्य रूप से prefixes, suffixes, substrings या regex जैसी संरचना जाँचता है, तो byte-by-byte bit-vectors की तुलना में `String`/`Seq` constraints आसान हो सकती हैं:<sup>[[3]](#references)</sup>

```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```

हालाँकि, जब binary characters पर arithmetic, rotations, checksums या casts करना शुरू करता है, तो आमतौर पर 8-bit bit-vectors पर वापस जाना बेहतर होता है।

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

## References

- [1] [उदाहरणों सहित Z3Py मार्गदर्शिका (ericpony z3py-tutorial)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Z3 मार्गदर्शिका - बिट-वेक्टर सिद्धांत (Microsoft z3guide)](https://microsoft.github.io/z3guide/)
- [3] [Z3 प्रोग्रामिंग (Nikolaj Bjørner, Leonardo de Moura, Lev Nachmanson, Christoph Wintersteiger)](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
