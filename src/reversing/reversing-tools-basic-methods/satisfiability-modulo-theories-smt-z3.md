# Satisfiability Modulo Theories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

सरल रूप में, यह टूल उन वेरिएबल्स के लिए मान ढूँढने में मदद करता है जिन्हें कुछ शर्तें पूरी करनी होती हैं और इन्हें हाथ से गणना करना बहुत झंझटभरा होगा। इसलिए, आप Z3 को वे शर्तें बता सकते हैं जिन्हें वेरिएबल्स को पूरा करना है और यह कुछ मान (अगर संभव हों) खोज देगा।

**Some texts and examples are extracted from [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## बुनियादी ऑपरेशन

### बूलियन/And/Or/Not
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
### मॉडल प्रिंट करना
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
## मशीन अंकगणित

आधुनिक CPUs और मुख्यधारा की प्रोग्रामिंग भाषाएँ **fixed-size bit-vectors** पर अंकगणित का उपयोग करती हैं। मशीन अंकगणित Z3Py में **Bit-Vectors** के रूप में उपलब्ध है।
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
### Signed/Unsigned संख्याएँ

Z3 कुछ अंकगणितीय ऑपरेशनों के विशेष signed संस्करण प्रदान करता है जहाँ फर्क पड़ता है कि **bit-vector को signed के रूप में माना जाता है या unsigned**।

Z3Py में, ऑपरेटर **<, <=, >, >=, /, % and >>** **signed** संस्करणों के अनुरूप हैं। संबंधित **unsigned** ऑपरेटर हैं **ULT, ULE, UGT, UGE, UDiv, URem and LShR.**
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
### Bit-vector सहायक जो reversing में आम तौर पर आवश्यक होते हैं

जब आप **lifting checks from assembly or decompiler output**, कर रहे होते हैं, तो आम तौर पर बेहतर होता है कि हर इनपुट बाइट को `BitVec(..., 8)` के रूप में मॉडल किया जाए और फिर शब्दों को बिल्कुल वैसे ही पुनर्निर्मित किया जाए जैसे target code करता है। इससे गणितीय पूर्णांकों को मशीन अंकगणित के साथ मिलाने से होने वाली बग्स से बचाव होता है।
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
Some common pitfalls while translating code into constraints:

- `>>` बिट-वेक्टर के लिए एक **अंकगणितीय** राइट-शिफ्ट है। लॉजिकल `shr` निर्देश के लिए `LShR` का उपयोग करें।
- जब मूल तुलना/विभाजन **unsigned** था तो `UDiv`, `URem`, `ULT`, `ULE`, `UGT` और `UGE` का उपयोग करें।
- Widths को स्पष्ट रखें। यदि बाइनरी 8 या 16 बिट तक truncate करती है, तो `Extract` जोड़ें या `Concat` के साथ वैल्यू को फिर बनाएं बजाय इसके कि सब कुछ चुपचाप Python integers में promote कर दिया जाए।

### Functions

**व्याख्यायित फ़ंक्शि**नों जैसे अंकगणितीय जहाँ **function +** की एक **निश्चित मानक व्याख्या** होती है (यह दो संख्याएँ जोड़ता है)। **अव्याख्यित फ़ंक्शन** और constants अत्यधिक लचीले होते हैं; वे किसी भी ऐसी व्याख्या की अनुमति देते हैं जो फ़ंक्शन या constant पर लगे constraints के साथ संगत हो।

उदाहरण: f को x पर दो बार लागू करने पर परिणाम फिर से x होता है, लेकिन f को x पर एक बार लागू करने पर यह x से अलग होता है।
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
## उदाहरण

### Sudoku सॉल्वर
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
### रिवर्सिंग वर्कफ़्लो

यदि आपको **binary को symbolically execute करके constraints स्वचालित रूप से इकट्ठा करने की आवश्यकता है**, तो angr नोट्स यहाँ देखें:

{{#ref}}
angr/README.md
{{#endref}}

यदि आप पहले से ही decompiled checks को देख रहे हैं और केवल उन्हें सुलझाना चाहते हैं, तो raw Z3 आमतौर पर तेज़ और नियंत्रण में आसान होता है।

#### crackme से byte-आधारित जाँचें निकालना

crackmes और packed loaders में एक बहुत सामान्य पैटर्न होता है: उम्मीदित पासवर्ड पर बाइट समीकरणों की लंबी सूची। बाइट्स को 8-bit vectors के रूप में मॉडल करें, अक्षर सेट को प्रतिबंधित करें, और उन्हें केवल तभी चौड़ा करें जब मूल कोड उन्हें चौड़ा करे।

<details>
<summary>उदाहरण: decompiled arithmetic से एक serial check पुनर्निर्माण</summary>
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

यह शैली वास्तविक दुनिया के reversing के लिए अच्छी तरह से मेल खाती है क्योंकि यह आधुनिक writeups में प्रैक्टिकल रूप से किए जाने वाले काम से मिलती है: arithmetic/bitwise relations को recover करें, हर comparison को एक constraint में बदलें, और पूरे system को एक साथ solve करें।

#### क्रमिक समाधान `push()` / `pop()` के साथ

Reversing करते समय आप अक्सर पूरे solver को फिर से बनाये बिना कई hypotheses का परीक्षण करना चाहते हैं। `push()` एक checkpoint बनाता है और `pop()` उस checkpoint के बाद जोड़े गए constraints को हटाता है। यह तब उपयोगी होता है जब आप सुनिश्चित नहीं हैं कि कोई branch signed है या unsigned, कोई register zero-extended है या sign-extended, या जब आप disassembly से निकाले गए कई candidate constants आज़मा रहे हों।
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
#### एक से अधिक वैध इनपुट सूचीबद्ध करना

कुछ keygens, license checks, और CTF challenges जानबूझकर **कई** वैध inputs स्वीकार करते हैं। Z3 उन्हें स्वचालित रूप से सूचीबद्ध नहीं करता, लेकिन आप प्रत्येक model के बाद एक **blocking clause** जोड़ सकते हैं ताकि अगला परिणाम कम से कम एक स्थान पर भिन्न हो।
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
#### Tactics for ugly bit-vector formulas

Z3 का डिफ़ॉल्ट solver आम तौर पर पर्याप्त होता है, लेकिन decompiler-जनित फ़ॉर्मूले जिनमें बहुत सारी equalities और bit-vector rewrites होते हैं, अक्सर एक प्रारंभिक normalization pass के बाद सरल हो जाते हैं। ऐसे मामलों में tactics से एक solver बनाना उपयोगी हो सकता है:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
यह विशेष रूप से तब उपयोगी होता है जब समस्या लगभग पूरी तरह से **bit-vector + Boolean logic** होती है और आप चाहते हैं कि Z3 सूत्र को SAT backend को सौंपने से पहले स्पष्ट समानताओं को सरल करे और हटा दे।

#### CRCs और अन्य custom checkers

हाल के reversing challenges अभी भी उन constraints के लिए Z3 का उपयोग करते हैं जिन्हें brute-force करना कष्टप्रद होता है लेकिन जिन्हें मॉडल करना सरल होता है, जैसे कि CRC32 checks over ASCII-only input, mixed rotate/xor/add pipelines, या कई chained arithmetic predicates जो किसी JITed/obfuscated checker से निकाली गई हों। CRC-like समस्याओं के लिए, state को bit-vectors के रूप में रखें और search space घटाने के लिए early per-byte ASCII constraints लागू करें।

## References

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
