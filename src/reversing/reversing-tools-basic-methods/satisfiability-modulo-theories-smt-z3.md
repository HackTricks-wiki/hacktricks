# Satisfiability Modulo Theories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

Çok temel düzeyde, bu araç belirli koşulları sağlaması gereken değişkenler için değerler bulmamıza yardımcı olur; bunları elle hesaplamak çok zahmetli olur. Bu nedenle Z3'e değişkenlerin sağlaması gereken koşulları belirtirseniz, mümkünse bazı değerler bulacaktır.

**Bazı metinler ve örnekler [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm) sitesinden alınmıştır**

## Temel İşlemler

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
### Printing Model
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
## Makine Aritmetiği

Modern işlemciler ve yaygın programlama dilleri, **fixed-size bit-vectors** üzerinde aritmetik kullanır. Makine aritmetiği Z3Py'de **Bit-Vectors** olarak mevcuttur.
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
### İşaretli/İşaretsiz Sayılar

Z3, **bit vektörünün işaretli mi yoksa işaretsiz mi olarak değerlendirildiğinin** fark yarattığı durumlarda aritmetik işlemlerin özel işaretli sürümlerini sağlar. Z3Py'de operatörler **<, <=, >, >=, /, % ve >>** işaretli sürümlere karşılık gelir. Buna karşılık gelen işaretsiz operatörler **ULT, ULE, UGT, UGE, UDiv, URem ve LShR.**
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
### Tersine mühendislikte sıkça ihtiyaç duyulan bit-vektör yardımcıları

**assembly veya decompiler çıktısından kontrolleri çıkarırken**, genellikle her giriş baytını `BitVec(..., 8)` olarak modellemek ve sonra kelimeleri hedef kodun yaptığı gibi tam olarak yeniden oluşturmak daha iyidir. Bu, matematiksel tamsayıları makine aritmetiği ile karıştırmaktan kaynaklanan hataları önler.
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
Bazı yaygın tuzaklar, kodu kısıtlamalara çevirirken:

- `>>` bit vektörleri (bit-vectors) için bir **aritmetik** sağa kaydırmadır. Mantıksal `shr` talimatı için `LShR` kullanın.
- Orijinal karşılaştırma/bölme **işaretsiz** ise `UDiv`, `URem`, `ULT`, `ULE`, `UGT` ve `UGE` kullanın.
- Genişlikleri açık tutun. Binary 8 veya 16 bite kırpılıyorsa, her şeyi sessizce Python integerlarına yükseltmek yerine `Extract` ekleyin veya değeri `Concat` ile yeniden oluşturun.

### Fonksiyonlar

**Yorumlanmış fonksiyonlar** aritmetik gibi, **function +**'nın **sabit standart yorumu** olduğu durumlarda (iki sayıyı toplar). **Yorumlanmamış fonksiyonlar** ve sabitler mümkün olduğunca esnektir; fonksiyon veya sabit üzerindeki kısıtlarla uyumlu olan herhangi bir yoruma izin verirler.

Örnek: f'in x'e iki kez uygulanması sonucunda tekrar x elde edilir, fakat f'in x'e bir kez uygulanması x'ten farklıdır.
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
## Örnekler

### Sudoku çözücü
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
### Reversing iş akışları

Eğer **ikiliyi sembolik olarak yürütmeniz ve kısıtlamaları otomatik olarak toplamanız** gerekiyorsa, angr notlarına buradan bakın:

{{#ref}}
angr/README.md
{{#endref}}

Zaten decompiled kontrollerine bakıyor ve sadece bunları çözmeniz gerekiyorsa, raw Z3 genellikle daha hızlıdır ve kontrol etmesi daha kolaydır.

#### crackme'den byte-based kontrolleri yükseltme

crackme'lerde ve packed loader'larda çok yaygın bir örüntü, aday parola üzerinde uzun bir byte denklemleri listesidir. Byte'ları 8-bit vectors olarak modelleyin, alfabeti kısıtlayın ve yalnızca orijinal kod bunları genişlettiğinde genişletin.

<details>
<summary>Örnek: decompiled arithmetic'ten bir serial check'i yeniden oluşturma</summary>
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

#### Artımlı çözümleme `push()` / `pop()` ile

Bu yaklaşım gerçek dünyadaki reversing ile iyi örtüşür çünkü modern writeups'ların pratikte yaptığına uyar: aritmetik/bit düzeyindeki ilişkileri ortaya çıkarmak, her karşılaştırmayı bir kısıta dönüştürmek ve tüm sistemi aynı anda çözmek.

Reversing sırasında genellikle tüm solver'ı yeniden oluşturmak zorunda kalmadan birden fazla hipotezi test etmek istersiniz. `push()` bir checkpoint oluşturur ve `pop()` o checkpoint'ten sonra eklenen kısıtları atar. Bu, bir branch'in signed mı yoksa unsigned mı olduğu, bir register'ın zero-extended mı yoksa sign-extended mı olduğu konusunda emin olmadığınızda veya disassembly'den çıkarılan birkaç aday sabiti denerken faydalıdır.
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
#### Birden fazla geçerli girdiyi listeleme

Bazı keygens, license checks ve CTF challenges kasıtlı olarak **birçok** geçerli girdi kabul eder. Z3 bunları otomatik olarak sıralamaz, fakat her modelden sonra bir sonraki sonucun en az bir pozisyonda farklı olmasını zorlamak için bir **engelleme kısıtı** ekleyebilirsiniz.
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
#### Çirkin bit-vector formülleri için tactics

Z3'in varsayılan solver'ı genellikle yeterlidir, ancak decompiler tarafından üretilen ve çok sayıda eşitlik ile bit-vector yeniden yazımı içeren formüller, ilk bir normalizasyon geçişinden sonra genellikle daha kolay hale gelir. Bu durumlarda tactics kullanarak bir solver oluşturmak faydalı olabilir:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
Bu, problem neredeyse tamamen **bit-vector + Boolean logic** olduğunda ve formülü SAT backend'e vermeden önce Z3'ün açık eşitlikleri basitleştirip ortadan kaldırmasını istediğinizde özellikle faydalıdır.

#### CRCs ve diğer özel denetleyiciler

Son reversing zorlukları hâlâ Z3'ü, brute-force ile çözülmesi zahmetli ama modellemesi basit olan kısıtlar için kullanıyor; örneğin CRC32 checks over ASCII-only input, mixed rotate/xor/add pipelines, veya JITed/obfuscated checker'dan çıkarılan birçok zincirlenmiş aritmetik predikat. CRC-benzeri problemlerde, durumu bit-vectors olarak tutun ve arama alanını daraltmak için her bayt için ASCII kısıtlarını erken uygulayın.

## Referanslar

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
