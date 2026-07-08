# Çok temel olarak, bu araç, bazı koşulları sağlaması gereken değişkenler için değerler bulmamıza yardımcı olacak ve bunları elle hesaplamak çok can sıkıcı olacaktır. Bu nedenle, Z3'e değişkenlerin sağlaması gereken koşulları belirtebilirsiniz ve o da bazı değerler bulacaktır (eğer mümkünse).

{{#include ../../banners/hacktricks-training.md}}

# Temel İşlemler

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
## Modeli Yazdırma
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
# Makine Aritmetiği

Modern CPU'lar ve ana akım programlama dilleri, sabit boyutlu bit-vektörler üzerinde aritmetik kullanır. Makine aritmetiği, Z3Py'de Bit-Vectors olarak mevcuttur.
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

Z3, bir bit-vector'ın signed mı unsigned mı olarak ele alınmasının fark yarattığı aritmetik işlemlerin özel signed sürümlerini sağlar. Z3Py'de `<`, `<=`, `>`, `>=`, `/`, `%` ve `>>` operatörleri signed sürümlere karşılık gelir. Karşılık gelen unsigned operatörler `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` ve `LShR`'dir.
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
## Fonksiyonlar

Aritmetik gibi yorumlanan fonksiyonların sabit bir standart yorumu vardır. Yorumlanmamış fonksiyonlar ve sabitler ise en esnek haldedir; fonksiyon ya da sabit üzerindeki kısıtlarla tutarlı olan herhangi bir yoruma izin verirler.

Örnek: `f`'in `x`'e iki kez uygulanması yine `x` sonucunu verir, ancak `f`'in `x`'e bir kez uygulanması `x`'ten farklıdır.
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

Bir binary üzerinde manuel olarak yalnızca birkaç kontrolü yükseltmek yerine tam symbolic execution gerekiyorsa, [Angr - Examples](angr/angr-examples.md) kısmına bakın. Pratikte çok yaygın bir workflow, ilgili predicates'leri decompiler/assembly’den geri çıkarmak ve yalnızca ilginç arithmetic veya memory constraints'leri Z3 içinde yeniden oluşturmaktır.

## Model user-controlled data as bytes first

Reversing için, genellikle her input byte için `BitVec(..., 8)` ile başlamak ve ardından kelimeleri target’ın yaptığı şekilde aynen yeniden kurmak daha iyidir. Bu yaklaşım wrap-around, signedness bug'ları, shift, rotate ve byte-order sorunlarını korur.
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
Assembly veya decompiler kodunu çevirirken yararlı yardımcılar:

- `Concat`: bytes'tan 16/32/64-bit değerleri yeniden oluşturur
- `Extract`: high/low words karşılaştırır veya maskeleri/shiftleri taklit eder
- `ZeroExt` / `SignExt`: zero/sign extension bug'larını doğru şekilde modellemeye yarar
- `LShR` / `RotateLeft` / `RotateRight`: crackmes, hashes ve obfuscators içinde yaygındır

## Model memory/register tables with arrays

Bir kontrol `buf[i]`, lookup tables veya emulated memory'ye bağlıysa, `Array` onlarca ayrı değişken oluşturmaktan daha temiz olabilir.
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
Bu, özellikle binary değerleri doğrulamadan önce memory içinde kopyaladığında veya tüm programı çalıştırmadan birkaç `mov`/`xor`/`add` operasyonunun etkisini modellemek istediğinde çok kullanışlıdır.

## Incremental solving branch triage için harikadır

Base constraints zaten çıkardıysan, her seferinde solver’ı yeniden oluşturmadan alternatif branch’leri test etmek için `push()` / `pop()` (veya assumptions) kullan:
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
Bu, bir decompiler'dan geri kazanılan path conditions'ları replay ederken veya modelin `unsat` olmasına hangi comparison'ın neden olduğunu hızlıca belirlemek istediğinizde faydalıdır.

## Daha güzel payloads için optimize et

Bir model satisfiable olduktan sonra, `Optimize()` daha kullanılabilir bir solution elde etmenize yardımcı olabilir: örneğin printable bytes'ları tercih etmek, bir checksum component'ini minimize etmek veya geri kazanılan password'ü yazmayı ya da kopyalamayı daha kolay hale getiren bir structure'ı maximize etmek.
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
## Format-ağır seriallar için String/sequences

Hedef esas olarak prefix, suffix, substring veya regex benzeri yapıyı kontrol ediyorsa, `String`/`Seq` constraints byte-byte bit-vector’lardan daha kolay olabilir:
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
Ancak, binary aritmetik, döndürmeler, checksum’lar veya karakterler üzerinde cast işlemleri yapmaya başladığında, genellikle 8-bit bit-vectors’a geri dönmek daha iyidir.

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
## Referanslar

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
* [https://microsoft.github.io/z3guide/](https://microsoft.github.io/z3guide/)
* [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
