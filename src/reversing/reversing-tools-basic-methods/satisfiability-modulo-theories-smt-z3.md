# Çok temel olarak, bu araç bazı koşulları sağlaması gereken değişkenler için değerler bulmamıza yardımcı olur; bu değerleri elle hesaplamak oldukça zahmetli olabilir. Bu nedenle, değişkenlerin sağlaması gereken koşulları Z3'e belirtebilirsiniz; Z3 de mümkünse bazı değerler bulur.

{{#include ../../banners/hacktricks-training.md}}

# Temel İşlemler

## Boolean'lar/And/Or/Not

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

## Tamsayılar/Sadeleştirme/Gerçel Sayılar

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

Modern CPU'lar ve yaygın programlama dilleri, sabit boyutlu bit vektörleri üzerinde aritmetik işlemler kullanır. Makine aritmetiği, Z3Py'de Bit-Vectors olarak kullanılabilir.

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

## İşaretli/İşaretsiz Sayılar

Z3, bit-vektörünün işaretli mi yoksa işaretsiz mi ele alındığına göre farklılık gösteren aritmetik işlemlerin özel işaretli sürümlerini sunar. Z3Py'de `<`, `<=`, `>`, `>=`, `/`, `%` ve `>>` operatörleri işaretli sürümlere karşılık gelir. Bunlara karşılık gelen işaretsiz operatörler `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` ve `LShR`'dir.<sup>[[1]](#references)</sup>

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

Aritmetik gibi yorumlanan fonksiyonların sabit bir standart yorumu vardır. Yorumlanmamış fonksiyonlar ve sabitler mümkün olduğunca esnektir; fonksiyon veya sabit üzerindeki kısıtlamalarla tutarlı olan herhangi bir yoruma izin verirler.<sup>[[1]](#references)</sup>

Örnek: `f`'nin `x`'e iki kez uygulanması yine `x` sonucunu verir, ancak `f`'nin `x`'e bir kez uygulanmasının sonucu `x`'ten farklıdır.

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

# Reversing Odaklı Örüntüler

Bir binary üzerinde yalnızca birkaç denetimi elle kaldırmak yerine tam sembolik yürütme gerekiyorsa [Angr - Examples](angr/angr-examples.md) sayfasına göz atın. Pratikte yaygın bir iş akışı, decompiler/assembly'den ilgili yüklemleri çıkarmak ve yalnızca ilgi çekici aritmetik veya bellek kısıtlarını Z3'te yeniden oluşturmaktır.

## Önce kullanıcı denetimindeki verileri bayt olarak modelleyin

Reversing için genellikle her girdi baytı için `BitVec(..., 8)` ile başlamak ve ardından kelimeleri hedefin yaptığı gibi yeniden oluşturmaktır. Bu, taşmaları, signedness hatalarını, kaydırmaları, döndürmeleri ve bayt sıralaması sorunlarını korur.<sup>[[2]](#references)</sup>

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

Assembly veya decompiler kodunu çevirirken kullanışlı yardımcılar:

- `Concat`: baytlardan 16/32/64 bitlik değerleri yeniden oluşturur
- `Extract`: üst/alt sözcükleri karşılaştırır veya maske/kaydırma işlemlerini taklit eder
- `ZeroExt` / `SignExt`: sıfır/işaret genişletme hatalarını doğru şekilde modeller
- `LShR` / `RotateLeft` / `RotateRight`: crackme'lerde, hash'lerde ve obfuscator'larda sık kullanılır

## Bellek/register tablolarını dizilerle modelleme

Bir kontrol `buf[i]`, lookup table'lar veya emüle edilmiş belleğe bağlıysa, `Array` kullanmak onlarca ayrı değişken oluşturmaktan daha temiz olabilir.<sup>[[3]](#references)</sup>

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

Bu, özellikle binary değerleri doğrulamadan önce bellekte kopyalıyorsa veya programın tamamını çalıştırmadan birkaç `mov`/`xor`/`add` işleminin etkisini modellemek istiyorsanız çok kullanışlıdır.

## Artımlı çözümleme, branch analizi için idealdir

Temel kısıtları zaten çıkardıysanız, her seferinde solver'ı yeniden oluşturmadan alternatif branch'leri test etmek için `push()` / `pop()` (veya varsayımlar) kullanın:<sup>[[3]](#references)</sup>

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

Bu, bir decompiler'dan elde edilen path condition'ları yeniden yürütürken veya modelin `unsat` olmasına hangi karşılaştırmanın neden olduğunu hızlıca belirlemek istediğinizde kullanışlıdır.

## Daha kullanışlı payload'lar için optimize edin

Bir model karşılanabilir olduğunda, `Optimize()` daha kullanışlı bir çözüm bulmanıza yardımcı olabilir: örneğin yazdırılabilir baytları tercih edebilir, bir checksum bileşenini minimize edebilir veya elde edilen parolanın yazılmasını ya da kopyalanmasını kolaylaştıran bir yapıyı maksimize edebilirsiniz.<sup>[[3]](#references)</sup>

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

## Biçim ağırlıklı seri numaraları için dizgeler/sıralar

Hedef temel olarak önekleri, sonekleri, alt dizgeleri veya regex benzeri yapıları denetliyorsa, `String`/`Seq` kısıtları bayt bayt bit vektörlerinden daha kolay olabilir:<sup>[[3]](#references)</sup>

```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```

Ancak binary, karakterler üzerinde aritmetik, döndürme, checksum veya tür dönüştürme işlemleri yapmaya başladığında genellikle 8 bitlik bit-vektörlere geri dönmek daha iyidir.

# Örnekler

## Sudoku çözücü

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

- [1] [Z3Py Rehberi, Örneklerle (ericpony z3py-tutorial)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Z3 Rehberi - Bit-Vektörleri teorisi (Microsoft z3guide)](https://microsoft.github.io/z3guide/)
- [3] [Z3 Programlama (Nikolaj Bjørner, Leonardo de Moura, Lev Nachmanson, Christoph Wintersteiger)](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
