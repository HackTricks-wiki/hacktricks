# Spełnialność względem teorii (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

Bardzo prosto, to narzędzie pomoże nam znaleźć wartości dla zmiennych, które muszą spełniać określone warunki, a obliczanie ich ręcznie byłoby bardzo uciążliwe. Możesz więc wskazać Z3 warunki, które zmienne muszą spełnić, a on znajdzie jakieś wartości (jeśli to możliwe).

**Niektóre teksty i przykłady zostały zaczerpnięte z [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## Podstawowe operacje

### Booleany/And/Or/Not
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
### Wypisywanie modelu
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
## Arytmetyka maszynowa

Współczesne procesory i mainstreamowe języki programowania używają arytmetyki na **wektorach bitowych o stałym rozmiarze**. Arytmetyka maszynowa jest dostępna w Z3Py jako **Bit-Vectors**.
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
### Liczby ze znakiem/bez znaku

Z3 udostępnia specjalne wersje operacji arytmetycznych, w których ma znaczenie, czy **bit-vector** jest traktowany jako ze znakiem czy bez znaku. W Z3Py operatory **<, <=, >, >=, /, % i >>** odpowiadają wersjom **ze znakiem**. Odpowiadające wersje **bez znaku** to **ULT, ULE, UGT, UGE, UDiv, URem i LShR.**
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
### Bit-vector helpers commonly needed in reversing

Kiedy wykonujesz **lifting checks from assembly or decompiler output**, zwykle lepiej jest zamodelować każdy bajt wejściowy jako `BitVec(..., 8)`, a następnie odbudować słowa dokładnie tak, jak robi to kod docelowy. Pozwala to uniknąć błędów wynikających z mieszania liczb całkowitych w sensie matematycznym z arytmetyką maszynową.
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
Typowe pułapki podczas tłumaczenia kodu na ograniczenia:

- `>>` jest **arytmetycznym** przesunięciem w prawo dla wektorów bitowych. Użyj `LShR` dla **logicznej** instrukcji `shr`.
- Użyj `UDiv`, `URem`, `ULT`, `ULE`, `UGT` and `UGE` gdy oryginalne porównanie/dzielenie było **bez znaku**.
- Wyraźnie określaj szerokości. Jeśli binarka obcina do 8 lub 16 bitów, dodaj `Extract` lub odbuduj wartość za pomocą `Concat` zamiast potajemnie promować wszystko do liczb całkowitych w Pythonie.

### Funkcje

**Funkcje interpretow**ane takie jak arytmetyka, gdzie **funkcja +** ma **ustaloną standardową interpretację** (dodaje dwie liczby). **Funkcje nieinterpretowane** i stałe są **maksymalnie elastyczne**; pozwalają na **dowolną interpretację**, która jest **zgodna** z **ograniczeniami** dotyczącymi funkcji lub stałej.

Przykład: f zastosowana dwukrotnie do x daje z powrotem x, ale f zastosowana raz do x różni się od x.
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
## Przykłady

### Rozwiązywacz Sudoku
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

Jeśli potrzebujesz **symbolically execute the binary and collect constraints automatically**, sprawdź notatki angr tutaj:

{{#ref}}
angr/README.md
{{#endref}}

Jeśli już patrzysz na dekompilowane sprawdzenia i potrzebujesz je tylko rozwiązać, raw Z3 jest zwykle szybsze i łatwiejsze do kontrolowania.

#### Wyodrębnianie sprawdzeń opartych na bajtach z crackme

Bardzo powszechnym wzorcem w crackmes i packed loaders jest długa lista równań bajtowych dotyczących kandydującego hasła. Modeluj bajty jako wektory 8-bitowe, ogranicz alfabet i rozszerzaj je tylko wtedy, gdy oryginalny kod je rozszerza.

<details>
<summary>Przykład: odbuduj sprawdzenie serialu z dekompilowanej arytmetyki</summary>
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

Ten styl dobrze pasuje do real-world reversing, ponieważ odpowiada temu, co nowoczesne writeups robią w praktyce: odtwarzać relacje arytmetyczne/bitowe, zamieniać każdą comparison na constraint i rozwiązywać cały system naraz.

#### Rozwiązywanie inkrementalne z `push()` / `pop()`

Podczas reversing często chcesz przetestować kilka hipotez bez przebudowy całego solvera. `push()` tworzy checkpoint, a `pop()` usuwa constraints dodane po tym checkpointcie. To jest przydatne, gdy nie jesteś pewien, czy branch jest signed czy unsigned, czy register jest zero-extended czy sign-extended, lub gdy próbujesz kilku candidate constants wyekstrahowanych z disassembly.
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
#### Wypisywanie więcej niż jednego poprawnego wejścia

Niektóre keygens, license checks i CTF challenges celowo dopuszczają **wiele** poprawnych wejść. Z3 nie wypisuje ich automatycznie, ale możesz dodać **blocking clause** po każdym modelu, aby wymusić, że następny wynik różni się w co najmniej jednej pozycji.
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
#### Taktyki dla problematycznych formuł bit-vector

Domyślny solver Z3 zwykle wystarcza, ale formuły wygenerowane przez dekompilator zawierające wiele równości i przekształceń bit-vector często stają się prostsze po pierwszym przebiegu normalizacyjnym. W takich przypadkach przydatne może być zbudowanie solvera z użyciem taktyk:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
To jest szczególnie przydatne, gdy problem jest niemal w całości oparty na **bit-vector + Boolean logic** i chcesz, aby Z3 uprościł i wyeliminował oczywiste równości, zanim przekaże formułę do SAT backend.

#### CRCs i inne niestandardowe checkery

Najnowsze wyzwania z reversing wciąż używają Z3 do constraints, które trudno rozwiązać metodą brute-force, ale proste do zamodelowania — na przykład CRC32 checks dla ASCII-only input, mixed rotate/xor/add pipelines, albo wiele powiązanych predykatów arytmetycznych wyodrębnionych z JITed/obfuscated checkera. W zadaniach typu CRC-like trzymaj stan jako bit-vectors i zastosuj per-byte ASCII constraints możliwie wcześnie, aby zawęzić przestrzeń przeszukiwania.

## Referencje

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
