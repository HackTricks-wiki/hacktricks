# Satisfiability Modulo Theories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

Просто кажучи, цей інструмент допоможе знайти значення змінних, які повинні задовольняти певні умови, а обчислювати їх вручну було б дуже втомливо. Тому можна вказати Z3 умови, які повинні виконувати змінні, і він знайде деякі значення (якщо це можливо).

**Деякі тексти та приклади взято з [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## Основні операції

### Булеві/And/Or/Not
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
### Друк моделі
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
## Машинна арифметика

Сучасні CPU та поширені мови програмування використовують арифметику над **bit-vectors фіксованого розміру**. Машинна арифметика доступна в Z3Py як **Bit-Vectors**.
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
### Знакові/Беззнакові числа

Z3 надає спеціальні знакові версії арифметичних операцій, де має значення, чи **бітовий вектор розглядається як знаковий чи беззнаковий**. У Z3Py оператори **<, <=, >, >=, /, % і >>** відповідають **знаковим** версіям. Відповідні **беззнакові** оператори — **ULT, ULE, UGT, UGE, UDiv, URem і LShR.**
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
### Bit-vector допоміжні засоби, які зазвичай потрібні у reversing

Коли ви **lifting checks from assembly or decompiler output**, зазвичай краще моделювати кожний вхідний байт як `BitVec(..., 8)` і потім відновлювати слова точно так, як це робить цільовий код. Це дозволяє уникнути багів, що виникають при змішуванні математичних цілих чисел з машинною арифметикою.
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
Деякі поширені підводні камені при перетворенні коду в обмеження:

- `>>` — це **арифметичний** зсув вправо для біт-векторів. Використовуйте `LShR` для логічної інструкції `shr`.
- Використовуйте `UDiv`, `URem`, `ULT`, `ULE`, `UGT` та `UGE`, коли початкове порівняння/ділення було **беззнаковим**.
- Тримайте ширини явними. Якщо бінарник усе відтинає до 8 або 16 біт, додайте `Extract` або відновіть значення за допомогою `Concat`, замість того щоб мовчки перетворювати все на цілі числа у Python.

### Functions

**Інтерпретовані функціо**ни, такі як арифметичні, де **функція +** має **фіксовану стандартну інтерпретацію** (вона додає два числа). **Неінтерпретовані функції** та константи є **максимально гнучкими**; вони дозволяють **будь-яку інтерпретацію**, яка **узгоджується** з **обмеженнями** над функцією чи константою.

Приклад: f, застосована двічі до x, дає знову x, але f, застосована один раз до x, відрізняється від x.
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
## Приклади

### Розв'язувач судоку
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
### Робочі процеси реверсингу

Якщо вам потрібно **symbolically execute the binary and collect constraints automatically**, перегляньте нотатки angr тут:

{{#ref}}
angr/README.md
{{#endref}}

Якщо ви вже переглядаєте декомпільовані перевірки і потрібно лише їх вирішити, сам Z3 зазвичай швидший і простіший у керуванні.

#### Витяг байтових перевірок із crackme

Дуже розповсюджений шаблон у crackmes та packed loaders — довгий перелік рівнянь по байтах над кандидатною пароллю. Замодельте байти як 8-бітні вектори, обмежте алфавіт і розширюйте їх тільки тоді, коли оригінальний код їх розширює.

<details>
<summary>Приклад: відтворити перевірку серійного номера з декомпільованої арифметики</summary>
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

Цей підхід добре підходить для реального reversing, оскільки відповідає тому, що сучасні writeups роблять на практиці: відновлювати арифметичні/бітові зв'язки, перетворювати кожне порівняння на обмеження і розв'язувати всю систему одразу.

#### Incremental solving with `push()` / `pop()`

Під час reversing часто хочеться перевірити кілька гіпотез без перебудови всього розв'язувача. `push()` створює контрольну точку, а `pop()` відкидає обмеження, додані після неї. Це корисно, коли ви не впевнені, чи гілка є знаковою чи беззнаковою, чи регістр нульово-розширений чи знаково-розширений, або коли ви випробовуєте кілька кандидатних констант, витягнутих з дизасемблювання.
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
#### Перелічення більше ніж одного валідного вводу

Деякі keygens, license checks, and CTF challenges навмисно допускають **багато** валідних входів. Z3 не перелічує їх автоматично, але ви можете додати **клаузу блокування** після кожної моделі, щоб змусити наступний результат відрізнятися принаймні в одній позиції.
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
#### Тактики для складних bit-vector формул

Стандартний solver Z3 зазвичай достатній, але формули, згенеровані декомпілятором, які містять багато рівностей та переписувань bit-vector, часто стають простішими після першого проходу нормалізації. У таких випадках корисно побудувати solver із використанням тактик:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
Це особливо корисно, коли задача майже повністю складається з **bit-vector + Boolean logic** і ви хочете, щоб Z3 спростив та усунув очевидні рівності перед тим, як передати формулу SAT backend'у.

#### CRCs and other custom checkers

Останні reversing challenges усе ще використовують Z3 для обмежень, які незручно перебирати brute-force, але які просто змоделювати — наприклад CRC32 checks над ASCII-only input, змішані rotate/xor/add pipelines або численні зчеплені арифметичні предикати, витягнуті з JITed/obfuscated checker. Для CRC-like задач тримайте стан як bit-vectors і застосовуйте per-byte ASCII constraints якомога раніше, щоб звузити простір пошуку.

## Посилання

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
