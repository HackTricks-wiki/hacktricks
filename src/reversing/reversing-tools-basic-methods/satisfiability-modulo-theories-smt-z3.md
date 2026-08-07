# Bardzo ogólnie rzecz biorąc, to narzędzie pomoże nam znaleźć wartości zmiennych, które muszą spełniać określone warunki, ponieważ obliczanie ich ręcznie byłoby bardzo uciążliwe. Możesz więc wskazać Z3 warunki, które muszą spełniać zmienne, a ono znajdzie pewne wartości (jeśli będzie to możliwe).

{{#include ../../banners/hacktricks-training.md}}

# Podstawowe operacje

## Wartości logiczne/And/Or/Not
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
## Liczby całkowite/Upraszczanie/Liczby rzeczywiste
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
## Model drukowania
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
# Arytmetyka maszynowa

Nowoczesne procesory i główne języki programowania używają arytmetyki na wektorach bitów o stałym rozmiarze. Arytmetyka maszynowa jest dostępna w Z3Py jako Bit-Vectors.
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
## Liczby ze znakiem/bez znaku

Z3 udostępnia specjalne wersje ze znakiem operacji arytmetycznych, w przypadku których ma znaczenie, czy wektor bitowy jest traktowany jako ze znakiem, czy bez znaku. W Z3Py operatory `<`, `<=`, `>`, `>=`, `/`, `%` i `>>` odpowiadają wersjom ze znakiem. Odpowiadające im operatory bez znaku to `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` i `LShR`.<sup>[[1]](#references)</sup>
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
## Funkcje

Funkcje interpretowane, takie jak funkcje arytmetyczne, mają ustaloną standardową interpretację. Funkcje i stałe nieinterpretowane są maksymalnie elastyczne; pozwalają na dowolną interpretację zgodną z ograniczeniami dotyczącymi funkcji lub stałej.<sup>[[1]](#references)</sup>

Przykład: dwukrotne zastosowanie `f` do `x` ponownie daje `x`, ale jednokrotne zastosowanie `f` do `x` daje wartość inną niż `x`.
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
# Wzorce ukierunkowane na reversing

Jeśli potrzebujesz pełnego symbolic execution na pliku binarnym zamiast ręcznego podnoszenia tylko kilku sprawdzeń, sprawdź [Angr - Examples](angr/angr-examples.md). W praktyce bardzo często odzyskuje się istotne predykaty z dekompilatora/assembly, a następnie odtwarza w Z3 tylko interesujące ograniczenia arytmetyczne lub ograniczenia pamięci.

## Najpierw modeluj dane kontrolowane przez użytkownika jako bajty

W reversing zazwyczaj lepiej jest zacząć od `BitVec(..., 8)` dla każdego bajtu wejściowego, a następnie odtworzyć słowa dokładnie tak, jak robi to cel. Zachowuje to zawijanie wartości, błędy związane ze znakiem, przesunięcia, rotacje i problemy z kolejnością bajtów.<sup>[[2]](#references)</sup>
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
Przydatne helpery podczas tłumaczenia kodu assembly lub dekompilatora:

- `Concat`: odbudowuje wartości 16-/32-/64-bitowe z bajtów
- `Extract`: porównuje słowa wysokie/niskie lub emuluje maski/przesunięcia
- `ZeroExt` / `SignExt`: poprawnie modeluje błędy rozszerzania z zerowaniem/ze znakiem
- `LShR` / `RotateLeft` / `RotateRight`: często używane w crackmes, hashach i obfuscatorach

## Modelowanie tabel pamięci/rejestrów za pomocą tablic

Gdy check zależy od `buf[i]`, tabel lookup lub emulowanej pamięci, `Array` może być przejrzystsze niż tworzenie dziesiątek oddzielnych zmiennych.<sup>[[3]](#references)</sup>
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
Jest to szczególnie przydatne, gdy binary kopiuje wartości między obszarami pamięci przed ich zweryfikowaniem lub gdy chcesz zamodelować efekt kilku operacji `mov`/`xor`/`add` bez uruchamiania całego programu.

## Incremental solving świetnie sprawdza się w analizie gałęzi

Gdy masz już wyodrębnione podstawowe ograniczenia, użyj `push()` / `pop()` (lub assumptions), aby testować alternatywne gałęzie bez każdorazowego tworzenia solvera od nowa:<sup>[[3]](#references)</sup>
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
Jest to przydatne podczas odtwarzania warunków ścieżki odzyskanych z dekompilatora lub gdy chcesz szybko zidentyfikować, które porównanie sprawia, że model jest `unsat`.

## Optymalizacja pod kątem wygodniejszych payloadów

Gdy model jest spełnialny, `Optimize()` może pomóc uzyskać bardziej użyteczne rozwiązanie: na przykład preferować drukowalne bajty, minimalizować komponent sumy kontrolnej lub maksymalizować strukturę, która ułatwia wpisywanie albo kopiowanie odzyskanego hasła.<sup>[[3]](#references)</sup>
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
## Łańcuchy/sekwencje dla identyfikatorów o złożonym formacie

Jeśli cel sprawdza głównie prefiksy, sufiksy, podłańcuchy lub strukturę podobną do regexów, ograniczenia `String`/`Seq` mogą być łatwiejsze niż wektory bitowe przetwarzane bajt po bajcie:<sup>[[3]](#references)</sup>
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
Jednak gdy binary zaczyna wykonywać działania arytmetyczne, rotacje, sumy kontrolne lub rzutowania na znakach, zazwyczaj lepiej wrócić do 8-bitowych bit-vectorów.

# Przykłady

## Solver Sudoku
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
## Odnośniki

- [1] [Z3Py Guide with Examples (ericpony z3py-tutorial)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Z3 Guide - Bit-Vectors theory (Microsoft z3guide)](https://microsoft.github.io/z3guide/)
- [3] [Programming Z3 (Nikolaj Bjørner, Leonardo de Moura, Lev Nachmanson, Christoph Wintersteiger)](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
