# Básicamente, esta herramienta nos ayudará a encontrar valores para variables que deben satisfacer ciertas condiciones, y calcularlos manualmente sería muy tedioso. Por lo tanto, puedes indicar a Z3 las condiciones que deben satisfacer las variables, y encontrará algunos valores (si es posible).

{{#include ../../banners/hacktricks-training.md}}

# Operaciones básicas

## Booleanos/Y/O/No
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
## Modelo de impresión
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
# Aritmética de máquina

Las CPU modernas y los lenguajes de programación principales utilizan aritmética sobre vectores de bits de tamaño fijo. La aritmética de máquina está disponible en Z3Py como Bit-Vectors.
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
## Números con signo/sin signo

Z3 proporciona versiones especiales con signo de las operaciones aritméticas cuando importa si el bit-vector se trata como con signo o sin signo. En Z3Py, los operadores `<`, `<=`, `>`, `>=`, `/`, `%` y `>>` corresponden a las versiones con signo. Los operadores sin signo correspondientes son `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` y `LShR`.<sup>[[1]](#references)</sup>
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
## Funciones

Las funciones interpretadas, como las aritméticas, tienen una interpretación estándar fija. Las funciones y constantes no interpretadas son máximamente flexibles; permiten cualquier interpretación que sea coherente con las restricciones sobre la función o constante.<sup>[[1]](#references)</sup>

Ejemplo: aplicar `f` dos veces a `x` da como resultado `x` de nuevo, pero aplicar `f` una vez a `x` es diferente de `x`.
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
# Patrones orientados al reversing

Si necesitas una ejecución simbólica completa sobre un binario en lugar de elevar manualmente solo unas pocas comprobaciones, consulta [Angr - Examples](angr/angr-examples.md). En la práctica, un flujo de trabajo muy común consiste en recuperar los predicados relevantes del decompiler/assembly y reconstruir únicamente las restricciones aritméticas o de memoria interesantes en Z3.

## Modela primero los datos controlados por el usuario como bytes

Para reversing, normalmente es mejor comenzar con `BitVec(..., 8)` para cada byte de entrada y después reconstruir las palabras exactamente como lo hace el objetivo. Esto conserva el wrap-around, los errores de signo, los desplazamientos, las rotaciones y los problemas de orden de bytes.<sup>[[2]](#references)</sup>
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
Ayudantes útiles al traducir código de assembly o decompilado:

- `Concat`: reconstruye valores de 16/32/64 bits a partir de bytes
- `Extract`: compara palabras altas/bajas o emula máscaras/desplazamientos
- `ZeroExt` / `SignExt`: modela correctamente los bugs de extensión con ceros/signo
- `LShR` / `RotateLeft` / `RotateRight`: comunes en crackmes, hashes y obfuscators

## Modela tablas de memoria/registros con arrays

Cuando un check depende de `buf[i]`, tablas de búsqueda o memoria emulada, `Array` puede ser más limpio que crear docenas de variables.<sup>[[3]](#references)</sup>
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
Esto resulta especialmente útil cuando el binario copia valores por la memoria antes de validarlos, o cuando quieres modelar el efecto de unas pocas operaciones `mov`/`xor`/`add` sin ejecutar todo el programa.

## La resolución incremental es ideal para clasificar ramas

Cuando ya hayas extraído las restricciones base, usa `push()` / `pop()` (o assumptions) para probar ramas alternativas sin reconstruir el solver cada vez:<sup>[[3]](#references)</sup>
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
Esto resulta útil al reproducir condiciones de ruta recuperadas de un decompilador o cuando quieres identificar rápidamente qué comparación está haciendo que el modelo sea `unsat`.

## Optimizar para obtener payloads más prácticos

Una vez que un modelo es satisfacible, `Optimize()` puede ayudarte a obtener una solución más usable: por ejemplo, preferir bytes imprimibles, minimizar un componente de checksum o maximizar alguna estructura que facilite escribir o copiar la contraseña recuperada.<sup>[[3]](#references)</sup>
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
## Strings/sequences para seriales con mucho formato

Si el objetivo comprueba principalmente prefijos, sufijos, subcadenas o estructuras similares a regex, las restricciones de `String`/`Seq` pueden ser más sencillas que los bit-vectors byte a byte:<sup>[[3]](#references)</sup>
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
Sin embargo, cuando el binario comienza a realizar operaciones aritméticas, rotaciones, checksums o conversiones de tipos sobre caracteres, normalmente es mejor volver a los bit-vectors de 8 bits.

# Ejemplos

## Solucionador de Sudoku
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
## Referencias

- [1] [Guía de Z3Py con ejemplos (ericpony z3py-tutorial)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Guía de Z3 - teoría de Bit-Vectors (Microsoft z3guide)](https://microsoft.github.io/z3guide/)
- [3] [Programación de Z3 (Nikolaj Bjørner, Leonardo de Moura, Lev Nachmanson, Christoph Wintersteiger)](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
