# Satisfacibilidad Módulo de Teorías (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

Básicamente, esta herramienta nos ayuda a encontrar valores para variables que deben satisfacer ciertas condiciones, y calcularlos a mano sería muy tedioso. Por lo tanto, puedes indicarle a Z3 las condiciones que deben cumplir las variables y él encontrará algunos valores (si es posible).

**Algunos textos y ejemplos se extraen de [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## Operaciones básicas

### Booleanos/And/Or/Not
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
### Imprimiendo el modelo
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
## Aritmética de máquina

Las CPUs modernas y los lenguajes de programación más comunes usan aritmética sobre **fixed-size bit-vectors**. La aritmética de máquina está disponible en Z3Py como **Bit-Vectors**.
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
### Números con signo/sin signo

Z3 proporciona versiones especiales con signo de las operaciones aritméticas en las que importa si el **vector de bits se trata como con signo o sin signo**. En Z3Py, los operadores **<, <=, >, >=, /, % y >>** corresponden a las versiones **con signo**. Los operadores correspondientes **sin signo** son **ULT, ULE, UGT, UGE, UDiv, URem y LShR.**
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
### Auxiliares de bit-vector comúnmente necesarios en reversing

Cuando estés **lifting checks from assembly or decompiler output**, suele ser mejor modelar cada byte de entrada como `BitVec(..., 8)` y luego reconstruir las palabras exactamente como lo hace el código objetivo. Esto evita bugs causados por mezclar enteros matemáticos con la aritmética de la máquina.
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
Algunas trampas comunes al traducir código a restricciones:

- `>>` es un desplazamiento a la derecha **aritmético** para bit-vectors. Usa `LShR` para la instrucción `shr` lógica.
- Usa `UDiv`, `URem`, `ULT`, `ULE`, `UGT` y `UGE` cuando la comparación/división original era **sin signo**.
- Mantén los anchos explícitos. Si el binario trunca a 8 o 16 bits, añade `Extract` o reconstruye el valor con `Concat` en lugar de promover silenciosamente todo a enteros de Python.

### Funciones

**Funciones interpretadas** como las aritméticas donde la **función +** tiene una **interpretación estándar fija** (suma dos números). Las **funciones no interpretadas** y las constantes son **máximamente flexibles**; permiten **cualquier interpretación** que sea **consistente** con las **restricciones** sobre la función o la constante.

Ejemplo: f aplicado dos veces a x resulta en x de nuevo, pero f aplicado una vez a x es diferente de x.
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
## Ejemplos

### Solucionador de Sudoku
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
### Flujos de trabajo de reversing

Si necesitas **ejecutar simbólicamente el binario y recopilar las restricciones automáticamente**, consulta las notas de angr aquí:

{{#ref}}
angr/README.md
{{#endref}}

Si ya estás mirando las comprobaciones descompiladas y solo necesitas resolverlas, raw Z3 suele ser más rápido y más fácil de controlar.

#### Extraer comprobaciones basadas en bytes de un crackme

Un patrón muy común en crackmes y packed loaders es una larga lista de ecuaciones de bytes sobre una contraseña candidata. Modela los bytes como vectores de 8 bits, restringe el alfabeto y solo amplíalos cuando el código original los amplíe.

<details>
<summary>Ejemplo: reconstruir un serial check a partir de aritmética descompilada</summary>
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

Este enfoque encaja bien con el reversing del mundo real porque coincide con lo que hacen los writeups modernos en la práctica: recuperar las relaciones aritméticas/bitwise, convertir cada comparación en una constraint y resolver todo el sistema de una vez.

#### Resolución incremental con `push()` / `pop()`

Mientras haces reversing, a menudo querrás probar varias hipótesis sin reconstruir todo el solver. `push()` crea un checkpoint y `pop()` descarta las constraints añadidas después de ese checkpoint. Esto es útil cuando no estás seguro de si una branch es signed u unsigned, si un registro está zero-extended o sign-extended, o cuando estás probando varias constantes candidatas extraídas del disassembly.
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
#### Enumerar más de una entrada válida

Algunos keygens, comprobaciones de licencia y retos CTF admiten intencionalmente **muchas** entradas válidas. Z3 no las enumera automáticamente, pero puedes añadir una **cláusula de bloqueo** después de cada modelo para forzar que el siguiente resultado difiera en al menos una posición.
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
#### Tactics para fórmulas de bit-vector complicadas

El solver por defecto de Z3 suele ser suficiente, pero decompiler-generated formulas con muchas igualdades y reescrituras de bit-vector a menudo se vuelven más manejables después de una primera pasada de normalización. En esos casos puede ser útil construir un solver a partir de tactics:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
Esto es especialmente útil cuando el problema es casi enteramente **bit-vector + Boolean logic** y quieres que Z3 simplifique y elimine igualdades obvias antes de pasar la fórmula al SAT backend.

#### CRCs y otros checkers personalizados

Desafíos recientes de reversing todavía usan Z3 para constraints que son molestos de brute-force pero sencillos de modelar, como CRC32 checks sobre input ASCII-only, pipelines mixtos rotate/xor/add, o muchos predicados aritméticos encadenados extraídos de un checker JITed/obfuscated. Para problemas tipo CRC, mantén el estado como bit-vectors y aplica restricciones ASCII por byte desde el inicio para reducir el search space.

## Referencias

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
