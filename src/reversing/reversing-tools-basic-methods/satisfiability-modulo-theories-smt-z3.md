# Muito basicamente, esta ferramenta vai nos ajudar a encontrar valores para variáveis que precisam satisfazer algumas condições, e calculá-los manualmente seria muito chato. Portanto, você pode indicar ao Z3 as condições que as variáveis precisam satisfazer e ele vai encontrar alguns valores (se possível).

{{#include ../../banners/hacktricks-training.md}}

# Operações Básicas

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
## Modelo de Impressão
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
# Aritmética de Máquina

CPUs modernas e linguagens de programação mainstream usam aritmética sobre vetores de bits de tamanho fixo. Aritmética de máquina está disponível em Z3Py como Bit-Vectors.
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
## Números Signed/Unsigned

O Z3 fornece versões signed especiais de operações aritméticas em que faz diferença se o bit-vector é tratado como signed ou unsigned. Em Z3Py, os operadores `<`, `<=`, `>`, `>=`, `/`, `%` e `>>` correspondem às versões signed. Os operadores unsigned correspondentes são `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` e `LShR`.
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
## Funções

Funções interpretadas, como aritmética, têm uma interpretação padrão fixa. Funções e constantes não interpretadas são maximamente flexíveis; elas permitem qualquer interpretação que seja consistente com as restrições sobre a função ou constante.

Exemplo: `f` aplicada duas vezes a `x` resulta em `x` novamente, mas `f` aplicada uma vez a `x` é diferente de `x`.
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

Se você precisar de execução simbólica completa sobre um binário em vez de elevar manualmente apenas algumas verificações, confira [Angr - Examples](angr/angr-examples.md). Na prática, um fluxo de trabalho muito comum é recuperar os predicados relevantes do decompiler/assembly e reconstruir apenas as restrições aritméticas ou de memória interessantes em Z3.

## Modele primeiro os dados controlados pelo usuário como bytes

Para reversing, geralmente é melhor começar com `BitVec(..., 8)` para cada byte de entrada e depois reconstruir palavras exatamente como o alvo faz. Isso preserva wrap-around, bugs de signedness, shifts, rotates e problemas de byte-order.
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
Helpers úteis ao traduzir assembly ou código de decompiler:

- `Concat`: reconstrói valores de 16/32/64 bits a partir de bytes
- `Extract`: compara words high/low ou emula masks/shifts
- `ZeroExt` / `SignExt`: modela corretamente bugs de extensão zero/sinal
- `LShR` / `RotateLeft` / `RotateRight`: comuns em crackmes, hashes e obfuscators

## Modele tabelas de memória/register com arrays

Quando uma verificação depende de `buf[i]`, lookup tables ou memória emulada, `Array` pode ser mais limpo do que criar dezenas de variáveis separadas.
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
Isso é especialmente útil quando o binário copia valores pela memória antes de validá-los, ou quando você quer modelar o efeito de algumas operações `mov`/`xor`/`add` sem executar o programa inteiro.

## Incremental solving é ótimo para branch triage

Quando você já extraiu as constraints base, use `push()` / `pop()` (ou assumptions) para testar branches alternativas sem reconstruir o solver toda vez:
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
Isto é útil ao reproduzir path conditions recuperadas de um decompiler, ou quando você quer identificar rapidamente qual comparison está tornando o modelo `unsat`.

## Optimize for nicer payloads

Uma vez que um model é satisfiable, `Optimize()` pode ajudar você a obter uma solução mais usable: por exemplo, preferir bytes imprimíveis, minimizar um componente de checksum, ou maximizar alguma structure que torne a recovered password mais fácil de digitar ou copiar.
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
## Strings/sequences para serials com muito formato

Se o alvo verifica principalmente prefixes, suffixes, substrings ou estrutura parecida com regex, constraints de `String`/`Seq` podem ser mais fáceis do que bit-vectors byte a byte:
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
No entanto, quando o binário começa a fazer aritmética, rotações, checksums ou casts sobre caracteres, geralmente é melhor voltar para bit-vectors de 8 bits.

# Exemplos

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
## Referências

* [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
* [https://microsoft.github.io/z3guide/](https://microsoft.github.io/z3guide/)
* [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
