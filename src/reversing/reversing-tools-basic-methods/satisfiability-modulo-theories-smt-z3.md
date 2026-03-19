# Satisfiability Modulo Theories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

De forma bem básica, esta ferramenta nos ajuda a encontrar valores para variáveis que precisam satisfazer certas condições — calcular isso manualmente é muito trabalhoso. Portanto, você pode indicar ao Z3 as condições que as variáveis devem satisfazer e ele encontrará alguns valores (se possível).

**Alguns textos e exemplos foram extraídos de [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## Operações Básicas

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
### Imprimindo o Modelo
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
## Aritmética de Máquina

CPUs modernas e as principais linguagens de programação usam aritmética sobre **fixed-size bit-vectors**. A aritmética de máquina está disponível em Z3Py como **Bit-Vectors**.
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
### Números com sinal/sem sinal

Z3 fornece versões especiais com sinal das operações aritméticas onde faz diferença se o **bit-vector é tratado como com sinal ou sem sinal**. No Z3Py, os operadores **<, <=, >, >=, /, % e >>** correspondem às versões **com sinal**. As correspondentes versões **sem sinal** são **ULT, ULE, UGT, UGE, UDiv, URem e LShR.**
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
### Bit-vector helpers comumente necessários em reversing

Quando você está **lifting checks from assembly or decompiler output**, geralmente é melhor modelar cada byte de entrada como um `BitVec(..., 8)` e então reconstruir palavras exatamente como o código alvo faz. Isso evita bugs causados por misturar inteiros matemáticos com aritmética de máquina.
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
Algumas armadilhas comuns ao traduzir código para restrições:

- `>>` é um deslocamento à direita **aritmético** para vetores de bits. Use `LShR` para a instrução lógica `shr`.
- Use `UDiv`, `URem`, `ULT`, `ULE`, `UGT` e `UGE` quando a comparação/divisão original foi **sem sinal**.
- Mantenha as larguras explícitas. Se o binário trunca para 8 ou 16 bits, adicione `Extract` ou reconstrua o valor com `Concat` em vez de promover silenciosamente tudo para inteiros do Python.

### Funções

**Funções interpretad**as tais como aritmética onde a **função +** tem uma **interpretação padrão fixa** (ela soma dois números). **Funções não interpretadas** e constantes são **maximamente flexíveis**; elas permitem **qualquer interpretação** que seja **consistente** com as **restrições** sobre a função ou constante.

Exemplo: f aplicado duas vezes a x resulta em x novamente, mas f aplicado uma vez a x é diferente de x.
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
## Exemplos

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
### Fluxos de trabalho de Reversing

Se você precisa **executar simbolicamente o binário e coletar restrições automaticamente**, consulte as notas do angr aqui:

{{#ref}}
angr/README.md
{{#endref}}

Se você já está examinando as checagens decompiladas e só precisa resolvê-las, o Z3 puro costuma ser mais rápido e mais fácil de controlar.

#### Lifting checagens baseadas em bytes de um crackme

Um padrão muito comum em crackmes e packed loaders é uma longa lista de equações por byte sobre uma senha candidata. Modele bytes como vetores de 8 bits, restrinja o alfabeto e só os alargue quando o código original os alargar.

<details>
<summary>Exemplo: reconstruir um serial check a partir de aritmética decompilada</summary>
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

This style maps well to real-world reversing because it matches what modern writeups do in practice: recover the arithmetic/bitwise relations, turn each comparison into a constraint, and solve the whole system at once.

#### Incremental solving with `push()` / `pop()`

Enquanto faz reversing, você frequentemente quer testar várias hipóteses sem reconstruir todo o solver. `push()` cria um checkpoint e `pop()` descarta as constraints adicionadas após esse checkpoint. Isso é útil quando você não tem certeza se um branch é signed ou unsigned, se um register está zero-extended ou sign-extended, ou quando está tentando várias constantes candidatas extraídas da disassembly.
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
#### Enumerando mais de uma entrada válida

Alguns keygens, license checks e desafios CTF aceitam intencionalmente **muitas** entradas válidas. Z3 não as enumera automaticamente, mas você pode adicionar uma **blocking clause** após cada model para forçar o próximo resultado a diferir em pelo menos uma posição.
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
#### Tactics para fórmulas bit-vector problemáticas

O solver padrão do Z3 normalmente é suficiente, mas fórmulas decompiler-generated com muitas igualdades e reescritas de bit-vector frequentemente ficam mais fáceis após uma primeira passagem de normalização. Nesses casos, pode ser útil construir um solver a partir de tactics:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
Isto é especialmente útil quando o problema é quase inteiramente **bit-vector + Boolean logic** e você quer que o Z3 simplifique e elimine igualdades óbvias antes de passar a fórmula para o backend SAT.

#### CRCs e outros custom checkers

Desafios recentes de reversing ainda usam Z3 para restrições que são cansativas de brute-force mas diretas de modelar, como checagens CRC32 sobre entrada ASCII-only, pipelines mistos rotate/xor/add, ou muitos predicados aritméticos encadeados extraídos de um checker JITed/obfuscated. Para problemas do tipo CRC, mantenha o estado como bit-vectors e aplique restrições ASCII por byte cedo para reduzir o espaço de busca.

## Referências

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
