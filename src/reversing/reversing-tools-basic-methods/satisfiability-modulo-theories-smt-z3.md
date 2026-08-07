# 아주 기본적으로, 이 도구는 특정 조건을 만족해야 하는 변수의 값을 찾는 데 도움을 주며, 이를 직접 계산하는 작업은 매우 번거로울 수 있습니다. 따라서 변수들이 만족해야 하는 조건을 Z3에 지정하면, Z3가 가능한 경우 해당 값을 찾아줍니다.

{{#include ../../banners/hacktricks-training.md}}

# Basic Operations

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
## 정수/Simplify/실수
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
## 모델 출력
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
# Machine Arithmetic

Modern CPU와 mainstream programming language는 고정 크기 bit-vector에 대한 arithmetic을 사용합니다. Machine arithmetic은 Z3Py에서 Bit-Vectors로 사용할 수 있습니다.
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

Z3는 bit-vector가 signed 또는 unsigned로 처리되는지에 따라 결과가 달라지는 산술 연산의 특수한 signed 버전을 제공합니다. Z3Py에서 연산자 `<`, `<=`, `>`, `>=`, `/`, `%`, `>>`는 signed 버전에 해당합니다. 이에 대응하는 unsigned 연산자는 `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem`, `LShR`입니다.<sup>[[1]](#references)</sup>
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
## 함수

산술과 같은 해석된 함수는 고정된 표준 해석을 갖습니다. 해석되지 않은 함수와 상수는 최대한 유연하며, 해당 함수 또는 상수에 대한 제약 조건과 일관되는 모든 해석을 허용합니다.<sup>[[1]](#references)</sup>

예시: `f`를 `x`에 두 번 적용하면 다시 `x`가 되지만, `f`를 `x`에 한 번 적용한 결과는 `x`와 다릅니다.
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
# Reversing 중심 패턴

바이너리에서 몇 가지 검사만 수동으로 lifting하는 대신 전체 symbolic execution이 필요하다면 [Angr - Examples](angr/angr-examples.md)를 확인하세요. 실제로는 decompiler/assembly에서 관련 predicate를 복구한 다음, 흥미로운 산술 또는 memory constraint만 Z3에서 다시 구축하는 workflow가 매우 일반적입니다.

## user-controlled data를 먼저 bytes로 모델링하기

Reversing에서는 일반적으로 각 input byte에 `BitVec(..., 8)`을 사용해 시작한 다음, target이 수행하는 방식 그대로 word를 다시 구축하는 것이 좋습니다. 이렇게 하면 wrap-around, signedness bug, shift, rotate 및 byte-order 문제를 보존할 수 있습니다.<sup>[[2]](#references)</sup>
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
Assembly 또는 decompiler code를 번역할 때 유용한 helper:

- `Concat`: byte에서 16/32/64-bit 값을 재구성
- `Extract`: high/low word 비교 또는 mask/shift 에뮬레이션
- `ZeroExt` / `SignExt`: zero/sign extension bug를 올바르게 모델링
- `LShR` / `RotateLeft` / `RotateRight`: crackmes, hash, obfuscator에서 일반적으로 사용

## array로 memory/register table 모델링

check가 `buf[i]`, lookup table 또는 emulated memory에 의존하는 경우, 수십 개의 별도 variable을 만드는 것보다 `Array`가 더 깔끔할 수 있습니다.<sup>[[3]](#references)</sup>
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
이는 binary가 값을 검증하기 전에 memory에서 값을 복사하거나, 전체 program을 실행하지 않고 몇 가지 `mov`/`xor`/`add` 연산의 효과를 모델링하려 할 때 특히 유용합니다.

## Incremental solving은 branch triage에 유용합니다

기본 constraints를 이미 추출했다면, 매번 solver를 다시 구성하지 않고 `push()` / `pop()` (또는 assumptions)을 사용해 여러 branch를 테스트할 수 있습니다:<sup>[[3]](#references)</sup>
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
이는 decompiler에서 복구한 path conditions를 재생하거나, 어떤 comparison 때문에 model이 `unsat`이 되는지 빠르게 식별할 때 유용합니다.

## 더 나은 payload 최적화

model이 satisfiable이 되면 `Optimize()`를 사용해 더 활용하기 쉬운 solution을 얻을 수 있습니다. 예를 들어 printable bytes를 우선하거나, checksum component를 최소화하거나, 복구한 password를 더 쉽게 입력하거나 복사할 수 있도록 특정 structure를 최대화할 수 있습니다.<sup>[[3]](#references)</sup>
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
## 형식이 중요한 serial을 위한 문자열/시퀀스

대상이 주로 prefix, suffix, substring 또는 regex와 유사한 구조를 검사한다면 `String`/`Seq` 제약 조건이 byte 단위 bit-vector보다 더 간단할 수 있습니다:<sup>[[3]](#references)</sup>
```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```
하지만 binary가 문자에 대해 arithmetic, rotation, checksum 또는 cast를 수행하기 시작하면 일반적으로 8-bit bit-vector로 돌아가는 것이 더 좋습니다.

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
## 참고 자료

- [1] [예제가 포함된 Z3Py Guide (ericpony z3py-tutorial)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Z3 Guide - Bit-Vectors theory (Microsoft z3guide)](https://microsoft.github.io/z3guide/)
- [3] [Programming Z3 (Nikolaj Bjørner, Leonardo de Moura, Lev Nachmanson, Christoph Wintersteiger)](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
