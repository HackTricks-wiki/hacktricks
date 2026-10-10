# 아주 기본적으로, 이 도구는 특정 조건을 만족해야 하는 변수의 값을 찾는 데 도움을 줍니다. 이 값을 손으로 계산하는 것은 매우 번거롭습니다. 따라서 변수들이 만족해야 하는 조건을 Z3에 지정하면, 가능한 경우 Z3가 값을 찾아줍니다.

{{#include ../../banners/hacktricks-training.md}}

# 기본 연산

## 불리언/And/Or/Not

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

## 출력 모델

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

# 기계 산술

최신 CPU와 주류 프로그래밍 언어는 고정 크기 비트 벡터에 대한 산술을 사용합니다. Z3Py에서는 Bit-Vectors를 사용할 수 있습니다.

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

## 부호 있는/부호 없는 수

Z3는 비트 벡터를 부호 있는 값으로 취급하는지 부호 없는 값으로 취급하는지에 따라 결과가 달라지는 산술 연산의 부호 있는 버전을 제공합니다. Z3Py에서 연산자 `<`, `<=`, `>`, `>=`, `/`, `%`, `>>`는 부호 있는 버전에 해당합니다. 이에 대응하는 부호 없는 연산자는 `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem`, `LShR`입니다.<sup>[[1]](#references)</sup>

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

산술 연산과 같은 해석 함수는 표준 해석이 고정되어 있습니다. 비해석 함수와 상수는 최대한 유연하며, 함수나 상수에 부과된 제약 조건을 만족하는 모든 해석을 허용합니다.<sup>[[1]](#references)</sup>

예: `f`를 `x`에 두 번 적용하면 다시 `x`가 되지만, 한 번 적용한 결과는 `x`와 다릅니다.

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

바이너리에서 몇 가지 검사만 직접 lifting하는 대신 전체 symbolic execution이 필요하다면 [Angr - Examples](angr/angr-examples.md)를 확인하세요. 실제로는 decompiler/assembly에서 관련 predicate를 찾아내고, 흥미로운 산술 또는 메모리 제약만 Z3에서 다시 구성하는 방식이 매우 흔한 workflow입니다.

## 사용자 제어 데이터를 먼저 바이트로 모델링하기

Reversing에서는 각 입력 바이트에 `BitVec(..., 8)`을 사용해 시작한 다음, 대상이 처리하는 방식 그대로 word를 다시 구성하는 편이 대개 더 좋습니다. 이렇게 하면 오버플로, signedness 버그, shift, rotate, byte order 문제를 그대로 보존할 수 있습니다.<sup>[[2]](#references)</sup>

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

어셈블리 또는 디컴파일된 코드를 변환할 때 유용한 헬퍼:

- `Concat`: 바이트에서 16/32/64비트 값 재구성
- `Extract`: 상위/하위 워드 비교 또는 마스크/시프트 에뮬레이션
- `ZeroExt` / `SignExt`: zero/sign extension 버그를 정확하게 모델링
- `LShR` / `RotateLeft` / `RotateRight`: crackme, 해시, obfuscator에서 흔히 사용

## 메모리/레지스터 테이블을 배열로 모델링

검사가 `buf[i]`, lookup table 또는 에뮬레이션된 메모리에 따라 달라지는 경우, `Array`를 사용하면 여러 개의 변수를 따로 만드는 것보다 더 깔끔하게 표현할 수 있습니다.<sup>[[3]](#references)</sup>

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

이는 binary가 값을 검증하기 전에 메모리 여기저기로 복사할 때, 또는 전체 프로그램을 실행하지 않고 몇 가지 `mov`/`xor`/`add` 연산의 효과를 모델링하고 싶을 때 특히 유용합니다.

## Incremental solving은 branch를 분류할 때 매우 유용합니다

기본 constraints를 이미 추출했다면, solver를 매번 다시 만들지 않고 `push()` / `pop()`(또는 assumptions)을 사용해 대안 branch를 테스트하세요:<sup>[[3]](#references)</sup>

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

이는 디컴파일러에서 복구한 경로 조건을 재생하거나, 어떤 비교 연산 때문에 모델이 `unsat`이 되는지 빠르게 확인할 때 유용합니다.

## 더 다루기 쉬운 페이로드를 위한 최적화

모델이 만족 가능해지면 `Optimize()`를 사용해 더 실용적인 해를 구할 수 있습니다. 예를 들어 출력 가능한 바이트를 우선하거나, 체크섬 구성 요소를 최소화하거나, 복구한 비밀번호를 입력하거나 복사하기 쉽게 만드는 구조를 최대화할 수 있습니다.<sup>[[3]](#references)</sup>

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

## 형식이 복잡한 시리얼용 문자열/시퀀스

대상이 주로 접두사, 접미사, 부분 문자열 또는 정규식과 비슷한 구조를 확인하는 경우, `String`/`Seq` 제약 조건이 바이트 단위 비트 벡터보다 사용하기 쉬울 수 있습니다:<sup>[[3]](#references)</sup>

```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```

하지만 바이너리가 문자에 대해 산술 연산, 회전, 체크섬 계산 또는 형 변환을 수행하기 시작하면 보통 8비트 비트 벡터로 돌아가는 것이 더 좋습니다.

# 예제

## 스도쿠 풀이기

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

- [1] [예제가 포함된 Z3Py 가이드 (ericpony z3py-tutorial)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Z3 가이드 - 비트 벡터 이론 (Microsoft z3guide)](https://microsoft.github.io/z3guide/)
- [3] [Z3 프로그래밍 (Nikolaj Bjørner, Leonardo de Moura, Lev Nachmanson, Christoph Wintersteiger)](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
