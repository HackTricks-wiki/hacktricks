# Satisfiability Modulo Theories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

아주 기본적으로, 이 도구는 어떤 조건을 만족해야 하는 변수들의 값을 찾는 데 도움을 줍니다. 수작업으로 계산하면 매우 번거롭기 때문에, Z3에 변수들이 만족해야 할 조건을 지정하면(가능한 경우) 그에 맞는 값을 찾아줍니다.

**일부 텍스트와 예제는 [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)에서 발췌했습니다**

## 기본 연산

### 부울/And/Or/Not
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
### 모델 출력
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
## 기계 산술

최신 CPU와 주류 프로그래밍 언어는 **고정 크기 비트 벡터** 위에서의 산술을 사용합니다. 기계 산술은 Z3Py에서 **Bit-Vectors**로 제공됩니다.
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
### 부호 있는/부호 없는 숫자

Z3는 산술 연산에 대해 특별한 부호 있는 버전을 제공하며, **bit-vector가 부호 있는 것으로 처리되는지 부호 없는 것으로 처리되는지**에 따라 차이가 있습니다. Z3Py에서 연산자 **<, <=, >, >=, /, % and >>**는 **부호 있는** 버전에 해당합니다. 그에 대응하는 **부호 없는** 연산자는 **ULT, ULE, UGT, UGE, UDiv, URem and LShR.**
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
### Bit-vector helpers — reversing에서 일반적으로 필요한 것들

When you are **assembly나 decompiler 출력에서 체크를 가져올 때**, it is usually better to model every input byte as a `BitVec(..., 8)` and then rebuild words exactly like the target code does. This avoids bugs caused by mixing mathematical integers with machine arithmetic.
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
코드를 제약(constraints)으로 변환할 때 흔히 발생하는 실수들:

- `>>`는 비트-벡터에 대한 **산술** 오른쪽 시프트입니다. 논리적 `shr` 명령에는 `LShR`을 사용하세요.
- 원래 비교/나눗셈이 **부호 없는** 경우 `UDiv`, `URem`, `ULT`, `ULE`, `UGT` 및 `UGE`를 사용하세요.
- 폭(width)을 명시적으로 유지하세요. 바이너리가 8비트 또는 16비트로 잘라낸다면, 모든 것을 조용히 Python 정수로 승격시키는 대신 `Extract`를 추가하거나 `Concat`으로 값을 재구성하세요.

### 함수

**Interpreted functio**ns(예: 산술)에서는 **function +**가 **고정된 표준 해석**을 가집니다(두 숫자를 더함). **Uninterpreted functions**와 상수는 **매우 유연**하며; 함수나 상수에 대한 **constraints**와 **일치하는** **어떤 해석이라도** 허용합니다.

예: f를 x에 두 번 적용하면 결과가 다시 x가 되지만, f를 한 번 적용한 결과는 x와 다릅니다.
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
## 예제

### 스도쿠 풀이기
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
### 리버싱 워크플로우

만약 바이너리를 **symbolically execute**하고 제약조건을 자동으로 수집해야 한다면, 다음 angr 노트를 확인하세요:

{{#ref}}
angr/README.md
{{#endref}}

이미 디컴파일된 검사들을 보고 있고 그것들을 풀기만 하면 된다면, raw Z3가 보통 더 빠르고 제어하기 쉽습니다.

#### crackme에서 바이트 기반 검사 추출

crackmes와 packed loaders에서 매우 흔한 패턴은 후보 비밀번호에 대한 바이트 방정식들의 긴 목록입니다. 바이트를 8-bit vectors로 모델링하고, 알파벳을 제약하며, 원래 코드가 그것들을 넓힐 때만 확장하세요.

<details>
<summary>예시: 디컴파일된 산술에서 시리얼 검사 재구성</summary>
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

이 방식은 실제 reversing에 잘 맞습니다. 현대 writeups에서 실제로 하는 방식과 일치하기 때문에: 산술/비트 관계를 복원하고, 각 comparison을 constraint로 바꾸며, 전체 시스템을 한 번에 해결합니다.

#### `push()` / `pop()`를 이용한 증분 해결

reversing하는 동안 전체 solver를 다시 구성하지 않고 여러 가설을 시험해보고 싶을 때가 많습니다. `push()`는 체크포인트를 생성하고 `pop()`는 그 체크포인트 이후에 추가된 constraints를 제거합니다. 이는 분기가 signed인지 unsigned인지, 레지스터가 zero-extended인지 sign-extended인지 확실하지 않거나 disassembly에서 추출한 여러 candidate constants를 시험해볼 때 유용합니다.
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
#### 둘 이상의 유효한 입력 열거

일부 keygens, license checks, 그리고 CTF 챌린지는 의도적으로 **많은** 유효한 입력을 허용합니다. Z3는 이를 자동으로 열거하지 않지만, 각 모델 뒤에 **blocking clause**를 추가하여 다음 결과가 적어도 한 위치에서 달라지도록 강제할 수 있습니다.
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
#### 보기 흉한 bit-vector 수식을 위한 Tactics

Z3의 기본 solver는 보통 충분하지만, 등식이 많고 bit-vector rewrites가 많은 디컴파일러가 생성한 수식은 첫 번째 정규화 패스를 거치면 더 쉬워지는 경우가 많습니다. 그런 경우에는 tactics로부터 solver를 구성하는 것이 유용할 수 있습니다:
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
이것은 문제가 거의 전적으로 **bit-vector + Boolean logic**일 때 특히 유용하며, Z3가 공식을 SAT backend로 전달하기 전에 명백한 등식을 단순화하고 제거하도록 할 수 있습니다.

#### CRCs 및 기타 커스텀 체커

최근 리버싱 챌린지들은 여전히 brute-force로 접근하기 번거롭지만 모델링은 간단한 제약 조건에 Z3를 사용합니다. 예를 들어 ASCII-only 입력에 대한 CRC32 검사, mixed rotate/xor/add 파이프라인, 또는 JITed/obfuscated 체커에서 추출된 다수의 연쇄된 산술 술어 등이 있습니다. CRC-like 문제의 경우 상태를 bit-vectors로 유지하고 per-byte ASCII constraints를 조기에 적용하여 탐색 공간을 줄이세요.

## 참고자료

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
