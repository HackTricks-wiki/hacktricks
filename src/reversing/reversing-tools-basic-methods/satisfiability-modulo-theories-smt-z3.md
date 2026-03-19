# Satisfiability Modulo Theories (SMT) - Z3

{{#include ../../banners/hacktricks-training.md}}

很基本地，这个工具可以帮助我们为需要满足某些条件的变量寻找取值，手工计算会非常繁琐。因此，你可以向 Z3 指定变量需要满足的条件，它会找到一些值（如果可能的话）。

**部分文本和示例摘自 [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)**

## 基本操作

### 布尔/与/或/非
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
### 打印模型
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
## 机器算术

现代 CPU 和主流编程语言使用基于 **定长位向量** 的算术运算。机器算术在 Z3Py 中以 **Bit-Vectors** 的形式提供。
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
### 有符号/无符号数

Z3 提供了针对有符号/无符号情形的特殊算术运算。对于位向量是否被视为有符号或无符号，运算结果会不同。在 Z3Py 中，运算符 **<, <=, >, >=, /, % 和 >>** 对应于 **有符号** 版本。相应的 **无符号** 运算符是 **ULT, ULE, UGT, UGE, UDiv, URem 和 LShR.**
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
### 在 reversing 中常用的 Bit-vector 辅助

当你 **lifting checks from assembly or decompiler output** 时，通常最好将每个输入字节建模为 `BitVec(..., 8)`，然后像目标代码那样精确重建字（word）。这样可以避免将数学整数与机器算术混用所导致的错误。
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
将代码翻译为约束时的一些常见陷阱：

- `>>` 对位向量表示 **算术** 右移。对于逻辑的 `shr` 指令，使用 `LShR`。
- 当原始比较/除法是 **无符号** 时，使用 `UDiv`、`URem`、`ULT`、`ULE`、`UGT` 和 `UGE`。
- 保持位宽明确。如果二进制截断到 8 或 16 位，请使用 `Extract` 或用 `Concat` 重建该值，而不要默默地将所有内容提升为 Python 整数。

### 函数

**解释型函数**，例如算术，其中 **函数 +** 有一个 **固定的标准解释**（它把两个数相加）。**未解释函数** 和常量是 **最大程度灵活的**；它们允许 **任何解释**，只要该解释与关于该函数或常量的 **约束** **一致**。
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
## 示例

### 数独求解器
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

如果你需要**对二进制进行符号执行并自动收集约束**，请查看 angr 的说明：

{{#ref}}
angr/README.md
{{#endref}}

如果你已经在查看反编译的校验并且只需求解它们，直接使用 Z3 通常更快且更易控制。

#### Lifting byte-based checks from a crackme

在 crackmes 和 packed loaders 中，一个非常常见的模式是针对候选密码的一长串字节方程。将字节建模为 8 位向量，限制字符集，并且只有在原始代码扩大它们时才放宽。

<details>
<summary>示例：从反编译的算术重建序列号校验</summary>
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

这种风格很适合真实世界的逆向，因为它与现代 writeups 的实际做法一致：恢复算术/按位关系，将每个比较转换为约束，然后一次性求解整个系统。

#### 使用 `push()` / `pop()` 的增量求解

在逆向过程中，你经常想在不重建整个求解器的情况下测试多个假设。`push()` 会创建一个检查点，`pop()` 会丢弃在该检查点之后添加的约束。当你不确定某个分支是带符号还是无符号、某个寄存器是零扩展还是符号扩展，或当你在尝试从反汇编中提取的多个候选常量时，这非常有用。
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
#### 枚举多个有效输入

有些 keygens、license checks 和 CTF 挑战故意接受 **许多** 有效输入。Z3 不会自动枚举它们，但你可以在每个模型之后添加一个 **blocking clause**，以强制下一个结果在至少一个位置上不同。
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
#### 针对棘手的位向量公式的策略

Z3 的默认求解器通常已经足够，但由反编译器生成、包含大量等式和位向量重写的公式，在经过第一次归一化处理后通常会更容易处理。在这些情况下，从 tactics 构建一个求解器会很有用：
```python
from z3 import *

t = Then('simplify', 'solve-eqs', 'bit-blast', 'sat')
s = t.solver()
```
当问题几乎完全是 **bit-vector + Boolean logic** 时，这尤其有用，且你希望 Z3 在将公式交给 SAT backend 之前简化并消除明显的等式。

#### CRCs 和其他自定义校验器

最近的 reversing 挑战仍然使用 Z3 来处理那些难以暴力破解但易于建模的约束，比如针对 ASCII-only 输入的 CRC32 校验、混合的 rotate/xor/add 流水线，或从 JITed/obfuscated checker 中提取的许多链式算术谓词。对于 CRC-like 问题，保持状态为 bit-vectors，并尽早施加逐字节 ASCII 约束以缩小搜索空间。

## 参考资料

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [https://microsoft.github.io/z3guide/docs/theories/Bitvectors/](https://microsoft.github.io/z3guide/docs/theories/Bitvectors/)
- [https://theory.stanford.edu/~nikolaj/programmingz3.html](https://theory.stanford.edu/~nikolaj/programmingz3.html)

{{#include ../../banners/hacktricks-training.md}}
