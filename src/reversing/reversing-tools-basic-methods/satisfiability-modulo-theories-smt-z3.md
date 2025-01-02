{{#include ../../banners/hacktricks-training.md}}

非常に基本的に、このツールは、いくつかの条件を満たす必要がある変数の値を見つけるのに役立ちます。手作業で計算するのは非常に面倒です。したがって、Z3に変数が満たす必要のある条件を示すと、可能であればいくつかの値を見つけてくれます。

**いくつかのテキストと例は[https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)から抽出されています**

# 基本操作

## ブール値/AND/OR/NOT
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
## Ints/Simplify/Reals
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
## モデルの印刷
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
# 機械算術

現代のCPUと主流のプログラミング言語は、**固定サイズのビットベクター**に対する算術を使用します。機械算術はZ3Pyで**ビットベクター**として利用可能です。
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
## 符号付き/符号なしの数

Z3は、**ビットベクターが符号付きまたは符号なしとして扱われるかどうか**が重要な算術演算の特別な符号付きバージョンを提供します。Z3Pyでは、演算子**<, <=, >, >=, /, % および >>**は**符号付き**バージョンに対応しています。対応する**符号なし**演算子は**ULT, ULE, UGT, UGE, UDiv, URem および LShR**です。
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
## 関数

**解釈された関数**は、**関数 +**が**固定された標準的な解釈**を持つ算術のようなもので（2つの数を加算します）。**解釈されていない関数**と定数は**最大限に柔軟**です；それらは関数や定数に対する**制約**と**一貫性**のある**任意の解釈**を許可します。

例：fをxに2回適用すると再びxになりますが、fをxに1回適用するとxとは異なります。
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
# 例

## 数独ソルバー
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
## 参考文献

- [https://ericpony.github.io/z3py-tutorial/guide-examples.htm](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)

{{#include ../../banners/hacktricks-training.md}}
