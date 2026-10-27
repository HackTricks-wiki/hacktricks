# Về cơ bản, công cụ này giúp chúng ta tìm giá trị cho các biến cần thỏa mãn một số điều kiện; tự tính các giá trị đó sẽ rất phiền phức. Vì vậy, bạn có thể chỉ định cho Z3 các điều kiện mà biến cần thỏa mãn, và Z3 sẽ tìm một số giá trị (nếu có thể).

{{#include ../../banners/hacktricks-training.md}}

# Các phép toán cơ bản

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

## Mô hình in

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

# Số học máy

CPU hiện đại và các ngôn ngữ lập trình phổ biến sử dụng phép toán số học trên các vector bit có kích thước cố định. Trong Z3Py, có thể dùng Bit-Vectors để thực hiện số học máy.

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

## Số có dấu/không dấu

Z3 cung cấp các phiên bản có dấu riêng của các phép toán số học, trong đó kết quả phụ thuộc vào việc vector bit được xem là có dấu hay không dấu. Trong Z3Py, các toán tử `<`, `<=`, `>`, `>=`, `/`, `%` và `>>` tương ứng với các phiên bản có dấu. Các toán tử không dấu tương ứng là `ULT`, `ULE`, `UGT`, `UGE`, `UDiv`, `URem` và `LShR`.<sup>[[1]](#references)</sup>

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

## Functions

Các hàm được diễn giải, chẳng hạn như phép toán số học, có cách diễn giải chuẩn cố định. Các hàm và hằng chưa được diễn giải có tính linh hoạt tối đa; chúng cho phép mọi cách diễn giải phù hợp với các ràng buộc áp dụng cho hàm hoặc hằng đó.<sup>[[1]](#references)</sup>

Ví dụ: áp dụng `f` hai lần lên `x` sẽ cho kết quả là `x`, nhưng áp dụng `f` một lần lên `x` sẽ cho kết quả khác `x`.

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

# Các mẫu hướng tới Reversing

Nếu bạn cần symbolic execution đầy đủ trên một binary thay vì tự nâng cấp thủ công chỉ một vài bước kiểm tra, hãy xem [Angr - Examples](angr/angr-examples.md). Trên thực tế, quy trình rất phổ biến là khôi phục các predicate liên quan từ decompiler/assembly rồi chỉ dựng lại trong Z3 những ràng buộc số học hoặc bộ nhớ đáng chú ý.

## Trước tiên, mô hình hóa dữ liệu do người dùng kiểm soát dưới dạng byte

Khi reversing, thường nên bắt đầu bằng `BitVec(..., 8)` cho mỗi byte đầu vào, rồi dựng lại các word chính xác theo cách chương trình mục tiêu thực hiện. Cách này giữ nguyên hiện tượng tràn vòng, lỗi về dấu, phép dịch bit, phép xoay bit và vấn đề thứ tự byte.<sup>[[2]](#references)</sup>

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

Các hàm trợ giúp hữu ích khi dịch mã assembly hoặc decompiler:

- `Concat`: dựng lại giá trị 16/32/64-bit từ các byte
- `Extract`: so sánh các word cao/thấp hoặc mô phỏng mask/shift
- `ZeroExt` / `SignExt`: mô hình hóa chính xác các lỗi mở rộng zero/sign
- `LShR` / `RotateLeft` / `RotateRight`: thường gặp trong crackmes, hash và obfuscator

## Mô hình hóa bảng bộ nhớ/thanh ghi bằng mảng

Khi một phép kiểm tra phụ thuộc vào `buf[i]`, bảng tra cứu hoặc bộ nhớ được mô phỏng, dùng `Array` có thể gọn hơn việc tạo hàng chục biến riêng biệt.<sup>[[3]](#references)</sup>

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

Điều này đặc biệt hữu ích khi binary sao chép các giá trị qua lại trong bộ nhớ trước khi xác thực chúng, hoặc khi bạn muốn mô hình hóa tác động của một vài thao tác `mov`/`xor`/`add` mà không cần chạy toàn bộ chương trình.

## Giải bài toán tăng dần rất hữu ích để phân loại nhánh

Khi đã trích xuất các ràng buộc cơ sở, hãy dùng `push()` / `pop()` (hoặc assumptions) để kiểm tra các nhánh thay thế mà không phải dựng lại solver mỗi lần:<sup>[[3]](#references)</sup>

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

Điều này hữu ích khi phát lại các điều kiện đường đi được khôi phục từ decompiler hoặc khi bạn muốn nhanh chóng xác định phép so sánh nào khiến model `unsat`.

## Tối ưu để có payload dễ dùng hơn

Khi model đã thỏa mãn, `Optimize()` có thể giúp bạn tìm lời giải hữu dụng hơn: chẳng hạn ưu tiên các byte có thể in được, giảm thiểu một thành phần checksum hoặc tối đa hóa một cấu trúc nào đó để mật khẩu được khôi phục dễ nhập hoặc sao chép hơn.<sup>[[3]](#references)</sup>

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

## Chuỗi/dãy cho các chuỗi định dạng phức tạp

Nếu mục tiêu chủ yếu kiểm tra tiền tố, hậu tố, chuỗi con hoặc cấu trúc dạng regex, các ràng buộc `String`/`Seq` có thể dễ dùng hơn bit-vector theo từng byte:<sup>[[3]](#references)</sup>

```python
from z3 import *

serial = String('serial')
s = Solver()
s.add(Length(serial) == 10)
s.add(PrefixOf(StringVal("HTB{"), serial))
s.add(SuffixOf(StringVal("}"), serial))
s.add(Contains(serial, StringVal("_")))
```

Tuy nhiên, khi binary bắt đầu thực hiện các phép toán số học, xoay bit, tính checksum hoặc ép kiểu trên các ký tự, thường sẽ tốt hơn nếu quay lại dùng bit-vector 8-bit.

# Ví dụ

## Bộ giải Sudoku

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

- [1] [Hướng dẫn Z3Py kèm ví dụ (ericpony z3py-tutorial)](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [2] [Hướng dẫn Z3 - Lý thuyết Bit-Vector (Microsoft z3guide)](https://microsoft.github.io/z3guide/)
- [3] [Lập trình Z3 (Nikolaj Bjørner, Leonardo de Moura, Lev Nachmanson, Christoph Wintersteiger)](https://theory.stanford.edu/~nikolaj/programmingz3.html)
{{#include ../../banners/hacktricks-training.md}}
