# Angr - 示例

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> angr 可以模拟多个 `scanf` 转换，但它的 SimProcedure 并不完整。先尝试内置模型。如果它无法正确处理某种特定格式，可以用针对该格式的 hook 替换该调用，或者从调用之后开始执行，并自行初始化其输出。<sup>[[2]](#references)[[3]](#references)</sup>

代码取自 [https://github.com/jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf)<sup>[[1]](#references)</sup>另请参阅 [angr 基础知识](./)，了解 state、solver 和 hook API。

### 输入以到达地址（指示该地址）

```python
import angr
import sys

def main(argv):
  path_to_binary = argv[1]  # :string
  project = angr.Project(path_to_binary)

  # Start in main()
  initial_state = project.factory.entry_state()
  # Start simulation
  simulation = project.factory.simgr(initial_state)

  # Find the way yo reach the good address
  good_address = 0x804867d

  # Avoiding this address
  avoid_address = 0x080485A8
  simulation.explore(find=good_address, avoid=avoid_address)

  # If found a way to reach the address
  if simulation.found:
    solution_state = simulation.found[0]

    # Print the string that Angr wrote to stdin to follow solution_state
    print(solution_state.posix.dumps(sys.stdin.fileno()))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

### 到达地址的输入（表示打印）

```python
# If you don't know the address you want to recah, but you know it's printing something
# You can also indicate that info

import angr
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    #Successful print
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job.' in stdout_output

  def should_abort(state):
    #Avoid this print
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try again.' in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

### 注册表值

```python
# If a particular scanf format is modeled incorrectly, begin after the call
# and initialize the values expected by the following instructions.

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  # Address were you want to indicate the relation BitVector - registries
  start_address = 0x80488d1
  initial_state = project.factory.blank_state(addr=start_address)


  # Create Bit Vectors
  password0_size_in_bits = 32  # :integer
  password0 = claripy.BVS('password0', password0_size_in_bits)

  password1_size_in_bits = 32  # :integer
  password1 = claripy.BVS('password1', password1_size_in_bits)

  password2_size_in_bits = 32  # :integer
  password2 = claripy.BVS('password2', password2_size_in_bits)

  # Relate its vectors to the register values needed to reach an address
  initial_state.regs.eax = password0
  initial_state.regs.ebx = password1
  initial_state.regs.edx = password2

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job.'.encode() in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.'.encode() in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.solver.eval(password0)
    solution1 = solution_state.solver.eval(password1)
    solution2 = solution_state.solver.eval(password2)

    # Aggregate and format the solutions you computed above, and then print
    # the full string. Pay attention to the order of the integers, and the
    # expected base (decimal, octal, hexadecimal, etc).
    solution = ' '.join(map('{:x}'.format, [ solution0, solution1, solution2 ]))  # :string
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

### 栈值

```python
# Put bit vectors in th stack to find out the vallue that stack position need to
# have to reach a rogram flow

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  # Go to some address after the scanf where values have already being set in the stack
  start_address = 0x8048697
  initial_state = project.factory.blank_state(addr=start_address)

  # Since we are starting after scanf, we are skipping this stack construction
  # step. To make up for this, we need to construct the stack ourselves. Let us
  # start by initializing ebp in the exact same way the program does.
  initial_state.regs.ebp = initial_state.regs.esp

  # In this case scanf("%u %u") is used, so 2 BVS are going to be needed
  password0 = claripy.BVS('password0', 32)
  password1 = claripy.BVS('password1', 32)

  # Now, in the address were you have stopped, check were are the scanf values saved
  # Then, substrack form the esp registry the needing padding to get to the
  # part of the stack were the scanf values are being saved and push the BVS
  # (see the image below to understan this -8)
  padding_length_in_bytes = 8  # :integer
  initial_state.regs.esp -= padding_length_in_bytes

  initial_state.stack_push(password0)
  initial_state.stack_push(password1)

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job.'.encode() in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.'.encode() in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.solver.eval(password0)
    solution1 = solution_state.solver.eval(password1)

    solution = ' '.join(map(str, [ solution0, solution1 ]))
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

在这个场景中，输入是通过 `scanf("%u %u")` 获取的，输入值为 `"1 1"`，因此栈中的 **`0x00000001`** 值来自**用户输入**。可以看到这些值从 `$ebp - 8` 开始。因此，在代码中，我们先将 `$esp` 减去 **8 个字节**（因为此时 `$ebp` 和 `$esp` 的值相同），然后压入 BVS。

![将位向量放入栈中，以找出栈位置需要达到的值，从而实现程序流控制：在这个场景中，输入是通过 scanf("%u %u") 获取的，输入值为 "1...](<../../../images/image (136).png>)

### 静态内存值（全局变量）

```python
import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  # Get an address after scanf, once the input has been saved in memory
  start_address = 0x8048606
  initial_state = project.factory.blank_state(addr=start_address)

  # The binary is calling scanf("%8s %8s %8s %8s").
  # So we need 4 BVS of size 8*8
  password0 = claripy.BVS('password0', 8*8)
  password1 = claripy.BVS('password1', 8*8)
  password2 = claripy.BVS('password2', 8*8)
  password3 = claripy.BVS('password3', 8*8)

  # Write the symbolic BVS in the memory positions
  password0_address = 0xa29faa0
  initial_state.memory.store(password0_address, password0)
  password1_address = 0xa29faa8
  initial_state.memory.store(password1_address, password1)
  password2_address = 0xa29fab0
  initial_state.memory.store(password2_address, password2)
  password3_address = 0xa29fab8
  initial_state.memory.store(password3_address, password3)

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job.'.encode() in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.'.encode() in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Get the values the memory addresses should store
    solution0 = solution_state.solver.eval(password0,cast_to=bytes).decode()
    solution1 = solution_state.solver.eval(password1,cast_to=bytes).decode()
    solution2 = solution_state.solver.eval(password2,cast_to=bytes).decode()
    solution3 = solution_state.solver.eval(password3,cast_to=bytes).decode()

    solution = ' '.join([ solution0, solution1, solution2, solution3 ])

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

### 动态内存值（Malloc）

```python
import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  # Get address after scanf
  start_address = 0x804869e
  initial_state = project.factory.blank_state(addr=start_address)

  # The binary is calling scanf("%8s %8s") so 2 BVS are needed.
  password0 = claripy.BVS('password0', 8*8)
  password1 = claripy.BVS('password0', 8*8)

  # Find a coupble of addresses that aren't used by the binary (like 0x4444444 & 0x4444454)
  # The address generated by mallosc is going to be saved in some address
  # Then, make that address point to the fake heap addresses were the BVS are going to be saved
  fake_heap_address0 = 0x4444444
  pointer_to_malloc_memory_address0 = 0xa79a118
  initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
  fake_heap_address1 = 0x4444454
  pointer_to_malloc_memory_address1 = 0xa79a120
  initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)

  # Save the VBS in the new fake heap addresses created
  initial_state.memory.store(fake_heap_address0, password0)
  initial_state.memory.store(fake_heap_address1, password1)

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job.'.encode() in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.'.encode() in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution0 = solution_state.solver.eval(password0,cast_to=bytes).decode()
    solution1 = solution_state.solver.eval(password1,cast_to=bytes).decode()

    solution = ' '.join([ solution0, solution1 ])

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

### 文件模拟

```python
#In this challenge a password is read from a file and we want to simulate its content

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  # Get an address just before opening the file with the symbolic content
  # Or at least when the file is not going to suffer more changes before being read
  start_address = 0x80488db
  initial_state = project.factory.blank_state(addr=start_address)

  # Specify the filena that is going to open
  # Note that in theory, the filename could be symbolic.
  filename = 'WCEXPXBW.txt'
  symbolic_file_size_bytes = 64

  # Create a bit-vector that will hold the symbolic file content
  password = claripy.BVS('password', symbolic_file_size_bytes * 8)

  # Create the simulated file with symbolic content
  password_file = angr.storage.SimFile(filename, content=password)

  # Add the symbolic file we created to the symbolic filesystem.
  initial_state.fs.insert(filename, password_file)

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job.'.encode() in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.'.encode() in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution = solution_state.solver.eval(password,cast_to=bytes).decode()

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

> [!TIP]
> 请注意，符号文件也可能包含与符号数据合并的常量数据：
>
> ```python
>  # Hello world, my name is John.
>  # ^                       ^
>  # ^ address 0             ^ address 24 (count the number of characters)
>  # In order to represent this in memory, we would want to write the string to
>  # the beginning of the file:
>  #
>  # hello_txt_contents = claripy.BVV('Hello world, my name is John.', 30*8)
>  #
>  # Perhaps, then, we would want to replace John with a
>  # symbolic variable. We would call:
>  #
>  # name_bitvector = claripy.BVS('symbolic_name', 4*8)
>  #
>  # Then, after the program calls fopen('hello.txt', 'r') and then
>  # fread(buffer, sizeof(char), 30, hello_txt_file), the buffer would contain
>  # the string from the file, except four symbolic bytes where the name would be
>  # stored.
>  # (!)
> ```

### 应用约束

> [!TIP]
> 有时，像逐字符比较两个长度为 16 的单词这样简单的人类操作（循环），对 **angr** 来说却很耗费资源，因为它需要指数级地生成分支：每个 if 都会生成一个分支，因此是 `2^16`\
> 因此，更简单的做法是**让 angr 到达之前的某个位置**（此时真正困难的部分已经完成），然后**手动设置这些约束**。

```python
# After perform some complex poperations to the input the program checks
# char by char the password against another password saved, like in the snippet:
#
# #define REFERENCE_PASSWORD = "AABBCCDDEEFFGGHH";
# int check_equals_AABBCCDDEEFFGGHH(char* to_check, size_t length) {
#   uint32_t num_correct = 0;
#   for (int i=0; i<length; ++i) {
#     if (to_check[i] == REFERENCE_PASSWORD[i]) {
#       num_correct += 1;
#     }
#   }
#   return num_correct == length;
# }
#
# ...
#
# char* input = user_input();
# char* encrypted_input = complex_function(input);
# if (check_equals_AABBCCDDEEFFGGHH(encrypted_input, 16)) {
#   puts("Good Job.");
# } else {
#   puts("Try again.");
# }
#
# The function checks if *to_check == "AABBCCDDEEFFGGHH". This is very RAM consumming
# as the computer needs to branch every time the if statement in the loop was called (16
# times), resulting in 2^16 = 65,536 branches, which will take too long of a
# time to evaluate for our needs.

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  simulation = project.factory.simgr(initial_state)

  # Get an address to check after the complex function and before the "easy compare" operation
  address_to_check_constraint = 0x8048671
  simulation.explore(find=address_to_check_constraint)


  if simulation.found:
    solution_state = simulation.found[0]

    # Find were the input that is going to be compared is saved in memory
    constrained_parameter_address = 0x804a050
    constrained_parameter_size_bytes = 16
    # Set the bitvector
    constrained_parameter_bitvector = solution_state.memory.load(
      constrained_parameter_address,
      constrained_parameter_size_bytes
    )

    # Indicate angr that this BV at this point needs to be equal to the password
    constrained_parameter_desired_value = 'BWYRUBQCMVSBRGFU'.encode()
    solution_state.add_constraints(constrained_parameter_bitvector == constrained_parameter_desired_value)

    print(solution_state.posix.dumps(sys.stdin.fileno()))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

> [!CAUTION]
> 在某些场景中，你可以启用 **veritesting**，它会合并相似状态，以避免无用的分支并找到解决方案：`simulation = project.factory.simgr(initial_state, veritesting=True)`

> [!TIP]
> 在这些场景中，你还可以**hook 函数，让 angr 更容易理解它**。

### Simulation Managers

有些 simulation manager 比其他的更有用。在前面的示例中，问题在于创建了许多有用的分支。这里，**veritesting** 技术会合并这些分支并找到解决方案。\
还可以通过以下方式启用此 simulation manager：`simulation = project.factory.simgr(initial_state, veritesting=True)`

```python
import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  simulation = project.factory.simgr(initial_state)
  # Set simulation technique
  simulation.use_technique(angr.exploration_techniques.Veritesting())


  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())

    return 'Good Job.'.encode() in stdout_output  # :boolean

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.'.encode() in stdout_output  # :boolean

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()))
  else:
    raise Exception('Could not find the solution')


if __name__ == '__main__':
  main(sys.argv)
```

### Hooking/Bypassing 函数的一次调用

```python
# This level performs the following computations:
#
# 1. Get 16 bytes of user input and encrypt it.
# 2. Save the result of check_equals_AABBCCDDEEFFGGHH (or similar)
# 3. Get another 16 bytes from the user and encrypt it.
# 4. Check that it's equal to a predefined password.
#
# The ONLY part of this program that we have to worry about is #2. We will be
# replacing the call to check_equals_ with our own version, using a hook, since
# check_equals_ will run too slowly otherwise.

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  # Hook the address of the call to hook indicating th length of the instruction (of the call)
  check_equals_called_address = 0x80486b8
  instruction_to_skip_length = 5
  @project.hook(check_equals_called_address, length=instruction_to_skip_length)
  def skip_check_equals_(state):
    #Load the input of the function reading direcly the memory
    user_input_buffer_address = 0x804a054
    user_input_buffer_length = 16
    user_input_string = state.memory.load(
      user_input_buffer_address,
      user_input_buffer_length
    )

    # Create a symbolic If expression that checks the string loaded from memory
    # return True (1) if not returns False (0) in eax
    check_against_string = 'XKSPZSJKJYQCQXZV'.encode() # :string

    state.regs.eax = claripy.If(
      user_input_string == check_against_string,
      claripy.BVV(1, 32),
      claripy.BVV(0, 32)
    )

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job.'.encode() in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.'.encode() in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]
    solution = solution_state.posix.dumps(sys.stdin.fileno()).decode()
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

### Hook 函数 / Simprocedure

```python
# Hook to the function called check_equals_WQNDNKKWAWOLXBAC

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  # Define a class and a tun method to hook completelly a function
  class ReplacementCheckEquals(angr.SimProcedure):
    # This C code:
    #
    # int add_if_positive(int a, int b) {
    #   if (a >= 0 && b >= 0) return a + b;
    #   else return 0;
    # }
    #
    # could be simulated with python:
    #
    # class ReplacementAddIfPositive(angr.SimProcedure):
    #   def run(self, a, b):
    #     if a >= 0 and b >=0:
    #       return a + b
    #     else:
    #       return 0
    #
    # run(...) receives the params of the hooked function
    def run(self, to_check, length):
      user_input_buffer_address = to_check
      user_input_buffer_length = length

      # Read the data from the memory address given to the function
      user_input_string = self.state.memory.load(
        user_input_buffer_address,
        user_input_buffer_length
      )

      check_against_string = 'WQNDNKKWAWOLXBAC'.encode()

      # Return 1 if equals to the string, 0 otherways
      return claripy.If(
        user_input_string == check_against_string,
        claripy.BVV(1, 32),
        claripy.BVV(0, 32)
      )


  # Hook the check_equals symbol. Angr automatically looks up the address
  # associated with the symbol. Alternatively, you can use 'hook' instead
  # of 'hook_symbol' and specify the address of the function. To find the
  # correct symbol, disassemble the binary.
  # (!)
  check_equals_symbol = 'check_equals_WQNDNKKWAWOLXBAC' # :string
  project.hook_symbol(check_equals_symbol, ReplacementCheckEquals())

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job.'.encode() in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.'.encode() in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    solution = solution_state.posix.dumps(sys.stdin.fileno()).decode()
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

### 用多个参数模拟 scanf

对于不受支持或不准确的 `scanf("%u %u", ...)` 模型，可以使用特定于格式的 hook 写入两个输出值。返回成功转换的数量，以便调用方获得一致的结果。这绕过了解析过程，也不会模拟 EOF 或格式错误的输入。<sup>[[2]](#references)[[3]](#references)</sup>

```python
# Replace this one known scanf format, not scanf in general.

import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  class ReplacementScanf(angr.SimProcedure):
    # The code uses: 'scanf("%u %u", ...)'
    def run(self, format_string, param0, param1):
      scanf0 = claripy.BVS('scanf0', 32)
      scanf1 = claripy.BVS('scanf1', 32)

      # Get the addresses from the params and store the BVS in memory
      scanf0_address = param0
      self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
      scanf1_address = param1
      self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)

      # Now, we want to 'set aside' references to our symbolic values in the
      # globals plugin included by default with a state. You will need to
      # store multiple bitvectors. You can either use a list, tuple, or multiple
      # keys to reference the different bitvectors.
      self.state.globals['solutions'] = (scanf0, scanf1)
      return 2

  scanf_symbol = '__isoc99_scanf'
  project.hook_symbol(scanf_symbol, ReplacementScanf())

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job.'.encode() in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.'.encode() in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Grab whatever you set aside in the globals dict.
    stored_solutions = solution_state.globals['solutions']
    solution = ' '.join(map(str, map(solution_state.solver.eval, stored_solutions)))

    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

### 查找由输入控制的指令指针

审计含有由输入驱动的间接跳转或被覆盖返回地址的二进制程序时，保存指令指针存在多个可能取值的状态。`unconstrained` 状态只是线索，并不能证明存在可利用性：angr 也可能因未初始化内存或环境不准确而产生 unconstrained 值。检查 *输入字节* 是否能使跳转到指定的可执行地址，然后在真实程序中重放生成的字节。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

本示例假设二进制程序有一个已知的 `win` 符号，并从 stdin 接收输入。将输入长度设为程序可读取的长度。对于 PIE，在重放前使用正确的运行时基址解析地址；仅靠 solver 无法绕过 ASLR 或其他缓解措施。<sup>[[6]](#references)[[7]](#references)</sup>

<details>
<summary>检查符号化 stdin 输入能否重定向控制流</summary>

```python
import angr
import claripy

project = angr.Project("./target", auto_load_libs=False)
win = project.loader.main_object.get_symbol("win").rebased_addr
input_bytes = claripy.BVS("input", 128 * 8)
stdin = angr.SimFileStream(name="stdin", content=input_bytes, has_end=True)
state = project.factory.entry_state(stdin=stdin)
simgr = project.factory.simgr(state, save_unconstrained=True)

payload = None
while simgr.active and payload is None:
    simgr.step()
    for candidate in simgr.unconstrained:
        if candidate.satisfiable(extra_constraints=[candidate.regs.ip == win]):
            candidate.add_constraints(candidate.regs.ip == win)
            payload = candidate.solver.eval(input_bytes, cast_to=bytes)
            break
    simgr.drop(stash="unconstrained")

print(repr(payload) if payload is not None else "No satisfiable jump found")
```

</details>

### 静态二进制文件

```python
# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# To solve the challenge, manually hook any standard library c functions that
# are used. Then, ensure that you begin the execution at the beginning of the
# main function. Do not use entry_state.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc

import angr
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()

  #Find the addresses were the lib functions are loaded in the binary
  #For example you could find: call   0x804ed80 <__isoc99_scanf>
  project.hook(0x804ed40, angr.SIM_PROCEDURES['libc']['printf']())
  project.hook(0x804ed80, angr.SIM_PROCEDURES['libc']['scanf']())
  project.hook(0x804f350, angr.SIM_PROCEDURES['libc']['puts']())
  project.hook(0x8048d10, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job.'.encode() in stdout_output  # :boolean

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.'.encode() in stdout_output  # :boolean

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```



## References

- [1] [jakespringer/angr_ctf - GitHub 仓库](https://github.com/jakespringer/angr_ctf)
- [2] [angr scanf 格式解析器源码](https://github.com/angr/angr/blob/master/angr/procedures/stubs/format_parser.py)
- [3] [angr：使用 angr 时的注意事项](https://docs.angr.io/en/stable/advanced-topics/gotchas.html)
- [4] [angr：Simulation managers](https://docs.angr.io/en/latest/core-concepts/pathgroups.html)
- [5] [angr：仿真与插桩](https://docs.angr.io/en/latest/core-concepts/simulation.html)
- [6] [angr-examples：InsomniHack AEG 求解器](https://github.com/angr/angr-examples/blob/master/examples/insomnihack_aeg/solve.py)
- [7] [angr SimOS stdin 处理](https://github.com/angr/angr/blob/master/angr/simos/simos.py)
{{#include ../../../banners/hacktricks-training.md}}
