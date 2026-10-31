# Angr - 예제

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> angr는 여러 `scanf` 변환을 모델링할 수 있지만, 해당 SimProcedure는 완전하지 않습니다. 먼저 기본 제공 모델을 사용해 보세요. 특정 형식을 제대로 처리하지 못하면 해당 호출을 형식에 맞는 hook으로 대체하거나, 호출 이후부터 시작해 출력값을 직접 초기화하세요.<sup>[[2]](#references)[[3]](#references)</sup>

[https://github.com/jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf)에서 가져온 코드입니다.<sup>[[1]](#references)</sup> 상태, solver 및 hook API는 [angr basics](./)도 참조하세요.

### 주소에 도달하는 입력 (주소 표시)

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

### 주소에 도달하는 입력 (출력 확인)

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

### 레지스트리 값

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

### 스택 값

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

이 시나리오에서는 `scanf("%u %u")`로 입력을 받고 `"1 1"` 값을 전달했으므로, 스택의 **`0x00000001`** 값은 **사용자 입력**에서 온 것입니다. 이 값이 `$ebp - 8`에서 시작하는 것을 볼 수 있습니다. 따라서 코드에서는 **`$esp`를 8바이트만큼 감소시킨 다음(당시 `$ebp`와 `$esp`의 값이 같았으므로) BVS를 push했습니다.**

![스택에 비트 벡터를 넣어 스택 위치에서 프로그램 흐름에 도달하는 데 필요한 값을 확인합니다. 이 시나리오에서는 scanf("%u %u")로 입력을 받고 "1...](<../../../images/image (136).png>)

### 정적 메모리 값(전역 변수)

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

### 동적 메모리 값(Malloc)

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

### 파일 시뮬레이션

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
> 심볼릭 파일에 심볼릭 데이터와 병합된 상수 데이터가 포함될 수도 있다는 점에 유의하세요:
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

### 제약 조건 적용

> [!TIP]
> 길이가 16인 단어 2개를 **문자 단위로** 비교하는(루프) 간단한 작업도 **angr**에는 많은 **비용**이 들 수 있습니다. 각 if문마다 분기가 하나씩 생성되므로 **기하급수적으로** 분기를 만들어야 하기 때문입니다: `2^16`\
> 따라서 **angr에게 이전 지점으로 이동하도록 요청하고**(실제로 어려운 부분은 이미 처리된 지점), **제약 조건을 직접 설정하는** 편이 더 쉽습니다.

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
> 일부 시나리오에서는 **veritesting**을 활성화할 수 있습니다. 이 기능은 유사한 상태를 병합하여 불필요한 분기를 줄이고 해결책을 찾습니다: `simulation = project.factory.simgr(initial_state, veritesting=True)`

> [!TIP]
> 이러한 시나리오에서 할 수 있는 또 다른 방법은 **angr이 더 쉽게 이해할 수 있는 방식으로 함수를 후킹하는 것**입니다.

### Simulation Managers

일부 시뮬레이션 관리자는 다른 관리자보다 더 유용할 수 있습니다. 이전 예제에서는 유용한 분기가 많이 생성되는 문제가 있었습니다. 여기서는 **veritesting** 기법이 해당 분기를 병합하여 해결책을 찾습니다.\
이 시뮬레이션 관리자는 다음과 같이 활성화할 수도 있습니다: `simulation = project.factory.simgr(initial_state, veritesting=True)`

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

### 함수 호출 한 번 후킹/우회하기

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

### 함수 후킹 / Simprocedure

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

### 여러 매개변수로 scanf 시뮬레이션

지원되지 않거나 부정확한 `scanf("%u %u", ...)` 모델의 경우, 형식별 hook으로 두 출력값을 모두 쓸 수 있습니다. 성공적으로 변환한 횟수를 반환하면 호출자가 일관된 결과를 받습니다. 이렇게 하면 파싱을 우회하지만 EOF나 잘못된 입력은 모델링하지 않습니다.<sup>[[2]](#references)[[3]](#references)</sup>

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

### 입력으로 제어되는 명령 포인터 찾기

입력에 의해 결정되는 간접 점프나 덮어쓴 반환 주소가 있는 바이너리를 감사할 때는 명령 포인터가 여러 값을 가질 수 있는 상태를 저장하세요. `unconstrained` 상태는 단서일 뿐, 악용 가능성의 증거는 아닙니다. angr는 초기화되지 않은 메모리나 부정확한 환경에서도 제약 없는 값을 만들 수 있습니다. *입력 바이트*가 선택한 실행 가능 주소로 점프하도록 만들 수 있는지 확인한 다음, 결과 바이트를 실제 프로그램에서 다시 실행하세요.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

이 예시는 `win` 심볼을 알고 있고 stdin 입력을 받는 바이너리를 가정합니다. 프로그램이 읽을 수 있는 양만큼 입력 길이를 설정하세요. PIE의 경우 다시 실행하기 전에 올바른 런타임 베이스를 사용해 주소를 확인하세요. 솔버만으로는 ASLR이나 다른 완화 기법을 우회할 수 없습니다.<sup>[[6]](#references)[[7]](#references)</sup>

<details>
<summary>심볼릭 stdin 입력을 검사해 제어 흐름 리디렉션 확인</summary>

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

### 정적 바이너리

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

- [1] [jakespringer/angr_ctf - GitHub 저장소](https://github.com/jakespringer/angr_ctf)
- [2] [angr scanf 형식 파서 소스](https://github.com/angr/angr/blob/master/angr/procedures/stubs/format_parser.py)
- [3] [angr: angr 사용 시 주의 사항](https://docs.angr.io/en/stable/advanced-topics/gotchas.html)
- [4] [angr: 시뮬레이션 관리자](https://docs.angr.io/en/latest/core-concepts/pathgroups.html)
- [5] [angr: 시뮬레이션 및 계측](https://docs.angr.io/en/latest/core-concepts/simulation.html)
- [6] [angr-examples: InsomniHack AEG 솔버](https://github.com/angr/angr-examples/blob/master/examples/insomnihack_aeg/solve.py)
- [7] [angr SimOS stdin 처리](https://github.com/angr/angr/blob/master/angr/simos/simos.py)
{{#include ../../../banners/hacktricks-training.md}}
