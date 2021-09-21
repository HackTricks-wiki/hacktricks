# Angr - Examples

### Input to reach address \(indicating the address\)

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
  simulation.explore(find=good_address , avoid=avoid_address ))

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

### Input to reach address \(indicating prints\)

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

### Registry values to reach address

```python
# Angr doesn't currently support reading multiple things with scanf (Ex: 
# scanf("%u %u).) You will have to tell the simulation engine to begin the
# program after scanf is called and manually inject the symbols into registers.

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

  # Relate it Vectors with the registriy values you are interested in to reach an address
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

### Stack values to reach address

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

In this scenario, the input was taken with `scanf("%u %u")` and the value `"1 1"` was given, so the values **`0x00000001`** of the stack come from the **user input**. You can see how this values starts in `$ebp - 8`. Therefore, in the code we have **subtracted 8 bytes to `$esp` \(as in that moment `$ebp` and `$esp` had the same value\)** and then we have pushed the BVS.

![](../../../.gitbook/assets/image%20%28613%29.png)





