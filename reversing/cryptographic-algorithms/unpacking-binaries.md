# Unpacking binaries

* lack of strings
* search for JMP's or CALLs to registers or regions of memory. Also search for functions pushing arguments and an address direction and the calling retn, because the return of the function in that case may call the address just pushed to the stack before calling it.
* Put a breakpoint on `VirtualAlloc` as this allocates space in memory where the program can write unpacked code.
* Start analysing the packer from the bottom in IDA before moving up. Unpackers exit once the unpacked code exit so it's unlikely that the unpacker passes execution to the unpacked code at the start.
* If the unpacked code gets executed use a tool such as PE-Sieve to dump the unpacked process once it has executed and unpacked itself
* VirtualAlloc with the value "40" as an argument means Read+Write+Execute \(some code that needs execution is going to be copied here\)
* While unpacking code it's normal to find several calls to arithmetic operations and functions like `memcopy` or `VirtualAlloc`. If you find yourself in a function that apparently only has those functions the recommendation is to try to find the end of the function \(maybe a JMP or call to some register\) or at least the call to the last function and navigate to therein order to bypass that unpacking code.
* While unpacking code note whenever you change memory region as a memory region change may indicate the starting of the unpacking code. You can easily dump a memory region using Process Hacker.
* Custom packers normally won't have much strings and functions, commercial packers are stealthier and they will have them
* While trying to unpack code a good way to know if you are already working with the unpacked code \(you you can just dump it\) is to check the strings of the binary. If at some point you perform a jump \(maybe changing the memory region\) and you notice that a lot more strings where added, then you can know you are working with the unpacked code. However, if the packer already contains a lot of strings you can see how many strings contains the word "http" and see if this number increases.
* To jump from a call to an API function \(like VirtualProtect\) to user code you can press the "run to user code" button

