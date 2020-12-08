# Unpacking binaries

* lack of strings
* search for JMP's or CALLs to registers or regions of memory. Also search for functions pushing arguments and an address direction and the calling retn, because the return of the function in that case may call the address just pushed to the stack before calling it.
* Put a breakpoint on `VirtualAlloc` as this allocates space in memory where the program can write unpacked code.
* Start analysing the packer from the bottom in IDA before moving up. Unpackers exit once the unpacked code exit so it's unlikely that the unpacker passes execution to the unpacked code at the start.
* If the unpacked code gets executed use a tool such as PE-Sieve to dump the unpacked process once it has executed and unpacked itself
* VirtualAlloc with the value "40" as an argument means Read+Write+Execute \(some code that needs execution is going to be copied here\)
* While unpacking code it's normal to find several calls to arithmetic operations and functions like `memcopy` or `VirtualAlloc`. If you find yourself in a function that apparently only has those functions the recommendation is to try to find the end of the function \(maybe a JMP or call to some register\) or at least the call to the last function and navigate to therein order to bypass that unpacking code.
* While unpacking code note whenever you change memory region as a memory region change may indicate the starting of the unpacking code. You can easily dump a memory region using Process Hacker.

