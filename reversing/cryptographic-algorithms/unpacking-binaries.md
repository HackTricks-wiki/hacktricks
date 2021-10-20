# Unpacking binaries

## Identifying packed binaries

* **lack of strings**: It's common to find that packed binaries doesn't have almost any string
* A lot of **unused strings**: Also, when a malware is using some kind of commercial packer it's common to find a lot of strings without cross-references. Even if these strings exist that doesn't mean that the binary isn't packed.
* You can also use some tools to try to find which packer was used to pack a binary:
  * [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
  * [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
  * [Language 2000](http://farrokhi.net/language/)

## Basic Recommendations

* **Start **analysing the packed binary **from the bottom in IDA and move up**. Unpackers exit once the unpacked code exit so it's unlikely that the unpacker passes execution to the unpacked code at the start.
* Search for **JMP's **or **CALLs **to **registers **or **regions** of **memory**. Also search for **functions pushing arguments and an address direction and then calling `retn`**, because the return of the function in that case may call the address just pushed to the stack before calling it.
* Put a **breakpoint **on `VirtualAlloc` as this allocates space in memory where the program can write unpacked code. The "run to user code" or use F8 to **get to value inside EAX** after executing the function and "**follow that address in dump**". You never know if that is the region where the unpacked code is going to be saved.
  * **`VirtualAlloc`** with the value "**40**" as an argument means Read+Write+Execute (some code that needs execution is going to be copied here).
* **While unpacking **code it's normal to find **several calls** to** arithmetic operations** and functions like **`memcopy`** or **`Virtual`**`Alloc`. If you find yourself in a function that apparently only perform arithmetic operations and maybe some` memcopy` , the recommendation is to try to **find the end of the function** (maybe a JMP or call to some register) **or **at least the** call to the last function** and run to then as the code isn't interesting.
* While unpacking code **note **whenever you **change memory region** as a memory region change may indicate the **starting of the unpacking code**. You can easily dump a memory region using Process Hacker (process --> properties --> memory).
* While trying to unpack code a good way to **know if you are already working with the unpacked code** (so you can just dump it) is to **check the strings of the binary**. If at some point you perform a jump (maybe changing the memory region) and you notice that **a lot more strings where added**, then you can know **you are working with the unpacked code**.\
  However, if the packer already contains a lot of strings you can see how many strings contains the word "http" and see if this number increases.
* When you dump an executable from a region of memory you can fix some headers using [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).
