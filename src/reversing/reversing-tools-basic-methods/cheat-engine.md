# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is a useful program to find where important values are saved inside the memory of a running game and change them.\
When you download and run it, you are **presented** with a **tutorial** of how to use the tool. If you want to learn how to use the tool it's highly recommended to complete it.

## What are you searching?

![Cheat Engine - What are you searching?: What are you searching?](<../../images/image (762).png>)

This tool is very useful to find **where some value** (usually a number) **is stored in the memory** of a program.\
**Usually numbers** are stored in **4bytes** form, but you could also find them in **double** or **float** formats, or you may want to look for something **different from a number**. For that reason you need to be sure you **select** what you want to **search for**:

![Cheat Engine - What are you searching?: Usually numbers are stored in 4bytes form, but you could also find them in double or float formats, or you may want to look for something...](<../../images/image (324).png>)

Also you can indicate **different** types of **searches**:

![Cheat Engine - What are you searching?: Also you can indicate different types of searches](<../../images/image (311).png>)

You can also check the box to **stop the game while scanning the memory**:

![Cheat Engine - What are you searching?: You can also check the box to stop the game while scanning the memory](<../../images/image (1052).png>)

### Hotkeys

In _**Edit --> Settings --> Hotkeys**_ you can set different **hotkeys** for different purposes like **stopping** the **game** (which is quiet useful if at some point you want to scan the memory). Other options are available:

![What are you searching? - Hotkeys: In Edit -- Settings -- Hotkeys you can set different hotkeys for different purposes like stopping the game (which is quiet useful if at some point you...](<../../images/image (864).png>)

## Modifying the value

Once you **found** where is the **value** you are **looking for** (more about this in the following steps) you can **modify it** double clicking it, then double clicking its value:

![Hotkeys - Modifying the value: Once you found where is the value you are looking for (more about this in the following steps) you can modify it double clicking it, then double clicking...](<../../images/image (563).png>)

And finally **marking the check** to get the modification done in the memory:

![Hotkeys - Modifying the value: And finally marking the check to get the modification done in the memory](<../../images/image (385).png>)

The **change** to the **memory** will be immediately **applied** (note that until the game doesn't use this value again the value **won't be updated in the game**).

## Searching the value

So, we are going to suppose that there is an important value (like the life of your user) that you want to improve, and you are looking for this value in the memory)

### Through a known change

Supposing you are looking for the value 100, you **perform a scan** searching for that value and you find a lot of coincidences:

![Searching the value - Through a known change: Supposing you are looking for the value 100, you perform a scan searching for that value and you find a lot of coincidences](<../../images/image (108).png>)

Then, you do something so that **value changes**, and you **stop** the game and **perform** a **next scan**:

![Searching the value - Through a known change: Then, you do something so that value changes , and you stop the game and perform a next scan](<../../images/image (684).png>)

Cheat Engine will search for the **values** that **went from 100 to the new value**. Congrats, you **found** the **address** of the value you were looking for, you can now modify it.\
_If you still have several values, do something to modify again that value, and perform another "next scan" to filter the addresses._

### Unknown Value, known change

In the scenario you **don't know the value** but you know **how to make it change** (and even the value of the change) you can look for your number.

So, start by performing a scan of type "**Unknown initial value**":

![Through a known change - Unknown Value, known change: So, start by performing a scan of type " Unknown initial value "](<../../images/image (890).png>)

Then, make the value change, indicate **how** the **value** **changed** (in my case it was decreased by 1) and perform a **next scan**:

![Through a known change - Unknown Value, known change: Then, make the value change, indicate how the value changed (in my case it was decreased by 1) and perform a next scan](<../../images/image (371).png>)

You will be presented **all the values that were modified in the selected way**:

![Through a known change - Unknown Value, known change: You will be presented all the values that were modified in the selected way](<../../images/image (569).png>)

Once you have found your value, you can modify it.

Note that there are a **lot of possible changes** and you can do these **steps as much as you want** to filter the results:

![Through a known change - Unknown Value, known change: Note that there are a lot of possible changes and you can do these steps as much as you want to filter the results](<../../images/image (574).png>)

### Random Memory Address - Finding the code

Until know we learnt how to find an address storing a value, but it's highly probably that in **different executions of the game that address is in different places of the memory**. So lets find out how to always find that address.

Using some of the mentioned tricks, find the address where your current game is storing the important value. Then (stopping the game if you whish) do a **right click** on the found **address** and select "**Find out what accesses this address**" or "**Find out what writes to this address**":

![Unknown Value, known change - Random Memory Address - Finding the code: Using some of the mentioned tricks, find the address where your current game is storing the important value. Then...](<../../images/image (1067).png>)

The **first option** is useful to know which **parts** of the **code** are **using** this **address** (which is useful for more things like **knowing where you can modify the code** of the game).\
The **second option** is more **specific**, and will be more helpful in this case as we are interested in knowing **from where this value is being written**.

Once you have selected one of those options, the **debugger** will be **attached** to the program and a new **empty window** will appear. Now, **play** the **game** and **modify** that **value** (without restarting the game). The **window** should be **filled** with the **addresses** that are **modifying** the **value**:

![Unknown Value, known change - Random Memory Address - Finding the code: Once you have selected one of those options, the debugger will be attached to the program and a new empty window...](<../../images/image (91).png>)

Now that you found the address it's modifying the value you can **modify the code at your pleasure** (Cheat Engine allows you to modify it for NOPs real quick):

![Unknown Value, known change - Random Memory Address - Finding the code: Now that you found the address it's modifying the value you can modify the code at your pleasure (Cheat Engine...](<../../images/image (1057).png>)

So, you can now modify it so the code won't affect your number, or will always affect in a positive way.

### Random Memory Address - Finding the pointer

Following the previous steps, find where the value you are interested is. Then, using "**Find out what writes to this address**" find out which address writes this value and double click on it to get the disassembly view:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Following the previous steps, find where the value you are interested is. Then, using " Find out...](<../../images/image (1039).png>)

Then, perform a new scan **searching for the hex value between "\[]"** (the value of $edx in this case):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Then, perform a new scan searching for the hex value between " ()" (the value of $edx in this case)](<../../images/image (994).png>)

(_If several appear you usually need the smallest address one_)\
Now, we have f**ound the pointer that will be modifying the value we are interested in**.

Click on "**Add Address Manually**":

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Click on " Add Address Manually "](<../../images/image (990).png>)

Now, click on the "Pointer" check box and add the found address in the text box (in this scenario, the found address in the previous image was "Tutorial-i386.exe"+2426B0):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Now, click on the "Pointer" check box and add the found address in the text box (in this scenario,...](<../../images/image (392).png>)

(Note how the first "Address" is automatically populated from the pointer address you introduce)

Click OK and a new pointer will be created:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Click OK and a new pointer will be created](<../../images/image (308).png>)

Now, every time you modifies that value you are **modifying the important value even if the memory address where the value is is different.**

### Code Injection

Code injection is a technique where you inject a piece of code into the target process, and then reroute the execution of code to go through your own written code (like giving you points instead of resting them).

So, imagine you have found the address that is subtracting 1 to the life of your player:

![Random Memory Address - Finding the pointer - Code Injection: So, imagine you have found the address that is subtracting 1 to the life of your player](<../../images/image (203).png>)

Click on Show disassembler to get the **disassemble code**.\
Then, click **CTRL+a** to invoke the Auto assemble window and select _**Template --> Code Injection**_

![Random Memory Address - Finding the pointer - Code Injection: Then, click CTRL+a to invoke the Auto assemble window and select Template -- Code Injection](<../../images/image (902).png>)

Fill the **address of the instruction you want to modify** (this is usually autofilled):

![Random Memory Address - Finding the pointer - Code Injection: Fill the address of the instruction you want to modify (this is usually autofilled)](<../../images/image (744).png>)

A template will be generated:

![Random Memory Address - Finding the pointer - Code Injection: A template will be generated](<../../images/image (944).png>)

So, insert your new assembly code in the "**newmem**" section and remove the original code from the "**originalcode**" if you don't want it to be executed**.** In this example the injected code will add 2 points instead of substracting 1:

![Random Memory Address - Finding the pointer - Code Injection: So, insert your new assembly code in the " newmem " section and remove the original code from the " originalcode " if you...](<../../images/image (521).png>)

**Click on execute and so on and your code should be injected in the program changing the behaviour of the functionality!**

## Relocation-safe code injection with AOB signatures

A script that hooks `game.exe+123456` can break after ASLR or a software update. An **Array of Bytes (AOB) signature** finds the instruction from its surrounding machine code instead. Use `aobscanmodule` to restrict the search to one module. Make the signature long enough to return one match. Wildcard relocation bytes, addresses and other bytes that may change. Do not wildcard the whole instruction that you need to restore.<sup>[[4]](#references)</sup>

In Memory View, select the instruction and use **Tools → Auto Assemble → Template → AOB Injection**. The generated `[DISABLE]` block is important. It must restore every overwritten byte and free the allocation.<sup>[[4]](#references)</sup>

<details>
<summary>Minimal x64 AOB injection skeleton</summary>

```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
  movss [rbx+000000A0],xmm0
  jmp return
INJECT:
  jmp newmem
  nop
  nop
  nop
return:
[DISABLE]
INJECT:
  db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```

</details>

Before enabling the script, verify these points:

1. The AOB returns **one** address. Add stable instructions on both sides if it returns more.
2. The jump replaces complete instructions. Never split an instruction.
3. The allocated cave is reachable by the generated jump. On x64, a far allocation may need a 14-byte jump.
4. The injected code preserves registers, flags and stack alignment that the original function expects.
5. The disable block restores the exact original bytes. Test enable and disable several times before saving the table.

## Reliable pointer workflow

A pointer found in one run is only a candidate. Build pointer maps in several fresh executions and rescan against all of them. Restart the target between captures so ASLR and heap allocations change. Prefer paths whose base is a module or another stable symbol. Reject paths that only work with one save, level or object instance.

The **pointer must end with specific offsets** filter and its deviation option can keep useful paths when a nearby field moves between builds. The 7.5 release also added this deviation control. It is a filter, not proof that a pointer chain is stable.<sup>[[1]](#references)</sup>

When a structure moves too often for pointer scanning, hook the instruction that accesses it. Capture the live object pointer from a register into an allocated symbol. This is often more reliable for entity lists and managed objects.

## Tracing code instead of scanning values

Use **Find out what writes to this address** when the value is directly modified. Use **Find out what accesses this address** when you need the owning object or when the write happens through copied data. Trigger only one action in the target. Then compare the hit count and register state.

**Ultimap 2** uses Intel Processor Trace on supported Intel CPUs. It records executed control flow with less interruption than stepping every instruction. Filter for code that executed while the interesting action occurred and remove code that also executed during an idle capture. Intel PT is not a stealth feature. The target can still detect tracing, timing changes or Cheat Engine itself.<sup>[[1]](#references)</sup>

Cheat Engine 7.5 also added an Intel PT interface provided by Windows. The older DBVM-backed Ultimap mode and the Intel PT mode have different hardware and OS requirements. Do not assume that a DBVM-capable CPU supports Intel PT.<sup>[[1]](#references)</sup>

## Debugger and breakpoint selection

Choose the least invasive debugger that works:

- **Windows debugger** is simple but creates normal debug events. Anti-debugging checks can detect it.
- **VEH debugger** handles breakpoints through a vectored exception handler. It avoids some basic debugger checks but it is not invisible.
- **Hardware breakpoints** do not patch the instruction bytes, but x86/x64 provides only a small number of debug-register slots.
- **Software breakpoints** replace a byte with `INT3`. They are easy to detect and can conflict with integrity checks.
- **DBVM debugger** moves some operations below the guest OS. It has much more privilege and can crash the host if it is misconfigured.

Cheat Engine 7.5 can use a one-byte jump based on an exception handler and `INT3` when there is not enough room for a normal relative jump. Treat it like a software breakpoint. Verify exception flow and do not assume that it bypasses anti-tamper checks.<sup>[[1]](#references)</sup>

DBVM is a hypervisor, not a general invisibility switch. Use it only in a disposable lab. Do not expose its control interface to untrusted code. Kernel anti-cheat and endpoint products may still detect the driver, hypervisor state or modified memory.

## Managed runtimes and recent 7.6/7.7 features

For Mono, IL2CPP, .NET and Java targets, prefer runtime metadata over blind scans when it is available. Open **Mono → Activate mono features** or the corresponding runtime information window. Locate the class, field or method first. Then use the native disassembly when the managed method is JIT-compiled.

The 7.6 line added `AOBSCANEX` for executable-memory-only signatures, a `gdbserver` debugger interface, Java metadata inspection, faster IL2CPP enumeration and a pointer-scan option that ignores the upper pointer byte used by ARM memory tagging. The 7.7 line added native Linux builds, `HOOK`/`UNHOOK`, `aobscanfunction`, better generic Mono method lookup, improved PDB structure support and basic Unreal Engine structure dissection.<sup>[[3]](#references)</sup>

These additions enable a useful workflow:

1. Resolve a managed method or static field from metadata.
2. Trace or disassemble the native code produced for that method.
3. Use `AOBSCANEX` or `aobscanfunction` to locate a stable executable signature.
4. Generate a reversible hook. Keep the original instructions and validate the disable path.
5. Recheck the signature after every target update. A successful match does not guarantee that the surrounding logic still has the same meaning.

## Remote targets with `ceserver`

`ceserver` exposes process enumeration, memory access and debugging to the Cheat Engine GUI. Official builds cover Linux and Android. Run the matching architecture on the target and connect through the **Network** tab. On Android, forwarding the default port avoids exposing it on the network:<sup>[[3]](#references)</sup>

```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```

The third-party `frida-ceserver` bridge can provide a Cheat Engine-compatible interface for iOS targets. It is not the official `ceserver` and its supported operations may differ.<sup>[[2]](#references)</sup>

Assume the protocol grants debugger-level access. Bind it to loopback or place it behind an SSH/ADB tunnel. Never expose TCP 52736 to an untrusted network. Stop the server when the session ends.

## Operational safety

Only attach to software you own or are authorized to test. Do not run Cheat Engine beside an online game or production endpoint. Memory writes, injected code, drivers and DBVM can crash or corrupt the target.<sup>[[3]](#references)</sup>

Download builds from the official site or compile the published source. Security products often classify memory editors, debuggers and their drivers as hack tools. Do not disable host protection globally. Use a dedicated VM or lab host and verify the artifact before running it.<sup>[[3]](#references)</sup>



## References

- [1] [Cheat Engine 7.5 release notes](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver bridge for remote targets](https://github.com/gmh5225/frida-ceserver)
- [3] [Cheat Engine official release news](https://www.cheatengine.org/)
- [4] [Cheat Engine Wiki: Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
