# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is a useful program to find where important values are saved inside the memory of a running game and change them.\
When you download and run it, you are **presented** with a **tutorial** of how to use the tool. If you want to learn how to use the tool it's highly recommended to complete it.

## What are you searching?

![](<../../images/image (762).png>)

This tool is very useful to find **where some value** (usually a number) **is stored in the memory** of a program.\
**Usually numbers** are stored in **4bytes** form, but you could also find them in **double** or **float** formats, or you may want to look for something **different from a number**. For that reason you need to be sure you **select** what you want to **search for**:

![](<../../images/image (324).png>)

Also you can indicate **different** types of **searches**:

![](<../../images/image (311).png>)

You can also check the box to **stop the game while scanning the memory**:

![](<../../images/image (1052).png>)

### Hotkeys

In _**Edit --> Settings --> Hotkeys**_ you can set different **hotkeys** for different purposes like **stopping** the **game** (which is quiet useful if at some point you want to scan the memory). Other options are available:

![](<../../images/image (864).png>)

## Modifying the value

Once you **found** where is the **value** you are **looking for** (more about this in the following steps) you can **modify it** double clicking it, then double clicking its value:

![](<../../images/image (563).png>)

And finally **marking the check** to get the modification done in the memory:

![](<../../images/image (385).png>)

The **change** to the **memory** will be immediately **applied** (note that until the game doesn't use this value again the value **won't be updated in the game**).

## Searching the value

So, we are going to suppose that there is an important value (like the life of your user) that you want to improve, and you are looking for this value in the memory)

### Through a known change

Supposing you are looking for the value 100, you **perform a scan** searching for that value and you find a lot of coincidences:

![](<../../images/image (108).png>)

Then, you do something so that **value changes**, and you **stop** the game and **perform** a **next scan**:

![](<../../images/image (684).png>)

Cheat Engine will search for the **values** that **went from 100 to the new value**. Congrats, you **found** the **address** of the value you were looking for, you can now modify it.\
_If you still have several values, do something to modify again that value, and perform another "next scan" to filter the addresses._

### Unknown Value, known change

In the scenario you **don't know the value** but you know **how to make it change** (and even the value of the change) you can look for your number.

So, start by performing a scan of type "**Unknown initial value**":

![](<../../images/image (890).png>)

Then, make the value change, indicate **how** the **value** **changed** (in my case it was decreased by 1) and perform a **next scan**:

![](<../../images/image (371).png>)

You will be presented **all the values that were modified in the selected way**:

![](<../../images/image (569).png>)

Once you have found your value, you can modify it.

Note that there are a **lot of possible changes** and you can do these **steps as much as you want** to filter the results:

![](<../../images/image (574).png>)

### Random Memory Address - Finding the code

Until know we learnt how to find an address storing a value, but it's highly probably that in **different executions of the game that address is in different places of the memory**. So lets find out how to always find that address.

Using some of the mentioned tricks, find the address where your current game is storing the important value. Then (stopping the game if you whish) do a **right click** on the found **address** and select "**Find out what accesses this address**" or "**Find out what writes to this address**":

![](<../../images/image (1067).png>)

The **first option** is useful to know which **parts** of the **code** are **using** this **address** (which is useful for more things like **knowing where you can modify the code** of the game).\
The **second option** is more **specific**, and will be more helpful in this case as we are interested in knowing **from where this value is being written**.

Once you have selected one of those options, the **debugger** will be **attached** to the program and a new **empty window** will appear. Now, **play** the **game** and **modify** that **value** (without restarting the game). The **window** should be **filled** with the **addresses** that are **modifying** the **value**:

![](<../../images/image (91).png>)

Now that you found the address it's modifying the value you can **modify the code at your pleasure** (Cheat Engine allows you to modify it for NOPs real quick):

![](<../../images/image (1057).png>)

So, you can now modify it so the code won't affect your number, or will always affect in a positive way.

### Random Memory Address - Finding the pointer

Following the previous steps, find where the value you are interested is. Then, using "**Find out what writes to this address**" find out which address writes this value and double click on it to get the disassembly view:

![](<../../images/image (1039).png>)

Then, perform a new scan **searching for the hex value between "\[]"** (the value of $edx in this case):

![](<../../images/image (994).png>)

(_If several appear you usually need the smallest address one_)\
Now, we have f**ound the pointer that will be modifying the value we are interested in**.

Click on "**Add Address Manually**":

![](<../../images/image (990).png>)

Now, click on the "Pointer" check box and add the found address in the text box (in this scenario, the found address in the previous image was "Tutorial-i386.exe"+2426B0):

![](<../../images/image (392).png>)

(Note how the first "Address" is automatically populated from the pointer address you introduce)

Click OK and a new pointer will be created:

![](<../../images/image (308).png>)

Now, every time you modifies that value you are **modifying the important value even if the memory address where the value is is different.**

### Code Injection

Code injection is a technique where you inject a piece of code into the target process, and then reroute the execution of code to go through your own written code (like giving you points instead of resting them).

So, imagine you have found the address that is subtracting 1 to the life of your player:

![](<../../images/image (203).png>)

Click on Show disassembler to get the **disassemble code**.\
Then, click **CTRL+a** to invoke the Auto assemble window and select _**Template --> Code Injection**_

![](<../../images/image (902).png>)

Fill the **address of the instruction you want to modify** (this is usually autofilled):

![](<../../images/image (744).png>)

A template will be generated:

![](<../../images/image (944).png>)

So, insert your new assembly code in the "**newmem**" section and remove the original code from the "**originalcode**" if you don't want it to be executed**.** In this example the injected code will add 2 points instead of substracting 1:

![](<../../images/image (521).png>)

**Click on execute and so on and your code should be injected in the program changing the behaviour of the functionality!**

## Advanced features in Cheat Engine 7.x (2023-2025)

Cheat Engine has continued to evolve since version 7.0 and several quality-of-life and *offensive-reversing* features have been added that are extremely handy when analysing modern software (and not only games!). Below is a **very condensed field guide** to the additions you will most likely use during red-team/CTF work.

### Pointer Scanner 2 improvements
* `Pointers must end with specific offsets` and the new **Deviation** slider (≥7.4) greatly reduce false positives when you rescan after an update. Use it together with multi-map comparison (`.PTR` → *Compare results with other saved pointer map*) to obtain a **single resilient base-pointer** in just a few minutes.
* Bulk-filter shortcut: after the first scan press `Ctrl+A → Space` to mark everything, then `Ctrl+I` (invert) to deselect addresses that failed the rescan.

### Ultimap 3 – Intel PT tracing
*From 7.5 the old Ultimap was re-implemented on top of **Intel Processor-Trace (IPT)***. This means you can now record *every* branch the target takes **without single-stepping** (user-mode only, it will not trip most anti-debug gadgets).

```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
After a few seconds stop the capture and **right-click → Save execution list to file**. Combine branch addresses with a `Find out what addresses this instruction accesses` session to locate high-frequency game-logic hotspots extremely fast. 

### 1-byte `jmp` / auto-patch templates
Version 7.5 introduced a *one-byte* JMP stub (0xEB) that installs an SEH handler and places an INT3 at the original location. It is generated automatically when you use **Auto Assembler → Template → Code Injection** on instructions that cannot be patched with a 5-byte relative jump. This makes “tight” hooks possible inside packed or size-constrained routines.

### Kernel-level stealth with DBVM (AMD & Intel)
*DBVM* is CE’s built-in Type-2 hypervisor. Recent builds finally added **AMD-V/SVM support** so you can run `Driver → Load DBVM` on Ryzen/EPYC hosts. DBVM lets you:
1. Create hardware breakpoints invisible to Ring-3/anti-debug checks.
2. Read/write pageable or protected kernel memory regions even when the user-mode driver is disabled.
3. Perform VM-EXIT-less timing-attack bypasses (e.g. query `rdtsc` from the hypervisor).

**Tip:** DBVM will refuse to load when HVCI/Memory-Integrity is enabled on Windows 11 → turn it off or boot a dedicated VM-host.

### Remote / cross-platform debugging with **ceserver**
CE now ships a full rewrite of *ceserver* and can attach over TCP to **Linux, Android, macOS & iOS** targets. A popular fork integrates *Frida* to combine dynamic instrumentation with CE’s GUI – ideal when you need to patch Unity or Unreal games running on a phone:

```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
For the Frida bridge see `bb33bb/frida-ceserver` on GitHub. 

### Other noteworthy goodies
* **Patch Scanner** (MemView → Tools) – detects unexpected code changes in executable sections; handy for malware analysis.
* **Structure Dissector 2** – drag-an-address → `Ctrl+D`, then *Guess fields* to auto-evaluate C-structures.
* **.NET & Mono Dissector** – improved Unity game support; call methods directly from the CE Lua console.
* **Big-Endian custom types** – reversed byte order scan/edit (useful for console emulators and network packet buffers).
* **Autosave & tabs** for AutoAssembler/Lua windows, plus `reassemble()` for multi-line instruction rewrite.

### Installation & OPSEC notes (2024-2025)
* The official installer is wrapped with InnoSetup **ad-offers** (`RAV` etc.). **Always click *Decline*** *or compile from source* to avoid PUPs. AVs will still flag `cheatengine.exe` as a *HackTool*, which is expected.
* Modern anti-cheat drivers (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) detect CE’s window class even when renamed. Run your reversing copy **inside a disposable VM** or after disabling network play.
* If you only need user-mode access choose **`Settings → Extra → Kernel mode debug = off`** to avoid loading CE’s unsigned driver that may BSOD on Windows 11 24H2 Secure-Boot.

---

## **References**

- [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- **Cheat Engine tutorial, complete it to learn how to start with Cheat Engine**

{{#include ../../banners/hacktricks-training.md}}



