

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

# Wasm Decompilation and Wat Compilation Guide

In the realm of **WebAssembly**, tools for **decompiling** and **compiling** are essential for developers. This guide introduces some online resources and software for handling **Wasm (WebAssembly binary)** and **Wat (WebAssembly text)** files.

## Online Tools

- To **decompile** Wasm to Wat, the tool available at [Wabt's wasm2wat demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) comes in handy. 
- For **compiling** Wat back to Wasm, [Wabt's wat2wasm demo](https://webassembly.github.io/wabt/demo/wat2wasm/) serves the purpose.
- Another decompilation option can be found at [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Software Solutions

- For a more robust solution, [JEB by PNF Software](https://www.pnfsoftware.com/jeb/demo) offers extensive features.
- The open-source project [wasmdec](https://github.com/wwwg/wasmdec) is also available for decompilation tasks.

# .Net Decompilation Resources

Decompiling .Net assemblies can be accomplished with tools such as:

- [ILSpy](https://github.com/icsharpcode/ILSpy), which also offers a [plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), allowing cross-platform usage.
- For tasks involving **decompilation**, **modification**, and **recompilation**, [dnSpy](https://github.com/0xd4d/dnSpy/releases) is highly recommended. **Right-clicking** a method and choosing **Modify Method** enables code changes.
- [JetBrains' dotPeek](https://www.jetbrains.com/es-es/decompiler/) is another alternative for decompiling .Net assemblies.

## Enhancing Debugging and Logging with DNSpy

### DNSpy Logging
To log information to a file using DNSpy, incorporate the following .Net code snippet:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpy Debugging
For effective debugging with DNSpy, a sequence of steps is recommended to adjust **Assembly attributes** for debugging, ensuring that optimizations that could hinder debugging are disabled. This process includes changing the `DebuggableAttribute` settings, recompiling the assembly, and saving the changes.

Moreover, to debug a .Net application run by **IIS**, executing `iisreset /noforce` restarts IIS. To attach DNSpy to the IIS process for debugging, the guide instructs on selecting the **w3wp.exe** process within DNSpy and starting the debugging session.

For a comprehensive view of loaded modules during debugging, accessing the **Modules** window in DNSpy is advised, followed by opening all modules and sorting assemblies for easier navigation and debugging.

This guide encapsulates the essence of WebAssembly and .Net decompilation, offering a pathway for developers to navigate these tasks with ease. 

## **Java Decompiler**
To decompile Java bytecode, these tools can be very helpful:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Debugging DLLs**
### Using IDA
- **Rundll32** is loaded from specific paths for 64-bit and 32-bit versions.
- **Windbg** is selected as the debugger with the option to suspend on library load/unload enabled.
- Execution parameters include the DLL path and function name. This setup halts execution upon each DLL's loading.

### Using x64dbg/x32dbg
- Similar to IDA, **rundll32** is loaded with command line modifications to specify the DLL and function.
- Settings are adjusted to break on DLL entry, allowing breakpoint setting at the desired DLL entry point.

### Images
- Execution stopping points and configurations are illustrated through screenshots.

## **ARM & MIPS**
- For emulation, [arm_now](https://github.com/nongiach/arm_now) is a useful resource.

## **Shellcodes**
### Debugging Techniques
- **Blobrunner** and **jmp2it** are tools for allocating shellcodes in memory and debugging them with Ida or x64dbg.
  - Blobrunner [releases](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
  - jmp2it [compiled version](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** offers GUI-based shellcode emulation and inspection, highlighting differences in shellcode handling as a file versus direct shellcode.

### Deobfuscation and Analysis
- **scdbg** provides insights into shellcode functions and deobfuscation capabilities.
%%%bash
scdbg.exe -f shellcode # Basic info
scdbg.exe -f shellcode -r # Analysis report
scdbg.exe -f shellcode -i -r # Interactive hooks
scdbg.exe -f shellcode -d # Dump decoded shellcode
scdbg.exe -f shellcode /findsc # Find start offset
scdbg.exe -f shellcode /foff 0x0000004D # Execute from offset
%%%

- **CyberChef** for disassembling shellcode: [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- An obfuscator that replaces all instructions with `mov`.
- Useful resources include a [YouTube explanation](https://www.youtube.com/watch?v=2VF_wPkiBJY) and [PDF slides](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** might reverse movfuscator's obfuscation, requiring dependencies like `libcapstone-dev` and `libz3-dev`, and installing [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**
- For Delphi binaries, [IDR](https://github.com/crypto2011/IDR) is recommended.


# Courses

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Binary deobfuscation\)



{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}



