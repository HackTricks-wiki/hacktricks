# Virtualized Payload Execution and Custom VM Evasion

{{#include ../banners/hacktricks-training.md}}

Payload virtualization compiles offensive logic to a guest instruction set and executes it with a native interpreter. Unlike a packer, which must eventually expose the original native instructions in memory, a virtualized payload can keep the protected logic as bytecode for its entire lifetime. This removes that specific unpacking window, but it does **not** hide host-visible behavior such as syscalls, network activity, or the VM-to-native call boundary.<sup>[[2]](#references)[[3]](#references)</sup>

## WebAssembly re-hosting for static-analysis evasion

Instead of editing a heavily signatured Go tool, it can be compiled as a `wasip1` guest and embedded in a separate native loader. The guest is built against a patched GOROOT in which unsupported operations such as `net.Dial`, `net.Listen`, `os/exec` and `os.Pipe` delegate through `//go:wasmimport`; a Wazero host module then implements sockets, process operations, Win32 calls and macOS framework calls. This keeps the original project's Go API usage intact while moving most of its logic into an encrypted WASM module that static PE tooling may not understand.<sup>[[4]](#references)</sup>

### Bridging linear memory to native APIs

A guest pointer is a 32-bit offset into WASM linear memory, not a host virtual address. Before a native call, the bridge can translate an argument only when it is marked as a local pointer and falls in the range `0x10000 <= value < wasmMemorySize`, producing `wasmMemoryBase + value`. The lower bound avoids rewriting small handles, flags and `nil`; per-API masks generated from `win32metadata` distinguish real pointers from handles, sizes and remote-process addresses, with overrides for inaccurate or ambiguous metadata.<sup>[[4]](#references)</sup>

Native APIs may also return host pointers through guest output buffers. A mirror table can assign such objects guest-memory representations and retain a reverse mapping to the original host address. COM requires mirroring both the interface and its vtable: data pointers can be followed and mirrored, whereas executable pointers in `MEM_IMAGE` regions must remain opaque tokens because WASM cannot execute native instructions. This model does not directly support host-to-guest callback APIs such as `EnumWindows` or `SetWindowsHookEx`.<sup>[[4]](#references)</sup>

### Per-build WASM VM polymorphism

The runtime and payload can be transformed together on every build: shuffle the opcode-to-handler table, rewrite every guest opcode to the new mapping, randomize section identifiers, replace the standard `\0asm` magic with a build-specific marker and change runtime cache magic. Identical source then yields bytewise-different modules, and ordinary WASM tooling cannot parse the payload until the analyst recovers the custom mapping and framing from the host loader.<sup>[[4]](#references)</sup>

For reverse engineering, start with the native host rather than carving only on `\0asm`: identify the compiled marker, module-decryption path, opcode dispatch table and `env` host-function registrations, then reconstruct a standard module or instrument the import boundary. The bridge remains a useful behavioral choke point because calls for networking, process creation, registry access, dynamic loading and generic Win32 dispatch cross it even when the embedded bytecode changes between builds.<sup>[[4]](#references)</sup>

### Camouflaging the outer Go executable

Changing the guest alone still leaves a recognizable loader. The demonstrated outer-binary transformations splice dense symbol profiles harvested from legitimate Go projects into `gopclntab`, rotate a small plausible set of DLL imports, and vary PE `VERSIONINFO` plus Authenticode identity strings. These transformations target static and machine-learning features of the container; they do not remove the runtime behavior exposed by the host shims.<sup>[[4]](#references)</sup>

## Execution model

A compact virtualized loader can split execution into the following layers.<sup>[[3]](#references)</sup>

1. Compile freestanding C, BOF source, or runtime libraries through LLVM into a custom bytecode ISA.
2. Start a small native interpreter and initialize a build-specific opcode mapping.
3. Run the PE linker-loader itself as bytecode: parse headers, map sections, apply relocations, resolve imports, and populate the IAT.
4. Keep guest-to-guest calls inside the interpreter. Route targets outside the bytecode region, such as imported DLL functions, through a native host-call thunk.
5. Move supporting facilities such as HTTP framing, TLS, and parts of the C runtime behind the same interpretation boundary.

This model avoids allocating a separate native code region for every plugin and prevents the original payload from appearing as a recognizable x86-64 instruction stream. It is still an evasion/obfuscation boundary rather than a security boundary: the native interpreter and every external effect remain observable.<sup>[[2]](#references)[[3]](#references)</sup>

## Shared-memory host bridge

An isolated VM represents pointers as offsets into a guest buffer, so every host API crossing requires pointer translation and special handling for output parameters. A shared-memory VM instead makes guest addresses valid host-process addresses. Reads and writes can therefore use `memcpy`-style operations, and a pointer returned by a native allocation ECALL can be dereferenced directly by bytecode. RISC-Y Business demonstrated that this design can reduce the bridge to obtaining the PEB and issuing arbitrary host calls.<sup>[[1]](#references)</sup>

For Windows x64, the virtual register file can mirror the ABI: place the first four integer or pointer arguments in `RCX`, `RDX`, `R8`, and `R9`, with later arguments and shadow space on the stack. When a virtual `CALL` resolves outside the bytecode range, a universal thunk marshals that state into a native call and copies the return value back to the VM. This permits IAT calls, heap allocation, and socket operations without pointer fixups.<sup>[[2]](#references)[[3]](#references)</sup>

The tradeoff is complete loss of isolation. Guest memory corruption can affect the host directly, native callees can retain or modify guest pointers, and the interpreter must treat bytecode as fully trusted. Native-to-VM callbacks also need a reverse bridge; a VM that only supports outbound calls cannot directly satisfy callback-based APIs such as `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Per-build ISA polymorphism

A fixed-width custom ISA simplifies decoding, dispatch, relocation, and virtual-register mapping. Centurion uses an 18-byte, x86-64-inspired instruction format, which trades code density for predictable parsing and also leaves a possible path for translating existing x86-64 artifacts into bytecode.<sup>[[3]](#references)</sup>

Randomizing the opcode-to-handler mapping for each build makes identical guest logic produce different byte sequences. Encrypting the mapping table and recovering it only at runtime further removes a stable on-disk opcode dictionary. This frustrates fixed signatures and reusable disassembly rules, but it does not polymorph the native dispatcher, table-decryption routine, or host-call boundary automatically.<sup>[[3]](#references)</sup>

## Bringing the execution environment into the VM

The host process can be reduced to memory, syscall, and socket primitives while freestanding libraries provide higher-level services inside the VM. For example, FreeRTOS coreHTTP can implement HTTP framing and mbedTLS can implement TLS without calling WinHTTP or an operating-system TLS API. Raw sockets through `afd.sys` or a similar interface then become the narrow native networking boundary.<sup>[[3]](#references)</sup>

This **Bring Your Own Execution Environment (BYOEE)** design can also place PE loading, runtime support, and an in-memory filesystem behind the interpreter. It reduces recognizable native implementations rather than eliminating telemetry: raw socket operations remain visible, and environments that require explicit proxies or TLS interception may prevent the networking design from working.<sup>[[3]](#references)</sup>

## Selective native acceleration

Interpreting every instruction is especially expensive in public-key cryptography. A practical split uses mbedTLS's `MBEDTLS_ALT` hooks as a software-coprocessor interface: retain TLS state, certificate parsing, negotiation, allocation, and the high-level bignum code in bytecode, but dispatch the hot arithmetic kernels from `bignum_core.c` through native ECALLs. In the Centurion prototype, `bignum.c`, `bignum_mod.c`, and `bignum_mod_raw.c` stayed virtualized while the inner loops ran natively, reducing an ECDHE handshake from minutes to seconds.<sup>[[3]](#references)</sup>

Make accelerators optional so payloads that do not need TLS omit the additional native entry points. This pattern generalizes to any interpreter workload: profile first, then expose the smallest possible native primitive instead of moving an entire subsystem outside the VM.<sup>[[3]](#references)</sup>

Centurion validated the complete chain with a TLS 1.2 bind shell: the bytecode loader mapped the PE, socket calls crossed the universal thunk, mbedTLS handled the protocol inside the VM, and native ECALLs accelerated ECDHE arithmetic. The approximately 18 KB native interpreter therefore supported an encrypted command channel without materializing the payload as native x86-64 code.<sup>[[3]](#references)</sup>

## Reversing and detection anchors

The following are practical analysis anchors inferred from the architecture; virtualization changes where analysts observe behavior, but does not remove the behavior itself.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Identify the fetch/decode/dispatch loop, virtual program counter, register file, and repeated fixed-width instruction stepping.
- Dump the opcode table after runtime decryption and map handler addresses back to semantic operations rather than matching encrypted bytecode on disk.
- Break on the universal thunk or ECALL dispatcher to record the native target, virtual argument registers, stack arguments, and return value.
- Trace PEB access, export resolution, PE-header parsing, relocation writes, and IAT population even when the loader implementation itself is bytecode.
- Correlate socket creation and `afd.sys` traffic with an absence of expected WinHTTP or native TLS calls; the missing high-level imports are a clue, not proof of benign behavior.
- Treat native arithmetic accelerators as semantic chokepoints: their callers can reveal key exchange and certificate-validation activity while the surrounding TLS state machine remains virtualized.

For analysis workflows that start from the dispatcher rather than the original control-flow graph, see the [malware-analysis guidance for virtualizing packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Operational constraints

Virtualization imposes interpretation overhead, increases toolchain and ABI complexity, and does not solve behavioral detection. Shared memory is unsafe by design, raw-socket networking may fail behind mandatory proxies, and callback-heavy Win32 APIs require native-to-VM trampolines. The interpreter, syscall bridge, and any native accelerators also remain a conventional native footprint that defenders can signature or instrument.<sup>[[2]](#references)[[3]](#references)</sup>

## Related pages

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Building a RISC-V Virtual Machine for Payload Obfuscation](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red Teaming in the Age of EDR — Evasion Through Malware Virtualisation](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Bring Your Own Execution Environment](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - Enter the WasmForge: Compiling Sliver into WebAssembly](https://praetorian.com/blog/wasmforge-sliver-webassembly)

{{#include ../banners/hacktricks-training.md}}
