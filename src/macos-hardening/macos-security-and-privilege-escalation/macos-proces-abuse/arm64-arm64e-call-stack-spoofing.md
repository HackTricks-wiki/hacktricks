# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## Why metadata-driven unwinding can be spoofed

Some macOS security tooling delegates thread-stack collection to `/usr/sbin/spindump` or otherwise trusts a conventional metadata-driven unwinder. An implant can exploit that trust boundary by placing ABI-correct synthetic records on its stack so a sensitive API appears to have been reached through attacker-selected functions in dyld and loaded Apple frameworks instead of from unbacked implant code. This is telemetry deception, not a change to the executable or its unwind metadata.<sup>[[1]](#references)</sup>

An unwinder does not prove that a compiler-generated prologue created a record. It repeatedly uses the current `PC` to choose a Mach-O recipe, applies that recipe to `SP`, `x29`, `x30`, stack memory and any declared nonvolatile registers, and uses the recovered caller `PC` to select the next recipe. If attacker-controlled memory satisfies every selected recipe, the resulting chain can be structurally valid and symbolizable even though those calls never happened.<sup>[[1]](#references)</sup>

## ARM64 frame state

`SP` is the current allocation boundary, `x29`/`FP` conventionally points to the saved frame record, `x30`/`LR` holds the immediate return address, and `x19-x28` are callee-saved GPRs. `BL`/`BLR` write the address following the call into LR; unlike an x86 `call`, they do not push it. A non-leaf framed function therefore saves LR explicitly, normally alongside the caller FP.<sup>[[1]](#references)[[4]](#references)</sup>

A common frame is created with `stp x29, x30, [sp, #-16]!` followed by `mov x29, sp`. Its Canonical Frame Address (CFA), representing the caller's entry `SP`, is `FP+0x10`:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Frame records form a linked list through `[FP]`, but blindly following that list is insufficient: leaf functions may be frameless, tail calls may remove logical transitions, and unusual layouts use DWARF CFI. The recipe selected by the current address determines whether the unwinder reads the FP chain at all.<sup>[[1]](#references)[[4]](#references)</sup>

## Selecting a Mach-O unwind recipe

Final linked images store compact unwind data in `__TEXT,__unwind_info`. The section header points to a first-level function index; each index range points to a regular (`kind=2`) or compressed (`kind=3`) second-level page. Layouts that compact unwind cannot describe use an FDE and call-frame instructions in `__eh_frame`.<sup>[[1]](#references)[[2]](#references)</sup>

For each candidate runtime PC:<sup>[[1]](#references)[[2]](#references)</sup>

1. Strip or normalize ARM64e PAC bits for lookup only.
2. Find the loaded Mach-O whose executable `__TEXT` range contains the address.
3. Calculate `functionOffset = normalizedPC - loadedImageBase` and reject negative results or values above `UINT32_MAX`.
4. Select the first-level range satisfying `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`.
5. Parse the referenced second-level page, choose the closest entry whose start does not exceed the offset, and verify the address is below the next entry or first-level range end.
6. Decode that entry and construct the exact state it describes.

When an address came from a saved LR, lookup may use `PC-1` so that an address immediately after a call remains in the caller's covered range. This changes recipe selection, not any stack offset.<sup>[[1]](#references)</sup>

A parser must bounds-check every header and array, require section version `1`, account for the final first-level sentinel, reject a zero second-level-page offset, and distinguish regular from compressed pages. In a regular page, `entryPageOffset` is relative to the start of that page, whereas the first-level page offset is relative to the start of `__unwind_info`.<sup>[[1]](#references)[[2]](#references)</sup>

The broad mode is `encoding & 0x0F000000`. Current LLVM definitions include the following modes; a parser should not treat every non-DWARF value as a classic frame:<sup>[[2]](#references)</sup>

| Mode | Value | Caller recovery |
| --- | --- | --- |
| No compact recipe | `0x00000000` | Stop or use an independent fallback. |
| Frameless | `0x02000000` | Add the encoded stack size to current `SP`; caller PC is live LR. |
| DWARF | `0x03000000` | Execute the FDE/CFI identified by the low 24 bits. |
| Frame | `0x04000000` | Read the conventional `x29` frame record. |
| arm64e frame with authenticated LR range | `0x05000000` | Handle `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`; its offset field locates `pacibsppc` within the covered range. |

For frameless mode, `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`. For frame mode, the five low bits declare contiguous saved GPR pairs `x19/x20` through `x27/x28`; bits `0x100-0x800` similarly declare `d8-d15` pairs. Those saved registers may not be necessary to find the next PC, but a believable virtual caller state must satisfy every field the consumer reconstructs.<sup>[[1]](#references)[[2]](#references)</sup>

## Constructing synthetic frame-mode records

The construction process reverses the unwinder rather than scanning the stack for address-like values:<sup>[[1]](#references)</sup>

1. Choose a real executable PC in a currently loaded image.
2. Decode the recipe covering that precise PC or call-site address.
3. Allocate a synthetic record with the required alignment and CFA relationship.
4. Store the next synthetic FP at `[FP]`, that frame's saved caller PC at `[FP+8]`, and every GPR/FPR save declared by the encoding below FP.
5. Link several records and put the first record in live `x29`.
6. Arrange live LR and the API return path so unwinding enters the chosen chain while execution can still be restored safely.

For example, `0x04000001` means frame mode plus the `x19/x20` pair. The corresponding state transformation and required memory are:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

A legitimate-looking address is therefore not enough. Every recovered PC becomes the key for the next lookup, so a single address whose encoding disagrees with the fabricated layout breaks the chain or causes the consumer to reconstruct inconsistent register state.<sup>[[1]](#references)</sup>

## ARM64e PAC requirements

PAC stores a keyed integrity value in otherwise spare pointer bits; it does not encrypt the address. Clang's arm64e return-address schema uses instruction key B and the stack pointer on function entry as the discriminator. For a conventional frame, that entry `SP` is the CFA, so the saved LR at `[FP+8]` is bound to `FP+0x10`.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Each synthetic LR must be signed independently because moving an already signed LR to a frame with a different CFA changes the discriminator and makes authentication fail. `ptrauth_strip()` is suitable for address normalization and symbol lookup but does **not** establish authenticity; any real return or authenticated indirect branch must use the key and modifier expected at that exact transition.<sup>[[1]](#references)[[3]](#references)</sup>

A typical non-leaf arm64e function signs LR before storing it and authenticates after restoring the entry SP:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline and restore bridge

Synthetic records only need to satisfy the unwinder; they do not contain a complete execution context. Returning from the sensitive API directly into the fabricated callers would normally crash. The practical design therefore places a gadget frame immediately below the API: the API returns to executable code in a loaded framework, and that gadget branches through a controlled callee-saved register to a restore bridge in the implant.<sup>[[1]](#references)</sup>

A useful gadget preserves LR and transfers through a controlled register, for example an appropriate `br`, `braa` or `brab` sequence. The restore bridge must recover the original `x19-x30` values and `SP` before resuming implant execution. On arm64e, the API-to-gadget return, gadget-to-bridge branch and bridge-to-implant transition each require a pointer signed for the precise key and discriminator used by that instruction.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

The result is an important trust-boundary failure for stack-based detections: a chain can contain only mapped, symbolizable Apple-framework PCs and still not represent actual control flow. Unwind output should therefore be corroborated with independent evidence about the thread's executable-memory provenance and the real transitions around the sensitive API rather than treated as an execution trace.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - ARM64 stack internals and obfuscation on Apple Silicon](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Mach-O compact unwind encoding definitions](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Pointer Authentication](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Procedure Call Standard for the Arm 64-bit Architecture](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)

{{#include ../../../banners/hacktricks-training.md}}
