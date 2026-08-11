# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

Mach-o binary 的真实 **entrypoint** 是 dynamic linker，定义在 `LC_LOAD_DYLINKER` 中，通常为 `/usr/lib/dyld`。<sup>[[3]](#references)</sup>

该 linker 需要定位所有 executable libraries，将它们映射到内存中，并链接所有 non-lazy libraries。只有完成此过程后，binary 的 entry-point 才会执行。

当然，**`dyld`** 没有任何 dependencies（它使用 syscalls 和 libSystem excerpts）。

> [!CAUTION]
> 如果该 linker 存在任何 vulnerability，由于它会在执行任何 binary（甚至高权限 binary）之前执行，因此可能导致 **escalate privileges**。

### 流程

Dyld 将由 **`dyldboostrap::start`** 加载，该函数还会加载 **stack canary** 等内容。这是因为该函数会在其 **`apple`** argument vector 中接收这些以及其他 **敏感** **值**。<sup>[[1]](#references)</sup>

**`dyls::_main()`** 是 dyld 的 entry point，它的第一个任务是运行 `configureProcessRestrictions()`，该函数通常会限制文档中解释的 **`DYLD_*`** environment variables：<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

然后，它会映射 dyld shared cache，该 cache 对所有重要的 system libraries 进行了 prelink；接着映射 binary 所依赖的 libraries，并递归地继续执行，直到所有所需 libraries 都被加载。因此：

1. 它开始使用 `DYLD_INSERT_LIBRARIES` 加载 inserted libraries（如果允许）
2. 然后加载 shared cache 中的 libraries
3. 然后加载 imported libraries
1. 然后继续递归地导入 libraries

全部加载完成后，会运行这些 libraries 的 **initialisers**。它们使用 `__attribute__((constructor))` 编写，定义在 `LC_ROUTINES[_64]`（现已弃用）中，或者通过指针定义在标记为 `S_MOD_INIT_FUNC_POINTERS` 的 section 中（通常为：**`__DATA.__MOD_INIT_FUNC`**）。

Terminators 使用 `__attribute__((destructor))` 编写，位于标记为 `S_MOD_TERM_FUNC_POINTERS` 的 section（**`__DATA.__mod_term_func`**）中。

### Stubs

macOS 中的所有 binaries 都是 dynamically linked。因此，它们包含一些 stub sections，用于帮助 binary 在不同 machines 和 contexts 中跳转到正确的 code。当 binary 执行时，由 dyld 负责解析这些 addresses（至少是 non-lazy addresses）。

binary 中的一些 stub sections：

- **`__TEXT.__[auth_]stubs`**：指向 `__DATA` sections 的 pointers
- **`__TEXT.__stub_helper`**：调用 dynamic linking 的小段 code，其中包含待调用 function 的信息
- **`__DATA.__[auth_]got`**：Global Offset Table（指向 imported functions 的 addresses；解析后会被绑定，因为其标记带有 `S_NON_LAZY_SYMBOL_POINTERS` flag）
- **`__DATA.__nl_symbol_ptr`**：Non-lazy symbol pointers（加载时绑定，因为其标记带有 `S_NON_LAZY_SYMBOL_POINTERS` flag）
- **`__DATA.__la_symbol_ptr`**：Lazy symbols pointers（首次访问时绑定）

> [!WARNING]
> 注意，带有 "auth_" 前缀的 pointers 使用一个进程内 encryption key 对其进行保护（PAC）。此外，可以使用 arm64 instruction `BLRA[A/B]` 在跟随 pointer 之前对其进行验证。还可以使用 RETA\[A/B] 代替 RET address。\
> 实际上，**`__TEXT.__auth_stubs`** 中的 code 会使用 **`braa`** 而不是 **`bl`** 来调用请求的 function，以 authenticate pointer。
>
> 另请注意，当前版本的 dyld 会将所有内容作为 non-lazy 加载。

### 查找 lazy symbols
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
有趣的反汇编部分：
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
可以看出，跳转到调用 printf 的位置将指向 **`__TEXT.__stubs`**：
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
在 **`__stubs`** section 的反汇编中：
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
你可以看到，我们正在 **跳转到 GOT 的地址**；在本例中，该地址以 non-lazy 方式解析，并将包含 printf 函数的地址。

在其他情况下，它可能不会直接跳转到 GOT，而是跳转到 **`__DATA.__la_symbol_ptr`**，后者会加载一个表示其尝试加载的函数的值；然后跳转到 **`__TEXT.__stub_helper`**，后者再跳转到包含 **`dyld_stub_binder`** 地址的 **`__DATA.__nl_symbol_ptr`**。`dyld_stub_binder` 接收函数编号和一个地址作为参数。\
该函数找到目标函数的地址后，会将其写入 **`__TEXT.__stub_helper`** 中对应的位置，从而避免将来再次执行查找。

> [!TIP]
> 但是请注意，当前版本的 dyld 会将所有内容以 non-lazy 方式加载。

#### Dyld opcodes

最后，**`dyld_stub_binder`** 需要找到指定的函数，并将其写入正确的地址，以免再次查找。为此，它使用 dyld 内部的 opcodes（有限状态机）。

## apple\[] argument vector

在 macOS 中，main 函数实际上接收 4 个参数，而不是 3 个。第四个参数称为 apple，每个条目的形式都是 `key=value`。例如：
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
未提供需要翻译的英文内容。
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
> [!TIP]
> 当这些值到达 main function 时，其中的敏感信息已经被移除，否则就会造成 data leak。

在进入 main 之前进行 debugging，可以看到所有这些有趣的值：

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld_all_image_infos

这是由 dyld 导出的一个结构，其中包含有关 dyld 状态的信息。你可以在 [**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) 中找到它。该结构包含版本、指向 dyld_image_info array 的指针、指向 dyld_image_notifier 的指针、proc 是否已从 shared cache 分离、libSystem initializer 是否已调用、指向 dyld 自身 Mach header 的指针、指向 dyld version string 的指针等信息……<sup>[[4]](#references)</sup>

## dyld env variables

### debug dyld

以下有趣的 env variables 有助于了解 dyld 正在执行什么操作：

- **DYLD_PRINT_LIBRARIES**

检查每个已加载的 library：
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
- **DYLD_PRINT_SEGMENTS**

检查每个 library 的加载方式：
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: reusing existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
- **DYLD_PRINT_INITIALIZERS**

打印每个 library initializer 运行时的信息：
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### 其他

- `DYLD_BIND_AT_LAUNCH`：使用非 lazy bindings 解析 lazy bindings
- `DYLD_DISABLE_PREFETCH`：禁用对 \_\_DATA 和 \_\_LINKEDIT 内容的预取
- `DYLD_FORCE_FLAT_NAMESPACE`：单层 bindings
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`：解析路径
- `DYLD_INSERT_LIBRARIES`：加载指定的 library
- `DYLD_PRINT_TO_FILE`：将 dyld 调试信息写入文件
- `DYLD_PRINT_APIS`：打印 libdyld API 调用
- `DYLD_PRINT_APIS_APP`：打印 main 发起的 libdyld API 调用
- `DYLD_PRINT_BINDINGS`：在 symbols 绑定时打印它们
- `DYLD_WEAK_BINDINGS`：仅在 weak symbols 绑定时打印它们
- `DYLD_PRINT_CODE_SIGNATURES`：打印代码签名注册操作
- `DYLD_PRINT_DOFS`：在加载时打印 D-Trace object format sections
- `DYLD_PRINT_ENV`：打印 dyld 看到的环境变量
- `DYLD_PRINT_INTERPOSTING`：打印 interposting 操作
- `DYLD_PRINT_LIBRARIES`：打印已加载的 libraries
- `DYLD_PRINT_OPTS`：打印加载选项
- `DYLD_REBASING`：打印 symbol rebasing 操作
- `DYLD_RPATHS`：打印 @rpath 的展开结果
- `DYLD_PRINT_SEGMENTS`：打印 Mach-O segments 的映射
- `DYLD_PRINT_STATISTICS`：打印计时统计信息
- `DYLD_PRINT_STATISTICS_DETAILS`：打印详细的计时统计信息
- `DYLD_PRINT_WARNINGS`：打印警告消息
- `DYLD_SHARED_CACHE_DIR`：用于 shared library cache 的路径
- `DYLD_SHARED_REGION`：`"use"`、`"private"`、`"avoid"`
- `DYLD_USE_CLOSURES`：启用 closures

可以通过类似以下方式找到更多变量：
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
或者从 [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) 下载 dyld project，并在该文件夹中运行：
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp`（进程启动路径）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp`（进程/安全配置）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c`（`execve` 的内核端，加载 dyld）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h`（`dyld_all_image_infos` 结构）](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
