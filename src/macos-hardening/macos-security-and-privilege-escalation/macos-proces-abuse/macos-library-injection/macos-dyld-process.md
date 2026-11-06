# macOS Dyld 进程

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

Mach-o 二进制文件真正的**入口点**是动态链接器，由 `LC_LOAD_DYLINKER` 定义，通常是 `/usr/lib/dyld`。<sup>[[3]](#references)</sup>

这个链接器需要找到所有可执行文件的库，将它们映射到内存中，并链接所有非惰性库。只有完成这个过程后，二进制文件的入口点才会执行。

当然，**`dyld`** 没有任何依赖项（它使用系统调用和 libSystem 代码片段）。

> [!CAUTION]
> 如果这个链接器包含漏洞，由于它会在执行任何二进制文件（甚至是高权限二进制文件）之前运行，因此就有可能**提升权限**。

### 流程

Dyld 由 **`dyldboostrap::start`** 加载，该函数还会加载**栈 canary** 等内容。这是因为该函数会通过其 **`apple`** 参数向量接收这些及其他**敏感** **值**。<sup>[[1]](#references)</sup>

**`dyls::_main()`** 是 dyld 的入口点，它首先会运行 `configureProcessRestrictions()`，通常会限制本文所述的 **`DYLD_*`** 环境变量：<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

然后，它会映射 dyld 共享缓存，该缓存预先链接了所有重要的系统库；接着映射二进制文件依赖的库，并递归继续，直到加载所有必需的库。因此：

1. 开始加载通过 `DYLD_INSERT_LIBRARIES` 插入的库（如果允许）
2. 然后加载共享缓存中的库
3. 然后加载导入的库
   1. 接着递归导入库

所有库加载完毕后，会运行这些库的**初始化函数**。这些函数通过 **`__attribute__((constructor))`** 编写，定义在 `LC_ROUTINES[_64]` 中（现已弃用），或通过指针定义在标记为 `S_MOD_INIT_FUNC_POINTERS` 的 section 中（通常是：**`__DATA.__MOD_INIT_FUNC`**）。

终止函数通过 **`__attribute__((destructor))`** 编写，位于标记为 `S_MOD_TERM_FUNC_POINTERS` 的 section 中（**`__DATA.__mod_term_func`**）。

另请参阅：[Reflective Mach-O Loading](../reflective-mach-o-loading.md)。

### Stubs

macOS 中的所有二进制文件都采用动态链接。因此，它们包含一些 stub section，帮助二进制文件在不同机器和上下文中跳转到正确的代码。二进制文件执行时，dyld 负责解析这些地址（至少是非惰性地址）。

二进制文件中的一些 stub section：

- **`__TEXT.__[auth_]stubs`**：来自 `__DATA` section 的指针
- **`__TEXT.__stub_helper`**：调用动态链接的小段代码，其中包含要调用的函数信息
- **`__DATA.__[auth_]got`**：全局偏移表（导入函数的地址；解析后绑定，加载时绑定，因为它标记了 `S_NON_LAZY_SYMBOL_POINTERS` 标志）
- **`__DATA.__nl_symbol_ptr`**：非惰性符号指针（加载时绑定，因为它标记了 `S_NON_LAZY_SYMBOL_POINTERS` 标志）
- **`__DATA.__la_symbol_ptr`**：惰性符号指针（首次访问时绑定）

> [!WARNING]
> 注意，带有前缀“auth\_”的指针使用进程内加密密钥进行保护（PAC）。此外，可以使用 arm64 指令 `BLRA[A/B]` 在跟随指针前对其进行验证。也可以使用 RETA\[A/B]，而不是 RET 地址。\
> 实际上，**`__TEXT.__auth_stubs`** 中的代码会使用 **`braa`** 而不是 **`bl`** 来调用所请求的函数，以验证指针。
>
> 另请注意，当前版本的 dyld 会将**所有内容都作为非惰性内容加载**。

### 查找惰性符号

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

可以看到，跳转到调用 printf 的位置将进入 **`__TEXT.__stubs`**：

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

在 **`__stubs`** 区段的反汇编中：

```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```

你可以看到，我们正在**跳转到 GOT 的地址**。在本例中，该地址以非延迟方式解析，其中包含 `printf` 函数的地址。

在其他情况下，它可能不会直接跳转到 GOT，而是跳转到 **`__DATA.__la_symbol_ptr`**，该位置会加载一个值，表示它尝试加载的函数；然后跳转到 **`__TEXT.__stub_helper`**，再由它跳转到 **`__DATA.__nl_symbol_ptr`**。后者包含 **`dyld_stub_binder`** 的地址，而它接收函数编号和一个地址作为参数。\
binder 会解析符号并更新其 **`__DATA.__la_symbol_ptr`** 槽位。之后的调用中，stub 会使用这个已解析的指针；它不会被重写到 `__TEXT.__stub_helper` 中。<sup>[[5]](#references)</sup>

> [!TIP]
> 不过请注意，当前版本的 dyld 会将所有内容都以非延迟方式加载。

#### Dyld opcodes

最后，**`dyld_stub_binder`** 需要找到指定的函数，并将其写入正确的地址，以免再次查找。为此，它会使用 dyld 中的 opcodes（一种有限状态机）。

## apple\[] argument vector

在 macOS 中，主函数实际接收 4 个参数，而不是 3 个。第四个参数称为 apple，每个条目的格式都是 `key=value`。例如：

```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    for (int i=0; apple[i]; i++)
        printf("%d: %s\n", i, apple[i])
}
```

结果：

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
> 到这些值传递到 main 函数时，其中的敏感信息已经被移除，否则就会造成 data leak。

可以在进入 main 之前通过调试查看这些有趣的值：

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Current executable set to '/tmp/a' (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

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

这是 dyld 导出的一个结构，其中包含 dyld 状态的相关信息。可以在[**源代码**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)中找到该结构，其中包含版本、指向 dyld_image_info 数组的指针、指向 dyld_image_notifier 的指针、进程是否已从 shared cache 分离、是否已调用 libSystem 初始化程序、指向 dyld 自身 Mach header 的指针、指向 dyld 版本字符串的指针等信息。<sup>[[4]](#references)</sup>

## dyld 环境变量

### 调试 dyld

有助于了解 dyld 正在执行什么操作的有趣环境变量：

- **DYLD_PRINT_LIBRARIES**

检查加载的每个库：

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

检查每个库是如何加载的：

```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
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

打印每个库初始化器运行时的信息：

```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```

### 跟踪运行时库解析

对于你可控的启动，在放置替换 dylib 之前，先跟踪 `@rpath` 或弱库候选项。`DYLD_PRINT_SEARCHING` 会报告 dyld 考虑过的路径，而 `DYLD_PRINT_LIBRARIES` 会显示实际加载的映像。`DYLD_PRINT_LOADERS` 可区分 `JustInTimeLoader` 和 `PrebuiltLoader`，并报告是否使用了预构建加载器集。<sup>[[6]](#references)</sup>

```bash
DYLD_PRINT_SEARCHING=1 DYLD_PRINT_LOADERS=1 DYLD_PRINT_LIBRARIES=1 /path/to/binary 2>&1 | tee /tmp/dyld-search.log
```

查找标明提供运行路径的映像的 `LC_RPATH` 行，然后将 `possible path(...)` 候选项与 `found: dylib-from-disk`、`found: dylib-from-cache` 或拒绝信息进行比较。候选路径**并不能**证明 dylib 已加载。预期库之前第一个可用的磁盘路径，是需要测试写入权限和 [library-validation restrictions](./#library-validation) 的路径。<sup>[[7]](#references)</sup>

预构建的加载器可以重用已记录的依赖信息，而不必重新执行完整的路径搜索。因此，搜索输出稀疏并不代表映像没有依赖项；请使用 `otool -l` 检查其加载命令，并比较库列表。<sup>[[8]](#references)</sup> 这些诊断还需要 dyld 的打印变量权限，因此受保护的目标可能完全忽略它们。<sup>[[2]](#references)</sup> 有关实际替换库的前提条件，请参阅 [Dylib Hijacking](./#dylib-hijacking)。

### 其他

以下某些开关仅适用于较旧版本的 dyld。请检查目标版本是否支持，不要假设所有变量仍然有效。<sup>[[2]](#references)[[9]](#references)</sup>

- `DYLD_BIND_AT_LAUNCH`：将 lazy bindings 与 non lazy bindings 一起解析
- `DYLD_DISABLE_PREFETCH`：禁用对 \_\_DATA 和 \_\_LINKEDIT 内容的预取
- `DYLD_FORCE_FLAT_NAMESPACE`：单层绑定
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`：解析路径
- `DYLD_INSERT_LIBRARIES`：加载指定的库
- `DYLD_PRINT_TO_FILE`：将 dyld 调试信息写入文件
- `DYLD_PRINT_APIS`：打印 libdyld API 调用
- `DYLD_PRINT_APIS_APP`：打印主程序进行的 libdyld API 调用
- `DYLD_PRINT_BINDINGS`：绑定时打印符号
- `DYLD_PRINT_WEAK_BINDINGS` (dyld2)：打印弱符号绑定
- `DYLD_PRINT_CODE_SIGNATURES`：打印代码签名注册操作
- `DYLD_PRINT_DOFS`：加载时打印 D-Trace 对象格式区段
- `DYLD_PRINT_ENV`：打印 dyld 看到的环境变量
- `DYLD_PRINT_INTERPOSING`：打印 interposing 操作
- `DYLD_PRINT_LIBRARIES`：打印已加载的库
- `DYLD_PRINT_OPTS`：打印加载选项
- `DYLD_PRINT_REBASINGS` (dyld2)：打印符号 rebasing 操作
- `DYLD_PRINT_RPATHS` (dyld2)：打印 `@rpath` 的展开结果
- `DYLD_PRINT_SEGMENTS`：打印 Mach-O 区段的映射
- `DYLD_PRINT_STATISTICS`：打印计时统计信息
- `DYLD_PRINT_STATISTICS_DETAILS`：打印详细计时统计信息
- `DYLD_PRINT_WARNINGS`：打印警告信息
- `DYLD_SHARED_CACHE_DIR`：共享库缓存的使用路径
- `DYLD_SHARED_REGION`："use"、"private"、"avoid"
- `DYLD_USE_CLOSURES`：启用 closures

还可以通过类似下面的方式查找更多内容：

```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```

或者从 [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) 下载 dyld 项目，并在文件夹内运行：

```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```



## References

- [1] [dyld — `dyld/dyldMain.cpp`（进程启动路径）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp`（进程/安全配置）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c`（`execve` 的内核端，加载 dyld）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h`（`dyld_all_image_infos` 结构）](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
- [5] [fishhook — lazy 和 non-lazy 符号指针绑定](https://github.com/meta/fishhook)
- [6] [dyld(1) — 动态链接器诊断](https://github.com/apple-oss-distributions/dyld/blob/main/doc/man/man1/dyld.1)
- [7] [dyld — 运行时库路径搜索](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp)
- [8] [dyld4 — 预构建和即时加载器](https://github.com/apple-oss-distributions/dyld/blob/main/doc/dyld4.md)
- [9] [dyld2 — 旧版诊断变量名称](https://github.com/apple-oss-distributions/dyld/blob/dyld-852.2/src/dyld2.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
