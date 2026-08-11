# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

Mach-o binary の実際の **entrypoint** は dynamic linked であり、`LC_LOAD_DYLINKER` に定義されています。通常は `/usr/lib/dyld` です。<sup>[[3]](#references)</sup>

この linker は、すべての executable libraries を見つけて memory に map し、すべての non-lazy libraries を link する必要があります。この処理が完了して初めて、binary の entry-point が実行されます。

もちろん、**`dyld`** には依存関係がありません（syscalls と libSystem excerpts を使用します）。

> [!CAUTION]
> この linker に vulnerability が存在する場合、あらゆる binary（高度な privilege を持つものを含む）の実行前に実行されるため、**escalate privileges** が可能になります。

### フロー

Dyld は **`dyldboostrap::start`** によってロードされます。この関数は **stack canary** などもロードします。これは、この関数が **`apple`** argument vector で、これらを含むその他の **sensitive** な **values** を受け取るためです。<sup>[[1]](#references)</sup>

**`dyls::_main()`** は dyld の entry point であり、最初のタスクとして `configureProcessRestrictions()` を実行します。通常、この関数は以下で説明されている **`DYLD_*`** environment variables を制限します。<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

次に、重要な system libraries をすべて prelink した dyld shared cache を map します。その後、binary が依存する libraries を map し、必要な libraries がすべてロードされるまで再帰的に処理を続けます。したがって、処理順序は次のとおりです。

1. `DYLD_INSERT_LIBRARIES` によって挿入された libraries をロードする（許可されている場合）
2. 次に shared cached libraries
3. 次に imported libraries
1. その後、libraries の import を再帰的に続ける

すべてがロードされると、これらの libraries の **initialisers** が実行されます。これらは、`LC_ROUTINES[_64]`（現在は deprecated）で定義された **`__attribute__((constructor))`**、または `S_MOD_INIT_FUNC_POINTERS` が設定された section（通常は **`__DATA.__MOD_INIT_FUNC`**）内の pointer として code 化されています。

Terminators は **`__attribute__((destructor))`** で code 化され、`S_MOD_TERM_FUNC_POINTERS` が設定された section（**`__DATA.__mod_term_func`**）に配置されます。

### スタブ

macOS のすべての binaries は dynamically linked されています。そのため、異なる machines や contexts で binary が正しい code に jump できるようにする stub sections が含まれています。binary の実行時にこれらの addresses（少なくとも non-lazy のもの）を resolve する役割を担うのが dyld です。

binary 内の stub sections の例：

- **`__TEXT.__[auth_]stubs`**: `__DATA` sections からの Pointers
- **`__TEXT.__stub_helper`**: 呼び出す function に関する info を持ち、dynamic linking を実行する短い code
- **`__DATA.__[auth_]got`**: Global Offset Table（imported functions への addresses。resolve されると、`S_NON_LAZY_SYMBOL_POINTERS` flag が設定されているため load time に bound される）
- **`__DATA.__nl_symbol_ptr`**: Non-lazy symbol pointers（`S_NON_LAZY_SYMBOL_POINTERS` flag が設定されているため load time に bound される）
- **`__DATA.__la_symbol_ptr`**: Lazy symbols pointers（first access 時に bound される）

> [!WARNING]
> "auth\_" prefix が付いた pointers は、process 内の 1 つの encryption key を使用して保護されています（PAC）。さらに、arm64 instruction の `BLRA[A/B]` を使用して、pointer を follow する前に検証できます。また、RET address の代わりに RETA\[A/B] を使用することもできます。\
> 実際、**`__TEXT.__auth_stubs`** 内の code は、pointer を authenticate するため、要求された function の call に **`braa`** を使用し、**`bl`** は使用しません。
>
> また、現在の dyld versions はすべてを non-lazy としてロードすることにも注意してください。

### lazy symbols の検索方法
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
興味深い逆アセンブリ部分:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
`printf` への jump が **`__TEXT.__stubs`** に向かっていることがわかります：
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
**`__stubs`** セクションの逆アセンブルでは：
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
ここでは、**GOTのアドレスへジャンプしている**ことがわかります。この場合、GOTはnon-lazyで解決され、`printf` functionのアドレスを含みます。

別の状況では、GOTへ直接ジャンプする代わりに、**`__DATA.__la_symbol_ptr`**へジャンプすることがあります。これは、loadしようとしているfunctionを表す値をloadし、その後 **`__TEXT.__stub_helper`**へジャンプします。`__TEXT.__stub_helper`は、**`dyld_stub_binder`**のアドレスを含む **`__DATA.__nl_symbol_ptr`**へジャンプします。`dyld_stub_binder`は、functionの番号とアドレスをparametersとして受け取ります。\
この最後のfunctionは、検索対象のfunctionのアドレスを見つけた後、それを **`__TEXT.__stub_helper`**内の対応するlocationに書き込み、今後lookupを実行せずに済むようにします。

> [!TIP]
> ただし、現在のdyld versionsはすべてをnon-lazyとしてloadすることに注意してください。

#### Dyld opcodes

最後に、**`dyld_stub_binder`**は指定されたfunctionを見つけ、再度検索しなくても済むように正しいアドレスへ書き込む必要があります。そのため、dyld内のopcodes（有限状態機械）を使用します。

## apple\[] argument vector

macOSでは、main functionは実際には3つではなく4つのargumentsを受け取ります。4つ目はappleと呼ばれ、各entryは`key=value`の形式です。例：
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
結果:
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
> これらの値が main 関数に到達する時点では、機密情報はすでに削除されているか、そうでなければ data leak になっています。

main に入る前に debugging することで、これらの興味深い値をすべて確認できます。

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

これは dyld によって export される structure で、dyld の state に関する情報を含んでいます。[**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) で確認でき、version、dyld_image_info array への pointer、dyld_image_notifier への pointer、proc が shared cache から detached されているかどうか、libSystem initializer が呼び出されたかどうか、dyld 自身の Mach header への pointer、dyld version string などの情報が含まれています。<sup>[[4]](#references)</sup>

## dyld env variables

### debug dyld

dyld が何をしているかを理解するのに役立つ興味深い env variables：

- **DYLD_PRINT_LIBRARIES**

load された各 library を確認します：
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

各 library がどのようにロードされるかを確認します：
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

各 library initializer の実行時に出力します:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### その他

- `DYLD_BIND_AT_LAUNCH`: Lazy bindings を non lazy bindings とともに解決
- `DYLD_DISABLE_PREFETCH`: \_\_DATA と \_\_LINKEDIT の内容の pre-fetching を無効化
- `DYLD_FORCE_FLAT_NAMESPACE`: Single-level bindings
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Resolution paths
- `DYLD_INSERT_LIBRARIES`: 特定の library をロード
- `DYLD_PRINT_TO_FILE`: dyld の debug 情報をファイルに書き込む
- `DYLD_PRINT_APIS`: libdyld API calls を表示
- `DYLD_PRINT_APIS_APP`: main によって実行された libdyld API calls を表示
- `DYLD_PRINT_BINDINGS`: bind 時に symbols を表示
- `DYLD_WEAK_BINDINGS`: bind 時に weak symbols のみを表示
- `DYLD_PRINT_CODE_SIGNATURES`: code signature の登録操作を表示
- `DYLD_PRINT_DOFS`: ロード時に D-Trace object format sections を表示
- `DYLD_PRINT_ENV`: dyld が認識した env を表示
- `DYLD_PRINT_INTERPOSTING`: interposting operations を表示
- `DYLD_PRINT_LIBRARIES`: ロードされた libraries を表示
- `DYLD_PRINT_OPTS`: load options を表示
- `DYLD_REBASING`: symbol rebasing operations を表示
- `DYLD_RPATHS`: @rpath の展開を表示
- `DYLD_PRINT_SEGMENTS`: Mach-O segments の mappings を表示
- `DYLD_PRINT_STATISTICS`: timing statistics を表示
- `DYLD_PRINT_STATISTICS_DETAILS`: 詳細な timing statistics を表示
- `DYLD_PRINT_WARNINGS`: warning messages を表示
- `DYLD_SHARED_CACHE_DIR`: shared library cache に使用する path
- `DYLD_SHARED_REGION`: "use"、"private"、"avoid"
- `DYLD_USE_CLOSURES`: closures を有効化

次のような方法で、さらに多くの項目を見つけられます:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
または、[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) から dyld project をダウンロードし、フォルダ内で次を実行します：
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## References

- [1] [dyld — `dyld/dyldMain.cpp`（プロセス起動パス）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp`（プロセス／security configuration）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c`（`execve` の kernel 側、dyld のロード）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h`（`dyld_all_image_infos` 構造体）](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
{{#include ../../../../banners/hacktricks-training.md}}
