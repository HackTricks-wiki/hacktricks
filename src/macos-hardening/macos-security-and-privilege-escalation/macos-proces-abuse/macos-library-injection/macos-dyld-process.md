# macOS Dyldプロセス

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

Mach-oバイナリの実際の**entrypoint**は、`LC_LOAD_DYLINKER`で定義されるdynamic linkerで、通常は`/usr/lib/dyld`です。<sup>[[3]](#references)</sup>

このlinkerは、実行ファイルのすべてのライブラリを特定してメモリにマップし、すべてのnon-lazyライブラリをリンクする必要があります。この処理が完了して初めて、バイナリのentry-pointが実行されます。

もちろん、**`dyld`**には依存関係がありません（syscallとlibSystemの抜粋を使用します）。

> [!CAUTION]
> このlinkerに脆弱性がある場合、あらゆるバイナリ（高い特権を持つものも含む）の実行前に実行されるため、**特権昇格**が可能になります。

### フロー

Dyldは**`dyldboostrap::start`**によってロードされます。この関数は**stack canary**などもロードします。この関数は、**`apple`**引数ベクターでこれらの**機密**な**値**を受け取るためです。<sup>[[1]](#references)</sup>

**`dyls::_main()`**はdyldのentry pointであり、最初に`configureProcessRestrictions()`を実行します。通常、この関数は以下で説明されている**`DYLD_*`**環境変数を制限します。<sup>[[2]](#references)</sup>


{{#ref}}
./
{{#endref}}

次に、重要なシステムライブラリを事前リンクしたdyld shared cacheをマップし、続いてバイナリが依存するライブラリをマップします。必要なライブラリがすべてロードされるまで、この処理を再帰的に続けます。そのため、処理は次のようになります。

1. `DYLD_INSERT_LIBRARIES`で挿入されたライブラリをロードする（許可されている場合）
2. 次に、shared cache内のライブラリをロードする
3. 次に、インポートされたライブラリをロードする
   1. その後、ライブラリのインポートを再帰的に続ける

すべてのライブラリがロードされると、それらの**initializer**が実行されます。これらは、`LC_ROUTINES[_64]`（現在は非推奨）で定義される**`__attribute__((constructor))`**、または`S_MOD_INIT_FUNC_POINTERS`フラグが設定されたセクション（通常は**`__DATA.__MOD_INIT_FUNC`**）内のポインターを使って記述されます。

Terminatorは**`__attribute__((destructor))`**で記述され、`S_MOD_TERM_FUNC_POINTERS`フラグが設定されたセクション（**`__DATA.__mod_term_func`**）に配置されます。

こちらも参照: [Reflective Mach-O Loading](../reflective-mach-o-loading.md)。

### スタブ

macOS上のすべてのバイナリは動的リンクされています。そのため、異なるマシンやコンテキストでバイナリが正しいコードにジャンプできるようにするスタブセクションが含まれています。バイナリの実行時に、これらのアドレス（少なくともnon-lazyのもの）を解決するのがdyldです。

バイナリ内のスタブセクションには、次のようなものがあります。

- **`__TEXT.__[auth_]stubs`**: `__DATA`セクションからのポインター
- **`__TEXT.__stub_helper`**: 呼び出す関数に関する情報を使って動的リンクを呼び出す小さなコード
- **`__DATA.__[auth_]got`**: Global Offset Table（インポートされた関数のアドレス。解決時にバインドされる。`S_NON_LAZY_SYMBOL_POINTERS`フラグが設定されているため、ロード時にバインドされる）
- **`__DATA.__nl_symbol_ptr`**: Non-lazy symbol pointer（`S_NON_LAZY_SYMBOL_POINTERS`フラグが設定されているため、ロード時にバインドされる）
- **`__DATA.__la_symbol_ptr`**: Lazy symbol pointer（初回アクセス時にバインドされる）

> [!WARNING]
> "auth\_"プレフィックスが付いたポインターは、プロセス内の暗号化キーを使って保護されています（PAC）。また、ポインターをたどる前に検証するため、arm64命令の`BLRA[A/B]`を使用できます。RETアドレスの代わりに`RETA[A/B]`を使用することもできます。\
> 実際、**`__TEXT.__auth_stubs`**内のコードは、要求された関数を呼び出す際にポインターを認証するため、**`bl`**の代わりに**`braa`**を使用します。
>
> また、現在のdyldのバージョンでは、**すべてがnon-lazyとしてロードされます**。

### Lazy symbolの特定

```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    printf("Hi\n");
}
```

興味深い逆アセンブル部分：

```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```

printf を呼び出すためのジャンプ先が **`__TEXT.__stubs`** であることが確認できます:

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

**`__stubs`**セクションの逆アセンブルでは:

```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```

GOT のアドレスへ **ジャンプしている**ことがわかります。この場合、GOT は non-lazy として解決され、`printf` 関数のアドレスが格納されます。

別の状況では、GOT に直接ジャンプする代わりに、**`__DATA.__la_symbol_ptr`** へジャンプすることがあります。ここでは、ロードしようとしている関数を表す値が読み込まれ、続いて **`__TEXT.__stub_helper`** へジャンプします。そこから **`__DATA.__nl_symbol_ptr`** へジャンプし、ここには **`dyld_stub_binder`** のアドレスが格納されています。`dyld_stub_binder` は、関数の番号とアドレスを引数として受け取ります。\
binder はシンボルを解決し、対応する **`__DATA.__la_symbol_ptr`** のスロットを更新します。スタブは後続の呼び出しで、解決済みのポインターを使用します。`__TEXT.__stub_helper` の内容が書き換えられるわけではありません。<sup>[[5]](#references)</sup>

> [!TIP]
> ただし、現在の dyld バージョンではすべて non-lazy としてロードされることに注意してください。

#### Dyld opcodes

最後に、**`dyld_stub_binder`** は指定された関数を見つけ、再度検索せずに済むよう、適切なアドレスに書き込む必要があります。そのために、dyld 内の opcodes（有限状態機械）を使用します。

## apple\[] 引数ベクトル

macOS では、main 関数は実際には 3 つではなく 4 つの引数を受け取ります。4 つ目は apple と呼ばれ、各エントリーは `key=value` の形式です。たとえば：

```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
    for (int i=0; apple[i]; i++)
        printf("%d: %s\n", i, apple[i])
}
```

結果：

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
> これらの値が main 関数に到達する頃には、機密情報はすでに値から削除されています。削除されていなければ、data leak が発生していたでしょう。

main に入る前にデバッグして、これらの興味深い値をすべて確認できます。

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

これは dyld がエクスポートする、dyld の状態に関する情報を含む構造体です。[**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html) で確認でき、バージョン、dyld_image_info 配列へのポインタ、dyld_image_notifier へのポインタ、proc が shared cache から切り離されているかどうか、libSystem の初期化関数が呼び出されたかどうか、dyld 自身の Mach header へのポインタ、dyld のバージョン文字列などの情報を含みます。<sup>[[4]](#references)</sup>

## dyld の環境変数

### dyld のデバッグ

dyld の動作を把握するのに役立つ興味深い環境変数:

- **DYLD_PRINT_LIBRARIES**

ロードされる各ライブラリを確認します。

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

各ライブラリがどのように読み込まれるかを確認します:

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

各ライブラリの初期化関数が実行される際に出力します:

```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```

### ランタイムのライブラリ解決をトレースする

制御可能な起動では、置き換え用の dylib を配置する前に、`@rpath` または weak-library の候補をトレースします。`DYLD_PRINT_SEARCHING` は dyld が検討したパスを報告し、`DYLD_PRINT_LIBRARIES` は実際にロードされたイメージを表示します。`DYLD_PRINT_LOADERS` は `JustInTimeLoader` と `PrebuiltLoader` を区別し、prebuilt loader set の使用状況を報告します。<sup>[[6]](#references)</sup>

```bash
DYLD_PRINT_SEARCHING=1 DYLD_PRINT_LOADERS=1 DYLD_PRINT_LIBRARIES=1 /path/to/binary 2>&1 | tee /tmp/dyld-search.log
```

`LC_RPATH` 行を確認して run path を提供した image を特定し、`possible path(...)` の候補を `found: dylib-from-disk`、`found: dylib-from-cache`、または拒否の結果と照合します。候補パスは、dylib がロードされた証拠には**なりません**。想定される library より前にある、最初に使用可能な disk path について、書き込み権限と [library-validation の制限](./#library-validation)を確認します。<sup>[[7]](#references)</sup>

prebuilt loader は、完全なパス検索を繰り返す代わりに、記録済みの依存情報を再利用できます。そのため、検索結果が少なくても image に依存関係がないとは限りません。`otool -l` で load command を調べ、library list と照合してください。<sup>[[8]](#references)</sup> これらの診断には dyld の print-variable 権限も必要なため、保護された target では完全に無視されることがあります。<sup>[[2]](#references)</sup> 実際に置換 library を使うための前提条件は [Dylib Hijacking](./#dylib-hijacking) を参照してください。

### その他

以下の一部のスイッチは、古い dyld リリース固有のものです。すべての変数が今も機能すると決めつけず、target のバージョンでサポートされているか確認してください。<sup>[[2]](#references)[[9]](#references)</sup>

- `DYLD_BIND_AT_LAUNCH`: Lazy binding を non lazy binding とともに解決する
- `DYLD_DISABLE_PREFETCH`: \_\_DATA および \_\_LINKEDIT の内容の pre-fetching を無効にする
- `DYLD_FORCE_FLAT_NAMESPACE`: Single-level binding
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: 解決に使うパス
- `DYLD_INSERT_LIBRARIES`: 指定した library をロードする
- `DYLD_PRINT_TO_FILE`: dyld のデバッグ情報をファイルに書き込む
- `DYLD_PRINT_APIS`: libdyld API 呼び出しを表示する
- `DYLD_PRINT_APIS_APP`: main による libdyld API 呼び出しを表示する
- `DYLD_PRINT_BINDINGS`: binding 時にシンボルを表示する
- `DYLD_PRINT_WEAK_BINDINGS` (dyld2): weak symbol binding を表示する
- `DYLD_PRINT_CODE_SIGNATURES`: code signature の登録操作を表示する
- `DYLD_PRINT_DOFS`: ロード時に D-Trace object format section を表示する
- `DYLD_PRINT_ENV`: dyld が認識した環境変数を表示する
- `DYLD_PRINT_INTERPOSING`: interposing 操作を表示する
- `DYLD_PRINT_LIBRARIES`: ロードされた librearies を表示する
- `DYLD_PRINT_OPTS`: load option を表示する
- `DYLD_PRINT_REBASINGS` (dyld2): シンボルの rebasing 操作を表示する
- `DYLD_PRINT_RPATHS` (dyld2): `@rpath` の展開を表示する
- `DYLD_PRINT_SEGMENTS`: Mach-O segment のマッピングを表示する
- `DYLD_PRINT_STATISTICS`: timing statistics を表示する
- `DYLD_PRINT_STATISTICS_DETAILS`: 詳細な timing statistics を表示する
- `DYLD_PRINT_WARNINGS`: warning message を表示する
- `DYLD_SHARED_CACHE_DIR`: shared library cache に使用するパス
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: closures を有効にする

次のような方法で、さらに確認できます:

```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```

または [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) から dyld プロジェクトをダウンロードし、フォルダー内で次を実行します。

```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```



## References

- [1] [dyld — `dyld/dyldMain.cpp`（プロセス起動パス）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
- [2] [dyld — `dyld/DyldProcessConfig.cpp`（プロセス／セキュリティ設定）](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [3] [XNU — `bsd/kern/kern_exec.c`（`execve` のカーネル側処理、dyld のロード）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
- [4] [dyld — `include/mach-o/dyld_images.h`（`dyld_all_image_infos` 構造体）](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)
- [5] [fishhook — lazy および non-lazy シンボルポインターのバインド](https://github.com/meta/fishhook)
- [6] [dyld(1) — dynamic linker の診断](https://github.com/apple-oss-distributions/dyld/blob/main/doc/man/man1/dyld.1)
- [7] [dyld — ランタイムのライブラリパス検索](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/Loader.cpp)
- [8] [dyld4 — 事前ビルドローダーと Just-In-Time ローダー](https://github.com/apple-oss-distributions/dyld/blob/main/doc/dyld4.md)
- [9] [dyld2 — レガシーな診断変数名](https://github.com/apple-oss-distributions/dyld/blob/dyld-852.2/src/dyld2.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
