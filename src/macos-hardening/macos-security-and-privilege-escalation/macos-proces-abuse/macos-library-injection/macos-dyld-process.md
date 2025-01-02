# macOS Dyld Process

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

Mach-o バイナリの実際の **entrypoint** は動的リンクされており、`LC_LOAD_DYLINKER` で定義されており、通常は `/usr/lib/dyld` です。

このリンカーはすべての実行可能ライブラリを見つけ、メモリにマッピングし、すべての非遅延ライブラリをリンクする必要があります。このプロセスの後にのみ、バイナリのエントリポイントが実行されます。

もちろん、**`dyld`** には依存関係はありません（syscalls と libSystem の抜粋を使用します）。

> [!CAUTION]
> このリンカーに脆弱性が含まれている場合、バイナリ（特権の高いものも含む）を実行する前に実行されるため、**特権昇格**が可能になります。

### フロー

Dyld は **`dyldboostrap::start`** によってロードされ、**スタックカナリア** などのものもロードされます。これは、この関数が **`apple`** 引数ベクターにこの他の **機密** **値** を受け取るためです。

**`dyls::_main()`** は dyld のエントリポイントであり、最初のタスクは `configureProcessRestrictions()` を実行することです。これは通常、以下で説明されている **`DYLD_*`** 環境変数を制限します。

{{#ref}}
./
{{#endref}}

次に、dyld 共有キャッシュをマッピングし、すべての重要なシステムライブラリを事前リンクし、次にバイナリが依存するライブラリをマッピングし、すべての必要なライブラリがロードされるまで再帰的に続けます。したがって：

1. `DYLD_INSERT_LIBRARIES` で挿入されたライブラリのロードを開始します（許可されている場合）
2. 次に、共有キャッシュされたもの
3. 次に、インポートされたもの
1. &#x20;次に、ライブラリを再帰的にインポートし続けます

すべてがロードされると、これらのライブラリの **初期化子** が実行されます。これらは、`LC_ROUTINES[_64]`（現在は非推奨）で定義された **`__attribute__((constructor))`** を使用してコーディングされるか、`S_MOD_INIT_FUNC_POINTERS` フラグが付けられたセクション内のポインタによってコーディングされます（通常は **`__DATA.__MOD_INIT_FUNC`**）。

終了子は **`__attribute__((destructor))`** でコーディングされ、`S_MOD_TERM_FUNC_POINTERS` フラグが付けられたセクションにあります（**`__DATA.__mod_term_func`**）。

### スタブ

macOS のすべてのバイナリは動的にリンクされています。したがって、異なるマシンやコンテキストでバイナリが正しいコードにジャンプするのを助けるスタブセクションが含まれています。バイナリが実行されるとき、これらのアドレスを解決する必要があるのは dyld です（少なくとも非遅延のもの）。

バイナリ内のスタブセクション：

- **`__TEXT.__[auth_]stubs`**: `__DATA` セクションからのポインタ
- **`__TEXT.__stub_helper`**: 呼び出す関数に関する情報を持つ動的リンクを呼び出す小さなコード
- **`__DATA.__[auth_]got`**: グローバルオフセットテーブル（インポートされた関数へのアドレス、解決されたとき、（ロード時にバインドされるため、フラグ `S_NON_LAZY_SYMBOL_POINTERS` でマークされます）
- **`__DATA.__nl_symbol_ptr`**: 非遅延シンボルポインタ（ロード時にバインドされるため、フラグ `S_NON_LAZY_SYMBOL_POINTERS` でマークされます）
- **`__DATA.__la_symbol_ptr`**: 遅延シンボルポインタ（最初のアクセス時にバインドされます）

> [!WARNING]
> "auth\_" プレフィックスの付いたポインタは、保護のためにプロセス内暗号化キーを使用しています（PAC）。さらに、ポインタを追跡する前に検証するために arm64 命令 `BLRA[A/B]` を使用することが可能です。そして、RETA\[A/B] は RET アドレスの代わりに使用できます。\
> 実際、**`__TEXT.__auth_stubs`** 内のコードは、ポインタを認証するために要求された関数を呼び出すために **`braa`** を使用します。
>
> また、現在の dyld バージョンは **すべてを非遅延** としてロードします。

### 遅延シンボルの検索
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
興味深い逆アセンブル部分:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
`printf`を呼び出すためのジャンプが**`__TEXT.__stubs`**に向かっていることがわかります。
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
**`__stubs`** セクションの逆アセンブルで:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
あなたは**GOTのアドレスにジャンプしている**ことがわかります。この場合、非遅延で解決され、printf関数のアドレスが含まれます。

他の状況では、直接GOTにジャンプする代わりに、**`__DATA.__la_symbol_ptr`**にジャンプすることがあり、これは読み込もうとしている関数を表す値をロードし、その後**`__TEXT.__stub_helper`**にジャンプします。これが**`__DATA.__nl_symbol_ptr`**にジャンプし、**`dyld_stub_binder`**のアドレスを含みます。この関数は、関数の番号とアドレスをパラメータとして受け取ります。\
この最後の関数は、検索された関数のアドレスを見つけた後、それを**`__TEXT.__stub_helper`**の対応する場所に書き込み、将来のルックアップを避けます。

> [!TIP]
> ただし、現在のdyldバージョンはすべてを非遅延でロードすることに注意してください。

#### Dyldオペコード

最後に、**`dyld_stub_binder`**は指定された関数を見つけて、再度検索しないように適切なアドレスに書き込む必要があります。そのために、dyld内でオペコード（有限状態機械）を使用します。

## apple\[] 引数ベクター

macOSでは、main関数は実際には3つの引数の代わりに4つの引数を受け取ります。4つ目はappleと呼ばれ、各エントリは`key=value`の形式です。例えば：
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
> これらの値がメイン関数に到達する頃には、機密情報はすでに削除されているか、データ漏洩が発生しているでしょう。

メインに入る前にデバッグしてこれらの興味深い値をすべて見ることができます：

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>現在の実行可能ファイルは '/tmp/a' (arm64) に設定されています。
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

これは、dyldの状態に関する情報を持つ構造体で、[**ソースコード**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld_images.h.auto.html)で見つけることができ、バージョン、dyld_image_info配列へのポインタ、dyld_image_notifier、プロセスが共有キャッシュから切り離されているかどうか、libSystem初期化子が呼び出されたかどうか、dyls自身のMachヘッダーへのポインタ、dyldバージョン文字列へのポインタなどの情報が含まれています...

## dyld env variables

### debug dyld

dyldが何をしているのかを理解するのに役立つ興味深い環境変数：

- **DYLD_PRINT_LIBRARIES**

読み込まれた各ライブラリを確認します：
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

各ライブラリがどのように読み込まれているかを確認します:
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

各ライブラリの初期化子が実行されるときに印刷します:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### その他

- `DYLD_BIND_AT_LAUNCH`: レイジーバインディングが非レイジーなものと解決される
- `DYLD_DISABLE_PREFETCH`: \_\_DATA と \_\_LINKEDIT コンテンツのプリフェッチを無効にする
- `DYLD_FORCE_FLAT_NAMESPACE`: 単一レベルのバインディング
- `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: 解決パス
- `DYLD_INSERT_LIBRARIES`: 特定のライブラリをロードする
- `DYLD_PRINT_TO_FILE`: dyld デバッグをファイルに書き込む
- `DYLD_PRINT_APIS`: libdyld API コールを印刷する
- `DYLD_PRINT_APIS_APP`: main によって行われた libdyld API コールを印刷する
- `DYLD_PRINT_BINDINGS`: バインドされたときにシンボルを印刷する
- `DYLD_WEAK_BINDINGS`: バインドされたときに弱いシンボルのみを印刷する
- `DYLD_PRINT_CODE_SIGNATURES`: コード署名登録操作を印刷する
- `DYLD_PRINT_DOFS`: 読み込まれた D-Trace オブジェクト形式セクションを印刷する
- `DYLD_PRINT_ENV`: dyld によって見られた環境を印刷する
- `DYLD_PRINT_INTERPOSTING`: インターポスティング操作を印刷する
- `DYLD_PRINT_LIBRARIES`: 読み込まれたライブラリを印刷する
- `DYLD_PRINT_OPTS`: ロードオプションを印刷する
- `DYLD_REBASING`: シンボルのリベース操作を印刷する
- `DYLD_RPATHS`: @rpath の展開を印刷する
- `DYLD_PRINT_SEGMENTS`: Mach-O セグメントのマッピングを印刷する
- `DYLD_PRINT_STATISTICS`: タイミング統計を印刷する
- `DYLD_PRINT_STATISTICS_DETAILS`: 詳細なタイミング統計を印刷する
- `DYLD_PRINT_WARNINGS`: 警告メッセージを印刷する
- `DYLD_SHARED_CACHE_DIR`: 共有ライブラリキャッシュに使用するパス
- `DYLD_SHARED_REGION`: "use", "private", "avoid"
- `DYLD_USE_CLOSURES`: クロージャを有効にする

何かを使ってさらに見つけることができます:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
または、[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) から dyld プロジェクトをダウンロードし、フォルダー内で実行します:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## 参考文献

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
