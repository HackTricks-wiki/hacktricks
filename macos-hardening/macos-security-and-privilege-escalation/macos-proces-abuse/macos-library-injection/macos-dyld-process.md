# macOS Dyld プロセス

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)を**フォロー**する。
* **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

## 基本情報

Mach-o バイナリの実際の **エントリーポイント** は、通常 `/usr/lib/dyld` に定義されている **動的リンカー** です。

このリンカーは、すべての実行可能なライブラリを見つけ、メモリにマップし、非遅延ライブラリをリンクする必要があります。このプロセスが完了した後に、バイナリのエントリーポイントが実行されます。

もちろん、**`dyld`** には依存関係はありません（システムコールと libSystem の抜粋を使用します）。

{% hint style="danger" %}
このリンカーに脆弱性が含まれている場合、高い特権を持つバイナリでさえ実行される前に実行されるため、**特権昇格**が可能になります。
{% endhint %}

### フロー

Dyld は **`dyldboostrap::start`** によってロードされ、**スタックキャナリー** のようなものもロードされます。これは、この関数が **`apple`** 引数ベクトルにこの他の **機密性の高い値** を受け取るためです。

**`dyls::_main()`** は dyld のエントリーポイントであり、最初のタスクは通常、**`DYLD_*`** 環境変数を制限する `configureProcessRestrictions()` を実行することです。詳細は以下に説明されています:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

その後、dyld 共有キャッシュをマップし、すべての重要なシステムライブラリを事前リンクし、バイナリが依存するライブラリをマップし、必要なすべてのライブラリがロードされるまで再帰的に続行します。したがって:

1. `DYLD_INSERT_LIBRARIES` で挿入されたライブラリの読み込みを開始します（許可されている場合）
2. 次に、共有キャッシュされたもの
3. 次に、インポートされたもの
4. その後、再帰的にライブラリをインポートし続けます

すべてがロードされたら、これらのライブラリの **初期化子** が実行されます。これらは、`LC_ROUTINES[_64]`（現在は非推奨）で定義された **`__attribute__((constructor))`** を使用してコーディングされるか、`S_MOD_INIT_FUNC_POINTERS` でフラグ付けされたセクション内のポインターで定義されます（通常: **`__DATA.__MOD_INIT_FUNC`**）。

終了子は **`__attribute__((destructor))`** でコーディングされ、`S_MOD_TERM_FUNC_POINTERS` でフラグ付けされたセクションに配置されます（**`__DATA.__mod_term_func`**）。

### スタブ

macOS のすべてのバイナリは動的にリンクされています。したがって、異なるマシンやコンテキストで正しいコードにジャンプするためのスタブセクションが含まれています。バイナリが実行されると、少なくとも非遅延の場合はこれらのアドレスを解決する必要があるのは dyld です。

バイナリ内の一部のスタブセクション:

* **`__TEXT.__[auth_]stubs`**: `__DATA` セクションからのポインター
* **`__TEXT.__stub_helper`**: 呼び出す関数の情報を持つ小さなコードを呼び出す動的リンク
* **`__DATA.__[auth_]got`**: グローバルオフセットテーブル（解決されるとインポートされた関数へのアドレスが含まれます（ロード時にバインドされるため、フラグ `S_NON_LAZY_SYMBOL_POINTERS` でマークされています）
* **`__DATA.__nl_symbol_ptr`**: 非遅延シンボルポインター（ロード時にバインドされるため、フラグ `S_NON_LAZY_SYMBOL_POINTERS` でマークされています）
* **`__DATA.__la_symbol_ptr`**: 遅延シンボルポインター（最初のアクセス時にバインドされます）

{% hint style="warning" %}
接頭辞 "auth\_" を持つポインターは、1つのプロセス内暗号化キーを使用して保護されています（PAC）。さらに、ポインターを認証するために arm64 命令 `BLRA[A/B]` を使用することができます。そして RETA\[A/B\] は RET アドレスの代わりに使用できます。\
実際には、**`__TEXT.__auth_stubs`** のコードでは、要求された関数を認証するために **`bl`** の代わりに **`braa`** を使用します。

また、現在の dyld バージョンでは、**すべてを非遅延でロード**します。
{% endhint %}

### 遅延シンボルの検索
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
興味深い逆アセンブリ部分：
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
次に、printfを呼び出すジャンプが**`__TEXT.__stubs`**に向かっていることがわかります:
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
**`__stubs`** セクションの逆アセンブルにおいて:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
あなたは、この場合には遅延解決されず、printf関数のアドレスを含むGOTのアドレスにジャンプしていることがわかります。

他の状況では、GOTに直接ジャンプする代わりに、`__DATA.__la_symbol_ptr`にジャンプすることがあります。これにより、読み込もうとしている関数を表す値がロードされ、その後、`__TEXT.__stub_helper`にジャンプし、`__DATA.__nl_symbol_ptr`にジャンプします。これには`dyld_stub_binder`のアドレスが含まれ、関数の番号とアドレスをパラメータとして取ります。\
この最後の関数は、検索された関数のアドレスを見つけた後、将来の検索を避けるために、それを`__TEXT.__stub_helper`の対応する場所に書き込みます。

{% hint style="success" %}
ただし、現在のdyldバージョンでは、すべてを遅延解決しないように注意してください。
{% endhint %}

#### Dyldオペコード

最後に、`dyld_stub_binder`は指定された関数を見つけ、それを再度検索しないように適切なアドレスに書き込む必要があります。これを行うために、dyld内でオペコード（有限状態機械）を使用します。

## apple\[] argument vector

macOSでは、メイン関数は実際に3つではなく4つの引数を受け取ります。4番目はappleと呼ばれ、各エントリは`key=value`の形式です。例えば：
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
## macOS Dynamic Linker (dyld) Process

### macOS ダイナミックリンカー（dyld）プロセス

The macOS Dynamic Linker (dyld) is responsible for loading dynamic libraries into a process's address space. Attackers can abuse this functionality to inject malicious code into a legitimate process, leading to privilege escalation and persistence.

macOS ダイナミックリンカー（dyld）は、動的ライブラリをプロセスのアドレス空間にロードする責務を持っています。攻撃者はこの機能を悪用して、正規のプロセスに悪意のあるコードを注入し、特権昇格や永続性をもたらすことができます。
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
{% hint style="success" %}
これらの値がmain関数に到達する時点で、それらから機密情報がすでに削除されているか、データリークが発生している可能性があります。
{% endhint %}

mainに入る前にデバッグでこれらの興味深い値をすべて見ることができます:

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

## dyld\_all\_image\_infos

これはdyldによってエクスポートされた構造体で、dyldの状態に関する情報が含まれており、[**ソースコード**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html)で見つけることができます。バージョン、dyld\_image\_info配列へのポインタ、dyld\_image\_notifierへのポインタ、procが共有キャッシュから切り離されているかどうか、libSystemの初期化子が呼び出されたかどうか、dyldの自身のMachヘッダーへのポインタ、dyldバージョン文字列へのポインタなどの情報が含まれています。

## dyld環境変数

### dyldのデバッグ

dyldが何をしているかを理解するのに役立つ興味深い環境変数:

* **DYLD\_PRINT\_LIBRARIES**

ロードされた各ライブラリをチェックします:
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
* **DYLD\_PRINT\_SEGMENTS**

各ライブラリがどのようにロードされているかを確認します：
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
* **DYLD\_PRINT\_INITIALIZERS**

各ライブラリの初期化子が実行されるときに出力します：
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### その他

* `DYLD_BIND_AT_LAUNCH`: 遅延バインディングは非遅延バインディングで解決されます
* `DYLD_DISABLE_PREFETCH`: \_\_DATA および \_\_LINKEDIT コンテンツのプリフェッチを無効にします
* `DYLD_FORCE_FLAT_NAMESPACE`: シングルレベルのバインディング
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: 解決パス
* `DYLD_INSERT_LIBRARIES`: 特定のライブラリをロードします
* `DYLD_PRINT_TO_FILE`: dyld デバッグをファイルに書き込みます
* `DYLD_PRINT_APIS`: libdyld API 呼び出しを表示します
* `DYLD_PRINT_APIS_APP`: main によって行われた libdyld API 呼び出しを表示します
* `DYLD_PRINT_BINDINGS`: バインド時にシンボルを表示します
* `DYLD_WEAK_BINDINGS`: バインドされたときに弱いシンボルのみを表示します
* `DYLD_PRINT_CODE_SIGNATURES`: コード署名登録操作を表示します
* `DYLD_PRINT_DOFS`: ロードされた D-Trace オブジェクト形式セクションを表示します
* `DYLD_PRINT_ENV`: dyld によって見られる環境を表示します
* `DYLD_PRINT_INTERPOSTING`: インターポスティング操作を表示します
* `DYLD_PRINT_LIBRARIES`: ロードされたライブラリを表示します
* `DYLD_PRINT_OPTS`: ロードオプションを表示します
* `DYLD_REBASING`: シンボル再配置操作を表示します
* `DYLD_RPATHS`: @rpath の展開を表示します
* `DYLD_PRINT_SEGMENTS`: Mach-O セグメントのマッピングを表示します
* `DYLD_PRINT_STATISTICS`: タイミング統計を表示します
* `DYLD_PRINT_STATISTICS_DETAILS`: 詳細なタイミング統計を表示します
* `DYLD_PRINT_WARNINGS`: 警告メッセージを表示します
* `DYLD_SHARED_CACHE_DIR`: 共有ライブラリキャッシュに使用するパス
* `DYLD_SHARED_REGION`: "use", "private", "avoid"
* `DYLD_USE_CLOSURES`: クロージャを有効にします

より多くの情報を次のような方法で見つけることができます:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
または、[https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) からdyldプロジェクトをダウンロードして、フォルダ内で実行する：
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## 参考文献

* [**\*OS Internals、Volume I: User Mode. Jonathan Levin著**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローする。**
* **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。
