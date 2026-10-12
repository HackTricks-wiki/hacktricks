# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## メタデータ駆動のアンワインドが偽装可能な理由

一部の macOS セキュリティツールは、スレッドスタックの収集を `/usr/sbin/spindump` に委ねるか、従来型のメタデータ駆動アンワインダを信頼しています。インプラントはこの信頼境界を悪用し、ABI に準拠した合成レコードをスタック上に配置できます。これにより、センシティブな API が、裏付けのないインプラントコードからではなく、dyld やロード済みの Apple framework にある攻撃者が選んだ関数を経由して呼び出されたように見せかけられます。これはテレメトリの欺瞞であり、実行ファイルやその unwind metadata を変更するものではありません。<sup>[[1]](#references)</sup>

収集側の背景については、[macOS stackshots and `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) を参照してください。

アンワインダは、コンパイラが生成したプロローグによってレコードが作られたことを証明するわけではありません。現在の `PC` を使って Mach-O のレシピを選び、そのレシピを `SP`、`x29`、`x30`、スタックメモリ、宣言された非揮発性レジスタに適用し、復元した呼び出し元の `PC` を使って次のレシピを選択します。攻撃者が制御するメモリが選択されたすべてのレシピを満たすなら、実際には発生していない呼び出しであっても、構造的に有効でシンボル解決可能なチェーンを作れます。<sup>[[1]](#references)</sup>

## ARM64 frame state

[ARM64 assembly overview](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) では、レジスタの役割と呼び出し規約について説明しています。`stp x29, x30, [sp, #-16]!` の後に `mov x29, sp` を実行して作られる従来型のフレームでは、呼び出し元のエントリ時の `SP` を表す Canonical Frame Address (CFA) は `FP+0x10` です。<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Frame recordは`[FP]`を介してリンクリストを形成しますが、そのリストを盲目的にたどるだけでは不十分です。leaf functionにはframeがない場合があり、tail callによって論理的な遷移が取り除かれる場合があり、特殊なレイアウトではDWARF CFIが使われます。現在のアドレスに対応するrecipeによって、unwinderがFP chainを読み取るかどうかが決まります。<sup>[[1]](#references)[[4]](#references)</sup>

## Mach-O unwind recipeの選択

最終リンク済みイメージは、`__TEXT,__unwind_info`にcompact unwindデータを格納します。section headerは先頭のfirst-level function indexを指し、各index範囲は通常（`kind=2`）または圧縮（`kind=3`）されたsecond-level pageを指します。compact unwindで記述できないレイアウトでは、`__eh_frame`内のFDEとcall-frame instructionsを使います。<sup>[[1]](#references)[[2]](#references)</sup>

候補となる各runtime PCについて、次の処理を行います。<sup>[[1]](#references)[[2]](#references)</sup>

1. 検索時に限り、ARM64e PAC bitsを除去または正規化する。
2. アドレスを含む実行可能な`__TEXT`範囲を持つ、ロード済みのMach-Oを見つける。
3. `functionOffset = normalizedPC - loadedImageBase`を計算し、負の値または`UINT32_MAX`を超える値を拒否する。
4. `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`を満たすfirst-level範囲を選択する。
5. 参照先のsecond-level pageを解析し、offsetを超えない最も近いentryを選択して、アドレスが次のentryまたはfirst-level範囲の終端より前にあることを確認する。
6. そのentryをデコードし、記述されている状態を正確に構築する。

アドレスが保存済みLRに由来する場合、`PC-1`を検索に使うことで、call直後のアドレスをcallerの対象範囲内にとどめられる場合があります。これによって変わるのはrecipeの選択であり、stack offsetではありません。<sup>[[1]](#references)</sup>

parserはすべてのheaderとarrayを境界チェックし、section versionが`1`であることを要求し、最後のfirst-level sentinelを考慮し、second-level-page offsetがゼロの場合は拒否して、通常ページと圧縮ページを区別する必要があります。通常ページでは、`entryPageOffset`はそのページの先頭からの相対位置ですが、first-level page offsetは`__unwind_info`の先頭からの相対位置です。<sup>[[1]](#references)[[2]](#references)</sup>

大まかなmodeは`encoding & 0x0F000000`で判定できます。現在のLLVM定義には次のmodeがあります。parserは、DWARF以外の値をすべて従来型のframeとして扱ってはなりません。<sup>[[1]](#references)[[2]](#references)</sup>

| Mode | Value | Callerの復元方法 |
| --- | --- | --- |
| Compact recipeなし | `0x00000000` | 停止するか、独立したfallbackを使う。 |
| Frameless | `0x02000000` | エンコードされたstack sizeを現在の`SP`に加える。caller PCはlive LR。 |
| DWARF | `0x03000000` | 下位24 bitsで識別されるFDE/CFIを実行する。 |
| Frame | `0x04000000` | 慣例的な`x29` frame recordを読み取る。 |
| 認証済みLR範囲を持つarm64e frame | `0x05000000` | `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`を処理する。そのoffset fieldは、対象範囲内の`pacibsppc`の位置を示す。 |

Frameless modeでは、`stackSize = ((encoding & 0x00FFF000) >> 12) * 16`です。Frame modeでは、下位5 bitsで、`x19/x20`から`x27/x28`までの連続した保存済みGPR pairを指定します。bits `0x100-0x800`も同様に、`d8-d15`のpairを指定します。次のPCを見つけるだけなら、これらの保存済みregisterは不要な場合があります。しかし、信頼できる仮想caller stateを作るには、consumerが復元するすべてのfieldを満たす必要があります。<sup>[[1]](#references)[[2]](#references)</sup>

## Synthetic frame-mode recordの構築

この構築プロセスでは、stackからアドレスらしき値を探すのではなく、unwinderの処理を逆にたどります。<sup>[[1]](#references)</sup>

1. 現在ロードされているイメージ内の、実在する実行可能なPCを選ぶ。
2. その正確なPCまたはcall-site addressを対象とするrecipeをデコードする。
3. 必要なalignmentとCFAとの関係を満たすsynthetic recordを割り当てる。
4. 次のsynthetic FPを`[FP]`に、そのframeの保存済みcaller PCを`[FP+8]`に格納し、encodingで指定されたすべてのGPR/FPR saveをFPより下に格納する。
5. 複数のrecordをリンクし、最初のrecordをlive `x29`に設定する。
6. 実行を安全に復元できるようにしながら、unwindingが選択したchainに入るようlive LRとAPI return pathを配置する。

たとえば、`0x04000001`はframe modeと`x19/x20` pairを意味します。対応する状態変換と必要なmemoryは次のとおりです。<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

したがって、正当に見えるアドレスだけでは不十分です。復元された各PCが次の検索のキーになるため、エンコーディングが偽造したレイアウトと一致しないアドレスが1つでもあると、チェーンが途切れるか、consumerが一貫性のないレジスタ状態を再構築します。<sup>[[1]](#references)</sup>

## ARM64e PAC requirements

PACは、ポインタの未使用ビットに鍵付きの整合性値を格納します。アドレスを暗号化するわけではありません。Clangのarm64eリターンアドレススキーマでは、関数エントリ時のスタックポインタを識別子として、命令キーBを使用します。一般的なフレームでは、エントリ時の`SP`はCFAなので、`[FP+8]`に保存されたLRは`FP+0x10`に紐付けられます。<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

各 synthetic LR は個別に署名する必要があります。署名済み LR を異なる CFA を持つフレームに移動すると discriminator が変わり、認証に失敗するためです。`ptrauth_strip()` はアドレスの正規化やシンボル検索には適していますが、真正性を保証するものでは**ありません**。実際の return または authenticated indirect branch では、その遷移時点で想定される key と modifier を使用する必要があります。<sup>[[1]](#references)[[3]](#references)</sup>

一般的な non-leaf arm64e 関数は、LR を保存する前に署名し、entry SP を復元した後に認証します。<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline と restore bridge

合成レコードはunwinderを満たすだけでよく、完全な実行コンテキストを含む必要はありません。機密性の高いAPIから偽造した呼び出し元へ直接戻ると、通常はクラッシュします。そのため実用的な設計では、APIのすぐ下にgadgetフレームを配置します。APIはロード済みframework内の実行可能コードに戻り、そのgadgetが制御されたcallee-saved registerを経由してimplant内のrestore bridgeへ分岐します。<sup>[[1]](#references)</sup>

有用なgadgetはLRを保持し、制御されたregisterを経由して処理を引き継ぎます。たとえば、適切な`br`、`braa`、`brab`シーケンスを使用します。restore bridgeは、implantの実行を再開する前に、元の`x19-x30`の値と`SP`を復元する必要があります。arm64eでは、APIからgadget、gadgetからbridge、bridgeからimplantへ至る経路における認証付きreturnまたはbranchごとに、その命令が使用するkeyとdiscriminatorで署名されたポインターが必要です。<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

stack-based detectionにとって、これは重要な信頼境界の破綻です。chainに含まれるのが、マッピング済みでシンボル解決可能なApple frameworkのPCだけであっても、実際のcontrol flowを表しているとは限りません。したがって、unwindの出力は実行トレースとして扱わず、threadの実行可能メモリの来歴や、機密性の高いAPIの前後における実際の遷移について、独立した証拠と照合する必要があります。<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Apple SiliconにおけるARM64 stackの内部構造と難読化](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Mach-O compact unwindエンコーディングの定義](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Pointer Authentication](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Arm 64-bit ArchitectureのProcedure Call Standard](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
