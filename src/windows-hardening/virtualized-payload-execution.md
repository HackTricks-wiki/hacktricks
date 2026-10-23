# Virtualized Payload Execution and Custom VM Evasion

{{#include ../banners/hacktricks-training.md}}

Payload virtualization は、攻撃ロジックを guest 命令セットにコンパイルし、native interpreter で実行します。元の native 命令を最終的にメモリ上に露出させる必要がある packer とは異なり、virtualized payload は保護対象のロジックをライフタイム全体にわたって bytecode として保持できます。これにより、特定の unpacking window はなくなりますが、syscall、ネットワーク活動、VM から native への呼び出し境界といった、ホストから観測可能な動作は隠せません。<sup>[[2]](#references)[[3]](#references)</sup>

## 静的解析を回避するための WebAssembly 再ホスティング

signature が多数設定された Go ツールを編集する代わりに、`wasip1` guest としてコンパイルし、別の native loader に埋め込む方法があります。guest は、`net.Dial`、`net.Listen`、`os/exec`、`os.Pipe` などの未対応操作が `//go:wasmimport` 経由で委譲されるよう、パッチを当てた GOROOT を使ってビルドします。Wazero host module は、ソケット、プロセス操作、Win32 呼び出し、macOS framework 呼び出しを実装します。これにより、元のプロジェクトの Go API の使い方を維持したまま、そのロジックの大部分を暗号化された WASM module に移せます。静的 PE 解析ツールは、この module を理解できない可能性があります。<sup>[[4]](#references)</sup>

### linear memory と native API のブリッジ

guest pointer は WASM linear memory 内の 32-bit offset であり、ホストの仮想アドレスではありません。native 呼び出しの前に、引数が local pointer として指定され、`0x10000 <= value < wasmMemorySize` の範囲にある場合に限り、ブリッジは `wasmMemoryBase + value` に変換できます。下限を設けることで、小さな handle、flag、`nil` が書き換えられるのを防ぎます。`win32metadata` から生成した API ごとの mask により、実際の pointer と handle、サイズ、リモートプロセスのアドレスを区別し、メタデータが不正確または曖昧な場合は override で補います。<sup>[[4]](#references)</sup>

native API は、guest の output buffer を通じてホストの pointer を返す場合もあります。mirror table は、そのようなオブジェクトに guest memory 上の表現を割り当て、元のホストアドレスへの逆引き対応を保持できます。COM では、interface と vtable の両方を mirror する必要があります。データ pointer はたどって mirror できますが、`MEM_IMAGE` 領域内の実行可能な pointer は、WASM が native 命令を実行できないため、不透明な token のままにする必要があります。このモデルは、`EnumWindows` や `SetWindowsHookEx` など、ホストから guest への callback API を直接サポートしません。<sup>[[4]](#references)</sup>

### ビルドごとの WASM VM polymorphism

runtime と payload は、ビルドのたびに一緒に変換できます。opcode-to-handler table を並べ替え、新しい対応に合わせて各 guest opcode を書き換え、section identifier をランダム化し、標準の `\0asm` magic をビルド固有の marker に置き換え、runtime cache magic を変更します。同一のソースから byte 単位で異なる module が生成され、解析者が host loader から独自の mapping と framing を復元するまで、通常の WASM ツールでは payload を解析できません。<sup>[[4]](#references)</sup>

リバースエンジニアリングでは、`\0asm` だけを手掛かりに切り出すのではなく、native host から調べ始めます。コンパイル済み marker、module の復号経路、opcode dispatch table、`env` host-function の登録を特定し、標準 module を再構築するか、import 境界に計測を仕掛けます。ネットワーク、プロセス作成、registry アクセス、動的ロード、汎用 Win32 dispatch の呼び出しは、ビルドごとに埋め込まれた bytecode が変わってもこのブリッジを通るため、ブリッジは有効な動作上の chokepoint です。<sup>[[4]](#references)</sup>

### 外側の Go executable のカモフラージュ

guest だけを変更しても、loader は識別可能なままです。実証された外側のバイナリ変換では、正規の Go プロジェクトから収集した密度の高い symbol profile を `gopclntab` に差し込み、もっともらしい少数の DLL import をローテーションし、PE `VERSIONINFO` と Authenticode の identity string を変化させます。これらの変換は、container の静的および機械学習ベースの特徴を狙ったものです。host shim が露呈する runtime の動作は取り除きません。<sup>[[4]](#references)</sup>

## 実行モデル

簡潔な virtualized loader は、実行を次のレイヤーに分けられます。<sup>[[3]](#references)</sup>

1. freestanding C、BOF source、または runtime library を LLVM 経由で custom bytecode ISA にコンパイルする。
2. 小規模な native interpreter を起動し、ビルド固有の opcode mapping を初期化する。
3. PE linker-loader 自体を bytecode として実行する。header を解析し、section を map し、relocation を適用し、import を解決して IAT を埋める。
4. guest 同士の呼び出しは interpreter 内にとどめる。import された DLL 関数など、bytecode 領域外の target は native host-call thunk 経由で呼び出す。
5. HTTP framing、TLS、C runtime の一部などの補助機能も、同じ解釈境界の内側に移す。

このモデルでは、plugin ごとに個別の native code 領域を割り当てる必要がなく、元の payload が識別可能な x86-64 命令列として現れるのを防げます。それでも、これは evasion/obfuscation の境界であって、セキュリティ境界ではありません。native interpreter と、外部へのあらゆる作用は引き続き観測可能です。<sup>[[2]](#references)[[3]](#references)</sup>

## 共有メモリ host bridge

分離型 VM では、pointer は guest buffer 内の offset として表されるため、host API を呼び出すたびに pointer の変換と output parameter の特別な処理が必要です。一方、共有メモリ型 VM では、guest address をホストプロセスのアドレスとして使用できます。そのため、読み書きに `memcpy` 形式の操作を使え、native allocation ECALL が返した pointer を bytecode から直接 dereference できます。RISC-Y Business は、この設計により、ブリッジを PEB の取得と任意の host call の発行だけに簡略化できることを実証しました。<sup>[[1]](#references)</sup>

Windows x64 では、仮想 register file を ABI に合わせられます。最初の 4 つの整数または pointer 引数を `RCX`、`RDX`、`R8`、`R9` に置き、以降の引数と shadow space は stack に配置します。仮想 `CALL` の解決先が bytecode 範囲外の場合、汎用 thunk がその状態を native call 用に marshal し、戻り値を VM にコピーし戻します。これにより、pointer の fixup なしで IAT 呼び出し、heap allocation、ソケット操作が可能になります。<sup>[[2]](#references)[[3]](#references)</sup>

その代償として、分離性は完全に失われます。guest memory の破損はホストに直接影響を与える可能性があり、native callee は guest pointer を保持または変更できます。また、interpreter は bytecode を完全に信頼できるものとして扱う必要があります。native から VM への callback にも逆方向のブリッジが必要です。外向きの呼び出ししかサポートしない VM では、`EnumWindows` のような callback ベースの API を直接利用できません。<sup>[[1]](#references)[[3]](#references)</sup>

## ビルドごとの ISA polymorphism

固定幅の custom ISA は、decode、dispatch、relocation、仮想 register mapping を簡略化します。Centurion は、x86-64 を参考にした 18-byte の命令形式を採用しています。これにより、コード密度を犠牲にする代わりに解析を予測可能にし、既存の x86-64 artifact を bytecode に変換する道も残しています。<sup>[[3]](#references)</sup>

ビルドごとに opcode-to-handler mapping をランダム化すると、同じ guest ロジックから異なる byte sequence が生成されます。さらに mapping table を暗号化し、runtime にのみ復元することで、ディスク上に安定した opcode dictionary が残るのを防げます。これにより、固定 signature や再利用可能な逆アセンブル規則を妨げられますが、native dispatcher、table の復号処理、host-call 境界が自動的に polymorph されるわけではありません。<sup>[[3]](#references)</sup>

## 実行環境を VM 内に取り込む

ホストプロセスを memory、syscall、socket の primitive にまで縮小し、freestanding library が VM 内で高レベルの機能を提供できます。たとえば、FreeRTOS coreHTTP で HTTP framing を実装し、mbedTLS で TLS を実装すれば、WinHTTP や OS の TLS API を呼び出さずに済みます。その場合、`afd.sys` などを介した raw socket が、限定的な native networking 境界になります。<sup>[[3]](#references)</sup>

この **Bring Your Own Execution Environment (BYOEE)** 設計では、PE loading、runtime support、in-memory filesystem も interpreter の内側に置けます。認識されやすい native 実装を減らせますが、telemetry をなくすわけではありません。raw socket 操作は依然として観測可能であり、明示的な proxy や TLS interception が必要な環境では、ネットワーク設計が機能しない可能性があります。<sup>[[3]](#references)</sup>

## 選択的な native 高速化

すべての命令を解釈実行すると、公開鍵暗号では特に大きなコストがかかります。実用的な分割方法として、mbedTLS の `MBEDTLS_ALT` hook を software coprocessor interface として使います。TLS state、証明書解析、negotiation、allocation、高レベルの bignum code は bytecode 内に残し、`bignum_core.c` の負荷の高い算術 kernel だけを native ECALL 経由で実行します。Centurion の prototype では、`bignum.c`、`bignum_mod.c`、`bignum_mod_raw.c` は virtualized のままにし、内部ループを native で実行することで、ECDHE handshake を数分から数秒に短縮しました。<sup>[[3]](#references)</sup>

accelerator は optional にし、TLS が不要な payload では追加の native entry point を省けるようにします。この方法は interpreter のあらゆる workload に応用できます。まず profile を取り、subsystem 全体を VM の外に移すのではなく、必要最小限の native primitive を公開します。<sup>[[3]](#references)</sup>

Centurion は TLS 1.2 bind shell で一連の処理を検証しました。bytecode loader が PE を map し、socket 呼び出しは汎用 thunk を通り、mbedTLS が VM 内で protocol を処理し、native ECALL が ECDHE 算術を高速化しました。約 18 KB の native interpreter により、payload を native x86-64 code として実体化させずに、暗号化された command channel を実現しました。<sup>[[3]](#references)</sup>

## リバース解析と検知の手掛かり

以下は、このアーキテクチャから推測される実用的な解析の手掛かりです。virtualization によって解析者が動作を観測する場所は変わりますが、動作そのものがなくなるわけではありません。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- fetch/decode/dispatch loop、仮想 program counter、register file、固定幅命令を繰り返し処理する箇所を特定する。
- runtime で復号された opcode table を dump し、ディスク上の暗号化 bytecode と照合するのではなく、handler address を意味的な operation に対応付ける。
- 汎用 thunk または ECALL dispatcher に breakpoint を設定し、native target、仮想引数 register、stack 引数、戻り値を記録する。
- loader 自体が bytecode で実装されている場合も、PEB アクセス、export 解決、PE header 解析、relocation 書き込み、IAT の設定を追跡する。
- socket の作成や `afd.sys` の通信を、想定される WinHTTP または native TLS 呼び出しの欠如と関連付ける。高レベルの import がないことは手掛かりではありますが、無害である証拠ではありません。
- native 算術 accelerator を、動作の意味を捉える chokepoint として扱う。周囲の TLS state machine が virtualized のままでも、呼び出し元から鍵交換や証明書検証の動作が分かる場合があります。

元の control-flow graph ではなく dispatcher から解析を始める workflow については、[packer を virtualize するための malware analysis ガイダンス](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation)を参照してください。

## 運用上の制約

virtualization は解釈実行の overhead をもたらし、toolchain と ABI の複雑さを増し、動作検知の問題を解決しません。共有メモリは設計上安全ではなく、raw socket によるネットワーク通信は必須 proxy の背後では失敗する可能性があり、callback を多用する Win32 API には native から VM への trampoline が必要です。interpreter、syscall bridge、native accelerator も、defender が signature を作成したり計測したりできる、従来型の native footprint として残ります。<sup>[[2]](#references)[[3]](#references)</sup>

## 関連ページ

VMProtect 3.x packing の解析については、[emulated unpacking と import 修復](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair)を参照してください。

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Payload obfuscation のための RISC-V Virtual Machine の構築](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: EDR 時代の Red Teaming — Malware Virtualisation による evasion](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — 独自の実行環境を持ち込む](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - WasmForge の世界へ: Sliver を WebAssembly にコンパイルする](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
