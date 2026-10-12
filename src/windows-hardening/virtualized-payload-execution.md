# 仮想化ペイロード実行とカスタムVMによる回避

{{#include ../banners/hacktricks-training.md}}

ペイロードの仮想化では、攻撃ロジックをゲスト命令セットにコンパイルし、ネイティブインタープリターで実行します。最終的に元のネイティブ命令をメモリ上に展開する必要があるpackerとは異なり、仮想化されたペイロードは、保護対象のロジックをライフサイクル全体にわたってbytecodeとして保持できます。これにより、特定のアンパッキングの時間枠をなくせますが、syscall、ネットワーク通信、VMからネイティブへの呼び出し境界など、ホストから観測可能な動作は隠せません。<sup>[[2]](#references)[[3]](#references)</sup>

## 実行モデル

コンパクトな仮想化ローダーでは、実行を次のレイヤーに分けられます。<sup>[[3]](#references)</sup>

1. freestanding C、BOFソース、またはランタイムライブラリをLLVM経由でカスタムbytecode ISAにコンパイルする。
2. 小型のネイティブインタープリターを起動し、ビルドごとのopcodeマッピングを初期化する。
3. PEリンカーローダー自体をbytecodeとして実行する。ヘッダーを解析し、セクションをマップし、relocationを適用し、importを解決して、IATに値を設定する。
4. ゲスト間の呼び出しはインタープリター内で処理する。importされたDLL関数など、bytecode領域の外部にある呼び出し先は、ネイティブのhost-call thunkを経由させる。
5. HTTP framing、TLS、Cランタイムの一部などの機能も、同じインタープリター境界の内側に置く。

このモデルでは、プラグインごとに独立したネイティブコード領域を割り当てる必要がなく、元のペイロードが識別可能なx86-64命令列として現れるのを防げます。ただし、これはセキュリティ境界ではなく、回避／難読化の境界です。ネイティブインタープリターと外部への作用はすべて観測可能なままです。<sup>[[2]](#references)[[3]](#references)</sup>

## 共有メモリのホストブリッジ

分離されたVMでは、ポインターはゲストバッファー内のオフセットとして表されるため、ホストAPIを呼び出すたびにポインター変換と出力パラメーターの特別な処理が必要です。一方、共有メモリVMでは、ゲストアドレスをホストプロセスのアドレスとして有効にできます。そのため、読み書きには`memcpy`形式の操作を使え、ネイティブのallocation ECALLが返したポインターをbytecodeから直接参照できます。RISC-Y Businessは、この設計によってブリッジをPEBの取得と任意のホスト呼び出しの実行にまで簡素化できることを実証しました。<sup>[[1]](#references)</sup>

Windows x64では、仮想レジスタファイルをABIに合わせられます。最初の4つの整数またはポインター引数を`RCX`、`RDX`、`R8`、`R9`に配置し、それ以降の引数とshadow spaceをスタックに置きます。仮想`CALL`の呼び出し先がbytecode範囲外に解決されると、汎用thunkがその状態をネイティブ呼び出し用にマーシャリングし、戻り値をVMにコピーします。これにより、ポインター修正なしでIAT呼び出し、heap allocation、socket操作を実行できます。<sup>[[2]](#references)[[3]](#references)</sup>

代償として、分離は完全に失われます。ゲストメモリの破損がホストに直接影響し、ネイティブの呼び出し先がゲストポインターを保持または変更する可能性があり、インタープリターはbytecodeを完全に信頼できるものとして扱う必要があります。ネイティブからVMへのコールバックにも逆方向のブリッジが必要です。外向きの呼び出ししかサポートしないVMでは、`EnumWindows`のようなコールバックベースのAPIを直接利用できません。<sup>[[1]](#references)[[3]](#references)</sup>

## ビルドごとのISA多態化

固定幅のカスタムISAを使うと、デコード、ディスパッチ、relocation、仮想レジスタのマッピングが簡素化されます。Centurionはx86-64を参考にした18バイトの命令形式を採用しています。コード密度よりも解析の予測可能性を優先する設計であり、既存のx86-64アーティファクトをbytecodeに変換できる可能性も残しています。<sup>[[3]](#references)</sup>

ビルドごとにopcodeとハンドラーの対応をランダム化すると、同じゲストロジックでも異なるバイト列になります。さらに対応表を暗号化し、実行時にのみ復元することで、ディスク上に安定したopcode辞書が残るのを防げます。これにより、固定シグネチャや再利用可能な逆アセンブルルールを妨げられますが、ネイティブディスパッチャー、テーブル復号ルーチン、ホスト呼び出し境界が自動的に多態化されるわけではありません。<sup>[[3]](#references)</sup>

## 実行環境をVM内に取り込む

ホストプロセスをメモリ、syscall、socketのプリミティブに絞り、freestandingライブラリを使ってVM内でより高水準のサービスを提供できます。たとえば、FreeRTOS coreHTTPでHTTP framingを実装し、mbedTLSでTLSを実装すれば、WinHTTPやOSのTLS APIを呼び出さずに済みます。その場合、`afd.sys`などを介したraw socketが、狭い範囲のネイティブネットワーク境界になります。<sup>[[3]](#references)</sup>

この**Bring Your Own Execution Environment (BYOEE)**設計では、PEローダー、ランタイムサポート、インメモリファイルシステムもインタープリターの内側に配置できます。これにより、識別されやすいネイティブ実装を減らせますが、telemetryをなくすことはできません。raw socket操作は引き続き可視であり、明示的なproxyやTLS interceptionが必要な環境では、ネットワーク設計が機能しない場合があります。<sup>[[3]](#references)</sup>

## 選択的なネイティブ高速化

すべての命令を解釈実行すると、特に公開鍵暗号では大きなコストがかかります。実用的な分割方法として、mbedTLSの`MBEDTLS_ALT`フックをソフトウェアコプロセッサーのインターフェースとして使えます。TLSの状態、証明書解析、ネゴシエーション、メモリ割り当て、高水準のbignumコードはbytecodeに残しつつ、`bignum_core.c`の負荷の高い算術カーネルをネイティブECALL経由で実行します。Centurionのprototypeでは、`bignum.c`、`bignum_mod.c`、`bignum_mod_raw.c`を仮想化したまま内部ループをネイティブ実行することで、ECDHE handshakeを数分から数秒に短縮しました。<sup>[[3]](#references)</sup>

acceleratorはオプションにし、TLSを必要としないペイロードでは追加のネイティブエントリーポイントを省けるようにします。この手法はあらゆるインタープリターのワークロードに応用できます。まずプロファイリングを行い、サブシステム全体をVMの外に出すのではなく、可能な限り小さなネイティブプリミティブだけを公開してください。<sup>[[3]](#references)</sup>

Centurionは、TLS 1.2 bind shellを使って一連の処理を検証しました。bytecodeローダーがPEをマップし、socket呼び出しは汎用thunkを経由し、mbedTLSがVM内でプロトコルを処理し、ネイティブECALLがECDHEの算術処理を高速化しました。約18 KBのネイティブインタープリターで、ペイロードをネイティブx86-64コードとしてメモリ上に展開することなく、暗号化されたコマンドチャネルを実現しました。<sup>[[3]](#references)</sup>

## リバースと検出の手がかり

以下は、このアーキテクチャから推測できる実用的な分析の手がかりです。仮想化によってアナリストが動作を観測する場所は変わりますが、動作そのものがなくなるわけではありません。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- fetch/decode/dispatchループ、仮想プログラムカウンター、レジスタファイル、固定幅命令を繰り返し処理する箇所を特定する。
- 実行時に復号されたopcodeテーブルをダンプし、ディスク上の暗号化bytecodeを照合するのではなく、ハンドラーのアドレスを意味上の操作に対応付ける。
- 汎用thunkまたはECALLディスパッチャーにbreakpointを設定し、ネイティブの呼び出し先、仮想引数レジスター、スタック引数、戻り値を記録する。
- ローダー自体がbytecodeで実装されていても、PEBアクセス、export解決、PEヘッダー解析、relocation書き込み、IATへの値の設定を追跡する。
- socketの作成や`afd.sys`の通信を、想定されるWinHTTPやネイティブTLS呼び出しがないことと関連付ける。高水準のimportがないことは手がかりにはなるものの、悪意がないことの証明にはならない。
- ネイティブ算術acceleratorを意味解析の要所として扱う。周囲のTLS状態機械が仮想化されたままでも、その呼び出し元から鍵交換や証明書検証の動作がわかる場合がある。

元のcontrol-flow graphではなくdispatcherから始める分析ワークフローについては、[packerの仮想化に関するマルウェア分析ガイダンス](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation)を参照してください。

## 運用上の制約

仮想化にはインタープリターのオーバーヘッドがあり、ツールチェーンとABIが複雑になり、動作検知の問題も解決しません。共有メモリは設計上安全ではなく、必須proxyがある環境ではraw socketによる通信に失敗することがあり、コールバックを多用するWin32 APIにはネイティブからVMへのtrampolineが必要です。また、インタープリター、syscallブリッジ、ネイティブacceleratorは従来型のネイティブフットプリントとして残るため、防御側はシグネチャ検出や計測が可能です。<sup>[[2]](#references)[[3]](#references)</sup>

## 関連ページ

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: ペイロード難読化のためのRISC-V仮想マシンの構築](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: EDR時代のRed Teaming — マルウェア仮想化による回避](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — 独自の実行環境を持ち込む](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
