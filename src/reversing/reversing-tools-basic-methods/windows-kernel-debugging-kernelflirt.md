# KernelFlirtを使ったWindowsカーネルデバッグ

{{#include ../../banners/hacktricks-training.md}}

KernelFlirtは、制御されたリバースエンジニアリングラボ向けのWindows x64デバッガーです。ホスト側のWPF UIまたは`KfConsole.exe`が、テスト署名済みWindows VM上の`KfRelay.exe`にコマンドを送信します。Relayはそれらを`KernelFlirt.sys`への`DeviceIoControl`リクエストに変換し、メモリ、レジスタ、ブレークポイント、実行制御、カーネルモジュールの操作を提供します。また、このドライバーは`KdpStub`/`KdTrap`のインラインフックでカーネルのデバッグ経路を変更するため、使い捨てVMでのみ使用してください。<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

relayは通常のリモートサービスではなく、特権を伴うデバッグ境界です。TCP `31337`は隔離されたホストオンリーネットワーク上に維持し、テスト署名されたdriverやrelayを信頼できないネットワークに決して公開しないでください。<sup>[[1]](#references)</sup>

関連するWindows exploitation techniques:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## ラボのセットアップと最初の停止

ビルドにはWindows 10/11 x64、C++を含むVisual Studio 2022、WDK 10.0.26100.0以降、および.NET 9が必要です。VM内でdriverとrelayを読み込み、ホストから接続します。UIではリモートのEXEまたはSYSを開くことができ、**Kernel Modules**ビューでは、すでに読み込まれているdriverにbreakpointを設定できます。<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

ラボが終了したら `KfLoader.exe unload` を使用してください。コンソールは、未接続の REPL、ローカルデバイスへの直接アクセス、relay access に対応しています。以下で説明する決定論的な `open` ワークフローを実装しているのは relay mode のみです。<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

最小限のコンソールワークフローは次のとおりです:<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

アドレスは式です。数値のみの場合は16進数として扱われ、式ではレジスタ、算術演算、`[rsp]`のような間接参照、`ntdll!NtCreateFile`のようなシンボルを使用できます。シンボルブレークポイントは、`open`または`attach`によってモジュールが列挙され、PDBが読み込まれた後にのみ設定してください。<sup>[[2]](#references)</sup>

## `EB FE`による確定的なエントリーポイント捕捉

Relay側の`open`は、ターゲットをサスペンド状態で作成し、最初のエントリーポイントのバイト列を保存してから`EB FE`を書き込み、エントリースレッドを再開して、命令ポインターがそのアドレスに到達するまでポーリングします。`EB FE`は自身に戻る2バイトの短いジャンプであり、ユーザーモードのデバッグ例外が配信されることに依存せずに実行を捕捉します。その後、Relayは元のバイト列を復元し、ターゲットをエントリーポイントで停止させます。<sup>[[2]](#references)</sup>

このパターンは、通常のデバッガー設定が完了する前に、初期のローダーパスを観察する必要がある場合にも便利です。<sup>[[2]](#references)</sup>

1. プロセスをサスペンド状態で作成し、イメージのマッピング後に実際のエントリーポイントを特定します。
2. エントリーポイントの元のバイト列を保存し、2バイトの自己ループに置き換えます。
3. エントリースレッドを再開し、命令ポインターがパッチ済みアドレスに到達するまでポーリングします。
4. ターゲットをサスペンドし、分析を続ける前に元のバイト列を正確に復元します。

この手法は意図的に侵襲的です。復元前にデバッガーまたはRelayが終了すると、ターゲットはループし続ける可能性があります。KernelFlirtのローカルモードはRelay側でのエントリーパッチに対応していません。代わりにプロセスを手動で起動し、`attach <pid>`を使用してください。<sup>[[2]](#references)</sup>

## ブレークポイントの方式を選択する

KernelFlirtは、異なる副作用を持つ複数のブレークポイント機構を提供します。以下のコマンドを使うと、パックされたコードが自らを書き換える場合、実行可能ページが読み取り専用の場合、またはソフトウェアブレークポイントのバイト列が整合性チェックされる場合に、方式を切り替えられます。<sup>[[1]](#references)[[2]](#references)</sup>

| 方式 | コマンド | 仕組みと用途 |
| --- | --- | --- |
| ソフトウェア | `bp <expr>` | MDLを介した`INT3`。RX `.text`ページを計測可能 |
| 条件付きソフトウェア | `bp <expr> if <condition>` | ヒットごとに評価し、条件が偽の場合は通知せずに再開 |
| ハードウェア実行 | `ba e1 <expr>` | コードのバイト列を変更せず、DR0-DR3のいずれかを使用 |
| ハードウェアデータ | `ba w4 <expr>` / `ba r8 <expr>` | 1、2、4、8バイトの書き込み、または読み書きを監視 |
| ガードページ | `bm <expr> [size]` | メモリ範囲のブレークポイントに`PAGE_GUARD`を使用 |
| 一時 | `g <expr>`、`p`、または`o` | アドレスまで実行、ステップオーバー、ステップアウトを行う補助ブレークポイント |

`bl`を使ってソフトウェア、ハードウェア、メモリ、一時ブレークポイントを見分け、`bc <address|handle|all>`で削除します。ハードウェアスロットは数に限りがあり、デバッグレジスタの状態を通じて適用されます。一方、ガードページはより広い範囲をカバーできますが、同じページへの無関係なアクセスでもトリガーされます。

## ネイティブx64とWoW64のステップ実行

ネイティブx64のシングルステップでは、`IOCTL_KF_SINGLE_STEP`を通じてプロセッサのトラップフラグを設定します。Step Overは現在の命令をデコードし、次に実行される可能性のあるアドレスに一時ブレークポイントを設定します。Step Outは現在のスタックの先頭から戻りアドレスを読み取ります。関数プロローグでは、スタックについてのこの前提が誤っている場合があるため、既知の内部ブレークポイントを使うことを推奨します。<sup>[[2]](#references)</sup>

`KdTrap`フックは、32ビット例外を同じ方法では捕捉しません。WoW64ターゲットの場合、デバッガーはIcedで命令をデコードし、計算した次の`EIP`に`EB FE`を書き込んで、スレッドの命令ポインターをポーリングします。そのため、WoW64では`g <address>`は使用できず、単独の`g`はブレークポイントに到達するまでコンソールをブロックします。到達可能なブレークポイントを先に設定し、無期限の実行は避けてください。`Ctrl+C`を押すとポーリングがキャンセルされるのではなく、コンソールが終了します。<sup>[[2]](#references)</sup>

## メモリ、レジスタ、シンボルを用いた分析

コンソールでは、シンボルで停止した後にメモリを調査し、制御されたパッチを適用できます。検索では、バイトのワイルドカード、ASCII、またはUTF-16を指定できます。検索サイズは最大4 MBで、報告される一致は最大256件です。割り当てと保護のコマンドは、ドライバーのallocate、free、protect IOCTLに対応します。<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

PDB の読み込みでは、各リモートモジュールの PE デバッグディレクトリを読み取り、RSDS 識別子を抽出して、DbgHelp/SymSrv 経由で一致する PDB を見つけ、PDB として読み込まれたことを確認します。プライベート PDB は中継マシン上のターゲットの隣に配置するか、そのディレクトリをホスト上の `_NT_SYMBOL_PATH` に追加してください。<sup>[[2]](#references)</sup>

## カーネルを利用した anti-debug 状態の変更

カーネルにアクセスすると、ユーザーモードのデバッガーでは確実に隠せない痕跡をデバッガーで取り除けます。変更は一度に1つずつ適用し、ターゲットのチェックを確認してから、セッションを終了する前に対応するフックを元に戻してください。<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port` は `EPROCESS.DebugPort` をクリアします。
- `clr_thread_hide` は対象スレッドから `HideFromDebugger` を削除します。
- `ntqsi on` は `NtQuerySystemInformation` クラス `0x23` (`SystemKernelDebuggerInformation`) を偽装します。
- `spoof on` は、トラップ機構に必要なカーネル状態を維持しながら、user-mode から `KUSER_SHARED_DATA.KdDebuggerEnabled` を読み取ると false が返るようにします。
- `stats` はフックのカウンターと、記録された `KiDebugRoutine`、`KdpStub`、`KdTrap` の状態を確認します。

これらの操作はプロセスとカーネルの状態を変更します。クラッシュ、古い inline hook、構造体オフセットの誤り、またはパッチの復元が未完了の状態は VM を不安定にする可能性があるため、スナップショットと隔離された test-signing 環境が必須です。<sup>[[1]](#references)</sup>

## References

- [1] [KernelFlirt リポジトリとメインドキュメント](https://github.com/AkaTorich/KernelFlirt)
- [2] [KernelFlirt コンソールリファレンス](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
