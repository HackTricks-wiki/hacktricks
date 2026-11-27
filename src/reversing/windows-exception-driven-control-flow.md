# Windows Exception-Driven Control Flow and Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

保護されたWindowsプログラムは、意図的な例外を分岐として利用できます。例外を発生させる命令は、次のユーザーコードのアドレスを選択するハンドラーへの入口にすぎません。これにより、線形逆アセンブルではエッジが見えにくくなり、次のステップは例外ディスパッチに移されます。<sup>[[1]](#references)</sup>

## ディスパッチが重要

プロセスにアタッチされたデバッガーは、アプリケーションのハンドラーより前に**first-chance**例外を受け取ります。イベントを未処理として渡すと、Windowsはプロセスのハンドラーを検索します。ハンドラーがない例外は、**last-chance**としてデバッガーに戻ります。そのため、ブレークポイントやシングルステップのイベントを処理するデバッガーは、プログラムのハンドラーが実行されるかどうかを変えてしまうことがあります。<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)`は、プロセス全体で有効なVEHをvectoredリストの先頭に登録します。これはフレームベースのSEHより前に実行されますが、後からfirst-priorityで登録されたハンドラーが、その前に移動することがあります。`EXCEPTION_CONTINUE_SEARCH`を返すと、例外はほかのハンドラーに渡されます。`EXCEPTION_CONTINUE_EXECUTION`を返すと、ハンドラーによるレジスターの変更も含め、保存された`CONTEXT`から実行が再開されます。<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

従来のx86 SEHではスタックにリンクされた登録を使用し、`!exchain`で調べられます。ネイティブx64ではこのx86チェーンではなく、`.pdata`内の`RUNTIME_FUNCTION`エントリーと、`.xdata`内のアンワインドデータを使用します。ネイティブx64プロセスに[x86 SEH overwrite workflow](../binary-exploitation/stack-overflow/windows-seh-overflow.md)を適用しないでください。<sup>[[5]](#references)[[6]](#references)</sup>

## 例外を制御フローのエッジに変える

たとえば、ゼロ除算はバグではなく、意図的に`EXCEPTION_INT_DIVIDE_BY_ZERO`を発生させるために使えます。ハンドラーは例外と障害アドレスを識別し、`EXCEPTION_CONTINUE_EXECUTION`を返す前に、`ContextRecord->Rip`（x86では`Eip`）を有効な継続先に設定する必要があります。<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

以下のハンドラーの中核部分は、`fault_site` と `continuation` が同じ制御フローコンテキスト内の既知のアドレスであることを前提としています。実際の実装では、想定されるスタックとレジスターを保持する必要があります。また、同じ障害発生命令から再開すると再び障害が発生するため、そこから再開してはいけません。<sup>[[7]](#references)</sup>

```c
if (e->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO &&
    e->ExceptionRecord->ExceptionAddress == fault_site) {
#ifdef _M_X64
    e->ContextRecord->Rip = (DWORD64)continuation;
#else
    e->ContextRecord->Eip = (DWORD)continuation;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}
return EXCEPTION_CONTINUE_SEARCH;
```

同じメカニズムで、意図的な `INT3`/`__debugbreak()`（`EXCEPTION_BREAKPOINT`）を処理して実行をリダイレクトすることもできます。「ブレークポイントをスキップ」するために、`Rip` をやみくもにインクリメントしてはいけません。保存されたアドレスと必要な調整量は、トラップ、命令のエンコーディング、デバッガーの動作によって異なります。継続先を選ぶ前に、`ExceptionRecord->ExceptionAddress` を保存された命令ポインターと比較し、バイト列を逆アセンブルしてください。<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) は、ローダーの syscall の戻り状態を変更する、別の hardware-breakpoint の例です。

## Fault-driven page materialization

VEH は、ページフォールトを単なるジャンプではなく、**遅延ローダー**に変えることができます。ページが未コミットのままになるようプライベートなイメージ領域を予約するか、サポートされている場合はマップ済みページにガードを設定します。イメージを実行する前に、再配置箇所と IAT thunk を宛先ページごとにインデックス化します。その領域内でフォールトが発生したら、ハンドラーは該当ページをコミットするか書き込み可能にし、そのセクションのバイト列をコピーして、そのページの再配置と import を適用し、最終的な保護属性を設定して、`EXCEPTION_CONTINUE_EXECUTION` を返します。元の命令が再実行されます。フォールトをスキップするハンドラーのように `Rip` を進めてはいけません。一度もアクセスされないページには、ペイロードをメモリ上に格納する必要はありません。<sup>[[11]](#references)</sup>

アクセス違反の場合、`ExceptionRecord->ExceptionAddress` はフォールトを起こした**命令**を示し、`ExceptionInformation[1]` はアクセスされたアドレスを示します。<sup>[[10]](#references)</sup> ページをマテリアライズする前に、例外コード、パラメーター数、アクセスされたアドレスの範囲を確認してください。確認しないと、無関係なフォールトをローダーの要求と誤認する可能性があります。<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` は初回アクセス時に `STATUS_GUARD_PAGE_VIOLATION`（`0x80000001`）を発生させ、Windows はガードビットを自動的にクリアします。そのため、再設定は別途必要であり、継続的なフックではありません。<sup>[[12]](#references)</sup> VEH と、ディスパッチ中に必要となるメタデータには、アクセス可能な状態を保ってください。<sup>[[11]](#references)</sup> x64 では、最初のフォールトより前にアンワインドデータを利用可能にする必要がある場合があります。引用したローダーは初期化時の競合を避けるため、`DllMain` を呼び出す前にページをすべてマテリアライズします。<sup>[[11]](#references)</sup> コードを書き込んだ後、実行する前に命令キャッシュをフラッシュしてください。<sup>[[13]](#references)</sup>

リバース時にこのフローを追跡するには、first-chance のガードページ違反とアクセス違反でブレークし、例外レコードを調べてから、`gn` でイベントをアプリケーションのハンドラーに渡します。<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> アクセスされたアドレスに対して `!vprot` を使い、現在のページ保護属性を確認してください。<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

ハンドラーがページを実体化した後、そのバイト列をダンプし、ファイルイメージと比較します。<sup>[[11]](#references)</sup> guard 状態はワンショットなので、fault 後の `!vprot` では、そのページが事前に guard 状態だったことを証明できません。<sup>[[11]](#references)[[12]](#references)</sup> 関連するイメージ範囲が判明したら、無関係な fault を避けるため、例外フィルターまたはハンドラーのブレークポイントを絞り込みます。<sup>[[16]](#references)</sup> フィルターの設定については、[WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) を参照してください。<sup>[[16]](#references)</sup>

## デバッガー依存のゲートとしての Trap Flag

`EFLAGS`/`RFLAGS` のビット `0x100` は Trap Flag (TF) です。これを設定すると、次の命令境界で `STATUS_SINGLE_STEP` (`0x80000004`) が発生します。VEH または SEH の分岐では、アプリケーションに渡された single-step イベントと、デバッガーが処理したイベントを区別できます。ただし、これは**デバッガーの例外ポリシーに左右されるヒューリスティック**であり、デバッガーの存在を確実に証明するものではありません。<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

ハンドラーが1ステップだけを必要とする場合は、続行する前に再開コンテキストの `EFlags` で `0x100` をクリアします。また、トリガーとなったアドレスとデバッグ状態を確認して、TFによるステップとハードウェアブレークポイントイベントを区別してください。どちらも `EXCEPTION_SINGLE_STEP` として発生することがあります。<sup>[[8]](#references)[[9]](#references)</sup> WinDbg の `sxe`、`sxd`、`sxi` による first-chance／second-chance の設定については、[WinDbg の例外自動化](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception)を参照してください。

## References

- [1] [Check Point Research - Anti-Debug: 例外](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - デバッガーの例外処理](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - ベクター化された例外処理](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64 の例外処理](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - ベクター化例外ハンドラーの使用](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: アセンブリ命令](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86 アーキテクチャ](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Fault-driven image loading](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Guard ページの作成](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (例外レコードの表示)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - sx 例外フィルター](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (未処理例外で続行)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
