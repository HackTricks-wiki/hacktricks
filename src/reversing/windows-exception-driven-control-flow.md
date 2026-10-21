# Windowsの例外駆動型制御フローとアンチデバッグ

{{#include ../banners/hacktricks-training.md}}

保護されたWindowsプログラムは、意図的な例外を分岐として利用できます。例外を発生させる命令は、次のユーザーコードのアドレスを選択するハンドラーへの入口にすぎません。これにより、線形逆アセンブルからエッジを隠し、例外ディスパッチに次のステップを担わせます。<sup>[[1]](#references)</sup>

## ディスパッチが重要

プロセスにアタッチされたデバッガーは、アプリケーションのハンドラーより先に**first-chance**例外を受け取ります。イベントを未処理として渡すと、Windowsはプロセスのハンドラーを検索します。ハンドラーがない例外は、**last-chance**としてデバッガーに戻ります。そのため、ブレークポイントまたはシングルステップイベントを消費するデバッガーは、プログラムのハンドラーが実行されるかどうかを変えてしまう可能性があります。<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)`は、プロセス全体に適用されるVEHをvectored listの先頭に登録します。これはフレームベースのSEHより先に実行されますが、後から最優先で登録されたハンドラーが、これより前に移動することがあります。`EXCEPTION_CONTINUE_SEARCH`を返すと、例外は他のハンドラーに渡されます。`EXCEPTION_CONTINUE_EXECUTION`を返すと、ハンドラーによるレジスターの変更も含め、保存された`CONTEXT`から実行が再開されます。<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

従来のx86 SEHはスタック上で連結された登録情報を使い、`!exchain`で確認できます。ネイティブx64では、このx86のチェーンではなく、`.pdata`内の`RUNTIME_FUNCTION`エントリーと`.xdata`内のunwind dataが使われます。ネイティブx64プロセスに[x86 SEH overwrite workflow](../binary-exploitation/stack-overflow/windows-seh-overflow.md)を適用しないでください。<sup>[[5]](#references)[[6]](#references)</sup>

## 例外を制御フローのエッジに変える

たとえば、ゼロ除算はバグではなく、意図的に`EXCEPTION_INT_DIVIDE_BY_ZERO`を発生させるために使えます。ハンドラーは例外と例外発生アドレスを識別し、`EXCEPTION_CONTINUE_EXECUTION`を返す前に、`ContextRecord->Rip`（x86では`Eip`）を有効な継続先に設定する必要があります。<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

以下のハンドラーのコア部分は、`fault_site` と `continuation` が同じ制御フローコンテキスト内の既知のアドレスであることを前提としています。実際の実装では、想定されるスタックとレジスタを保持する必要があります。また、同じ障害発生命令から再開すると再び障害が発生するため、そこから再開してはいけません。<sup>[[7]](#references)</sup>

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

同じメカニズムで、意図的な `INT3`/`__debugbreak()`（`EXCEPTION_BREAKPOINT`）を処理して実行をリダイレクトできます。ブレークポイントを「スキップ」するために、`Rip` を無条件にインクリメントしてはいけません。保存されたアドレスと必要な調整量は、トラップ、命令エンコーディング、デバッガの動作によって異なります。継続先を選ぶ前に、`ExceptionRecord->ExceptionAddress` と保存された命令ポインターを比較し、バイト列を逆アセンブルしてください。<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) は、loader syscall の戻り状態を変更する、別の hardware-breakpoint の例です。

## Trap Flag を使ったデバッガ依存のゲート

`EFLAGS`/`RFLAGS` のビット `0x100` は Trap Flag（TF）です。これを設定すると、次の命令境界で `STATUS_SINGLE_STEP`（`0x80000004`）が発生します。VEH または SEH の分岐は、アプリケーションに渡された single-step イベントと、デバッガに処理されたイベントを区別できます。ただし、これは**デバッガの例外ポリシーに左右されるヒューリスティックであり、デバッガの存在を確実に証明するものではありません**。<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

ハンドラーが1ステップだけを求めている場合は、続行する前に再開時のコンテキストの `EFlags` で `0x100` をクリアします。また、トリガーされたアドレスとデバッグ状態を確認して、TFによるステップとhardware-breakpointイベントを区別してください。どちらも `EXCEPTION_SINGLE_STEP` として発生することがあります。<sup>[[8]](#references)[[9]](#references)</sup> WinDbgの `sxe`、`sxd`、`sxi` による初回／2回目のチャンスの設定については、[WinDbgの例外自動化](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception)を参照してください。

## References

- [1] [Check Point Research - Anti-Debug: 例外](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - デバッガーの例外処理](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - ベクター化例外処理](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - x64の例外処理](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - ベクター化例外ハンドラーの使用](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: アセンブリ命令](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - x86アーキテクチャ](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
