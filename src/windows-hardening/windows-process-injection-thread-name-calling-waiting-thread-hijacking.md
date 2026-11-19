# Thread Names と Waiting Threads を介した Windows Process Injection

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) は `WriteProcessMemory` を使わずに、実行中のプロセスへバイト列を転送します。Waiting Thread Hijacking (WTH) は `SetThreadContext` やリモートスレッドの作成をせずに、既存のスレッド上でコードを実行します。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> これらは**プロセスインジェクションのプリミティブであり、権限昇格の脆弱性ではありません**。インジェクターには、引き続きターゲットプロセスとスレッドへのアクセスが必要です。スレッドの説明を扱う API を使用するには、Windows 10 version 1607 以降が必要です。<sup>[[1]](#references)[[3]](#references)</sup> ほかのインジェクションや回避手法については、[Antivirus (AV) Bypass](av-bypass.md) を参照してください。

## Thread Name-Calling: target 側での payload コピー

`NtSetInformationThread(ThreadNameInformation)` は、渡された `UNICODE_STRING` をスレッド名のストレージにコピーします。**target 内で** `GetThreadDescription` を呼び出すと、その名前の user-mode heap コピーが作成されます。これにより、payload の転送と最終的なメモリコピーを分離できます。インジェクターは返された heap の**ポインター**を読み取り、target 内で実行される APC が `RtlMoveMemory` を実行して、バイト列をコピー先へ移します。<sup>[[1]](#references)</sup> 元の手法は special user APC もサポートしていますが、WhisperHijack の実装では、待機中のスレッドに通常の `NtQueueApcThread` を使用します。<sup>[[1]](#references)[[3]](#references)</sup>

`0xFFFE` バイト以下の各チャンクについて、PoC は次の順序で処理します。複製された auto-reset event は、target が scratch slot に書き込み終えた後にのみ完了を通知します。インジェクターはその通知を待ってからポインターを読み取ります。このイベントが確認するのは heap-pointer APC の完了であり、その後のコピー APC の完了ではありません。PoC はコピーをキューに追加した後、同じスレッドを alert し、2 回目の完了通知の代わりに APC の順序に依存します。<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

スクラッチアドレスはターゲット内で書き込み可能で、事前に書き込むことなくインジェクターが把握できる必要があります。元のPoCでは `PEB.SpareUlongs` を使用しています。<sup>[[1]](#references)</sup> WhisperHijack では `PEB.PostProcessInitRoutine` も選択でき、デフォルトでは `TEB.TlsSlots[63]` を使用します（`NtQueryInformationThread(ThreadBasicInformation)` で取得）。TLS slot がすべてのターゲットで未使用とは **限りません**。使用中のslotを上書きすると、そのスレッドに問題が起きる可能性があります。`Main.c` ではオプションを必ず1つだけ有効にしてください。コンパイル時チェックにより、PEB/TEB の選択漏れや競合は拒否されます。<sup>[[4]](#references)</sup>

通常の `RtlInitUnicodeString` 呼び出しでは、埋め込まれたワイド文字のヌル文字で処理が止まります。バイナリデータを渡すには、同じサイズのヌル文字を含まないパディングバッファを使って `UNICODE_STRING` の長さを初期化し、`Buffer` のバイト列を実際のチャンクに置き換えてから、`NtSetInformationThread` に渡します。この長さベースの転送は、終端文字列としてシェルコードを直接 `SetThreadDescription` に渡す方法とは異なります。<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: キュー待機からの復帰

`NtQuerySystemInformation(SystemProcessInformation)` でスレッドを列挙し、`ThreadState == Waiting` かつ `WaitReason == WrQueue` のものを探します。`NtWaitForWorkViaWorkerFactory` などの syscall wrapper 内でブロックしているスレッドには、保存された呼び出し元の戻りアドレスが `[Rsp]` にあります。このスタックslotを書き換えると、`SetThreadContext` で `Rip` を変更せずに、wrapper の `ret` を stub にリダイレクトできます。stub はフラグとレジスターを保存し、復帰する payload を **call** してから状態を復元し、保存した元の戻りアドレスへジャンプする必要があります。<sup>[[2]](#references)[[3]](#references)</sup>

x64 PoC では、stub は `+0x00` に8バイトの戻りアドレス保存領域、`+0x08` に命令、`+0x45` に payload を配置します。スタックslotに設定するのはデータslotのアドレスではなく、`allocation_base + 0x08` です。`WrQueue` だけでは worker-factory wait の **証明になりません**。元の研究では、キュー待機経路として `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` も特定しています。このレイアウトに依存する前に、実際の wait/call stack と `[Rsp]` が意図した戻りアドレスslotであることを確認してください。<sup>[[2]](#references)[[3]](#references)</sup>

## プロセス間書き込みなしでTNCとWTHを組み合わせる

WhisperHijack は、既存のネイティブ x64 プロセスを対象にした一連の処理を示しています。Writer が候補となるプロセス/スレッドを選び、Flipper の子プロセスは最終的な引き渡しに必要なハンドルを継承します。プロセスハンドルには `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE` を要求し、`PROCESS_VM_WRITE` は要求しません。ただし、現行のPoCはスレッドを `THREAD_ALL_ACCESS` で開きます。アクセスチェックとプロセス緩和策は引き続き適用されます。<sup>[[3]](#references)[[4]](#references)</sup>

組み合わせたPoCでは、次の手順を使います。メモリコピーの APC は、リモート書き込み権限のあるハンドルを介さず、ターゲット内で実行されます。<sup>[[4]](#references)</sup>

1. ターゲット内で64-KB境界に揃った空き領域を予約し、その後、4-KBページを `PAGE_READWRITE` として commit します。PoC は `NtQueryVirtualMemory` で固定の候補アドレスを調べますが、これらのアドレスは実装上の選択であり、TNCやWTHの要件ではありません。
2. `[0x45-byte WTH stub][復帰するx64 payload][8-byte stub-entry pointer]` を組み立てます。最後のポインターは `allocation_base + 0x08` です。このバッファを TNC のチャンクループで転送します。
3. Flipper 内で `NtGetContextThread(CONTEXT_CONTROL)` を使い、待機スレッドの `Rsp` を取得します。ターゲット内で実行する `RtlMoveMemory` の APC をキューに入れ、`[Rsp]` にある元の8バイト値を stub のデータslotにコピーします。
4. `NtProtectVirtualMemory` でステージ済み領域を実行可能にします。このPoCではポリモーフィック payload が自己デコードするため、`PAGE_EXECUTE_READWRITE` を選択します。WTH 自体は自己書き換え型 payload を必要としません。
5. ターゲット内で実行する別の `RtlMoveMemory` の APC をキューに入れ、**事前にステージした末尾のポインター**を `[Rsp]` にコピーしてから、`NtAlertThread` を呼び出します。APC の FIFO 順序により、元の戻りアドレスを保存してから置き換えます。wrapper の復帰先は stub となり、payload の復帰後に元の呼び出し元へ戻ります。

`NtWriteVirtualMemory` がないからといって、ターゲットへの書き込みがないわけではありません。`GetThreadDescription` と `RtlMoveMemory` がターゲット内で書き込みを行います。<sup>[[1]](#references)[[3]](#references)</sup> 通常のユーザー APC の配信は、選択したスレッドが APC キューを処理するかどうかにも依存します。`WrQueue` のスナップショットと alert は、即時実行を一般的に保証するものではありません。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> この例ではリモートスレッドの作成、スレッドの suspend、コンテキストの直接置換を避けていますが、APC と保護属性の変更によって検知される可能性は残ります。<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Waiting Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack PoC と README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – WhisperHijack Main.c の実装](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
