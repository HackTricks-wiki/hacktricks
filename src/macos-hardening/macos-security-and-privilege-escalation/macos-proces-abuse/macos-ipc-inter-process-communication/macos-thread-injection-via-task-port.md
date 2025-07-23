# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

最初に、`task_threads()`関数がタスクポートで呼び出され、リモートタスクからスレッドリストが取得されます。ハイジャックするためのスレッドが選択されます。このアプローチは、`thread_create_running()`をブロックする緩和策により、新しいリモートスレッドを作成することが禁止されているため、従来のコードインジェクション手法とは異なります。

スレッドを制御するために、`thread_suspend()`が呼び出され、その実行が停止されます。

リモートスレッドで許可される唯一の操作は、**停止**と**開始**、および**レジスタ値の取得**/**変更**です。リモート関数呼び出しは、レジスタ`x0`から`x7`を**引数**に設定し、`pc`をターゲット関数に設定してスレッドを再開することによって開始されます。戻り後にスレッドがクラッシュしないようにするためには、戻りを検出する必要があります。

1つの戦略は、`thread_set_exception_ports()`を使用してリモートスレッドの**例外ハンドラ**を登録し、関数呼び出しの前に`lr`レジスタを無効なアドレスに設定することです。これにより、関数実行後に例外がトリガーされ、例外ポートにメッセージが送信され、スレッドの状態を検査して戻り値を回収できるようになります。あるいは、Ian Beerの*triple_fetch*エクスプロイトから採用された方法として、`lr`を無限ループに設定し、`pc`がその命令を指すまでスレッドのレジスタを継続的に監視します。

## 2. Mach ports for communication

次の段階では、リモートスレッドとの通信を促進するためにMachポートを確立します。これらのポートは、タスク間で任意の送信/受信権を転送するのに重要です。

双方向通信のために、ローカルタスクとリモートタスクのそれぞれに1つずつ、2つのMach受信権が作成されます。その後、各ポートの送信権が対となるタスクに転送され、メッセージの交換が可能になります。

ローカルポートに焦点を当てると、受信権はローカルタスクによって保持されます。ポートは`mach_port_allocate()`で作成されます。このポートに送信権をリモートタスクに転送することが課題となります。

戦略の1つは、`thread_set_special_port()`を利用して、リモートスレッドの`THREAD_KERNEL_PORT`にローカルポートへの送信権を配置することです。その後、リモートスレッドに`mach_thread_self()`を呼び出して送信権を取得させます。

リモートポートについては、プロセスが基本的に逆になります。リモートスレッドに`mach_reply_port()`を介してMachポートを生成させます（`mach_port_allocate()`はその戻りメカニズムのため不適切です）。ポートが作成されると、リモートスレッド内で`mach_port_insert_right()`が呼び出され、送信権が確立されます。この権利はその後、`thread_set_special_port()`を使用してカーネルに保存されます。ローカルタスクに戻ると、`thread_get_special_port()`をリモートスレッドに対して使用して、リモートタスク内の新しく割り当てられたMachポートへの送信権を取得します。

これらのステップを完了すると、Machポートが確立され、双方向通信の基盤が整います。

## 3. Basic Memory Read/Write Primitives

このセクションでは、基本的なメモリの読み書きプリミティブを確立するためにexecuteプリミティブを利用することに焦点を当てます。これらの初期ステップは、リモートプロセスに対するより多くの制御を得るために重要ですが、この段階のプリミティブはあまり多くの目的には役立ちません。すぐに、より高度なバージョンにアップグレードされます。

### Memory reading and writing using the execute primitive

メモリの読み書きを特定の関数を使用して行うことが目標です。**メモリの読み取り**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
**メモリの書き込み**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
これらの関数は次のアセンブリに対応しています：
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### 適切な関数の特定

一般的なライブラリのスキャンにより、これらの操作に適した候補が明らかになりました：

1. **メモリの読み取り — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **メモリの書き込み — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
任意のアドレスに64ビットの書き込みを行うには：
```c
_xpc_int64_set_value(address - 0x18, value);
```
これらのプリミティブが確立されると、共有メモリを作成するためのステージが整い、リモートプロセスの制御において重要な進展が見られます。

## 4. 共有メモリの設定

目的は、ローカルタスクとリモートタスク間で共有メモリを確立し、データ転送を簡素化し、複数の引数を持つ関数の呼び出しを容易にすることです。このアプローチは、Machメモリエントリに基づいて構築された`libxpc`とその`OS_xpc_shmem`オブジェクトタイプを活用します。

### プロセスの概要

1. **メモリの割り当て**
* `mach_vm_allocate()`を使用して共有用のメモリを割り当てます。
* 割り当てた領域のために`xpc_shmem_create()`を使用して`OS_xpc_shmem`オブジェクトを作成します。
2. **リモートプロセスでの共有メモリの作成**
* リモートプロセス内で`OS_xpc_shmem`オブジェクトのためにメモリを割り当てます（`remote_malloc`）。
* ローカルテンプレートオブジェクトをコピーします。埋め込まれたMach送信権のオフセット`0x18`の修正がまだ必要です。
3. **Machメモリエントリの修正**
* `thread_set_special_port()`を使用して送信権を挿入し、リモートエントリの名前で`0x18`フィールドを上書きします。
4. **最終化**
* リモートオブジェクトを検証し、`xpc_shmem_remote()`へのリモート呼び出しでマッピングします。

## 5. 完全な制御の達成

任意の実行と共有メモリのバックチャネルが利用可能になると、ターゲットプロセスを効果的に所有します：

* **任意のメモリR/W** — ローカルと共有領域間で`memcpy()`を使用します。
* **8引数以上の関数呼び出し** — arm64呼び出し規約に従って、スタックに追加の引数を配置します。
* **Machポートの転送** — 確立されたポートを介してMachメッセージ内で権利を渡します。
* **ファイルディスクリプタの転送** — ファイルポートを活用します（*triple_fetch*を参照）。

これらすべては、再利用を容易にするために[`threadexec`](https://github.com/bazad/threadexec)ライブラリにラップされています。

---

## 6. Apple Silicon (arm64e) のニュアンス

Apple Siliconデバイス（arm64e）では、**ポインタ認証コード（PAC）**がすべての戻りアドレスと多くの関数ポインタを保護します。*既存のコードを再利用する*スレッドハイジャック技術は、`lr`/`pc`内の元の値がすでに有効なPAC署名を持っているため、引き続き機能します。攻撃者が制御するメモリにジャンプしようとすると問題が発生します：

1. ターゲット内に実行可能なメモリを割り当てます（リモート`mach_vm_allocate` + `mprotect(PROT_EXEC)`）。
2. ペイロードをコピーします。
3. *リモート*プロセス内でポインタに署名します：
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. ハイジャックされたスレッド状態で `pc = ptr` を設定します。

または、既存のガジェット/関数をチェーンしてPAC準拠を維持します（従来のROP）。

## 7. 検出とエンドポイントセキュリティによる強化

**EndpointSecurity (ES)** フレームワークは、ディフェンダーがスレッドインジェクションの試行を観察またはブロックできるカーネルイベントを公開します：

* `ES_EVENT_TYPE_AUTH_GET_TASK` – プロセスが別のタスクのポートを要求したときに発火します（例：`task_for_pid()`）。
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – 異なるタスクでスレッドが作成されるたびに発生します。
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE`（macOS 14 Sonomaで追加） – 既存のスレッドのレジスタ操作を示します。

リモートスレッドイベントを印刷する最小限のSwiftクライアント：
```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
(_, msg) in
if let evt = msg.remoteThreadCreate {
print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
}
}
RunLoop.main.run()
```
**osquery** ≥ 5.8を使用したクエリ:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Hardened-runtime considerations

アプリケーションを `com.apple.security.get-task-allow` 権限なしで配布することで、非ルート攻撃者がそのタスクポートを取得するのを防ぎます。システム整合性保護（SIP）は多くのAppleバイナリへのアクセスをブロックしますが、サードパーティ製ソフトウェアは明示的にオプトアウトする必要があります。

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Ventura/SonomaでのPAC対応スレッドハイジャックを示すコンパクトなPoC |
| `remote_thread_es` | 2024 | `REMOTE_THREAD_CREATE`イベントを表示するためにいくつかのEDRベンダーによって使用されるEndpointSecurityヘルパー |

> これらのプロジェクトのソースコードを読むことは、macOS 13/14で導入されたAPIの変更を理解し、Intel ↔ Apple Silicon間での互換性を保つのに役立ちます。

## References

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [https://github.com/rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine)
- [https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
