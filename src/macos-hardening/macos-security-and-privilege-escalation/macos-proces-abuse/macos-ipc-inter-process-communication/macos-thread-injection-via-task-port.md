# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

まず、リモート task から thread リストを取得するため、task port に対して `task_threads()` 関数が呼び出されます。その後、Hijacking 対象の thread が選択されます。`thread_create_running()` をブロックする mitigation により、新しい remote thread の作成が禁止されているため、このアプローチは従来の code-injection 手法とは異なります。<sup>[[1]](#references)</sup>

thread を制御するため、`thread_suspend()` が呼び出され、その実行を停止します。<sup>[[1]](#references)</sup>

remote thread に対して許可されている操作は、**停止**と**開始**、およびレジスタ値の**取得**/**変更**のみです。Remote function call は、レジスタ `x0` から `x7` に**引数**を設定し、`pc` に目的の関数を指定して、thread を再開することで開始されます。return 後に thread が crash しないようにするには、return を検出する必要があります。<sup>[[1]](#references)</sup>

1 つの方法は、`thread_set_exception_ports()` を使用して remote thread に **exception handler** を登録し、function call の前に `lr` レジスタを無効なアドレスに設定することです。これにより、function 実行後に exception が発生し、exception port に message が送信されます。その結果、thread の state を検査して return value を取得できます。別の方法として、Ian Beer の *triple_fetch* exploit から採用された手法では、`lr` を無限 loop に設定します。その後、`pc` がその instruction を指すまで thread のレジスタを継続的に監視します。<sup>[[1]](#references)</sup>

## 2. Mach ports for communication

次の段階では、remote thread との communication を可能にする Mach ports を確立します。これらの ports は、task 間で任意の send/receive rights を転送するために使用されます。<sup>[[1]](#references)</sup>

双方向 communication のため、2 つの Mach receive rights を作成します。一方を local task に、もう一方を remote task に配置します。その後、各 port の send right を相手側の task に転送し、message exchange を可能にします。<sup>[[1]](#references)</sup>

local port に注目すると、receive right は local task が保持します。port は `mach_port_allocate()` で作成されます。課題は、この port への send right を remote task に転送することです。<sup>[[1]](#references)</sup>

1 つの方法は、`thread_set_special_port()` を利用して、local port への send right を remote thread の `THREAD_KERNEL_PORT` に配置することです。その後、remote thread に `mach_thread_self()` を呼び出させ、send right を取得します。<sup>[[1]](#references)</sup>

remote port では、処理は基本的に逆になります。remote thread に `mach_reply_port()` を介して Mach port を生成させます（return mechanism の関係上、`mach_port_allocate()` は適していません）。port の作成後、remote thread 内で `mach_port_insert_right()` を呼び出し、send right を確立します。この right は `thread_set_special_port()` を使用して kernel 内に保存されます。local task に戻り、remote thread に対して `thread_get_special_port()` を使用し、remote task に新たに割り当てられた Mach port への send right を取得します。<sup>[[1]](#references)</sup>

これらの手順が完了すると Mach ports が確立され、双方向 communication の基盤が整います。<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

このセクションでは、execute primitive を利用して基本的な memory read/write primitives を確立することに焦点を当てます。これらの初期手順は remote process をより強力に制御するために重要ですが、この段階の primitives は多くの用途には使えません。まもなく、より高度な versions に upgrade されます。<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

目的は、特定の functions を使用して memory reading と writing を実行することです。**reading memory** の場合:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
**メモリへの書き込み:**
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
これらの関数は、次のアセンブリに対応します。
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### 適切な関数の特定

一般的なライブラリをスキャンした結果、これらの操作に適した候補が明らかになりました:<sup>[[1]](#references)</sup>

1. **メモリの読み取り — `property_getName()`**（libobjc）:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **メモリへの書き込み — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
任意のアドレスに対して64ビット書き込みを実行するには：
```c
_xpc_int64_set_value(address - 0x18, value);
```
これらのプリミティブが確立されたことで、shared memory を作成する準備が整い、remote process の制御における重要な進展となります。<sup>[[1]](#references)</sup>

## 4. Shared Memory のセットアップ

目的は local task と remote task の間に shared memory を確立し、data transfer を簡略化するとともに、複数の引数を持つ function の呼び出しを容易にすることです。このアプローチでは `libxpc` と、その `OS_xpc_shmem` object type を利用します。これは Mach memory entries 上に構築されています。<sup>[[1]](#references)</sup>

### Process の概要

1. **Memory の割り当て**
* `mach_vm_allocate()` を使用して、sharing 用の memory を割り当てます。
* `xpc_shmem_create()` を使用して、割り当てた region 用の `OS_xpc_shmem` object を作成します。
2. **Remote process での shared memory の作成**
* Remote process 内に `OS_xpc_shmem` object 用の memory を割り当てます（`remote_malloc`）。
* Local template object をコピーします。ただし、offset `0x18` にある埋め込み Mach send right の fix-up が必要です。
3. **Mach memory entry の修正**
* `thread_set_special_port()` で send right を挿入し、`0x18` field を remote entry の name で上書きします。
4. **仕上げ**
* Remote object を検証し、remote call で `xpc_shmem_remote()` を呼び出して map します。

## 5. Full Control の実現

Arbitrary execution と shared-memory back-channel が利用可能になると、実質的に target process を完全に制御できます。<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — local region と shared region の間で `memcpy()` を使用します。
* **8 個を超える引数を使用した Function call** — arm64 calling convention に従い、追加の引数を stack 上に配置します。
* **Mach port transfer** — 確立済みの port を介して Mach message 内で rights を渡します。
* **File-descriptor transfer** — fileports を利用します（*triple_fetch* を参照）。

これらはすべて [`threadexec`](https://github.com/bazad/threadexec) library にまとめられており、簡単に再利用できます。

---

## 6. Apple Silicon (arm64e) の注意点

Apple Silicon device（arm64e）では、**Pointer Authentication Codes (PAC)** がすべての return address と多くの function pointer を保護します。既存の code を *reuse* する Thread-hijacking technique は、`lr`/`pc` 内の元の値に有効な PAC signature がすでに付与されているため、引き続き機能します。問題が発生するのは、attacker-controlled memory へ jump しようとした場合です。

1. Target 内に executable memory を割り当てます（remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`）。
2. Payload をコピーします。
3. *Remote* process 内で pointer に署名します。
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. 乗っ取った thread state で `pc = ptr` を設定します。

または、既存の gadget/function をチェーンして（traditional ROP）、PAC-compliant の状態を維持します。

## 7. EndpointSecurity による Detection & Hardening

**EndpointSecurity (ES)** framework は、defender が thread-injection attempts を監視または block できる kernel events を公開します。

* `ES_EVENT_TYPE_AUTH_GET_TASK` – process が別の task の port を要求したときに発生します（例：`task_for_pid()`）。
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – *異なる task* に thread が作成されるたびに発行されます。<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE`（macOS 14 Sonoma で追加）– 既存の thread に対する register manipulation を示します。

remote-thread events を表示する最小限の Swift client:
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
**osquery** ≥ 5.8 を使ったクエリ:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Hardened-runtime に関する考慮事項

アプリケーションを `com.apple.security.get-task-allow` entitlement なしで配布すると、non-root attacker がその task-port を取得できなくなります。System Integrity Protection (SIP) は依然として多くの Apple binaries へのアクセスをブロックしますが、third-party software では明示的に opt-out する必要があります。

## 8. 最近の Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Ventura/Sonoma 上で PAC-aware thread hijacking を実証するコンパクトな PoC<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | 複数の EDR vendors が `REMOTE_THREAD_CREATE` events を検出するために使用する EndpointSecurity helper |

> これらの projects の source code を読むことは、macOS 13/14 で導入された API changes を理解し、Intel ↔ Apple Silicon 間で互換性を維持するうえで役立ちます。

## References

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
