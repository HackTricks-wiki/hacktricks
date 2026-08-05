# macOS Task port経由のThread Injection

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

最初に、`task_threads()` 関数をtask port上で呼び出し、remote taskからthread listを取得します。Hijackingするthreadを1つ選択します。`thread_create_running()` をブロックするmitigationにより、新しいremote threadの作成が禁止されているため、この方法は従来のcode-injection手法とは異なります。<sup>[[1]](#references)</sup>

threadを制御するために、`thread_suspend()` を呼び出して実行を停止します。<sup>[[1]](#references)</sup>

remote threadに対して許可されている操作は、**停止**および**開始**、そしてregister値の**取得**/**変更**のみです。Remote function callは、register `x0` から `x7` に**引数**を設定し、`pc` を目的のfunctionに設定して、threadを再開することで開始します。return後にthreadがcrashしないようにするには、returnを検出する必要があります。<sup>[[1]](#references)</sup>

1つの方法は、`thread_set_exception_ports()` を使用してremote threadに **exception handler** を登録し、function callの前に `lr` registerを無効なアドレスに設定することです。これによりfunction実行後にexceptionが発生し、exception portにmessageが送信されます。その結果、threadのstateを検査してreturn valueを回収できます。別の方法として、Ian Beerの *triple_fetch* exploitから採用された手法では、`lr` を無限loopに設定します。その後、threadのregisterを継続的に監視し、`pc` がその命令を指すまで待機します。<sup>[[1]](#references)</sup>

## 2. 通信用のMach ports

次の段階では、remote threadとの通信を可能にするMach portsを確立します。これらのportsは、任意のsend/receive rightsをtask間で転送するために使用されます。<sup>[[1]](#references)</sup>

双方向通信のために、2つのMach receive rightsを作成します。1つはlocal taskに、もう1つはremote taskに作成します。続いて、各portのsend rightを相手側のtaskに転送し、message交換を可能にします。<sup>[[1]](#references)</sup>

local portに注目すると、receive rightはlocal taskが保持します。portは `mach_port_allocate()` で作成します。課題は、このportへのsend rightをremote taskに転送することです。<sup>[[1]](#references)</sup>

1つの方法は、`thread_set_special_port()` を利用して、local portへのsend rightをremote threadの `THREAD_KERNEL_PORT` に配置することです。その後、remote threadに `mach_thread_self()` を呼び出させ、send rightを取得します。<sup>[[1]](#references)</sup>

remote portの場合、処理は基本的に逆になります。remote threadに `mach_reply_port()` でMach portを生成させます（returnの仕組み上、`mach_port_allocate()` は適していません）。portの作成後、remote thread内で `mach_port_insert_right()` を呼び出してsend rightを確立します。このrightは `thread_set_special_port()` を使用してkernel内にstashされます。local taskに戻り、remote threadに対して `thread_get_special_port()` を使用し、remote task内で新たに割り当てられたMach portへのsend rightを取得します。<sup>[[1]](#references)</sup>

これらの手順が完了するとMach portsが確立され、双方向通信の基盤が整います。<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

このセクションでは、execute primitiveを利用して基本的なmemory read/write primitivesを確立する方法に焦点を当てます。これらの初期手順はremote processをさらに制御するために重要ですが、この段階のprimitivesで実行できることは多くありません。まもなく、より高度なversionへupgradeします。<sup>[[1]](#references)</sup>

### execute primitiveを使用したMemory reading and writing

目的は、特定のfunctionを使用してmemoryのread/writeを実行することです。**reading memory** の場合:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
**メモリへの書き込みの場合:**
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
これらの関数は、以下のアセンブリに対応します：
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### 適切な関数の特定

一般的な library の scan により、これらの操作に適した候補が明らかになりました:<sup>[[1]](#references)</sup>

1. **memory の読み取り — `property_getName()`** (libobjc):
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
任意のアドレスに64ビット書き込みを実行するには：
```c
_xpc_int64_set_value(address - 0x18, value);
```
これらのプリミティブが確立されたことで、shared memory を作成する段階が整い、remote process の制御が大きく前進します。<sup>[[1]](#references)</sup>

## 4. Shared Memory Setup

目的は local task と remote task の間に shared memory を確立し、データ転送を簡素化するとともに、複数の引数を取る関数の呼び出しを可能にすることです。このアプローチでは、Mach memory entries を基盤とする `libxpc` と、その `OS_xpc_shmem` object type を利用します。<sup>[[1]](#references)</sup>

### Process overview

1. **Memory allocation**
* `mach_vm_allocate()` を使用して、共有用のメモリを確保します。
* `xpc_shmem_create()` を使用して、確保した領域の `OS_xpc_shmem` object を作成します。
2. **Creating shared memory in the remote process**
* remote process 内に `OS_xpc_shmem` object 用のメモリを確保します（`remote_malloc`）。
* local template object をコピーします。ただし、オフセット `0x18` にある組み込み Mach send right の fix-up が必要です。
3. **Correcting the Mach memory entry**
* `thread_set_special_port()` を使用して send right を挿入し、`0x18` フィールドを remote entry の name で上書きします。
4. **Finalising**
* remote object を検証し、remote call で `xpc_shmem_remote()` を呼び出して map します。

## 5. Achieving Full Control

arbitrary execution と shared-memory back-channel が利用可能になると、実質的に target process を完全に掌握できます。<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — local region と shared region の間で `memcpy()` を使用します。
* **Function calls with > 8 args** — arm64 calling convention に従い、追加の引数を stack に配置します。
* **Mach port transfer** — 確立した port を介して、Mach message 内で rights を渡します。
* **File-descriptor transfer** — fileports を利用します（*triple_fetch* を参照）。

これらはすべて、簡単に再利用できるよう [`threadexec`](https://github.com/bazad/threadexec) library にまとめられています。

---

## 6. Apple Silicon (arm64e) Nuances

Apple Silicon devices（arm64e）では、**Pointer Authentication Codes (PAC)** によって、すべての return address と多くの function pointer が保護されています。既存の code を*reuse*する Thread-hijacking techniques は、`lr`/`pc` 内の元の値がすでに有効な PAC signature を保持しているため、引き続き機能します。問題が発生するのは、attacker-controlled memory へ jump しようとする場合です。

1. target 内に executable memory を確保します（remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`）。
2. payload をコピーします。
3. *remote* process 内で pointer に sign を付与します。
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. 乗っ取った thread state で `pc = ptr` を設定します。

あるいは、既存の gadget/function をチェーンして（traditional ROP）、PAC-compliant な状態を維持します。

## 7. EndpointSecurity による Detection & Hardening

**EndpointSecurity (ES)** framework は、defender が thread-injection の試みを監視またはブロックできる kernel event を公開します。

* `ES_EVENT_TYPE_AUTH_GET_TASK` – process が別の task の port を要求したときに発生します（例: `task_for_pid()`）。
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – *異なる task* 内で thread が作成されるたびに発行されます。<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE`（macOS 14 Sonoma で追加）– 既存の thread の register manipulation を示します。

remote-thread event を出力する最小限の Swift client:
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
**osquery** ≥ 5.8 でのクエリ実行：
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Hardened-runtime に関する考慮事項

アプリケーションを `com.apple.security.get-task-allow` entitlement **なしで**配布すると、non-root 攻撃者がその task-port を取得するのを防止できます。System Integrity Protection (SIP) は依然として多くの Apple バイナリへのアクセスをブロックしますが、third-party ソフトウェアでは明示的な opt-out が必要です。

## 8. 最近の Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Ventura/Sonoma で PAC-aware thread hijacking を実証するコンパクトな PoC |
| `remote_thread_es` | 2024 | 複数の EDR ベンダーが `REMOTE_THREAD_CREATE` イベントを検出するために使用する EndpointSecurity helper |

> これらのプロジェクトの source code を読むと、macOS 13/14 で導入された API の変更を理解し、Intel ↔ Apple Silicon 間の互換性を維持するのに役立ちます。

## References

- [1] [task_threads() による platform binary restrictions の bypass - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
