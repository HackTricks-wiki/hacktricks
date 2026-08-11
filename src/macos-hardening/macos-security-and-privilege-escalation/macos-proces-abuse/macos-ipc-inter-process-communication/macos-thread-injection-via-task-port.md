# task portを介したmacOS Thread Injection

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

まず、`task_threads()` 関数を task port に対して呼び出し、remote task から thread list を取得します。Hijacking 対象の thread を1つ選択します。この手法は、`thread_create_running()` をブロックする mitigation により新しい remote thread の作成が禁止されているため、従来の code-injection 手法とは異なります。<sup>[[1]](#references)</sup>

thread を制御するため、`thread_suspend()` を呼び出してその実行を停止します。<sup>[[1]](#references)</sup>

remote thread に対して許可されている操作は、**停止**と**開始**、および register 値の**取得**/**変更**のみです。remote function call は、register `x0` から `x7` に**引数**を設定し、`pc` を対象の function に設定してから thread を再開することで開始します。return 後に thread が crash しないようにするには、return を検出する必要があります。<sup>[[1]](#references)</sup>

1つの方法は、`thread_set_exception_ports()` を使用して remote thread に **exception handler** を登録し、function call の前に `lr` register を無効なアドレスに設定することです。これにより function 実行後に exception が発生し、exception port に message が送信されます。その結果、thread の state を検査して return value を取得できます。別の方法として、Ian Beer の *triple_fetch* exploit から採用された手法では、`lr` を無限 loop に設定します。その後、`pc` がその命令を指すまで thread の registers を継続的に監視します。<sup>[[1]](#references)</sup>

## 2. 通信用の Mach ports

次の段階では、remote thread との通信を可能にする Mach ports を確立します。これらの ports は、task 間で任意の send/receive rights を転送するために使用されます。<sup>[[1]](#references)</sup>

双方向通信を行うため、2つの Mach receive rights を作成します。1つは local task に、もう1つは remote task に作成します。その後、各 port の send right を相手側の task に転送し、message の交換を可能にします。<sup>[[1]](#references)</sup>

local port に注目すると、receive right は local task が保持します。port は `mach_port_allocate()` で作成します。課題は、この port への send right を remote task に転送することです。<sup>[[1]](#references)</sup>

1つの方法は、`thread_set_special_port()` を利用して local port への send right を remote thread の `THREAD_KERNEL_PORT` に配置することです。その後、remote thread に `mach_thread_self()` を呼び出させて send right を取得します。<sup>[[1]](#references)</sup>

remote port では、処理は基本的に逆になります。remote thread に `mach_reply_port()` を使用して Mach port を生成させます（`mach_port_allocate()` は return mechanism の都合上、適していません）。port が作成されたら、remote thread 内で `mach_port_insert_right()` を呼び出して send right を確立します。この right は `thread_set_special_port()` を使用して kernel に保存されます。local task に戻り、remote thread に対して `thread_get_special_port()` を使用し、remote task で新たに割り当てられた Mach port への send right を取得します。<sup>[[1]](#references)</sup>

これらの手順が完了すると Mach ports が確立され、双方向通信の基盤が整います。<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

このセクションでは、execute primitive を利用して基本的な memory read/write primitives を確立する方法に焦点を当てます。これらの初期手順は remote process をより強く制御するために重要ですが、この段階の primitives はまだ多くの用途には使えません。まもなく、より高度な versions に upgrade されます。<sup>[[1]](#references)</sup>

### execute primitive を使用した Memory reading and writing

目的は、特定の functions を使用して memory の読み取りと書き込みを行うことです。**memory の読み取り**には:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
メモリへの書き込み:
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

一般的なライブラリをスキャンした結果、これらの操作に適した候補が見つかりました。<sup>[[1]](#references)</sup>

1. **メモリの読み取り — `property_getName()`**（libobjc）：
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
任意のアドレスに64ビット書き込みを実行するには:
```c
_xpc_int64_set_value(address - 0x18, value);
```
これらのプリミティブが確立されたことで、shared memoryを作成する段階が整い、remote processの制御が大きく前進します。<sup>[[1]](#references)</sup>

## 4. Shared Memory Setup

目的はlocal taskとremote taskの間にshared memoryを確立し、データ転送を簡略化するとともに、複数の引数を持つ関数の呼び出しを容易にすることです。このアプローチでは`libxpc`と、その`OS_xpc_shmem` object typeを利用します。これはMach memory entriesを基盤としています。<sup>[[1]](#references)</sup>

### Process overview

1. **Memory allocation**
* `mach_vm_allocate()`を使用して共有用のmemoryをallocateします。
* `xpc_shmem_create()`を使用して、allocateしたregion用の`OS_xpc_shmem` objectを作成します。
2. **Creating shared memory in the remote process**
* remote process内で`OS_xpc_shmem` object用のmemoryをallocateします（`remote_malloc`）。
* local template objectをcopyします。ただし、offset `0x18`に埋め込まれたMach send rightのfix-upは引き続き必要です。
3. **Correcting the Mach memory entry**
* `thread_set_special_port()`でsend rightをinsertし、`0x18` fieldをremote entryのnameでoverwriteします。
4. **Finalising**
* remote objectをvalidateし、remote callで`xpc_shmem_remote()`を使用してmapします。

## 5. Achieving Full Control

arbitrary executionとshared-memory back-channelが利用可能になると、実質的にtarget processを完全に掌握できます。<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — local regionとshared regionの間で`memcpy()`を使用します。
* **Function calls with > 8 args** — arm64 calling conventionに従い、追加の引数をstack上に配置します。
* **Mach port transfer** — 確立済みのportを介して、Mach messageでrightsを渡します。
* **File-descriptor transfer** — fileportsを利用します（*triple_fetch*を参照）。

これらはすべて、簡単に再利用できるよう[`threadexec`](https://github.com/bazad/threadexec) libraryにまとめられています。

---

## 6. Apple Silicon (arm64e) Nuances

Apple Silicon devices（arm64e）では、**Pointer Authentication Codes (PAC)**がすべてのreturn addressと多数のfunction pointerを保護します。既存のcodeを*reuse*するThread-hijacking techniqueは、`lr`/`pc`内の元のvalueに有効なPAC signatureがすでに含まれているため、引き続き機能します。問題が発生するのは、attacker-controlled memoryへjumpしようとする場合です。

1. target内でexecutable memoryをallocateします（remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`）。
2. payloadをcopyします。
3. *remote* process内でpointerにsignします。
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. ハイジャックされた thread state で `pc = ptr` を設定します。

あるいは、既存の gadgets/functions をチェーンして（traditional ROP）、PAC-compliant のままにします。

## 7. Detection & Hardening with EndpointSecurity

**EndpointSecurity (ES)** framework は、defender が thread-injection の試行を監視またはブロックできる kernel events を公開します。

* `ES_EVENT_TYPE_AUTH_GET_TASK` – process が別の task の port を要求したとき（例：`task_for_pid()`）に発生します。
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – *異なる task* 内で thread が作成されるたびに発行されます。<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (macOS 14 Sonoma で追加) – 既存の thread の register manipulation を示します。

remote-thread events を出力する最小限の Swift client:
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
**osquery** ≥ 5.8 を使用したクエリ:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Hardened-runtimeに関する考慮事項

`com.apple.security.get-task-allow` entitlement なしでアプリケーションを配布すると、non-root attackers がその task-port を取得することを防止できます。System Integrity Protection (SIP) は依然として多くの Apple binaries へのアクセスをブロックしますが、third-party software は明示的に opt-out する必要があります。

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | 備考 |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Ventura/Sonoma で PAC-aware thread hijacking を実証するコンパクトな PoC<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | 複数の EDR vendors が `REMOTE_THREAD_CREATE` events を検出するために使用する EndpointSecurity helper |

> これらのプロジェクトの source code を読むことは、macOS 13/14 で導入された API changes を理解し、Intel ↔ Apple Silicon 間の互換性を維持するうえで役立ちます。

## References

- [1] [task_threads()を使用した platform binary restrictions の回避 - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)
{{#include ../../../../banners/hacktricks-training.md}}
