# Task port を介した macOS Thread Injection

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

まず、`task_threads()` 関数を task port に対して呼び出し、remote task から thread list を取得します。次に、Hijacking 対象の thread を選択します。`thread_create_running()` をブロックする mitigation により新しい remote thread の作成が禁止されているため、この手法は従来の code-injection 方法とは異なります。<sup>[1]</sup>

thread を制御するために、`thread_suspend()` を呼び出して実行を停止します。<sup>[1]</sup>

remote thread に対して許可される操作は、**停止**および**開始**、そして register 値の**取得**/**変更**のみです。Remote function call は、register `x0` から `x7` に**引数**を設定し、`pc` に目的の function を指定して、thread を再開することで開始されます。return 後に thread が crash しないようにするには、return の検出が必要です。<sup>[1]</sup>

1 つの方法は、`thread_set_exception_ports()` を使用して remote thread に **exception handler** を登録し、function call の前に `lr` register を無効なアドレスに設定することです。これにより function 実行後に exception が発生し、exception port に message が送信されるため、thread の state を調査して return value を回収できます。別の方法として、Ian Beer の *triple_fetch* exploit から採用された手法では、`lr` を無限 loop に設定します。その後、`pc` がその instruction を指すまで thread の register を継続的に監視します。<sup>[1]</sup>

## 2. 通信用の Mach ports

次の段階では、remote thread との communication を可能にする Mach ports を確立します。これらの ports は、task 間で任意の send/receive rights を転送するために使用されます。<sup>[1]</sup>

双方向 communication のために、2 つの Mach receive rights を作成します。1 つは local task に、もう 1 つは remote task に作成します。その後、各 port の send right を相手側の task に転送し、message exchange を可能にします。<sup>[1]</sup>

local port に注目すると、receive right は local task が保持します。この port は `mach_port_allocate()` で作成します。課題は、この port への send right を remote task に転送することです。<sup>[1]</sup>

1 つの方法は、`thread_set_special_port()` を利用して local port への send right を remote thread の `THREAD_KERNEL_PORT` に配置することです。その後、remote thread に `mach_thread_self()` を呼び出させて send right を取得します。<sup>[1]</sup>

remote port では、処理は基本的に逆になります。remote thread に `mach_reply_port()` を使用して Mach port を生成させます（`mach_port_allocate()` は return mechanism の都合上適していません）。port の作成後、remote thread 内で `mach_port_insert_right()` を呼び出して send right を確立します。この right は `thread_set_special_port()` を使用して kernel 内に一時保存されます。local task に戻り、remote thread に対して `thread_get_special_port()` を使用し、remote task に新しく割り当てられた Mach port への send right を取得します。<sup>[1]</sup>

これらの手順が完了すると Mach ports が確立され、双方向 communication の基盤が整います。<sup>[1]</sup>

## 3. Basic Memory Read/Write Primitives

この section では、execute primitive を利用して基本的な memory read/write primitives を確立することに焦点を当てます。これらの初期手順は remote process をより強力に制御するために重要ですが、この段階の primitives は多くの用途には使用できません。まもなく、より高度な versions に upgrade します。<sup>[1]</sup>

### execute primitive を使用した Memory reading and writing

目的は、特定の functions を使用して memory reading and writing を実行することです。**reading memory** の場合：
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

一般的なライブラリをスキャンした結果、これらの操作に適した候補が明らかになりました:<sup>[1]</sup>

1. **メモリの読み取り — `property_getName()`** (libobjc):
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
任意のアドレスに64-bit writeを実行するには:
```c
_xpc_int64_set_value(address - 0x18, value);
```
これらのプリミティブが確立されたことで、shared memory を作成する準備が整い、remote process の制御における重要な進展となります。<sup>[1]</sup>

## 4. Shared Memory Setup

目的は local task と remote task の間に shared memory を確立し、data transfer を簡略化するとともに、複数の引数を持つ function の呼び出しを容易にすることです。この手法では `libxpc` と、その `OS_xpc_shmem` object type を利用します。これは Mach memory entries を基盤としています。<sup>[1]</sup>

### Process overview

1. **Memory allocation**
* `mach_vm_allocate()` を使用して、sharing 用の memory を allocate します。
* `xpc_shmem_create()` を使用して、allocate した領域用の `OS_xpc_shmem` object を作成します。
2. **Creating shared memory in the remote process**
* remote process 内に `OS_xpc_shmem` object 用の memory を allocate します（`remote_malloc`）。
* local template object を copy します。ただし、offset `0x18` にある埋め込み Mach send right の fix-up は引き続き必要です。
3. **Correcting the Mach memory entry**
* `thread_set_special_port()` で send right を insert し、`0x18` field を remote entry の name で overwrite します。
4. **Finalising**
* remote call で `xpc_shmem_remote()` を呼び出し、remote object を validate して map します。

## 5. Achieving Full Control

arbitrary execution と shared-memory back-channel が利用可能になると、実質的に target process を完全に掌握できます。<sup>[1]</sup>

* **Arbitrary memory R/W** — local region と shared region の間で `memcpy()` を使用します。
* **Function calls with > 8 args** — arm64 calling convention に従い、追加の arguments を stack 上に配置します。
* **Mach port transfer** — 確立済みの ports を介して Mach messages 内で rights を渡します。
* **File-descriptor transfer** — fileports を利用します（*triple_fetch* を参照）。

これらはすべて [`threadexec`](https://github.com/bazad/threadexec) library にまとめられており、簡単に再利用できます。

---

## 6. Apple Silicon (arm64e) Nuances

Apple Silicon devices (arm64e) では、**Pointer Authentication Codes (PAC)** がすべての return addresses と多数の function pointers を保護します。既存の code を**再利用する** thread-hijacking techniques は、`lr`/`pc` 内の元の値にすでに有効な PAC signatures が付いているため、引き続き機能します。問題が発生するのは、attacker-controlled memory へ jump しようとする場合です。

1. target 内に executable memory を allocate します（remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`）。
2. payload を copy します。
3. *remote* process 内で pointer に sign を付けます。
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. hijacked thread state で `pc = ptr` を設定します。

または、既存の gadget/function をチェーンして（traditional ROP）、PAC-compliant のままにします。

## 7. EndpointSecurity による Detection と Hardening

**EndpointSecurity (ES)** framework は、defender が thread-injection の試行を監視またはブロックできる kernel event を公開します。

* `ES_EVENT_TYPE_AUTH_GET_TASK` – process が別の task の port（例：`task_for_pid()`）を要求したときに発生します。
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – *異なる task* に thread が作成されるたびに発行されます。<sup>[3]</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE`（macOS 14 Sonoma で追加）– 既存の thread の register 操作を示します。

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
**osquery** ≥ 5.8 でのクエリ実行:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Hardened-runtime に関する考慮事項

アプリケーションを `com.apple.security.get-task-allow` entitlement **なしで**配布すると、non-root attacker がその task-port を取得するのを防止できます。System Integrity Protection（SIP）は依然として多くの Apple binary へのアクセスをブロックしますが、third-party software では明示的に opt-out する必要があります。

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Ventura/Sonoma 上で PAC-aware thread hijacking を実証するコンパクトな PoC |
| `remote_thread_es` | 2024 | 複数の EDR vendor が `REMOTE_THREAD_CREATE` event を検出するために使用する EndpointSecurity helper |

> これらの project の source code を読むことは、macOS 13/14 で導入された API changes を理解し、Intel ↔ Apple Silicon 間で互換性を維持するうえで役立ちます。

## References

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
