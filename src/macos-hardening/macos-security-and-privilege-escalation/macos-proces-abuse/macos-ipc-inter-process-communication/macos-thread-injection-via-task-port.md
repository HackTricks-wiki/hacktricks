# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## 0. Modern task_for_pid Hardening (macOS 14.4+ / 15.x)

Apple quietly tightened `task_for_pid()` semantics in macOS 14.4 (Sonoma) and kept those guard rails in Sequoia betas: when a non-entitled process touches a protected task port, the kernel now throws an `EXC_GUARD` with the message `Process used task_for_pid()` and immediately kills the caller. Practically this means you can no longer probe arbitrary processes for a hijackable thread without either:

* running inside the same security context (matching `com.apple.security.get-task-allow` entitlement and hardened-runtime profile) or
* arranging for the target to gift you a send right through another channel (XPC, shared Mach service, etc.).

For lab work you can still opt into the legacy behaviour by relaxing AMFI and the new guard checks through NVRAM boot-args (requires full disk access + reboot):

```bash
sudo nvram boot-args="-arm64e_preview_abi amfi_get_out_of_my_way=1 thid_should_crash=0 tss_should_crash=0"
```

The extra flags re-enable the arm64e preview ABI, turn off several task-signing checks, and prevent the guard exception helpers (`thid_should_crash`, `tss_should_crash`) from panic-killing your injector. Only do this on disposable research hosts and remember to clear the boot-args afterwards (`sudo nvram -d boot-args`) before going back to production targets.

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Initially, the `task_threads()` function is invoked on the task port to obtain a thread list from the remote task. A thread is selected for hijacking. This approach diverges from conventional code-injection methods as creating a new remote thread is prohibited due to the mitigation that blocks `thread_create_running()`.

To control the thread, `thread_suspend()` is called, halting its execution.

The only operations permitted on the remote thread involve **stopping** and **starting** it and **retrieving**/**modifying** its register values. Remote function calls are initiated by setting registers `x0` to `x7` to the **arguments**, configuring `pc` to target the desired function, and resuming the thread. Ensuring the thread does not crash after the return necessitates detection of the return.

One strategy involves registering an **exception handler** for the remote thread using `thread_set_exception_ports()`, setting the `lr` register to an invalid address before the function call. This triggers an exception post-function execution, sending a message to the exception port, enabling state inspection of the thread to recover the return value. Alternatively, as adopted from Ian Beer’s *triple_fetch* exploit, `lr` is set to loop infinitely; the thread’s registers are then continuously monitored until `pc` points to that instruction.

## 2. Mach ports for communication

The subsequent phase involves establishing Mach ports to facilitate communication with the remote thread. These ports are instrumental in transferring arbitrary send/receive rights between tasks.

For bidirectional communication, two Mach receive rights are created: one in the local and the other in the remote task. Subsequently, a send right for each port is transferred to the counterpart task, enabling message exchange.

Focusing on the local port, the receive right is held by the local task. The port is created with `mach_port_allocate()`. The challenge lies in transferring a send right to this port into the remote task.

A strategy involves leveraging `thread_set_special_port()` to place a send right to the local port in the remote thread’s `THREAD_KERNEL_PORT`. Then, the remote thread is instructed to call `mach_thread_self()` to retrieve the send right.

For the remote port, the process is essentially reversed. The remote thread is directed to generate a Mach port via `mach_reply_port()` (as `mach_port_allocate()` is unsuitable due to its return mechanism). Upon port creation, `mach_port_insert_right()` is invoked in the remote thread to establish a send right. This right is then stashed in the kernel using `thread_set_special_port()`. Back in the local task, `thread_get_special_port()` is used on the remote thread to acquire a send right to the newly allocated Mach port in the remote task.

Completion of these steps results in the establishment of Mach ports, laying the groundwork for bidirectional communication.

## 3. Basic Memory Read/Write Primitives

In this section, the focus is on utilizing the execute primitive to establish basic memory read/write primitives. These initial steps are crucial for gaining more control over the remote process, though the primitives at this stage won't serve many purposes. Soon, they will be upgraded to more advanced versions.

### Memory reading and writing using the execute primitive

The goal is to perform memory reading and writing using specific functions. For **reading memory**:

```c
uint64_t read_func(uint64_t *address) {
    return *address;
}
```

For **writing memory**:

```c
void write_func(uint64_t *address, uint64_t value) {
    *address = value;
}
```

These functions correspond to the following assembly:

```
_read_func:
    ldr x0, [x0]
    ret
_write_func:
    str x1, [x0]
    ret
```

### Identifying suitable functions

A scan of common libraries revealed appropriate candidates for these operations:

1. **Reading memory — `property_getName()`** (libobjc):

```c
const char *property_getName(objc_property_t prop) {
    return prop->name;
}
```

2. **Writing memory — `_xpc_int64_set_value()`** (libxpc):

```c
__xpc_int64_set_value:
    str x1, [x0, #0x18]
    ret
```

To perform a 64-bit write at an arbitrary address:

```c
_xpc_int64_set_value(address - 0x18, value);
```

With these primitives established, the stage is set for creating shared memory, marking a significant progression in controlling the remote process.

## 4. Shared Memory Setup

The objective is to establish shared memory between local and remote tasks, simplifying data transfer and facilitating the calling of functions with multiple arguments. The approach leverages `libxpc` and its `OS_xpc_shmem` object type, which is built upon Mach memory entries.

### Process overview

1. **Memory allocation**
   * Allocate memory for sharing using `mach_vm_allocate()`.  
   * Use `xpc_shmem_create()` to create an `OS_xpc_shmem` object for the allocated region.
2. **Creating shared memory in the remote process**
   * Allocate memory for the `OS_xpc_shmem` object in the remote process (`remote_malloc`).  
   * Copy the local template object; fix-up of the embedded Mach send right at offset `0x18` is still required.
3. **Correcting the Mach memory entry**
   * Insert a send right with `thread_set_special_port()` and overwrite the `0x18` field with the remote entry’s name.
4. **Finalising**
   * Validate the remote object and map it with a remote call to `xpc_shmem_remote()`.

## 5. Achieving Full Control

Once arbitrary execution and a shared-memory back-channel are available you effectively own the target process:

* **Arbitrary memory R/W** — use `memcpy()` between local & shared regions.  
* **Function calls with > 8 args** — place the extra arguments on the stack following the arm64 calling convention.  
* **Mach port transfer** — pass rights in Mach messages via the established ports.  
* **File-descriptor transfer** — leverage fileports (see *triple_fetch*).

All of this is wrapped in the [`threadexec`](https://github.com/bazad/threadexec) library for easy re-use.

---

## 6. Apple Silicon (arm64e) Nuances

On Apple Silicon devices (arm64e) **Pointer Authentication Codes (PAC)** protect all return addresses and many function pointers. Thread-hijacking techniques that *reuse existing code* continue to work because the original values in `lr`/`pc` already carry valid PAC signatures. Problems arise when you try to jump to attacker-controlled memory:

1. Allocate executable memory inside the target (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Copy your payload.
3. Inside the *remote* process sign the pointer:

```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```

4. Set `pc = ptr` in the hijacked thread state.

Alternatively, stay PAC-compliant by chaining existing gadgets/functions (traditional ROP).

### Tracking PAC bypass CVEs (2024+)

Keep tabs on CL-style vulnerabilities that downgrade PAC requirements. For instance, CVE-2024-40815 (patched in Ventura 13.6.8 and Sonoma 14.6 on 29 July 2024) is a dyld race condition that lets an attacker with arbitrary R/W bypass pointer authentication entirely. On unpatched hosts this bug turns any memory disclosure + write primitive into a PAC-strip primitive, meaning you can drop signed return addresses without calling `ptrauth_sign_unauthenticated()` first. When targeting high-value systems, check their patch level before assuming your PAC-aware shellcode will survive.

## 7. Detection & Hardening with EndpointSecurity

The **EndpointSecurity (ES)** framework exposes kernel events that allow defenders to observe or block thread-injection attempts:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – fired when a process requests another task’s port (e.g. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – emitted whenever a thread is created in a *different* task.
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (added in macOS 14 Sonoma) – indicates register manipulation of an existing thread.

Minimal Swift client that prints remote-thread events:

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

Querying with **osquery** ≥ 5.8:

```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```

### Hardened-runtime considerations

Distributing your application **without** the `com.apple.security.get-task-allow` entitlement prevents non-root attackers from obtaining its task-port. System Integrity Protection (SIP) still blocks access to many Apple binaries, but third-party software must opt-out explicitly.

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Compact PoC that demonstrates PAC-aware thread hijacking on Ventura/Sonoma |
| `remote_thread_es` | 2024 | EndpointSecurity helper used by several EDR vendors to surface `REMOTE_THREAD_CREATE` events |

> Reading these projects’ source code is useful to understand API changes introduced in macOS 13/14 and to stay compatible across Intel ↔ Apple Silicon.

## References

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [https://github.com/rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine)
- [https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)
- [https://unsafe.sh/go-179561.html](https://unsafe.sh/go-179561.html)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-40815](https://nvd.nist.gov/vuln/detail/CVE-2024-40815)

{{#include ../../../../banners/hacktricks-training.md}}