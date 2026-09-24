# Windows Kernel Rootkits 和 DKOM

{{#include ../../banners/hacktricks-training.md}}

## 范围

一个 compromise 后 implant 可以将已签名的 kernel driver 作为服务加载，并通过 `IRP_MJ_DEVICE_CONTROL` 暴露 user-mode control plane。Driver signing 只能证明 Windows 接受该 image；它并不能保证 IOCTL authorization、memory operations、callbacks 或 hooks 是安全的。某个经过分析的 rootkit 在正常运行期间使用了三个 handlers，但还暴露了数十个额外的 post-exploitation primitives，因此 reverse engineering 必须覆盖完整的 dispatcher，而不能只分析 malware trace 中观察到的请求。<sup>[[1]](#references)</sup>

## Signed-driver 和 IOCTL triage

从 `DriverEntry` 开始，记录 device objects 和 DOS symbolic links，定位 `MajorFunction[IRP_MJ_DEVICE_CONTROL]` routine，并映射所有能够到达 handler 的 comparison/table entry。将 user mode 打开的名称与 driver 实际创建的名称进行交叉核对：某个观察到的链路打开了 `\\.\msagent`，而其 driver 创建了 `\Device\ToolTool` 和 `\DosDevices\ToolTool`。这种不匹配可能表明存在另一个 sample/configuration、缺失的 setup logic，或分析不一致。<sup>[[1]](#references)</sup>

在重建 input structure 之前，先 decode 每个 control code。<sup>[[1]](#references)</sup>
```python
def decode_ioctl(code):
return {
"device_type": code >> 16,
"access": (code >> 14) & 3,
"function": (code >> 2) & 0xfff,
"method": code & 3,
}

for code in (0x2220F0, 0x222120, 0x2221E0):
print(hex(code), decode_ioctl(code))
```
这三个代码分别解码为 `FILE_DEVICE_UNKNOWN`、`FILE_ANY_ACCESS` 和 `METHOD_BUFFERED`。这**不能**证明非特权调用者可以访问它们：还需要检查设备 DACL、创建/打开分发逻辑、每个请求的调用者检查、预期缓冲区长度、嵌入式指针、PID 生命周期处理，以及处理程序是否信任调用者提供的 PID 或标志。<sup>[[1]](#references)</sup>

当 implant 只使用一部分命令时，应按 primitive 对剩余处理程序进行分组，而不是将它们视为死代码。单个 multifunction driver 暴露了以下所有类别：<sup>[[1]](#references)</sup>

- **控制/配置：**切换 rootkit 状态；添加、移除、查询或清除受保护的路径、进程和 C2 地址。
- **进程操纵：**终止 PID，解除其 image 映射，使用 `NtCreateThreadEx` 注入，隐藏/恢复进程或 user module，以及移除 PPL 保护。
- **Kernel 操纵：**从链表中解除已加载 driver 的链接，枚举/禁用/恢复 notification callback，手动映射另一个 driver，以及写入任意 kernel 地址。
- **对象操纵：**删除/解密文件，以及创建或修改 registry value。

## Trusted-process exemptions

一种有用的设计模式是使用一个注册 PID 加 **trusted** 标志的 IOCTL。随后，文件、registry、进程和线程 filter 都会查询同一个 trust 表：不受信任的工具会收到经过过滤的枚举结果、降低的 handle 权限或 `STATUS_ACCESS_DENIED`，而 implant 仍可以更新自身隐藏的对象。应将其视为授权边界，并验证条目在进程退出或 PID 重用后如何进行身份验证、同步和移除。<sup>[[1]](#references)</sup>

Rootkit 可以将策略持久化在 `REG_MULTI_SZ` value 中，并将文件、目录、registry-key、registry-value、ignored-image、protected-image 和 hidden-image 列表编译到 AVL tree 中。在分析期间，跟踪这些共享 tree 的每个读取者和写入者；即使函数名称已被移除，这也能关联 registry 配置、IOCTL、callback 和 filtering logic。<sup>[[1]](#references)</sup>

## DKOM 进程和 module 隐藏

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks` 的 offset 会因 Windows build 而变化。具有版本容错能力的 rootkit 可以测试已知候选 offset，然后扫描 `EPROCESS`，寻找一个自洽的 `LIST_ENTRY`，其 neighbors 会指回该候选位置。它会保留发现的 offset，通过重新连接其 neighbors 的 `Flink`/`Blink` 来隐藏进程，并保存状态以便之后重新链接该 entry。进程仍会继续运行，但会从遍历 active-process list 的 enumerator 中消失。<sup>[[1]](#references)</sup>

这是 **DKOM**，不是终止进程。检测应将基于 list 的结果与独立证据进行比较，例如 pool/object scan、thread ownership、handle table、scheduler artifact 和 kernel memory inspection。一个在 scan 中可见、但不在 canonical list 中的进程，比单独依赖任一视图更有意义。<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

等效的 module-hiding primitive 会在 `PsLoadedModuleList` 中找到目标 entry，并修改相邻的 `Flink`/`Blink` 指针。该 driver 仍然处于 mapped 且可执行状态，但基于 list 的 module query 会将其省略。将 loader list 与可执行的 kernel mapping、pool tag、device/driver object、service key、callback address，以及指向未列出 image 的 dispatch pointer 进行比较。<sup>[[1]](#references)</sup>

## 基于 Callback 的保护和隐藏

Rootkit 可以将 documented callback framework 与 DKOM 和 hook 结合起来：<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` 针对 `PsProcessType` 和 `PsThreadType` 的 pre-operation handler，会在不受信任的调用者打开受保护目标时，移除用于终止、VM 访问、duplicate 或 thread 操纵的权限。记录 callback altitude，并将每个 callback address 解析到其所属 module。
- `PsSetCreateProcessNotifyRoutineEx` 和 `PsSetLoadImageNotifyRoutine` 会在进程和 image 出现时维护 protected/ignored/hidden process 状态；一次性的进程遍历可以补充注册之前就已存在的 object。
- filesystem minifilter 会拒绝访问已配置的路径。异常实现可能会创建自己的 `Instances` key，动态选择 altitude，并在 `FltRegisterFilter` 报告冲突时递增并重试。
- `CmRegisterCallbackEx` routine 可以从 enumeration 中隐藏受保护的名称，并拒绝直接 open、rename、set 或 delete 操作，同时对已注册的 trusted process 进行豁免。

关联 `ObRegisterCallbacks` registration、registry-callback altitude、`fltmc filters` 输出、service `Instances` key 和 callback address。如果正常工具正在被过滤，请从 offline memory image 或其他 trusted acquisition layer 中检查这些结构。<sup>[[1]](#references)</sup>

## Nsiproxy 结果过滤

Network concealment 可以针对 `\Driver\Nsiproxy`：使用 `ObReferenceObjectByName` 获取 driver object，保存 handler pointer，将其替换为 wrapper，并在 user mode 接收返回结果之前，移除与 IOCTL 管理的 C2 list 匹配的 IPv4 record。依赖经过过滤的 NSI data 的 application 可能不再显示该 connection，即使 traffic 仍然存在。<sup>[[1]](#references)</sup>

将 host connection view 与 packet capture、WFP/ETW telemetry 和 kernel-memory network object 进行比较。同时检查 `Nsiproxy` dispatch/handler pointer，并确认每个 pointer 都解析到预期的 signed module 内；指向未列出 mapping 的 pointer 可能将 network filtering 与 `PsLoadedModuleList` DKOM 关联起来。<sup>[[1]](#references)</sup>

## 调查清单

最强的信号是不同 layer 之间存在不一致，而不是某个 filename 或 hash。关联以下内容：<sup>[[1]](#references)</sup>

1. Kernel-service creation，以及一个其 certificate age、publisher 或 path 与已安装 product 不一致的 signed driver。
2. Device creation、DOS link 和 IOCTL traffic，包括 user mode 与 kernel device name 不匹配的情况。
3. 一次 PID registration request，随后其他 process 无法 open、enumerate、modify 或 delete 相同 object。
4. Object/registry/process/image callback、minifilter instance 和 hook 的 address 不属于正常 enumerated driver。
5. 基于 list 与基于 scan 的 process、module、callback 和 network inventory 之间的差异。

## References

- [1] [Kaspersky Securelist - HoneyMyte 使用 Signed Windows Kernel Rootkit 增强 CoolClient](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
