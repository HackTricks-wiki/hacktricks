# 通过 Object Manager 慢路径 利用内核竞争条件

{{#include ../../banners/hacktricks-training.md}}

## 为什么拉长竞争窗口很重要

许多 Windows 内核 LPE 遵循经典模式 `check_state(); NtOpenX("name"); privileged_action();`。在现代硬件上，冷启动的 `NtOpenEvent`/`NtOpenSection` 对短名称的解析大约需要 2 µs，几乎没有时间在安全操作发生前切换被检查的状态。通过故意让 Object Manager Namespace (OMNS) 在第 2 步的查找耗时数十微秒，攻击者就能获得足够的时间稳定地赢得本来不可靠的竞争，而无需成千上万次尝试。

## 对象管理器查找内部机制概述

* **OMNS structure** – 像 `\BaseNamedObjects\Foo` 这样的名称按目录逐级解析。每个组件都会导致内核查找/打开一个 *Object Directory* 并比较 Unicode 字符串。路径上可能会遍历符号链接（例如盘符）。
* **UNICODE_STRING limit** – OM 路径被放在一个 `UNICODE_STRING` 中，其 `Length` 是一个 16 位值。绝对上限是 65 535 字节（32 767 个 UTF-16 码点）。带上诸如 `\BaseNamedObjects\` 的前缀后，攻击者仍可控制约 ≈32 000 个字符。
* **Attacker prerequisites** – 任何用户都可以在可写目录（例如 `\BaseNamedObjects`）下创建对象。当易受攻击的代码使用位于其中的名称，或跟随落在那里 的符号链接时，攻击者在没有特殊权限的情况下即可控制查找性能。

## Slowdown primitive #1 – 单个最大组件

解析一个组件的成本大致与其长度呈线性关系，因为内核必须对父目录中的每个条目执行 Unicode 比较。创建一个名称为 32 kB 的事件会立即将 `NtOpenEvent` 的延迟从约 2 µs 提高到约 35 µs（Windows 11 24H2，Snapdragon X Elite 测试平台）。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*实用说明*

- 你可以通过使用任何命名的内核对象（events、sections、semaphores…）来触及长度限制。
- Symbolic links 或 reparse points 可以将一个短的“victim”名称指向该巨大的组件，从而透明地施加 slowdown。
- 因为一切都存在于 user-writable namespaces，payload 可以在 standard user integrity level 下运行。

## Slowdown primitive #2 – 深度递归目录

一种更激进的变体会分配数千个目录的链（`\BaseNamedObjects\A\A\...\X`）。每一次跳转都会触发目录解析逻辑（ACL checks、hash lookups、reference counting），因此每级的延迟高于单次字符串比较。当达到大约 16 000 层（受相同的 `UNICODE_STRING` 大小限制）时，实测时间超过了由长单组件实现的 35 µs 门槛。
```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
dirs.emplace_back(CreateDirectory(L"A", last_dir));
last_dir = dirs.back().get();
if ((i % 500) == 0) {
auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
printf("%d,%f\n", i + 1, result);
}
}
```
提示：

* 如果父目录开始拒绝重复项，请按层级交替字符 (`A/B/C/...`)。
* 保留一个 handle array，以便在利用后干净地删除该链，避免污染命名空间。

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories 支持 **shadow directories**（回退查找）和针对条目的分桶哈希表。滥用这两者以及 64-component symbolic-link reparse limit，可以在不超过 `UNICODE_STRING` 长度的情况下倍增延迟：

1. 在 `\BaseNamedObjects` 下创建两个目录，例如 `A`（shadow）和 `A\A`（目标）。使用第一个作为 shadow directory 创建第二个（`NtCreateDirectoryObjectEx`），这样在 `A` 中未找到的查找会回退到 `A\A`。
2. 将每个目录填充成千上万的 **colliding names**，使它们落在相同的哈希桶中（例如，改变尾部数字但保持相同的 `RtlHashUnicodeString` 值）。现在查找会退化为在单个目录内的 O(n) 线性扫描。
3. 构建大约 63 个 **object manager symbolic links** 链，反复 reparse 到长的 `A\A\…` 后缀，从而消耗 reparse 预算。每次 reparse 都从顶部重新开始解析，成倍增加冲突成本。
4. 当每个目录存在 16 000 个冲突时，最终组件的查找（`...\\0`）在 Windows 11 上现在需要 **分钟**，这几乎可以保证为 one-shot kernel LPEs 提供竞态胜利。
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*为什么重要*: 分钟级的延迟会将一次性基于 race 的 LPE 变成确定性的 exploit。

### 2025 复测说明与现成工具

- James Forshaw 重新发布了该技术，并在 Windows 11 24H2 (ARM64) 上更新了时序数据。Baseline opens 仍约为 ~2 µs；一个 32 kB 组件会将其提高到约 ~35 µs，且 shadow-dir + collision + 63-reparse chains 仍可将其拉长到约 ~3 minutes，证明这些 primitives 在当前构建中仍然可用。Source code and perf harness 在更新后的 Project Zero 帖子中。
- 你可以使用公开的 `symboliclink-testing-tools` 包来脚本化设置：用 `CreateObjectDirectory.exe` 生成 shadow/target 对，用 `NativeSymlink.exe` 在循环中发出 63-hop 链。这样可以避免手写 `NtCreate*` wrappers 并保持 ACLs 一致。

## 测量你的 race 窗口

在你的 exploit 中嵌入一个简短的 harness 来测量在受害者硬件上窗口会变得多大。下面的片段会对目标对象打开 `iterations` 次，并使用 `QueryPerformanceCounter` 返回每次打开的平均耗时。
```cpp
static double RunTest(const std::wstring name, int iterations,
std::wstring create_name = L"", HANDLE root = nullptr) {
if (create_name.empty()) {
create_name = name;
}
ScopedHandle event_handle = CreateEvent(create_name, root);
ObjectAttributes obja(name);
std::vector<ScopedHandle> handles;
Timer timer;
for (int i = 0; i < iterations; ++i) {
HANDLE open_handle;
Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
handles.emplace_back(open_handle);
}
return timer.GetTime(iterations);
}
```
The results feed directly into your race orchestration strategy (e.g., number of worker threads needed, sleep intervals, how early you need to flip the shared state).

## Exploitation workflow

1. **Locate the vulnerable open** – 追踪内核路径（通过 symbols、ETW、hypervisor tracing，或 reversing），直到找到一个对攻击者可控名称或位于用户可写目录中的符号链接进行遍历的 `NtOpen*`/`ObOpenObjectByName` 调用。
2. **Replace that name with a slow path**
- 在 `\BaseNamedObjects`（或另一个可写的 OM root）下创建长组件或目录链。
- 创建一个符号链接，使内核期望的名称现在解析到慢路径。你可以在不触碰原始目标的情况下，将易受攻击驱动的目录查找指向你的结构。
3. **Trigger the race**
- Thread A（受害线程）执行易受攻击的代码并在慢查找内被阻塞。
- Thread B（攻击者）在 Thread A 被占用时翻转受保护的状态（例如，交换文件句柄、重写符号链接、切换对象安全性）。
- 当 Thread A 恢复并执行特权操作时，它观察到陈旧状态并执行攻击者控制的操作。
4. **Clean up** – 删除目录链和符号链接以避免留下可疑痕迹或破坏合法的 IPC 用户。

## Operational considerations

- **Combine primitives** – 你可以在目录链的每一层使用一个长名称，以获得更高的延迟，直到耗尽 `UNICODE_STRING` 大小为止。
- **One-shot bugs** – 扩展后的窗口（从几十微秒到数分钟）使得“单触发”漏洞在与 CPU affinity pinning 或 hypervisor-assisted preemption 配合时变得现实可行。
- **Side effects** – 慢速路径只影响恶意路径，因此总体系统性能保持不受影响；除非防御方监控命名空间增长，否则很少会注意到这一点。
- **Cleanup** – 保持对你创建的每个目录/对象的句柄，以便之后调用 `NtMakeTemporaryObject`/`NtClose`。否则无限制的目录链可能会在重启后继续存在。
- **File-system races** – 如果易受攻击的路径最终通过 NTFS 解析，你可以在 OM slowdown 运行时在后备文件上叠加一个 Oplock（例如，同一工具包中的 `SetOpLock.exe`），在不改变 OM 图的情况下再冻结消费者数毫秒。

## Defensive notes

- 依赖命名对象的内核代码应在 open 之后重新验证与安全相关的状态，或在检查之前先获取引用（在 TOCTOU 缝隙上采取补救）。
- 在取消引用用户控制的名称之前强制对 OM 路径深度/长度施加上限。拒绝过长的名称会迫使攻击者回到微秒级窗口。
- 对对象管理器命名空间增长进行检测（ETW `Microsoft-Windows-Kernel-Object`），以发现 `\BaseNamedObjects` 下可疑的数千组件链。

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
