# 内核竞态条件利用：通过 Object Manager 慢路径放大窗口

{{#include ../../banners/hacktricks-training.md}}

## 为什么扩展竞态窗口很重要

许多 Windows 内核 LPE 遵循经典模式 `check_state(); NtOpenX("name"); privileged_action();`。在现代硬件上，冷启动的 `NtOpenEvent`/`NtOpenSection` 对短名称的解析大约只需 ~2 µs，几乎不给攻击者在安全操作发生前翻转被检查状态的时间。通过故意让 Object Manager Namespace (OMNS) 在第 2 步的查找耗时达到数十微秒，攻击者就能在无需成千上万次尝试的情况下稳定赢得原本不可靠的竞态。

## Object Manager 查找内部原理概述

* **OMNS structure** – 名称如 `\BaseNamedObjects\Foo` 按目录逐级解析。每个组件都会导致内核查找/打开一个 *Object Directory* 并进行 Unicode 字符串比较。路径中可能会经过符号链接（例如驱动器字母）。
* **UNICODE_STRING limit** – OM 路径承载在 `UNICODE_STRING` 中，其 `Length` 是一个 16 位值。绝对上限为 65 535 字节（32 767 个 UTF-16 码点）。有了像 `\BaseNamedObjects\` 这样的前缀，攻击者仍然可以控制大约 ≈32 000 个字符。
* **Attacker prerequisites** – 任何用户都可以在可写目录（如 `\BaseNamedObjects`）下创建对象。当易受攻击的代码使用该目录内的名称，或遵循落在那里 的符号链接时，攻击者无需特殊权限即可控制查找性能。

## Slowdown primitive #1 – Single maximal component

解析一个组件的成本大致与其长度呈线性关系，因为内核必须对父目录中的每一项执行 Unicode 比较。在名称为 32 kB 的事件上，会立即把 `NtOpenEvent` 的延迟从大约 ~2 µs 提高到 ~35 µs（测试平台：Windows 11 24H2，Snapdragon X Elite）。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*实用说明*

- 你可以使用任何命名的内核对象（events, sections, semaphores…）来达到长度限制。
- Symbolic links 或 reparse points 可以将一个短的“victim”名称指向这个巨型组件，从而透明地应用 slowdown。
- 因为一切都存在于 user-writable namespaces，payload 可在标准用户完整性级别下工作。

## Slowdown primitive #2 – Deep recursive directories

一个更激进的变体会分配成千上万目录的链（`\BaseNamedObjects\A\A\...\X`）。每一跳都会触发目录解析逻辑（ACL checks, hash lookups, reference counting），所以每级的延迟高于单次字符串比较。使用约16 000级（受相同的 `UNICODE_STRING` 大小限制），实测时间超过了由长单个组件达到的 35 µs 门槛。
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

* 如果父目录开始拒绝重复项，请在每一级交替使用字符（`A/B/C/...`）。
* 保留一个 handle array，以便在利用后能干净地删除该链，避免污染命名空间。

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses（分钟而非微秒）

Object directories 支持 **shadow directories**（回退查找）和用于条目的分桶哈希表。滥用两者并利用 64-component symbolic-link reparse 限制，可以在不超出 `UNICODE_STRING` 长度的情况下成倍增加延迟：

1. 在 `\BaseNamedObjects` 下创建两个目录，例如 `A`（shadow）和 `A\A`（target）。使用第一个作为 shadow directory 创建第二个（`NtCreateDirectoryObjectEx`），这样在 `A` 中找不到的查找会回退到 `A\A`。
2. 在每个目录中填充数千个落在同一哈希桶的 **colliding names**（例如改变尾部数字但保持相同的 `RtlHashUnicodeString` 值）。查找现在退化为在单个目录内的 O(n) 线性扫描。
3. 构建大约 63 个 **object manager symbolic links** 的链，这些链接反复重新解析到长的 `A\A\…` 后缀，从而耗尽 reparse 预算。每次重新解析都会从头重新开始解析，乘数地增加冲突成本。
4. 当每个目录存在 16 000 个冲突时，最终组件的查找（`...\\0`）在 Windows 11 上现在需要 **分钟** 级别的时间，这为 one-shot kernel LPEs 提供了几乎可以保证的竞态获胜机会。
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*为什么重要*: 持续数分钟的性能下降会把一次性的基于竞争的 LPEs 变为确定性的利用。

## 测量你的竞态窗口

在你的 exploit 中嵌入一个快速的测试程序，以测量窗口在目标硬件上变得有多大。下面的代码片段将打开目标对象 `iterations` 次，并使用 `QueryPerformanceCounter` 返回每次打开的平均开销。
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
这些结果直接用于指导你的竞态编排策略（例如，需要的工作线程数量、休眠间隔、以及需要多早翻转共享状态）。

## 利用流程

1. **Locate the vulnerable open** – 通过符号、ETW、hypervisor tracing 或逆向追踪内核路径，直到你找到一个 `NtOpen*`/`ObOpenObjectByName` 调用，该调用遍历攻击者可控的名称或位于用户可写目录的符号链接。
2. **Replace that name with a slow path**
- 在 `\BaseNamedObjects`（或另一个可写的 OM 根）下创建长组件或目录链。
- 创建一个符号链接，使内核期望的名称现在解析到慢路径。你可以将易受攻击的驱动的目录查找指向你的结构，而无需触及原始目标。
3. **Trigger the race**
- 线程 A（受害者）执行易受攻击的代码并在慢查找中阻塞。
- 线程 B（攻击者）在线程 A 被占用时翻转受保护的状态（例如，交换文件句柄、重写符号链接、切换对象安全性）。
- 当线程 A 恢复并执行特权操作时，会观察到陈旧状态并执行被攻击者控制的操作。
4. **Clean up** – 删除目录链和符号链接，以避免留下可疑遗迹或破坏合法的 IPC 使用者。

## 操作注意事项

- **Combine primitives** – 你可以在目录链的*每一级*使用长名称以获得更高延迟，直到耗尽 `UNICODE_STRING` 大小。
- **One-shot bugs** – 扩展的时间窗口（几十微秒到几分钟）使“single trigger”漏洞在配合 CPU affinity pinning 或 hypervisor-assisted preemption 时变得现实可行。
- **Side effects** – 这种减速仅影响恶意路径，因此整体系统性能不受影响；防御方很少会注意到，除非他们监控命名空间增长。
- **Cleanup** – 保留对你创建的每个目录/对象的句柄，以便之后调用 `NtMakeTemporaryObject`/`NtClose`。否则，无界的目录链可能在重启后仍然存在。

## 防御说明

- 依赖命名对象的内核代码应在 open *之后* 重新验证安全敏感状态，或在检查之前获取引用（以弥合 TOCTOU 缝隙）。
- 在取消引用用户可控名称之前，对 OM 路径深度/长度强制上限。拒绝过长的名称会迫使攻击者回到微秒级的时间窗口。
- 对 object manager 命名空间的增长进行检测（ETW `Microsoft-Windows-Kernel-Object`），以发现 `\BaseNamedObjects` 下可疑的数千组件链。

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
