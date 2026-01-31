# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## 为什么延长竞争窗口很重要

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. On modern hardware a cold `NtOpenEvent`/`NtOpenSection` resolves a short name in ~2 µs, leaving almost no time to flip the checked state before the secure action happens. By deliberately forcing the Object Manager Namespace (OMNS) lookup in step 2 to take tens of microseconds, the attacker gains enough time to consistently win otherwise flaky races without needing thousands of attempts.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Names such as `\BaseNamedObjects\Foo` are resolved directory-by-directory. Each component causes the kernel to find/open an *Object Directory* and compare Unicode strings. Symbolic links (e.g., drive letters) may be traversed en route.
* **UNICODE_STRING limit** – OM paths are carried inside a `UNICODE_STRING` whose `Length` is a 16-bit value. The absolute limit is 65 535 bytes (32 767 UTF-16 codepoints). With prefixes like `\BaseNamedObjects\`, an attacker still controls ≈32 000 characters.
* **Attacker prerequisites** – Any user can create objects underneath writable directories such as `\BaseNamedObjects`. When the vulnerable code uses a name inside, or follows a symbolic link that lands there, the attacker controls the lookup performance with no special privileges.

## Slowdown primitive #1 – Single maximal component

The cost of resolving a component is roughly linear with its length because the kernel must perform a Unicode comparison against every entry in the parent directory. Creating an event with a 32 kB-long name immediately increases the `NtOpenEvent` latency from ~2 µs to ~35 µs on Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*实用说明*

- 你可以使用任何命名的 kernel object（events、sections、semaphores…）触及长度上限。
- Symbolic links 或 reparse points 可以将短的 “victim” 名称指向这个巨大组件，从而透明地施加 slowdown。
- 由于所有内容都位于 user-writable namespaces 中，payload 可以在标准用户完整性级别下运行。

## Slowdown primitive #2 – Deep recursive directories

一个更激进的变体会分配由数千个目录组成的链 (`\BaseNamedObjects\A\A\...\X`)。每一级都会触发目录解析逻辑（ACL checks、hash lookups、reference counting），因此每层的延迟比单次字符串比较要高。使用约 16 000 层（受相同的 `UNICODE_STRING` 大小限制），实测时间超过了长单个组件所达到的 35 µs 阈值。
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

* 如果父目录开始拒绝重复项，按级别交替字符 (`A/B/C/...`)。
* 维护一个句柄数组，以便在利用后干净地删除链，避免污染命名空间。

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories 支持 **shadow directories**（回退查找）和条目的分桶哈希表。滥用这两者，再加上 64 组件的 symbolic-link reparse 限制，可以在不超过 `UNICODE_STRING` 长度的情况下成倍放大减速：

1. 在 `\BaseNamedObjects` 下创建两个目录，例如 `A`（shadow）和 `A\A`（target）。使用第一个作为 shadow directory 创建第二个（`NtCreateDirectoryObjectEx`），这样在 `A` 中未找到的查找会回落到 `A\A`。
2. 向每个目录填充数千个 **colliding names**，使它们落在同一哈希桶内（例如改变尾部数字但保持相同的 `RtlHashUnicodeString` 值）。查找现在在单个目录内退化为 O(n) 线性扫描。
3. 构建一个大约 63 个的 **object manager symbolic links** 链，反复将解析重定向到长的 `A\A\…` 后缀，从而耗尽 reparse 预算。每次 reparse 都会从头重新开始解析，成倍增加碰撞成本。
4. 当每个目录存在 16 000 个碰撞时，最终组件 (`...\\0`) 的查找在 Windows 11 上现在需要 **分钟**，为一次性 kernel LPE 提供几乎可保证的竞争胜利。
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Why it matters*: 持续数分钟的延迟会将 one-shot race-based LPEs 转变为确定性的 exploits。

## 测量你的竞态窗口

在你的 exploit 中嵌入一个简短的 harness，以测量该窗口在受害者硬件上的大小。下面的代码片段会打开目标对象 `iterations` 次，并使用 `QueryPerformanceCounter` 返回每次打开的平均开销。
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
这些结果会直接输入到你的竞态协调策略中（例如所需的工作线程数、睡眠间隔，以及需要多早翻转共享状态）。

## 利用流程

1. **定位易受攻击的打开操作** – 通过 symbols、ETW、hypervisor tracing 或 reversing 跟踪内核路径，直到你发现会遍历攻击者控制的名称或位于用户可写目录中的符号链接的 `NtOpen*`/`ObOpenObjectByName` 调用。
2. **用慢路径替换该名称**
- 在 `\BaseNamedObjects`（或另一个可写的 OM 根）下创建长组件或目录链。
- 创建一个符号链接，使内核期望的名称现在解析到慢路径。你可以将易受攻击驱动程序的目录查找指向你的结构，而无需触及原始目标。
3. **触发竞态**
- 线程 A（受害者）执行易受攻击的代码并在慢速查找中阻塞。
- 线程 B（攻击者）在线程 A 忙碌时翻转受保护状态（例如交换文件句柄、重写符号链接、切换对象安全性）。
- 当线程 A 恢复并执行特权操作时，它会观察到陈旧状态并执行由攻击者控制的操作。
4. **清理** – 删除目录链和符号链接，以避免留下可疑痕迹或破坏合法的 IPC 用户。

## 操作注意事项

- **组合原语** – 你可以在目录链的 *每层* 使用一个长名称以获得更高的延迟，直到耗尽 `UNICODE_STRING` 大小。
- **一次性漏洞** – 扩展后的窗口（从几十微秒到几分钟）使 “single trigger” 漏洞在配合 CPU affinity pinning 或 hypervisor-assisted preemption 时变得现实可行。
- **副作用** – 慢速只影响恶意路径，因此整体系统性能不受影响；除非监控命名空间增长，否则防御方很少会注意到。
- **清理** – 保留对你创建的每个目录/对象的句柄，以便之后调用 `NtMakeTemporaryObject`/`NtClose`。否则无限制的目录链可能会在重启后保留。

## 防御注意事项

- 依赖具名对象的内核代码应在打开 *之后* 重新验证安全敏感状态，或在检查之前获取引用（以闭合 TOCTOU 缺口）。
- 在对用户控制的名称进行解引用之前，对 OM 路径深度/长度实施上限。拒绝过长的名称会迫使攻击者回到微秒级的时间窗。
- 对 object manager 命名空间增长进行监控（ETW `Microsoft-Windows-Kernel-Object`），以检测 `\BaseNamedObjects` 下可疑的上千组件链。

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
