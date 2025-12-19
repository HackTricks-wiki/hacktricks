# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## 为什么拉长 race 窗口很重要

许多 Windows kernel LPEs 遵循经典模式 `check_state(); NtOpenX("name"); privileged_action();`。在现代硬件上，冷启动的 `NtOpenEvent`/`NtOpenSection` 解析一个短名称大约需要 2 µs，几乎没有时间在安全操作发生前翻转被检查的状态。通过故意让 Object Manager Namespace (OMNS) 在第 2 步的查找耗时数十微秒，攻击者就能获得足够的时间稳定地赢得原本不可靠的 races，而不需要成千上万次尝试。

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Names such as `\BaseNamedObjects\Foo` are resolved directory-by-directory. Each component causes the kernel to find/open an *Object Directory* and compare Unicode strings. Symbolic links (e.g., drive letters) may be traversed en route.
* **UNICODE_STRING limit** – OM paths are carried inside a `UNICODE_STRING` whose `Length` is a 16-bit value. The absolute limit is 65 535 bytes (32 767 UTF-16 codepoints). With prefixes like `\BaseNamedObjects\`, an attacker still controls ≈32 000 characters.
* **Attacker prerequisites** – Any user can create objects underneath writable directories such as `\BaseNamedObjects`. When the vulnerable code uses a name inside, or follows a symbolic link that lands there, the attacker controls the lookup performance with no special privileges.

## Slowdown primitive #1 – Single maximal component

解析一个组件的开销大体上与其长度呈线性关系，因为内核必须针对父目录中的每个条目执行 Unicode 比较。在 Windows 11 24H2 (Snapdragon X Elite testbed) 上，创建一个 32 kB 长的事件名称会使 `NtOpenEvent` 的延迟从约 2 µs 立即增加到约 35 µs。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*实用说明*

- 你可以通过使用任意 named kernel object (events, sections, semaphores…) 来触发长度限制。
- Symbolic links 或 reparse points 可以将一个简短的“victim”名称指向这个巨大的组件，从而透明地施加 slowdown。
- 因为所有内容都存在于 user-writable namespaces，payload 可以从标准用户完整性级别运行。

## Slowdown primitive #2 – 深度递归目录

更激进的变体会分配一条由数千个目录组成的链（`\BaseNamedObjects\A\A\...\X`）。每次跳转都会触发 directory resolution logic (ACL checks, hash lookups, reference counting)，因此每一级的延迟高于单次字符串比较。使用约 16 000 级（受相同的 `UNICODE_STRING` 大小限制），经验计时超过了由长单一组件达到的 35 µs 阈值。
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

* 如果父目录开始拒绝重复项，按层级交替使用字符（`A/B/C/...`）。
* 保留一个 handle array，以便在 exploitation 后干净地删除链，避免污染 namespace。

## 测量你的竞态窗口

在你的 exploit 中嵌入一个快速 harness，以测量在受害者硬件上窗口变得有多大。下面的代码片段将打开目标对象 `iterations` 次，并使用 `QueryPerformanceCounter` 返回每次打开的平均开销。
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
这些结果直接影响你的竞态调度策略（例如所需的工作线程数、休眠间隔以及需要多早翻转共享状态）。

## 利用工作流程

1. **Locate the vulnerable open** – 追踪内核路径 (via symbols, ETW, hypervisor tracing, or reversing) 直到你发现一个会遍历攻击者可控名称或位于用户可写目录中的符号链接的 `NtOpen*`/`ObOpenObjectByName` 调用。
2. **Replace that name with a slow path**
- 在 `\BaseNamedObjects`（或另一个可写的 OM 根）下创建长组件或目录链。
- 创建一个符号链接，使内核期望的名称现在解析到慢路径。你可以将易受攻击的驱动的目录查找指向你的结构，而无需接触原始目标。
3. **Trigger the race**
- 线程 A（受害者）执行易受攻击的代码并在慢查找中阻塞。
- 线程 B（攻击者）在线程 A 占用时翻转被保护的状态（例如交换文件句柄、重写符号链接、切换对象安全设置）。
- 当线程 A 恢复并执行特权操作时，它会看到过时的状态并执行攻击者控制的操作。
4. **Clean up** – 删除目录链和符号链接，以避免留下可疑痕迹或破坏合法的 IPC 使用者。

## 操作注意事项

- **Combine primitives** – 你可以在目录链的每一层使用一个长名称（*每层*），以获得更高的延迟，直到耗尽 `UNICODE_STRING` 大小。
- **One-shot bugs** – 扩大的时间窗口（几十微秒）使“单次触发”漏洞在与 CPU affinity pinning 或 hypervisor-assisted preemption 配合时变得现实可利用。
- **Side effects** – 慢查找仅影响恶意路径，因此整体系统性能不受影响；除非防御方监控命名空间增长，否则很少能注意到。
- **Cleanup** – 保留对你创建的每个目录/对象的句柄，以便随后调用 `NtMakeTemporaryObject`/`NtClose`。否则无界的目录链可能会在重启后持续存在。

## 防御要点

- 依赖命名对象的内核代码应在 open 之后重新验证安全敏感状态，或在检查之前获取引用（以弥合 TOCTOU 缺口）。
- 在对用户可控名称进行取消引用之前，对 OM 路径深度/长度强制上限。拒绝过长的名称会把攻击者强制回到微秒级的窗口。
- 对 object manager 命名空间的增长进行监测（ETW `Microsoft-Windows-Kernel-Object`），以检测 `\BaseNamedObjects` 下可疑的数千组件链。

## 参考资料

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
