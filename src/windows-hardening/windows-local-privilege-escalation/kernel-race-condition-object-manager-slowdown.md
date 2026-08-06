# 通过 Object Manager Slow Paths 利用 Kernel Race Condition

{{#include ../../banners/hacktricks-training.md}}

## 为什么拉长 race window 很重要

许多 Windows kernel LPE 都遵循经典模式 `check_state(); NtOpenX("name"); privileged_action();`。在现代硬件上，cold `NtOpenEvent`/`NtOpenSection` 只需约 2 µs 即可解析短名称，因此几乎没有时间在 secure action 发生前翻转已检查的状态。通过有意迫使第 2 步中的 Object Manager Namespace (OMNS) lookup 耗时几十微秒，attacker 可以获得足够时间，从而稳定赢得原本不可靠的 race，而不需要尝试数千次。<sup>[[1]](#references)</sup>

## Object Manager lookup internals 简介

* **OMNS structure** – `\BaseNamedObjects\Foo` 等名称会按 directory 逐级解析。每个 component 都会使 kernel 查找或打开一个 *Object Directory*，并比较 Unicode strings。途中还可能遍历 symbolic links（例如 drive letters）。
* **UNICODE_STRING limit** – OM paths 存储在 `UNICODE_STRING` 中，其 `Length` 是一个 16-bit value。绝对上限为 65 535 bytes（32 767 个 UTF-16 codepoints）。即使扣除 `\BaseNamedObjects\` 等 prefixes，attacker 仍可控制约 32 000 个 characters。
* **Attacker prerequisites** – 任何 user 都可以在 `\BaseNamedObjects` 等 writable directories 下创建 objects。当 vulnerable code 使用其中的 name，或跟随一个最终指向该目录的 symbolic link 时，attacker 无需 special privileges 即可控制 lookup performance。<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

解析一个 component 的成本大致与其长度呈线性关系，因为 kernel 必须针对 parent directory 中的每个 entry 执行 Unicode comparison。创建一个名称长度为 32 kB 的 event，会立即将 Windows 11 24H2（Snapdragon X Elite testbed）上的 `NtOpenEvent` latency 从约 2 µs 提升至约 35 µs。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*实践注意事项*

- 使用任何命名 kernel object（events、sections、semaphores……）都可以达到长度限制。
- Symbolic links 或 reparse points 可以将一个较短的“victim”名称指向这个超大组件，从而透明地应用 slowdown。
- 由于所有内容都位于用户可写的命名空间中，因此 payload 可在标准用户完整性级别下运行。<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – 深层递归目录

更激进的变体会分配由数千个目录组成的链（`\BaseNamedObjects\A\A\...\X`）。每次跳转都会触发目录解析逻辑（ACL 检查、哈希查找、引用计数），因此每层的延迟都高于单次字符串比较。在约 16,000 层时（受相同 `UNICODE_STRING` 大小限制），实测耗时超过了长单组件所达到的 35 µs barrier。
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

* 如果父目录开始拒绝重复项，请按级别交替使用字符（`A/B/C/...`）。
* 保留一个句柄数组，这样在 exploitation 后可以干净地删除整个链，避免污染命名空间。<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories、hash collisions 与 symlink reparses（数分钟而非数微秒）

Object directories 支持 **shadow directories**（fallback lookups）以及用于条目的分桶 hash tables。结合利用这两者，再加上 64-component symbolic-link reparse limit，可以在不超过 `UNICODE_STRING` 长度的情况下成倍增加 slowdown：

1. 在 `\BaseNamedObjects` 下创建两个目录，例如 `A`（shadow）和 `A\A`（target）。使用第一个目录作为 shadow directory，通过 `NtCreateDirectoryObjectEx` 创建第二个目录，使得在 `A` 中未找到的 lookup 会回退到 `A\A`。
2. 向每个目录填充数千个落入同一 hash bucket 的 **colliding names**（例如改变末尾数字，同时保持相同的 `RtlHashUnicodeString` 值）。这样，lookup 会退化为单个目录内的 O(n) 线性扫描。
3. 构建一条约 63 个 **Object Manager symbolic links** 的链，使其反复 reparse 到较长的 `A\A\…` 后缀，从而消耗 reparse budget。每次 reparse 都会从顶层重新开始 parsing，使 collision cost 成倍增加。
4. 对最终 component（`...\\0`）的 lookup，在每个目录存在 16 000 个 collisions 时，在 Windows 11 上现在需要 **数分钟**，从而为 one-shot kernel LPE 提供实际上几乎必胜的 race。
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*重要性*: 持续数分钟的 slowdown 会将基于 one-shot race 的 LPE 转变为 deterministic exploits。<sup>[[1]](#references)</sup>

### 2025 retest notes & ready-made tooling

- James Forshaw 在 Windows 11 24H2 (ARM64) 上重新发布了该 technique，并更新了 timings。Baseline opens 仍约为 2 µs；32 kB component 会将其提升至约 35 µs，而 shadow-dir + collision + 63-reparse chains 仍可达到约 3 minutes，确认这些 primitives 在当前 builds 中依然有效。Source code 和 perf harness 位于更新后的 Project Zero post 中。<sup>[[1]](#references)</sup>
- 你可以使用公开的 `symboliclink-testing-tools` bundle 编写 setup 脚本：使用 `CreateObjectDirectory.exe` 创建 shadow/target pair，并循环调用 `NativeSymlink.exe` 生成 63-hop chain。这可以避免手写 `NtCreate*` wrappers，并保持 ACLs 一致。<sup>[[2]](#references)</sup>

## Measuring your race window

将一个快速 harness 嵌入 exploit，以测量 victim hardware 上 window 的大小。下面的 snippet 会使用 `QueryPerformanceCounter` 打开 target object `iterations` 次，并返回每次 open 的平均 cost。<sup>[[1]](#references)</sup>
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
这些结果会直接影响你的 race orchestration strategy（例如所需 worker thread 的数量、sleep 间隔，以及需要多早翻转 shared state）。

## Exploitation workflow

1. **Locate the vulnerable open** – 跟踪 kernel path（通过 symbols、ETW、hypervisor tracing 或 reversing），直到找到一个 `NtOpen*`/`ObOpenObjectByName` 调用，该调用会遍历 attacker-controlled name，或遍历 user-writable directory 中的 symbolic link。
2. **Replace that name with a slow path**
- 在 `\BaseNamedObjects`（或其他可写的 OM root）下创建长 component 或 directory chain。
- 创建一个 symbolic link，使 kernel 预期的 name 现在解析到 slow path。你可以将 vulnerable driver 的 directory lookup 指向你构造的结构，而不触碰原始 target。
3. **Trigger the race**
- Thread A（victim）执行 vulnerable code，并在 slow lookup 内阻塞。
- Thread B（attacker）在 Thread A 被占用期间翻转 guarded state（例如交换 file handle、重写 symbolic link、切换 object security）。
- Thread A 恢复并执行 privileged action 时，会看到 stale state，并执行 attacker-controlled operation。
4. **Clean up** – 删除 directory chain 和 symbolic link，避免留下可疑 artifacts，或破坏合法的 IPC users。<sup>[[1]](#references)</sup>

## Operational considerations

- **Combine primitives** – 你可以在 directory chain 的每一层使用一个长 name，以获得更高的 latency，直到耗尽 `UNICODE_STRING` 的 size。
- **One-shot bugs** – 扩大的 window（数十微秒到数分钟）结合 CPU affinity pinning 或 hypervisor-assisted preemption 后，可以让“single trigger” bugs 变得切实可行。
- **Side effects** – slowdown 只影响 malicious path，因此整体 system performance 不会受到影响；除非 defenders 监控 namespace growth，否则通常很难察觉。
- **Cleanup** – 保留对所创建的每个 directory/object 的 handles，以便之后调用 `NtMakeTemporaryObject`/`NtClose`。否则，无限制的 directory chains 可能会在 reboot 后继续存在。
- **File-system races** – 如果 vulnerable path 最终通过 NTFS 解析，可以在 backing file 上设置一个 Oplock（例如使用同一 toolkit 中的 `SetOpLock.exe`），同时运行 OM slowdown，使 consumer 额外冻结数毫秒，而无需修改 OM graph。<sup>[[2]](#references)</sup>

## Defensive notes

- 依赖 named objects 的 kernel code 应在 open 之后重新验证 security-sensitive state，或在检查之前获取 reference（从而弥合 TOCTOU gap）。
- 在 dereference user-controlled names 之前，对 OM path 的 depth/length 强制设置 upper bounds。拒绝过长的 names 会迫使 attackers 回到微秒级 window。
- 监控 object manager namespace growth（ETW `Microsoft-Windows-Kernel-Object`），以检测 `\BaseNamedObjects` 下可疑的数千 component chains。

## References

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
