# 通过 Object Manager 慢速路径利用 Kernel Race Condition

{{#include ../../banners/hacktricks-training.md}}

## 为什么扩大 race window 很重要

许多 Windows kernel LPE 都遵循经典模式 `check_state(); NtOpenX("name"); privileged_action();`。在现代硬件上，冷启动的 `NtOpenEvent`/`NtOpenSection` 只需约 2 µs 即可解析短名称，几乎没有时间在安全操作发生前翻转已检查的状态。通过有意迫使第 2 步中的 Object Manager Namespace (OMNS) 查找耗时数十微秒，攻击者便能获得足够时间，稳定赢得原本容易失败的 race，而无需尝试数千次。<sup>[[1]](#references)</sup>

## Object Manager 查找内部机制简介

* **OMNS 结构** – `\BaseNamedObjects\Foo` 等名称会逐目录解析。每个组件都会使 kernel 查找或打开一个 *Object Directory*，并比较 Unicode 字符串。沿途可能会遍历 symbolic links（例如驱动器号）。
* **UNICODE_STRING 限制** – OM 路径存储在 `UNICODE_STRING` 中，其 `Length` 是一个 16 位值。绝对上限为 65 535 字节（32 767 个 UTF-16 codepoint）。加上 `\BaseNamedObjects\` 等前缀后，攻击者仍可控制约 32 000 个字符。
* **攻击者前提条件** – 任何用户都可以在 `\BaseNamedObjects` 等可写目录下创建对象。当易受攻击的代码使用其中的名称，或跟随一个最终指向此处的 symbolic link 时，攻击者无需特殊权限即可控制查找性能。<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – 单个最大长度组件

解析一个组件的成本大致与其长度呈线性关系，因为 kernel 必须针对父目录中的每个条目执行 Unicode 比较。在 Windows 11 24H2（Snapdragon X Elite 测试平台）上，创建一个名称长度为 32 kB 的 event，可立即将 `NtOpenEvent` 延迟从约 2 µs 提高到约 35 µs。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*实践要点*

- 使用任何 named kernel object（events、sections、semaphores……）都可以达到长度限制。
- Symbolic links 或 reparse points 可以将一个较短的“victim”名称指向这个超大的组件，从而透明地应用 slowdown。
- 由于所有内容都位于用户可写的 namespaces 中，payload 可以在 standard user integrity level 下运行。<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – 深度递归目录

一种更激进的变体会分配由数千个目录组成的链（`\BaseNamedObjects\A\A\...\X`）。每一跳都会触发目录解析逻辑（ACL 检查、哈希查找、引用计数），因此每层的延迟都高于单次字符串比较。在约 16,000 层时（受相同的 `UNICODE_STRING` 大小限制），实测耗时超过了长单一组件所达到的 35 µs barrier。
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

* 如果父目录开始拒绝重复项，请按层级交替使用字符（`A/B/C/...`）。
* 保留一个句柄数组，以便在 exploitation 后干净地删除整个链，避免污染命名空间。<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories 支持 **shadow directories**（回退查找）以及用于条目的分桶哈希表。结合滥用这两者，再利用 64 组件的 symbolic-link reparse 限制，可以在不超出 `UNICODE_STRING` 长度的情况下大幅增加 slowdown：

1. 在 `\BaseNamedObjects` 下创建两个目录，例如 `A`（shadow）和 `A\A`（target）。使用第一个目录作为 shadow directory，通过 `NtCreateDirectoryObjectEx` 创建第二个目录，使得在 `A` 中未找到的查找会回退到 `A\A`。
2. 在每个目录中填充数千个会发生 **hash collisions** 的名称，使其落入同一个哈希桶（例如，在保持相同 `RtlHashUnicodeString` 值的同时改变末尾数字）。此时，查找会退化为单个目录内的 O(n) 线性扫描。
3. 构造一条约 63 个 **object manager symbolic links** 组成的链，使其反复 reparse 到较长的 `A\A\…` 后缀，从而消耗 reparse 预算。每次 reparse 都会从顶层重新开始解析，进一步放大 collision 成本。
4. 当每个目录中存在 16 000 个 collisions 时，对最终组件（`...\\0`）的查找在 Windows 11 上现在需要 **minutes**，从而为 one-shot kernel LPE 提供实际上几乎必胜的 race。
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*重要性*: 持续数分钟的 slowdown 可将基于 one-shot race 的 LPE 转变为 deterministic exploits。<sup>[[1]](#references)</sup>

### 2025 年复测说明与现成 tooling

- James Forshaw 在 Windows 11 24H2（ARM64）上重新发布了该 technique，并更新了 timing。Baseline opens 仍约为 2 µs；32 kB component 会将其提高到约 35 µs，而 shadow-dir + collision + 63-reparse chains 仍可达到约 3 分钟，确认这些 primitives 在当前 builds 上依然有效。Source code 和 perf harness 位于更新后的 Project Zero post 中。<sup>[[1]](#references)</sup>
- 你可以使用公开的 `symboliclink-testing-tools` bundle 编写 setup 脚本：使用 `CreateObjectDirectory.exe` 创建 shadow/target pair，并循环使用 `NativeSymlink.exe` 生成 63-hop chain。这可以避免手写 `NtCreate*` wrappers，并确保 ACLs 保持一致。<sup>[[2]](#references)</sup>

## 测量你的 race window

将一个快速 harness 嵌入你的 exploit，以测量 victim hardware 上 window 会扩大到多大。下面的 snippet 会打开 target object `iterations` 次，并使用 `QueryPerformanceCounter` 返回每次 open 的平均成本。<sup>[[1]](#references)</sup>
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
这些结果会直接影响你的 race orchestration strategy（例如所需 worker threads 的数量、sleep intervals，以及需要多早翻转 shared state）。

## Exploitation workflow

1. **定位 vulnerable open** – 通过 symbols、ETW、hypervisor tracing 或 reversing 跟踪 kernel path，直到找到一个 `NtOpen*`/`ObOpenObjectByName` 调用，该调用会遍历 attacker-controlled name，或遍历 user-writable directory 中的 symbolic link。
2. **将该 name 替换为 slow path**
- 在 `\BaseNamedObjects`（或其他 writable OM root）下创建长 component 或 directory chain。
- 创建一个 symbolic link，使 kernel 期望的 name 现在解析到 slow path。你可以将 vulnerable driver 的 directory lookup 指向自己的结构，而无需修改原始 target。
3. **触发 race**
- Thread A（victim）执行 vulnerable code，并在 slow lookup 内阻塞。
- Thread B（attacker）在 Thread A 被占用期间翻转 guarded state（例如交换 file handle、重写 symbolic link、切换 object security）。
- Thread A 恢复并执行 privileged action 时，会观察到 stale state，并执行 attacker-controlled operation。
4. **清理** – 删除 directory chain 和 symbolic links，以避免留下可疑 artifacts，或破坏合法的 IPC users。<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak) 作为 RoguePlanet（CVE-2026-50656）的 bypass 发布，展示了一种更广泛的 exploitation pattern：让 privileged scanner 对 logical file 的一种 representation 进行分类，然后在 remediation 使用它之前，同时修改其 bytes 和 namespace resolution。该 PoC 结合了 Cloud Files hydration TOCTOU、Object Manager shadow-directory fallback、CLFS-generated-name capture，以及 local administrative-share link，将 Defender cleanup 转化为 protected DLL write。<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Substitute content through Cloud Files hydration

将 attacker-writable directory 注册为 Cloud Files sync root，连接 `CF_CALLBACK_TYPE_FETCH_DATA` callback，并创建一个 advertised size 与 EICAR ZIP 等 deterministic detection trigger 匹配的 placeholder。第一次 fetch 返回 trigger 并翻转 callback state；之后的 fetch 返回 payload。在 scanner 对第一种 representation 完成分类后，获取 transfer key，并使用 payload-sized metadata 重新启动 hydration，然后强制 hydration 到 EOF。<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
如果 security boundary 的 scan、verdict 和 remediation 只引用 pathname 或 placeholder identity，则该边界会失效：这两者都无法保证后续 hydration 返回的是已检查过的字节。<sup>[[4]](#references)</sup>

### 2. 通过 shadow-directory fallback 切换 invariant path

使用 `NtCreateDirectoryObjectEx` 创建一个 target Object Manager directory 和第二个目录，并将 target handle 作为其 shadow/fallback directory 传入。在两个 resolution layer 中都放置一个同名的 `WD_SCAN` entry：visible entry 指向 normal working directory，而 fallback entry 指向 `\CLFS\??\<working-directory>`。只向 Defender 提供下面的 invariant path；在该操作处于活动状态时删除 visible link，会使同一个字符串回退到 CLFS-backed entry。<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
这不同于仅使用 shadow directories 来减慢 lookup：攻击者无需修改路径字符串，就能改变此前已接受路径的**含义**。<sup>[[4]](#references)</sup>

### 3. 捕获生成的名称并安装 filename-specific link

使用 `ReadDirectoryChangesW` 监控工作目录。在首次出现 `FILE_ACTION_ADDED` 时，移除可见的 `WD_SCAN` link，以激活 fallback lookup。捕获第二个生成的 filename，打开该 CLFS 相关文件，并使用 `LockFileEx` 锁定 `0..MAXLONGLONG` 范围。在 privileged operation 暂停期间，将可见目录中的 `WD_SCAN` 替换为真实的 Object Manager directory，并创建一个以观测到的 filename 命名的 child symbolic link（PoC 会去除其最后四个字符）。通过本地 SMB 将其指向受保护的 destination：<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
非特权进程本身无法写入该目标，但 Defender 的 SYSTEM 上下文可以遍历 loopback administrative share。将生成名称观测与 filename-specific Object Manager link 结合后，无需提前预测 remediation artifact。<sup>[[4]](#references)</sup>

### 4. Stabilize cleanup race 并触发 privileged loader

扫描前，PoC 会将有效 PE（`ntdll.dll`）存储到占位符的 `:stream` NTFS alternate data stream 中。重定向创建受保护的基础文件后，它会以执行权限打开 `phoneinfo.dll:stream`，并在 cleanup 恢复期间保持一个 `PAGE_EXECUTE_READ | SEC_IMAGE` mapping 存活；活动的 file/section objects 会在最终 race 期间限制删除或替换操作。重启的 hydration 此时返回 payload DLL，而不是 EICAR，因此受保护的基础文件包含攻击者控制的代码。<sup>[[4]](#references)</sup>

随后，通过在 `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` 下放置精心构造的 `Report.wer`，并通过 Task Scheduler COM API 调用 `\Microsoft\Windows\Windows Error Reporting\QueueReporting`，即可将受保护的写入转换为 SYSTEM 执行。在此 chain 中，privileged WER processing 会加载植入的 `C:\Windows\System32\phoneinfo.dll`；named-pipe connection 用作 payload execution signal。<sup>[[4]](#references)</sup>

### Detection pivots

有用的 correlations 比任何单个临时文件名都更加具体，并覆盖 chain 中的所有 namespace transitions：<sup>[[4]](#references)</sup>

- 新注册的 Cloud Files provider，随后在同一占位符上检测到 EICAR 和 `CF_OPERATION_TYPE_RESTART_HYDRATION`。
- 包含 `WD_TARGET_*`、`WD_SHADOW_*` 或 `WD_SCAN` 的 Object Manager paths，尤其是位于 `\\.\globalroot\BaseNamedObjects\Restricted\` 下的 scan path。
- 创建 CLFS file，随后对整个文件施加 exclusive lock，并由 privileged security process loopback 访问 `\\127.0.0.1\C$\Windows\System32\*.dll`。
- 创建 System32 DLL 及其 NTFS ADS，随后对该 stream 进行 `SEC_IMAGE` mapping。
- attacker-created WER queue entry，随后异常手动运行 `\Microsoft\Windows\Windows Error Reporting\QueueReporting`，并加载植入的 DLL。

## Operational considerations

- **Combine primitives** – 你可以在 directory chain 的*每一层*使用长名称，在耗尽 `UNICODE_STRING` 大小之前获得更高的 latency。
- **One-shot bugs** – 扩大的窗口（数十微秒到数分钟）在配合 CPU affinity pinning 或 hypervisor-assisted preemption 时，使“single trigger” bugs 变得切实可行。
- **Side effects** – slowdown 只影响 malicious path，因此整体 system performance 不受影响；除非 defenders 监控 namespace growth，否则很少会注意到。
- **Cleanup** – 保留对所创建的每个 directory/object 的 handles，以便之后调用 `NtMakeTemporaryObject`/`NtClose`。否则，无界 directory chains 可能在 reboot 后仍然存在。
- **File-system races** – 如果 vulnerable path 最终通过 NTFS 解析，你可以在 OM slowdown 运行期间，对 backing file 叠加一个 Oplock（例如同一 toolkit 中的 `SetOpLock.exe`），在不修改 OM graph 的情况下将 consumer 冻结额外数毫秒。<sup>[[2]](#references)</sup>

## Defensive notes

- 依赖 named objects 的 kernel code 应在 open 之后重新验证 security-sensitive state，或在 check 之前获取 reference（弥合 TOCTOU gap）。
- 在 dereferencing user-controlled names 之前，对 OM path 的 depth/length 强制设置上限。拒绝过长名称会迫使 attackers 回到微秒级窗口。
- 对 Object Manager namespace growth 进行 instrumentation（ETW `Microsoft-Windows-Kernel-Object`），以检测 `\BaseNamedObjects` 下可疑的数千组件 chains。

## References

- [1] [Project Zero – Windows Exploitation Techniques：通过 Path Lookups 赢得 Race Conditions](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
