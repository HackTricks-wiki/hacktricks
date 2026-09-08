# 通过 Object Manager 慢速路径利用 Kernel Race Condition

{{#include ../../banners/hacktricks-training.md}}

## 为什么扩大 race window 很重要

许多 Windows kernel LPE 都遵循经典模式 `check_state(); NtOpenX("name"); privileged_action();`。在现代硬件上，冷启动的 `NtOpenEvent`/`NtOpenSection` 只需约 2 µs 即可解析短名称，几乎没有时间在安全操作发生前翻转已检查的状态。通过有意迫使第 2 步中的 Object Manager Namespace (OMNS) 查找耗时几十微秒，攻击者便能获得足够时间，从而稳定赢得原本不稳定的 race，而无需尝试数千次。<sup>[[1]](#references)</sup>

## Object Manager 查找内部机制简介

* **OMNS 结构** – `\BaseNamedObjects\Foo` 等名称会逐目录解析。每个组件都会导致 kernel 查找或打开一个 *Object Directory*，并比较 Unicode 字符串。在此过程中可能会遍历 Symbolic links（例如盘符）。
* **UNICODE_STRING 限制** – OM 路径存储在 `UNICODE_STRING` 中，其 `Length` 是一个 16 位值。绝对上限为 65 535 字节（32 767 个 UTF-16 codepoint）。使用 `\BaseNamedObjects\` 等前缀后，攻击者仍可控制约 32 000 个字符。
* **攻击者前提条件** – 任何用户都可以在 `\BaseNamedObjects` 等可写目录下创建 objects。当存在漏洞的代码使用其中的名称，或跟随最终指向该目录的 symbolic link 时，攻击者无需特殊权限即可控制查找性能。<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – 单个最大长度组件

解析组件的成本大致与其长度呈线性关系，因为 kernel 必须将其与父目录中的每个条目执行 Unicode 比较。在 Windows 11 24H2 上（Snapdragon X Elite testbed），创建一个名称长度为 32 kB 的 event，会立即将 `NtOpenEvent` 的延迟从约 2 µs 提高到约 35 µs。
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*实践注意事项*

- 你可以使用任何 named kernel object（events、sections、semaphores……）触及长度限制。
- Symbolic links 或 reparse points 可以将一个较短的“victim”名称指向这个巨型组件，从而透明地应用 slowdown。
- 由于所有内容都存在于用户可写的 namespaces 中，因此该 payload 可以从标准用户完整性级别运行。<sup>[[1]](#references)</sup>

## slowdown primitive #2 – 深层递归目录

一种更激进的变体会分配一条包含数千个目录的链（`\BaseNamedObjects\A\A\...\X`）。每一跳都会触发目录解析逻辑（ACL 检查、哈希查找、引用计数），因此每层的延迟都高于单次字符串比较。在约 16 000 层时（受相同的 `UNICODE_STRING` 大小限制），实测计时结果超过了长单一组件所达到的 35 µs 阈值。
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
* 保留一个 handle 数组，以便在 exploitation 后干净地删除整个链，避免污染 namespace。<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories、hash collisions 与 symlink reparses（从微秒级变为分钟级）

Object directories 支持 **shadow directories**（fallback lookups）以及用于存储条目的分桶 hash tables。结合滥用这两者，再利用 64-component symbolic-link reparse limit，可以在不超过 `UNICODE_STRING` 长度的情况下显著放大 slowdown：

1. 在 `\BaseNamedObjects` 下创建两个目录，例如 `A`（shadow）和 `A\A`（target）。使用第一个目录作为 shadow directory，通过 `NtCreateDirectoryObjectEx` 创建第二个目录，使得在 `A` 中未找到的 lookup 会回退到 `A\A`。
2. 为每个目录填充数千个会发生 **hash collisions** 的名称，使它们落入同一个 hash bucket（例如，在保持相同 `RtlHashUnicodeString` 值的同时改变末尾数字）。这样，lookup 会退化为单个目录内的 O(n) 线性扫描。
3. 构建一条约 63 个 **object manager symbolic links** 组成的链，反复 reparse 到较长的 `A\A\…` 后缀，从而消耗 reparse budget。每次 reparse 都会从顶层重新开始解析，进一步放大 collision cost。
4. 当每个目录存在 16 000 个 collisions 时，对最终 component（`...\\0`）的 lookup 在 Windows 11 上现在需要 **数分钟**，从而为 one-shot kernel LPE 提供实际上几乎必然的 race win。
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*重要性*: 持续数分钟的 slowdown 可将一次性 race-based LPEs 转化为确定性 exploits。<sup>[[1]](#references)</sup>

### 2025 retest notes & ready-made tooling

- James Forshaw 在 Windows 11 24H2（ARM64）上重新发布了该 technique，并更新了 timing。Baseline opens 仍约为 2 µs；32 kB component 会将其提升至约 35 µs，而 shadow-dir + collision + 63-reparse chains 仍可达到约 3 分钟，确认这些 primitives 在当前 builds 上依然有效。Source code 和 perf harness 位于更新后的 Project Zero post 中。<sup>[[1]](#references)</sup>
- 你可以使用公开的 `symboliclink-testing-tools` bundle 编写 setup script：使用 `CreateObjectDirectory.exe` 创建 shadow/target pair，并循环运行 `NativeSymlink.exe` 生成 63-hop chain。这样无需手写 `NtCreate*` wrappers，同时可保持 ACLs 一致。<sup>[[2]](#references)</sup>

## 测量你的 race window

在 exploit 中嵌入一个快速 harness，以测量该 window 在目标硬件上有多大。下面的 snippet 会打开 target object `iterations` 次，并使用 `QueryPerformanceCounter` 返回每次 open 的平均成本。<sup>[[1]](#references)</sup>
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
这些结果会直接影响你的 race orchestration strategy（例如所需的 worker threads 数量、sleep intervals，以及需要多早翻转 shared state）。

## Exploitation workflow

1. **定位存在漏洞的 open** – 通过 symbols、ETW、hypervisor tracing 或 reversing 跟踪 kernel path，直到找到一个 `NtOpen*`/`ObOpenObjectByName` 调用，该调用会遍历 attacker-controlled name，或遍历 user-writable directory 中的 symbolic link。
2. **将该 name 替换为 slow path**
- 在 `\BaseNamedObjects`（或其他 writable OM root）下创建 long component 或 directory chain。
- 创建一个 symbolic link，使 kernel 预期的 name 现在解析到 slow path。你可以将 vulnerable driver 的 directory lookup 指向自己的结构，而无需接触原始 target。
3. **触发 race**
- Thread A（victim）执行 vulnerable code，并在 slow lookup 内部阻塞。
- Thread B（attacker）在 Thread A 被占用期间翻转 guarded state（例如替换 file handle、重写 symbolic link 或切换 object security）。
- Thread A 恢复并执行 privileged action 时，会观察到 stale state，并执行 attacker-controlled operation。
4. **清理** – 删除 directory chain 和 symbolic links，避免留下可疑 artifacts 或破坏合法的 IPC users。<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak) 作为 RoguePlanet（CVE-2026-50656）的 bypass 发布，展示了一种更广泛的 exploitation pattern：让 privileged scanner 对 logical file 的一种 representation 进行分类，然后在 remediation 使用它之前，同时修改其 bytes 和 namespace resolution。该 PoC 结合了 Cloud Files hydration TOCTOU、Object Manager shadow-directory fallback、CLFS-generated-name capture，以及 local administrative-share link，将 Defender cleanup 转变为一次 protected DLL write。<sup>[[3]](#references)[[4]](#references)</sup>

### 1. 通过 Cloud Files hydration 替换 content

将 attacker-writable directory 注册为 Cloud Files sync root，连接一个 `CF_CALLBACK_TYPE_FETCH_DATA` callback，并创建一个 advertised size 与确定性 detection trigger（例如 EICAR ZIP）匹配的 placeholder。第一次 fetch 返回 trigger 并翻转 callback state；后续 fetch 返回 payload。在 scanner 对第一种 representation 完成分类后，获取 transfer key，并使用 payload-sized metadata 重启 hydration，然后强制 hydration 到 EOF。<sup>[[4]](#references)</sup>
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
如果安全边界中的 scan、verdict 和 remediation 仅引用路径名或占位身份，则该边界会失效：它们都无法保证后续的 hydration 返回的是已检查过的字节。<sup>[[4]](#references)</sup>

### 2. 通过 shadow-directory fallback 切换 invariant path

使用 `NtCreateDirectoryObjectEx` 创建一个目标 Object Manager directory 和第二个 directory，并将目标句柄作为其 shadow/fallback directory 传入。在两个 resolution layer 中放置同名的 `WD_SCAN` entry：可见 entry 指向正常的 working directory，而 fallback entry 指向 `\CLFS\??\<working-directory>`。只向 Defender 提供下面的 invariant path；在该操作处于活动状态时删除可见 link，会使同一个字符串回退到 CLFS-backed entry。<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
这不同于仅使用 shadow directories 来减慢查找：攻击者会在不修改路径字符串的情况下，改变此前已接受路径的**含义**。<sup>[[4]](#references)</sup>

### 3. Capture 生成的名称并安装 filename-specific link

使用 `ReadDirectoryChangesW` 监控工作目录。在第一次 `FILE_ACTION_ADDED` 时，移除可见的 `WD_SCAN` link 以激活 fallback lookup。Capture 第二个生成的 filename，打开该 CLFS 相关文件，并使用 `LockFileEx` 锁定 `0..MAXLONGLONG` 范围。在 privileged operation 停滞期间，将可见目录中的 `WD_SCAN` 替换为真实的 Object Manager directory，并创建一个以观察到的 filename 命名的子 symbolic link（PoC 会移除其最后四个字符）。通过 local SMB 将其指向受保护的 destination：<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
非特权进程本身无法写入该目标，但 Defender 的 SYSTEM 上下文可以遍历 loopback administrative share。将生成名称观测与 filename-specific Object Manager link 结合后，无需预先猜测 remediation artifact。<sup>[[4]](#references)</sup>

### 4. Stabilize the cleanup race and trigger a privileged loader

在扫描前，PoC 会将有效 PE（`ntdll.dll`）存储到占位符的 `:stream` NTFS alternate data stream 中。重定向创建受保护的基础文件后，它会以 execute access 打开 `phoneinfo.dll:stream`，并在 cleanup 恢复期间保持一个 `PAGE_EXECUTE_READ | SEC_IMAGE` mapping 存活；活动的 file/section objects 会在最终 race 期间限制删除或替换。重新启动的 hydration 此时返回 payload DLL，而不是 EICAR，因此受保护的基础文件包含攻击者控制的代码。<sup>[[4]](#references)</sup>

随后，通过在 `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` 下放置构造的 `Report.wer`，并通过 Task Scheduler COM API 调用 `\Microsoft\Windows\Windows Error Reporting\QueueReporting`，将受保护的写入转换为 SYSTEM execution。在此 chain 中，特权 WER processing 会加载植入的 `C:\Windows\System32\phoneinfo.dll`；named-pipe connection 用作 payload execution signal。<sup>[[4]](#references)</sup>

### Detection pivots

有用的 correlations 比任何单个 temporary filename 都更具体，并覆盖 chain 中的所有 namespace transitions：<sup>[[4]](#references)</sup>

- 新注册的 Cloud Files provider，随后在同一 placeholder 上检测到 EICAR 和 `CF_OPERATION_TYPE_RESTART_HYDRATION`。
- 包含 `WD_TARGET_*`、`WD_SHADOW_*` 或 `WD_SCAN` 的 Object Manager paths，尤其是位于 `\\.\globalroot\BaseNamedObjects\Restricted\` 下的 scan path。
- 创建 CLFS file，随后进行 exclusive whole-file lock，并由特权 security process loopback 访问 `\\127.0.0.1\C$\Windows\System32\*.dll`。
- 创建 System32 DLL 及 NTFS ADS，随后对该 stream 进行 `SEC_IMAGE` mapping。
- 攻击者创建的 WER queue entry，随后对 `\Microsoft\Windows\Windows Error Reporting\QueueReporting` 进行异常的 manual run，并加载植入的 DLL。

## Applied chain: oplock-gated mount-point switch against privileged remediation

当特权 scanner 检查攻击者控制的文件，之后通过重新打开 **pathname** 而不是继续使用已验证的 handles 来执行 remediation 时，会出现一种可复用的 LPE pattern。FalconFlank 是一个公开示例，目标是 CrowdStrike Falcon 的 Office macro-removal workflow；其 repository 声称已在启用相关 policy 的 Windows 11 25H2 和 Windows Server 2025 上测试，但没有公布 CVE、受影响的 build range、vendor advisory 或 patch status，因此应将该 product-specific claim 视为未经验证且取决于 build。<sup>[[5]](#references)[[6]](#references)</sup>

### Race layout

1. 构建一个可写 tree，使其最终 relative name 在预期 destination 中具有实际用途。示例使用 `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`，但最初写入 `bcrypt.dll` 的是 OLE macro document，而不是 PE DLL。基于内容的 detection 会触发 remediation，同时保留攻击者控制的 basename，以供之后的 side-load 使用。<sup>[[5]](#references)</sup>
2. 使用 broad sharing 和 `FILE_OPEN_REPARSE_POINT` 打开 directories，然后通过 `FSCTL_REQUEST_OPLOCK` 请求 trigger 上的 asynchronous RH oplock，并指定 `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` 和 `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`。等待 overlapped event，并将其 completion 用作 path-switch cue。RH oplock-break notification 只是 advisory，并不能证明每个 conflicting operation 都已被阻止，因此 exploitability 仍取决于 victim 的确切 open/remediation sequence。<sup>[[5]](#references)[[7]](#references)</sup>
3. break 之后，使用 `FileDispositionInformationEx`（information class 64）以及 delete 和 POSIX-semantics flags 删除 leaf directory，关闭其 handle，然后通过 `FSCTL_SET_REPARSE_POINT_EX` 将 `IO_REPARSE_TAG_MOUNT_POINT` 应用到现在为空的 parent。mount point 会将未改变的 suffix 重定向到受保护的 tree，例如 `\\SystemRoot\\System32\\WindowsPowerShell`；如果 directory 不为空，设置 reparse point 会失败，这解释了前面的 deletion step。<sup>[[5]](#references)[[8]](#references)</sup>
4. 恢复特权 workflow。如果它在未证明 directory chain 和 final object 仍是之前检查过的对象时再次解析该 string，那么同一个 logical pathname 现在会到达攻击者选择的受保护 directory。在该示例中，通过原始 process 以 read/write 方式重新打开 `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` 来测试成功；这将 confused-deputy write primitive 与后续 code-execution stage 区分开来。<sup>[[5]](#references)</sup>
5. 将生成的文件替换为真实 DLL，并激活 privileged loader。PoC 使用 `CreateTransaction` + `CreateFileTransacted`，截断文件，mapping DLL-sized replacement，复制 PE，然后 commit；TxF 会将 file handle 及后续 handle-based operations 绑定到 transaction，但它是 race 之后的 replacement mechanism，而不是 privilege boundary failure 的来源。<sup>[[5]](#references)[[9]](#references)</sup>
6. 最后，运行一个现有的 privileged scheduled task，其 executable 会探测植入的 adjacent filename。FalconFlank 调用 `\\Microsoft\\Windows\\Application Experience\\MareBackup`，等待 DLL 连接到 `\\??\\pipe\\FALCONFLANK`，然后删除植入的文件。不要仅根据 task name 假定最终 token；应在测试 build 上验证 launched process、module path、integrity level 和 token。<sup>[[5]](#references)</sup>

因此，核心 audit question 不是“service 是否验证了 original input path？”，而是“每次 privileged mutation 是否始终绑定到已验证的同一组 opened file 和 directory objects？”在 check 和 use 期间持有 handles、相对于 trusted directory handle 打开 child objects、拒绝意外的 reparse tags，并在 mutation 前重新验证 file identity，可以消除这类 pathname-substitution bug。<sup>[[1]](#references)[[8]](#references)</sup>

### Detection and PoC triage

高信号 detection 会将 namespace transition 与 privileged consumer 相关联：在 GUID-named temporary tree 中出现 DLL basename 下的 OLE header、oplock break、对 leaf directory 的 POSIX-style removal、创建指向受保护 Windows directory 的 mount point，以及在该 destination 下创建或修改相同 basename。对于公开示例，还可加入 `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`、`MareBackup` 的 manual execution 和 `FALCONFLANK` named pipe 作为更窄的 pivots；但其中任何单项都不足以单独判定。<sup>[[5]](#references)</sup>

重现 PoC 时，应考虑 published source 中的三个 reliability defects：它使用 embedded byte-array pointer 而不是 file handle 调用 `FlushFileBuffers`；在 `GetFolder`、`GetTask` 和 `Run` 之后检查 stale `HRESULT`；并对 directory deletion、reparse creation、oplock event 和 pipe connection 使用无界 retry/wait loops。<sup>[[5]](#references)</sup>

## Operational considerations

- **Combine primitives** – 你可以在 directory chain 的 *每一层* 使用 long name，以获得更高的 latency，直到耗尽 `UNICODE_STRING` size。
- **One-shot bugs** – 扩大的 window（数十 microseconds 到数分钟）与 CPU affinity pinning 或 hypervisor-assisted preemption 配合后，可以使“single trigger” bugs 成为现实。
- **Side effects** – slowdown 只影响 malicious path，因此整体 system performance 不受影响；除非监控 namespace growth，否则 defenders 很少会注意到。
- **Cleanup** – 保留对所创建的每个 directory/object 的 handles，以便之后调用 `NtMakeTemporaryObject`/`NtClose`。否则，无界 directory chains 可能跨 reboot 持续存在。
- **File-system races** – 如果 vulnerable path 最终通过 NTFS 解析，可以在 OM slowdown 运行期间，在 backing file 上叠加 Oplock（例如同一 toolkit 中的 `SetOpLock.exe`），在不改变 OM graph 的情况下将 consumer 冻结额外数 milliseconds。<sup>[[2]](#references)</sup>

## Defensive notes

- 依赖 named objects 的 kernel code 应在 open 之后重新验证 security-sensitive state，或在 check 前获取 reference（关闭 TOCTOU gap）。
- 在 dereference user-controlled names 之前，对 OM path depth/length 强制执行 upper bounds。拒绝过长的 names 会迫使攻击者回到 microsecond window。
- 监控 object manager namespace growth（ETW `Microsoft-Windows-Kernel-Object`），以检测 `\BaseNamedObjects` 下可疑的数千组件 chains。

## References

- [1] [Project Zero – Windows Exploitation Techniques: 使用 Path Lookups 赢得 Race Conditions](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp（commit be016d8）](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp（commit 702b574）](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - 如何使用 Transactional NTFS](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
