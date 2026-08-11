# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

**MACF** 代表 **Mandatory Access Control Framework**，是集成在操作系统中的安全系统，用于帮助保护计算机。它通过设置**关于谁或什么可以访问系统特定部分的严格规则**来工作，例如文件、应用程序和系统资源。通过自动执行这些规则，MACF 可确保只有经过授权的用户和进程才能执行特定操作，从而降低未经授权访问或恶意活动的风险。

需要注意的是，MACF 本身并不会真正做出任何决策，它只负责**拦截**操作，并将决策交给它调用的**策略模块**（kernel extensions），例如 `AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext`、`TMSafetyNet.kext` 和 `mcxalr.kext`。

- 策略可以强制执行（在某些操作上返回 0 或非 0）
- 策略可以进行监控（返回 0，从而不进行阻止，但可借助 hook 执行某些操作）
- MACF static policy 会在启动时安装，并且永远不会被移除
- MACF dynamic policy 由 KEXT（kextload）安装，理论上可以通过 kextunload 卸载
- 在 iOS 中只允许使用 static policy，而在 macOS 中允许使用 static + dynamic。<sup>[[7]](#references)</sup>

### 流程

1. 进程执行 syscall/mach trap
2. kernel 内部调用相关函数
3. 函数调用 MACF
4. MACF 检查在其策略中请求对该函数设置 hook 的策略模块
5. MACF 调用相关策略
6. 策略指示是否允许或拒绝该操作

> [!CAUTION]
> 只有 Apple 可以使用 MAC Framework KPI。

通常，使用 MACF 检查权限的函数会调用宏 `MAC_CHECK`。例如，创建 socket 的 syscall 会调用函数 `mac_socket_check_create`，而该函数会调用 `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`。此外，宏 `MAC_CHECK` 在 security/mac_internal.h 中定义如下：<sup>[[3]](#references)</sup>
```c
Resolver tambien MAC_POLICY_ITERATE, MAC_CHECK_CALL, MAC_CHECK_RSLT


#define MAC_CHECK(check, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_ ## check != NULL) {                   \
MAC_CHECK_CALL(check, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
MAC_CHECK_RSLT(check, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
请注意，将 `check` 转换为 `socket_check_create`，并将 `(cred, domain, type, protocol)` 中的 `args...` 转换后，你会得到：
```c
// Note the "##" just get the param name and append it to the prefix
#define MAC_CHECK(socket_check_create, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {                   \
MAC_CHECK_CALL(socket_check_create, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_socket_check_create (args); \
MAC_CHECK_RSLT(socket_check_create, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
展开 helper macros 后，可以看到具体的控制流：
```c
do {                                                // MAC_CHECK
error = 0;
do {                                            // MAC_POLICY_ITERATE
struct mac_policy_conf *mpc;
u_int i;
for (i = 0; i < mac_policy_list.staticmax; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK); // MAC_CHECK_CALL
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);                    // MAC_CHECK_RSLT
error = mac_error_select(__step_err, error);
}
}
if (mac_policy_list_conditional_busy() != 0) {
for (; i <= mac_policy_list.maxindex; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK);
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);
error = mac_error_select(__step_err, error);
}
}
mac_policy_list_unbusy();
}
} while (0);
} while (0);
```
换句话说，`MAC_CHECK(socket_check_create, ...)` 会先遍历静态策略，然后有条件地锁定并遍历动态策略，在每个 hook 周围发出 DTrace probes，并通过 `mac_error_select()` 将每个 hook 的返回代码汇总为单一的 `error` 结果。


### Labels

MACF 使用 **labels**，策略会通过这些 **labels** 检查是否应授予某项访问权限。labels 结构体声明的代码可以在[这里](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h)找到，该结构体随后会在 **`struct ucred`** 的[这里](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86)的 **`cr_label`** 部分中使用。该 label 包含 flags 以及一定数量的 **slots**，MACF policies 可以使用这些 slots 分配指针。例如，Sanbox 会指向 container profile。

## MACF Policies

MACF Policy 定义了要应用于特定 kernel 操作的**规则和条件**。

kernel extension 可以配置一个 `mac_policy_conf` 结构体，然后调用 `mac_policy_register` 对其进行注册。根据[这里](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)：<sup>[[1]](#references)</sup>
```c
#define mpc_t	struct mac_policy_conf *

/**
@brief Mac policy configuration

This structure specifies the configuration information for a
MAC policy module.  A policy module developer must supply
a short unique policy name, a more descriptive full name, a list of label
namespaces and count, a pointer to the registered entry-point operations,
any load time flags, and optionally, a pointer to a label slot identifier.

The Framework will update the runtime flags (mpc_runtime_flags) to
indicate that the module has been registered.

If the label slot identifier (mpc_field_off) is NULL, the Framework
will not provide label storage for the policy.  Otherwise, the
Framework will store the label location (slot) in this field.

The mpc_list field is used by the Framework and should not be
modified by policies.
*/
/* XXX - reorder these for better alignment on 64bit platforms */
struct mac_policy_conf {
const char		*mpc_name;		/** policy name */
const char		*mpc_fullname;		/** full name */
const char		**mpc_labelnames;	/** managed label namespaces */
unsigned int		 mpc_labelname_count;	/** number of managed label namespaces */
struct mac_policy_ops	*mpc_ops;		/** operation vector */
int			 mpc_loadtime_flags;	/** load time flags */
int			*mpc_field_off;		/** label slot */
int			 mpc_runtime_flags;	/** run time flags */
mpc_t			 mpc_list;		/** List reference */
void			*mpc_data;		/** module data */
};
```
通过检查对 `mac_policy_register` 的调用，可以轻松识别配置这些策略的 kernel extensions。此外，检查该 extension 的反汇编，也可以找到所使用的 `mac_policy_conf` struct。

请注意，MACF policies 也可以**动态地**注册和注销。

`mac_policy_conf` 的主要字段之一是 **`mpc_ops`**。此字段指定该 policy 关注哪些操作。此类操作有数百种，因此可以将所有条目置零，然后只选择 policy 所需的操作。来源：[here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)：<sup>[[1]](#references)</sup>
```c
struct mac_policy_ops {
mpo_audit_check_postselect_t		*mpo_audit_check_postselect;
mpo_audit_check_preselect_t		*mpo_audit_check_preselect;
mpo_bpfdesc_label_associate_t		*mpo_bpfdesc_label_associate;
mpo_bpfdesc_label_destroy_t		*mpo_bpfdesc_label_destroy;
mpo_bpfdesc_label_init_t		*mpo_bpfdesc_label_init;
mpo_bpfdesc_check_receive_t		*mpo_bpfdesc_check_receive;
mpo_cred_check_label_update_execve_t	*mpo_cred_check_label_update_execve;
mpo_cred_check_label_update_t		*mpo_cred_check_label_update;
[...]
```
几乎所有 hooks 都会在这些操作被拦截时由 MACF 回调。然而，**`mpo_policy_*`** hooks 是例外，因为 **`mpo_hook_policy_init()`** 是在注册时调用的 callback（即在 `mac_policy_register()` 之后），而 **`mpo_hook_policy_initbsd()`** 则会在 BSD subsystem 正确初始化后、late registration 期间调用。

此外，任何 kext 都可以注册 **`mpo_policy_syscall`** hook，以暴露一个私有的 **ioctl** 风格调用 **interface**。之后，user client 将能够调用 `mac_syscall` (#381)，并将 **policy name**、整数 **code** 以及可选的 **arguments** 指定为参数。\
例如，**`Sandbox.kext`** 大量使用了这一机制。

检查 kext 的 **`__DATA.__const*`**，可以识别注册 policy 时使用的 `mac_policy_ops` 结构。之所以能够找到它，是因为其指针位于 `mpo_policy_conf` 内的某个偏移处，同时该区域中还会存在一定数量的 NULL pointers。

此外，还可以通过从内存中 dump **`_mac_policy_list`** 结构，获取已配置 policy 的 kext 列表；每注册一个 policy，该结构都会更新。

你也可以使用工具 `xnoop` dump 系统中注册的所有 policies：
```bash
xnoop offline .

Xn👀p> macp
mac_policy_list(@0xfffffff0447159b8): 3 Mac Policies@0xfffffff0447153f0
0: 0xfffffff044886f18:
mpc_name: AppleImage4
mpc_fullName: AppleImage4 hooks
mpc_ops: mac_policy_ops@0xfffffff044886f68
1: 0xfffffff0448d7d40:
mpc_name: AMFI
mpc_fullName: Apple Mobile File Integrity
mpc_ops: mac_policy_ops@0xfffffff0448d72c8
2: 0xfffffff044b0b950:
mpc_name: Sandbox
mpc_fullName: Seatbelt sandbox policy
mpc_ops: mac_policy_ops@0xfffffff044b0b9b0
Xn👀p> dump mac_policy_opns@0xfffffff0448d72c8
Type 'struct mac_policy_opns' is unrecognized - dumping as raw 64 bytes
Dumping 64 bytes from 0xfffffff0448d72c8
```
然后使用以下命令转储 check policy 的所有检查项：
```bash
Xn👀p> dump mac_policy_ops@0xfffffff044b0b9b0
Dumping 2696 bytes from 0xfffffff044b0b9b0 (as struct mac_policy_ops)

mpo_cred_check_label_update_execve(@0x30): 0xfffffff046d7fb54(PACed)
mpo_cred_check_label_update(@0x38): 0xfffffff046d7348c(PACed)
mpo_cred_label_associate(@0x58): 0xfffffff046d733f0(PACed)
mpo_cred_label_destroy(@0x68): 0xfffffff046d733e4(PACed)
mpo_cred_label_update_execve(@0x90): 0xfffffff046d7fb60(PACed)
mpo_cred_label_update(@0x98): 0xfffffff046d73370(PACed)
mpo_file_check_fcntl(@0xe8): 0xfffffff046d73164(PACed)
mpo_file_check_lock(@0x110): 0xfffffff046d7309c(PACed)
mpo_file_check_mmap(@0x120): 0xfffffff046d72fc4(PACed)
mpo_file_check_set(@0x130): 0xfffffff046d72f2c(PACed)
mpo_reserved08(@0x168): 0xfffffff046d72e3c(PACed)
mpo_reserved09(@0x170): 0xfffffff046d72e34(PACed)
mpo_necp_check_open(@0x1f0): 0xfffffff046d72d9c(PACed)
mpo_necp_check_client_action(@0x1f8): 0xfffffff046d72cf8(PACed)
mpo_vnode_notify_setextattr(@0x218): 0xfffffff046d72ca4(PACed)
mpo_vnode_notify_setflags(@0x220): 0xfffffff046d72c84(PACed)
mpo_proc_check_get_task_special_port(@0x250): 0xfffffff046d72b98(PACed)
mpo_proc_check_set_task_special_port(@0x258): 0xfffffff046d72ab4(PACed)
mpo_vnode_notify_unlink(@0x268): 0xfffffff046d72958(PACed)
mpo_vnode_check_copyfile(@0x290): 0xfffffff046d726c0(PACed)
mpo_mount_check_quotactl(@0x298): 0xfffffff046d725c4(PACed)
...
```
## XNU 中的 MACF 初始化

### Early bootstrap 和 mac_policy_init()

- MACF 很早就会被初始化。在 `bootstrap_thread`（XNU 启动代码中）里，`ipc_bootstrap` 之后，XNU 会调用 `mac_policy_init()`（位于 `mac_base.c`）。
- `mac_policy_init()` 初始化全局的 `mac_policy_list`（一个 policy slot 数组或列表），并在 XNU 中建立 MAC（Mandatory Access Control）基础设施。
- 随后会调用 `mac_policy_initmach()`，负责处理内置或捆绑 policies 的 kernel 侧注册。

### `mac_policy_initmach()` 和加载 “security extensions”

- `mac_policy_initmach()` 会检查预加载的 kernel extensions（kexts）（或位于 “policy injection” 列表中的 kexts），并检查其 Info.plist 中是否存在 `AppleSecurityExtension` 键。
- 在 Info.plist 中声明 `<key>AppleSecurityExtension</key>`（或 `true`）的 kexts 会被视为 “security extensions”——也就是实现 MAC policy 或接入 MACF 基础设施的 kexts。
- 包含该键的 Apple kexts 示例包括 **ALF.kext**、**AppleMobileFileIntegrity.kext (AMFI)**、**Sandbox.kext**、**Quarantine.kext**、**TMSafetyNet.kext**、**CoreTrust.kext**、**AppleSystemPolicy.kext** 等（正如你之前列出的）。
- kernel 会确保这些 kexts 被提前加载，然后在启动期间通过 `mac_policy_register` 调用其注册例程，将它们插入 `mac_policy_list`。

- 每个 policy module（kext）都会提供一个 `mac_policy_conf` 结构，其中包含针对各种 MAC 操作的 hooks（vnode checks、exec checks、label updates 等）。
- load time flags 可能包括 `MPC_LOADTIME_FLAG_NOTLATE`，其含义是“必须提前加载”（因此 late registration 尝试会被拒绝）。
- 注册后，每个 module 都会获得一个 handle，并占据 `mac_policy_list` 中的一个 slot。
- 之后调用 MAC hook 时（例如 vnode access、exec 等），MACF 会遍历所有已注册的 policies，以做出集体决策。

- 特别是，**AMFI**（Apple Mobile File Integrity）就是这样的 security extension。其 Info.plist 包含 `AppleSecurityExtension`，用于标记其为 security policy。
- 作为 kernel boot 的一部分，kernel load logic 会确保 “security policy”（包括 AMFI 等）在许多 subsystems 依赖它们之前已经处于 active 状态。例如，kernel 会“通过加载 security policy（包括 AppleMobileFileIntegrity (AMFI)、Sandbox、Quarantine policy）来为即将执行的 tasks 做准备”。
```bash
cd /System/Library/Extensions
find . -name Info.plist | xargs grep AppleSecurityExtension 2>/dev/null

./AppleImage4.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./ALF.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./CoreTrust.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleMobileFileIntegrity.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Quarantine.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Sandbox.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleSystemPolicy.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
```
## KPI dependency & com.apple.kpi.dsep in MAC policy kexts

编写使用 MAC framework 的 kext（即调用 `mac_policy_register()` 等函数）时，必须声明对 KPI（Kernel Programming Interfaces）的依赖，以便 kext linker（kxld）解析这些符号。因此，要声明某个 `kext` 依赖 MACF，需要在 `Info.plist` 中通过 `com.apple.kpi.dsep` 指明这一点（`find . Info.plist | grep AppleSecurityExtension`）。之后，该 kext 将引用 `mac_policy_register`、`mac_policy_unregister` 以及 MAC hook function pointers 等符号。要解析这些符号，必须将 `com.apple.kpi.dsep` 列为依赖项。

Example Info.plist snippet（位于你的 .kext 内）：
```xml
<key>OSBundleLibraries</key>
<dict>
<key>com.apple.kpi.dsep</key>
<string>18.0</string>
<key>com.apple.kpi.libkern</key>
<string>18.0</string>
<key>com.apple.kpi.bsd</key>
<string>18.0</string>
<key>com.apple.kpi.mach</key>
<string>18.0</string>
… (other kpi dependencies as needed)
</dict>
```
## 现代 macOS 版本中的 MACF

在现代 macOS 上，Apple 安全策略通常不应被视为松散的独立 `.kext` bundle。自 **macOS 11** 起，kernel extensions 会被链接到 **kernel collections** 中；在 **Apple Silicon** 上不存在独立的 **SystemKC**，第三方 kext 只有在构建到 **Auxiliary Kernel Collection (AuxKC)** 中并重启后，才可以被加载。对于 MACF 研究而言，这意味着使用 `kmutil` 枚举内置策略（如 **Sandbox**、**AMFI**、**AppleSystemPolicy**、**CoreTrust** 或 **Quarantine**）通常比使用 `kextstat` 等已弃用的工具更容易。
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> 在 Apple Silicon 上，如果某个 security kext 不在 BootKC 中，请接着检查 AuxKC。这通常比在 `/System/Library/Extensions` 下寻找 standalone bundle 更有用。

## MACF Callouts

通常可以在类似 **`#if CONFIG_MAC`** 的条件代码块中找到对 MACF 的 callouts。此外，在这些代码块中还可以找到对 `mac_proc_check*` 的调用，这些调用 MACF 来**检查执行特定操作所需的权限**。此外，MACF callouts 的格式为：**`mac_<object>_<opType>_opName`**。

object 是以下之一：`bpfdesc`、`cred`、`file`、`proc`、`vnode`、`mount`、`devfs`、`ifnet`、`inpcb`、`mbuf`、`ipq`、`pipe`、`sysv[msg/msq/shm/sem]`、`posix[shm/sem]`、`socket`、`kext`。\
`opType` 通常是 check，用于允许或拒绝该操作。不过，也可能找到 `notify`，它允许 kext 对给定操作作出响应。

你可以在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) 中找到一个示例：

<pre class="language-c"><code class="lang-c">int
mmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)
{
[...]
#if CONFIG_MACF
<strong>			error = mac_file_check_mmap(vfs_context_ucred(ctx),
</strong>			    fp->fp_glob, prot, flags, file_pos + pageoff,
&maxprot);
if (error) {
(void)vnode_put(vp);
goto bad;
}
#endif /* MAC */
[...]
</code></pre>

然后，可以在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) 中找到 `mac_file_check_mmap` 的代码。
```c
mac_file_check_mmap(struct ucred *cred, struct fileglob *fg, int prot,
int flags, uint64_t offset, int *maxprot)
{
int error;
int maxp;

maxp = *maxprot;
MAC_CHECK(file_check_mmap, cred, fg, NULL, prot, flags, offset, &maxp);
if ((maxp | *maxprot) != *maxprot) {
panic("file_check_mmap increased max protections");
}
*maxprot = maxp;
return error;
}
```
它会调用 `MAC_CHECK` 宏，其代码可在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup> 中找到。
```c
/*
* MAC_CHECK performs the designated check by walking the policy
* module list and checking with each as to how it feels about the
* request.  Note that it returns its value via 'error' in the scope
* of the caller.
*/
#define MAC_CHECK(check, args...) do {                              \
error = 0;                                                      \
MAC_POLICY_ITERATE({                                            \
if (mpc->mpc_ops->mpo_ ## check != NULL) {              \
DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_CHECK); \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_err); \
error = mac_error_select(__step_err, error);         \
}                                                           \
});                                                             \
} while (0)
```
它会遍历所有已注册的 mac policies，调用它们的函数，并将输出存储在 `error` 变量中。该变量只有在成功代码的情况下才能由 `mac_error_select` 覆盖，因此只要有任何检查失败，整个检查就会失败，并且不会允许执行该操作。

> [!TIP]
> 但是，请记住，并非所有 MACF callouts 都仅用于拒绝操作。例如，`mac_priv_grant` 调用宏 [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274)。如果任何 policy 返回 0，该宏就会授予所请求的 privilege：
>
> ```c
> /*
> * MAC_GRANT performs the designated check by walking the policy
> * module list and checking with each as to how it feels about the
> * request.  Unlike MAC_CHECK, it grants if any policies return '0',
> * and otherwise returns EPERM.  Note that it returns its value via
> * 'error' in the scope of the caller.
> */
> #define MAC_GRANT(check, args...) do {                              \
>    error = EPERM;                                                  \
>    MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>    });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

这些 callout 用于检查并提供 [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) 中定义的几十种 **privileges**。\
某些 kernel 代码会从 [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) 调用 `priv_check_cred()`，并传入进程的 KAuth credentials 以及某个 privilege code。该函数会调用 `mac_priv_check`，检查是否有任何 policy **拒绝**授予该 privilege，随后调用 `mac_priv_grant`，检查是否有任何 policy 授予该 `privilege`。<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

该 hook 允许拦截所有 system calls。在 `bsd/dev/[i386|arm]/systemcalls.c` 中，可以看到已声明的函数 [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25)，其中包含以下代码：
```c
#if CONFIG_MACF
if (__improbable(proc_syscall_filter_mask(proc) != NULL && !bitstr_test(proc_syscall_filter_mask(proc), syscode))) {
error = mac_proc_check_syscall_unix(proc, syscode);
if (error) {
goto skip_syscall;
}
}
#endif /* CONFIG_MACF */
```
该检查调用进程中的 **bitmask**，判断当前 syscall 是否应调用 `mac_proc_check_syscall_unix`。这是因为 syscall 的调用频率很高，因此避免每次都调用 `mac_proc_check_syscall_unix` 会更合适。

注意，函数 `proc_set_syscall_filter_mask()` 用于设置进程中的 syscall bitmask，它由 Sandbox 调用，以便为受 sandbox 保护的进程设置掩码。

## Exposed MACF syscalls

可以通过 [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) 中定义的一些 syscall 与 MACF 交互：
```c
/*
* Extended non-POSIX.1e interfaces that offer additional services
* available from the userland and kernel MAC frameworks.
*/
#ifdef __APPLE_API_PRIVATE
__BEGIN_DECLS
int      __mac_execve(char *fname, char **argv, char **envv, mac_t _label);
int      __mac_get_fd(int _fd, mac_t _label);
int      __mac_get_file(const char *_path, mac_t _label);
int      __mac_get_link(const char *_path, mac_t _label);
int      __mac_get_pid(pid_t _pid, mac_t _label);
int      __mac_get_proc(mac_t _label);
int      __mac_set_fd(int _fildes, const mac_t _label);
int      __mac_set_file(const char *_path, mac_t _label);
int      __mac_set_link(const char *_path, mac_t _label);
int      __mac_mount(const char *type, const char *path, int flags, void *data,
struct mac *label);
int      __mac_get_mount(const char *path, struct mac *label);
int      __mac_set_proc(const mac_t _label);
int      __mac_syscall(const char *_policyname, int _call, void *_arg);
__END_DECLS
#endif /*__APPLE_API_PRIVATE*/
```
对于 offensive reversing，**`__mac_syscall`** 仍然是 userland 中最好的 chokepoint 之一。它携带一个 **policy name**（例如 `"Sandbox"` 或 `"AMFI"`）、一个 **policy-specific selector/code**，以及一个指向 **opaque argument blob** 的指针，后者将由 `mpo_policy_syscall` 处理。当先从 userland 逆向分析未公开的操作，之后再转入 kernel 实现时，这一点非常有用。Sandbox 通常通过 `__sandbox_ms` 访问它，而 AMFI 也使用相同机制处理 dyld policy 决策。<sup>[[2]](#references)[[5]](#references)</sup>

## Practical offensive research notes

近期的 macOS bug 很少会直接“break MACF”。相反，它们通常会利用 **MACF / Sandbox / TCC 决策与之后发生的 privileged action 之间的 desynchronisation**。

### Broker path checks vs real privileged action

一种反复出现的模式是：privileged daemon 对某个版本的路径执行 **userland pre-check**（例如 `sandbox_check_by_audit_token()`），之后却使用**不同的或非 canonical 的 attacker-controlled path** 执行真正的 privileged sink。近期对 `diskarbitrationd` / `storagekitd` 的研究就是一个很好的例子：**directory traversal** 加上 **symlink swaps**，使攻击者能够通过 daemon 的 sandbox validation，随后 mount 到 `~/Library/Application Support/com.apple.TCC` 等敏感位置，从而根据所选的 mount point，将该 bug 转化为 **sandbox escape**、**local privilege escalation** 或 **TCC bypass**。<sup>[[6]](#references)</sup>

审计从 sandbox 可访问的 root broker 时，首先 grep：

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`、path canonicalisation helpers
- privileged sinks，例如 `mount`、`rename`、`copyfile`、helper-tool XPC methods，或任何之后会以 root 身份处理 attacker-controlled paths 的操作

### Trusted deputies with private entitlements

另一种实用模式是不直接攻击 MACF hooks，而是滥用一个已经具备跨越该边界所需权限的 **trusted process**。近期的 Safari/TCC 研究就是一个很好的例子：其中有价值的 primitive 并不是“在 kernel 中 disable TCC”，而是修改本地 policy/configuration，使一个拥有 **`com.apple.private.tcc.allow`** 的 Apple-signed process 代表你执行敏感操作。<sup>[[8]](#references)</sup> 实际审计中，高价值目标是同时具备以下条件的 Apple daemons/apps：

- **private entitlements** 或类似 FDA 的访问能力
- 可写的 config / database / mount point / policy file
- 之后由 **Sandbox**、**AMFI**、**TCC** 或其他 MACF policy mediated 的敏感操作

如需进行更深入的、针对特定产品的 reversing，请查看 [macOS Sandbox](macos-sandbox/README.md) 和 [macOS TCC](macos-tcc/README.md) 专页。

## References

- [1] [XNU — `security/mac_policy.h`（完整的 MACF policy operations vector）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c`（`mac_policy_register`、`__mac_syscall`）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h`（`MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE` macros）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h`（`priv_check`/`priv_grant` 使用的 privilege codes）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall（Offensive Security）](https://www.offsec.com/blog/amfi-syscall/)
- [6] [发现 Apple Vulnerabilities：diskarbitrationd 和 storagekitd Audit 第 2 部分](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — XNU Cross Reference 工具](https://newosxbook.com/xxr/index.php)
- [8] [新的 macOS vulnerability：“HM Surf” 可能导致未经授权的数据访问（Microsoft Security Blog）](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
{{#include ../../../banners/hacktricks-training.md}}
