# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

**MACF** 代表 **Mandatory Access Control Framework**，这是内置于操作系统中的一个安全系统，用于帮助保护你的计算机。它通过设置**关于谁或什么可以访问系统某些部分的严格规则**来工作，例如文件、应用程序和系统资源。通过自动强制执行这些规则，MACF 确保只有授权用户和进程才能执行特定操作，从而降低未授权访问或恶意活动的风险。

注意，MACF 本身并不会真正做出任何决定，它只是**拦截**动作，真正的决定交给它调用的**policy modules**（kernel extensions），例如 `AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext`、`TMSafetyNet.kext` 和 `mcxalr.kext`。

- 一个 policy 可能是 enforcing 的（在某些操作上返回非 0）
- 一个 policy 可能是 monitoring 的（返回 0，这样不会阻止，但会借助 hook 做一些事情）
- MACF static policy 在启动时安装，并且**永远不会**被移除
- MACF dynamic policy 由 KEXT（kextload）安装，理论上可以被 kextunloaded
- 在 iOS 中只允许 static policies，而在 macOS 中允许 static + dynamic。
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### 流程

1. Process 执行一个 syscall/mach trap
2. 内核中调用相关函数
3. 函数调用 MACF
4. MACF 检查在其 policy 中请求 hook 该函数的 policy modules
5. MACF 调用相关 policies
6. Policies 指示它们是否允许或拒绝该动作

> [!CAUTION]
> 只有 Apple 可以使用 MAC Framework KPI。

通常，使用 MACF 检查权限的函数会调用宏 `MAC_CHECK`。例如，创建 socket 的 syscall 会调用函数 `mac_socket_check_create`，后者再调用 `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`。此外，宏 `MAC_CHECK` 在 security/mac_internal.h 中定义如下：
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
注意，将 `check` 转换为 `socket_check_create`，并将 `(cred, domain, type, protocol)` 中的 `args...` 替换后，你会得到：
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
展开 helper macros 后会显示具体的控制流：
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
换句话说，`MAC_CHECK(socket_check_create, ...)` 会先遍历静态 policies，然后按条件锁定并遍历动态 policies，在每个 hook 周围发出 DTrace probes，并通过 `mac_error_select()` 将每个 hook 的返回码折叠为单一的 `error` 结果。


### Labels

MACF 使用 **labels**，随后用于检查是否应授予某些访问权限的 policies 会使用它们。labels 结构体声明的代码可以在 [这里](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) 找到，然后它在 [这里](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) 的 **`struct ucred`** 中的 **`cr_label`** 部分被使用。该 label 包含 flags 和若干 **slots**，这些 **slots** 可由 **MACF policies** 用来分配 pointers。例如，Sanbox 会指向 container profile

## MACF Policies

一个 MACF Policy 定义了 **要在某些 kernel operations 中应用的规则和条件**。

一个 kernel extension 可以配置一个 `mac_policy_conf` struct，然后通过调用 `mac_policy_register` 来注册它。来自 [这里](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)：
```c
#define mpc_t	struct mac_policy_conf *

/**
@brief Mac policy configuration

This structure specifies the configuration information for a
MAC policy module.  A policy module developer must supply
a short unique policy name, a more descriptive full name, a list of label
namespaces and count, a pointer to the registered enty point operations,
any load time flags, and optionally, a pointer to a label slot identifier.

The Framework will update the runtime flags (mpc_runtime_flags) to
indicate that the module has been registered.

If the label slot identifier (mpc_field_off) is NULL, the Framework
will not provide label storage for the policy.  Otherwise, the
Framework will store the label location (slot) in this field.

The mpc_list field is used by the Framework and should not be
modified by policies.
*/
/* XXX - reorder these for better aligment on 64bit platforms */
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
通过检查对 `mac_policy_register` 的调用，很容易识别出配置这些策略的 kernel extensions。此外，检查该 extension 的反汇编，也可以找到所使用的 `mac_policy_conf` 结构体。

注意，MACF policies 也可以 **动态** 注册和注销。

`mac_policy_conf` 的主要字段之一是 **`mpc_ops`**。这个字段指定了该 policy 关注哪些操作。注意，这类操作有数百个，所以可以先把它们全部置零，然后只选择该 policy 感兴趣的那些。来自 [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)：
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
几乎所有的 hooks 都会在这些操作被拦截时由 MACF 回调。不过，**`mpo_policy_*`** hooks 是个例外，因为 `mpo_hook_policy_init()` 是在注册时触发的回调（也就是在 `mac_policy_register()` 之后），而 `mpo_hook_policy_initbsd()` 则是在晚期注册阶段、BSD 子系统正确初始化之后调用。

另外，**`mpo_policy_syscall`** hook 可以由任何 kext 注册，用来暴露一个私有的 **ioctl** 风格调用 **interface**。然后，用户客户端就可以调用 `mac_syscall` (#381)，并将 **policy name**、一个整数 **code** 以及可选的 **arguments** 作为参数。\
例如，**`Sandbox.kext`** 经常大量使用这个功能。

检查 kext 的 **`__DATA.__const*`** 可以帮助识别注册 policy 时使用的 `mac_policy_ops` 结构。之所以能找到它，是因为它的指针位于 `mpo_policy_conf` 内的某个偏移处，并且因为那里会有大量 NULL 指针。

此外，也可以通过从内存中 dump 出结构 **`_mac_policy_list`** 来获取已配置 policy 的 kext 列表，这个结构会随着每个已注册的 policy 更新。

你也可以使用工具 `xnoop` 来 dump 系统中注册的所有 policies：
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
然后用以下方式转储 check policy 的所有检查：
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

### 早期启动和 `mac_policy_init()`

- MACF 很早就会被初始化。在 `bootstrap_thread` 中（XNU 启动代码里），在 `ipc_bootstrap` 之后，XNU 会调用 `mac_policy_init()`（位于 `mac_base.c`）。
- `mac_policy_init()` 会初始化全局 `mac_policy_list`（一个策略槽数组或列表），并为 XNU 内部的 MAC（Mandatory Access Control）建立基础设施。
- 随后会调用 `mac_policy_initmach()`，它负责内置或捆绑策略在内核侧的注册处理。

### `mac_policy_initmach()` 与加载 “security extensions”

- `mac_policy_initmach()` 会检查预加载的内核扩展（kexts）（或者位于 “policy injection” 列表中的 kexts），并查看它们的 Info.plist 中是否包含键 `AppleSecurityExtension`。
- 在 Info.plist 中声明 `<key>AppleSecurityExtension</key>`（或 `true`）的 kexts 会被视为 “security extensions”——也就是实现 MAC policy 或接入 MACF 基础设施的组件。
- 带有该键的 Apple kexts 示例包括 **ALF.kext**、**AppleMobileFileIntegrity.kext (AMFI)**、**Sandbox.kext**、**Quarantine.kext**、**TMSafetyNet.kext**、**CoreTrust.kext**、**AppleSystemPolicy.kext** 等（正如你已经列出的那样）。
- 内核会确保这些 kexts 尽早加载，然后在启动过程中调用它们的注册例程（通过 `mac_policy_register`），把它们插入到 `mac_policy_list` 中。

- 每个 policy module（kext）都会提供一个 `mac_policy_conf` 结构，其中包含针对各种 MAC 操作的 hooks（`mpc_ops`）（如 vnode 检查、exec 检查、label 更新等）。
- 加载时标志可能包含 `MPC_LOADTIME_FLAG_NOTLATE`，表示“必须尽早加载”（因此晚注册的尝试会被拒绝）。
- 一旦注册完成，每个模块都会获得一个 handle，并占用 `mac_policy_list` 中的一个槽位。
- 当之后触发某个 MAC hook 时（例如 vnode 访问、exec 等），MACF 会遍历所有已注册的策略，做出联合决策。

- 其中，**AMFI**（Apple Mobile File Integrity）就是这样的一个 security extension。它的 Info.plist 包含 `AppleSecurityExtension`，表明它是一个 security policy。
- 在内核启动过程中，内核加载逻辑会确保 “security policy”（如 AMFI 等）在很多子系统依赖它之前就已经处于激活状态。例如，内核会“通过加载……security policy，包括 AppleMobileFileIntegrity (AMFI)、Sandbox、Quarantine policy，为后续任务做准备。”
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

当编写一个使用 MAC framework 的 kext（即调用 `mac_policy_register()` 等）时，你必须声明对 KPI（Kernel Programming Interfaces）的依赖，这样 kext linker（kxld）才能解析这些符号。因此，要声明一个 `kext` 依赖 MACF，你需要在 `Info.plist` 中使用 `com.apple.kpi.dsep` 来标明它（`find . Info.plist | grep AppleSecurityExtension`），这样 kext 就会引用诸如 `mac_policy_register`、`mac_policy_unregister` 以及 MAC hook function pointers 之类的符号。要解析这些符号，你必须将 `com.apple.kpi.dsep` 列为依赖项。

Example Info.plist snippet (inside your .kext):
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
## 现代 macOS 版本上的 MACF

在现代 macOS 上，Apple 安全策略通常不再适合被看作松散独立的 `.kext` bundle。自 **macOS 11** 起，kernel extensions 被链接进 **kernel collections**；在 **Apple Silicon** 上没有单独的 **SystemKC**，第三方 kext 只有在被构建进 **Auxiliary Kernel Collection (AuxKC)** 并重启后才可加载。对于 MACF 研究来说，这意味着像 **Sandbox**、**AMFI**、**AppleSystemPolicy**、**CoreTrust** 或 **Quarantine** 这类内置策略，通常用 `kmutil` 比用已废弃的工具如 `kextstat` 更容易枚举。
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> 在 Apple Silicon 上，如果某个 security kext 不在 BootKC 中，接着检查 AuxKC。这通常比在 `/System/Library/Extensions` 下寻找一个独立 bundle 更有用。

## MACF Callouts

在代码中经常能找到对 MACF 的 callouts，例如：**`#if CONFIG_MAC`** 条件块。此外，在这些块里面还可能找到对 `mac_proc_check*` 的调用，它会调用 MACF 来**检查执行某些操作的权限**。另外，MACF callouts 的格式是：**`mac_<object>_<opType>_opName`**。

object 可能是以下之一：`bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`。\
`opType` 通常是 check，用于允许或拒绝该操作。不过，也可能找到 `notify`，它会让 kext 对给定操作做出反应。

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

然后，可以在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) 中找到 `mac_file_check_mmap` 的代码
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
它调用了 `MAC_CHECK` 宏，其代码可以在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) 中找到
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
这会遍历所有已注册的 MAC policy，调用它们的函数，并将输出存储到 error 变量中；而 error 变量只能被 `mac_error_select` 通过成功代码覆盖，所以如果任何检查失败，完整检查就会失败，并且不会允许该操作。

> [!TIP]
> 不过，记住并不是所有 MACF callouts 只用于拒绝操作。例如，`mac_priv_grant` 会调用宏 [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274)，如果任意 policy 返回 0，它就会授予请求的 privilege：
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

这些 callas 用于检查并提供 [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) 中定义的（几十个）**privileges**。\
某些内核代码会使用进程的 KAuth credentials 和某个 privilege code 调用 [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) 中的 `priv_check_cred()`，它会先调用 `mac_priv_check` 来查看是否有任何 policy **denies** 授予该 privilege，然后再调用 `mac_priv_grant` 来查看是否有任何 policy 授予该 `privilege`。

### proc_check_syscall_unix

这个 hook 允许拦截所有 system calls。在 `bsd/dev/[i386|arm]/systemcalls.c` 中可以看到声明的函数 [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25)，其中包含以下代码：
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
它会在调用进程的 **bitmask** 中检查当前 syscall 是否应该调用 `mac_proc_check_syscall_unix`。这是因为 syscalls 调用非常频繁，因此有必要避免每次都调用 `mac_proc_check_syscall_unix`。

注意，函数 `proc_set_syscall_filter_mask()` 会在进程中设置 bitmask syscalls，它由 Sandbox 调用，用于给被 sandbox 的进程设置 masks。

## 暴露的 MACF syscalls

可以通过 [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) 中定义的一些 syscalls 与 MACF 交互：
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
对于 offensive reversing，**`__mac_syscall`** 仍然是最好的 userland chokepoint 之一。它携带一个 **policy name**（例如 `"Sandbox"` 或 `"AMFI"`）、一个 **policy-specific selector/code**，以及一个指向 **opaque argument blob** 的指针，这些内容会由 `mpo_policy_syscall` 处理。当你先从 userland 逆向未文档化操作，然后再逐步切入 kernel implementation 时，这非常有用。Sandbox 通常通过 `__sandbox_ms` 到达这里，而 AMFI 也使用同样的机制来做 dyld policy decisions。

## Practical offensive research notes

最近的 macOS bug 很少会直接“break MACF”。相反，它们通常是利用 **MACF / Sandbox / TCC decision 与之后发生的 privileged action 之间的 desynchronisation**。

### Broker path checks vs real privileged action

一个反复出现的模式是：某个 privileged daemon 先对 **userland pre-check**（例如 `sandbox_check_by_audit_token()`）使用某个路径版本进行检查，然后再用 **不同的、或者非 canonical 的 attacker-controlled path** 执行真正的 privileged sink。最近关于 `diskarbitrationd` / `storagekitd` 的研究就是一个很好的例子：**directory traversal** 加上 **symlink swaps** 让攻击者绕过 daemon 的 sandbox validation，然后在诸如 `~/Library/Application Support/com.apple.TCC` 这样的敏感位置上方挂载，从而把漏洞变成 **sandbox escape**、**local privilege escalation** 或 **TCC bypass**，具体取决于选定的 mount point。

在审计从 sandbox 可达的 root broker 时，先 grep 以下内容：

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, path canonicalisation helpers
- privileged sinks such as `mount`, `rename`, `copyfile`, helper-tool XPC methods, or anything that later touches attacker-controlled paths as root

### Trusted deputies with private entitlements

另一种实用模式不是直接攻击 MACF hooks，而是滥用一个已经拥有跨越边界所需权限的 **trusted process**。最近的 Safari/TCC 研究就是一个很好的例子：有意思的 primitive 不是“在 kernel 里 disable TCC”，而是修改本地 policy/configuration，让一个带有 **`com.apple.private.tcc.allow`** 的 Apple-signed process 代你执行敏感操作。实际上，高价值的审计目标是那些同时具备以下特征的 Apple daemons/apps：

- **private entitlements** 或类似 FDA 的 reach
- 可写的 config / database / mount point / policy file
- 之后由 **Sandbox**, **AMFI**, **TCC** 或其他 MACF policy 介导的敏感操作

要做更深入、产品特定的 reversing，请查看 [macOS Sandbox](macos-sandbox/README.md) 和 [macOS TCC](macos-tcc/README.md) 的专门页面。

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
