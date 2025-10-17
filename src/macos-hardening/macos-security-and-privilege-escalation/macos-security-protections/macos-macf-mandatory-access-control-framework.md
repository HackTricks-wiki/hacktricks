# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

**MACF** 代表 **Mandatory Access Control Framework（强制访问控制框架）**，它是内置在操作系统中的一个安全机制，用于帮助保护你的计算机。它通过为系统的某些部分（例如文件、应用程序和系统资源）设置**关于谁或什么可以访问这些部分的严格规则**来工作。通过自动强制这些规则，MACF 确保只有被授权的用户和进程可以执行特定操作，从而降低未授权访问或恶意活动的风险。

注意 MACF 本身并不真正做出决策，它只是**拦截**操作，并将决策留给它调用的**策略模块**（kernel extensions），例如 `AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext`、`TMSafetyNet.kext` 和 `mcxalr.kext`。

- 策略可能是 enforcing（在某些操作上返回非零以阻止）
- 策略可能是 monitoring（返回 0，以不反对但借助 hook 执行某些操作）
- MACF 的静态策略在启动时安装并且永远不会被移除
- MACF 的动态策略由 KEXT 安装（kextload），理论上可能被 kextunloaded
- 在 iOS 中只允许静态策略，而在 macOS 中允许静态 + 动态策略
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### 流程

1. 进程 执行 syscall/mach trap
2. 内核中调用相关函数
3. 该函数调用 MACF
4. MACF 检查在其策略中请求 hook 该函数的策略模块
5. MACF 调用相关策略
6. 策略指示是否允许或拒绝该操作

> [!CAUTION]
> 只有 Apple 可以使用 MAC Framework KPI。

通常使用 MACF 检查权限的函数会调用宏 `MAC_CHECK`。例如，在创建 socket 的 syscall 中，会调用函数 `mac_socket_check_create`，该函数调用 `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`。此外，宏 `MAC_CHECK` 在 security/mac_internal.h 中定义为：
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
注意，将 `check` 转换为 `socket_check_create` 并将 `args...` 替换为 `(cred, domain, type, protocol)`，你会得到：
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
展开辅助宏可以显示具体的控制流：
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
换言之，`MAC_CHECK(socket_check_create, ...)` 会先遍历静态策略，按条件锁定并迭代动态策略，在每个 hook 周围触发 DTrace 探针，并通过 `mac_error_select()` 将每个 hook 的返回码合并为单一的 `error` 结果。

### 标签

MACF 使用 **labels**，策略会根据这些标签来决定是否授予某些访问权限。labels 结构体声明的代码可以在 [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) 找到，该结构随后在 [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) 的 **`struct ucred`** 中的 **`cr_label`** 部分使用。label 包含标志和若干个可以被 **槽（**slots**）** 使用的槽位，这些槽位可被 **MACF 策略用来分配指针**。例如 Sandbox 会指向容器的 profile。

## MACF 策略

MACF 策略定义了**应在特定内核操作中应用的规则和条件**。

内核扩展可以配置一个 `mac_policy_conf` 结构体，然后通过调用 `mac_policy_register` 注册它。摘自 [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html)：
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
通过检查对 `mac_policy_register` 的调用，可以很容易识别配置这些策略的内核扩展。此外，检查扩展的反汇编也可以找到所使用的 `mac_policy_conf` 结构体。

请注意，MACF 策略也可以**动态**注册和注销。

`mac_policy_conf` 的主要字段之一是 **`mpc_ops`**。该字段指定了策略感兴趣的操作。注意，这些操作有数百种，因此可以先将它们全部清零，然后只选择策略关注的那些。详见 [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
几乎所有的 hooks 在这些操作被拦截时都会由 MACF 回调调用。然而，**`mpo_policy_*`** hooks 是个例外，因为 `mpo_hook_policy_init()` 是在注册时（也就是在 `mac_policy_register()` 之后）被调用的回调，而 `mpo_hook_policy_initbsd()` 则在 BSD 子系统正确初始化后于晚期注册期间被调用。

此外，**`mpo_policy_syscall`** hook 可以由任何 kext 注册来暴露私有的 **ioctl** 样式调用 **接口**。然后，用户客户端将能够调用 `mac_syscall` (#381)，以 **policy name**、一个整数 **code** 和可选 **arguments** 作为参数。\
例如，**`Sandbox.kext`** 经常使用这个。

检查 kext 的 **`__DATA.__const*`** 可以识别用于注册策略的 `mac_policy_ops` 结构。可以找到它，因为它的指针位于 `mpo_policy_conf` 内的一个偏移处，并且该区域中会有一定数量的 NULL 指针。

此外，还可以通过从内存中转储结构 **`_mac_policy_list`** 来获取已配置策略的 kext 列表，该结构会随着每个已注册的策略而更新。

你也可以使用工具 `xnoop` 来转储系统中注册的所有策略：
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
然后用以下命令转储 check policy 的所有检查：
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
## MACF 在 XNU 中的初始化

### 早期引导与 mac_policy_init()

- MACF 会很早就被初始化。在 `bootstrap_thread`（XNU 启动代码中），在 `ipc_bootstrap` 之后，XNU 调用 `mac_policy_init()`（位于 `mac_base.c`）。
- `mac_policy_init()` 初始化全局 `mac_policy_list`（一个策略槽的数组或列表），并在 XNU 内部为 MAC（强制访问控制）建立基础设施。
- 随后会调用 `mac_policy_initmach()`，它负责内核端的策略注册（针对内建或捆绑的策略）。

### `mac_policy_initmach()` 和加载“安全扩展”

- `mac_policy_initmach()` 会检查已预加载的 kernel extensions (kexts)（或位于“policy injection”列表中的），并检查它们的 Info.plist 中是否包含键 `AppleSecurityExtension`。
- 在 Info.plist 中声明 `<key>AppleSecurityExtension</key>`（或 `true`）的 kexts 被视为“security extensions”——即实现 MAC 策略或挂接到 MACF 基础设施的扩展。
- 带有该键的 Apple kext 示例包括 **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext** 等（如你已列出）。
- 内核确保这些 kexts 提前加载，然后在引导过程中通过 `mac_policy_register` 调用它们的注册例程，并将它们插入 `mac_policy_list`。

- 每个策略模块（kext）提供一个 `mac_policy_conf` 结构，包含用于各种 MAC 操作（vnode 检查、exec 检查、标签更新等）的钩子（`mpc_ops`）。
- 加载时标志可能包含 `MPC_LOADTIME_FLAG_NOTLATE`，表示“必须提前加载”（因此晚期的注册尝试会被拒绝）。
- 一旦注册，每个模块都会获得一个句柄并占据 `mac_policy_list` 中的一个槽。
- 当随后调用 MAC 钩子（例如 vnode 访问、exec 等）时，MACF 会遍历所有已注册的策略以做出集体决策。

- 特别是，**AMFI**（Apple Mobile File Integrity）就是这样一个安全扩展。它的 Info.plist 包含 `AppleSecurityExtension`，将其标记为安全策略。
- 作为内核引导的一部分，内核加载逻辑确保在许多子系统依赖它之前，“security policy”（AMFI 等）已经处于活动状态。例如，内核“为接下来的任务做好准备，加载……安全策略，包括 AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy。”
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
## KPI 依赖 & com.apple.kpi.dsep 在 MAC policy kexts 中

当编写使用 MAC framework 的 kext（例如调用 `mac_policy_register()` 等）时，必须声明对 KPIs（Kernel Programming Interfaces）的依赖，以便 kext 链接器（kxld）能够解析这些符号。因此，为了声明一个 `kext` 依赖于 MACF，你需要在 `Info.plist` 中用 `com.apple.kpi.dsep` 指明（`find . Info.plist | grep AppleSecurityExtension`），然后 kext 会引用诸如 `mac_policy_register`、`mac_policy_unregister` 以及 MAC hook 函数指针等符号。为了解决这些引用，必须将 `com.apple.kpi.dsep` 列为依赖项。

示例 Info.plist 片段（在你的 .kext 内）：
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
## MACF 调用点

常见在代码中发现对 MACF 的调用，例如通过 **`#if CONFIG_MAC`** 条件块定义。此外，在这些块内可能会发现对 `mac_proc_check*` 的调用，它调用 MACF 来 **检查权限** 以执行某些操作。此外，MACF 调用的格式为：**`mac_<object>_<opType>_opName`**。

对象为以下之一： `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
`opType` 通常为 check，用于允许或拒绝该操作。不过，也可能看到 `notify`，它允许 kext 对该操作做出响应。

You can find an example in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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

然后，可以在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174) 找到 `mac_file_check_mmap` 的实现代码。
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
它调用了 `MAC_CHECK` 宏，其代码可以在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) 找到。
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
它会遍历所有已注册的 mac 策略，调用它们的函数并将输出存储在 `error` 变量中，该变量只能被 `mac_error_select` 根据成功码覆盖，因此如果任何检查失败，整个检查将失败并且该操作将不被允许。

> [!TIP]
> 不过，请记住并非所有 MACF callouts 都仅用于拒绝操作。例如，`mac_priv_grant` 会调用宏 [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274)，如果任一策略返回 0，该宏将授予请求的权限：
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

These callas are meant to check and provide (tens of) **特权** defined in [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Some kernel code would call `priv_check_cred()` from [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) with the KAuth credentials of the process and one of the privileges code which will call `mac_priv_check` to see if any policy **拒绝** giving the privilege and then it calls `mac_priv_grant` to see if any policy grants the `privilege`.

### proc_check_syscall_unix

This hook allows to intercept all system calls. In `bsd/dev/[i386|arm]/systemcalls.c` it's possible to see the declared function [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), which contains this code:
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
它会在调用进程的 **bitmask** 中检查当前 syscall 是否应该调用 `mac_proc_check_syscall_unix`。这是因为 syscalls 被调用得非常频繁，所以有必要避免每次都调用 `mac_proc_check_syscall_unix`。

注意函数 `proc_set_syscall_filter_mask()`，它在进程中设置 syscalls 的 bitmask，会被 Sandbox 调用以在被 sandbox 限制的进程上设置掩码。

## 暴露的 MACF syscalls

可以通过一些在 [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) 中定义的 syscalls 与 MACF 交互：
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
## 参考资料

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
