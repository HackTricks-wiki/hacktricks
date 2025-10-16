# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

**MACF** 代表 **Mandatory Access Control Framework**，它是内置于操作系统的一个安全系统，用于帮助保护你的计算机。它通过设置 **关于谁或什么可以访问系统某些部分（如文件、应用程序和系统资源）的严格规则** 来工作。通过自动强制执行这些规则，MACF 确保只有被授权的用户和进程才能执行特定操作，从而降低未授权访问或恶意活动的风险。

注意 MACF 本身并不做出决策，它只是**拦截**操作，并将决策留给它调用的**策略模块**（kernel extensions），例如 `AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext`、`TMSafetyNet.kext` 和 `mcxalr.kext`。

- A policy may be enforcing (return 0 non-zero on some operation)
- A policy may be monitoring (return 0, so as not to object but piggyback on hook to do something)
- A MACF static policy is installed in boot and will NEVER be removed
- A MACF dynamic policy is installed by a KEXT (kextload) and may hypothetically be kextunloaded
- In iOS only static policies are allowed and in macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### 流程

1. 进程执行 syscall/mach trap
2. 在内核中调用相关函数
3. 函数调用 MACF
4. MACF 检查在其策略中请求 hook 该函数的策略模块
5. MACF 调用相关策略
6. 策略指示是否允许或拒绝该操作

> [!CAUTION]
> Apple 是唯一能够使用 MAC Framework KPI 的实体。

通常，使用 MACF 检查权限的函数会调用宏 `MAC_CHECK`。例如，在创建 socket 的 syscall 中，会调用函数 `mac_socket_check_create`，该函数会调用 `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`。此外，宏 `MAC_CHECK` 在 security/mac_internal.h 中定义如下：
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
注意，将 `check` 转换为 `socket_check_create`，并将 `args...` 替换为 `(cred, domain, type, protocol)`，你会得到：
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
换句话说，`MAC_CHECK(socket_check_create, ...)` 先遍历静态策略，按条件锁定并迭代动态策略，在每个 hook 周围发出 DTrace 探针，并通过 `mac_error_select()` 将每个 hook 的返回码合并为单一的 `error` 结果。

### 标签

MACF 使用 **标签**，策略在检查是否应授予某些访问时会使用这些标签。标签结构体声明的代码可以在 [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h)，随后在 **`struct ucred`** 的 [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) 中的 **`cr_label`** 部分使用。该标签包含 flags 和若干 **槽位**，可被 **MACF 策略用于分配指针**。例如 Sanbox 会指向 container profile

## MACF 策略

MACF Policy 定义了在特定内核操作中应应用的规则和条件。

一个内核扩展可以配置一个 `mac_policy_conf` 结构体，然后调用 `mac_policy_register` 注册它。摘自 [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
通过检查对 `mac_policy_register` 的调用，很容易识别出配置这些策略的内核扩展。  
此外，通过反汇编该扩展也可以找到使用的 `mac_policy_conf` 结构体。

注意 MACF 策略也可以**动态**地注册和注销。

在 `mac_policy_conf` 中的主要字段之一是 **`mpc_ops`**。该字段指定了策略关注的操作。注意这些操作有数百个，因此可以将它们全部清零，然后只选择策略感兴趣的那些。 From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
当这些操作之一被拦截时，几乎所有的 hooks 都会被 MACF 回调。然而，**`mpo_policy_*`** hooks 是个例外，因为 `mpo_hook_policy_init()` 是在注册时（即在 `mac_policy_register()` 之后）被调用的回调，而 `mpo_hook_policy_initbsd()` 则在 BSD 子系统正确初始化后的后期注册期间被调用。

此外，**`mpo_policy_syscall`** hook 可以被任何 kext 注册以暴露一个私有的 **ioctl** 风格调用 **interface**。然后，用户 client 将能够调用 `mac_syscall` (#381)，将 **policy name**、一个整数 **code** 以及可选 **arguments** 作为参数指定。\
例如，**`Sandbox.kext`** 经常这样使用。

检查 kext 的 **`__DATA.__const*`** 可以识别在注册 policy 时使用的 `mac_policy_ops` 结构。之所以能找到它，是因为它的指针位于 `mpo_policy_conf` 内的某个偏移处，并且该区域会包含一定数量的 NULL 指针。

此外，也可以通过从内存中转储 struct **`_mac_policy_list`** 来获取配置了 policy 的 kext 列表，该结构会随着每个已注册的 policy 而更新。

你也可以使用工具 `xnoop` 来转储系统中注册的所有 policies：
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
然后使用以下命令转储 check policy 的所有检查：
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

### 早期引导和 mac_policy_init()

- MACF 会很早被初始化。在 `bootstrap_thread`（XNU 启动代码）中，在 `ipc_bootstrap` 之后，XNU 调用 `mac_policy_init()`（位于 `mac_base.c`）。
- `mac_policy_init()` 初始化全局 `mac_policy_list`（一个策略槽的数组或列表），并为 XNU 内的 MAC（Mandatory Access Control，强制访问控制）搭建基础设施。
- 随后会调用 `mac_policy_initmach()`，负责内核端对内置或捆绑策略的注册处理。

### `mac_policy_initmach()` 与加载 “安全扩展”

- `mac_policy_initmach()` 会检查已预加载的内核扩展 (kexts)（或在“policy injection”列表中的 kexts），并在其 Info.plist 中查找键 `AppleSecurityExtension`。
- 在 Info.plist 中声明 `<key>AppleSecurityExtension</key>`（或设置为 `true`）的 kexts 被视为“安全扩展”——即实现 MAC 策略或挂接到 MACF 基础设施的扩展。
- 带有该键的 Apple kext 示例包括 **ALF.kext**、**AppleMobileFileIntegrity.kext (AMFI)**、**Sandbox.kext**、**Quarantine.kext**、**TMSafetyNet.kext**、**CoreTrust.kext**、**AppleSystemPolicy.kext** 等（如你已列出）。
- 内核确保这些 kexts 提前加载，然后在引导期间通过 `mac_policy_register` 调用它们的注册例程，将它们插入 `mac_policy_list`。
- 每个策略模块（kext）会提供一个 `mac_policy_conf` 结构，包含用于各种 MAC 操作的钩子（`mpc_ops`），例如 vnode 检查、exec 检查、标签更新等。
- 加载时的标志可能包含 `MPC_LOADTIME_FLAG_NOTLATE`，表示“必须早期加载”（因此晚期注册尝试会被拒绝）。
- 注册后，每个模块会获得一个句柄并占据 `mac_policy_list` 中的一个槽位。
- 当以后触发某个 MAC 钩子（例如 vnode 访问、exec 等）时，MACF 会遍历所有已注册的策略以做出综合决策。
- 特别是，**AMFI**（Apple Mobile File Integrity）就是这样一个安全扩展。其 Info.plist 包含 `AppleSecurityExtension`，将其标记为安全策略。
- 作为内核引导的一部分，内核的加载逻辑会确保在许多子系统依赖它之前，“安全策略”（如 AMFI 等）已经处于活动状态。例如，内核会“通过加载……安全策略来为即将到来的任务做准备，包括 AppleMobileFileIntegrity (AMFI)、Sandbox、Quarantine 策略。”
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

当编写使用 MAC 框架的 kext（例如调用 `mac_policy_register()` 等）时，必须声明对 KPIs（Kernel Programming Interfaces）的依赖，以便 kext 链接器 (kxld) 能解析这些符号。因此，要声明一个 `kext` 依赖于 MACF，你需要在 `Info.plist` 中用 `com.apple.kpi.dsep` 来指明（`find . Info.plist | grep AppleSecurityExtension`），然后该 kext 会引用诸如 `mac_policy_register`、`mac_policy_unregister` 以及 MAC 钩子函数指针等符号。要解析这些符号，必须将 `com.apple.kpi.dsep` 列为依赖项。

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
## MACF 调用点

通常会在代码中看到对 MACF 的调用，它们定义在类似 **`#if CONFIG_MAC`** 的条件块中。此外，在这些块内可能会发现对 `mac_proc_check*` 的调用，该调用会让 MACF **检查权限** 以执行某些操作。此外，MACF 调用的格式是：**`mac_<object>_<opType>_opName`**。

对象可以是下列之一：`bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`。  
`opType` 通常为 check，用于允许或拒绝该操作。但也可能是 `notify`，这会允许 kext 对该操作作出反应。

你可以在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) 找到一个示例：

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
它调用了 `MAC_CHECK` 宏，其代码可以在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) 找到
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
这会遍历所有已注册的 mac 策略，调用它们的函数并将输出存储在 error 变量中，只有通过 `mac_error_select` 的成功代码才能覆盖该变量，因此如果任何检查失败，整个检查将失败，操作将不被允许。

> [!TIP]
> 但是，请记住，并非所有 MACF 调用点都仅用于拒绝操作。例如，`mac_priv_grant` 调用了宏 [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274)，如果有任何策略返回 0，它将授予请求的特权：
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

这些调用用于检查并提供（几十个）**特权**，定义在 [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h)。\
某些内核代码会从 [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) 调用 `priv_check_cred()`，使用进程的 KAuth 凭证 和 某个特权代码，`priv_check_cred()` 会调用 `mac_priv_check` 来查看是否有策略**拒绝**授予该特权，然后它会调用 `mac_priv_grant` 来查看是否有策略授予该 `privilege`。

### proc_check_syscall_unix

该 hook 允许拦截所有系统调用。在 `bsd/dev/[i386|arm]/systemcalls.c` 中可以看到声明的函数 [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25)，其中包含以下代码：
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
该函数会在调用进程的 **bitmask** 中检查当前 syscall 是否应调用 `mac_proc_check_syscall_unix`。这是因为 syscalls 被调用的频率很高，因此有必要避免每次都调用 `mac_proc_check_syscall_unix`。

注意，函数 `proc_set_syscall_filter_mask()`（用于在进程中设置 bitmask syscalls）由 Sandbox 调用，以在受沙箱限制的进程上设置掩码。

## 暴露的 MACF syscalls

可以通过一些在 [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) 中定义的 syscalls 与 MACF 进行交互：
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
