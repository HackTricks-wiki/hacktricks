# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

**MACF** 代表 **强制访问控制框架**，这是一个内置于操作系统的安全系统，用于帮助保护您的计算机。它通过设置 **关于谁或什么可以访问系统某些部分的严格规则** 来工作，例如文件、应用程序和系统资源。通过自动执行这些规则，MACF 确保只有授权用户和进程可以执行特定操作，从而降低未经授权访问或恶意活动的风险。

请注意，MACF 并不真正做出任何决策，因为它只是 **拦截** 操作，它将决策留给它调用的 **策略模块**（内核扩展），如 `AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext`、`TMSafetyNet.kext` 和 `mcxalr.kext`。

### 流程

1. 进程执行 syscall/mach trap
2. 内核内部调用相关函数
3. 函数调用 MACF
4. MACF 检查请求在其策略中挂钩该函数的策略模块
5. MACF 调用相关策略
6. 策略指示是否允许或拒绝该操作

> [!CAUTION]
> 只有 Apple 可以使用 MAC 框架 KPI。

### 标签

MACF 使用 **标签**，然后策略检查是否应该授予某些访问权限。标签结构声明的代码可以在 [这里](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h) 找到，该代码随后在 [**这里**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) 的 **`struct ucred`** 中使用，位于 **`cr_label`** 部分。标签包含标志和可由 **MACF 策略分配指针** 的 **槽** 数量。例如，Sandbox 将指向容器配置文件。

## MACF 策略

MACF 策略定义了 **在某些内核操作中应用的规则和条件**。&#x20;

内核扩展可以配置 `mac_policy_conf` 结构，然后通过调用 `mac_policy_register` 注册它。从 [这里](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
通过检查对 `mac_policy_register` 的调用，可以轻松识别配置这些策略的内核扩展。此外，通过检查扩展的反汇编，也可以找到使用的 `mac_policy_conf` 结构。

请注意，MACF 策略也可以**动态**注册和注销。

`mac_policy_conf` 的主要字段之一是 **`mpc_ops`**。该字段指定策略感兴趣的操作。请注意，它们有数百个，因此可以将所有操作置为零，然后仅选择策略感兴趣的操作。从 [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
几乎所有的钩子在拦截这些操作时都会被 MACF 回调。然而，**`mpo_policy_*`** 钩子是一个例外，因为 `mpo_hook_policy_init()` 是在注册时调用的回调（即在 `mac_policy_register()` 之后），而 `mpo_hook_policy_initbsd()` 是在 BSD 子系统正确初始化后进行晚期注册时调用的。

此外，**`mpo_policy_syscall`** 钩子可以被任何 kext 注册，以暴露一个私有的 **ioctl** 风格调用 **接口**。然后，用户客户端将能够调用 `mac_syscall` (#381)，并指定参数为 **策略名称**、一个整数 **代码** 和可选的 **参数**。\
例如，**`Sandbox.kext`** 经常使用这个。

检查 kext 的 **`__DATA.__const*`** 可以识别在注册策略时使用的 `mac_policy_ops` 结构。可以找到它，因为它的指针在 `mpo_policy_conf` 内部的一个偏移量处，并且因为该区域内将有许多 NULL 指针。

此外，还可以通过从内存中转储结构 **`_mac_policy_list`** 来获取已配置策略的 kext 列表，该结构会随着每个注册的策略而更新。

## MACF 初始化

MACF 很快就会初始化。它在 XNU 的 `bootstrap_thread` 中设置：在 `ipc_bootstrap` 之后调用 `mac_policy_init()`，该函数初始化 `mac_policy_list`，随后调用 `mac_policy_initmach()`。除了其他功能外，该函数将获取所有在其 Info.plist 中具有 `AppleSecurityExtension` 键的 Apple kext，如 `ALF.kext`、`AppleMobileFileIntegrity.kext`、`Quarantine.kext`、`Sandbox.kext` 和 `TMSafetyNet.kext` 并加载它们。

## MACF 回调

在代码中常常可以找到对 MACF 的回调定义，例如：**`#if CONFIG_MAC`** 条件块。此外，在这些块内可以找到对 `mac_proc_check*` 的调用，该调用会调用 MACF 来 **检查权限** 以执行某些操作。此外，MACF 回调的格式为：**`mac_<object>_<opType>_opName`**。

对象是以下之一：`bpfdesc`、`cred`、`file`、`proc`、`vnode`、`mount`、`devfs`、`ifnet`、`inpcb`、`mbuf`、`ipq`、`pipe`、`sysv[msg/msq/shm/sem]`、`posix[shm/sem]`、`socket`、`kext`。\
`opType` 通常是 check，用于允许或拒绝该操作。然而，也可以找到 `notify`，这将允许 kext 对给定操作做出反应。

您可以在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621) 中找到一个示例：

<pre class="language-c"><code class="lang-c">int
mmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)
{
[...]
#if CONFIG_MACF
<strong>			error = mac_file_check_mmap(vfs_context_ucred(ctx),
</strong>			    fp->fp_glob, prot, flags, file_pos + pageoff,
&#x26;maxprot);
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
调用 `MAC_CHECK` 宏，其代码可以在 [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261) 找到。
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
将遍历所有注册的 mac 策略，调用它们的函数并将输出存储在 error 变量中，该变量只能通过成功代码的 `mac_error_select` 被覆盖，因此如果任何检查失败，整个检查将失败，操作将不被允许。

> [!TIP]
> 然而，请记住，并非所有 MACF 调用仅用于拒绝操作。例如，`mac_priv_grant` 调用宏 [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274)，如果任何策略返回 0，将授予请求的特权：
>
> ```c
> /*
>  * MAC_GRANT 执行指定的检查，通过遍历策略
>  * 模块列表并与每个模块检查其对请求的看法。
>  * 与 MAC_CHECK 不同，如果任何策略返回 '0'，它将授予，
>  * 否则返回 EPERM。请注意，它通过
>  * 调用者的 'error' 返回其值。
>  */
> #define MAC_GRANT(check, args...) do {                              \
>     error = EPERM;                                                  \
>     MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>     });                                                             \
> } while (0)
> ```

### priv_check & priv_grant

这些调用旨在检查和提供在 [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h) 中定义的（数十个）**特权**。\
一些内核代码会使用进程的 KAuth 凭据调用 `priv_check_cred()`，并使用特权代码之一，这将调用 `mac_priv_check` 来查看是否有任何策略 **拒绝** 授予特权，然后调用 `mac_priv_grant` 来查看是否有任何策略授予该 `privilege`。

### proc_check_syscall_unix

此钩子允许拦截所有系统调用。在 `bsd/dev/[i386|arm]/systemcalls.c` 中，可以看到声明的函数 [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25)，其中包含以下代码：
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
将检查调用进程的 **bitmask** 是否当前系统调用应该调用 `mac_proc_check_syscall_unix`。这是因为系统调用被调用的频率很高，因此避免每次都调用 `mac_proc_check_syscall_unix` 是很有意义的。

请注意，函数 `proc_set_syscall_filter_mask()`，它在进程中设置 bitmask 系统调用，是由 Sandbox 调用以在沙箱进程上设置掩码。

## 暴露的 MACF 系统调用

可以通过在 [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151) 中定义的一些系统调用与 MACF 进行交互：
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
## 参考文献

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
